#include "conduit/mysql/connection.hpp"

#include "conduit/crypto.hpp"

namespace conduit::mysql {

task<packet> connection::read_packet() {
    for (;;) {
        auto p = peek_packet(buf_.readable());
        if (p) co_return *p;
        bool alive = co_await read_some(*loop_, sock_, buf_);
        if (!alive) {
            poisoned_ = true;
            throw io_error("MySQL server closed the connection");
        }
    }
}

task<void> connection::send(std::uint8_t sequence, byte_span payload, const char* name,
                            std::string detail) {
    out_.clear();
    write_packet(out_, sequence, payload);
    trace_.record(direction::to_server, name, out_.size(), std::move(detail));
    co_await write_all(*loop_, sock_, byte_span(out_));
    out_.clear();
    trace_.count_round_trip();
}

task<void> connection::open(connect_params p) {
    co_await connect(*loop_, sock_, p.host, p.port);

    auto first = co_await read_packet();
    auto h = decode_handshake(first.payload);
    trace_.record(direction::from_server, "HandshakeV10", first.consumed,
                  h.server_version + " plugin=" + h.auth_plugin);
    server_version_ = h.server_version;
    connection_id_ = h.connection_id;
    std::uint8_t seq = first.sequence;
    consume(first);

    co_await authenticate(p, h);
    (void)seq;
    open_ = true;
    poisoned_ = false;
}

task<void> connection::authenticate(const connect_params& p, const handshake& h) {
    std::uint32_t want = caps::protocol_41 | caps::secure_connection | caps::plugin_auth |
                         caps::transactions | caps::long_password | caps::long_flag |
                         caps::multi_results;
    if (!p.database.empty()) want |= caps::connect_with_db;
    // Only ask for what the server offers, and never for TLS: this client does
    // not implement it, and claiming the capability would break the handshake.
    capabilities_ = want & (h.capabilities | caps::long_password);
    capabilities_ &= ~caps::ssl;

    if (!h.auth_plugin.empty() && h.auth_plugin != "mysql_native_password")
        throw protocol_error("server asked for authentication plugin '" + h.auth_plugin +
                             "', only mysql_native_password is implemented");

    auto reply = crypto::mysql_native_password(p.password, byte_span(h.auth_data));
    byte_span reply_span = p.password.empty() ? byte_span{} : byte_span(reply);

    std::vector<std::byte> payload;
    encode_handshake_response(payload, capabilities_, p.user, reply_span, p.database,
                              "mysql_native_password");
    co_await send(1, byte_span(payload), "HandshakeResponse41",
                  "user=" + p.user + " database=" + p.database);

    for (;;) {
        auto pk = co_await read_packet();
        auto kind = classify(pk.payload);
        if (kind == packet_kind::ok) {
            trace_.record(direction::from_server, "OK_Packet", pk.consumed, "authenticated");
            consume(pk);
            co_return;
        }
        if (kind == packet_kind::err) {
            auto e = decode_err(pk.payload);
            trace_.record(direction::from_server, "ERR_Packet", pk.consumed, e.sql_state);
            consume(pk);
            poisoned_ = true;
            throw server_exception(std::move(e));
        }
        if (kind == packet_kind::auth_switch) {
            auto sw = decode_auth_switch(pk.payload);
            trace_.record(direction::from_server, "AuthSwitchRequest", pk.consumed, sw.plugin);
            std::uint8_t seq = pk.sequence;
            consume(pk);
            if (sw.plugin != "mysql_native_password") {
                poisoned_ = true;
                throw protocol_error("server switched to authentication plugin '" + sw.plugin +
                                     "', only mysql_native_password is implemented");
            }
            auto again = crypto::mysql_native_password(p.password, byte_span(sw.data));
            byte_span again_span = p.password.empty() ? byte_span{} : byte_span(again);
            co_await send(static_cast<std::uint8_t>(seq + 1), again_span, "AuthSwitchResponse");
            continue;
        }
        trace_.record(direction::from_server, "Payload", pk.consumed);
        consume(pk);
        poisoned_ = true;
        throw protocol_error("unexpected packet during authentication");
    }
}

task<query_result> connection::query(std::string_view sql, row_callback on_row) {
    if (!is_usable()) throw io_error("connection is not usable");

    std::vector<std::byte> payload;
    {
        byte_writer w{payload};
        w.u8(static_cast<std::uint8_t>(command::query));
        w.raw(sql);
    }
    co_await send(0, byte_span(payload), "COM_QUERY", std::string(sql));

    query_result result;

    // First packet after COM_QUERY is either a status packet or the column count.
    auto first = co_await read_packet();
    auto kind = classify(first.payload);
    if (kind == packet_kind::ok) {
        auto ok = decode_ok(first.payload);
        result.affected_rows = ok.affected_rows;
        result.last_insert_id = ok.last_insert_id;
        trace_.record(direction::from_server, "OK_Packet", first.consumed,
                      std::to_string(ok.affected_rows) + " rows affected");
        consume(first);
        co_return result;
    }
    if (kind == packet_kind::err) {
        auto e = decode_err(first.payload);
        trace_.record(direction::from_server, "ERR_Packet", first.consumed, e.sql_state);
        consume(first);
        throw server_exception(std::move(e));
    }

    byte_reader cr{first.payload};
    auto column_count = read_lenenc_int(cr);
    trace_.record(direction::from_server, "ColumnCount", first.consumed,
                  std::to_string(column_count) + " columns");
    consume(first);

    for (std::uint64_t i = 0; i < column_count; ++i) {
        auto pk = co_await read_packet();
        result.columns.push_back(decode_column_definition(pk.payload));
        trace_.record(direction::from_server, "ColumnDefinition41", pk.consumed,
                      result.columns.back().name + " " + type_name(result.columns.back().type));
        consume(pk);
    }

    // Without CLIENT_DEPRECATE_EOF the column block is closed by an EOF packet.
    {
        auto pk = co_await read_packet();
        if (classify(pk.payload) != packet_kind::eof)
            throw protocol_error("expected EOF after the column definitions");
        trace_.record(direction::from_server, "EOF_Packet", pk.consumed, "end of columns");
        consume(pk);
    }

    std::vector<field_view> row;
    for (;;) {
        auto pk = co_await read_packet();
        auto k = classify(pk.payload);
        if (k == packet_kind::eof) {
            trace_.record(direction::from_server, "EOF_Packet", pk.consumed, "end of rows");
            consume(pk);
            co_return result;
        }
        if (k == packet_kind::err) {
            auto e = decode_err(pk.payload);
            trace_.record(direction::from_server, "ERR_Packet", pk.consumed, e.sql_state);
            consume(pk);
            throw server_exception(std::move(e));
        }
        decode_text_row(pk.payload, result.columns, row);
        ++result.rows;
        if (on_row) on_row(result.columns, row);
        trace_.record(direction::from_server, "ResultsetRow", pk.consumed);
        consume(pk);
    }
}

task<bool> connection::ping() {
    if (!is_usable()) co_return false;
    try {
        std::vector<std::byte> payload;
        byte_writer w{payload};
        w.u8(static_cast<std::uint8_t>(command::ping));
        co_await send(0, byte_span(payload), "COM_PING");
        auto pk = co_await read_packet();
        bool ok = classify(pk.payload) == packet_kind::ok;
        trace_.record(direction::from_server, ok ? "OK_Packet" : "Payload", pk.consumed);
        consume(pk);
        co_return ok;
    } catch (const io_error&) {
        poisoned_ = true;
        co_return false;
    } catch (const protocol_error&) {
        poisoned_ = true;
        co_return false;
    }
}

task<void> connection::close() {
    if (!sock_.valid()) co_return;
    if (open_ && !poisoned_) {
        try {
            std::vector<std::byte> payload;
            byte_writer w{payload};
            w.u8(static_cast<std::uint8_t>(command::quit));
            out_.clear();
            write_packet(out_, 0, byte_span(payload));
            trace_.record(direction::to_server, "COM_QUIT", out_.size());
            co_await write_all(*loop_, sock_, byte_span(out_));
            out_.clear();
        } catch (const io_error&) {
            // The peer may already be gone.
        }
    }
    sock_.close();
    open_ = false;
    co_return;
}

}  // namespace conduit::mysql
