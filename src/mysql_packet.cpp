#include "conduit/mysql/protocol.hpp"

namespace conduit::mysql {

std::optional<packet> peek_packet(byte_span in) {
    if (in.size() < 4) return std::nullopt;
    std::uint32_t len = load_le24(in.data());
    std::size_t total = std::size_t{len} + 4;
    if (in.size() < total) return std::nullopt;
    packet p;
    p.payload = in.subspan(4, len);
    p.sequence = std::to_integer<std::uint8_t>(in[3]);
    p.consumed = total;
    return p;
}

std::optional<packet> codec::peek(byte_span in) { return peek_packet(in); }

const char* codec::describe(const packet& p) {
    if (p.payload.empty()) return "EmptyPacket";
    switch (classify(p.payload)) {
        case packet_kind::ok: return "OK_Packet";
        case packet_kind::err: return "ERR_Packet";
        case packet_kind::eof: return "EOF_Packet";
        case packet_kind::auth_switch: return "AuthSwitchRequest";
        case packet_kind::data: return "Payload";
    }
    return "Payload";
}

void write_packet(std::vector<std::byte>& out, std::uint8_t sequence, byte_span payload) {
    if (payload.size() > max_payload)
        throw protocol_error("payload larger than one packet is out of scope");
    byte_writer w{out};
    w.le24(static_cast<std::uint32_t>(payload.size()));
    w.u8(sequence);
    w.raw(payload);
}

// --- length encoded values ---------------------------------------------------

std::uint64_t read_lenenc_int(byte_reader& r) {
    std::uint8_t first = r.u8();
    if (first < 0xFB) return first;
    if (first == 0xFC) return r.le16();
    if (first == 0xFD) return r.le24();
    if (first == 0xFE) return r.le64();
    // 0xFB is NULL in a row context and has no meaning as an integer.
    throw protocol_error("0xFB is not a length encoded integer");
}

std::optional<std::string_view> read_lenenc_string(byte_reader& r) {
    std::uint8_t first = r.u8();
    if (first == 0xFB) return std::nullopt;
    std::uint64_t len;
    if (first < 0xFB) len = first;
    else if (first == 0xFC) len = r.le16();
    else if (first == 0xFD) len = r.le24();
    else if (first == 0xFE) len = r.le64();
    else throw protocol_error("0xFF is not a length encoded string header");
    return r.str(static_cast<std::size_t>(len));
}

void write_lenenc_int(byte_writer& w, std::uint64_t v) {
    if (v < 251) { w.u8(static_cast<std::uint8_t>(v)); return; }
    if (v < 0x10000) { w.u8(0xFC); w.le16(static_cast<std::uint16_t>(v)); return; }
    if (v < 0x1000000) { w.u8(0xFD); w.le24(static_cast<std::uint32_t>(v)); return; }
    w.u8(0xFE);
    w.le64(v);
}

void write_lenenc_string(byte_writer& w, std::string_view s) {
    write_lenenc_int(w, s.size());
    w.raw(s);
}

// --- handshake ---------------------------------------------------------------

handshake decode_handshake(byte_span payload) {
    byte_reader r{payload};
    handshake h;
    h.protocol_version = r.u8();
    if (h.protocol_version != 10)
        throw protocol_error("only handshake protocol version 10 is implemented, got " +
                             std::to_string(h.protocol_version));
    h.server_version.assign(r.cstr());
    h.connection_id = r.le32();

    auto part1 = r.bytes(8);
    h.auth_data.assign(part1.begin(), part1.end());
    r.skip(1);  // filler

    std::uint32_t lower = r.le16();
    h.capabilities = lower;
    if (r.remaining() > 0) {
        h.character_set = r.u8();
        h.status_flags = r.le16();
        std::uint32_t upper = r.le16();
        h.capabilities |= upper << 16;

        std::uint8_t auth_data_len = r.u8();
        r.skip(10);  // reserved

        if (h.capabilities & caps::secure_connection) {
            // The specification says at least 13 bytes, of which the last is a
            // NUL that is not part of the seed. Trusting auth_data_len alone
            // breaks against servers that report 0 here.
            std::size_t want = auth_data_len > 8 ? std::size_t(auth_data_len) - 8 : 12;
            if (want < 13) want = 13;
            if (want > r.remaining()) want = r.remaining();
            auto part2 = r.bytes(want);
            // Drop the trailing NUL so the seed is exactly 20 bytes.
            std::size_t keep = part2.size();
            while (keep > 0 && part2[keep - 1] == std::byte{0}) --keep;
            h.auth_data.insert(h.auth_data.end(), part2.begin(), part2.begin() + keep);
        }
        if ((h.capabilities & caps::plugin_auth) && r.remaining() > 0)
            h.auth_plugin.assign(r.cstr());
    }
    return h;
}

void encode_handshake_response(std::vector<std::byte>& out, std::uint32_t capabilities,
                               std::string_view user, byte_span auth_response,
                               std::string_view database, std::string_view auth_plugin) {
    byte_writer w{out};
    w.le32(capabilities);
    w.le32(static_cast<std::uint32_t>(max_payload));  // max packet size
    w.u8(45);                                         // utf8mb4_general_ci
    for (int i = 0; i < 23; ++i) w.u8(0);             // reserved
    w.cstr(user);

    if (capabilities & caps::plugin_auth_lenenc) {
        write_lenenc_int(w, auth_response.size());
        w.raw(auth_response);
    } else if (capabilities & caps::secure_connection) {
        w.u8(static_cast<std::uint8_t>(auth_response.size()));
        w.raw(auth_response);
    } else {
        w.raw(auth_response);
        w.u8(0);
    }

    if (capabilities & caps::connect_with_db) w.cstr(database);
    if (capabilities & caps::plugin_auth) w.cstr(auth_plugin);
}

void encode_ssl_request(std::vector<std::byte>& out, std::uint32_t capabilities) {
    byte_writer w{out};
    w.le32(capabilities | caps::ssl);
    w.le32(static_cast<std::uint32_t>(max_payload));
    w.u8(45);
    for (int i = 0; i < 23; ++i) w.u8(0);
}

// --- generic packets ----------------------------------------------------------

packet_kind classify(byte_span payload) {
    if (payload.empty()) return packet_kind::data;
    auto first = std::to_integer<std::uint8_t>(payload[0]);
    if (first == 0xFF) return packet_kind::err;
    // An OK packet is 0x00 and at least seven bytes; a shorter one is a row
    // whose first column happens to be the empty string.
    if (first == 0x00 && payload.size() >= 7) return packet_kind::ok;
    if (first == 0xFE) {
        // Under nine bytes it is an EOF marker, otherwise the server is asking
        // the client to switch authentication plugin.
        return payload.size() < 9 ? packet_kind::eof : packet_kind::auth_switch;
    }
    return packet_kind::data;
}

ok_packet decode_ok(byte_span payload) {
    byte_reader r{payload};
    r.u8();  // 0x00
    ok_packet ok;
    ok.affected_rows = read_lenenc_int(r);
    ok.last_insert_id = read_lenenc_int(r);
    if (r.remaining() >= 4) {
        ok.status_flags = r.le16();
        ok.warnings = r.le16();
    }
    if (r.remaining() > 0) {
        auto rest = r.rest();
        ok.info.assign(reinterpret_cast<const char*>(rest.data()), rest.size());
    }
    return ok;
}

err_packet decode_err(byte_span payload) {
    byte_reader r{payload};
    r.u8();  // 0xFF
    err_packet e;
    e.code = r.le16();
    if (r.remaining() > 0 && r.rest()[0] == std::byte{'#'}) {
        r.skip(1);
        e.sql_state.assign(r.str(5));
    }
    auto rest = r.rest();
    e.message.assign(reinterpret_cast<const char*>(rest.data()), rest.size());
    return e;
}

std::string err_packet::summary() const {
    std::string s = "ERROR " + std::to_string(code);
    if (!sql_state.empty()) s += " (" + sql_state + ")";
    if (!message.empty()) s += ": " + message;
    return s;
}

auth_switch decode_auth_switch(byte_span payload) {
    byte_reader r{payload};
    r.u8();  // 0xFE
    auth_switch a;
    a.plugin.assign(r.cstr());
    auto rest = r.rest();
    std::size_t keep = rest.size();
    while (keep > 0 && rest[keep - 1] == std::byte{0}) --keep;
    a.data.assign(rest.begin(), rest.begin() + keep);
    return a;
}

// --- result sets ---------------------------------------------------------------

column decode_column_definition(byte_span payload) {
    byte_reader r{payload};
    column c;
    read_lenenc_string(r);  // catalog, always "def"
    if (auto v = read_lenenc_string(r)) c.schema.assign(*v);
    if (auto v = read_lenenc_string(r)) c.table.assign(*v);
    read_lenenc_string(r);  // original table
    if (auto v = read_lenenc_string(r)) c.name.assign(*v);
    if (auto v = read_lenenc_string(r)) c.original_name.assign(*v);
    read_lenenc_int(r);  // length of the fixed part, always 0x0c
    c.character_set = r.le16();
    c.length = r.le32();
    c.type = r.u8();
    c.flags = r.le16();
    c.decimals = r.u8();
    return c;
}

void decode_text_row(byte_span payload, const std::vector<column>& cols,
                     std::vector<field_view>& into) {
    byte_reader r{payload};
    into.clear();
    into.reserve(cols.size());
    for (const auto& c : cols) {
        field_view f;
        f.oid = c.type;
        f.format = wire_format::text;  // the text protocol has no other option
        auto v = read_lenenc_string(r);
        if (!v) f.is_null = true;
        else f.data = byte_span(reinterpret_cast<const std::byte*>(v->data()), v->size());
        into.push_back(f);
    }
    if (!r.empty())
        throw protocol_error("row payload has " + std::to_string(r.remaining()) +
                             " bytes left after all columns");
}

const char* type_name(std::uint8_t code) {
    switch (code) {
        case type::decimal: return "decimal";
        case type::tiny: return "tinyint";
        case type::short_: return "smallint";
        case type::long_: return "int";
        case type::float_: return "float";
        case type::double_: return "double";
        case type::null: return "null";
        case type::timestamp: return "timestamp";
        case type::longlong: return "bigint";
        case type::int24: return "mediumint";
        case type::date: return "date";
        case type::time: return "time";
        case type::datetime: return "datetime";
        case type::year: return "year";
        case type::varchar: return "varchar";
        case type::bit: return "bit";
        case type::newdecimal: return "decimal";
        case type::blob: return "blob";
        case type::var_string: return "varchar";
        case type::string: return "char";
        default: return "unknown";
    }
}

}  // namespace conduit::mysql
