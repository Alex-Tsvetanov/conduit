#include "conduit/pg/connection.hpp"

#include "conduit/crypto.hpp"
#include "conduit/scram.hpp"

namespace conduit::pg {
namespace {

// The one place that decides whether a backend message is worth a trace line.
void trace_in(message_trace& t, const frame& f, std::string detail = {}) {
    t.record(direction::from_server, backend_name(f.tag), f.consumed, std::move(detail));
}

}  // namespace

// The slow half of read_message: only reached when the receive buffer does not
// yet hold a whole message. See message_awaitable in the header for why the
// fast half is not a coroutine.
task<frame> connection::read_message_slow() {
    for (;;) {
        auto f = peek_frame(buf_.readable());
        if (f) co_return *f;
        // Nothing whole in the buffer yet. This is the resumable path: a partial
        // message costs one more read, never a lost byte.
        bool alive = co_await read_some(*loop_, sock_, tls_, buf_);
        if (!alive) {
            poisoned_ = true;
            throw io_error("PostgreSQL server closed the connection");
        }
    }
}

task<void> connection::flush() {
    if (out_.empty()) co_return;
    co_await write_all(*loop_, sock_, tls_, byte_span(out_));
    out_.clear();
    trace_.count_round_trip();
}

task<void> connection::open(connect_params p) {
    statements_ = lru_cache<prepared_statement>(p.statement_cache_size);
    if (p.tls.enabled && !tls_available())
        throw io_error(
            "TLS was requested but this build of Conduit was not linked against OpenSSL");
    co_await connect(*loop_, sock_, p.host, p.port);
    if (p.tls.enabled) co_await negotiate_tls(p);
    co_await authenticate(p);
    open_ = true;
    poisoned_ = false;
}

task<void> connection::negotiate_tls(const connect_params& p) {
    out_.clear();
    encode_ssl_request(out_);
    trace_.record(direction::to_server, "SSLRequest", out_.size());
    co_await write_all(*loop_, sock_, byte_span(out_));
    out_.clear();
    trace_.count_round_trip();

    // Exactly one byte: 'S' or 'N'. Reading more would swallow the start of
    // the TLS records if they arrived in the same TCP segment, and those bytes
    // would then be invisible to OpenSSL.
    std::byte reply{};
    for (;;) {
        auto r = sock_.try_read(std::span<std::byte>(&reply, 1));
        if (r.status == io_status::ok && r.bytes == 1) break;
        if (r.status == io_status::closed) {
            poisoned_ = true;
            throw io_error("PostgreSQL server closed during TLS negotiation");
        }
        co_await loop_->wait_readable(sock_.native());
    }
    char c = static_cast<char>(std::to_integer<std::uint8_t>(reply));
    if (c != 'S') {
        sock_.close();
        poisoned_ = true;
        // An ErrorResponse here is not authenticated (CVE-2024-10977). Do
        // not surface its text; the connection is already closed.
        if (c == 'N') throw io_error("PostgreSQL server refused TLS");
        throw io_error("PostgreSQL server rejected the TLS request");
    }
    trace_.record(direction::from_server, "SSLResponse", 1, "S");
    co_await handshake_tls(*loop_, sock_, tls_, p.tls, p.host);
}

task<void> connection::authenticate(const connect_params& p) {
    out_.clear();
    encode_startup(out_, p.user, p.database, p.options);
    trace_.record(direction::to_server, "StartupMessage", out_.size(),
                  "user=" + p.user + " database=" + p.database);
    co_await flush();

    std::optional<scram_client> scram;

    for (;;) {
        auto f = co_await read_message();
        auto tag = static_cast<backend>(f.tag);

        if (tag == backend::error_response) {
            auto e = decode_error(f.body);
            trace_in(trace_, f, e.sqlstate);
            consume(f);
            poisoned_ = true;
            throw server_exception(std::move(e));
        }

        if (tag == backend::authentication) {
            auto a = decode_authentication(f.body);
            trace_in(trace_, f, "kind=" + std::to_string(static_cast<int>(a.kind)));
            consume(f);
            switch (a.kind) {
                case auth_kind::ok:
                    break;
                case auth_kind::cleartext_password:
                    encode_password(out_, p.password);
                    trace_.record(direction::to_server, "PasswordMessage", out_.size(), "cleartext");
                    co_await flush();
                    break;
                case auth_kind::md5_password: {
                    auto reply = crypto::pg_md5_password(p.password, p.user, byte_span(a.salt));
                    encode_password(out_, reply);
                    trace_.record(direction::to_server, "PasswordMessage", out_.size(), "md5");
                    co_await flush();
                    break;
                }
                case auth_kind::sasl: {
                    bool offered = false;
                    for (const auto& m : a.mechanisms)
                        if (m == "SCRAM-SHA-256") offered = true;
                    if (!offered)
                        throw protocol_error("server offered no SASL mechanism this client knows");
                    // The user name goes in the startup packet, so SCRAM's own
                    // n= attribute is left empty, as PostgreSQL expects.
                    scram.emplace(std::string_view{}, p.password);
                    encode_sasl_initial(out_, "SCRAM-SHA-256", scram->client_first());
                    trace_.record(direction::to_server, "SASLInitialResponse", out_.size(),
                                  "SCRAM-SHA-256");
                    co_await flush();
                    break;
                }
                case auth_kind::sasl_continue: {
                    if (!scram) throw protocol_error("SASLContinue without a SASL exchange");
                    auto final_message = scram->client_final(a.data);
                    encode_sasl_response(out_, final_message);
                    trace_.record(direction::to_server, "SASLResponse", out_.size(), "client-final");
                    co_await flush();
                    break;
                }
                case auth_kind::sasl_final: {
                    if (!scram || !scram->verify_server_final(a.data)) {
                        poisoned_ = true;
                        throw protocol_error("SCRAM server signature did not verify");
                    }
                    break;
                }
                default:
                    throw protocol_error("authentication method " +
                                         std::to_string(static_cast<int>(a.kind)) +
                                         " is not implemented");
            }
            continue;
        }

        if (tag == backend::parameter_status) {
            byte_reader r{f.body};
            std::string k(r.cstr());
            std::string v(r.cstr());
            trace_in(trace_, f, k + "=" + v);
            server_params_.emplace_back(std::move(k), std::move(v));
            consume(f);
            continue;
        }
        if (tag == backend::backend_key_data) {
            byte_reader r{f.body};
            backend_pid_ = r.i32be();
            backend_key_ = r.i32be();
            trace_in(trace_, f, "pid=" + std::to_string(backend_pid_));
            consume(f);
            continue;
        }
        if (tag == backend::ready_for_query) {
            tx_status_ = decode_ready_for_query(f.body);
            trace_in(trace_, f, std::string(1, tx_status_));
            consume(f);
            co_return;
        }
        if (tag == backend::notice_response) {
            trace_in(trace_, f);
            consume(f);
            continue;
        }
        trace_in(trace_, f);
        consume(f);
    }
}

std::string connection::parameter(const std::string& name) const {
    for (const auto& [k, v] : server_params_)
        if (k == name) return v;
    return {};
}

task<query_result> connection::simple_query(std::string_view sql, row_callback on_row) {
    if (!is_usable()) throw io_error("connection is not usable");
    out_.clear();
    encode_query(out_, sql);
    trace_.record(direction::to_server, "Query", out_.size(), std::string(sql));
    co_await flush();

    query_result result;
    std::optional<server_error> failure;
    std::vector<field_view> row;

    for (;;) {
        auto f = co_await read_message();
        auto tag = static_cast<backend>(f.tag);
        switch (tag) {
            case backend::row_description:
                result.columns = decode_row_description(f.body);
                trace_in(trace_, f, std::to_string(result.columns.size()) + " columns");
                break;
            case backend::data_row:
                decode_data_row(f.body, result.columns, row);
                ++result.rows;
                if (on_row) on_row(result.columns, row);
                trace_in(trace_, f);
                break;
            case backend::command_complete: {
                auto t = decode_command_complete(f.body);
                result.command = t.text;
                result.rows_affected = t.rows;
                trace_in(trace_, f, t.text);
                break;
            }
            case backend::empty_query_response:
                trace_in(trace_, f);
                break;
            case backend::error_response:
                failure = decode_error(f.body);
                trace_in(trace_, f, failure->sqlstate);
                break;
            case backend::ready_for_query:
                tx_status_ = decode_ready_for_query(f.body);
                trace_in(trace_, f, std::string(1, tx_status_));
                consume(f);
                if (failure) throw server_exception(std::move(*failure));
                co_return result;
            default:
                trace_in(trace_, f);
                break;
        }
        consume(f);
    }
}

task<query_result> connection::execute(std::string_view sql, param_list values,
                                       wire_format result_format, row_callback on_row) {
    if (!is_usable()) throw io_error("connection is not usable");
    co_return co_await run_extended(sql, values, result_format, on_row, /*allow_retry=*/true);
}

task<query_result> connection::run_extended(std::string_view sql, const param_list& values,
                                            wire_format fmt, const row_callback& on_row,
                                            bool allow_retry) {
    std::string key(sql);
    auto* cached = statements_.find(key);

    out_.clear();
    std::string name;
    bool freshly_parsed = false;
    if (cached) {
        name = cached->name;
    } else {
        name = "conduit_s" + std::to_string(++statement_counter_);
        encode_parse(out_, name, sql, {});
        trace_.record(direction::to_server, "Parse", out_.size(), name + ": " + std::string(sql));
        auto before = out_.size();
        encode_describe(out_, 'S', name);
        trace_.record(direction::to_server, "Describe", out_.size() - before, "statement " + name);
        freshly_parsed = true;
    }

    auto before_bind = out_.size();
    encode_bind(out_, "", name, values, fmt);
    trace_.record(direction::to_server, "Bind", out_.size() - before_bind,
                  std::to_string(values.size()) + " parameters, " +
                      (fmt == wire_format::binary ? "binary" : "text") + " results");
    auto before_exec = out_.size();
    encode_execute(out_, "", 0);
    trace_.record(direction::to_server, "Execute", out_.size() - before_exec, "unlimited rows");
    auto before_sync = out_.size();
    encode_sync(out_);
    trace_.record(direction::to_server, "Sync", out_.size() - before_sync);

    co_await flush();

    query_result result;
    if (cached) result.columns = cached->columns;
    std::size_t param_count = cached ? cached->param_count : 0;

    std::optional<server_error> failure;
    std::vector<field_view> row;
    bool described = false;

    for (;;) {
        auto f = co_await read_message();
        auto tag = static_cast<backend>(f.tag);
        switch (tag) {
            case backend::parse_complete:
                trace_in(trace_, f);
                break;
            case backend::parameter_description: {
                byte_reader r{f.body};
                param_count = r.be16();
                trace_in(trace_, f, std::to_string(param_count) + " parameters");
                break;
            }
            case backend::row_description:
                result.columns = decode_row_description(f.body);
                described = true;
                trace_in(trace_, f, std::to_string(result.columns.size()) + " columns");
                break;
            case backend::no_data:
                described = true;
                trace_in(trace_, f);
                break;
            case backend::bind_complete:
                trace_in(trace_, f);
                break;
            case backend::data_row:
                // Describe reports the format the statement was prepared with,
                // which is text. The actual format of the values is the one
                // asked for in Bind, so it is applied here.
                for (auto& c : result.columns) c.format = fmt;
                decode_data_row(f.body, result.columns, row);
                ++result.rows;
                if (on_row) on_row(result.columns, row);
                trace_in(trace_, f);
                break;
            case backend::command_complete: {
                auto t = decode_command_complete(f.body);
                result.command = t.text;
                result.rows_affected = t.rows;
                trace_in(trace_, f, t.text);
                break;
            }
            case backend::portal_suspended:
            case backend::empty_query_response:
                trace_in(trace_, f);
                break;
            case backend::error_response:
                failure = decode_error(f.body);
                trace_in(trace_, f, failure->sqlstate);
                break;
            case backend::ready_for_query: {
                tx_status_ = decode_ready_for_query(f.body);
                trace_in(trace_, f, std::string(1, tx_status_));
                consume(f);

                if (failure) {
                    // 26000 is "invalid_sql_statement_name": the server no
                    // longer has the statement this client believes it cached,
                    // which happens after DISCARD ALL or a server restart behind
                    // a pooler. Drop the entry and run the whole flow again,
                    // once, so the caller never sees a stale cache.
                    if (failure->sqlstate == "26000" && cached && allow_retry) {
                        statements_.erase(key);
                        co_return co_await run_extended(sql, values, fmt, on_row, false);
                    }
                    throw server_exception(std::move(*failure));
                }

                if (freshly_parsed && described) {
                    auto evicted = statements_.put(
                        key, prepared_statement{name, result.columns, param_count});
                    if (evicted) {
                        // The evicted statement still exists on the server.
                        out_.clear();
                        encode_close(out_, 'S', evicted->second.name);
                        encode_sync(out_);
                        trace_.record(direction::to_server, "Close", out_.size(),
                                      "statement " + evicted->second.name);
                        co_await flush();
                        for (;;) {
                            auto g = co_await read_message();
                            bool ready = static_cast<backend>(g.tag) == backend::ready_for_query;
                            if (ready) tx_status_ = decode_ready_for_query(g.body);
                            trace_in(trace_, g);
                            consume(g);
                            if (ready) break;
                        }
                    }
                }
                co_return result;
            }
            default:
                trace_in(trace_, f);
                break;
        }
        consume(f);
    }
}

task<bool> connection::ping() {
    if (!is_usable()) co_return false;
    try {
        auto r = co_await simple_query("SELECT 1");
        co_return r.rows == 1;
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
            out_.clear();
            encode_terminate(out_);
            trace_.record(direction::to_server, "Terminate", out_.size());
            co_await write_all(*loop_, sock_, tls_, byte_span(out_));
            out_.clear();
        } catch (const io_error&) {
            // The peer may already be gone. Closing is still the right move.
        }
    }
    tls_.close();
    sock_.close();
    open_ = false;
    co_return;
}

}  // namespace conduit::pg
