// A PostgreSQL connection: the codec bolted to a socket and an event loop.
//
// Every operation is a coroutine. Nothing here blocks a thread; a query that is
// waiting for the server suspends and the loop runs something else.
#pragma once

#include <chrono>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "conduit/lru_cache.hpp"
#include "conduit/net.hpp"
#include "conduit/pg/protocol.hpp"
#include "conduit/row_map.hpp"
#include "conduit/trace.hpp"

namespace conduit::pg {

// An error the server reported by the rules of the protocol. The connection
// stays usable after this: the server resynchronises at the next Sync, and the
// client has already read up to ReadyForQuery before the exception is thrown.
class server_exception : public std::runtime_error {
public:
    explicit server_exception(server_error e)
        : std::runtime_error(e.summary()), info(std::move(e)) {}
    server_error info;
};

struct connect_params {
    std::string host = "127.0.0.1";
    std::uint16_t port = 5432;
    std::string user = "postgres";
    std::string password;
    std::string database;
    std::vector<std::pair<std::string, std::string>> options;
    // Size of the per connection prepared statement cache. Zero disables
    // eviction bookkeeping entirely, which is how the benchmark measures what
    // the cache is worth.
    std::size_t statement_cache_size = 32;
};

struct query_result {
    std::vector<column> columns;
    std::size_t rows = 0;
    std::int64_t rows_affected = -1;
    std::string command;
};

// Called once per row, with the column metadata and the field views. The views
// are valid for the duration of the call and not one byte longer: the next read
// from the socket may move the bytes they point into.
using row_callback = std::function<void(const std::vector<column>&, std::span<const field_view>)>;

// Parameters are sent in text format, the one representation every PostgreSQL
// type accepts without the client having to know the type OID first.
using param_list = std::vector<std::optional<std::string>>;

namespace detail {
inline void push_param(param_list& p, std::nullopt_t) { p.push_back(std::nullopt); }
inline void push_param(param_list& p, bool v) { p.push_back(v ? "t" : "f"); }
inline void push_param(param_list& p, const char* v) { p.push_back(std::string(v)); }
inline void push_param(param_list& p, std::string v) { p.push_back(std::move(v)); }
inline void push_param(param_list& p, std::string_view v) { p.push_back(std::string(v)); }
template <class T>
    requires std::is_arithmetic_v<T>
void push_param(param_list& p, T v) { p.push_back(std::to_string(v)); }
}  // namespace detail

template <class... Ts>
param_list params(Ts&&... values) {
    param_list p;
    p.reserve(sizeof...(Ts));
    (detail::push_param(p, std::forward<Ts>(values)), ...);
    return p;
}

// A statement that exists on the server under a generated name.
struct prepared_statement {
    std::string name;
    std::vector<column> columns;
    std::size_t param_count = 0;
};

class connection {
public:
    explicit connection(event_loop& loop) : loop_(&loop), statements_(32) {}
    connection(connection&&) noexcept = default;
    connection& operator=(connection&&) noexcept = default;
    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;

    task<void> open(connect_params p);
    task<void> close();

    // Simple query flow: one Query message, one round trip, no parameters and
    // no way to ask for binary results.
    task<query_result> simple_query(std::string_view sql, row_callback on_row = {});

    // Extended query flow: Parse, Bind, Describe, Execute, Sync. The statement
    // is cached by SQL text, so the second execution of the same text sends
    // neither Parse nor Describe.
    task<query_result> execute(std::string_view sql, param_list values = {},
                               wire_format result_format = wire_format::binary,
                               row_callback on_row = {});

    // Executes and maps every row onto T. Column names are resolved once, when
    // the first row arrives, and reused for the rest of the result set.
    template <mappable T>
    task<std::vector<T>> query_as(std::string_view sql, param_list values = {},
                                  wire_format fmt = wire_format::binary) {
        std::vector<T> out;
        std::optional<row_mapper<T>> mapper;
        co_await execute(sql, std::move(values), fmt,
                         [&](const std::vector<column>& cols, std::span<const field_view> row) {
                             if (!mapper) mapper.emplace(cols);
                             out.push_back((*mapper)(row));
                         });
        co_return out;
    }

    // A liveness probe that costs a real round trip on purpose: a socket that
    // still looks open says nothing about whether the backend is alive.
    task<bool> ping();

    bool is_open() const noexcept { return open_ && sock_.valid(); }
    // False once a protocol error or a transport failure has been seen. Such a
    // connection must not go back into a pool.
    bool is_usable() const noexcept { return open_ && !poisoned_ && sock_.valid(); }
    char transaction_status() const noexcept { return tx_status_; }

    message_trace& trace() noexcept { return trace_; }
    const message_trace& trace() const noexcept { return trace_; }

    const lru_cache<prepared_statement>& statement_cache() const noexcept { return statements_; }
    std::size_t cache_hits() const noexcept { return statements_.hits(); }
    std::size_t cache_misses() const noexcept { return statements_.misses(); }

    std::string parameter(const std::string& name) const;
    std::int32_t backend_pid() const noexcept { return backend_pid_; }
    event_loop& loop() noexcept { return *loop_; }

private:
    task<void> authenticate(const connect_params& p);
    task<frame> read_message();
    void consume(const frame& f) { buf_.consume(f.consumed); }
    task<void> flush();
    task<query_result> run_extended(std::string_view sql, const param_list& values,
                                    wire_format fmt, const row_callback& on_row,
                                    bool allow_retry);

    event_loop* loop_;
    tcp_socket sock_;
    recv_buffer buf_;
    std::vector<std::byte> out_;
    message_trace trace_;

    bool open_ = false;
    bool poisoned_ = false;
    char tx_status_ = 'I';
    std::int32_t backend_pid_ = 0;
    std::int32_t backend_key_ = 0;
    std::vector<std::pair<std::string, std::string>> server_params_;

    lru_cache<prepared_statement> statements_;
    std::uint64_t statement_counter_ = 0;
};

}  // namespace conduit::pg
