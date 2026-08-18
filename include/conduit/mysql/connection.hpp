// A MySQL connection. Same shape as the PostgreSQL one, deliberately not the
// same type: the two protocols agree on nothing below the surface, and forcing
// them under a common base class would push the difference into run time
// branches instead of leaving it where it belongs, in two separate codecs.
#pragma once

#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "conduit/mysql/protocol.hpp"
#include "conduit/net.hpp"
#include "conduit/row_map.hpp"
#include "conduit/trace.hpp"

namespace conduit::mysql {

class server_exception : public std::runtime_error {
public:
    explicit server_exception(err_packet e)
        : std::runtime_error(e.summary()), info(std::move(e)) {}
    err_packet info;
};

struct connect_params {
    std::string host = "127.0.0.1";
    std::uint16_t port = 3306;
    std::string user = "root";
    std::string password;
    std::string database;
};

struct query_result {
    std::vector<column> columns;
    std::size_t rows = 0;
    std::uint64_t affected_rows = 0;
    std::uint64_t last_insert_id = 0;
};

using row_callback = std::function<void(const std::vector<column>&, std::span<const field_view>)>;

class connection {
public:
    explicit connection(event_loop& loop) : loop_(&loop) {}
    connection(connection&&) noexcept = default;
    connection& operator=(connection&&) noexcept = default;
    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;

    task<void> open(connect_params p);
    task<void> close();

    // Text protocol query. Values arrive as text, which is why the decoders in
    // value.hpp accept both formats rather than assuming binary.
    task<query_result> query(std::string_view sql, row_callback on_row = {});

    template <mappable T>
    task<std::vector<T>> query_as(std::string_view sql) {
        std::vector<T> out;
        std::optional<row_mapper<T>> mapper;
        co_await query(sql, [&](const std::vector<column>& cols, std::span<const field_view> row) {
            if (!mapper) mapper.emplace(cols);
            out.push_back((*mapper)(row));
        });
        co_return out;
    }

    task<bool> ping();

    bool is_open() const noexcept { return open_ && sock_.valid(); }
    bool is_usable() const noexcept { return open_ && !poisoned_ && sock_.valid(); }

    message_trace& trace() noexcept { return trace_; }
    const message_trace& trace() const noexcept { return trace_; }

    const std::string& server_version() const noexcept { return server_version_; }
    std::uint32_t connection_id() const noexcept { return connection_id_; }
    event_loop& loop() noexcept { return *loop_; }

private:
    task<packet> read_packet();
    void consume(const packet& p) { buf_.consume(p.consumed); }
    task<void> send(std::uint8_t sequence, byte_span payload, const char* name,
                    std::string detail = {});
    task<void> authenticate(const connect_params& p, const handshake& h);

    event_loop* loop_;
    tcp_socket sock_;
    recv_buffer buf_;
    std::vector<std::byte> out_;
    message_trace trace_;

    bool open_ = false;
    bool poisoned_ = false;
    std::uint32_t capabilities_ = 0;
    std::uint32_t connection_id_ = 0;
    std::string server_version_;
};

}  // namespace conduit::mysql
