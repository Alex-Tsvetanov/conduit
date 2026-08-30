// Transport: a non blocking TCP socket and the event loop that decides which
// suspended coroutine to resume next.
//
// Platform specific code is confined to src/net.cpp. Everything above this
// header sees one handle type and three verbs: try_read, try_write, wait.
#pragma once

#include <chrono>
#include <coroutine>
#include <cstdint>
#include <functional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "conduit/bytes.hpp"
#include "conduit/task.hpp"

namespace conduit {

// Socket level failure: refused connection, reset, name that does not resolve.
// Distinct from protocol_error, because the byte stream was never wrong, it
// simply stopped.
class io_error : public std::runtime_error {
public:
    explicit io_error(const std::string& what) : std::runtime_error(what) {}
};

#ifdef _WIN32
using native_handle = std::uintptr_t;
inline constexpr native_handle invalid_handle = static_cast<native_handle>(~0ull);
#else
using native_handle = int;
inline constexpr native_handle invalid_handle = -1;
#endif

// The three outcomes of a non blocking transfer, kept apart because the caller
// treats them completely differently: `ok` continues, `would_block` suspends,
// `closed` retires the connection.
enum class io_status { ok, would_block, closed };

struct io_result {
    io_status status = io_status::ok;
    std::size_t bytes = 0;
    // TLS: SSL_read can need the socket writable, and SSL_write can need it
    // readable. Plaintext I/O leaves this false on a read and true on a write.
    bool wait_for_write = false;
};

class tls_engine;

class tcp_socket {
public:
    tcp_socket() noexcept = default;
    ~tcp_socket();
    tcp_socket(tcp_socket&& o) noexcept;
    tcp_socket& operator=(tcp_socket&& o) noexcept;
    tcp_socket(const tcp_socket&) = delete;
    tcp_socket& operator=(const tcp_socket&) = delete;

    // Resolves and starts a non blocking connect. Returns true when the connect
    // already completed (a loopback connect usually does), false when the caller
    // must wait for the socket to become writable.
    bool start_connect(std::string_view host, std::uint16_t port);
    // Reads SO_ERROR once the socket reports writable. Throws on failure.
    void finish_connect();

    io_result try_read(std::span<std::byte> into);
    io_result try_write(byte_span from);

    void close() noexcept;
    bool valid() const noexcept { return h_ != invalid_handle; }
    native_handle native() const noexcept { return h_; }

    void set_no_delay(bool on);

    // Takes ownership of an already open handle. The listener uses it after
    // accept(); nothing else should.
    void adopt_handle(native_handle h) noexcept { close(); h_ = h; }

private:
    native_handle h_ = invalid_handle;
};

// A listening socket. Only the tests use it, to build a real pair of connected
// sockets on loopback so the event loop is exercised without a database.
class tcp_listener {
public:
    tcp_listener() noexcept = default;
    ~tcp_listener();
    tcp_listener(tcp_listener&&) noexcept;
    tcp_listener& operator=(tcp_listener&&) noexcept;
    tcp_listener(const tcp_listener&) = delete;
    tcp_listener& operator=(const tcp_listener&) = delete;

    // Binds to 127.0.0.1 on an ephemeral port and returns the chosen port.
    std::uint16_t bind_loopback();
    // Blocking accept. Test only, so blocking is acceptable here.
    tcp_socket accept();
    void close() noexcept;
    native_handle native() const noexcept { return h_; }

private:
    native_handle h_ = invalid_handle;
};

// --- event loop -------------------------------------------------------------
//
// ponytail: readiness is polled with select(). It is O(registered handles) per
// pass and capped at FD_SETSIZE, which is 64 on Windows by default. That ceiling
// is above any pool size this project measures, and select is the only readiness
// call that is identical on Windows and POSIX. Swap in epoll and IOCP behind the
// same three methods if the handle count ever matters.
class event_loop {
public:
    enum class wait_result { ready, timed_out };

    struct io_awaiter {
        event_loop* loop;
        native_handle handle;
        bool for_read;
        std::chrono::steady_clock::time_point deadline{};
        bool has_deadline = false;
        bool timed_out = false;
        std::coroutine_handle<> co{};

        bool await_ready() const noexcept { return false; }
        void await_suspend(std::coroutine_handle<> h);
        wait_result await_resume() const noexcept {
            return timed_out ? wait_result::timed_out : wait_result::ready;
        }
    };

    struct timer_awaiter {
        event_loop* loop;
        std::chrono::steady_clock::time_point deadline;
        std::coroutine_handle<> co{};
        bool await_ready() const noexcept {
            return deadline <= std::chrono::steady_clock::now();
        }
        void await_suspend(std::coroutine_handle<> h);
        void await_resume() const noexcept {}
    };

    io_awaiter wait_readable(native_handle h) { return {this, h, true}; }
    io_awaiter wait_writable(native_handle h) { return {this, h, false}; }
    io_awaiter wait_readable_for(native_handle h, std::chrono::milliseconds timeout) {
        return {this, h, true, std::chrono::steady_clock::now() + timeout, true};
    }
    timer_awaiter sleep_for(std::chrono::milliseconds d) {
        return {this, std::chrono::steady_clock::now() + d};
    }

    // Runs one unit of work. Returns false when there is nothing left to do.
    bool step();
    // Runs until nothing is pending.
    void run() { while (step()) {} }

    // Drives one task to completion, returning its value. This is the only
    // bridge between ordinary code and the coroutine world.
    template <class T>
    T block_on(task<T> t);

    // Starts a task without waiting for it. The loop keeps it alive.
    void spawn(task<void> t);

    std::size_t pending() const noexcept {
        return ready_.size() + waiters_.size() + timers_.size() + callbacks_.size();
    }

    // Only for the awaiters and for the pool's condition queue.
    void schedule(std::coroutine_handle<> h) { ready_.push_back(h); }
    void add_waiter(io_awaiter* w) { waiters_.push_back(w); }
    void add_timer(timer_awaiter* t) { timers_.push_back(t); }

    // Runs a callback at a deadline. The connection pool needs this because a
    // coroutine cannot await a slot and a timeout at the same time: one of the
    // two has to arrive as a callback that settles the other.
    void call_at(std::chrono::steady_clock::time_point when, std::function<void()> fn) {
        callbacks_.push_back({when, std::move(fn)});
    }

private:
    struct callback_timer {
        std::chrono::steady_clock::time_point deadline;
        std::function<void()> fn;
    };

    std::vector<std::coroutine_handle<>> ready_;
    std::vector<io_awaiter*> waiters_;
    std::vector<timer_awaiter*> timers_;
    std::vector<callback_timer> callbacks_;
};

namespace detail {
template <class T>
detached_task run_root(task<T> t, T* out, std::exception_ptr* err, bool* done) {
    try {
        *out = co_await std::move(t);
    } catch (...) {
        *err = std::current_exception();
    }
    *done = true;
}
inline detached_task run_root_void(task<void> t, std::exception_ptr* err, bool* done) {
    try {
        co_await std::move(t);
    } catch (...) {
        *err = std::current_exception();
    }
    *done = true;
}
inline detached_task run_spawned(task<void> t) { co_await std::move(t); }
}  // namespace detail

template <class T>
T event_loop::block_on(task<T> t) {
    if constexpr (std::is_void_v<T>) {
        std::exception_ptr err;
        bool done = false;
        detail::run_root_void(std::move(t), &err, &done);
        while (!done && step()) {}
        if (err) std::rethrow_exception(err);
        if (!done) throw io_error("event loop ran dry before the task finished");
    } else {
        T out{};
        std::exception_ptr err;
        bool done = false;
        detail::run_root(std::move(t), &out, &err, &done);
        while (!done && step()) {}
        if (err) std::rethrow_exception(err);
        if (!done) throw io_error("event loop ran dry before the task finished");
        return out;
    }
}

inline void event_loop::spawn(task<void> t) { detail::run_spawned(std::move(t)); }

// Reads exactly into the buffer's writable tail, suspending while the socket is
// dry. Returns false when the peer closed the connection: the caller decides
// whether that is an error or the expected end of a stream.
task<bool> read_some(event_loop& loop, tcp_socket& sock, recv_buffer& buf,
                     std::size_t want = 4096);
task<bool> read_some(event_loop& loop, tcp_socket& sock, tls_engine& tls,
                     recv_buffer& buf, std::size_t want = 4096);

// Writes the whole span, suspending as often as the kernel makes it wait.
task<void> write_all(event_loop& loop, tcp_socket& sock, byte_span data);
task<void> write_all(event_loop& loop, tcp_socket& sock, tls_engine& tls, byte_span data);

// Connects, suspending until the handshake at the TCP level is done.
task<void> connect(event_loop& loop, tcp_socket& sock, std::string_view host,
                   std::uint16_t port);

}  // namespace conduit
