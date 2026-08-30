#include "conduit/net.hpp"
#include "conduit/tls.hpp"

#include <algorithm>
#include <cstring>
#include <thread>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
   using socklen_t_compat = int;
#else
#  include <arpa/inet.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
   using socklen_t_compat = socklen_t;
#endif

namespace conduit {
namespace {

#ifdef _WIN32
// One WSAStartup for the process. A static object is enough: the standard
// guarantees the constructor runs before main and the destructor after it.
struct winsock_init {
    winsock_init() {
        WSADATA d;
        if (WSAStartup(MAKEWORD(2, 2), &d) != 0) throw io_error("WSAStartup failed");
    }
    ~winsock_init() { WSACleanup(); }
};
const winsock_init& winsock() {
    static winsock_init w;
    return w;
}

int last_error() { return WSAGetLastError(); }
bool is_would_block(int e) { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
bool is_in_progress(int e) { return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS; }
void close_native(native_handle h) { ::closesocket(static_cast<SOCKET>(h)); }
void set_non_blocking(native_handle h) {
    u_long on = 1;
    if (::ioctlsocket(static_cast<SOCKET>(h), FIONBIO, &on) != 0)
        throw io_error("ioctlsocket(FIONBIO) failed");
}
#else
void winsock() {}
int last_error() { return errno; }
bool is_would_block(int e) { return e == EAGAIN || e == EWOULDBLOCK; }
bool is_in_progress(int e) { return e == EINPROGRESS; }
void close_native(native_handle h) { ::close(h); }
void set_non_blocking(native_handle h) {
    int flags = ::fcntl(h, F_GETFL, 0);
    if (flags < 0 || ::fcntl(h, F_SETFL, flags | O_NONBLOCK) < 0)
        throw io_error("fcntl(O_NONBLOCK) failed");
}
#endif

std::string errno_text(int e) { return "errno " + std::to_string(e); }

}  // namespace

// --- tcp_socket -------------------------------------------------------------

tcp_socket::~tcp_socket() { close(); }

tcp_socket::tcp_socket(tcp_socket&& o) noexcept : h_(o.h_) { o.h_ = invalid_handle; }

tcp_socket& tcp_socket::operator=(tcp_socket&& o) noexcept {
    if (this != &o) {
        close();
        h_ = o.h_;
        o.h_ = invalid_handle;
    }
    return *this;
}

void tcp_socket::close() noexcept {
    if (h_ != invalid_handle) {
        close_native(h_);
        h_ = invalid_handle;
    }
}

bool tcp_socket::start_connect(std::string_view host, std::uint16_t port) {
    winsock();
    close();

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string host_s(host);
    std::string port_s = std::to_string(port);
    addrinfo* res = nullptr;
    if (::getaddrinfo(host_s.c_str(), port_s.c_str(), &hints, &res) != 0 || res == nullptr)
        throw io_error("cannot resolve " + host_s + ":" + port_s);

    native_handle h = invalid_handle;
    int connect_err = 0;
    bool connected = false;
    for (addrinfo* a = res; a != nullptr; a = a->ai_next) {
        auto s = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
#ifdef _WIN32
        if (s == INVALID_SOCKET) continue;
        h = static_cast<native_handle>(s);
#else
        if (s < 0) continue;
        h = s;
#endif
        set_non_blocking(h);
        int rc = ::connect(
#ifdef _WIN32
            static_cast<SOCKET>(h),
#else
            h,
#endif
            a->ai_addr, static_cast<socklen_t_compat>(a->ai_addrlen));
        if (rc == 0) { connected = true; break; }
        connect_err = last_error();
        if (is_in_progress(connect_err)) break;
        close_native(h);
        h = invalid_handle;
    }
    ::freeaddrinfo(res);

    if (h == invalid_handle)
        throw io_error("connect to " + host_s + ":" + port_s + " failed, " +
                       errno_text(connect_err));
    h_ = h;
    return connected;
}

void tcp_socket::finish_connect() {
    int err = 0;
    socklen_t_compat len = sizeof(err);
    if (::getsockopt(
#ifdef _WIN32
            static_cast<SOCKET>(h_),
#else
            h_,
#endif
            SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) != 0)
        throw io_error("getsockopt(SO_ERROR) failed");
    if (err != 0) throw io_error("connect failed, " + errno_text(err));
}

void tcp_socket::set_no_delay(bool on) {
    int flag = on ? 1 : 0;
    ::setsockopt(
#ifdef _WIN32
        static_cast<SOCKET>(h_),
#else
        h_,
#endif
        IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&flag), sizeof(flag));
}

io_result tcp_socket::try_read(std::span<std::byte> into) {
    if (into.empty()) return {io_status::ok, 0};
    auto n = ::recv(
#ifdef _WIN32
        static_cast<SOCKET>(h_), reinterpret_cast<char*>(into.data()),
        static_cast<int>(into.size()),
#else
        h_, into.data(), into.size(),
#endif
        0);
    if (n > 0) return {io_status::ok, static_cast<std::size_t>(n)};
    if (n == 0) return {io_status::closed, 0};
    int e = last_error();
    if (is_would_block(e)) return {io_status::would_block, 0};
#ifdef _WIN32
    if (e == WSAECONNRESET || e == WSAECONNABORTED) return {io_status::closed, 0};
#else
    if (e == ECONNRESET || e == EPIPE) return {io_status::closed, 0};
    if (e == EINTR) return {io_status::would_block, 0};
#endif
    throw io_error("recv failed, " + errno_text(e));
}

io_result tcp_socket::try_write(byte_span from) {
    if (from.empty()) return {io_status::ok, 0};
    auto n = ::send(
#ifdef _WIN32
        static_cast<SOCKET>(h_), reinterpret_cast<const char*>(from.data()),
        static_cast<int>(from.size()),
#else
        h_, from.data(), from.size(),
#endif
        0);
    if (n > 0) return {io_status::ok, static_cast<std::size_t>(n)};
    int e = last_error();
    if (is_would_block(e)) return {io_status::would_block, 0, true};
#ifdef _WIN32
    if (e == WSAECONNRESET || e == WSAECONNABORTED) return {io_status::closed, 0};
#else
    if (e == ECONNRESET || e == EPIPE) return {io_status::closed, 0};
    if (e == EINTR) return {io_status::would_block, 0, true};
#endif
    throw io_error("send failed, " + errno_text(e));
}

// --- tcp_listener -----------------------------------------------------------

tcp_listener::~tcp_listener() { close(); }
tcp_listener::tcp_listener(tcp_listener&& o) noexcept : h_(o.h_) { o.h_ = invalid_handle; }
tcp_listener& tcp_listener::operator=(tcp_listener&& o) noexcept {
    if (this != &o) { close(); h_ = o.h_; o.h_ = invalid_handle; }
    return *this;
}
void tcp_listener::close() noexcept {
    if (h_ != invalid_handle) { close_native(h_); h_ = invalid_handle; }
}

std::uint16_t tcp_listener::bind_loopback() {
    winsock();
    auto s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
    if (s == INVALID_SOCKET) throw io_error("socket() failed");
    h_ = static_cast<native_handle>(s);
#else
    if (s < 0) throw io_error("socket() failed");
    h_ = s;
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    if (::bind(
#ifdef _WIN32
            static_cast<SOCKET>(h_),
#else
            h_,
#endif
            reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
        throw io_error("bind failed, " + errno_text(last_error()));
    if (::listen(
#ifdef _WIN32
            static_cast<SOCKET>(h_),
#else
            h_,
#endif
            8) != 0)
        throw io_error("listen failed, " + errno_text(last_error()));

    sockaddr_in bound{};
    socklen_t_compat len = sizeof(bound);
    if (::getsockname(
#ifdef _WIN32
            static_cast<SOCKET>(h_),
#else
            h_,
#endif
            reinterpret_cast<sockaddr*>(&bound), &len) != 0)
        throw io_error("getsockname failed");
    return ::ntohs(bound.sin_port);
}

tcp_socket tcp_listener::accept() {
    auto s = ::accept(
#ifdef _WIN32
        static_cast<SOCKET>(h_),
#else
        h_,
#endif
        nullptr, nullptr);
    tcp_socket out;
#ifdef _WIN32
    if (s == INVALID_SOCKET) throw io_error("accept failed, " + errno_text(last_error()));
    auto h = static_cast<native_handle>(s);
#else
    if (s < 0) throw io_error("accept failed, " + errno_text(last_error()));
    auto h = s;
#endif
    set_non_blocking(h);
    out.adopt_handle(h);
    return out;
}

// --- event loop -------------------------------------------------------------

void event_loop::io_awaiter::await_suspend(std::coroutine_handle<> h) {
    co = h;
    loop->add_waiter(this);
}

void event_loop::timer_awaiter::await_suspend(std::coroutine_handle<> h) {
    co = h;
    loop->add_timer(this);
}

bool event_loop::step() {
    if (!ready_.empty()) {
        auto h = ready_.front();
        ready_.erase(ready_.begin());
        h.resume();
        return true;
    }
    if (waiters_.empty() && timers_.empty() && callbacks_.empty()) return false;

    using clock = std::chrono::steady_clock;
    auto now = clock::now();

    // Earliest deadline across both waiter kinds decides how long select blocks.
    bool has_deadline = false;
    clock::time_point earliest{};
    for (auto* w : waiters_)
        if (w->has_deadline && (!has_deadline || w->deadline < earliest)) {
            earliest = w->deadline;
            has_deadline = true;
        }
    for (auto* t : timers_)
        if (!has_deadline || t->deadline < earliest) {
            earliest = t->deadline;
            has_deadline = true;
        }
    for (const auto& c : callbacks_)
        if (!has_deadline || c.deadline < earliest) {
            earliest = c.deadline;
            has_deadline = true;
        }

    if (!waiters_.empty()) {
        fd_set rfds, wfds, efds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&efds);
        native_handle max_h = 0;
        std::size_t registered = 0;
        for (auto* w : waiters_) {
            if (registered >= FD_SETSIZE) break;  // ponytail: see the note in net.hpp
            ++registered;
#ifdef _WIN32
            auto s = static_cast<SOCKET>(w->handle);
#else
            auto s = w->handle;
            if (w->handle > max_h) max_h = w->handle;
#endif
            FD_SET(s, w->for_read ? &rfds : &wfds);
            // A connect that is refused is reported by Winsock in the exception
            // set and nowhere else. Without this the loop never wakes and the
            // caller hangs instead of being told the connection failed. POSIX
            // reports the same event as writable, so the extra registration is
            // needed only on Windows and is harmless elsewhere.
            if (!w->for_read) FD_SET(s, &efds);
        }

        timeval tv{};
        timeval* tvp = nullptr;
        if (has_deadline) {
            auto d = std::chrono::duration_cast<std::chrono::microseconds>(earliest - now);
            if (d.count() < 0) d = std::chrono::microseconds{0};
            tv.tv_sec = static_cast<decltype(tv.tv_sec)>(d.count() / 1000000);
            tv.tv_usec = static_cast<decltype(tv.tv_usec)>(d.count() % 1000000);
            tvp = &tv;
        }

        int rc = ::select(static_cast<int>(max_h) + 1, &rfds, &wfds, &efds, tvp);
        if (rc < 0) {
#ifndef _WIN32
            if (errno == EINTR) return true;
#endif
            throw io_error("select failed, " + errno_text(last_error()));
        }

        now = clock::now();
        std::vector<io_awaiter*> still;
        still.reserve(waiters_.size());
        for (auto* w : waiters_) {
#ifdef _WIN32
            auto s = static_cast<SOCKET>(w->handle);
#else
            auto s = w->handle;
#endif
            bool fired = FD_ISSET(s, w->for_read ? &rfds : &wfds) != 0 ||
                         (!w->for_read && FD_ISSET(s, &efds) != 0);
            bool expired = w->has_deadline && w->deadline <= now;
            if (fired || expired) {
                w->timed_out = !fired && expired;
                ready_.push_back(w->co);
            } else {
                still.push_back(w);
            }
        }
        waiters_.swap(still);
    } else {
        // Timers only. Sleeping the thread is correct here: nothing else in this
        // loop can become runnable while no handle is registered.
        auto d = earliest - now;
        if (d > clock::duration::zero())
            std::this_thread::sleep_for(d);
        now = clock::now();
    }

    std::vector<timer_awaiter*> still_timers;
    still_timers.reserve(timers_.size());
    for (auto* t : timers_) {
        if (t->deadline <= now) ready_.push_back(t->co);
        else still_timers.push_back(t);
    }
    timers_.swap(still_timers);

    // Callbacks are moved out before being run: one of them may register
    // another, and appending to the vector being iterated would invalidate it.
    std::vector<callback_timer> due;
    std::vector<callback_timer> still_callbacks;
    for (auto& c : callbacks_) {
        if (c.deadline <= now) due.push_back(std::move(c));
        else still_callbacks.push_back(std::move(c));
    }
    callbacks_.swap(still_callbacks);
    for (auto& c : due) c.fn();

    return true;
}

// --- transfer helpers -------------------------------------------------------

task<bool> read_some(event_loop& loop, tcp_socket& sock, recv_buffer& buf, std::size_t want) {
    for (;;) {
        auto dst = buf.writable(want);
        auto r = sock.try_read(dst);
        if (r.status == io_status::ok) {
            buf.committed(r.bytes);
            co_return true;
        }
        if (r.status == io_status::closed) co_return false;
        co_await loop.wait_readable(sock.native());
    }
}

task<void> write_all(event_loop& loop, tcp_socket& sock, byte_span data) {
    std::size_t sent = 0;
    while (sent < data.size()) {
        auto r = sock.try_write(data.subspan(sent));
        if (r.status == io_status::ok) {
            sent += r.bytes;
            continue;
        }
        if (r.status == io_status::closed) throw io_error("peer closed while writing");
        co_await loop.wait_writable(sock.native());
    }
    co_return;
}

task<bool> read_some(event_loop& loop, tcp_socket& sock, tls_engine& tls,
                     recv_buffer& buf, std::size_t want) {
    if (!tls.active()) co_return co_await read_some(loop, sock, buf, want);
    for (;;) {
        auto dst = buf.writable(want);
        auto r = tls.try_read(dst);
        if (r.status == io_status::ok) {
            buf.committed(r.bytes);
            co_return true;
        }
        if (r.status == io_status::closed) co_return false;
        if (r.wait_for_write)
            co_await loop.wait_writable(sock.native());
        else
            co_await loop.wait_readable(sock.native());
    }
}

task<void> write_all(event_loop& loop, tcp_socket& sock, tls_engine& tls, byte_span data) {
    if (!tls.active()) {
        co_await write_all(loop, sock, data);
        co_return;
    }
    std::size_t sent = 0;
    while (sent < data.size()) {
        auto r = tls.try_write(data.subspan(sent));
        if (r.status == io_status::ok) {
            sent += r.bytes;
            continue;
        }
        if (r.status == io_status::closed) throw io_error("peer closed while writing");
        if (r.wait_for_write)
            co_await loop.wait_writable(sock.native());
        else
            co_await loop.wait_readable(sock.native());
    }
    co_return;
}

task<void> connect(event_loop& loop, tcp_socket& sock, std::string_view host,
                   std::uint16_t port) {
    if (!sock.start_connect(host, port)) {
        co_await loop.wait_writable(sock.native());
        sock.finish_connect();
    }
    sock.set_no_delay(true);
    co_return;
}

}  // namespace conduit
