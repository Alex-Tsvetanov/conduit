// TLS, optional. The library never vendors a TLS stack: OpenSSL is located
// with find_package(OpenSSL QUIET), the same rule as libpq. A build without
// it still compiles; requesting TLS then is a clear error, and the tests skip
// rather than guess.
#pragma once

#include <span>
#include <string>
#include <string_view>

#include "conduit/net.hpp"

namespace conduit {

struct tls_options {
    bool enabled = false;
    // Off unless asked. The compose servers use a self-signed certificate, so
    // verification has to be an explicit choice together with `ca_file`.
    bool verify_peer = false;
    std::string ca_file;
    std::string cert_file;
    std::string key_file;
};

// True only when this build was linked against OpenSSL. Always safe to call.
bool tls_available() noexcept;

// Owns an OpenSSL client session for one socket. Empty until start() succeeds.
// After that, every byte on the socket has to go through try_read/try_write;
// mixing them with tcp_socket::try_read would desynchronise the record layer.
class tls_engine {
public:
    tls_engine() noexcept = default;
    ~tls_engine() { close(); }
    tls_engine(tls_engine&& o) noexcept : ctx_(o.ctx_), ssl_(o.ssl_) {
        o.ctx_ = o.ssl_ = nullptr;
    }
    tls_engine& operator=(tls_engine&& o) noexcept {
        if (this != &o) {
            close();
            ctx_ = o.ctx_;
            ssl_ = o.ssl_;
            o.ctx_ = o.ssl_ = nullptr;
        }
        return *this;
    }
    tls_engine(const tls_engine&) = delete;
    tls_engine& operator=(const tls_engine&) = delete;

    bool active() const noexcept { return ssl_ != nullptr; }

    // Prepares the client session. Does not block; handshake_step() is the
    // part that talks to the peer.
    void start(native_handle h, const tls_options& opt, std::string_view server_name);
    io_result handshake_step();
    io_result try_read(std::span<std::byte> into);
    io_result try_write(byte_span from);
    void close() noexcept;

private:
    void* ctx_ = nullptr;  // SSL_CTX*, only touched in src/tls.cpp
    void* ssl_ = nullptr;  // SSL*
};

// Runs the TLS handshake, suspending on WANT_READ / WANT_WRITE. Call this
// after the protocol-specific SSL request has been answered, and before any
// further protocol bytes.
task<void> handshake_tls(event_loop& loop, tcp_socket& sock, tls_engine& tls,
                         const tls_options& opt, std::string_view server_name);

}  // namespace conduit
