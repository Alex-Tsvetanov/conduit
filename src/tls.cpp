#include "conduit/tls.hpp"

#include <limits>
#include <string>

#ifdef CONDUIT_HAS_OPENSSL
#  include <openssl/err.h>
#  include <openssl/ssl.h>
#  include <openssl/x509v3.h>
#endif

namespace conduit {
namespace {

#ifdef CONDUIT_HAS_OPENSSL

std::string openssl_error() {
    std::string out;
    char buf[256];
    for (;;) {
        unsigned long e = ERR_get_error();
        if (e == 0) break;
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!out.empty()) out += "; ";
        out += buf;
    }
    return out.empty() ? "unknown OpenSSL error" : out;
}

int as_int_len(std::size_t n) {
    auto max = static_cast<std::size_t>(std::numeric_limits<int>::max());
    return static_cast<int>(n > max ? max : n);
}

io_result map_ssl_io(SSL* ssl, int n, const char* what) {
    if (n > 0) return {io_status::ok, static_cast<std::size_t>(n)};
    int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_WANT_READ) return {io_status::would_block, 0, false};
    if (err == SSL_ERROR_WANT_WRITE) return {io_status::would_block, 0, true};
    if (err == SSL_ERROR_ZERO_RETURN) return {io_status::closed, 0};
    if (err == SSL_ERROR_SYSCALL && n == 0) return {io_status::closed, 0};
    throw io_error(std::string(what) + ": " + openssl_error());
}

bool looks_like_ip(std::string_view host) {
    if (host.empty()) return false;
    // SNI is a hostname. An IPv4/IPv6 literal is not one, and some stacks
    // reject setting the extension to an address.
    bool v4 = true;
    bool v6 = true;
    for (char c : host) {
        if (c != '.' && (c < '0' || c > '9')) v4 = false;
        if (c != ':' && (c < '0' || c > '9') && (c < 'a' || c > 'f') &&
            (c < 'A' || c > 'F'))
            v6 = false;
    }
    return (v4 && host.find('.') != std::string_view::npos) ||
           (v6 && host.find(':') != std::string_view::npos);
}

#endif

}  // namespace

bool tls_available() noexcept {
#ifdef CONDUIT_HAS_OPENSSL
    return true;
#else
    return false;
#endif
}

void tls_engine::start(native_handle h, const tls_options& opt, std::string_view server_name) {
#ifdef CONDUIT_HAS_OPENSSL
    close();
    ERR_clear_error();

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) throw io_error("SSL_CTX_new failed: " + openssl_error());
    ctx_ = ctx;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    if (opt.verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        if (!opt.ca_file.empty()) {
            if (SSL_CTX_load_verify_locations(ctx, opt.ca_file.c_str(), nullptr) != 1) {
                close();
                throw io_error("cannot load TLS CA file '" + opt.ca_file + "': " +
                               openssl_error());
            }
        } else if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            close();
            throw io_error("cannot load the system TLS trust store: " + openssl_error());
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }

    if (!opt.cert_file.empty()) {
        if (SSL_CTX_use_certificate_file(ctx, opt.cert_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            close();
            throw io_error("cannot load TLS client certificate: " + openssl_error());
        }
        const char* key = opt.key_file.empty() ? opt.cert_file.c_str() : opt.key_file.c_str();
        if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
            close();
            throw io_error("cannot load TLS client key: " + openssl_error());
        }
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        close();
        throw io_error("SSL_new failed: " + openssl_error());
    }
    ssl_ = ssl;
    SSL_set_connect_state(ssl);

#ifdef _WIN32
    BIO* bio = BIO_new_socket(static_cast<int>(h), BIO_NOCLOSE);
    if (!bio) {
        close();
        throw io_error("BIO_new_socket failed: " + openssl_error());
    }
    SSL_set_bio(ssl, bio, bio);
#else
    if (SSL_set_fd(ssl, h) != 1) {
        close();
        throw io_error("SSL_set_fd failed: " + openssl_error());
    }
#endif

    std::string name(server_name);
    if (!name.empty() && !looks_like_ip(name)) {
        if (SSL_set_tlsext_host_name(ssl, name.c_str()) != 1) {
            close();
            throw io_error("TLS SNI failed: " + openssl_error());
        }
    }
    if (opt.verify_peer && !name.empty()) {
        if (SSL_set1_host(ssl, name.c_str()) != 1) {
            close();
            throw io_error("TLS hostname check could not be set: " + openssl_error());
        }
    }
    (void)h;
#else
    (void)h;
    (void)opt;
    (void)server_name;
    throw io_error("TLS was requested but this build of Conduit was not linked against OpenSSL");
#endif
}

io_result tls_engine::handshake_step() {
#ifdef CONDUIT_HAS_OPENSSL
    auto* ssl = static_cast<SSL*>(ssl_);
    if (!ssl) throw io_error("TLS handshake without a session");
    ERR_clear_error();
    int rc = SSL_connect(ssl);
    if (rc == 1) return {io_status::ok, 0};
    int err = SSL_get_error(ssl, rc);
    if (err == SSL_ERROR_WANT_READ) return {io_status::would_block, 0, false};
    if (err == SSL_ERROR_WANT_WRITE) return {io_status::would_block, 0, true};
    throw io_error("TLS handshake failed: " + openssl_error());
#else
    throw io_error("TLS was requested but this build of Conduit was not linked against OpenSSL");
#endif
}

io_result tls_engine::try_read(std::span<std::byte> into) {
#ifdef CONDUIT_HAS_OPENSSL
    auto* ssl = static_cast<SSL*>(ssl_);
    if (!ssl) throw io_error("TLS read without a session");
    if (into.empty()) return {io_status::ok, 0};
    ERR_clear_error();
    int n = SSL_read(ssl, into.data(), as_int_len(into.size()));
    return map_ssl_io(ssl, n, "TLS read failed");
#else
    (void)into;
    throw io_error("TLS was requested but this build of Conduit was not linked against OpenSSL");
#endif
}

io_result tls_engine::try_write(byte_span from) {
#ifdef CONDUIT_HAS_OPENSSL
    auto* ssl = static_cast<SSL*>(ssl_);
    if (!ssl) throw io_error("TLS write without a session");
    if (from.empty()) return {io_status::ok, 0};
    ERR_clear_error();
    int n = SSL_write(ssl, from.data(), as_int_len(from.size()));
    return map_ssl_io(ssl, n, "TLS write failed");
#else
    (void)from;
    throw io_error("TLS was requested but this build of Conduit was not linked against OpenSSL");
#endif
}

void tls_engine::close() noexcept {
#ifdef CONDUIT_HAS_OPENSSL
    if (ssl_) {
        // One non-blocking shutdown attempt. Waiting for the close_notify
        // would need the event loop, and close() has to work from a destructor.
        SSL_shutdown(static_cast<SSL*>(ssl_));
        SSL_free(static_cast<SSL*>(ssl_));
        ssl_ = nullptr;
    }
    if (ctx_) {
        SSL_CTX_free(static_cast<SSL_CTX*>(ctx_));
        ctx_ = nullptr;
    }
#else
    ssl_ = nullptr;
    ctx_ = nullptr;
#endif
}

task<void> handshake_tls(event_loop& loop, tcp_socket& sock, tls_engine& tls,
                         const tls_options& opt, std::string_view server_name) {
    if (!tls_available())
        throw io_error(
            "TLS was requested but this build of Conduit was not linked against OpenSSL");
    try {
        tls.start(sock.native(), opt, server_name);
        for (;;) {
            auto r = tls.handshake_step();
            if (r.status == io_status::ok) co_return;
            if (r.status == io_status::closed)
                throw io_error("peer closed during TLS handshake");
            if (r.wait_for_write)
                co_await loop.wait_writable(sock.native());
            else
                co_await loop.wait_readable(sock.native());
        }
    } catch (...) {
        tls.close();
        throw;
    }
}

}  // namespace conduit
