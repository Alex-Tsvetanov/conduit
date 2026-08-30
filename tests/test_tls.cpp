// TLS without a database. The handshake is exercised over a loopback socket
// pair: one end is OpenSSL in this process, the other is conduit::tls_engine.
// When the library was built without OpenSSL the cases that need it skip.
#include <chrono>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <thread>

#ifdef _WIN32
#  include <process.h>
#  define conduit_getpid _getpid
#else
#  include <unistd.h>
#  define conduit_getpid getpid
#endif

#include "check.hpp"
#include "conduit/net.hpp"
#include "conduit/tls.hpp"

#ifdef CONDUIT_HAS_OPENSSL
#  include <openssl/evp.h>
#  include <openssl/pem.h>
#  include <openssl/ssl.h>
#  include <openssl/x509.h>
#endif

using namespace conduit;
using namespace std::chrono_literals;

namespace {

#ifdef CONDUIT_HAS_OPENSSL

struct ephemeral_cert {
    EVP_PKEY* key = nullptr;
    X509* cert = nullptr;
    ~ephemeral_cert() {
        if (cert) X509_free(cert);
        if (key) EVP_PKEY_free(key);
    }
};

ephemeral_cert make_self_signed() {
    ephemeral_cert out;
    out.key = EVP_RSA_gen(2048);
    if (!out.key) throw std::runtime_error("EVP_RSA_gen failed");
    out.cert = X509_new();
    if (!out.cert) throw std::runtime_error("X509_new failed");
    ASN1_INTEGER_set(X509_get_serialNumber(out.cert), 1);
    X509_gmtime_adj(X509_get_notBefore(out.cert), 0);
    X509_gmtime_adj(X509_get_notAfter(out.cert), 60 * 60 * 24);
    X509_set_pubkey(out.cert, out.key);
    X509_NAME* name = X509_get_subject_name(out.cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(out.cert, name);
    if (X509_sign(out.cert, out.key, EVP_sha256()) == 0)
        throw std::runtime_error("X509_sign failed");
    return out;
}

std::string write_ca(X509* cert) {
    auto path = (std::filesystem::temp_directory_path() /
                  ("conduit_tls_ca_" + std::to_string(conduit_getpid()) + ".pem"))
                     .string();
    FILE* f = std::fopen(path.c_str(), "w");
    if (!f) throw std::runtime_error("cannot write temporary CA file");
    int rc = PEM_write_X509(f, cert);
    std::fclose(f);
    if (rc != 1) throw std::runtime_error("PEM_write_X509 failed");
    return path;
}

struct socket_pair {
    tcp_listener listener;
    tcp_socket client;
    tcp_socket server;

    socket_pair() {
        auto port = listener.bind_loopback();
        client.start_connect("127.0.0.1", port);
        server = listener.accept();
        client.finish_connect();
    }
};

#endif

}  // namespace

CONDUIT_TEST(requesting_tls_without_openssl_is_a_clear_error) {
    if (tls_available()) CONDUIT_SKIP("OpenSSL is linked in this build");
    event_loop loop;
    tcp_socket sock;
    tls_engine tls;
    tls_options opt;
    opt.enabled = true;
    bool threw = false;
    try {
        loop.block_on(handshake_tls(loop, sock, tls, opt, "localhost"));
    } catch (const io_error& e) {
        threw = std::string(e.what()).find("OpenSSL") != std::string::npos;
    }
    CHECK(threw);
}

CONDUIT_TEST(tls_loopback_handshake_transfers_bytes) {
    if (!tls_available()) CONDUIT_SKIP("OpenSSL is not linked");
#ifndef CONDUIT_HAS_OPENSSL
    CONDUIT_SKIP("OpenSSL headers were not present at compile time");
#else
    auto creds = make_self_signed();
    socket_pair p;
    event_loop loop;

    std::exception_ptr server_err;
    std::thread server([&] {
        try {
            SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
            if (!ctx) throw std::runtime_error("SSL_CTX_new failed");
            SSL_CTX_use_certificate(ctx, creds.cert);
            SSL_CTX_use_PrivateKey(ctx, creds.key);
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, p.server.native());
            for (;;) {
                int rc = SSL_accept(ssl);
                if (rc == 1) break;
                int err = SSL_get_error(ssl, rc);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    std::this_thread::sleep_for(1ms);
                    continue;
                }
                throw std::runtime_error("SSL_accept failed");
            }
            const char* msg = "hello";
            while (SSL_write(ssl, msg, 5) <= 0) std::this_thread::sleep_for(1ms);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        } catch (...) {
            server_err = std::current_exception();
        }
    });

    tls_engine tls;
    tls_options opt;
    opt.enabled = true;
    opt.verify_peer = false;
    loop.block_on(handshake_tls(loop, p.client, tls, opt, "localhost"));
    recv_buffer buf;
    bool alive = loop.block_on(read_some(loop, p.client, tls, buf));
    server.join();
    if (server_err) std::rethrow_exception(server_err);
    CHECK(alive);
    CHECK_EQ(std::string(reinterpret_cast<const char*>(buf.readable().data()),
                         buf.readable_size()),
             std::string("hello"));
    CHECK(tls.active());
#endif
}

CONDUIT_TEST(tls_loopback_rejects_an_untrusted_certificate) {
    if (!tls_available()) CONDUIT_SKIP("OpenSSL is not linked");
#ifndef CONDUIT_HAS_OPENSSL
    CONDUIT_SKIP("OpenSSL headers were not present at compile time");
#else
    auto creds = make_self_signed();
    socket_pair p;
    event_loop loop;

    std::thread server([&] {
        SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
        SSL_CTX_use_certificate(ctx, creds.cert);
        SSL_CTX_use_PrivateKey(ctx, creds.key);
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, p.server.native());
        for (int i = 0; i < 200; ++i) {
            int rc = SSL_accept(ssl);
            if (rc == 1) break;
            std::this_thread::sleep_for(5ms);
        }
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    });

    tls_engine tls;
    tls_options opt;
    opt.enabled = true;
    opt.verify_peer = true;
    bool threw = false;
    try {
        loop.block_on(handshake_tls(loop, p.client, tls, opt, "localhost"));
    } catch (const io_error&) {
        threw = true;
    }
    server.join();
    CHECK(threw);
    CHECK(!tls.active());
#endif
}

CONDUIT_TEST(tls_loopback_accepts_a_certificate_when_its_ca_is_given) {
    if (!tls_available()) CONDUIT_SKIP("OpenSSL is not linked");
#ifndef CONDUIT_HAS_OPENSSL
    CONDUIT_SKIP("OpenSSL headers were not present at compile time");
#else
    auto creds = make_self_signed();
    std::string ca = write_ca(creds.cert);
    socket_pair p;
    event_loop loop;

    std::exception_ptr server_err;
    std::thread server([&] {
        try {
            SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
            SSL_CTX_use_certificate(ctx, creds.cert);
            SSL_CTX_use_PrivateKey(ctx, creds.key);
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, p.server.native());
            for (;;) {
                int rc = SSL_accept(ssl);
                if (rc == 1) break;
                int err = SSL_get_error(ssl, rc);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    std::this_thread::sleep_for(1ms);
                    continue;
                }
                throw std::runtime_error("SSL_accept failed");
            }
            const char* msg = "ok";
            while (SSL_write(ssl, msg, 2) <= 0) std::this_thread::sleep_for(1ms);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        } catch (...) {
            server_err = std::current_exception();
        }
    });

    tls_engine tls;
    tls_options opt;
    opt.enabled = true;
    opt.verify_peer = true;
    opt.ca_file = ca;
    loop.block_on(handshake_tls(loop, p.client, tls, opt, "localhost"));
    recv_buffer buf;
    bool alive = loop.block_on(read_some(loop, p.client, tls, buf));
    server.join();
    std::filesystem::remove(ca);
    if (server_err) std::rethrow_exception(server_err);
    CHECK(alive);
    CHECK_EQ(std::string(reinterpret_cast<const char*>(buf.readable().data()),
                         buf.readable_size()),
             std::string("ok"));
#endif
}