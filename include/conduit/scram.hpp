// SCRAM-SHA-256 client side, RFC 5802 and RFC 7677.
//
// This is the mechanism PostgreSQL 14 and later use by default, so without it
// the client cannot connect to a server that was not deliberately weakened.
// The exchange is three steps and is written as a small state object so the
// connection code does not have to hold the intermediate strings.
//
// The nonce is injectable so the published test vector can be replayed exactly.
// In normal use it is generated from std::random_device.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace conduit {

class scram_client {
public:
    // `nonce` empty means generate one.
    scram_client(std::string_view user, std::string_view password, std::string nonce = {});

    // Step one: "n,,n=<user>,r=<nonce>".
    const std::string& client_first() const noexcept { return client_first_; }

    // Step two: consume the server's "r=...,s=...,i=..." and produce
    // "c=biws,r=...,p=<proof>".
    std::string client_final(std::string_view server_first);

    // Step three: check the server's "v=<signature>". A server that cannot
    // produce it does not know the stored key, so this check is what makes the
    // authentication mutual rather than one sided.
    bool verify_server_final(std::string_view server_final) const;

    const std::string& nonce() const noexcept { return client_nonce_; }

private:
    std::string user_;
    std::string password_;
    std::string client_nonce_;
    std::string client_first_bare_;
    std::string client_first_;
    std::string server_signature_b64_;
};

// Extracts the value of a single letter attribute from a SCRAM message such as
// "r=abc,s=def,i=4096". Exposed because the tests check it directly.
std::string scram_attribute(std::string_view message, char key);

}  // namespace conduit
