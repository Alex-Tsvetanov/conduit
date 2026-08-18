#include "conduit/scram.hpp"

#include <random>
#include <stdexcept>

#include "conduit/crypto.hpp"

namespace conduit {
namespace {

std::string random_nonce() {
    // The printable ASCII range without the comma, which SCRAM uses as its
    // separator. 24 characters is above the 16 bytes RFC 5802 asks for.
    static const char* alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 63);
    std::string s;
    s.reserve(24);
    for (int i = 0; i < 24; ++i) s.push_back(alphabet[dist(rd)]);
    return s;
}

}  // namespace

std::string scram_attribute(std::string_view message, char key) {
    std::size_t i = 0;
    while (i < message.size()) {
        std::size_t end = message.find(',', i);
        if (end == std::string_view::npos) end = message.size();
        if (end - i >= 2 && message[i] == key && message[i + 1] == '=')
            return std::string(message.substr(i + 2, end - i - 2));
        i = end + 1;
    }
    return {};
}

scram_client::scram_client(std::string_view user, std::string_view password, std::string nonce)
    : user_(user), password_(password),
      client_nonce_(nonce.empty() ? random_nonce() : std::move(nonce)) {
    // PostgreSQL ignores the n= attribute and takes the user name from the
    // startup packet, so the connection code passes an empty one. The parameter
    // exists because RFC 5802 defines it and the published test vector uses it.
    client_first_bare_ = "n=" + user_ + ",r=" + client_nonce_;
    client_first_ = "n,," + client_first_bare_;
}

std::string scram_client::client_final(std::string_view server_first) {
    std::string server_nonce = scram_attribute(server_first, 'r');
    std::string salt_b64 = scram_attribute(server_first, 's');
    std::string iter_text = scram_attribute(server_first, 'i');
    if (server_nonce.empty() || salt_b64.empty() || iter_text.empty())
        throw std::runtime_error("malformed SCRAM server-first message");
    if (server_nonce.rfind(client_nonce_, 0) != 0)
        throw std::runtime_error("SCRAM server nonce does not extend the client nonce");

    std::uint32_t iterations = static_cast<std::uint32_t>(std::stoul(iter_text));
    auto salt = crypto::base64_decode(salt_b64);

    // ponytail: the password is used as raw bytes rather than SASLprep
    // normalised. That is exact for any ASCII password and only differs for a
    // password containing non ASCII whitespace or unassigned code points.
    auto salted = crypto::pbkdf2_sha256(as_bytes(password_), byte_span(salt), iterations);
    auto client_key = crypto::hmac_sha256(byte_span(salted), as_bytes("Client Key"));
    auto stored_key = crypto::sha256(byte_span(client_key));

    std::string channel_binding = "c=biws";  // base64 of "n,,"
    std::string final_without_proof = channel_binding + ",r=" + server_nonce;
    std::string auth_message =
        client_first_bare_ + "," + std::string(server_first) + "," + final_without_proof;

    auto client_signature = crypto::hmac_sha256(byte_span(stored_key), as_bytes(auth_message));
    std::vector<std::byte> proof(client_key.size());
    for (std::size_t i = 0; i < proof.size(); ++i) proof[i] = client_key[i] ^ client_signature[i];

    auto server_key = crypto::hmac_sha256(byte_span(salted), as_bytes("Server Key"));
    auto server_signature = crypto::hmac_sha256(byte_span(server_key), as_bytes(auth_message));
    server_signature_b64_ = crypto::base64_encode(byte_span(server_signature));

    return final_without_proof + ",p=" + crypto::base64_encode(byte_span(proof));
}

bool scram_client::verify_server_final(std::string_view server_final) const {
    auto v = scram_attribute(server_final, 'v');
    return !v.empty() && v == server_signature_b64_;
}

}  // namespace conduit
