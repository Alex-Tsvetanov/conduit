// The hashes the two authentication exchanges need, implemented here rather
// than pulled from a crypto library.
//
// The reason is the build contract: the default build must succeed with no
// package manager and no network. MD5 is required by PostgreSQL md5
// authentication, SHA-1 by mysql_native_password, and SHA-256 with HMAC and
// PBKDF2 by SCRAM-SHA-256. All four are short and fully specified, so the
// alternative is a mandatory dependency for a few hundred lines of arithmetic.
//
// These are used only where the protocol specifies them. MD5 and SHA-1 are not
// treated as sound hashes here, they are treated as protocol constants.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "conduit/bytes.hpp"

namespace conduit::crypto {

using md5_digest = std::array<std::byte, 16>;
using sha1_digest = std::array<std::byte, 20>;
using sha256_digest = std::array<std::byte, 32>;

md5_digest md5(byte_span data);
sha1_digest sha1(byte_span data);
sha256_digest sha256(byte_span data);

// HMAC-SHA-256 as used by SCRAM. Key longer than the 64 byte block is hashed
// first, per RFC 2104.
sha256_digest hmac_sha256(byte_span key, byte_span data);

// PBKDF2 with HMAC-SHA-256 as the pseudo random function, one output block.
// SCRAM-SHA-256 never asks for more than the digest length, so the block index
// is fixed at 1 and the general multi block loop is not written.
sha256_digest pbkdf2_sha256(byte_span password, byte_span salt, std::uint32_t iterations);

std::string base64_encode(byte_span data);
std::vector<std::byte> base64_decode(std::string_view text);

// The exact string PostgreSQL expects for AuthenticationMD5Password:
//     "md5" + hex(md5(hex(md5(password + user)) + salt))
std::string pg_md5_password(std::string_view password, std::string_view user,
                            byte_span salt4);

// mysql_native_password reply:
//     SHA1(seed + SHA1(SHA1(password))) xor SHA1(password)
sha1_digest mysql_native_password(std::string_view password, byte_span seed20);

}  // namespace conduit::crypto
