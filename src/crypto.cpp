#include "conduit/crypto.hpp"

#include <cstring>

namespace conduit::crypto {
namespace {

inline std::uint32_t rotl32(std::uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }
inline std::uint32_t rotr32(std::uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

// --- MD5, RFC 1321 ----------------------------------------------------------

const std::uint32_t md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

const int md5_s[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                       5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

// Length padding shared by MD5 (little endian length) and SHA (big endian).
std::vector<std::byte> pad_message(byte_span data, bool little_endian_length) {
    std::vector<std::byte> m(data.begin(), data.end());
    std::uint64_t bit_len = static_cast<std::uint64_t>(data.size()) * 8;
    m.push_back(std::byte{0x80});
    while (m.size() % 64 != 56) m.push_back(std::byte{0});
    for (int i = 0; i < 8; ++i) {
        int shift = little_endian_length ? (8 * i) : (56 - 8 * i);
        m.push_back(std::byte(std::uint8_t(bit_len >> shift)));
    }
    return m;
}

// --- SHA-256 constants, FIPS 180-4 ------------------------------------------
const std::uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

}  // namespace

md5_digest md5(byte_span data) {
    std::uint32_t h[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    auto m = pad_message(data, /*little_endian_length=*/true);

    for (std::size_t off = 0; off < m.size(); off += 64) {
        std::uint32_t w[16];
        for (int i = 0; i < 16; ++i) w[i] = load_le32(m.data() + off + i * 4);

        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        for (int i = 0; i < 64; ++i) {
            std::uint32_t f;
            int g;
            if (i < 16)      { f = (b & c) | (~b & d);        g = i; }
            else if (i < 32) { f = (d & b) | (~d & c);        g = (5 * i + 1) % 16; }
            else if (i < 48) { f = b ^ c ^ d;                 g = (3 * i + 5) % 16; }
            else             { f = c ^ (b | ~d);              g = (7 * i) % 16; }
            std::uint32_t tmp = d;
            d = c;
            c = b;
            b = b + rotl32(a + f + md5_k[i] + w[g], md5_s[i]);
            a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    }

    md5_digest out{};
    for (int i = 0; i < 4; ++i)
        for (int j = 0; j < 4; ++j)
            out[std::size_t(i * 4 + j)] = std::byte(std::uint8_t(h[i] >> (8 * j)));
    return out;
}

sha1_digest sha1(byte_span data) {
    std::uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    auto m = pad_message(data, /*little_endian_length=*/false);

    for (std::size_t off = 0; off < m.size(); off += 64) {
        std::uint32_t w[80];
        for (int i = 0; i < 16; ++i) w[i] = load_be32(m.data() + off + i * 4);
        for (int i = 16; i < 80; ++i) w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int i = 0; i < 80; ++i) {
            std::uint32_t f, k;
            if (i < 20)      { f = (b & c) | (~b & d);            k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
            else             { f = b ^ c ^ d;                     k = 0xCA62C1D6; }
            std::uint32_t tmp = rotl32(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rotl32(b, 30); b = a; a = tmp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }

    sha1_digest out{};
    for (int i = 0; i < 5; ++i)
        for (int j = 0; j < 4; ++j)
            out[std::size_t(i * 4 + j)] = std::byte(std::uint8_t(h[i] >> (24 - 8 * j)));
    return out;
}

sha256_digest sha256(byte_span data) {
    std::uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    auto m = pad_message(data, /*little_endian_length=*/false);

    for (std::size_t off = 0; off < m.size(); off += 64) {
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i) w[i] = load_be32(m.data() + off + i * 4);
        for (int i = 16; i < 64; ++i) {
            std::uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
            std::uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        std::uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            std::uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
            std::uint32_t ch = (e & f) ^ (~e & g);
            std::uint32_t t1 = hh + S1 + ch + sha256_k[i] + w[i];
            std::uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
            std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            std::uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    sha256_digest out{};
    for (int i = 0; i < 8; ++i)
        for (int j = 0; j < 4; ++j)
            out[std::size_t(i * 4 + j)] = std::byte(std::uint8_t(h[i] >> (24 - 8 * j)));
    return out;
}

sha256_digest hmac_sha256(byte_span key, byte_span data) {
    constexpr std::size_t block = 64;
    std::array<std::byte, block> k{};
    if (key.size() > block) {
        auto kh = sha256(key);
        std::memcpy(k.data(), kh.data(), kh.size());
    } else {
        std::memcpy(k.data(), key.data(), key.size());
    }

    std::vector<std::byte> inner(block);
    std::vector<std::byte> outer(block);
    for (std::size_t i = 0; i < block; ++i) {
        inner[i] = k[i] ^ std::byte{0x36};
        outer[i] = k[i] ^ std::byte{0x5c};
    }
    inner.insert(inner.end(), data.begin(), data.end());
    auto ih = sha256(byte_span(inner));
    outer.insert(outer.end(), ih.begin(), ih.end());
    return sha256(byte_span(outer));
}

sha256_digest pbkdf2_sha256(byte_span password, byte_span salt, std::uint32_t iterations) {
    std::vector<std::byte> block(salt.begin(), salt.end());
    block.push_back(std::byte{0});
    block.push_back(std::byte{0});
    block.push_back(std::byte{0});
    block.push_back(std::byte{1});  // INT(1), the only block SCRAM needs

    auto u = hmac_sha256(password, byte_span(block));
    auto result = u;
    for (std::uint32_t i = 1; i < iterations; ++i) {
        u = hmac_sha256(password, byte_span(u));
        for (std::size_t j = 0; j < result.size(); ++j) result[j] = result[j] ^ u[j];
    }
    return result;
}

// --- base64, RFC 4648 -------------------------------------------------------

namespace {
const char* b64_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int b64_index(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
}  // namespace

std::string base64_encode(byte_span data) {
    std::string out;
    out.reserve((data.size() + 2) / 3 * 4);
    std::size_t i = 0;
    for (; i + 3 <= data.size(); i += 3) {
        std::uint32_t v = (std::to_integer<std::uint32_t>(data[i]) << 16) |
                          (std::to_integer<std::uint32_t>(data[i + 1]) << 8) |
                          std::to_integer<std::uint32_t>(data[i + 2]);
        out.push_back(b64_alphabet[(v >> 18) & 63]);
        out.push_back(b64_alphabet[(v >> 12) & 63]);
        out.push_back(b64_alphabet[(v >> 6) & 63]);
        out.push_back(b64_alphabet[v & 63]);
    }
    std::size_t left = data.size() - i;
    if (left == 1) {
        std::uint32_t v = std::to_integer<std::uint32_t>(data[i]) << 16;
        out.push_back(b64_alphabet[(v >> 18) & 63]);
        out.push_back(b64_alphabet[(v >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (left == 2) {
        std::uint32_t v = (std::to_integer<std::uint32_t>(data[i]) << 16) |
                          (std::to_integer<std::uint32_t>(data[i + 1]) << 8);
        out.push_back(b64_alphabet[(v >> 18) & 63]);
        out.push_back(b64_alphabet[(v >> 12) & 63]);
        out.push_back(b64_alphabet[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

std::vector<std::byte> base64_decode(std::string_view text) {
    std::vector<std::byte> out;
    std::uint32_t acc = 0;
    int bits = 0;
    for (char c : text) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        int v = b64_index(c);
        if (v < 0) throw protocol_error("invalid base64 character");
        acc = (acc << 6) | std::uint32_t(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(std::byte(std::uint8_t((acc >> bits) & 0xFF)));
        }
    }
    return out;
}

std::string pg_md5_password(std::string_view password, std::string_view user, byte_span salt4) {
    std::vector<std::byte> pu;
    pu.insert(pu.end(), reinterpret_cast<const std::byte*>(password.data()),
              reinterpret_cast<const std::byte*>(password.data()) + password.size());
    pu.insert(pu.end(), reinterpret_cast<const std::byte*>(user.data()),
              reinterpret_cast<const std::byte*>(user.data()) + user.size());
    std::string inner = to_hex(byte_span(md5(byte_span(pu))));

    std::vector<std::byte> second;
    second.insert(second.end(), reinterpret_cast<const std::byte*>(inner.data()),
                  reinterpret_cast<const std::byte*>(inner.data()) + inner.size());
    second.insert(second.end(), salt4.begin(), salt4.end());
    return "md5" + to_hex(byte_span(md5(byte_span(second))));
}

sha1_digest mysql_native_password(std::string_view password, byte_span seed20) {
    auto stage1 = sha1(as_bytes(password));                    // SHA1(password)
    auto stage2 = sha1(byte_span(stage1));                     // SHA1(SHA1(password))

    std::vector<std::byte> seeded(seed20.begin(), seed20.end());
    seeded.insert(seeded.end(), stage2.begin(), stage2.end());
    auto scrambled = sha1(byte_span(seeded));                  // SHA1(seed + stage2)

    sha1_digest out{};
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = scrambled[i] ^ stage1[i];
    return out;
}

}  // namespace conduit::crypto
