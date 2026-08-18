#include "conduit/bytes.hpp"

namespace conduit {
namespace {
int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
}  // namespace

std::vector<std::byte> from_hex(std::string_view hex) {
    std::vector<std::byte> out;
    int hi = -1;
    for (char c : hex) {
        int v = hex_val(c);
        if (v < 0) continue;  // whitespace and separators are ignored on purpose
        if (hi < 0) { hi = v; }
        else { out.push_back(std::byte(std::uint8_t(hi * 16 + v))); hi = -1; }
    }
    if (hi >= 0) throw protocol_error("odd number of hex digits");
    return out;
}

std::string to_hex(byte_span data) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (std::byte b : data) {
        auto v = std::to_integer<unsigned>(b);
        out.push_back(digits[v >> 4]);
        out.push_back(digits[v & 0xF]);
    }
    return out;
}

}  // namespace conduit
