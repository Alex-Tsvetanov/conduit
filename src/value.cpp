// Type decoding, shared by both backends.
//
// Every decoder takes a field_view and reads it in place. Nothing here copies
// unless the requested C++ type is an owning one, which is the point: a text
// column read as std::string_view costs no allocation at all.
#include "conduit/value.hpp"

#include <bit>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <cmath>

namespace conduit {
namespace {

void reject_null(const field_view& f, const char* what) {
    if (f.is_null) throw conversion_error(std::string("NULL cannot be read as ") + what);
}

// Howard Hinnant's civil calendar algorithms. Exact for the whole proleptic
// Gregorian range and free of any locale or time zone database.
constexpr std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

struct civil { std::int64_t y; unsigned m; unsigned d; };

constexpr civil civil_from_days(std::int64_t z) {
    z += 719468;
    const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned d = doy - (153 * mp + 2) / 5 + 1;
    const unsigned m = mp + (mp < 10 ? 3 : -9);
    return {y + (m <= 2), m, d};
}

// Days between the Unix epoch and the PostgreSQL timestamp epoch of 2000-01-01.
constexpr std::int64_t pg_epoch_days = 10957;
constexpr std::int64_t us_per_day = 86400ll * 1000000ll;

std::int64_t floor_div(std::int64_t a, std::int64_t b) {
    std::int64_t q = a / b;
    if ((a % b != 0) && ((a < 0) != (b < 0))) --q;
    return q;
}

std::string pad(int value, int width) {
    std::string s = std::to_string(value);
    while (static_cast<int>(s.size()) < width) s.insert(s.begin(), '0');
    return s;
}

std::int64_t parse_int(std::string_view s, const char* what) {
    std::int64_t v = 0;
    auto* first = s.data();
    auto* last = s.data() + s.size();
    while (first != last && *first == ' ') ++first;
    auto [ptr, ec] = std::from_chars(first, last, v);
    if (ec != std::errc{} || ptr != last)
        throw conversion_error(std::string("not an integer for ") + what + ": " + std::string(s));
    return v;
}

double parse_double(std::string_view s) {
    // from_chars for floating point is present in libstdc++ 11 and later, but
    // strtod is the portable floor and the parse cost is not on the hot path
    // for text format, which is already the slow format by construction.
    std::string tmp(s);
    char* end = nullptr;
    double v = std::strtod(tmp.c_str(), &end);
    if (end == tmp.c_str() || *end != '\0') {
        if (tmp == "NaN") return std::nan("");
        if (tmp == "Infinity") return HUGE_VAL;
        if (tmp == "-Infinity") return -HUGE_VAL;
        throw conversion_error("not a number: " + tmp);
    }
    return v;
}

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw conversion_error("bad hex digit in bytea");
}

}  // namespace

// --- scalars ----------------------------------------------------------------

bool decode_bool(const field_view& f) {
    reject_null(f, "bool");
    if (f.format == wire_format::binary) {
        if (f.data.size() != 1) throw conversion_error("binary bool must be one byte");
        return f.data[0] != std::byte{0};
    }
    auto s = f.text();
    if (s == "t" || s == "true" || s == "TRUE" || s == "1") return true;
    if (s == "f" || s == "false" || s == "FALSE" || s == "0") return false;
    throw conversion_error("not a boolean: " + std::string(s));
}

std::int64_t decode_i64(const field_view& f) {
    reject_null(f, "integer");
    if (f.format == wire_format::binary) {
        switch (f.data.size()) {
            case 1: return static_cast<std::int8_t>(std::to_integer<std::uint8_t>(f.data[0]));
            case 2: return static_cast<std::int16_t>(load_be16(f.data.data()));
            case 4: return static_cast<std::int32_t>(load_be32(f.data.data()));
            case 8: return static_cast<std::int64_t>(load_be64(f.data.data()));
            default: throw conversion_error("binary integer of unexpected width " +
                                            std::to_string(f.data.size()));
        }
    }
    return parse_int(f.text(), "integer");
}

std::int32_t decode_i32(const field_view& f) {
    auto v = decode_i64(f);
    if (v < INT32_MIN || v > INT32_MAX) throw conversion_error("value does not fit in int32");
    return static_cast<std::int32_t>(v);
}

std::int16_t decode_i16(const field_view& f) {
    auto v = decode_i64(f);
    if (v < INT16_MIN || v > INT16_MAX) throw conversion_error("value does not fit in int16");
    return static_cast<std::int16_t>(v);
}

double decode_f64(const field_view& f) {
    reject_null(f, "double");
    if (f.format == wire_format::binary) {
        if (f.data.size() == 4)
            return static_cast<double>(std::bit_cast<float>(load_be32(f.data.data())));
        if (f.data.size() == 8) return std::bit_cast<double>(load_be64(f.data.data()));
        throw conversion_error("binary float of unexpected width");
    }
    return parse_double(f.text());
}

float decode_f32(const field_view& f) { return static_cast<float>(decode_f64(f)); }

std::string_view decode_text(const field_view& f) {
    reject_null(f, "text");
    return f.text();
}

std::vector<std::byte> decode_bytea(const field_view& f) {
    reject_null(f, "bytea");
    if (f.format == wire_format::binary)
        return std::vector<std::byte>(f.data.begin(), f.data.end());

    auto s = f.text();
    std::vector<std::byte> out;
    if (s.size() >= 2 && s[0] == '\\' && s[1] == 'x') {
        // The hex output format, the default since PostgreSQL 9.0.
        if ((s.size() - 2) % 2 != 0) throw conversion_error("odd hex length in bytea");
        out.reserve((s.size() - 2) / 2);
        for (std::size_t i = 2; i + 1 < s.size(); i += 2)
            out.push_back(std::byte(std::uint8_t(hex_digit(s[i]) * 16 + hex_digit(s[i + 1]))));
        return out;
    }
    // The older escape format: \\ for a backslash, \nnn octal for anything else.
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '\\') { out.push_back(static_cast<std::byte>(s[i])); continue; }
        if (i + 1 < s.size() && s[i + 1] == '\\') { out.push_back(std::byte{'\\'}); ++i; continue; }
        if (i + 3 < s.size()) {
            int v = (s[i + 1] - '0') * 64 + (s[i + 2] - '0') * 8 + (s[i + 3] - '0');
            out.push_back(std::byte(std::uint8_t(v)));
            i += 3;
            continue;
        }
        throw conversion_error("truncated escape in bytea");
    }
    return out;
}

// --- timestamps -------------------------------------------------------------

timestamp timestamp::from_micros(std::int64_t micros) {
    timestamp t;
    t.micros_since_2000 = micros;
    std::int64_t days = floor_div(micros, us_per_day);
    std::int64_t rem = micros - days * us_per_day;
    auto c = civil_from_days(days + pg_epoch_days);
    t.year = static_cast<int>(c.y);
    t.month = static_cast<int>(c.m);
    t.day = static_cast<int>(c.d);
    t.hour = static_cast<int>(rem / 3600000000ll);
    rem %= 3600000000ll;
    t.minute = static_cast<int>(rem / 60000000ll);
    rem %= 60000000ll;
    t.second = static_cast<int>(rem / 1000000ll);
    t.microsecond = static_cast<int>(rem % 1000000ll);
    return t;
}

timestamp timestamp::parse(std::string_view s) {
    // Accepts "YYYY-MM-DD HH:MM:SS[.ffffff]" and the same with 'T', which covers
    // the text format of both servers. A trailing time zone offset is rejected
    // rather than silently ignored: silently ignoring it produces a wrong value.
    if (s.size() < 19) throw conversion_error("timestamp text too short: " + std::string(s));
    timestamp t;
    t.year = static_cast<int>(parse_int(s.substr(0, 4), "year"));
    t.month = static_cast<int>(parse_int(s.substr(5, 2), "month"));
    t.day = static_cast<int>(parse_int(s.substr(8, 2), "day"));
    t.hour = static_cast<int>(parse_int(s.substr(11, 2), "hour"));
    t.minute = static_cast<int>(parse_int(s.substr(14, 2), "minute"));
    t.second = static_cast<int>(parse_int(s.substr(17, 2), "second"));
    t.microsecond = 0;
    if (s.size() > 19) {
        if (s[19] != '.') throw conversion_error("unsupported timestamp suffix: " + std::string(s));
        std::size_t i = 20;
        int scale = 100000;
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
            if (scale > 0) { t.microsecond += (s[i] - '0') * scale; scale /= 10; }
            ++i;
        }
        if (i != s.size()) throw conversion_error("unsupported timestamp suffix: " + std::string(s));
    }
    std::int64_t days = days_from_civil(t.year, static_cast<unsigned>(t.month),
                                        static_cast<unsigned>(t.day)) - pg_epoch_days;
    t.micros_since_2000 = days * us_per_day + t.hour * 3600000000ll +
                          t.minute * 60000000ll + t.second * 1000000ll + t.microsecond;
    return t;
}

std::string timestamp::to_string() const {
    std::string s = pad(year, 4) + "-" + pad(month, 2) + "-" + pad(day, 2) + " " +
                    pad(hour, 2) + ":" + pad(minute, 2) + ":" + pad(second, 2);
    if (microsecond != 0) s += "." + pad(microsecond, 6);
    return s;
}

timestamp decode_timestamp(const field_view& f) {
    reject_null(f, "timestamp");
    if (f.format == wire_format::binary) {
        if (f.data.size() != 8)
            throw conversion_error("binary timestamp must be eight bytes");
        return timestamp::from_micros(static_cast<std::int64_t>(load_be64(f.data.data())));
    }
    return timestamp::parse(f.text());
}

// --- numeric ----------------------------------------------------------------

std::string decode_numeric(const field_view& f) {
    reject_null(f, "numeric");
    if (f.format == wire_format::text) return std::string(f.text());

    // Binary numeric: ndigits, weight, sign, dscale, then base 10000 groups.
    byte_reader r{f.data};
    int ndigits = r.i16be();
    int weight = r.i16be();
    std::uint16_t sign = r.be16();
    int dscale = static_cast<int>(r.be16());
    if (sign == 0xC000) return "NaN";
    if (sign == 0xD000) return "Infinity";
    if (sign == 0xF000) return "-Infinity";

    std::vector<int> digits;
    digits.reserve(static_cast<std::size_t>(ndigits));
    for (int i = 0; i < ndigits; ++i) digits.push_back(r.i16be());

    std::string out;
    if (sign == 0x4000) out += '-';

    if (weight < 0) {
        out += '0';
    } else {
        for (int i = 0; i <= weight; ++i) {
            int d = (i < ndigits) ? digits[static_cast<std::size_t>(i)] : 0;
            out += (i == 0) ? std::to_string(d) : pad(d, 4);
        }
    }

    if (dscale > 0) {
        std::string frac;
        for (int i = weight + 1; static_cast<int>(frac.size()) < dscale; ++i) {
            int d = (i >= 0 && i < ndigits) ? digits[static_cast<std::size_t>(i)] : 0;
            frac += pad(d, 4);
        }
        frac.resize(static_cast<std::size_t>(dscale));
        out += '.';
        out += frac;
    }
    return out;
}

// --- arrays -----------------------------------------------------------------

std::vector<std::optional<std::string>> decode_array_text(const field_view& f) {
    // PostgreSQL text array syntax: {a,b,"c,d",NULL}. Only one dimension is
    // handled; a nested brace is reported rather than flattened, because
    // flattening would silently change the shape of the data.
    std::vector<std::optional<std::string>> out;
    auto s = f.text();
    std::size_t i = 0;
    while (i < s.size() && s[i] != '{') ++i;
    if (i == s.size()) throw conversion_error("array text does not start with a brace");
    ++i;
    if (i < s.size() && s[i] == '}') return out;

    std::string cur;
    bool quoted = false, any = false;
    for (; i < s.size(); ++i) {
        char c = s[i];
        if (quoted) {
            if (c == '\\' && i + 1 < s.size()) { cur += s[++i]; continue; }
            if (c == '"') { quoted = false; continue; }
            cur += c;
            continue;
        }
        if (c == '"') { quoted = true; any = true; continue; }
        if (c == '{') throw conversion_error("nested arrays are out of scope");
        if (c == ',' || c == '}') {
            if (cur == "NULL" && !any) out.push_back(std::nullopt);
            else out.push_back(cur);
            cur.clear();
            any = false;
            if (c == '}') break;
            continue;
        }
        cur += c;
    }
    return out;
}

std::vector<field_view> decode_array_binary(const field_view& f) {
    byte_reader r{f.data};
    std::int32_t ndim = r.i32be();
    r.be32();  // null flag, redundant with the per element length below
    std::uint32_t elem_oid = r.be32();
    if (ndim == 0) return {};
    if (ndim != 1) throw conversion_error("only one dimensional arrays are decoded");

    std::int32_t count = r.i32be();
    r.i32be();  // lower bound, always 1 unless the array was built with an explicit one

    std::vector<field_view> out;
    out.reserve(static_cast<std::size_t>(count));
    for (std::int32_t i = 0; i < count; ++i) {
        std::int32_t len = r.i32be();
        field_view e;
        e.oid = elem_oid;
        e.format = wire_format::binary;
        if (len < 0) { e.is_null = true; }
        else { e.data = r.bytes(static_cast<std::size_t>(len)); }
        out.push_back(e);
    }
    return out;
}

}  // namespace conduit
