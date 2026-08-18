// A decoded field, and the rules for turning it into a C++ value.
//
// field_view holds a view into the connection's receive buffer, never a copy.
// The lifetime rule is part of the public contract: the view is valid until the
// next row is fetched on the same connection. Ask for a std::string if the
// value has to outlive the row, and the copy happens then, once, visibly.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "conduit/bytes.hpp"

namespace conduit {

// Wire format of a single field. PostgreSQL negotiates this per column, MySQL
// text protocol is always text.
enum class wire_format : std::int16_t { text = 0, binary = 1 };

struct field_view {
    bool is_null = false;
    byte_span data{};
    std::uint32_t oid = 0;          // PostgreSQL type OID, or the MySQL column type
    wire_format format = wire_format::text;

    std::string_view text() const noexcept {
        return std::string_view(reinterpret_cast<const char*>(data.data()), data.size());
    }
};

// --- calendar ---------------------------------------------------------------
// PostgreSQL sends timestamps as microseconds from 2000-01-01. Rendering that
// as a date needs a civil calendar conversion, which is why the algorithm is
// here rather than a call into <chrono>: std::chrono::year_month_day exists in
// C++20 but the conversion below is exact, short and identical everywhere.
struct timestamp {
    std::int64_t micros_since_2000 = 0;

    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    int microsecond = 0;

    std::string to_string() const;
    static timestamp from_micros(std::int64_t micros);
    // ISO-8601 style text, as PostgreSQL sends it in text format.
    static timestamp parse(std::string_view text);
};

// --- decoding ---------------------------------------------------------------
// One entry point. Specialised per C++ type rather than per OID, because the
// caller knows what it wants and the OID only decides how to read the bytes.
// A type with no specialisation is a compile error, which is the compile time
// half of the "schema and struct must agree" claim.
template <class T>
struct field_codec;

template <class T>
T decode_field(const field_view& f) {
    return field_codec<T>::decode(f);
}

// Free functions used by the specialisations, and directly by the tests.
bool        decode_bool(const field_view& f);
std::int16_t decode_i16(const field_view& f);
std::int32_t decode_i32(const field_view& f);
std::int64_t decode_i64(const field_view& f);
float       decode_f32(const field_view& f);
double      decode_f64(const field_view& f);
std::string_view decode_text(const field_view& f);
std::vector<std::byte> decode_bytea(const field_view& f);
timestamp   decode_timestamp(const field_view& f);
// Arbitrary precision decimal is rendered as its exact decimal text. Turning it
// into double would lose the precision the type exists to keep.
std::string decode_numeric(const field_view& f);
// Elements of a one dimensional array, still as views for binary format and as
// owned strings for text format.
std::vector<std::optional<std::string>> decode_array_text(const field_view& f);
std::vector<field_view> decode_array_binary(const field_view& f);

// Thrown when the bytes are well formed but do not represent the requested type.
class conversion_error : public std::runtime_error {
public:
    explicit conversion_error(const std::string& what) : std::runtime_error(what) {}
};

template <> struct field_codec<bool> { static bool decode(const field_view& f) { return decode_bool(f); } };
template <> struct field_codec<std::int16_t> { static std::int16_t decode(const field_view& f) { return decode_i16(f); } };
template <> struct field_codec<std::int32_t> { static std::int32_t decode(const field_view& f) { return decode_i32(f); } };
template <> struct field_codec<std::int64_t> { static std::int64_t decode(const field_view& f) { return decode_i64(f); } };
template <> struct field_codec<float> { static float decode(const field_view& f) { return decode_f32(f); } };
template <> struct field_codec<double> { static double decode(const field_view& f) { return decode_f64(f); } };
template <> struct field_codec<std::string_view> {
    // No copy. Valid only while the row is.
    static std::string_view decode(const field_view& f) { return decode_text(f); }
};
template <> struct field_codec<std::string> {
    // The copy the caller asked for.
    static std::string decode(const field_view& f) { return std::string(decode_text(f)); }
};
template <> struct field_codec<std::vector<std::byte>> {
    static std::vector<std::byte> decode(const field_view& f) { return decode_bytea(f); }
};
template <> struct field_codec<timestamp> {
    static timestamp decode(const field_view& f) { return decode_timestamp(f); }
};

// An optional column maps to std::optional. This is the only correct way to
// read a nullable column: everything else has to invent a value for NULL.
template <class T>
struct field_codec<std::optional<T>> {
    static std::optional<T> decode(const field_view& f) {
        if (f.is_null) return std::nullopt;
        return field_codec<T>::decode(f);
    }
};

// A one dimensional array column.
template <class T>
struct field_codec<std::vector<T>> {
    static std::vector<T> decode(const field_view& f) {
        std::vector<T> out;
        if (f.is_null) return out;
        if (f.format == wire_format::binary) {
            for (const auto& e : decode_array_binary(f)) {
                if (e.is_null) throw conversion_error("NULL element in a non optional array");
                out.push_back(field_codec<T>::decode(e));
            }
        } else {
            for (const auto& e : decode_array_text(f)) {
                if (!e) throw conversion_error("NULL element in a non optional array");
                field_view ev;
                ev.data = as_bytes(*e);
                ev.format = wire_format::text;
                // The element text is owned by the vector above, so decode into
                // an owning type before it dies.
                out.push_back(field_codec<T>::decode(ev));
            }
        }
        return out;
    }
};

}  // namespace conduit
