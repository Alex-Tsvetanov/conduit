// Type decoding in both wire formats.
#include <optional>
#include <string>

#include "check.hpp"
#include "conduit/pg/protocol.hpp"
#include "conduit/row_map.hpp"
#include "conduit/value.hpp"

using namespace conduit;

namespace {

field_view text_field(std::string_view s, std::uint32_t oid = 0) {
    field_view f;
    f.data = as_bytes(s);
    f.oid = oid;
    f.format = wire_format::text;
    return f;
}

field_view binary_field(const std::vector<std::byte>& bytes, std::uint32_t oid = 0) {
    field_view f;
    f.data = byte_span(bytes);
    f.oid = oid;
    f.format = wire_format::binary;
    return f;
}

}  // namespace

CONDUIT_TEST(integers_decode_from_every_binary_width_and_from_text) {
    auto b2 = from_hex("fffe");
    auto b4 = from_hex("fffffffe");
    auto b8 = from_hex("fffffffffffffffe");
    CHECK_EQ(decode_i64(binary_field(b2)), std::int64_t{-2});
    CHECK_EQ(decode_i64(binary_field(b4)), std::int64_t{-2});
    CHECK_EQ(decode_i64(binary_field(b8)), std::int64_t{-2});
    CHECK_EQ(decode_i64(text_field("-2")), std::int64_t{-2});
    CHECK_EQ(decode_i32(text_field("2147483647")), 2147483647);
    CHECK_THROWS(decode_i32(text_field("2147483648")), conversion_error);
    CHECK_THROWS(decode_i64(text_field("12x")), conversion_error);
}

CONDUIT_TEST(floats_decode_from_ieee754_big_endian_and_from_text) {
    auto f4 = from_hex("40490fdb");           // 3.14159274f
    auto f8 = from_hex("400921fb54442d18");   // pi as double
    CHECK_NEAR(decode_f32(binary_field(f4)), 3.14159274, 1e-6);
    CHECK_NEAR(decode_f64(binary_field(f8)), 3.14159265358979, 1e-12);
    CHECK_NEAR(decode_f64(text_field("2.5")), 2.5, 1e-12);
    CHECK_NEAR(decode_f64(text_field("-1e3")), -1000.0, 1e-9);
    CHECK_THROWS(decode_f64(text_field("not a number")), conversion_error);
}

CONDUIT_TEST(booleans_accept_both_spellings_and_reject_anything_else) {
    CHECK(decode_bool(text_field("t")));
    CHECK(!decode_bool(text_field("f")));
    CHECK(decode_bool(text_field("1")));
    CHECK(!decode_bool(text_field("0")));
    auto one = from_hex("01");
    auto zero = from_hex("00");
    CHECK(decode_bool(binary_field(one)));
    CHECK(!decode_bool(binary_field(zero)));
    CHECK_THROWS(decode_bool(text_field("maybe")), conversion_error);
}

CONDUIT_TEST(text_decoding_makes_no_copy) {
    std::string owner = "the receive buffer";
    auto f = text_field(owner);
    auto view = decode_text(f);
    CHECK_EQ(view.data(), owner.data());
    CHECK_EQ(std::string(view), owner);
    // Asking for a std::string is the point at which a copy happens, visibly.
    auto copy = decode_field<std::string>(f);
    CHECK(copy.data() != owner.data());
    CHECK_EQ(copy, owner);
}

CONDUIT_TEST(null_is_only_readable_through_optional) {
    field_view f;
    f.is_null = true;
    CHECK_THROWS(decode_i64(f), conversion_error);
    auto opt = decode_field<std::optional<std::int64_t>>(f);
    CHECK(!opt.has_value());
    auto present = decode_field<std::optional<std::int64_t>>(text_field("5"));
    CHECK(present.has_value());
    CHECK_EQ(*present, std::int64_t{5});
}

CONDUIT_TEST(bytea_decodes_from_hex_escape_and_binary) {
    auto hex = decode_bytea(text_field("\\x00ff10"));
    CHECK_EQ(to_hex(byte_span(hex)), std::string("00ff10"));
    auto escaped = decode_bytea(text_field("a\\\\b"));
    CHECK_EQ(to_hex(byte_span(escaped)), std::string("615c62"));
    auto raw = from_hex("deadbeef");
    CHECK_EQ(to_hex(byte_span(decode_bytea(binary_field(raw)))), std::string("deadbeef"));
    CHECK_THROWS(decode_bytea(text_field("\\xabc")), conversion_error);
}

CONDUIT_TEST(timestamps_round_trip_through_the_2000_epoch) {
    // 2000-01-01 00:00:00 is exactly zero on the wire.
    auto zero = from_hex("0000000000000000");
    auto t0 = decode_timestamp(binary_field(zero));
    CHECK_EQ(t0.year, 2000);
    CHECK_EQ(t0.month, 1);
    CHECK_EQ(t0.day, 1);
    CHECK_EQ(t0.to_string(), std::string("2000-01-01 00:00:00"));

    auto parsed = timestamp::parse("2024-02-29 13:45:30.123456");
    CHECK_EQ(parsed.year, 2024);
    CHECK_EQ(parsed.month, 2);
    CHECK_EQ(parsed.day, 29);
    CHECK_EQ(parsed.microsecond, 123456);
    CHECK_EQ(parsed.to_string(), std::string("2024-02-29 13:45:30.123456"));

    // Reading the same instant back from its microsecond count must reproduce
    // the calendar fields; a leap year off by one shows up here.
    auto again = timestamp::from_micros(parsed.micros_since_2000);
    CHECK_EQ(again.to_string(), parsed.to_string());

    // A date before the epoch exercises the floor division.
    auto before = timestamp::parse("1999-12-31 23:59:59");
    CHECK(before.micros_since_2000 < 0);
    CHECK_EQ(timestamp::from_micros(before.micros_since_2000).to_string(),
             std::string("1999-12-31 23:59:59"));
}

CONDUIT_TEST(timestamp_text_with_a_zone_offset_is_refused_not_silently_truncated) {
    CHECK_THROWS(timestamp::parse("2024-01-15 10:00:00+02"), conversion_error);
}

CONDUIT_TEST(binary_numeric_keeps_full_precision) {
    // 123456.789 in the binary numeric layout: three base 10000 groups with a
    // weight of one and a display scale of three.
    std::vector<std::byte> body;
    {
        byte_writer w{body};
        w.i16be(3);       // ndigits
        w.i16be(1);       // weight
        w.be16(0x0000);   // positive
        w.be16(3);        // dscale
        w.i16be(12);      // 12 * 10000^1
        w.i16be(3456);    // 3456 * 10000^0
        w.i16be(7890);    // 7890 * 10000^-1
    }
    CHECK_EQ(decode_numeric(binary_field(body, pg::oid::numeric)), std::string("123456.789"));

    std::vector<std::byte> nan;
    {
        byte_writer w{nan};
        w.i16be(0); w.i16be(0); w.be16(0xC000); w.be16(0);
    }
    CHECK_EQ(decode_numeric(binary_field(nan)), std::string("NaN"));

    std::vector<std::byte> small;
    {
        byte_writer w{small};
        w.i16be(1); w.i16be(-1); w.be16(0x4000); w.be16(4);
        w.i16be(500);  // 0.0500, negative
    }
    CHECK_EQ(decode_numeric(binary_field(small)), std::string("-0.0500"));

    // Text format is already exact and is passed straight through.
    CHECK_EQ(decode_numeric(text_field("0.10")), std::string("0.10"));
}

CONDUIT_TEST(text_arrays_handle_quoting_and_nulls) {
    auto parts = decode_array_text(text_field("{1,2,NULL,3}"));
    CHECK_EQ(parts.size(), std::size_t{4});
    CHECK(!parts[2].has_value());
    CHECK_EQ(*parts[0], std::string("1"));

    auto quoted = decode_array_text(text_field("{\"a,b\",\"c\\\"d\",NULL}"));
    CHECK_EQ(quoted.size(), std::size_t{3});
    CHECK_EQ(*quoted[0], std::string("a,b"));
    CHECK_EQ(*quoted[1], std::string("c\"d"));
    CHECK(!quoted[2].has_value());

    // A quoted literal NULL is the four character string, not a null element.
    auto literal = decode_array_text(text_field("{\"NULL\"}"));
    CHECK(literal[0].has_value());
    CHECK_EQ(*literal[0], std::string("NULL"));

    CHECK_EQ(decode_array_text(text_field("{}")).size(), std::size_t{0});
    CHECK_THROWS(decode_array_text(text_field("{{1},{2}}")), conversion_error);
}

CONDUIT_TEST(binary_arrays_decode_elements_and_nulls) {
    std::vector<std::byte> body;
    {
        byte_writer w{body};
        w.i32be(1);                  // one dimension
        w.i32be(1);                  // has nulls
        w.be32(pg::oid::int4);
        w.i32be(3);                  // three elements
        w.i32be(1);                  // lower bound
        w.i32be(4); w.i32be(10);
        w.i32be(-1);                 // NULL
        w.i32be(4); w.i32be(30);
    }
    auto elems = decode_array_binary(binary_field(body, pg::oid::int4_array));
    CHECK_EQ(elems.size(), std::size_t{3});
    CHECK_EQ(decode_i32(elems[0]), 10);
    CHECK(elems[1].is_null);
    CHECK_EQ(decode_i32(elems[2]), 30);

    // A vector of a non optional type refuses to invent a value for NULL.
    CHECK_THROWS(decode_field<std::vector<std::int32_t>>(binary_field(body, pg::oid::int4_array)),
                 conversion_error);
}

CONDUIT_TEST(vector_of_int_decodes_a_null_free_binary_array) {
    std::vector<std::byte> body;
    {
        byte_writer w{body};
        w.i32be(1); w.i32be(0); w.be32(pg::oid::int8);
        w.i32be(2); w.i32be(1);
        w.i32be(8); w.i64be(7);
        w.i32be(8); w.i64be(-9);
    }
    auto v = decode_field<std::vector<std::int64_t>>(binary_field(body, pg::oid::int8_array));
    CHECK_EQ(v.size(), std::size_t{2});
    CHECK_EQ(v[0], std::int64_t{7});
    CHECK_EQ(v[1], std::int64_t{-9});
}

// --- typed mapping ----------------------------------------------------------

namespace {
struct book {
    std::int64_t id = 0;
    std::string title;
    double price = 0;
    std::optional<std::int32_t> year;
};
struct fake_column {
    std::string name;
};
}  // namespace

template <>
struct conduit::row_mapping<book> {
    static constexpr auto fields = std::tuple{
        conduit::bind_field("id", &book::id),
        conduit::bind_field("title", &book::title),
        conduit::bind_field("price", &book::price),
        conduit::bind_field("published", &book::year)};
};

CONDUIT_TEST(row_mapper_resolves_columns_by_name_in_any_order) {
    std::vector<fake_column> cols{{"title"}, {"published"}, {"id"}, {"price"}};
    row_mapper<book> mapper{cols};

    std::string title = "Dune";
    field_view null_year;
    null_year.is_null = true;
    std::vector<field_view> row{text_field(title), null_year, text_field("42"),
                                text_field("9.99")};

    book b = mapper(row);
    CHECK_EQ(b.id, std::int64_t{42});
    CHECK_EQ(b.title, std::string("Dune"));
    CHECK_NEAR(b.price, 9.99, 1e-9);
    CHECK(!b.year.has_value());
}

CONDUIT_TEST(row_mapper_reports_a_missing_column_by_name) {
    std::vector<fake_column> cols{{"id"}, {"title"}, {"price"}};
    bool caught = false;
    try {
        row_mapper<book> mapper{cols};
    } catch (const mapping_error& e) {
        caught = true;
        CHECK(std::string(e.what()).find("published") != std::string::npos);
    }
    CHECK(caught);
}

CONDUIT_TEST(row_mapper_binds_field_count_at_compile_time) {
    static_assert(row_mapper<book>::field_count == 4);
    static_assert(mappable<book>);
    static_assert(!mappable<fake_column>);
    CHECK(true);
}
