#include <string>

#include "check.hpp"
#include "conduit/bytes.hpp"

using namespace conduit;

CONDUIT_TEST(reader_reads_both_byte_orders) {
    auto data = from_hex("01020304 04030201");
    byte_reader r{byte_span(data)};
    CHECK_EQ(r.be32(), 0x01020304u);
    CHECK_EQ(r.le32(), 0x01020304u);
    CHECK(r.empty());
}

CONDUIT_TEST(reader_signed_negative_round_trip) {
    std::vector<std::byte> out;
    byte_writer w{out};
    w.i32be(-1);
    w.i16be(-2);
    w.i64be(-3);
    byte_reader r{byte_span(out)};
    CHECK_EQ(r.i32be(), -1);
    CHECK_EQ(r.i16be(), static_cast<std::int16_t>(-2));
    CHECK_EQ(r.i64be(), static_cast<std::int64_t>(-3));
}

CONDUIT_TEST(reader_rejects_short_read) {
    auto data = from_hex("0102");
    byte_reader r{byte_span(data)};
    CHECK_THROWS(r.be32(), protocol_error);
}

CONDUIT_TEST(reader_cstring_stops_at_nul_and_rejects_unterminated) {
    auto data = from_hex("41 42 00 43");
    byte_reader r{byte_span(data)};
    CHECK_EQ(std::string(r.cstr()), std::string("AB"));
    CHECK_EQ(r.remaining(), std::size_t{1});

    auto bad = from_hex("41 42");
    byte_reader r2{byte_span(bad)};
    CHECK_THROWS(r2.cstr(), protocol_error);
}

CONDUIT_TEST(writer_patches_reserved_length) {
    std::vector<std::byte> out;
    byte_writer w{out};
    auto at = w.reserve_be32();
    w.raw(std::string_view("hello"));
    w.patch_be32(at, static_cast<std::uint32_t>(out.size() - at));
    byte_reader r{byte_span(out)};
    CHECK_EQ(r.be32(), 9u);
    CHECK_EQ(std::string(r.str(5)), std::string("hello"));
}

CONDUIT_TEST(writer_le24_covers_the_mysql_packet_length_field) {
    std::vector<std::byte> out;
    byte_writer w{out};
    w.le24(0xFFFFFE);
    CHECK_EQ(to_hex(byte_span(out)), std::string("feffff"));
    byte_reader r{byte_span(out)};
    CHECK_EQ(r.le24(), 0xFFFFFEu);
}

CONDUIT_TEST(recv_buffer_keeps_views_stable_until_consumed) {
    recv_buffer buf;
    buf.append(as_bytes("first"));
    auto view = buf.readable();
    CHECK_EQ(view.size(), std::size_t{5});
    buf.append(as_bytes("second"));
    // Appending inside the existing capacity must not move the bytes already
    // handed out, otherwise the zero copy contract is a lie.
    CHECK_EQ(view.data(), buf.readable().data());
    CHECK_EQ(buf.readable_size(), std::size_t{11});
    buf.consume(5);
    CHECK_EQ(std::string(reinterpret_cast<const char*>(buf.readable().data()),
                         buf.readable_size()),
             std::string("second"));
}

CONDUIT_TEST(recv_buffer_resets_when_fully_drained) {
    recv_buffer buf;
    buf.append(as_bytes("abc"));
    buf.consume(3);
    CHECK_EQ(buf.readable_size(), std::size_t{0});
    buf.append(as_bytes("xy"));
    CHECK_EQ(buf.readable_size(), std::size_t{2});
    CHECK_EQ(std::to_integer<int>(buf.readable()[0]), int('x'));
}

CONDUIT_TEST(recv_buffer_grows_past_its_initial_capacity) {
    recv_buffer buf;
    std::string big(64 * 1024, 'z');
    buf.append(as_bytes(big));
    CHECK_EQ(buf.readable_size(), big.size());
    CHECK(buf.capacity() >= big.size());
}

CONDUIT_TEST(hex_helpers_round_trip) {
    auto data = from_hex("00 ff 10 a5");
    CHECK_EQ(to_hex(byte_span(data)), std::string("00ff10a5"));
    CHECK_THROWS(from_hex("abc"), protocol_error);
}
