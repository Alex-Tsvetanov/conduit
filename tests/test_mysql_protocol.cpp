// The MySQL codec. The handshake bytes below are a version 10 handshake
// assembled field by field from the packet layout in the protocol
// documentation, not captured from a server.
#include <string>

#include "check.hpp"
#include "conduit/mysql/protocol.hpp"

using namespace conduit;
using namespace conduit::mysql;

namespace {

std::vector<std::byte> make_handshake() {
    std::vector<std::byte> body;
    byte_writer w{body};
    w.u8(10);
    w.cstr("8.0.36");
    w.le32(1234);                       // connection id
    w.raw(std::string_view("ABCDEFGH"));  // auth data part 1
    w.u8(0);                            // filler
    std::uint32_t capabilities = caps::protocol_41 | caps::secure_connection | caps::plugin_auth |
                                 caps::transactions | caps::long_password;
    w.le16(static_cast<std::uint16_t>(capabilities & 0xFFFF));
    w.u8(45);                           // character set
    w.le16(2);                          // status flags
    w.le16(static_cast<std::uint16_t>(capabilities >> 16));
    w.u8(21);                           // auth data length
    for (int i = 0; i < 10; ++i) w.u8(0);
    w.raw(std::string_view("IJKLMNOPQRST"));  // auth data part 2, twelve bytes
    w.u8(0);                                  // its terminator
    w.cstr("mysql_native_password");
    return body;
}

std::vector<std::byte> framed(std::uint8_t seq, byte_span payload) {
    std::vector<std::byte> out;
    write_packet(out, seq, payload);
    return out;
}

}  // namespace

CONDUIT_TEST(packet_framing_needs_the_whole_header_and_payload) {
    auto p = framed(7, as_bytes("hello"));
    for (std::size_t n = 0; n < p.size(); ++n) CHECK(!peek_packet(byte_span(p).subspan(0, n)));
    auto got = peek_packet(byte_span(p));
    CHECK(got.has_value());
    CHECK_EQ(got->sequence, std::uint8_t{7});
    CHECK_EQ(got->consumed, std::size_t{9});
    CHECK_EQ(std::string(reinterpret_cast<const char*>(got->payload.data()), got->payload.size()),
             std::string("hello"));
}

CONDUIT_TEST(length_encoded_integers_cover_all_four_widths) {
    struct sample { std::uint64_t value; std::size_t encoded_size; };
    const sample samples[] = {{0, 1}, {250, 1}, {251, 3}, {65535, 3}, {65536, 4},
                              {0xFFFFFF, 4}, {0x1000000, 9}};
    for (const auto& s : samples) {
        std::vector<std::byte> out;
        byte_writer w{out};
        write_lenenc_int(w, s.value);
        CHECK_EQ(out.size(), s.encoded_size);
        byte_reader r{byte_span(out)};
        CHECK_EQ(read_lenenc_int(r), s.value);
        CHECK(r.empty());
    }
}

CONDUIT_TEST(length_encoded_string_reports_null_as_an_empty_optional) {
    std::vector<std::byte> out;
    byte_writer w{out};
    write_lenenc_string(w, "abc");
    w.u8(0xFB);  // NULL marker
    write_lenenc_string(w, "");
    byte_reader r{byte_span(out)};
    auto a = read_lenenc_string(r);
    CHECK(a.has_value());
    CHECK_EQ(std::string(*a), std::string("abc"));
    CHECK(!read_lenenc_string(r).has_value());
    auto c = read_lenenc_string(r);
    CHECK(c.has_value());
    CHECK_EQ(c->size(), std::size_t{0});
}

CONDUIT_TEST(handshake_v10_is_decoded_field_by_field) {
    auto body = make_handshake();
    auto h = decode_handshake(byte_span(body));
    CHECK_EQ(h.protocol_version, std::uint8_t{10});
    CHECK_EQ(h.server_version, std::string("8.0.36"));
    CHECK_EQ(h.connection_id, std::uint32_t{1234});
    CHECK_EQ(h.auth_plugin, std::string("mysql_native_password"));
    CHECK(h.capabilities & caps::plugin_auth);
    // Eight bytes from the first half plus twelve from the second, with the
    // terminating NUL dropped: exactly the twenty byte seed.
    CHECK_EQ(h.auth_data.size(), std::size_t{20});
    CHECK_EQ(std::string(reinterpret_cast<const char*>(h.auth_data.data()), 20),
             std::string("ABCDEFGHIJKLMNOPQRST"));
}

CONDUIT_TEST(handshake_of_an_unknown_protocol_version_is_rejected) {
    auto body = make_handshake();
    body[0] = std::byte{9};
    CHECK_THROWS(decode_handshake(byte_span(body)), protocol_error);
}

CONDUIT_TEST(handshake_response_layout_matches_the_specification) {
    std::vector<std::byte> out;
    std::uint32_t capabilities = caps::protocol_41 | caps::secure_connection | caps::plugin_auth |
                                 caps::connect_with_db;
    auto scramble = from_hex("00112233445566778899aabbccddeeff00112233");
    encode_handshake_response(out, capabilities, "root", byte_span(scramble), "shop",
                              "mysql_native_password");
    byte_reader r{byte_span(out)};
    CHECK_EQ(r.le32(), capabilities);
    CHECK_EQ(r.le32(), static_cast<std::uint32_t>(max_payload));
    CHECK_EQ(r.u8(), std::uint8_t{45});
    for (int i = 0; i < 23; ++i) CHECK_EQ(r.u8(), std::uint8_t{0});
    CHECK_EQ(std::string(r.cstr()), std::string("root"));
    CHECK_EQ(r.u8(), std::uint8_t{20});
    CHECK_EQ(to_hex(r.bytes(20)), to_hex(byte_span(scramble)));
    CHECK_EQ(std::string(r.cstr()), std::string("shop"));
    CHECK_EQ(std::string(r.cstr()), std::string("mysql_native_password"));
    CHECK(r.empty());
}

CONDUIT_TEST(packet_classification_separates_ok_err_eof_and_rows) {
    std::vector<std::byte> ok;
    {
        byte_writer w{ok};
        w.u8(0x00);
        write_lenenc_int(w, 5);   // affected rows
        write_lenenc_int(w, 11);  // last insert id
        w.le16(2);
        w.le16(0);
    }
    CHECK(classify(byte_span(ok)) == packet_kind::ok);
    auto decoded = decode_ok(byte_span(ok));
    CHECK_EQ(decoded.affected_rows, std::uint64_t{5});
    CHECK_EQ(decoded.last_insert_id, std::uint64_t{11});

    std::vector<std::byte> err;
    {
        byte_writer w{err};
        w.u8(0xFF);
        w.le16(1146);
        w.ch('#');
        w.raw(std::string_view("42S02"));
        w.raw(std::string_view("Table 'shop.nope' doesn't exist"));
    }
    CHECK(classify(byte_span(err)) == packet_kind::err);
    auto e = decode_err(byte_span(err));
    CHECK_EQ(e.code, std::uint16_t{1146});
    CHECK_EQ(e.sql_state, std::string("42S02"));
    CHECK(e.message.find("doesn't exist") != std::string::npos);

    auto eof = from_hex("fe 00 00 02 00");
    CHECK(classify(byte_span(eof)) == packet_kind::eof);

    // A row whose first column is a one byte string starting with 0x00 must not
    // be mistaken for an OK packet, which is why the length check exists.
    auto row = from_hex("00 01 41");
    CHECK(classify(byte_span(row)) == packet_kind::data);
}

CONDUIT_TEST(column_definition_and_text_row_decode_together) {
    std::vector<std::byte> col;
    {
        byte_writer w{col};
        write_lenenc_string(w, "def");
        write_lenenc_string(w, "shop");
        write_lenenc_string(w, "book");
        write_lenenc_string(w, "book");
        write_lenenc_string(w, "title");
        write_lenenc_string(w, "title");
        write_lenenc_int(w, 0x0c);
        w.le16(45);
        w.le32(255);
        w.u8(type::var_string);
        w.le16(0);
        w.u8(0);
    }
    auto c = decode_column_definition(byte_span(col));
    CHECK_EQ(c.name, std::string("title"));
    CHECK_EQ(c.schema, std::string("shop"));
    CHECK_EQ(std::string(type_name(c.type)), std::string("varchar"));

    std::vector<column> cols{c, c};
    std::vector<std::byte> row;
    {
        byte_writer w{row};
        write_lenenc_string(w, "Dune");
        w.u8(0xFB);
    }
    std::vector<field_view> fields;
    decode_text_row(byte_span(row), cols, fields);
    CHECK_EQ(fields.size(), std::size_t{2});
    CHECK_EQ(std::string(decode_text(fields[0])), std::string("Dune"));
    CHECK(fields[1].is_null);
    CHECK(fields[0].format == wire_format::text);
}

CONDUIT_TEST(text_row_with_leftover_bytes_is_a_protocol_error) {
    std::vector<column> cols(1);
    std::vector<std::byte> row;
    {
        byte_writer w{row};
        write_lenenc_string(w, "a");
        write_lenenc_string(w, "b");  // one column too many
    }
    std::vector<field_view> fields;
    CHECK_THROWS(decode_text_row(byte_span(row), cols, fields), protocol_error);
}

CONDUIT_TEST(auth_switch_request_carries_a_plugin_and_a_new_seed) {
    std::vector<std::byte> body;
    byte_writer w{body};
    w.u8(0xFE);
    w.cstr("mysql_native_password");
    w.raw(std::string_view("ABCDEFGHIJKLMNOPQRST"));
    w.u8(0);
    auto sw = decode_auth_switch(byte_span(body));
    CHECK_EQ(sw.plugin, std::string("mysql_native_password"));
    CHECK_EQ(sw.data.size(), std::size_t{20});
}

CONDUIT_TEST(mysql_codec_satisfies_the_shared_framing_concept) {
    auto p = framed(0, as_bytes("\xfe\x00\x00\x02\x00"));
    auto f = codec::peek(byte_span(p));
    CHECK(f.has_value());
    CHECK_EQ(std::string(codec::describe(*f)), std::string("EOF_Packet"));
}
