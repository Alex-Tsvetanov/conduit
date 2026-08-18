// The PostgreSQL codec, driven by byte streams built here rather than by a
// server. Every expected byte comes from the message formats in the protocol
// specification.
#include <string>

#include "check.hpp"
#include "conduit/pg/protocol.hpp"

using namespace conduit;
using namespace conduit::pg;

namespace {
// Builds one backend message: tag, length including itself, body.
std::vector<std::byte> backend_message(char tag, std::string_view body) {
    std::vector<std::byte> out;
    byte_writer w{out};
    w.ch(tag);
    w.be32(static_cast<std::uint32_t>(body.size() + 4));
    w.raw(body);
    return out;
}
}  // namespace

CONDUIT_TEST(startup_packet_has_no_tag_and_carries_the_protocol_version) {
    std::vector<std::byte> out;
    encode_startup(out, "alice", "shop");
    byte_reader r{byte_span(out)};
    CHECK_EQ(r.be32(), static_cast<std::uint32_t>(out.size()));
    CHECK_EQ(r.be32(), 196608u);  // 3.0
    CHECK_EQ(std::string(r.cstr()), std::string("user"));
    CHECK_EQ(std::string(r.cstr()), std::string("alice"));
    CHECK_EQ(std::string(r.cstr()), std::string("database"));
    CHECK_EQ(std::string(r.cstr()), std::string("shop"));
    CHECK_EQ(r.u8(), std::uint8_t{0});
    CHECK(r.empty());
}

CONDUIT_TEST(query_message_is_tag_length_and_a_c_string) {
    std::vector<std::byte> out;
    encode_query(out, "SELECT 1");
    CHECK_EQ(static_cast<char>(std::to_integer<std::uint8_t>(out[0])), 'Q');
    byte_reader r{byte_span(out).subspan(1)};
    CHECK_EQ(r.be32(), std::uint32_t{4 + 8 + 1});
    CHECK_EQ(std::string(r.cstr()), std::string("SELECT 1"));
}

CONDUIT_TEST(peek_frame_refuses_to_consume_a_partial_message) {
    auto whole = backend_message('Z', std::string(1, 'I'));
    for (std::size_t n = 0; n < whole.size(); ++n) {
        auto f = peek_frame(byte_span(whole).subspan(0, n));
        CHECK(!f.has_value());
    }
    auto f = peek_frame(byte_span(whole));
    CHECK(f.has_value());
    CHECK_EQ(f->tag, 'Z');
    CHECK_EQ(f->consumed, whole.size());
    CHECK_EQ(f->body.size(), std::size_t{1});
}

CONDUIT_TEST(peek_frame_finds_the_first_of_several_pipelined_messages) {
    std::vector<std::byte> stream;
    for (auto tag : {'1', '2', 'Z'}) {
        auto m = backend_message(tag, tag == 'Z' ? std::string("I") : std::string());
        stream.insert(stream.end(), m.begin(), m.end());
    }
    byte_span rest(stream);
    std::string tags;
    while (auto f = peek_frame(rest)) {
        tags += f->tag;
        rest = rest.subspan(f->consumed);
    }
    CHECK_EQ(tags, std::string("12Z"));
    CHECK_EQ(rest.size(), std::size_t{0});
}

CONDUIT_TEST(peek_frame_rejects_a_length_below_the_minimum) {
    auto bad = from_hex("5A 00 00 00 02");
    CHECK_THROWS(peek_frame(byte_span(bad)), protocol_error);
}

CONDUIT_TEST(authentication_md5_carries_a_four_byte_salt) {
    std::vector<std::byte> body;
    byte_writer w{body};
    w.be32(5);
    w.raw(std::string_view("\x01\x02\x03\x04", 4));
    auto a = decode_authentication(byte_span(body));
    CHECK(a.kind == auth_kind::md5_password);
    CHECK_EQ(a.salt.size(), std::size_t{4});
    CHECK_EQ(to_hex(byte_span(a.salt)), std::string("01020304"));
}

CONDUIT_TEST(authentication_sasl_lists_its_mechanisms) {
    std::vector<std::byte> body;
    byte_writer w{body};
    w.be32(10);
    w.cstr("SCRAM-SHA-256");
    w.cstr("SCRAM-SHA-256-PLUS");
    w.u8(0);
    auto a = decode_authentication(byte_span(body));
    CHECK(a.kind == auth_kind::sasl);
    CHECK_EQ(a.mechanisms.size(), std::size_t{2});
    CHECK_EQ(a.mechanisms[0], std::string("SCRAM-SHA-256"));
}

CONDUIT_TEST(error_response_keeps_the_fields_it_knows_and_skips_the_rest) {
    std::vector<std::byte> body;
    byte_writer w{body};
    w.ch('S'); w.cstr("ERROR");
    w.ch('V'); w.cstr("ERROR");            // unknown to this decoder, must be skipped
    w.ch('C'); w.cstr("42P01");
    w.ch('M'); w.cstr("relation \"nope\" does not exist");
    w.ch('P'); w.cstr("15");               // also skipped
    w.u8(0);
    auto e = decode_error(byte_span(body));
    CHECK_EQ(e.severity, std::string("ERROR"));
    CHECK_EQ(e.sqlstate, std::string("42P01"));
    CHECK_EQ(e.message, std::string("relation \"nope\" does not exist"));
    CHECK(e.summary().find("42P01") != std::string::npos);
}

CONDUIT_TEST(row_description_and_data_row_agree_on_shape) {
    std::vector<std::byte> desc;
    {
        byte_writer w{desc};
        w.be16(2);
        w.cstr("id");    w.be32(0); w.i16be(0); w.be32(oid::int4); w.i16be(4);  w.i32be(-1); w.i16be(1);
        w.cstr("title"); w.be32(0); w.i16be(0); w.be32(oid::text); w.i16be(-1); w.i32be(-1); w.i16be(0);
    }
    auto cols = decode_row_description(byte_span(desc));
    CHECK_EQ(cols.size(), std::size_t{2});
    CHECK_EQ(cols[0].name, std::string("id"));
    CHECK_EQ(cols[0].type_oid, oid::int4);
    CHECK(cols[0].format == wire_format::binary);
    CHECK(cols[1].format == wire_format::text);

    std::vector<std::byte> row_bytes;
    {
        byte_writer w{row_bytes};
        w.be16(2);
        w.be32(4); w.i32be(42);
        w.i32be(-1);  // NULL title
    }
    std::vector<field_view> row;
    decode_data_row(byte_span(row_bytes), cols, row);
    CHECK_EQ(row.size(), std::size_t{2});
    CHECK_EQ(decode_i32(row[0]), 42);
    CHECK(row[1].is_null);
}

CONDUIT_TEST(data_row_with_the_wrong_field_count_is_a_protocol_error) {
    std::vector<column> cols(2);
    std::vector<std::byte> row_bytes;
    {
        byte_writer w{row_bytes};
        w.be16(1);
        w.be32(1);
        w.u8('x');
    }
    std::vector<field_view> row;
    CHECK_THROWS(decode_data_row(byte_span(row_bytes), cols, row), protocol_error);
}

CONDUIT_TEST(command_complete_extracts_the_row_count_from_the_last_token) {
    std::vector<std::byte> b1;
    byte_writer{b1}.cstr("SELECT 3");
    CHECK_EQ(decode_command_complete(byte_span(b1)).rows, std::int64_t{3});

    std::vector<std::byte> b2;
    byte_writer{b2}.cstr("INSERT 0 7");
    CHECK_EQ(decode_command_complete(byte_span(b2)).rows, std::int64_t{7});

    std::vector<std::byte> b3;
    byte_writer{b3}.cstr("BEGIN");
    CHECK_EQ(decode_command_complete(byte_span(b3)).rows, std::int64_t{-1});
}

CONDUIT_TEST(bind_writes_null_as_a_negative_length) {
    std::vector<std::byte> out;
    encode_bind(out, "", "s1", {std::string("7"), std::nullopt}, wire_format::binary);
    byte_reader r{byte_span(out).subspan(1)};
    r.be32();                                   // length
    CHECK_EQ(std::string(r.cstr()), std::string(""));    // portal
    CHECK_EQ(std::string(r.cstr()), std::string("s1"));  // statement
    CHECK_EQ(r.be16(), std::uint16_t{0});       // no parameter format codes
    CHECK_EQ(r.be16(), std::uint16_t{2});       // two parameters
    CHECK_EQ(r.i32be(), 1);
    CHECK_EQ(std::string(r.str(1)), std::string("7"));
    CHECK_EQ(r.i32be(), -1);                    // NULL
    CHECK_EQ(r.be16(), std::uint16_t{1});       // one result format code
    CHECK_EQ(r.be16(), std::uint16_t{1});       // binary
}

CONDUIT_TEST(extended_flow_produces_the_messages_the_specification_names) {
    std::vector<std::byte> out;
    encode_parse(out, "s1", "SELECT $1::int", {});
    encode_describe(out, 'S', "s1");
    encode_bind(out, "", "s1", {std::string("1")}, wire_format::binary);
    encode_execute(out, "", 0);
    encode_sync(out);

    // Read the stream back the way the server would.
    std::string tags;
    byte_span rest(out);
    while (!rest.empty()) {
        char tag = static_cast<char>(std::to_integer<std::uint8_t>(rest[0]));
        std::uint32_t len = load_be32(rest.data() + 1);
        tags += tag;
        rest = rest.subspan(len + 1);
    }
    CHECK_EQ(tags, std::string("PDBES"));
}

CONDUIT_TEST(codec_type_satisfies_the_shared_framing_concept) {
    auto whole = backend_message('T', std::string(2, '\0'));
    auto f = codec::peek(byte_span(whole));
    CHECK(f.has_value());
    CHECK_EQ(std::string(codec::describe(*f)), std::string("RowDescription"));
    CHECK_EQ(std::string(backend_name('Z')), std::string("ReadyForQuery"));
}
