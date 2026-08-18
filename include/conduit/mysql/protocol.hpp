// MySQL client/server protocol: packet framing, the version 10 handshake and
// the text protocol query flow.
//
// Two things differ from PostgreSQL at every level and are the reason the two
// codecs share no code: MySQL is little endian, and it carries lengths as
// variable width integers rather than fixed width ones. The framing is also
// different in kind, since a MySQL packet has a sequence number the client has
// to echo, and a payload of exactly 0xFFFFFF bytes means the message continues
// in the next packet.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "conduit/bytes.hpp"
#include "conduit/codec.hpp"
#include "conduit/value.hpp"

namespace conduit::mysql {

inline constexpr std::size_t max_payload = 0xFFFFFF;

// Capability flags. Only the ones this client sets or tests are named.
namespace caps {
inline constexpr std::uint32_t long_password = 1;
inline constexpr std::uint32_t found_rows = 2;
inline constexpr std::uint32_t long_flag = 4;
inline constexpr std::uint32_t connect_with_db = 8;
inline constexpr std::uint32_t protocol_41 = 512;
inline constexpr std::uint32_t ssl = 2048;
inline constexpr std::uint32_t transactions = 8192;
inline constexpr std::uint32_t secure_connection = 32768;
inline constexpr std::uint32_t multi_results = 1u << 17;
inline constexpr std::uint32_t plugin_auth = 1u << 19;
inline constexpr std::uint32_t plugin_auth_lenenc = 1u << 21;
inline constexpr std::uint32_t deprecate_eof = 1u << 24;
}  // namespace caps

enum class command : std::uint8_t {
    quit = 0x01,
    query = 0x03,
    ping = 0x0E,
};

// One framed packet: the payload without the four byte header.
struct packet {
    byte_span payload{};
    std::uint8_t sequence = 0;
    std::size_t consumed = 0;
};

// Satisfies conduit::frame_codec. Static functions rather than a base class,
// so nothing virtual appears anywhere on the decode path.
struct codec {
    using frame = packet;
    static std::optional<packet> peek(byte_span in);
    static const char* describe(const packet& p);
};

std::optional<packet> peek_packet(byte_span in);

// Writes a packet header in front of a payload already appended to `out`, given
// where the payload started.
void write_packet(std::vector<std::byte>& out, std::uint8_t sequence, byte_span payload);

// --- length encoded integers and strings -------------------------------------
std::uint64_t read_lenenc_int(byte_reader& r);
// Reports NULL, which the wire spells as a 0xFB length byte in a result row.
std::optional<std::string_view> read_lenenc_string(byte_reader& r);
void write_lenenc_int(byte_writer& w, std::uint64_t v);
void write_lenenc_string(byte_writer& w, std::string_view s);

// --- handshake ---------------------------------------------------------------

struct handshake {
    std::uint8_t protocol_version = 0;
    std::string server_version;
    std::uint32_t connection_id = 0;
    std::vector<std::byte> auth_data;  // the 20 byte seed, both halves joined
    std::uint32_t capabilities = 0;
    std::uint8_t character_set = 0;
    std::uint16_t status_flags = 0;
    std::string auth_plugin;
};
handshake decode_handshake(byte_span payload);

void encode_handshake_response(std::vector<std::byte>& out, std::uint32_t capabilities,
                               std::string_view user, byte_span auth_response,
                               std::string_view database, std::string_view auth_plugin);

// --- generic server packets ---------------------------------------------------

enum class packet_kind { ok, err, eof, auth_switch, data };
packet_kind classify(byte_span payload);

struct ok_packet {
    std::uint64_t affected_rows = 0;
    std::uint64_t last_insert_id = 0;
    std::uint16_t status_flags = 0;
    std::uint16_t warnings = 0;
    std::string info;
};
ok_packet decode_ok(byte_span payload);

struct err_packet {
    std::uint16_t code = 0;
    std::string sql_state;
    std::string message;
    std::string summary() const;
};
err_packet decode_err(byte_span payload);

struct auth_switch {
    std::string plugin;
    std::vector<std::byte> data;
};
auth_switch decode_auth_switch(byte_span payload);

// --- result sets ---------------------------------------------------------------

struct column {
    std::string schema;
    std::string table;
    std::string name;
    std::string original_name;
    std::uint16_t character_set = 0;
    std::uint32_t length = 0;
    std::uint8_t type = 0;
    std::uint16_t flags = 0;
    std::uint8_t decimals = 0;
};
column decode_column_definition(byte_span payload);

// Text protocol row: one length encoded string per column, 0xFB for NULL. The
// views point into the payload, which points into the receive buffer.
void decode_text_row(byte_span payload, const std::vector<column>& cols,
                     std::vector<field_view>& into);

// MySQL field type codes, for the trace and for the type name table.
namespace type {
inline constexpr std::uint8_t decimal = 0;
inline constexpr std::uint8_t tiny = 1;
inline constexpr std::uint8_t short_ = 2;
inline constexpr std::uint8_t long_ = 3;
inline constexpr std::uint8_t float_ = 4;
inline constexpr std::uint8_t double_ = 5;
inline constexpr std::uint8_t null = 6;
inline constexpr std::uint8_t timestamp = 7;
inline constexpr std::uint8_t longlong = 8;
inline constexpr std::uint8_t int24 = 9;
inline constexpr std::uint8_t date = 10;
inline constexpr std::uint8_t time = 11;
inline constexpr std::uint8_t datetime = 12;
inline constexpr std::uint8_t year = 13;
inline constexpr std::uint8_t varchar = 15;
inline constexpr std::uint8_t bit = 16;
inline constexpr std::uint8_t newdecimal = 246;
inline constexpr std::uint8_t blob = 252;
inline constexpr std::uint8_t var_string = 253;
inline constexpr std::uint8_t string = 254;
}  // namespace type

const char* type_name(std::uint8_t code);

static_assert(frame_codec<codec>, "the MySQL codec must satisfy the shared framing concept");

}  // namespace conduit::mysql
