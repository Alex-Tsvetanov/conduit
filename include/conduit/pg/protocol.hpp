// PostgreSQL frontend/backend protocol, version 3.0.
//
// Pure codec: it turns bytes into messages and messages into bytes, and it owns
// no socket. Everything here can be tested by handing it a recorded byte
// stream, which is how the tests in tests/test_pg_protocol.cpp work.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "conduit/bytes.hpp"
#include "conduit/codec.hpp"
#include "conduit/value.hpp"

namespace conduit::pg {

// Backend message tags, as the specification spells them. Kept as a char enum
// because the tag is literally the byte on the wire.
enum class backend : char {
    authentication = 'R',
    backend_key_data = 'K',
    bind_complete = '2',
    close_complete = '3',
    command_complete = 'C',
    copy_in_response = 'G',
    copy_out_response = 'H',
    data_row = 'D',
    empty_query_response = 'I',
    error_response = 'E',
    no_data = 'n',
    notice_response = 'N',
    notification_response = 'A',
    parameter_description = 't',
    parameter_status = 'S',
    parse_complete = '1',
    portal_suspended = 's',
    ready_for_query = 'Z',
    row_description = 'T',
};

const char* backend_name(char tag);

// Subtypes of the Authentication message.
enum class auth_kind : std::int32_t {
    ok = 0,
    kerberos_v5 = 2,
    cleartext_password = 3,
    md5_password = 5,
    scm_credential = 6,
    gss = 7,
    gss_continue = 8,
    sspi = 9,
    sasl = 10,
    sasl_continue = 11,
    sasl_final = 12,
};

// One framed message: the tag, and a view of the body without the length prefix.
struct frame {
    char tag = 0;
    byte_span body{};
    std::size_t consumed = 0;  // total bytes of the framed message, tag included
};

// Returns nothing when the buffer holds less than one whole message. This is
// the resumable half of the codec: a short read costs a return, never a lost
// byte, because nothing is consumed until a whole message is present.
std::optional<frame> peek_frame(byte_span in);

// The framing half of the codec, packaged so it satisfies conduit::frame_codec.
// The static_assert at the bottom of this header is what makes the claim in the
// design chapter checkable rather than decorative.
struct codec {
    using frame = pg::frame;
    static std::optional<frame> peek(byte_span in) { return peek_frame(in); }
    static const char* describe(const frame& f) { return backend_name(f.tag); }
};

// --- frontend messages ------------------------------------------------------

// SSLRequest: length 8, code 80877103. Sent instead of StartupMessage. The
// server replies with a single byte, not a framed message: 'S' or 'N'.
inline constexpr std::uint32_t ssl_request_code = 80877103;
void encode_ssl_request(std::vector<std::byte>& out);

void encode_startup(std::vector<std::byte>& out, std::string_view user,
                    std::string_view database,
                    const std::vector<std::pair<std::string, std::string>>& options = {});
void encode_password(std::vector<std::byte>& out, std::string_view password);
void encode_sasl_initial(std::vector<std::byte>& out, std::string_view mechanism,
                         std::string_view response);
void encode_sasl_response(std::vector<std::byte>& out, std::string_view response);
void encode_query(std::vector<std::byte>& out, std::string_view sql);
void encode_parse(std::vector<std::byte>& out, std::string_view name, std::string_view sql,
                  const std::vector<std::uint32_t>& param_oids = {});
// A null parameter is an empty optional. Text format is used for parameters
// because it is the only format every type accepts without knowing its OID.
void encode_bind(std::vector<std::byte>& out, std::string_view portal, std::string_view stmt,
                 const std::vector<std::optional<std::string>>& params,
                 wire_format result_format);
void encode_describe(std::vector<std::byte>& out, char kind, std::string_view name);
void encode_execute(std::vector<std::byte>& out, std::string_view portal,
                    std::int32_t max_rows = 0);
void encode_close(std::vector<std::byte>& out, char kind, std::string_view name);
void encode_sync(std::vector<std::byte>& out);
void encode_flush(std::vector<std::byte>& out);
void encode_terminate(std::vector<std::byte>& out);

// --- backend messages -------------------------------------------------------

struct auth_request {
    auth_kind kind = auth_kind::ok;
    std::vector<std::byte> salt;        // md5: four bytes
    std::vector<std::string> mechanisms;  // sasl: the offered mechanism names
    std::string data;                   // sasl_continue and sasl_final payload
};
auth_request decode_authentication(byte_span body);

struct server_error {
    std::string severity;
    std::string sqlstate;
    std::string message;
    std::string detail;
    std::string hint;
    std::string where;

    std::string summary() const;
};
server_error decode_error(byte_span body);

struct column {
    std::string name;
    std::uint32_t table_oid = 0;
    std::int16_t column_index = 0;
    std::uint32_t type_oid = 0;
    std::int16_t type_size = 0;
    std::int32_t type_modifier = 0;
    wire_format format = wire_format::text;
};
std::vector<column> decode_row_description(byte_span body);

// Fills `into` with one view per column. The views point into `body`, which
// points into the connection's receive buffer: no copy is made anywhere on
// this path.
void decode_data_row(byte_span body, const std::vector<column>& cols,
                     std::vector<field_view>& into);

// "SELECT 3", "INSERT 0 1", "UPDATE 2". The trailing count is the only part
// most callers want.
struct command_tag {
    std::string text;
    std::int64_t rows = -1;
};
command_tag decode_command_complete(byte_span body);

// Transaction status letter from ReadyForQuery: 'I' idle, 'T' in a block,
// 'E' in a failed block.
char decode_ready_for_query(byte_span body);

// --- type OIDs --------------------------------------------------------------
// Only the ones the decoders act on. A column of any other type still arrives
// and can be read as text; the OID list is not a whitelist.
namespace oid {
inline constexpr std::uint32_t boolean = 16;
inline constexpr std::uint32_t bytea = 17;
inline constexpr std::uint32_t int8 = 20;
inline constexpr std::uint32_t int2 = 21;
inline constexpr std::uint32_t int4 = 23;
inline constexpr std::uint32_t text = 25;
inline constexpr std::uint32_t oid_t = 26;
inline constexpr std::uint32_t json = 114;
inline constexpr std::uint32_t float4 = 700;
inline constexpr std::uint32_t float8 = 701;
inline constexpr std::uint32_t varchar = 1043;
inline constexpr std::uint32_t date = 1082;
inline constexpr std::uint32_t time = 1083;
inline constexpr std::uint32_t timestamp = 1114;
inline constexpr std::uint32_t timestamptz = 1184;
inline constexpr std::uint32_t numeric = 1700;
inline constexpr std::uint32_t uuid = 2950;

inline constexpr std::uint32_t bool_array = 1000;
inline constexpr std::uint32_t int2_array = 1005;
inline constexpr std::uint32_t int4_array = 1007;
inline constexpr std::uint32_t text_array = 1009;
inline constexpr std::uint32_t varchar_array = 1015;
inline constexpr std::uint32_t int8_array = 1016;
inline constexpr std::uint32_t float4_array = 1021;
inline constexpr std::uint32_t float8_array = 1022;
inline constexpr std::uint32_t numeric_array = 1231;
}  // namespace oid

const char* type_name(std::uint32_t type_oid);

static_assert(frame_codec<codec>, "the PostgreSQL codec must satisfy the shared framing concept");

}  // namespace conduit::pg
