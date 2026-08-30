#include "conduit/pg/protocol.hpp"

#include <cstdlib>
#include <utility>

namespace conduit::pg {
namespace {

// Every frontend message except the startup packet is: tag, int32 length
// including itself, body. This helper writes the tag, reserves the length and
// returns the offset so it can be patched once the body is known.
struct message_writer {
    std::vector<std::byte>& out;
    byte_writer w;
    std::size_t len_at;

    message_writer(std::vector<std::byte>& o, char tag) : out(o), w(o), len_at(0) {
        w.ch(tag);
        len_at = w.reserve_be32();
    }
    ~message_writer() {
        w.patch_be32(len_at, static_cast<std::uint32_t>(out.size() - len_at));
    }
};

}  // namespace

const char* backend_name(char tag) {
    switch (static_cast<backend>(tag)) {
        case backend::authentication: return "Authentication";
        case backend::backend_key_data: return "BackendKeyData";
        case backend::bind_complete: return "BindComplete";
        case backend::close_complete: return "CloseComplete";
        case backend::command_complete: return "CommandComplete";
        case backend::copy_in_response: return "CopyInResponse";
        case backend::copy_out_response: return "CopyOutResponse";
        case backend::data_row: return "DataRow";
        case backend::empty_query_response: return "EmptyQueryResponse";
        case backend::error_response: return "ErrorResponse";
        case backend::no_data: return "NoData";
        case backend::notice_response: return "NoticeResponse";
        case backend::notification_response: return "NotificationResponse";
        case backend::parameter_description: return "ParameterDescription";
        case backend::parameter_status: return "ParameterStatus";
        case backend::parse_complete: return "ParseComplete";
        case backend::portal_suspended: return "PortalSuspended";
        case backend::ready_for_query: return "ReadyForQuery";
        case backend::row_description: return "RowDescription";
    }
    return "Unknown";
}

std::optional<frame> peek_frame(byte_span in) {
    if (in.size() < 5) return std::nullopt;
    std::uint32_t len = load_be32(in.data() + 1);
    if (len < 4) throw protocol_error("message length below the minimum of four");
    std::size_t total = std::size_t{len} + 1;
    if (in.size() < total) return std::nullopt;
    frame f;
    f.tag = static_cast<char>(std::to_integer<std::uint8_t>(in[0]));
    f.body = in.subspan(5, total - 5);
    f.consumed = total;
    return f;
}

// --- frontend ---------------------------------------------------------------

void encode_ssl_request(std::vector<std::byte>& out) {
    byte_writer w{out};
    w.be32(8);
    w.be32(ssl_request_code);
}

void encode_startup(std::vector<std::byte>& out, std::string_view user,
                    std::string_view database,
                    const std::vector<std::pair<std::string, std::string>>& options) {
    // The startup packet has no tag byte. That asymmetry is in the protocol,
    // not a shortcut here.
    byte_writer w{out};
    auto len_at = w.reserve_be32();
    w.be32(196608);  // protocol 3.0, major in the high half
    w.cstr("user");
    w.cstr(user);
    if (!database.empty()) {
        w.cstr("database");
        w.cstr(database);
    }
    for (const auto& [k, v] : options) {
        w.cstr(k);
        w.cstr(v);
    }
    w.u8(0);
    w.patch_be32(len_at, static_cast<std::uint32_t>(out.size() - len_at));
}

void encode_password(std::vector<std::byte>& out, std::string_view password) {
    message_writer m{out, 'p'};
    m.w.cstr(password);
}

void encode_sasl_initial(std::vector<std::byte>& out, std::string_view mechanism,
                         std::string_view response) {
    message_writer m{out, 'p'};
    m.w.cstr(mechanism);
    m.w.be32(static_cast<std::uint32_t>(response.size()));
    m.w.raw(response);
}

void encode_sasl_response(std::vector<std::byte>& out, std::string_view response) {
    message_writer m{out, 'p'};
    m.w.raw(response);
}

void encode_query(std::vector<std::byte>& out, std::string_view sql) {
    message_writer m{out, 'Q'};
    m.w.cstr(sql);
}

void encode_parse(std::vector<std::byte>& out, std::string_view name, std::string_view sql,
                  const std::vector<std::uint32_t>& param_oids) {
    message_writer m{out, 'P'};
    m.w.cstr(name);
    m.w.cstr(sql);
    m.w.be16(static_cast<std::uint16_t>(param_oids.size()));
    for (auto o : param_oids) m.w.be32(o);
}

void encode_bind(std::vector<std::byte>& out, std::string_view portal, std::string_view stmt,
                 const std::vector<std::optional<std::string>>& params,
                 wire_format result_format) {
    message_writer m{out, 'B'};
    m.w.cstr(portal);
    m.w.cstr(stmt);
    m.w.be16(0);  // no parameter format codes, so all parameters are text
    m.w.be16(static_cast<std::uint16_t>(params.size()));
    for (const auto& p : params) {
        if (!p) {
            m.w.i32be(-1);  // the wire spelling of NULL
        } else {
            m.w.be32(static_cast<std::uint32_t>(p->size()));
            m.w.raw(*p);
        }
    }
    m.w.be16(1);  // one result format code, applied to every column
    m.w.be16(static_cast<std::uint16_t>(result_format));
}

void encode_describe(std::vector<std::byte>& out, char kind, std::string_view name) {
    message_writer m{out, 'D'};
    m.w.ch(kind);  // 'S' statement, 'P' portal
    m.w.cstr(name);
}

void encode_execute(std::vector<std::byte>& out, std::string_view portal, std::int32_t max_rows) {
    message_writer m{out, 'E'};
    m.w.cstr(portal);
    m.w.i32be(max_rows);
}

void encode_close(std::vector<std::byte>& out, char kind, std::string_view name) {
    message_writer m{out, 'C'};
    m.w.ch(kind);
    m.w.cstr(name);
}

void encode_sync(std::vector<std::byte>& out) { message_writer m{out, 'S'}; }
void encode_flush(std::vector<std::byte>& out) { message_writer m{out, 'H'}; }
void encode_terminate(std::vector<std::byte>& out) { message_writer m{out, 'X'}; }

// --- backend ----------------------------------------------------------------

auth_request decode_authentication(byte_span body) {
    byte_reader r{body};
    auth_request a;
    a.kind = static_cast<auth_kind>(r.i32be());
    switch (a.kind) {
        case auth_kind::md5_password: {
            auto s = r.bytes(4);
            a.salt.assign(s.begin(), s.end());
            break;
        }
        case auth_kind::sasl: {
            // A list of mechanism names, terminated by an empty one.
            for (;;) {
                auto name = r.cstr();
                if (name.empty()) break;
                a.mechanisms.emplace_back(name);
            }
            break;
        }
        case auth_kind::sasl_continue:
        case auth_kind::sasl_final: {
            auto rest = r.rest();
            a.data.assign(reinterpret_cast<const char*>(rest.data()), rest.size());
            break;
        }
        default:
            break;
    }
    return a;
}

server_error decode_error(byte_span body) {
    // A sequence of one byte field codes, each followed by a C string, ended by
    // a zero byte. Unknown codes are skipped rather than rejected, because the
    // server is allowed to add fields.
    byte_reader r{body};
    server_error e;
    while (!r.empty()) {
        char code = static_cast<char>(r.u8());
        if (code == 0) break;
        auto value = r.cstr();
        switch (code) {
            case 'S': e.severity.assign(value); break;
            case 'C': e.sqlstate.assign(value); break;
            case 'M': e.message.assign(value); break;
            case 'D': e.detail.assign(value); break;
            case 'H': e.hint.assign(value); break;
            case 'W': e.where.assign(value); break;
            default: break;
        }
    }
    return e;
}

std::string server_error::summary() const {
    std::string s = severity.empty() ? "ERROR" : severity;
    if (!sqlstate.empty()) s += " " + sqlstate;
    if (!message.empty()) s += ": " + message;
    if (!detail.empty()) s += " (" + detail + ")";
    return s;
}

std::vector<column> decode_row_description(byte_span body) {
    byte_reader r{body};
    std::uint16_t n = r.be16();
    std::vector<column> cols;
    cols.reserve(n);
    for (std::uint16_t i = 0; i < n; ++i) {
        column c;
        c.name.assign(r.cstr());
        c.table_oid = r.be32();
        c.column_index = r.i16be();
        c.type_oid = r.be32();
        c.type_size = r.i16be();
        c.type_modifier = r.i32be();
        c.format = static_cast<wire_format>(r.i16be());
        cols.push_back(std::move(c));
    }
    return cols;
}

void decode_data_row(byte_span body, const std::vector<column>& cols,
                     std::vector<field_view>& into) {
    byte_reader r{body};
    std::uint16_t n = r.be16();
    if (n != cols.size())
        throw protocol_error("DataRow has " + std::to_string(n) + " fields but RowDescription had " +
                             std::to_string(cols.size()));
    into.clear();
    into.reserve(n);
    for (std::uint16_t i = 0; i < n; ++i) {
        field_view f;
        f.oid = cols[i].type_oid;
        f.format = cols[i].format;
        std::int32_t len = r.i32be();
        if (len < 0) f.is_null = true;
        else f.data = r.bytes(static_cast<std::size_t>(len));
        into.push_back(f);
    }
}

command_tag decode_command_complete(byte_span body) {
    byte_reader r{body};
    command_tag t;
    t.text.assign(r.cstr());
    // The affected row count is the last space separated token when it is a
    // number. "INSERT 0 1" puts the oid first, which is why the last token wins.
    auto pos = t.text.find_last_of(' ');
    if (pos != std::string::npos && pos + 1 < t.text.size()) {
        const char* first = t.text.data() + pos + 1;
        char* end = nullptr;
        long long v = std::strtoll(first, &end, 10);
        if (end != first && *end == '\0') t.rows = v;
    }
    return t;
}

char decode_ready_for_query(byte_span body) {
    byte_reader r{body};
    return static_cast<char>(r.u8());
}

const char* type_name(std::uint32_t type_oid) {
    switch (type_oid) {
        case oid::boolean: return "bool";
        case oid::bytea: return "bytea";
        case oid::int8: return "int8";
        case oid::int2: return "int2";
        case oid::int4: return "int4";
        case oid::text: return "text";
        case oid::oid_t: return "oid";
        case oid::json: return "json";
        case oid::float4: return "float4";
        case oid::float8: return "float8";
        case oid::varchar: return "varchar";
        case oid::date: return "date";
        case oid::time: return "time";
        case oid::timestamp: return "timestamp";
        case oid::timestamptz: return "timestamptz";
        case oid::numeric: return "numeric";
        case oid::uuid: return "uuid";
        case oid::bool_array: return "bool[]";
        case oid::int2_array: return "int2[]";
        case oid::int4_array: return "int4[]";
        case oid::text_array: return "text[]";
        case oid::varchar_array: return "varchar[]";
        case oid::int8_array: return "int8[]";
        case oid::float4_array: return "float4[]";
        case oid::float8_array: return "float8[]";
        case oid::numeric_array: return "numeric[]";
        default: return "oid";
    }
}

}  // namespace conduit::pg
