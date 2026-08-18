// The demonstration.
//
// One command, both backends. For each one it connects, builds a table, inserts
// rows, runs a parameterised query and prints the decoded typed values together
// with the protocol message trace. The trace is the part worth reading: it
// shows the exact messages the client wrote and read, and how many round trips
// each shape of query cost.
//
//     docker compose up -d
//     cmake --build build --target demo
//
// Connection details come from the environment when set, and otherwise from the
// ports in docker-compose.yml.
#include <cstdlib>
#include <exception>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "conduit/mysql/connection.hpp"
#include "conduit/pg/connection.hpp"
#include "conduit/pool.hpp"

using namespace conduit;
using namespace std::chrono_literals;

namespace {

std::string env_or(const char* name, const char* fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : std::string(fallback);
}
std::uint16_t env_port(const char* name, std::uint16_t fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? static_cast<std::uint16_t>(std::strtoul(v, nullptr, 10)) : fallback;
}

void rule(const char* title) {
    std::cout << "\n== " << title << " "
              << std::string(title && *title ? (68 - std::string(title).size()) : 68, '=')
              << "\n";
}

// The struct the rows are mapped onto. The binding below is checked at compile
// time: a member whose type has no decoder does not compile.
struct measurement {
    std::int64_t id = 0;
    std::string sensor;
    double reading = 0;
    bool valid = false;
};

}  // namespace

template <>
struct conduit::row_mapping<measurement> {
    static constexpr auto fields = std::tuple{
        conduit::bind_field("id", &measurement::id),
        conduit::bind_field("sensor", &measurement::sensor),
        conduit::bind_field("reading", &measurement::reading),
        conduit::bind_field("valid", &measurement::valid)};
};

namespace {

void print_rows(const std::vector<measurement>& rows) {
    std::cout << "    " << std::left << std::setw(5) << "id" << std::setw(12) << "sensor"
              << std::setw(12) << "reading" << "valid\n";
    for (const auto& m : rows) {
        std::cout << "    " << std::left << std::setw(5) << m.id << std::setw(12) << m.sensor
                  << std::setw(12) << std::fixed << std::setprecision(3) << m.reading
                  << (m.valid ? "true" : "false") << "\n";
    }
}

task<void> run_postgres(event_loop& loop) {
    pg::connection c{loop};

    pg::connect_params p;
    p.host = env_or("CONDUIT_PG_HOST", "127.0.0.1");
    p.port = env_port("CONDUIT_PG_PORT", 55432);
    p.user = env_or("CONDUIT_PG_USER", "conduit");
    p.password = env_or("CONDUIT_PG_PASSWORD", "conduit");
    p.database = env_or("CONDUIT_PG_DATABASE", "conduit");

    c.trace().enable(true);
    co_await c.open(p);
    std::cout << "  connected to PostgreSQL " << c.parameter("server_version") << " as " << p.user
              << ", backend pid " << c.backend_pid() << "\n";
    std::cout << "  authentication and startup trace:\n";
    c.trace().print(std::cout, "    ");
    c.trace().clear();

    co_await c.simple_query("DROP TABLE IF EXISTS conduit_demo");
    co_await c.simple_query(
        "CREATE TABLE conduit_demo (id bigint primary key, sensor text,"
        " reading double precision, valid boolean, amount numeric(10,3), seen_at timestamp)");
    co_await c.simple_query(
        "INSERT INTO conduit_demo VALUES"
        " (1,'north',12.500,true,1234.500,'2024-02-29 13:45:30.123456'),"
        " (2,'south',-3.250,false,-0.050,'1999-12-31 23:59:59'),"
        " (3,'east',44.125,true,0.001,'2000-01-01 00:00:00')");
    std::cout << "\n  table created and three rows inserted through the simple query flow\n";

    // --- simple query flow --------------------------------------------------
    c.trace().clear();
    auto simple = co_await c.simple_query("SELECT id, sensor FROM conduit_demo ORDER BY id");
    std::cout << "\n  simple query, " << simple.rows << " rows, "
              << c.trace().round_trips() << " round trip(s):\n";
    c.trace().print(std::cout, "    ");

    // --- extended query flow, first execution -------------------------------
    const char* sql =
        "SELECT id, sensor, reading, valid FROM conduit_demo WHERE reading > $1 ORDER BY id";
    c.trace().clear();
    auto rows = co_await c.query_as<measurement>(sql, pg::params(0.0), wire_format::binary);
    std::cout << "\n  extended query, first execution (Parse, Describe, Bind, Execute, Sync),"
              << " binary results:\n";
    c.trace().print(std::cout, "    ");
    print_rows(rows);

    // --- extended query flow, cached ----------------------------------------
    c.trace().clear();
    auto again = co_await c.query_as<measurement>(sql, pg::params(10.0), wire_format::binary);
    std::cout << "\n  same SQL again: the statement cache skips Parse and Describe\n";
    c.trace().print(std::cout, "    ");
    print_rows(again);
    std::cout << "    cache hits " << c.cache_hits() << ", misses " << c.cache_misses() << "\n";

    // --- decoding the harder types ------------------------------------------
    c.trace().clear();
    std::cout << "\n  arbitrary precision and calendar types, decoded from binary format:\n";
    co_await c.execute("SELECT id, amount, seen_at FROM conduit_demo ORDER BY id", {},
                       wire_format::binary,
                       [](const std::vector<pg::column>& cols, std::span<const field_view> row) {
                           std::cout << "    id=" << decode_i64(row[0]) << "  "
                                     << cols[1].name << "(" << pg::type_name(cols[1].type_oid)
                                     << ")=" << decode_numeric(row[1]) << "  " << cols[2].name
                                     << "(" << pg::type_name(cols[2].type_oid)
                                     << ")=" << decode_timestamp(row[2]).to_string() << "\n";
                       });

    // --- an error, and the recovery the protocol requires --------------------
    std::cout << "\n  a deliberate server error, to show the connection resynchronises:\n";
    try {
        co_await c.simple_query("SELECT * FROM no_such_table");
    } catch (const pg::server_exception& e) {
        std::cout << "    caught: " << e.info.summary() << "\n";
    }
    auto after = co_await c.simple_query("SELECT 1");
    std::cout << "    connection still usable, follow up query returned " << after.rows
              << " row\n";

    co_await c.close();
    co_return;
}

task<void> run_mysql(event_loop& loop) {
    mysql::connection c{loop};

    mysql::connect_params p;
    p.host = env_or("CONDUIT_MYSQL_HOST", "127.0.0.1");
    p.port = env_port("CONDUIT_MYSQL_PORT", 33306);
    p.user = env_or("CONDUIT_MYSQL_USER", "conduit");
    p.password = env_or("CONDUIT_MYSQL_PASSWORD", "conduit");
    p.database = env_or("CONDUIT_MYSQL_DATABASE", "conduit");

    c.trace().enable(true);
    co_await c.open(p);
    std::cout << "  connected to MySQL " << c.server_version() << " as " << p.user
              << ", connection id " << c.connection_id() << "\n";
    std::cout << "  handshake trace:\n";
    c.trace().print(std::cout, "    ");

    co_await c.query("DROP TABLE IF EXISTS conduit_demo");
    co_await c.query(
        "CREATE TABLE conduit_demo (id bigint primary key, sensor varchar(32),"
        " reading double, valid tinyint(1), amount decimal(10,3), seen_at datetime(6))");
    auto ins = co_await c.query(
        "INSERT INTO conduit_demo VALUES"
        " (1,'north',12.500,1,1234.500,'2024-02-29 13:45:30.123456'),"
        " (2,'south',-3.250,0,-0.050,'1999-12-31 23:59:59'),"
        " (3,'east',44.125,1,0.001,'2000-01-01 00:00:00')");
    std::cout << "\n  table created, " << ins.affected_rows << " rows inserted\n";

    c.trace().clear();
    auto rows = co_await c.query_as<measurement>(
        "SELECT id, sensor, reading, valid FROM conduit_demo WHERE reading > 0 ORDER BY id");
    std::cout << "\n  text protocol query, " << c.trace().round_trips() << " round trip:\n";
    c.trace().print(std::cout, "    ");
    print_rows(rows);

    c.trace().clear();
    std::cout << "\n  decimal and datetime, decoded from the text protocol by the same decoders:\n";
    co_await c.query("SELECT id, amount, seen_at FROM conduit_demo ORDER BY id",
                     [](const std::vector<mysql::column>& cols, std::span<const field_view> row) {
                         std::cout << "    id=" << decode_i64(row[0]) << "  " << cols[1].name << "("
                                   << mysql::type_name(cols[1].type)
                                   << ")=" << decode_numeric(row[1]) << "  " << cols[2].name << "("
                                   << mysql::type_name(cols[2].type)
                                   << ")=" << decode_timestamp(row[2]).to_string() << "\n";
                     });

    std::cout << "\n  a deliberate server error:\n";
    try {
        co_await c.query("SELECT * FROM no_such_table");
    } catch (const mysql::server_exception& e) {
        std::cout << "    caught: " << e.info.summary() << "\n";
    }
    auto after = co_await c.query("SELECT 1");
    std::cout << "    connection still usable, follow up query returned " << after.rows
              << " row\n";

    co_await c.close();
    co_return;
}

// Six pieces of work sharing two connections, to show that the pool suspends
// rather than blocks and that the work interleaves on one thread.
task<void> one_unit(connection_pool<pg::connection, pg::connect_params>& pool, int index,
                    std::string* order) {
    auto lease = co_await pool.acquire();
    auto r = co_await lease->execute("SELECT $1::int", pg::params(index));
    if (r.rows == 1) *order += std::to_string(index);
}

int run_pool_demo() {
    event_loop loop;
    pg::connect_params p;
    p.host = env_or("CONDUIT_PG_HOST", "127.0.0.1");
    p.port = env_port("CONDUIT_PG_PORT", 55432);
    p.user = env_or("CONDUIT_PG_USER", "conduit");
    p.password = env_or("CONDUIT_PG_PASSWORD", "conduit");
    p.database = env_or("CONDUIT_PG_DATABASE", "conduit");

    connection_pool<pg::connection, pg::connect_params> pool{loop, p, pool_config{2, 5000ms, 30000ms}};
    std::string order;
    for (int i = 1; i <= 6; ++i) loop.spawn(one_unit(pool, i, &order));
    loop.run();

    std::cout << "  six queries completed in the order " << order << " over a pool bounded at "
              << pool.config().max_size << "\n";
    std::cout << "  connections opened: " << pool.stats().created
              << ", acquisitions: " << pool.stats().acquired
              << ", acquisitions that had to wait: " << pool.stats().waited << "\n";
    loop.block_on(pool.close_all());
    return 0;
}

}  // namespace

int main() {
    int failures = 0;

    rule("PostgreSQL, wire protocol version 3");
    try {
        event_loop loop;
        loop.block_on(run_postgres(loop));
    } catch (const std::exception& e) {
        std::cout << "  PostgreSQL part failed: " << e.what() << "\n";
        std::cout << "  is the compose environment up?  docker compose up -d\n";
        ++failures;
    }

    rule("MySQL, client/server protocol");
    try {
        event_loop loop;
        loop.block_on(run_mysql(loop));
    } catch (const std::exception& e) {
        std::cout << "  MySQL part failed: " << e.what() << "\n";
        std::cout << "  is the compose environment up?  docker compose up -d\n";
        ++failures;
    }

    rule("Asynchronous connection pool");
    try {
        run_pool_demo();
    } catch (const std::exception& e) {
        std::cout << "  pool part failed: " << e.what() << "\n";
        ++failures;
    }

    std::cout << "\n";
    return failures == 0 ? 0 : 1;
}
