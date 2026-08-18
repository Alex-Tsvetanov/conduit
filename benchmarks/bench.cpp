// The measurement program.
//
// Separate from the tests on purpose: a test says whether the code is correct,
// a measurement says what it costs, and mixing the two makes both harder to
// read. Every number this program prints comes from a clock reading taken here.
// Nothing is estimated and nothing is carried over from a previous run.
//
//     docker compose up -d
//     cmake --build build --target bench
//
// Output is a set of tables. The raw per repetition samples go to
// benchmarks/results/ when --raw is passed, so the appendix of the report can
// quote them.
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "conduit/mysql/connection.hpp"
#include "conduit/pg/connection.hpp"
#include "conduit/pool.hpp"

#ifdef CONDUIT_HAVE_LIBPQ
#  include <libpq-fe.h>
#endif

using namespace conduit;
using namespace std::chrono_literals;
using clock_type = std::chrono::steady_clock;

namespace {

// --- sample statistics -------------------------------------------------------

struct summary {
    std::size_t n = 0;
    double median_us = 0;
    double p95_us = 0;
    double mean_us = 0;
    double stddev_us = 0;
    double min_us = 0;
    double max_us = 0;
};

summary summarise(std::vector<double> samples) {
    summary s;
    if (samples.empty()) return s;
    std::sort(samples.begin(), samples.end());
    s.n = samples.size();
    s.min_us = samples.front();
    s.max_us = samples.back();
    s.median_us = samples[samples.size() / 2];
    s.p95_us = samples[static_cast<std::size_t>(std::floor(0.95 * (samples.size() - 1)))];
    double total = 0;
    for (double v : samples) total += v;
    s.mean_us = total / static_cast<double>(samples.size());
    double acc = 0;
    for (double v : samples) acc += (v - s.mean_us) * (v - s.mean_us);
    s.stddev_us = samples.size() > 1 ? std::sqrt(acc / static_cast<double>(samples.size() - 1)) : 0;
    return s;
}

void row(const std::string& label, const summary& s, const std::string& extra = {}) {
    std::cout << "  " << std::left << std::setw(38) << label << std::right << std::fixed
              << std::setprecision(1) << std::setw(10) << s.median_us << std::setw(10) << s.p95_us
              << std::setw(10) << s.mean_us << std::setw(10) << s.stddev_us << std::setw(7) << s.n;
    if (!extra.empty()) std::cout << "   " << extra;
    std::cout << "\n";
}

void header(const std::string& title) {
    std::cout << "\n" << title << "\n";
    std::cout << "  " << std::left << std::setw(38) << "case" << std::right << std::setw(10)
              << "median" << std::setw(10) << "p95" << std::setw(10) << "mean" << std::setw(10)
              << "stddev" << std::setw(7) << "n" << "   (microseconds)\n";
    std::cout << "  " << std::string(85, '-') << "\n";
}

std::string env_or(const char* name, const char* fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : std::string(fallback);
}
std::uint16_t env_port(const char* name, std::uint16_t fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? static_cast<std::uint16_t>(std::strtoul(v, nullptr, 10)) : fallback;
}

pg::connect_params pg_params() {
    pg::connect_params p;
    p.host = env_or("CONDUIT_PG_HOST", "127.0.0.1");
    p.port = env_port("CONDUIT_PG_PORT", 55432);
    p.user = env_or("CONDUIT_PG_USER", "conduit");
    p.password = env_or("CONDUIT_PG_PASSWORD", "conduit");
    p.database = env_or("CONDUIT_PG_DATABASE", "conduit");
    return p;
}

mysql::connect_params mysql_params() {
    mysql::connect_params p;
    p.host = env_or("CONDUIT_MYSQL_HOST", "127.0.0.1");
    p.port = env_port("CONDUIT_MYSQL_PORT", 33306);
    p.user = env_or("CONDUIT_MYSQL_USER", "conduit");
    p.password = env_or("CONDUIT_MYSQL_PASSWORD", "conduit");
    p.database = env_or("CONDUIT_MYSQL_DATABASE", "conduit");
    return p;
}

constexpr int warmup = 20;
constexpr int reps = 500;

// Collected so the raw samples can be written out and quoted in the appendix.
std::vector<std::pair<std::string, std::vector<double>>> raw_samples;

void keep(const std::string& name, const std::vector<double>& samples) {
    raw_samples.emplace_back(name, samples);
}

// --- PostgreSQL --------------------------------------------------------------

task<void> pg_setup(pg::connection& c, int rows) {
    co_await c.simple_query("DROP TABLE IF EXISTS conduit_bench");
    co_await c.simple_query(
        "CREATE TABLE conduit_bench (id bigint primary key, label text,"
        " value double precision, flag boolean)");
    std::string sql = "INSERT INTO conduit_bench VALUES ";
    for (int i = 1; i <= rows; ++i) {
        if (i > 1) sql += ",";
        sql += "(" + std::to_string(i) + ",'label" + std::to_string(i) + "'," +
               std::to_string(i * 1.5) + "," + ((i % 2) ? "true" : "false") + ")";
    }
    co_await c.simple_query(sql);
    co_return;
}

struct pg_results {
    summary simple_one;
    summary extended_first;
    summary extended_cached;
    summary extended_no_cache;
    summary large_text;
    summary large_binary;
    std::size_t simple_msgs = 0;
    std::size_t extended_first_msgs = 0;
    std::size_t extended_cached_msgs = 0;
    std::size_t simple_trips = 0;
    std::size_t extended_first_trips = 0;
    std::size_t extended_cached_trips = 0;
    std::size_t large_rows = 0;
    double decode_text_us = 0;
    double decode_binary_us = 0;
};

task<pg_results> measure_pg(event_loop& loop, int large_rows) {
    pg_results out;
    pg::connection c{loop};
    // The cold cache loop below runs a different SQL text on every repetition. With
    // the default cache of 32 entries the cache saturates after 32 of them, and every
    // later repetition then also pays an eviction: an extra Close, a second flush and
    // a second wait for the server. That is a real cost, but it is not the cost of a
    // cache miss, and folding the two into one number labelled "cold cache" measures
    // the wrong thing. The cache is sized so that no eviction happens instead.
    auto params = pg_params();
    params.statement_cache_size = static_cast<std::size_t>(warmup + reps + 16);
    co_await c.open(params);
    co_await pg_setup(c, large_rows);

    // --- one row, simple query flow -----------------------------------------
    {
        std::vector<double> samples;
        for (int i = 0; i < warmup + reps; ++i) {
            auto t0 = clock_type::now();
            co_await c.simple_query("SELECT id, label FROM conduit_bench WHERE id = 1");
            auto dt = std::chrono::duration<double, std::micro>(clock_type::now() - t0).count();
            if (i >= warmup) samples.push_back(dt);
        }
        out.simple_one = summarise(samples);
        keep("pg_simple_one_row", samples);
    }

    // --- extended flow, cache cold every time --------------------------------
    // A fresh connection per repetition would also measure the connect, so the
    // cache is cleared instead by using a different statement text each time.
    {
        std::vector<double> samples;
        for (int i = 0; i < warmup + reps; ++i) {
            std::string sql = "SELECT id, label FROM conduit_bench WHERE id = $1 /*" +
                              std::to_string(i) + "*/";
            auto t0 = clock_type::now();
            co_await c.execute(sql, pg::params(1), wire_format::binary);
            auto dt = std::chrono::duration<double, std::micro>(clock_type::now() - t0).count();
            if (i >= warmup) samples.push_back(dt);
        }
        out.extended_first = summarise(samples);
        keep("pg_extended_first_execution", samples);
    }

    // --- extended flow, cache warm ------------------------------------------
    {
        const char* sql = "SELECT id, label FROM conduit_bench WHERE id = $1";
        std::vector<double> samples;
        for (int i = 0; i < warmup + reps; ++i) {
            auto t0 = clock_type::now();
            co_await c.execute(sql, pg::params(1), wire_format::binary);
            auto dt = std::chrono::duration<double, std::micro>(clock_type::now() - t0).count();
            if (i >= warmup) samples.push_back(dt);
        }
        out.extended_cached = summarise(samples);
        keep("pg_extended_cached", samples);
    }

    // --- message counts, from the trace --------------------------------------
    {
        c.trace().enable(true);
        c.trace().clear();
        co_await c.simple_query("SELECT id, label FROM conduit_bench WHERE id = 1");
        out.simple_msgs = c.trace().entries().size();
        out.simple_trips = c.trace().round_trips();

        c.trace().clear();
        co_await c.execute("SELECT id, label FROM conduit_bench WHERE id = $1 /*counted*/",
                           pg::params(1), wire_format::binary);
        out.extended_first_msgs = c.trace().entries().size();
        out.extended_first_trips = c.trace().round_trips();

        c.trace().clear();
        co_await c.execute("SELECT id, label FROM conduit_bench WHERE id = $1 /*counted*/",
                           pg::params(1), wire_format::binary);
        out.extended_cached_msgs = c.trace().entries().size();
        out.extended_cached_trips = c.trace().round_trips();
        c.trace().enable(false);
        c.trace().clear();
    }

    // --- a large result, text against binary ---------------------------------
    {
        const char* sql = "SELECT id, label, value, flag FROM conduit_bench";
        std::vector<double> text_samples, binary_samples;
        double text_decode = 0, binary_decode = 0;
        std::size_t seen = 0;

        for (int i = 0; i < warmup + reps / 5; ++i) {
            double decode_us = 0;
            auto t0 = clock_type::now();
            auto r = co_await c.execute(
                sql, {}, wire_format::text,
                [&](const std::vector<pg::column>&, std::span<const field_view> row) {
                    auto d0 = clock_type::now();
                    volatile auto id = decode_i64(row[0]);
                    volatile auto v = decode_f64(row[2]);
                    volatile auto f = decode_bool(row[3]);
                    (void)id; (void)v; (void)f;
                    decode_us +=
                        std::chrono::duration<double, std::micro>(clock_type::now() - d0).count();
                });
            auto dt = std::chrono::duration<double, std::micro>(clock_type::now() - t0).count();
            if (i >= warmup) { text_samples.push_back(dt); text_decode += decode_us; }
            seen = r.rows;
        }
        for (int i = 0; i < warmup + reps / 5; ++i) {
            double decode_us = 0;
            auto t0 = clock_type::now();
            co_await c.execute(sql, {}, wire_format::binary,
                               [&](const std::vector<pg::column>&, std::span<const field_view> row) {
                                   auto d0 = clock_type::now();
                                   volatile auto id = decode_i64(row[0]);
                                   volatile auto v = decode_f64(row[2]);
                                   volatile auto f = decode_bool(row[3]);
                                   (void)id; (void)v; (void)f;
                                   decode_us += std::chrono::duration<double, std::micro>(
                                                    clock_type::now() - d0).count();
                               });
            auto dt = std::chrono::duration<double, std::micro>(clock_type::now() - t0).count();
            if (i >= warmup) { binary_samples.push_back(dt); binary_decode += decode_us; }
        }
        out.large_text = summarise(text_samples);
        out.large_binary = summarise(binary_samples);
        out.large_rows = seen;
        out.decode_text_us = text_decode / static_cast<double>(text_samples.size());
        out.decode_binary_us = binary_decode / static_cast<double>(binary_samples.size());
        keep("pg_large_result_text", text_samples);
        keep("pg_large_result_binary", binary_samples);
    }

    co_await c.close();
    co_return out;
}

// --- pool acquisition latency --------------------------------------------------

struct pool_point {
    std::size_t pool_size;
    std::size_t concurrency;
    summary acquire;
    std::size_t waited;
};

task<void> pool_worker(connection_pool<pg::connection, pg::connect_params>& pool,
                       std::vector<double>* samples, int iterations) {
    for (int i = 0; i < iterations; ++i) {
        auto t0 = clock_type::now();
        auto lease = co_await pool.acquire();
        samples->push_back(
            std::chrono::duration<double, std::micro>(clock_type::now() - t0).count());
        co_await lease->execute("SELECT 1");
    }
    co_return;
}

pool_point measure_pool(std::size_t pool_size, std::size_t concurrency, int iterations) {
    event_loop loop;
    connection_pool<pg::connection, pg::connect_params> pool{
        loop, pg_params(), pool_config{pool_size, 30000ms, 60000ms}};

    std::vector<std::vector<double>> per_worker(concurrency);

    // Warm the pool: pool_size workers acquire at the same time, which forces
    // every connection to be opened before the timed part starts. Doing this
    // sequentially would open exactly one connection and leave the connect cost
    // inside the measurement.
    std::vector<std::vector<double>> warm(pool_size);
    for (std::size_t i = 0; i < pool_size; ++i) loop.spawn(pool_worker(pool, &warm[i], 1));
    loop.run();

    for (std::size_t i = 0; i < concurrency; ++i)
        loop.spawn(pool_worker(pool, &per_worker[i], iterations));
    loop.run();

    std::vector<double> all;
    for (auto& v : per_worker) all.insert(all.end(), v.begin(), v.end());
    pool_point p{pool_size, concurrency, summarise(all), pool.stats().waited};
    keep("pool_acquire_size" + std::to_string(pool_size) + "_conc" + std::to_string(concurrency),
         all);
    loop.block_on(pool.close_all());
    return p;
}

// --- MySQL ---------------------------------------------------------------------

task<summary> measure_mysql(event_loop& loop, int large_rows, summary* large) {
    mysql::connection c{loop};
    co_await c.open(mysql_params());
    co_await c.query("DROP TABLE IF EXISTS conduit_bench");
    co_await c.query(
        "CREATE TABLE conduit_bench (id bigint primary key, label varchar(64),"
        " value double, flag tinyint(1))");
    std::string sql = "INSERT INTO conduit_bench VALUES ";
    for (int i = 1; i <= large_rows; ++i) {
        if (i > 1) sql += ",";
        sql += "(" + std::to_string(i) + ",'label" + std::to_string(i) + "'," +
               std::to_string(i * 1.5) + "," + std::to_string(i % 2) + ")";
    }
    co_await c.query(sql);

    std::vector<double> one;
    for (int i = 0; i < warmup + reps; ++i) {
        auto t0 = clock_type::now();
        co_await c.query("SELECT id, label FROM conduit_bench WHERE id = 1");
        auto dt = std::chrono::duration<double, std::micro>(clock_type::now() - t0).count();
        if (i >= warmup) one.push_back(dt);
    }
    keep("mysql_simple_one_row", one);

    std::vector<double> big;
    for (int i = 0; i < warmup + reps / 5; ++i) {
        auto t0 = clock_type::now();
        co_await c.query("SELECT id, label, value, flag FROM conduit_bench",
                         [](const std::vector<mysql::column>&, std::span<const field_view> row) {
                             volatile auto id = decode_i64(row[0]);
                             volatile auto v = decode_f64(row[2]);
                             (void)id; (void)v;
                         });
        auto dt = std::chrono::duration<double, std::micro>(clock_type::now() - t0).count();
        if (i >= warmup) big.push_back(dt);
    }
    keep("mysql_large_result_text", big);
    *large = summarise(big);

    co_await c.close();
    co_return summarise(one);
}

// --- optional libpq baseline ------------------------------------------------------

#ifdef CONDUIT_HAVE_LIBPQ
summary measure_libpq() {
    auto p = pg_params();
    std::string conninfo = "host=" + p.host + " port=" + std::to_string(p.port) +
                           " user=" + p.user + " password=" + p.password +
                           " dbname=" + p.database;
    PGconn* conn = PQconnectdb(conninfo.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cout << "  libpq baseline unavailable: " << PQerrorMessage(conn) << "\n";
        PQfinish(conn);
        return {};
    }
    std::vector<double> samples;
    for (int i = 0; i < warmup + reps; ++i) {
        auto t0 = clock_type::now();
        PGresult* r = PQexec(conn, "SELECT id, label FROM conduit_bench WHERE id = 1");
        PQclear(r);
        auto dt = std::chrono::duration<double, std::micro>(clock_type::now() - t0).count();
        if (i >= warmup) samples.push_back(dt);
    }
    PQfinish(conn);
    keep("libpq_simple_one_row", samples);
    return summarise(samples);
}
#endif

void write_raw() {
    std::filesystem::create_directories("benchmarks/results");
    std::ofstream f("benchmarks/results/raw_samples.csv");
    f << "case,repetition,microseconds\n";
    for (const auto& [name, samples] : raw_samples)
        for (std::size_t i = 0; i < samples.size(); ++i)
            f << name << "," << i << "," << std::fixed << std::setprecision(3) << samples[i]
              << "\n";
    std::cout << "\nraw samples written to benchmarks/results/raw_samples.csv\n";
}

}  // namespace

int main(int argc, char** argv) {
    bool raw = false;
    int large_rows = 5000;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--raw") raw = true;
        else if (a.rfind("--rows=", 0) == 0) large_rows = std::atoi(a.c_str() + 7);
    }

    std::cout << "Conduit measurements\n";
    std::cout << "  repetitions " << reps << ", warm up repetitions " << warmup
              << " (discarded), large result " << large_rows << " rows\n";
    std::cout << "  both servers are the ones in docker-compose.yml, reached over loopback\n";

    int failures = 0;

    pg_results pg{};
    try {
        event_loop loop;
        pg = loop.block_on(measure_pg(loop, large_rows));

        header("PostgreSQL, one row");
        row("simple query flow", pg.simple_one);
        row("extended flow, first execution", pg.extended_first);
        row("extended flow, statement cached", pg.extended_cached);

        header("PostgreSQL, " + std::to_string(pg.large_rows) + " rows");
        row("extended flow, text results", pg.large_text,
            "decode " + std::to_string(static_cast<long long>(pg.decode_text_us)) + " us/result");
        row("extended flow, binary results", pg.large_binary,
            "decode " + std::to_string(static_cast<long long>(pg.decode_binary_us)) + " us/result");

        std::cout << "\nProtocol messages and round trips for one logical query\n";
        std::cout << "  case                                  messages  round trips\n";
        std::cout << "  simple query flow                     " << std::setw(8) << pg.simple_msgs
                  << std::setw(13) << pg.simple_trips << "\n";
        std::cout << "  extended flow, first execution        " << std::setw(8)
                  << pg.extended_first_msgs << std::setw(13) << pg.extended_first_trips << "\n";
        std::cout << "  extended flow, statement cached       " << std::setw(8)
                  << pg.extended_cached_msgs << std::setw(13) << pg.extended_cached_trips << "\n";
    } catch (const std::exception& e) {
        std::cout << "\nPostgreSQL measurements failed: " << e.what() << "\n";
        std::cout << "is the compose environment up?  docker compose up -d\n";
        ++failures;
    }

    try {
        header("Connection pool acquisition latency");
        for (std::size_t size : {std::size_t{1}, std::size_t{2}, std::size_t{4}, std::size_t{8}}) {
            for (std::size_t conc : {std::size_t{1}, std::size_t{4}, std::size_t{16}}) {
                auto point = measure_pool(size, conc, 40);
                row("pool " + std::to_string(size) + ", concurrency " + std::to_string(conc),
                    point.acquire, std::to_string(point.waited) + " waited");
            }
        }
    } catch (const std::exception& e) {
        std::cout << "\npool measurements failed: " << e.what() << "\n";
        ++failures;
    }

    try {
        event_loop loop;
        summary large{};
        auto one = loop.block_on(measure_mysql(loop, large_rows, &large));
        header("MySQL");
        row("text protocol, one row", one);
        row("text protocol, " + std::to_string(large_rows) + " rows", large);
    } catch (const std::exception& e) {
        std::cout << "\nMySQL measurements failed: " << e.what() << "\n";
        ++failures;
    }

#ifdef CONDUIT_HAVE_LIBPQ
    try {
        header("libpq baseline, same query, same server");
        row("libpq PQexec, one row", measure_libpq());
    } catch (const std::exception& e) {
        std::cout << "libpq baseline failed: " << e.what() << "\n";
    }
#else
    std::cout << "\nlibpq baseline: not built. libpq was not found on this machine at configure\n"
              << "time, so no vendor library comparison was measured and none is reported.\n";
#endif

    if (raw) write_raw();
    std::cout << "\n";
    return failures == 0 ? 0 : 1;
}
