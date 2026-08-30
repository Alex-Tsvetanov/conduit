// PostgreSQL against a real server.
#include <string>

#include "../check.hpp"
#include "conduit/pool.hpp"
#include "conduit/tls.hpp"
#include "live.hpp"

using namespace conduit;
using namespace std::chrono_literals;

namespace {
struct row_pg {
    std::int64_t id = 0;
    std::string label;
    double weight = 0;
    bool flag = false;
};
}  // namespace

template <>
struct conduit::row_mapping<row_pg> {
    static constexpr auto fields = std::tuple{
        conduit::bind_field("id", &row_pg::id),
        conduit::bind_field("label", &row_pg::label),
        conduit::bind_field("weight", &row_pg::weight),
        conduit::bind_field("flag", &row_pg::flag)};
};

namespace {

task<void> prepare_schema(pg::connection& c) {
    co_await c.simple_query("DROP TABLE IF EXISTS conduit_items");
    co_await c.simple_query(
        "CREATE TABLE conduit_items ("
        "  id bigint primary key, label text, weight double precision,"
        "  flag boolean, amount numeric(12,3), made_at timestamp, tags int4[])");
    co_await c.simple_query(
        "INSERT INTO conduit_items VALUES "
        "(1,'alpha',1.5,true,123456.789,'2024-02-29 13:45:30.123456','{1,2,3}'),"
        "(2,'beta',2.5,false,-0.050,'1999-12-31 23:59:59','{}'),"
        "(3,'gamma',3.5,true,0.001,'2000-01-01 00:00:00',NULL)");
    co_return;
}

}  // namespace

CONDUIT_TEST(pg_live_simple_query_returns_rows) {
    if (!live::pg_up()) CONDUIT_SKIP("no PostgreSQL server reachable");
    event_loop loop;
    pg::connection c{loop};
    struct helper {
        static task<std::size_t> run(pg::connection& c) {
            co_await c.open(live::pg_params());
            co_await prepare_schema(c);
            auto r = co_await c.simple_query("SELECT id, label FROM conduit_items ORDER BY id");
            co_await c.close();
            co_return r.rows;
        }
    };
    CHECK_EQ(loop.block_on(helper::run(c)), std::size_t{3});
}

CONDUIT_TEST(pg_live_extended_query_decodes_binary_results) {
    if (!live::pg_up()) CONDUIT_SKIP("no PostgreSQL server reachable");
    event_loop loop;
    pg::connection c{loop};
    struct helper {
        static task<std::vector<row_pg>> run(pg::connection& c) {
            co_await c.open(live::pg_params());
            co_await prepare_schema(c);
            auto rows = co_await c.query_as<row_pg>(
                "SELECT id, label, weight, flag FROM conduit_items WHERE id >= $1 ORDER BY id",
                pg::params(2), wire_format::binary);
            co_await c.close();
            co_return rows;
        }
    };
    auto rows = loop.block_on(helper::run(c));
    CHECK_EQ(rows.size(), std::size_t{2});
    CHECK_EQ(rows[0].label, std::string("beta"));
    CHECK_NEAR(rows[0].weight, 2.5, 1e-9);
    CHECK(!rows[0].flag);
    CHECK_EQ(rows[1].id, std::int64_t{3});
}

CONDUIT_TEST(pg_live_numeric_timestamp_and_array_survive_a_round_trip) {
    if (!live::pg_up()) CONDUIT_SKIP("no PostgreSQL server reachable");
    event_loop loop;
    pg::connection c{loop};
    struct helper {
        static task<std::vector<std::string>> run(pg::connection& c) {
            co_await c.open(live::pg_params());
            co_await prepare_schema(c);
            std::vector<std::string> seen;
            co_await c.execute(
                "SELECT amount, made_at, tags FROM conduit_items WHERE id = $1",
                pg::params(1), wire_format::binary,
                [&](const std::vector<pg::column>&, std::span<const field_view> row) {
                    seen.push_back(decode_numeric(row[0]));
                    seen.push_back(decode_timestamp(row[1]).to_string());
                    auto tags = decode_field<std::vector<std::int32_t>>(row[2]);
                    std::string joined;
                    for (auto t : tags) joined += std::to_string(t);
                    seen.push_back(joined);
                });
            co_await c.close();
            co_return seen;
        }
    };
    auto seen = loop.block_on(helper::run(c));
    CHECK_EQ(seen.size(), std::size_t{3});
    CHECK_EQ(seen[0], std::string("123456.789"));
    CHECK_EQ(seen[1], std::string("2024-02-29 13:45:30.123456"));
    CHECK_EQ(seen[2], std::string("123"));
}

CONDUIT_TEST(pg_live_prepared_statement_cache_saves_the_parse_step) {
    if (!live::pg_up()) CONDUIT_SKIP("no PostgreSQL server reachable");
    event_loop loop;
    pg::connection c{loop};
    struct counts { std::size_t hits, misses, first_msgs, second_msgs; };
    struct helper {
        static task<counts> run(pg::connection& c) {
            co_await c.open(live::pg_params());
            co_await prepare_schema(c);
            const char* sql = "SELECT id FROM conduit_items WHERE id = $1";
            c.trace().enable(true);
            c.trace().clear();
            co_await c.execute(sql, pg::params(1));
            std::size_t first = c.trace().entries().size();
            c.trace().clear();
            co_await c.execute(sql, pg::params(2));
            std::size_t second = c.trace().entries().size();
            counts out{c.cache_hits(), c.cache_misses(), first, second};
            co_await c.close();
            co_return out;
        }
    };
    auto r = loop.block_on(helper::run(c));
    CHECK_EQ(r.hits, std::size_t{1});
    CHECK_EQ(r.misses, std::size_t{1});
    // The second execution sends no Parse and no Describe, and the server sends
    // back no ParseComplete, no ParameterDescription and no RowDescription.
    CHECK(r.second_msgs < r.first_msgs);
}

CONDUIT_TEST(pg_live_server_error_leaves_the_connection_usable) {
    if (!live::pg_up()) CONDUIT_SKIP("no PostgreSQL server reachable");
    event_loop loop;
    pg::connection c{loop};
    struct helper {
        static task<std::string> run(pg::connection& c) {
            co_await c.open(live::pg_params());
            std::string state;
            try {
                co_await c.simple_query("SELECT * FROM a_table_that_does_not_exist");
            } catch (const pg::server_exception& e) {
                state = e.info.sqlstate;
            }
            // The connection resynchronised at ReadyForQuery, so this succeeds.
            auto r = co_await c.simple_query("SELECT 1");
            state += r.rows == 1 ? "|recovered" : "|broken";
            co_await c.close();
            co_return state;
        }
    };
    CHECK_EQ(loop.block_on(helper::run(c)), std::string("42P01|recovered"));
}

CONDUIT_TEST(pg_live_pool_serves_more_work_than_it_has_connections) {
    if (!live::pg_up()) CONDUIT_SKIP("no PostgreSQL server reachable");
    event_loop loop;
    connection_pool<pg::connection, pg::connect_params> pool{
        loop, live::pg_params(), pool_config{2, 5000ms, 30000ms}};

    int done = 0;  // the loop is single threaded, so a plain counter is enough
    struct helper {
        static task<void> one(connection_pool<pg::connection, pg::connect_params>& p,
                              int* done) {
            auto lease = co_await p.acquire();
            auto r = co_await lease->execute("SELECT $1::int", pg::params(7));
            if (r.rows == 1) ++*done;
        }
    };
    for (int i = 0; i < 6; ++i) loop.spawn(helper::one(pool, &done));
    loop.run();
    CHECK_EQ(done, 6);
    CHECK(pool.size() <= 2);
    loop.block_on(pool.close_all());
}

CONDUIT_TEST(pg_live_tls_connects_and_runs_a_query) {
    if (!tls_available()) CONDUIT_SKIP("OpenSSL is not linked");
    if (!live::pg_up()) CONDUIT_SKIP("no PostgreSQL server reachable");
    event_loop loop;
    pg::connection c{loop};
    auto p = live::pg_params();
    p.tls.enabled = true;
    p.tls.verify_peer = false;
    struct helper {
        static task<std::string> run(pg::connection& c, pg::connect_params p) {
            co_await c.open(std::move(p));
            std::string out = c.tls_active() ? "tls" : "plain";
            auto r = co_await c.simple_query("SELECT 1");
            out += r.rows == 1 ? "|ok" : "|no-row";
            co_await c.close();
            co_return out;
        }
    };
    CHECK_EQ(loop.block_on(helper::run(c, p)), std::string("tls|ok"));
}
