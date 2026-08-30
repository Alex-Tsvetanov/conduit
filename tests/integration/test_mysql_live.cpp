// MySQL against a real server.
#include <string>

#include "../check.hpp"
#include "conduit/pool.hpp"
#include "conduit/tls.hpp"
#include "live.hpp"

using namespace conduit;
using namespace std::chrono_literals;

namespace {
struct row_my {
    std::int64_t id = 0;
    std::string label;
    double weight = 0;
};
}  // namespace

template <>
struct conduit::row_mapping<row_my> {
    static constexpr auto fields = std::tuple{
        conduit::bind_field("id", &row_my::id),
        conduit::bind_field("label", &row_my::label),
        conduit::bind_field("weight", &row_my::weight)};
};

namespace {

task<void> prepare_schema(mysql::connection& c) {
    co_await c.query("DROP TABLE IF EXISTS conduit_items");
    co_await c.query(
        "CREATE TABLE conduit_items ("
        "  id bigint primary key, label varchar(64), weight double,"
        "  flag tinyint(1), amount decimal(12,3), made_at datetime(6))");
    co_await c.query(
        "INSERT INTO conduit_items VALUES "
        "(1,'alpha',1.5,1,123456.789,'2024-02-29 13:45:30.123456'),"
        "(2,'beta',2.5,0,-0.050,'1999-12-31 23:59:59'),"
        "(3,'gamma',3.5,1,0.001,'2000-01-01 00:00:00')");
    co_return;
}

}  // namespace

CONDUIT_TEST(mysql_live_handshake_reports_a_server_version) {
    if (!live::mysql_up()) CONDUIT_SKIP("no MySQL server reachable");
    event_loop loop;
    mysql::connection c{loop};
    struct helper {
        static task<std::string> run(mysql::connection& c) {
            co_await c.open(live::mysql_params());
            std::string v = c.server_version();
            co_await c.close();
            co_return v;
        }
    };
    auto version = loop.block_on(helper::run(c));
    CHECK(!version.empty());
}

CONDUIT_TEST(mysql_live_text_protocol_returns_typed_rows) {
    if (!live::mysql_up()) CONDUIT_SKIP("no MySQL server reachable");
    event_loop loop;
    mysql::connection c{loop};
    struct helper {
        static task<std::vector<row_my>> run(mysql::connection& c) {
            co_await c.open(live::mysql_params());
            co_await prepare_schema(c);
            auto rows = co_await c.query_as<row_my>(
                "SELECT id, label, weight FROM conduit_items ORDER BY id");
            co_await c.close();
            co_return rows;
        }
    };
    auto rows = loop.block_on(helper::run(c));
    CHECK_EQ(rows.size(), std::size_t{3});
    CHECK_EQ(rows[0].label, std::string("alpha"));
    CHECK_NEAR(rows[2].weight, 3.5, 1e-9);
}

CONDUIT_TEST(mysql_live_decimal_and_datetime_decode_from_text) {
    if (!live::mysql_up()) CONDUIT_SKIP("no MySQL server reachable");
    event_loop loop;
    mysql::connection c{loop};
    struct helper {
        static task<std::vector<std::string>> run(mysql::connection& c) {
            co_await c.open(live::mysql_params());
            co_await prepare_schema(c);
            std::vector<std::string> seen;
            co_await c.query("SELECT amount, made_at FROM conduit_items WHERE id = 1",
                             [&](const std::vector<mysql::column>&,
                                 std::span<const field_view> row) {
                                 seen.push_back(decode_numeric(row[0]));
                                 seen.push_back(decode_timestamp(row[1]).to_string());
                             });
            co_await c.close();
            co_return seen;
        }
    };
    auto seen = loop.block_on(helper::run(c));
    CHECK_EQ(seen.size(), std::size_t{2});
    CHECK_EQ(seen[0], std::string("123456.789"));
    CHECK_EQ(seen[1], std::string("2024-02-29 13:45:30.123456"));
}

CONDUIT_TEST(mysql_live_reports_a_server_error_without_breaking_the_connection) {
    if (!live::mysql_up()) CONDUIT_SKIP("no MySQL server reachable");
    event_loop loop;
    mysql::connection c{loop};
    struct helper {
        static task<std::string> run(mysql::connection& c) {
            co_await c.open(live::mysql_params());
            std::string out;
            try {
                co_await c.query("SELECT * FROM a_table_that_does_not_exist");
            } catch (const mysql::server_exception& e) {
                out = e.info.sql_state;
            }
            auto r = co_await c.query("SELECT 1");
            out += r.rows == 1 ? "|recovered" : "|broken";
            co_await c.close();
            co_return out;
        }
    };
    CHECK_EQ(loop.block_on(helper::run(c)), std::string("42S02|recovered"));
}

CONDUIT_TEST(mysql_live_insert_reports_affected_rows) {
    if (!live::mysql_up()) CONDUIT_SKIP("no MySQL server reachable");
    event_loop loop;
    mysql::connection c{loop};
    struct helper {
        static task<std::uint64_t> run(mysql::connection& c) {
            co_await c.open(live::mysql_params());
            co_await prepare_schema(c);
            auto r = co_await c.query("UPDATE conduit_items SET weight = weight + 1");
            co_await c.close();
            co_return r.affected_rows;
        }
    };
    CHECK_EQ(loop.block_on(helper::run(c)), std::uint64_t{3});
}

CONDUIT_TEST(mysql_live_pool_shares_two_connections_across_six_queries) {
    if (!live::mysql_up()) CONDUIT_SKIP("no MySQL server reachable");
    event_loop loop;
    connection_pool<mysql::connection, mysql::connect_params> pool{
        loop, live::mysql_params(), pool_config{2, 5000ms, 30000ms}};
    int done = 0;
    struct helper {
        static task<void> one(connection_pool<mysql::connection, mysql::connect_params>& p,
                              int* done) {
            auto lease = co_await p.acquire();
            auto r = co_await lease->query("SELECT 1");
            if (r.rows == 1) ++*done;
        }
    };
    for (int i = 0; i < 6; ++i) loop.spawn(helper::one(pool, &done));
    loop.run();
    CHECK_EQ(done, 6);
    CHECK(pool.size() <= 2);
    loop.block_on(pool.close_all());
}

CONDUIT_TEST(mysql_live_tls_connects_and_runs_a_query) {
    if (!tls_available()) CONDUIT_SKIP("OpenSSL is not linked");
    if (!live::mysql_up()) CONDUIT_SKIP("no MySQL server reachable");
    event_loop loop;
    mysql::connection c{loop};
    auto p = live::mysql_params();
    p.tls.enabled = true;
    p.tls.verify_peer = false;
    struct helper {
        static task<std::string> run(mysql::connection& c, mysql::connect_params p) {
            co_await c.open(std::move(p));
            std::string out = c.tls_active() ? "tls" : "plain";
            auto r = co_await c.query("SELECT 1");
            out += r.rows == 1 ? "|ok" : "|no-row";
            co_await c.close();
            co_return out;
        }
    };
    CHECK_EQ(loop.block_on(helper::run(c, p)), std::string("tls|ok"));
}
