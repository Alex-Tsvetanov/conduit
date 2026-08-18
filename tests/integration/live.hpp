// Shared setup for the tests that need a real server.
//
// The servers come from docker-compose.yml. When they are not running the
// cases report themselves as skipped and the binary still exits zero, so a
// plain `ctest` run passes on a machine with no database installed. Run them
// deliberately with `ctest -L integration` after `docker compose up -d`.
#pragma once

#include <cstdio>
#include <cstdlib>
#include <string>

#include "conduit/mysql/connection.hpp"
#include "conduit/net.hpp"
#include "conduit/pg/connection.hpp"

namespace live {

inline std::string env_or(const char* name, const char* fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : std::string(fallback);
}

inline std::uint16_t env_port(const char* name, std::uint16_t fallback) {
    const char* v = std::getenv(name);
    if (!v || !*v) return fallback;
    return static_cast<std::uint16_t>(std::strtoul(v, nullptr, 10));
}

inline conduit::pg::connect_params pg_params() {
    conduit::pg::connect_params p;
    p.host = env_or("CONDUIT_PG_HOST", "127.0.0.1");
    p.port = env_port("CONDUIT_PG_PORT", 55432);
    p.user = env_or("CONDUIT_PG_USER", "conduit");
    p.password = env_or("CONDUIT_PG_PASSWORD", "conduit");
    p.database = env_or("CONDUIT_PG_DATABASE", "conduit");
    return p;
}

inline conduit::mysql::connect_params mysql_params() {
    conduit::mysql::connect_params p;
    p.host = env_or("CONDUIT_MYSQL_HOST", "127.0.0.1");
    p.port = env_port("CONDUIT_MYSQL_PORT", 33306);
    p.user = env_or("CONDUIT_MYSQL_USER", "conduit");
    p.password = env_or("CONDUIT_MYSQL_PASSWORD", "conduit");
    p.database = env_or("CONDUIT_MYSQL_DATABASE", "conduit");
    return p;
}

// Probed once. A server that is not there is a skip, not a failure.
template <class Connection, class Params>
bool reachable(const Params& params, const char* label) {
    static int state = -1;
    if (state < 0) {
        conduit::event_loop loop;
        Connection c{loop};
        try {
            loop.block_on(c.open(params));
            loop.block_on(c.close());
            state = 1;
        } catch (const std::exception& e) {
            std::printf("skip %s: %s\n", label, e.what());
            state = 0;
        }
    }
    return state == 1;
}

inline bool pg_up() {
    return reachable<conduit::pg::connection>(pg_params(), "PostgreSQL integration tests");
}
inline bool mysql_up() {
    return reachable<conduit::mysql::connection>(mysql_params(), "MySQL integration tests");
}

}  // namespace live
