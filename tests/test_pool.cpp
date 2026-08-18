// The prepared statement cache, the SCRAM exchange and the connection pool.
// The pool is driven by a fake connection so its behaviour under contention,
// timeout and server side disconnection is deterministic and needs no server.
#include <chrono>
#include <string>
#include <vector>

#include "check.hpp"
#include "conduit/lru_cache.hpp"
#include "conduit/pool.hpp"
#include "conduit/scram.hpp"

using namespace conduit;
using namespace std::chrono_literals;

// --- prepared statement cache ------------------------------------------------

CONDUIT_TEST(lru_cache_evicts_the_least_recently_used_entry) {
    lru_cache<int> c{2};
    CHECK(!c.put("a", 1).has_value());
    CHECK(!c.put("b", 2).has_value());
    CHECK_EQ(*c.find("a"), 1);  // touching "a" makes "b" the oldest
    auto evicted = c.put("c", 3);
    CHECK(evicted.has_value());
    CHECK_EQ(evicted->first, std::string("b"));
    CHECK_EQ(evicted->second, 2);
    CHECK(c.find("b") == nullptr);
    CHECK_EQ(c.size(), std::size_t{2});
    CHECK_EQ(c.evictions(), std::size_t{1});
}

CONDUIT_TEST(lru_cache_counts_hits_and_misses) {
    lru_cache<int> c{4};
    c.put("x", 1);
    c.find("x");
    c.find("x");
    c.find("y");
    CHECK_EQ(c.hits(), std::size_t{2});
    CHECK_EQ(c.misses(), std::size_t{1});
    c.reset_stats();
    CHECK_EQ(c.hits(), std::size_t{0});
}

CONDUIT_TEST(lru_cache_replaces_without_evicting_and_keeps_order) {
    lru_cache<int> c{3};
    c.put("a", 1);
    c.put("b", 2);
    c.put("c", 3);
    CHECK(!c.put("a", 9).has_value());
    CHECK_EQ(*c.find("a"), 9);
    CHECK_EQ(c.size(), std::size_t{3});
    auto order = c.keys_in_order();
    CHECK_EQ(order.front(), std::string("a"));
}

CONDUIT_TEST(lru_cache_erase_returns_the_entry_so_it_can_be_closed) {
    lru_cache<std::string> c{4};
    c.put("sql", "conduit_s1");
    auto gone = c.erase("sql");
    CHECK(gone.has_value());
    CHECK_EQ(gone->second, std::string("conduit_s1"));
    CHECK_EQ(c.size(), std::size_t{0});
    CHECK(!c.erase("sql").has_value());
}

CONDUIT_TEST(lru_cache_with_zero_capacity_never_evicts) {
    // Zero means the eviction rule is off, which is how the benchmark runs the
    // "no cache" arm without a second code path.
    lru_cache<int> c{0};
    for (int i = 0; i < 10; ++i) c.put(std::to_string(i), i);
    CHECK_EQ(c.size(), std::size_t{10});
    CHECK_EQ(c.evictions(), std::size_t{0});
}

// --- SCRAM -------------------------------------------------------------------

CONDUIT_TEST(scram_reproduces_the_rfc7677_exchange) {
    // RFC 7677 section 3 gives a complete SCRAM-SHA-256 exchange for the user
    // "user" with password "pencil". Fixing the client nonce lets it be
    // replayed byte for byte.
    scram_client c{"user", "pencil", "rOprNGfwEbeRWgbNEkqO"};
    CHECK_EQ(c.client_first(), std::string("n,,n=user,r=rOprNGfwEbeRWgbNEkqO"));

    const std::string server_first =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
        "s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    auto final_message = c.client_final(server_first);
    CHECK_EQ(final_message,
             std::string("c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,"
                         "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="));
    CHECK(c.verify_server_final("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="));
    CHECK(!c.verify_server_final("v=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
}

CONDUIT_TEST(scram_rejects_a_server_nonce_that_does_not_extend_the_client_one) {
    scram_client c{"user", "pencil", "clientnonce"};
    bool caught = false;
    try {
        c.client_final("r=somethingelse,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096");
    } catch (const std::exception&) {
        caught = true;
    }
    CHECK(caught);
}

CONDUIT_TEST(scram_attribute_reads_one_key_out_of_a_message) {
    std::string m = "r=abc,s=ZGVm,i=4096";
    CHECK_EQ(scram_attribute(m, 'r'), std::string("abc"));
    CHECK_EQ(scram_attribute(m, 'i'), std::string("4096"));
    CHECK_EQ(scram_attribute(m, 'q'), std::string(""));
}

// --- pool --------------------------------------------------------------------

namespace {

struct fake_params {
    bool fail_open = false;
};

// Satisfies the poolable concept and nothing more. It records what the pool did
// to it, which is what the tests assert on.
struct fake_connection {
    explicit fake_connection(event_loop& loop) : loop_(&loop) { ++live(); }
    ~fake_connection() { --live(); }
    fake_connection(const fake_connection&) = delete;
    fake_connection& operator=(const fake_connection&) = delete;

    task<void> open(fake_params p) {
        if (p.fail_open) throw io_error("refused");
        // A real open suspends; suspending here keeps the pool's interleaving
        // honest rather than letting every acquisition finish synchronously.
        co_await loop_->sleep_for(1ms);
        open_ = true;
        co_return;
    }
    task<void> close() { open_ = false; co_return; }
    task<bool> ping() {
        ++pings;
        co_return alive_;
    }
    bool is_usable() const noexcept { return open_ && alive_; }

    void kill() { alive_ = false; }

    static int& live() { static int n = 0; return n; }

    event_loop* loop_;
    bool open_ = false;
    bool alive_ = true;
    int pings = 0;
};

using fake_pool = connection_pool<fake_connection, fake_params>;

}  // namespace

CONDUIT_TEST(pool_reuses_a_returned_connection_instead_of_opening_another) {
    event_loop loop;
    fake_pool pool{loop, fake_params{}, pool_config{4, 1000ms, 1000ms}};
    struct helper {
        static task<void> run(fake_pool& p, int* first_id, int* second_id) {
            {
                auto lease = co_await p.acquire();
                *first_id = static_cast<int>(reinterpret_cast<std::uintptr_t>(&*lease) % 100000);
            }
            auto lease2 = co_await p.acquire();
            *second_id = static_cast<int>(reinterpret_cast<std::uintptr_t>(&*lease2) % 100000);
        }
    };
    int a = 0, b = 0;
    loop.block_on(helper::run(pool, &a, &b));
    CHECK_EQ(a, b);
    CHECK_EQ(pool.size(), std::size_t{1});
    CHECK_EQ(pool.stats().created, std::size_t{1});
    CHECK_EQ(pool.stats().acquired, std::size_t{2});
    loop.block_on(pool.close_all());
}

CONDUIT_TEST(pool_never_exceeds_its_bound_and_makes_the_extra_waiters_queue) {
    event_loop loop;
    fake_pool pool{loop, fake_params{}, pool_config{2, 2000ms, 1000ms}};
    std::string order;

    struct helper {
        static task<void> work(fake_pool& p, std::string* order, char tag,
                               std::chrono::milliseconds hold) {
            auto lease = co_await p.acquire();
            *order += tag;
            co_await lease->loop_->sleep_for(hold);
        }
    };

    loop.spawn(helper::work(pool, &order, 'a', 30ms));
    loop.spawn(helper::work(pool, &order, 'b', 30ms));
    loop.spawn(helper::work(pool, &order, 'c', 1ms));
    loop.spawn(helper::work(pool, &order, 'd', 1ms));
    loop.run();

    CHECK_EQ(order.size(), std::size_t{4});
    CHECK_EQ(pool.size(), std::size_t{2});
    CHECK_EQ(pool.stats().created, std::size_t{2});
    // The last two had to wait for one of the first two to be released.
    CHECK(pool.stats().waited >= 2);
    loop.block_on(pool.close_all());
}

CONDUIT_TEST(pool_acquisition_times_out_when_nothing_is_released) {
    event_loop loop;
    fake_pool pool{loop, fake_params{}, pool_config{1, 25ms, 1000ms}};

    struct helper {
        static task<void> hog(fake_pool& p, std::chrono::milliseconds hold) {
            auto lease = co_await p.acquire();
            co_await lease->loop_->sleep_for(hold);
        }
        static task<bool> starve(fake_pool& p) {
            try {
                auto lease = co_await p.acquire();
                co_return false;
            } catch (const pool_timeout&) {
                co_return true;
            }
        }
    };

    loop.spawn(helper::hog(pool, 200ms));
    bool timed_out = false;
    std::exception_ptr err;
    bool done = false;
    // Run the starving acquisition alongside the hog on the same loop.
    auto probe = helper::starve(pool);
    loop.spawn([](task<bool> t, bool* out, bool* fin) -> task<void> {
        *out = co_await std::move(t);
        *fin = true;
    }(std::move(probe), &timed_out, &done));
    loop.run();

    CHECK(done);
    CHECK(timed_out);
    CHECK_EQ(pool.stats().timeouts, std::size_t{1});
    (void)err;
    loop.block_on(pool.close_all());
}

CONDUIT_TEST(pool_discards_a_connection_the_server_closed_underneath_it) {
    event_loop loop;
    fake_pool pool{loop, fake_params{}, pool_config{2, 1000ms, 1000ms}};

    struct helper {
        static task<void> run(fake_pool& p, std::size_t* size_after) {
            {
                auto lease = co_await p.acquire();
                lease->kill();  // the server went away while the lease was held
            }
            // The dead connection must not be handed out again.
            auto lease2 = co_await p.acquire();
            CHECK(lease2->is_usable());
            *size_after = p.size();
        }
    };
    std::size_t after = 0;
    loop.block_on(helper::run(pool, &after));
    CHECK_EQ(after, std::size_t{1});
    CHECK_EQ(pool.stats().created, std::size_t{2});
    CHECK_EQ(pool.stats().discarded, std::size_t{1});
    loop.block_on(pool.close_all());
}

CONDUIT_TEST(pool_health_checks_a_connection_that_sat_idle) {
    event_loop loop;
    // A zero threshold means every idle connection is checked before reuse.
    fake_pool pool{loop, fake_params{}, pool_config{2, 1000ms, 0ms}};

    struct helper {
        static task<int> run(fake_pool& p) {
            { auto lease = co_await p.acquire(); }
            auto lease2 = co_await p.acquire();
            co_return lease2->pings;
        }
    };
    int pings = loop.block_on(helper::run(pool));
    CHECK_EQ(pings, 1);
    CHECK_EQ(pool.stats().health_checks, std::size_t{1});
    loop.block_on(pool.close_all());
}

CONDUIT_TEST(pool_does_not_keep_a_slot_for_a_connection_that_failed_to_open) {
    event_loop loop;
    fake_pool pool{loop, fake_params{true}, pool_config{2, 100ms, 1000ms}};
    struct helper {
        static task<bool> run(fake_pool& p) {
            try {
                auto lease = co_await p.acquire();
                co_return false;
            } catch (const io_error&) {
                co_return true;
            }
        }
    };
    CHECK(loop.block_on(helper::run(pool)));
    CHECK_EQ(pool.size(), std::size_t{0});
    loop.block_on(pool.close_all());
}

CONDUIT_TEST(every_fake_connection_is_destroyed_when_the_pool_closes) {
    CHECK_EQ(fake_connection::live(), 0);
}

CONDUIT_TEST(pool_hands_a_released_connection_straight_to_the_waiter) {
    // Fairness. Without a direct handoff the coroutine that releases a
    // connection resumes before the woken waiter and takes the same connection
    // back, so one worker runs to completion and the other starves. The
    // interleaving below is what proves the handoff happened.
    event_loop loop;
    fake_pool pool{loop, fake_params{}, pool_config{1, 5000ms, 60000ms}};
    std::string order;

    struct helper {
        static task<void> worker(fake_pool& p, std::string* order, char tag, int rounds) {
            for (int i = 0; i < rounds; ++i) {
                auto lease = co_await p.acquire();
                *order += tag;
                co_await lease->loop_->sleep_for(1ms);
            }
        }
    };
    loop.spawn(helper::worker(pool, &order, 'a', 4));
    loop.spawn(helper::worker(pool, &order, 'b', 4));
    loop.run();

    CHECK_EQ(order.size(), std::size_t{8});
    // Both made progress in alternation rather than one finishing first.
    CHECK_EQ(order, std::string("abababab"));
    loop.block_on(pool.close_all());
}
