// The event loop and the transport, exercised over a real loopback socket pair.
// No database is involved: one end is a listener in this process.
#include <chrono>
#include <string>
#include <thread>

#include "check.hpp"
#include "conduit/net.hpp"

using namespace conduit;
using namespace std::chrono_literals;

namespace {

// Builds two connected sockets on 127.0.0.1. The client side is non blocking
// and belongs to the loop, the server side is the test's puppet.
struct socket_pair {
    tcp_listener listener;
    tcp_socket client;
    tcp_socket server;

    socket_pair() {
        auto port = listener.bind_loopback();
        client.start_connect("127.0.0.1", port);
        server = listener.accept();
        // A non blocking connect on loopback may still be in flight; the accept
        // above proves the handshake completed on the server side.
        client.finish_connect();
    }
};

task<int> add(int a, int b) { co_return a + b; }

task<int> nested_sum(int n) {
    int total = 0;
    for (int i = 1; i <= n; ++i) total = co_await add(total, i);
    co_return total;
}

}  // namespace

CONDUIT_TEST(task_chains_without_an_event_loop) {
    CHECK_EQ(nested_sum(4).sync_get(), 10);
}

CONDUIT_TEST(task_propagates_an_exception_through_the_chain) {
    struct thrower {
        static task<int> boom() {
            throw protocol_error("deliberate");
            co_return 0;
        }
        static task<int> caller() { co_return co_await boom(); }
    };
    bool caught = false;
    try {
        thrower::caller().sync_get();
    } catch (const protocol_error&) {
        caught = true;
    }
    CHECK(caught);
}

CONDUIT_TEST(loop_runs_a_task_that_never_suspends) {
    event_loop loop;
    CHECK_EQ(loop.block_on(nested_sum(10)), 55);
    CHECK_EQ(loop.pending(), std::size_t{0});
}

CONDUIT_TEST(loop_transfers_bytes_over_a_real_socket) {
    socket_pair p;
    event_loop loop;

    std::string payload = "the quick brown fox";
    loop.block_on(write_all(loop, p.client, as_bytes(payload)));

    // Read the other end with a blocking style spin: the server socket is the
    // test's, not the loop's.
    std::string got;
    while (got.size() < payload.size()) {
        std::byte tmp[64];
        auto r = p.server.try_read(std::span<std::byte>(tmp, sizeof(tmp)));
        if (r.status == io_status::would_block) { std::this_thread::sleep_for(1ms); continue; }
        if (r.status == io_status::closed) break;
        got.append(reinterpret_cast<const char*>(tmp), r.bytes);
    }
    CHECK_EQ(got, payload);
}

CONDUIT_TEST(loop_suspends_a_read_until_the_peer_writes) {
    socket_pair p;
    event_loop loop;
    recv_buffer buf;

    // The write happens on another thread after a delay, so the read below must
    // genuinely suspend rather than find the bytes already waiting.
    std::thread writer([&] {
        std::this_thread::sleep_for(30ms);
        std::string msg = "late";
        std::size_t sent = 0;
        while (sent < msg.size()) {
            auto r = p.server.try_write(as_bytes(std::string_view(msg).substr(sent)));
            if (r.status == io_status::ok) sent += r.bytes;
            else std::this_thread::sleep_for(1ms);
        }
    });

    bool alive = loop.block_on(read_some(loop, p.client, buf));
    writer.join();
    CHECK(alive);
    CHECK_EQ(std::string(reinterpret_cast<const char*>(buf.readable().data()),
                         buf.readable_size()),
             std::string("late"));
}

CONDUIT_TEST(read_reports_closed_when_the_peer_hangs_up) {
    socket_pair p;
    event_loop loop;
    recv_buffer buf;
    p.server.close();
    bool alive = loop.block_on(read_some(loop, p.client, buf));
    CHECK(!alive);
    CHECK_EQ(buf.readable_size(), std::size_t{0});
}

CONDUIT_TEST(wait_with_a_deadline_reports_the_timeout) {
    socket_pair p;
    event_loop loop;
    struct helper {
        static task<bool> wait(event_loop& l, native_handle h) {
            auto r = co_await l.wait_readable_for(h, 20ms);
            co_return r == event_loop::wait_result::timed_out;
        }
    };
    auto start = std::chrono::steady_clock::now();
    bool timed_out = loop.block_on(helper::wait(loop, p.client.native()));
    auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(timed_out);
    CHECK(elapsed >= 15ms);
}

CONDUIT_TEST(loop_interleaves_two_spawned_tasks) {
    event_loop loop;
    std::string order;
    struct helper {
        static task<void> step(event_loop& l, std::string* out, const char* tag,
                               std::chrono::milliseconds d) {
            co_await l.sleep_for(d);
            *out += tag;
        }
    };
    loop.spawn(helper::step(loop, &order, "b", 25ms));
    loop.spawn(helper::step(loop, &order, "a", 5ms));
    loop.run();
    CHECK_EQ(order, std::string("ab"));
}

CONDUIT_TEST(connect_to_a_closed_port_reports_an_error_instead_of_hanging) {
    // Regression. A refused connection is reported by Winsock only in the
    // exception set of select, so a loop that watches the write set alone never
    // wakes and the caller waits forever. This case binds a listener only to
    // learn a free port, closes it, and then connects to nothing.
    std::uint16_t port = 0;
    {
        tcp_listener probe;
        port = probe.bind_loopback();
    }

    event_loop loop;
    tcp_socket sock;
    auto start = std::chrono::steady_clock::now();
    bool reported = false;
    try {
        loop.block_on(connect(loop, sock, "127.0.0.1", port));
    } catch (const io_error&) {
        reported = true;
    }
    auto elapsed = std::chrono::steady_clock::now() - start;
    CHECK(reported);
    CHECK(elapsed < 5s);
}
