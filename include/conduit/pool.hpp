// A bounded, asynchronous connection pool.
//
// Templated on the connection type rather than built on a common interface,
// because the two connection classes have nothing in common at run time. What
// the pool needs from a connection is small and is written down as a concept:
// open, close, ping and a usability flag.
//
// The pool is single threaded. It belongs to one event loop and is used from
// the coroutines that loop runs, so no lock appears anywhere below.
#pragma once

#include <chrono>
#include <concepts>
#include <deque>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

#include "conduit/net.hpp"
#include "conduit/task.hpp"

namespace conduit {

class pool_timeout : public std::runtime_error {
public:
    pool_timeout() : std::runtime_error("timed out waiting for a pooled connection") {}
};

template <class C, class P>
concept poolable = requires(C& c, P p) {
    { c.is_usable() } -> std::same_as<bool>;
    { c.open(p) } -> std::same_as<task<void>>;
    { c.close() } -> std::same_as<task<void>>;
    { c.ping() } -> std::same_as<task<bool>>;
};

struct pool_config {
    std::size_t max_size = 8;
    std::chrono::milliseconds acquire_timeout{5000};
    // A connection idle for longer than this is pinged before it is handed out.
    // Zero checks every time, which is correct but costs a round trip per
    // acquisition.
    std::chrono::milliseconds health_check_after{30000};
};

struct pool_stats {
    std::size_t created = 0;
    std::size_t acquired = 0;
    std::size_t timeouts = 0;
    std::size_t health_checks = 0;
    std::size_t discarded = 0;
    std::size_t waited = 0;  // acquisitions that had to suspend
};

template <class Connection, class Params>
    requires poolable<Connection, Params>
class connection_pool {
public:
    connection_pool(event_loop& loop, Params params, pool_config cfg = {})
        : loop_(&loop), params_(std::move(params)), cfg_(cfg) {}

    connection_pool(const connection_pool&) = delete;
    connection_pool& operator=(const connection_pool&) = delete;

    // Returned by acquire. Puts the connection back when it goes out of scope,
    // which is the only way it can go back: there is no manual release.
    class lease {
    public:
        lease() = default;
        lease(connection_pool* p, Connection* c) : pool_(p), conn_(c) {}
        lease(lease&& o) noexcept : pool_(std::exchange(o.pool_, nullptr)),
                                    conn_(std::exchange(o.conn_, nullptr)) {}
        lease& operator=(lease&& o) noexcept {
            if (this != &o) {
                reset();
                pool_ = std::exchange(o.pool_, nullptr);
                conn_ = std::exchange(o.conn_, nullptr);
            }
            return *this;
        }
        lease(const lease&) = delete;
        lease& operator=(const lease&) = delete;
        ~lease() { reset(); }

        Connection& operator*() const noexcept { return *conn_; }
        Connection* operator->() const noexcept { return conn_; }
        explicit operator bool() const noexcept { return conn_ != nullptr; }

    private:
        void reset() {
            if (pool_ && conn_) pool_->give_back(conn_);
            pool_ = nullptr;
            conn_ = nullptr;
        }
        connection_pool* pool_ = nullptr;
        Connection* conn_ = nullptr;
    };

    task<lease> acquire() {
        auto deadline = std::chrono::steady_clock::now() + cfg_.acquire_timeout;

        for (;;) {
            // A connection that is already idle is the cheap path.
            while (!idle_.empty()) {
                auto slot = idle_.front();
                idle_.pop_front();
                auto* c = slot.conn;
                if (!c->is_usable()) { retire(c); continue; }
                if (needs_check(slot.returned_at)) {
                    ++stats_.health_checks;
                    bool alive = co_await c->ping();
                    if (!alive) { retire(c); continue; }
                }
                ++stats_.acquired;
                co_return lease(this, c);
            }

            if (all_.size() < cfg_.max_size) {
                auto owned = std::make_unique<Connection>(*loop_);
                Connection* raw = owned.get();
                all_.push_back(std::move(owned));
                ++stats_.created;
                try {
                    co_await raw->open(params_);
                } catch (...) {
                    // A failed connect must not leave a dead object occupying a
                    // slot, otherwise the pool shrinks by one on every failure.
                    erase_owned(raw);
                    throw;
                }
                ++stats_.acquired;
                co_return lease(this, raw);
            }

            if (std::chrono::steady_clock::now() >= deadline) {
                ++stats_.timeouts;
                throw pool_timeout();
            }

            ++stats_.waited;
            auto w = std::make_shared<waiter>();
            bool timed_out = co_await slot_awaiter{this, w, deadline};
            if (timed_out) {
                ++stats_.timeouts;
                throw pool_timeout();
            }
            // A released connection is handed to the waiter directly rather
            // than dropped into the idle list. Going through the idle list
            // looks equivalent and is not: the coroutine that released the
            // connection continues running before the woken waiter does, so it
            // takes the connection straight back and the waiter starves. That
            // showed up in the measurement as a bimodal acquisition latency,
            // sub microsecond for almost every sample and hundreds of
            // milliseconds for the rest.
            if (w->granted) {
                ++stats_.acquired;
                co_return lease(this, w->granted);
            }
        }
    }

    // Closes every connection. Must be awaited before the loop is destroyed.
    task<void> close_all() {
        idle_.clear();
        for (auto& c : all_) co_await c->close();
        all_.clear();
        co_return;
    }

    std::size_t size() const noexcept { return all_.size(); }
    std::size_t idle() const noexcept { return idle_.size(); }
    std::size_t in_use() const noexcept { return all_.size() - idle_.size(); }
    const pool_stats& stats() const noexcept { return stats_; }
    const pool_config& config() const noexcept { return cfg_; }

private:
    struct slot {
        Connection* conn;
        std::chrono::steady_clock::time_point returned_at;
    };

    struct waiter {
        std::coroutine_handle<> co{};
        bool settled = false;
        bool timed_out = false;
        Connection* granted = nullptr;
    };

    // Suspends until a connection is released or the deadline passes. The two
    // events race, so the waiter is shared: whichever arrives first settles it
    // and the loser finds `settled` already true and does nothing.
    struct slot_awaiter {
        connection_pool* pool;
        std::shared_ptr<waiter> w;
        std::chrono::steady_clock::time_point deadline;

        bool await_ready() const noexcept { return false; }
        void await_suspend(std::coroutine_handle<> h) {
            w->co = h;
            pool->waiters_.push_back(w);
            auto* loop = pool->loop_;
            auto* p = pool;
            // Weak, not strong, and the difference is a defect ASan found.
            //
            // Nothing cancels this callback when the slot is granted normally,
            // so it stays in the loop until its deadline and can run long after
            // the waiter it refers to is gone: the pool drops its reference in
            // hand_off, and the awaiting coroutine drops the last one when it
            // finishes. A captured shared_ptr looks like it prevents that and
            // does not, because the copy is not the thing being kept alive by
            // the time the callback fires. Holding it weakly says what is
            // actually true: if the waiter is still waiting it is alive and
            // reachable, and if it is not, this callback has nothing to do.
            std::weak_ptr<waiter> weak = w;
            loop->call_at(deadline, [loop, weak, p]() {
                auto shared = weak.lock();
                if (!shared || shared->settled) return;
                shared->settled = true;
                shared->timed_out = true;
                p->forget_waiter(shared);
                loop->schedule(shared->co);
            });
        }
        bool await_resume() const noexcept { return w->timed_out; }
    };

    bool needs_check(std::chrono::steady_clock::time_point returned_at) const {
        return std::chrono::steady_clock::now() - returned_at >= cfg_.health_check_after;
    }

    void give_back(Connection* c) {
        if (!c->is_usable()) { retire(c); return; }
        if (hand_off(c)) return;
        idle_.push_back({c, std::chrono::steady_clock::now()});
    }

    // Gives the connection to the longest waiting acquirer. Returns false when
    // nobody is waiting.
    bool hand_off(Connection* c) {
        while (!waiters_.empty()) {
            auto w = waiters_.front();
            waiters_.pop_front();
            if (w->settled) continue;
            w->settled = true;
            w->granted = c;
            loop_->schedule(w->co);
            return true;
        }
        return false;
    }

    void retire(Connection* c) {
        ++stats_.discarded;
        erase_owned(c);
        // No connection to hand over, but a slot has opened, so one waiter can
        // stop waiting and open a fresh one.
        wake_one();
    }

    void erase_owned(Connection* c) {
        for (auto it = all_.begin(); it != all_.end(); ++it)
            if (it->get() == c) { all_.erase(it); return; }
    }

    void wake_one() {
        while (!waiters_.empty()) {
            auto w = waiters_.front();
            waiters_.pop_front();
            if (w->settled) continue;
            w->settled = true;
            loop_->schedule(w->co);
            return;
        }
    }

    void forget_waiter(const std::shared_ptr<waiter>& target) {
        for (auto it = waiters_.begin(); it != waiters_.end(); ++it)
            if (*it == target) { waiters_.erase(it); return; }
    }

    event_loop* loop_;
    Params params_;
    pool_config cfg_;
    std::vector<std::unique_ptr<Connection>> all_;
    std::deque<slot> idle_;
    std::deque<std::shared_ptr<waiter>> waiters_;
    pool_stats stats_;
};

}  // namespace conduit
