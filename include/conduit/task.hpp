// The coroutine type the whole client is written in.
//
// task<T> is lazy: creating it starts nothing. Awaiting it resumes the callee
// through symmetric transfer, so a chain of N awaits costs one resume, not N
// nested stack frames. The final suspend hands control straight back to the
// awaiting coroutine, which is why the handle is returned from await_suspend
// rather than resumed inside it.
#pragma once

#include <coroutine>
#include <exception>
#include <optional>
#include <utility>

namespace conduit {

template <class T>
class task;

namespace detail {

struct final_awaiter {
    bool await_ready() const noexcept { return false; }
    template <class P>
    std::coroutine_handle<> await_suspend(std::coroutine_handle<P> h) const noexcept {
        auto cont = h.promise().continuation;
        return cont ? cont : std::noop_coroutine();
    }
    void await_resume() const noexcept {}
};

struct promise_base {
    std::coroutine_handle<> continuation{};
    std::exception_ptr error{};

    std::suspend_always initial_suspend() const noexcept { return {}; }
    final_awaiter final_suspend() const noexcept { return {}; }
    void unhandled_exception() noexcept { error = std::current_exception(); }
};

}  // namespace detail

template <class T>
class task {
public:
    struct promise_type : detail::promise_base {
        std::optional<T> value;
        task get_return_object() {
            return task(std::coroutine_handle<promise_type>::from_promise(*this));
        }
        template <class U = T>
        void return_value(U&& v) { value.emplace(std::forward<U>(v)); }
    };

    task() noexcept = default;
    explicit task(std::coroutine_handle<promise_type> h) noexcept : h_(h) {}
    task(task&& o) noexcept : h_(std::exchange(o.h_, {})) {}
    task& operator=(task&& o) noexcept {
        if (this != &o) { if (h_) h_.destroy(); h_ = std::exchange(o.h_, {}); }
        return *this;
    }
    task(const task&) = delete;
    task& operator=(const task&) = delete;
    ~task() { if (h_) h_.destroy(); }

    bool done() const noexcept { return !h_ || h_.done(); }

    struct awaiter {
        std::coroutine_handle<promise_type> h;
        bool await_ready() const noexcept { return !h || h.done(); }
        std::coroutine_handle<> await_suspend(std::coroutine_handle<> caller) noexcept {
            h.promise().continuation = caller;
            return h;
        }
        T await_resume() {
            if (h.promise().error) std::rethrow_exception(h.promise().error);
            return std::move(*h.promise().value);
        }
    };
    awaiter operator co_await() && noexcept { return awaiter{h_}; }

    // Start and drive to completion by hand. Only correct for a task that never
    // suspends on external I/O, which is exactly what the codec level tests need.
    T sync_get() {
        h_.resume();
        if (h_.promise().error) std::rethrow_exception(h_.promise().error);
        return std::move(*h_.promise().value);
    }

    std::coroutine_handle<promise_type> handle() const noexcept { return h_; }

    // The value of a task that has already run to completion, with the same
    // semantics as awaiting it. Needed by an awaiter that decides for itself
    // whether to suspend, so it can hand the result back from await_resume.
    T take() {
        if (h_.promise().error) std::rethrow_exception(h_.promise().error);
        return std::move(*h_.promise().value);
    }

private:
    std::coroutine_handle<promise_type> h_{};
};

template <>
class task<void> {
public:
    struct promise_type : detail::promise_base {
        task get_return_object() {
            return task(std::coroutine_handle<promise_type>::from_promise(*this));
        }
        void return_void() const noexcept {}
    };

    task() noexcept = default;
    explicit task(std::coroutine_handle<promise_type> h) noexcept : h_(h) {}
    task(task&& o) noexcept : h_(std::exchange(o.h_, {})) {}
    task& operator=(task&& o) noexcept {
        if (this != &o) { if (h_) h_.destroy(); h_ = std::exchange(o.h_, {}); }
        return *this;
    }
    task(const task&) = delete;
    task& operator=(const task&) = delete;
    ~task() { if (h_) h_.destroy(); }

    bool done() const noexcept { return !h_ || h_.done(); }

    struct awaiter {
        std::coroutine_handle<promise_type> h;
        bool await_ready() const noexcept { return !h || h.done(); }
        std::coroutine_handle<> await_suspend(std::coroutine_handle<> caller) noexcept {
            h.promise().continuation = caller;
            return h;
        }
        void await_resume() {
            if (h.promise().error) std::rethrow_exception(h.promise().error);
        }
    };
    awaiter operator co_await() && noexcept { return awaiter{h_}; }

    void sync_get() {
        h_.resume();
        if (h_.promise().error) std::rethrow_exception(h_.promise().error);
    }

    std::coroutine_handle<promise_type> handle() const noexcept { return h_; }

private:
    std::coroutine_handle<promise_type> h_{};
};

// A coroutine with no result and no owner: it runs to completion and then
// destroys its own frame. The event loop uses it to hold the root of a task
// chain, since something has to own that root and the caller has already
// handed the task over.
struct detached_task {
    struct promise_type {
        detached_task get_return_object() const noexcept { return {}; }
        std::suspend_never initial_suspend() const noexcept { return {}; }
        std::suspend_never final_suspend() const noexcept { return {}; }
        void return_void() const noexcept {}
        void unhandled_exception() const { std::terminate(); }
    };
};

}  // namespace conduit
