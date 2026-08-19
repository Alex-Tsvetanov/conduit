// Does symmetric transfer grow the stack on this compiler?
//
// Written to settle one question during the diagnosis of the crash described in
// the results section of the report. read_message() used to be a coroutine
// invoked once per protocol message, and on a large result set the program died
// with SIGSEGV under GCC 12.2 while GCC 14.2 survived. That looks like a
// compiler difference. This program checks whether it is one.
//
// It uses the same shape as conduit's task<T>: await_suspend returns a
// coroutine handle, which is symmetric transfer, so [expr.await] requires the
// resumption to happen without growing the stack. If that holds, awaiting two
// hundred thousand coroutines in a row completes. If it does not, the process
// dies here.
//
//     cmake --build build --target symmetric_transfer_check
//     ./build/benchmarks/symmetric_transfer_check 200000
//
// Result on the machines used for the report: it completes on GCC 12.2 at -O2,
// which rules the compiler out and puts the defect in conduit, where the fix
// went. At -O0 it dies on both compilers, which is a known property of
// unoptimised builds and not what the report's Release measurements hit.
#include <coroutine>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <utility>

namespace {

struct final_awaiter {
    bool await_ready() const noexcept { return false; }
    template <class P>
    std::coroutine_handle<> await_suspend(std::coroutine_handle<P> h) const noexcept {
        auto c = h.promise().continuation;
        return c ? c : std::noop_coroutine();
    }
    void await_resume() const noexcept {}
};

struct task {
    struct promise_type {
        std::coroutine_handle<> continuation{};
        task get_return_object() {
            return task{std::coroutine_handle<promise_type>::from_promise(*this)};
        }
        std::suspend_always initial_suspend() const noexcept { return {}; }
        final_awaiter final_suspend() const noexcept { return {}; }
        void return_void() const noexcept {}
        void unhandled_exception() { std::terminate(); }
    };

    std::coroutine_handle<promise_type> h{};
    explicit task(std::coroutine_handle<promise_type> x) noexcept : h(x) {}
    task(task&& o) noexcept : h(std::exchange(o.h, {})) {}
    task(const task&) = delete;
    ~task() { if (h) h.destroy(); }

    struct awaiter {
        std::coroutine_handle<promise_type> h;
        bool await_ready() const noexcept { return false; }
        std::coroutine_handle<> await_suspend(std::coroutine_handle<> caller) noexcept {
            h.promise().continuation = caller;
            return h;
        }
        void await_resume() const noexcept {}
    };
    awaiter operator co_await() && noexcept { return awaiter{h}; }
};

task leaf() { co_return; }

task driver(int n) {
    for (int i = 0; i < n; ++i) co_await leaf();
    co_return;
}

}  // namespace

int main(int argc, char** argv) {
    int n = argc > 1 ? std::atoi(argv[1]) : 200000;
    auto t = driver(n);
    t.h.resume();
    std::printf("%d symmetric transfers completed without exhausting the stack\n", n);
    return 0;
}
