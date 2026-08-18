// A test runner small enough to read in one sitting. It exists because the
// build must work on a machine with nothing but a compiler and CMake, and a
// test framework fetched from the network is a dependency a stranger cannot
// satisfy offline.
//
// Usage:
//     CONDUIT_TEST(name_of_case) { CHECK(expr); CHECK_EQ(a, b); }
// Cases self register through a static constructor. main() runs them all,
// prints one line per case and returns non zero if any failed.
#pragma once

#include <cstdio>
#include <exception>
#include <sstream>
#include <string>
#include <vector>

namespace conduit_test {

struct failure {
    std::string file;
    int line;
    std::string text;
};

struct case_state {
    std::vector<failure> failures;
    std::string skip_reason;
    bool skipped = false;
};

// The case currently running. Single threaded by design: the runner never
// executes two cases at once, so a plain pointer is enough.
inline case_state*& current() {
    static case_state* p = nullptr;
    return p;
}

struct test_case {
    const char* name;
    void (*fn)();
};

inline std::vector<test_case>& registry() {
    static std::vector<test_case> v;
    return v;
}

struct registrar {
    registrar(const char* name, void (*fn)()) { registry().push_back({name, fn}); }
};

inline void record(const char* file, int line, std::string text) {
    if (current()) current()->failures.push_back({file, line, std::move(text)});
}

// A case that cannot run, for example because the server it needs is not up.
// Reported separately from a pass: "passed" and "did not run" are different
// statements, and folding them together hides missing coverage.
inline void skip(std::string reason) {
    if (current()) {
        current()->skipped = true;
        current()->skip_reason = std::move(reason);
    }
}

template <class A, class B>
std::string describe(const A& a, const B& b) {
    std::ostringstream os;
    os << "  left  = " << a << "\n  right = " << b;
    return os.str();
}

inline int run_all(int argc, char** argv) {
    std::string filter = argc > 1 ? argv[1] : "";
    int passed = 0, failed = 0, skipped = 0, not_selected = 0;
    for (const auto& tc : registry()) {
        if (!filter.empty() && std::string(tc.name).find(filter) == std::string::npos) {
            ++not_selected;
            continue;
        }
        case_state st;
        current() = &st;
        try {
            tc.fn();
        } catch (const std::exception& e) {
            st.failures.push_back({"<exception>", 0, std::string("uncaught: ") + e.what()});
        } catch (...) {
            st.failures.push_back({"<exception>", 0, "uncaught non standard exception"});
        }
        current() = nullptr;

        if (!st.failures.empty()) {
            ++failed;
            std::printf("FAIL %s\n", tc.name);
            for (const auto& f : st.failures)
                std::printf("     %s:%d\n%s\n", f.file.c_str(), f.line, f.text.c_str());
        } else if (st.skipped) {
            ++skipped;
            std::printf("skip %s  (%s)\n", tc.name, st.skip_reason.c_str());
        } else {
            ++passed;
            std::printf("ok   %s\n", tc.name);
        }
    }
    std::printf("\n%d passed, %d failed", passed, failed);
    if (skipped) std::printf(", %d skipped", skipped);
    if (not_selected) std::printf(", %d not selected", not_selected);
    std::printf("\n");
    return failed == 0 ? 0 : 1;
}

}  // namespace conduit_test

#define CONDUIT_CAT_(a, b) a##b
#define CONDUIT_CAT(a, b) CONDUIT_CAT_(a, b)

#define CONDUIT_TEST(name)                                                       \
    static void CONDUIT_CAT(conduit_case_, name)();                              \
    static ::conduit_test::registrar CONDUIT_CAT(conduit_reg_, name)(            \
        #name, &CONDUIT_CAT(conduit_case_, name));                               \
    static void CONDUIT_CAT(conduit_case_, name)()

// Ends the case immediately and reports it as skipped, never as passed.
#define CONDUIT_SKIP(reason)                                                     \
    do {                                                                         \
        ::conduit_test::skip(reason);                                            \
        return;                                                                  \
    } while (0)

#define CHECK(expr)                                                              \
    do {                                                                         \
        if (!(expr))                                                             \
            ::conduit_test::record(__FILE__, __LINE__, "  CHECK(" #expr ") is false"); \
    } while (0)

#define CHECK_EQ(a, b)                                                           \
    do {                                                                         \
        auto&& conduit_a_ = (a);                                                 \
        auto&& conduit_b_ = (b);                                                 \
        if (!(conduit_a_ == conduit_b_))                                         \
            ::conduit_test::record(__FILE__, __LINE__,                           \
                                   "  CHECK_EQ(" #a ", " #b ")\n" +              \
                                       ::conduit_test::describe(conduit_a_, conduit_b_)); \
    } while (0)

#define CHECK_NEAR(a, b, eps)                                                    \
    do {                                                                         \
        double conduit_a_ = double(a), conduit_b_ = double(b);                   \
        double conduit_d_ = conduit_a_ - conduit_b_;                             \
        if (conduit_d_ < 0) conduit_d_ = -conduit_d_;                            \
        if (!(conduit_d_ <= double(eps)))                                        \
            ::conduit_test::record(__FILE__, __LINE__,                           \
                                   "  CHECK_NEAR(" #a ", " #b ")\n" +            \
                                       ::conduit_test::describe(conduit_a_, conduit_b_)); \
    } while (0)

#define CHECK_THROWS(expr, exc)                                                  \
    do {                                                                         \
        bool conduit_caught_ = false;                                            \
        try {                                                                    \
            (void)(expr);                                                        \
        } catch (const exc&) {                                                   \
            conduit_caught_ = true;                                              \
        } catch (...) {                                                          \
        }                                                                        \
        if (!conduit_caught_)                                                    \
            ::conduit_test::record(__FILE__, __LINE__,                           \
                                   "  expected " #exc " from " #expr);           \
    } while (0)
