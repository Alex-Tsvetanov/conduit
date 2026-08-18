// The protocol message trace.
//
// Every message the client writes and every message it reads can be recorded
// with its name, its direction and its size. The trace is what makes the claim
// "the extended query flow costs one extra round trip the first time" checkable
// instead of asserted, and it is what the demonstration prints.
//
// Recording is off by default and costs one branch when off.
#pragma once

#include <cstddef>
#include <iosfwd>
#include <string>
#include <vector>

namespace conduit {

enum class direction { to_server, from_server };

struct trace_entry {
    direction dir;
    std::string message;  // protocol message name, as the specification names it
    std::size_t bytes;
    std::string detail;   // optional, for example the SQL text or an error code
};

class message_trace {
public:
    void enable(bool on) noexcept { enabled_ = on; }
    bool enabled() const noexcept { return enabled_; }

    void record(direction d, std::string message, std::size_t bytes, std::string detail = {}) {
        if (!enabled_) return;
        entries_.push_back({d, std::move(message), bytes, std::move(detail)});
    }

    // A round trip is one flush of pending output followed by a wait for the
    // server. Counted by the connection, not inferred from the entries, because
    // several messages are pipelined into a single flush on purpose.
    void count_round_trip() noexcept { ++round_trips_; }
    std::size_t round_trips() const noexcept { return round_trips_; }

    const std::vector<trace_entry>& entries() const noexcept { return entries_; }
    void clear() noexcept { entries_.clear(); round_trips_ = 0; }

    void print(std::ostream& os, const char* prefix = "") const;

private:
    bool enabled_ = false;
    std::size_t round_trips_ = 0;
    std::vector<trace_entry> entries_;
};

}  // namespace conduit
