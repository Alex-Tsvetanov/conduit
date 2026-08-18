#include "conduit/trace.hpp"

#include <ostream>

namespace conduit {

void message_trace::print(std::ostream& os, const char* prefix) const {
    for (const auto& e : entries_) {
        os << prefix << (e.dir == direction::to_server ? "-> " : "<- ") << e.message;
        os << "  (" << e.bytes << " B)";
        if (!e.detail.empty()) os << "  " << e.detail;
        os << '\n';
    }
    os << prefix << "round trips: " << round_trips_ << '\n';
}

}  // namespace conduit
