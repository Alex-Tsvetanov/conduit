// The one thing the two protocol codecs have in common, written down.
//
// PostgreSQL and MySQL share no base class and no message vocabulary. What they
// do share is the shape of the framing step: given the bytes received so far,
// either produce one whole frame or say "not yet", without consuming anything.
// Expressing that as a concept rather than a virtual interface means the layers
// above can be templates and pay nothing for the abstraction.
#pragma once

#include <concepts>
#include <optional>

#include "conduit/bytes.hpp"

namespace conduit {

template <class C>
concept frame_codec = requires(byte_span in, const typename C::frame& f) {
    typename C::frame;
    // Never consumes. A partial frame is reported, not buffered internally,
    // which is what lets the same codec be driven by a socket or by a test that
    // feeds it one byte at a time.
    { C::peek(in) } -> std::same_as<std::optional<typename C::frame>>;
    // Total size of the frame including its header, so the caller knows how
    // much to drop from the receive buffer.
    { f.consumed } -> std::convertible_to<std::size_t>;
    // A human readable name for the trace.
    { C::describe(f) } -> std::convertible_to<const char*>;
};

}  // namespace conduit
