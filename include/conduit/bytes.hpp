// Byte level primitives: fixed width reads and writes in both byte orders, and
// the growable buffer that owns the bytes a connection has received.
//
// The two wire protocols disagree about byte order. PostgreSQL sends network
// order, MySQL sends little endian. Both live here so no codec has to open
// code a shift chain.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace conduit {

using byte_span = std::span<const std::byte>;

// Thrown when a decoder is asked to read past the end of the bytes it was
// given, or when the bytes do not match the protocol specification. A
// connection that raises this is not reusable: the stream position is lost.
class protocol_error : public std::runtime_error {
public:
    explicit protocol_error(const std::string& what) : std::runtime_error(what) {}
};

// --- fixed width scalar reads -----------------------------------------------
// Unchecked, on purpose. The callers below (byte_reader) do the bounds check
// once for the whole field rather than once per byte.

inline std::uint16_t load_be16(const std::byte* p) noexcept {
    return static_cast<std::uint16_t>((std::to_integer<std::uint32_t>(p[0]) << 8) |
                                      std::to_integer<std::uint32_t>(p[1]));
}
inline std::uint32_t load_be32(const std::byte* p) noexcept {
    return (std::to_integer<std::uint32_t>(p[0]) << 24) |
           (std::to_integer<std::uint32_t>(p[1]) << 16) |
           (std::to_integer<std::uint32_t>(p[2]) << 8) |
           std::to_integer<std::uint32_t>(p[3]);
}
inline std::uint64_t load_be64(const std::byte* p) noexcept {
    return (static_cast<std::uint64_t>(load_be32(p)) << 32) | load_be32(p + 4);
}
inline std::uint16_t load_le16(const std::byte* p) noexcept {
    return static_cast<std::uint16_t>(std::to_integer<std::uint32_t>(p[0]) |
                                      (std::to_integer<std::uint32_t>(p[1]) << 8));
}
inline std::uint32_t load_le24(const std::byte* p) noexcept {
    return std::to_integer<std::uint32_t>(p[0]) |
           (std::to_integer<std::uint32_t>(p[1]) << 8) |
           (std::to_integer<std::uint32_t>(p[2]) << 16);
}
inline std::uint32_t load_le32(const std::byte* p) noexcept {
    return load_le24(p) | (std::to_integer<std::uint32_t>(p[3]) << 24);
}
inline std::uint64_t load_le64(const std::byte* p) noexcept {
    return static_cast<std::uint64_t>(load_le32(p)) |
           (static_cast<std::uint64_t>(load_le32(p + 4)) << 32);
}

// --- reader over a borrowed span --------------------------------------------
// Owns nothing. Every accessor either returns a value inside the span or
// throws protocol_error. This is the only place the codecs are allowed to
// walk raw bytes.
class byte_reader {
public:
    explicit byte_reader(byte_span data) noexcept : data_(data) {}

    std::size_t remaining() const noexcept { return data_.size() - pos_; }
    std::size_t position() const noexcept { return pos_; }
    bool empty() const noexcept { return remaining() == 0; }
    byte_span rest() const noexcept { return data_.subspan(pos_); }
    void skip(std::size_t n) { need(n); pos_ += n; }

    std::uint8_t u8() { need(1); return std::to_integer<std::uint8_t>(data_[pos_++]); }
    std::int8_t i8() { return static_cast<std::int8_t>(u8()); }

    std::uint16_t be16() { need(2); auto v = load_be16(data_.data() + pos_); pos_ += 2; return v; }
    std::uint32_t be32() { need(4); auto v = load_be32(data_.data() + pos_); pos_ += 4; return v; }
    std::uint64_t be64() { need(8); auto v = load_be64(data_.data() + pos_); pos_ += 8; return v; }
    std::int16_t  i16be() { return static_cast<std::int16_t>(be16()); }
    std::int32_t  i32be() { return static_cast<std::int32_t>(be32()); }
    std::int64_t  i64be() { return static_cast<std::int64_t>(be64()); }

    std::uint16_t le16() { need(2); auto v = load_le16(data_.data() + pos_); pos_ += 2; return v; }
    std::uint32_t le24() { need(3); auto v = load_le24(data_.data() + pos_); pos_ += 3; return v; }
    std::uint32_t le32() { need(4); auto v = load_le32(data_.data() + pos_); pos_ += 4; return v; }
    std::uint64_t le64() { need(8); auto v = load_le64(data_.data() + pos_); pos_ += 8; return v; }

    byte_span bytes(std::size_t n) { need(n); auto s = data_.subspan(pos_, n); pos_ += n; return s; }

    // A view, not a copy. Valid while the underlying buffer is unchanged. This
    // is the zero copy rule stated in one place.
    std::string_view str(std::size_t n) {
        auto s = bytes(n);
        return std::string_view(reinterpret_cast<const char*>(s.data()), s.size());
    }

    // NUL terminated string, as both protocols use for names and error fields.
    std::string_view cstr() {
        std::size_t start = pos_;
        while (pos_ < data_.size() && data_[pos_] != std::byte{0}) ++pos_;
        if (pos_ >= data_.size()) throw protocol_error("unterminated C string");
        auto sv = std::string_view(reinterpret_cast<const char*>(data_.data() + start), pos_ - start);
        ++pos_;
        return sv;
    }

private:
    void need(std::size_t n) const {
        if (remaining() < n)
            throw protocol_error("short read: need " + std::to_string(n) + " have " +
                                 std::to_string(remaining()));
    }
    byte_span data_;
    std::size_t pos_ = 0;
};

// --- writer -----------------------------------------------------------------
// Appends to a caller owned vector. Message length prefixes are patched in
// place afterwards, which is why the offset returning helpers exist.
class byte_writer {
public:
    explicit byte_writer(std::vector<std::byte>& out) noexcept : out_(out) {}

    std::size_t size() const noexcept { return out_.size(); }

    void u8(std::uint8_t v) { out_.push_back(std::byte{v}); }
    void ch(char c) { out_.push_back(static_cast<std::byte>(c)); }

    void be16(std::uint16_t v) { u8(std::uint8_t(v >> 8)); u8(std::uint8_t(v)); }
    void be32(std::uint32_t v) { be16(std::uint16_t(v >> 16)); be16(std::uint16_t(v)); }
    void be64(std::uint64_t v) { be32(std::uint32_t(v >> 32)); be32(std::uint32_t(v)); }
    void i16be(std::int16_t v) { be16(static_cast<std::uint16_t>(v)); }
    void i32be(std::int32_t v) { be32(static_cast<std::uint32_t>(v)); }
    void i64be(std::int64_t v) { be64(static_cast<std::uint64_t>(v)); }

    void le16(std::uint16_t v) { u8(std::uint8_t(v)); u8(std::uint8_t(v >> 8)); }
    void le24(std::uint32_t v) { u8(std::uint8_t(v)); u8(std::uint8_t(v >> 8)); u8(std::uint8_t(v >> 16)); }
    void le32(std::uint32_t v) { le24(v); u8(std::uint8_t(v >> 24)); }
    void le64(std::uint64_t v) { le32(std::uint32_t(v)); le32(std::uint32_t(v >> 32)); }

    void raw(byte_span s) { out_.insert(out_.end(), s.begin(), s.end()); }
    void raw(std::string_view s) {
        out_.insert(out_.end(), reinterpret_cast<const std::byte*>(s.data()),
                    reinterpret_cast<const std::byte*>(s.data()) + s.size());
    }
    void cstr(std::string_view s) { raw(s); u8(0); }

    // Reserve four bytes for a length that is not known yet, and return the
    // offset so it can be filled once the body is written.
    std::size_t reserve_be32() { std::size_t at = out_.size(); be32(0); return at; }
    void patch_be32(std::size_t at, std::uint32_t v) {
        out_[at + 0] = std::byte(std::uint8_t(v >> 24));
        out_[at + 1] = std::byte(std::uint8_t(v >> 16));
        out_[at + 2] = std::byte(std::uint8_t(v >> 8));
        out_[at + 3] = std::byte(std::uint8_t(v));
    }
    std::size_t reserve_le24() { std::size_t at = out_.size(); le24(0); return at; }
    void patch_le24(std::size_t at, std::uint32_t v) {
        out_[at + 0] = std::byte(std::uint8_t(v));
        out_[at + 1] = std::byte(std::uint8_t(v >> 8));
        out_[at + 2] = std::byte(std::uint8_t(v >> 16));
    }

private:
    std::vector<std::byte>& out_;
};

// --- receive buffer ---------------------------------------------------------
// A connection reads into the tail and the codec consumes from the head. The
// two never meet because consume() only moves a cursor: the bytes are
// physically shifted at most once per compaction, when the head has grown past
// half the buffer. Views handed out by the decoder stay valid until the next
// compaction, which is exactly the documented lifetime of a row.
class recv_buffer {
public:
    byte_span readable() const noexcept {
        return byte_span(data_.data() + head_, tail_ - head_);
    }
    std::size_t readable_size() const noexcept { return tail_ - head_; }

    // Space to read into. Grows the storage if fewer than `want` bytes are free.
    std::span<std::byte> writable(std::size_t want) {
        if (data_.size() - tail_ < want) {
            compact();
            if (data_.size() - tail_ < want) data_.resize(tail_ + want);
        }
        return std::span<std::byte>(data_.data() + tail_, data_.size() - tail_);
    }
    void committed(std::size_t n) noexcept { tail_ += n; }
    void consume(std::size_t n) noexcept {
        head_ += n;
        if (head_ == tail_) { head_ = tail_ = 0; }
    }
    void clear() noexcept { head_ = tail_ = 0; }

    void compact() {
        if (head_ == 0) return;
        std::memmove(data_.data(), data_.data() + head_, tail_ - head_);
        tail_ -= head_;
        head_ = 0;
    }

    // Test seam: feed bytes as if they had arrived from the socket.
    void append(byte_span s) {
        auto dst = writable(s.size());
        std::memcpy(dst.data(), s.data(), s.size());
        committed(s.size());
    }
    std::size_t capacity() const noexcept { return data_.size(); }

private:
    std::vector<std::byte> data_ = std::vector<std::byte>(16 * 1024);
    std::size_t head_ = 0;
    std::size_t tail_ = 0;
};

// Convenience for tests and for building literal wire messages.
std::vector<std::byte> from_hex(std::string_view hex);
std::string to_hex(byte_span data);
inline byte_span as_bytes(std::string_view s) {
    return byte_span(reinterpret_cast<const std::byte*>(s.data()), s.size());
}

}  // namespace conduit
