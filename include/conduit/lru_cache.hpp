// A least recently used map, used for the prepared statement cache.
//
// Eviction returns the evicted entry rather than dropping it, because a
// prepared statement that leaves the cache still exists on the server and has
// to be closed. A cache that silently forgot the name would leak one server
// side statement per eviction.
#pragma once

#include <cstddef>
#include <list>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

namespace conduit {

template <class Value>
class lru_cache {
public:
    using entry = std::pair<std::string, Value>;

    explicit lru_cache(std::size_t capacity) : capacity_(capacity) {}

    Value* find(const std::string& key) {
        auto it = index_.find(key);
        if (it == index_.end()) { ++misses_; return nullptr; }
        ++hits_;
        order_.splice(order_.begin(), order_, it->second);
        return &it->second->second;
    }

    // Inserts or replaces. Returns the entry that had to be evicted, if any.
    std::optional<entry> put(std::string key, Value value) {
        auto it = index_.find(key);
        if (it != index_.end()) {
            it->second->second = std::move(value);
            order_.splice(order_.begin(), order_, it->second);
            return std::nullopt;
        }
        order_.emplace_front(key, std::move(value));
        index_.emplace(std::move(key), order_.begin());

        if (capacity_ == 0 || order_.size() <= capacity_) return std::nullopt;
        entry victim = std::move(order_.back());
        index_.erase(victim.first);
        order_.pop_back();
        ++evictions_;
        return victim;
    }

    std::optional<entry> erase(const std::string& key) {
        auto it = index_.find(key);
        if (it == index_.end()) return std::nullopt;
        entry gone = std::move(*it->second);
        order_.erase(it->second);
        index_.erase(it);
        return gone;
    }

    // Drains the cache, handing every entry back so the caller can close each
    // one on the server.
    std::list<entry> take_all() {
        index_.clear();
        std::list<entry> out;
        out.swap(order_);
        return out;
    }

    std::size_t size() const noexcept { return order_.size(); }
    std::size_t capacity() const noexcept { return capacity_; }
    std::size_t hits() const noexcept { return hits_; }
    std::size_t misses() const noexcept { return misses_; }
    std::size_t evictions() const noexcept { return evictions_; }
    void reset_stats() noexcept { hits_ = misses_ = evictions_ = 0; }

    // Most recently used first. Only the tests need the order made visible.
    std::vector<std::string> keys_in_order() const {
        std::vector<std::string> out;
        out.reserve(order_.size());
        for (const auto& e : order_) out.push_back(e.first);
        return out;
    }

private:
    std::size_t capacity_;
    std::list<entry> order_;
    std::unordered_map<std::string, typename std::list<entry>::iterator> index_;
    std::size_t hits_ = 0, misses_ = 0, evictions_ = 0;
};

}  // namespace conduit
