// Typed row mapping with compile time field binding.
//
// The user declares which struct member each column feeds. The binding is a
// constexpr tuple of member pointers, so the decoder chosen for every field is
// picked at compile time and a member whose type has no field_codec is a
// compilation error, not a run time surprise.
//
// Column names are resolved once per result set, not once per row: the mapper
// stores the resolved indices.
//
//     struct book { std::int64_t id; std::string title; double price; };
//     template <> struct conduit::row_mapping<book> {
//         static constexpr auto fields = std::tuple{
//             conduit::bind_field("id", &book::id),
//             conduit::bind_field("title", &book::title),
//             conduit::bind_field("price", &book::price)};
//     };
#pragma once

#include <array>
#include <cstddef>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#include "conduit/value.hpp"

namespace conduit {

class mapping_error : public std::runtime_error {
public:
    explicit mapping_error(const std::string& what) : std::runtime_error(what) {}
};

template <class Struct, class Member>
struct field_binding {
    const char* name;
    Member Struct::* pointer;
    using member_type = Member;
    using struct_type = Struct;
};

template <class Struct, class Member>
constexpr field_binding<Struct, Member> bind_field(const char* name, Member Struct::* p) {
    return {name, p};
}

// Specialise this for every struct that is read from a result set.
template <class T>
struct row_mapping;

template <class T>
concept mappable = requires { row_mapping<T>::fields; };

template <mappable T>
class row_mapper {
public:
    static constexpr auto bindings = row_mapping<T>::fields;
    static constexpr std::size_t field_count =
        std::tuple_size_v<std::remove_cvref_t<decltype(bindings)>>;

    // `columns` is any range whose elements have a `.name` convertible to a
    // string view. Both backends satisfy that without sharing a base class,
    // which is the point of the design.
    template <class Columns>
    explicit row_mapper(const Columns& columns) {
        [&]<std::size_t... I>(std::index_sequence<I...>) {
            ((indices_[I] = resolve(columns, std::get<I>(bindings).name)), ...);
        }(std::make_index_sequence<field_count>{});
    }

    T operator()(std::span<const field_view> row) const {
        T out{};
        [&]<std::size_t... I>(std::index_sequence<I...>) {
            (assign<I>(out, row), ...);
        }(std::make_index_sequence<field_count>{});
        return out;
    }

    std::size_t index_of(std::size_t field) const { return indices_[field]; }

private:
    template <std::size_t I>
    void assign(T& out, std::span<const field_view> row) const {
        constexpr auto binding = std::get<I>(bindings);
        using member = typename std::remove_cvref_t<decltype(binding)>::member_type;
        static_assert(requires(field_view f) { field_codec<member>::decode(f); },
                      "no field_codec for this member type; add a specialisation or "
                      "change the member to a supported type");
        if (indices_[I] >= row.size())
            throw mapping_error(std::string("column ") + binding.name + " is not in the row");
        out.*(binding.pointer) = field_codec<member>::decode(row[indices_[I]]);
    }

    template <class Columns>
    static std::size_t resolve(const Columns& columns, std::string_view name) {
        std::size_t i = 0;
        for (const auto& c : columns) {
            if (std::string_view(c.name) == name) return i;
            ++i;
        }
        throw mapping_error("result set has no column named " + std::string(name));
    }

    std::array<std::size_t, field_count> indices_{};
};

}  // namespace conduit
