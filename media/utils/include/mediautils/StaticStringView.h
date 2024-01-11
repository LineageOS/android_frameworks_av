/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <string_view>
#include <type_traits>

#pragma push_macro("EXPLICIT_CONVERSION_GENERATE_OPERATOR")
#undef EXPLICIT_CONVERSION_GENERATE_OPERATOR
#define EXPLICIT_CONVERSION_GENERATE_OPERATOR(T, U, op)    \
    friend constexpr bool operator op(T lhs, T rhs) {      \
        return static_cast<U>(lhs) op static_cast<U>(rhs); \
    }                                                      \
    friend constexpr bool operator op(T lhs, U rhs) {      \
        return static_cast<U>(lhs) op rhs;                 \
    }                                                      \
    friend constexpr bool operator op(U lhs, T rhs) {      \
        return lhs op static_cast<U>(rhs);                 \
    }

#pragma push_macro("EXPLICIT_CONVERSION_GENERATE_COMPARISON_OPERATORS")
#undef EXPLICIT_CONVERSION_GENERATE_COMPARISON_OPERATORS
// Generate comparison operator friend functions for types (appropriately
// const/ref qualified) where T is **explicitly** convertible to U.
#define EXPLICIT_CONVERSION_GENERATE_COMPARISON_OPERATORS(T, U)      \
    EXPLICIT_CONVERSION_GENERATE_OPERATOR(T, U, ==)                  \
    EXPLICIT_CONVERSION_GENERATE_OPERATOR(T, U, !=)                  \
    EXPLICIT_CONVERSION_GENERATE_OPERATOR(T, U, <)                   \
    EXPLICIT_CONVERSION_GENERATE_OPERATOR(T, U, <=)                  \
    EXPLICIT_CONVERSION_GENERATE_OPERATOR(T, U, >)                   \
    EXPLICIT_CONVERSION_GENERATE_OPERATOR(T, U, >=)

namespace android::mediautils {

// This class a reference to a string with static storage duration
// which is const (i.e. a string view). We expose an identical API to
// string_view, however we do not publicly inherit to avoid potential mis-use of
// non-virtual dtors/methods.
//
// We can create APIs which consume only static strings, which
// avoids allocation/deallocation of the string locally, as well as potential
// lifetime issues caused by consuming raw pointers (or string_views).
// Equivalently, a string_view which is always valid, and whose underlying data
// can never change.
//
// In most cases, the string_view should be initialized at compile time (and there are
// helpers to do so below). In order to initialize a non-constexpr array,
// the second template param must be false (i.e. opt-in).
// Construction/usage as follows (constexpr required unless second template param is false):
//
//     constexpr static std::array<char, 12> debugString = toStdArray("MyMethodName");
//     constexpr auto myStaticStringView = StaticStringView::create<debugString>();
//     const auto size_t length = myStaticStringView.length() // can call any string_view methods
//     globalLog(myStaticStringView, ...); // Pass to APIs consuming StaticStringViews
//
struct StaticStringView final : private std::string_view {
    template <typename T>
    struct is_const_char_array : std::false_type {};

    // Use templated value helper
    template <size_t N>
    struct is_const_char_array<const std::array<char, N>> : std::true_type {};

    template <typename T>
    static constexpr bool is_const_char_array_v =
            is_const_char_array<std::remove_reference_t<T>>::value;

    template <auto& val, std::enable_if_t<is_const_char_array_v<decltype(val)>, bool> Check = true>
    static constexpr StaticStringView create() {
        if constexpr (Check) {
            // If this static_assert fails to compile, this method was called
            // with a non-constexpr
            static_assert(val[0]);
        }
        return StaticStringView{val.data(), val.size()};
    }

    // We can copy/move assign/construct from other StaticStringViews as their validity is already
    // ensured
    constexpr StaticStringView(const StaticStringView& other) = default;
    constexpr StaticStringView& operator=(const StaticStringView& other) = default;
    constexpr StaticStringView(StaticStringView&& other) = default;
    constexpr StaticStringView& operator=(StaticStringView&& other) = default;

    // Explicitly convert to a std::string_view (this is a strict loss of
    // information so should only be used across APIs which intend to consume
    // any std::string_view).
    constexpr std::string_view getStringView() const { return *this; }

    // The following methods expose an identical API to std::string_view
    using std::string_view::begin;
    using std::string_view::cbegin;
    using std::string_view::cend;
    using std::string_view::crbegin;
    using std::string_view::crend;
    using std::string_view::end;
    using std::string_view::rbegin;
    using std::string_view::rend;
    using std::string_view::operator[];
    using std::string_view::at;
    using std::string_view::back;
    using std::string_view::data;
    using std::string_view::empty;
    using std::string_view::front;
    using std::string_view::length;
    using std::string_view::max_size;
    using std::string_view::size;
    // These modifiers are valid because the resulting view is a
    // substring of the original static string
    using std::string_view::remove_prefix;
    using std::string_view::remove_suffix;
    // Skip swap
    using std::string_view::compare;
    using std::string_view::copy;
    using std::string_view::find;
    using std::string_view::find_first_not_of;
    using std::string_view::find_first_of;
    using std::string_view::find_last_not_of;
    using std::string_view::find_last_of;
    using std::string_view::rfind;
    using std::string_view::substr;
#if __cplusplus >= 202202L
    using std::string_view::ends_with;
    using std::string_view::starts_with;
#endif
    using std::string_view::npos;

    // Non-member friend functions to follow. Identical API to std::string_view
    template <class CharT, class Traits>
    friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os,
                                                         StaticStringView v) {
        return os << static_cast<std::string_view&>(v);
    }

    EXPLICIT_CONVERSION_GENERATE_COMPARISON_OPERATORS(const StaticStringView&,
                                                      const std::string_view&)

  private:
    constexpr StaticStringView(const char* ptr, size_t sz) : std::string_view(ptr, sz){};

  public:
    // The next two functions are logically consteval (only avail in c++20).
    // We can't use templates as params, as they would require references to
    // static which would unnecessarily bloat executable size.
    template <typename T, size_t N, size_t M>
    static constexpr std::array<T, N + M> concatArray(const std::array<T, N>& a,
                                                      const std::array<T, M>& b) {
        std::array<T, N + M> res{};
        for (size_t i = 0; i < N; i++) {
            res[i] = a[i];
        }
        for (size_t i = 0; i < M; i++) {
            res[N + i] = b[i];
        }
        return res;
    }

    static void arrayIsNotNullTerminated();

    // This method should only be called on C-style char arrays which are
    // null-terminated. Calling this method on a char array with intermediate null
    // characters (i.e. "hello\0" or "hel\0lo" will result in a std::array with null
    // characters, which is most likely not intended.
    // We attempt to detect a non-null terminated char array at link-time, but
    // this is best effort. A consequence of this approach is that this method
    // will fail to link for extern args, or when not inlined. Since this method
    // is intended to be used constexpr, this is not an issue.
    template <size_t N>
    static constexpr std::array<char, N - 1> toStdArray(const char (&input)[N]) {
        std::array<char, N - 1> res{};
        for (size_t i = 0; i < N - 1; i++) {
            res[i] = input[i];
        }
        // A workaround to generate a link-time error if toStdArray is not called on
        // a null-terminated char array.
        if (input[N - 1] != 0) arrayIsNotNullTerminated();
        return res;
    }
};
}  // namespace android::mediautils

// Specialization of std::hash for use with std::unordered_map
namespace std {
template <>
struct hash<android::mediautils::StaticStringView> {
    constexpr size_t operator()(const android::mediautils::StaticStringView& val) {
        return std::hash<std::string_view>{}(val.getStringView());
    }
};
}  // namespace std

#pragma pop_macro("EXPLICIT_CONVERSION_GENERATE_OPERATOR")
#pragma pop_macro("EXPLICIT_CONVERSION_GENERATE_COMPARISON_OPERATORS")
