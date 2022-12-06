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

#include <algorithm>
#include <string>
#include <string_view>

namespace android::mediautils {

/*
 * FixedString is a stack allocatable string buffer that supports
 * simple appending of other strings and string_views.
 *
 * It is designed for no-malloc operation when std::string
 * small buffer optimization is insufficient.
 *
 * To keep code small, use asStringView() for operations on this.
 *
 * Notes:
 * 1) Appending beyond the internal buffer size results in truncation.
 *
 * Alternatives:
 * 1) If you want a sharable copy-on-write string implementation,
 *    consider using the legacy android::String8().
 * 2) Using std::string with a fixed stack allocator may suit your needs,
 *    but exception avoidance is tricky.
 * 3) Using C++20 ranges https://en.cppreference.com/w/cpp/ranges if you don't
 *    need backing store.  Be careful about allocation with ranges.
 *
 * Good small sizes are multiples of 16 minus 2, e.g. 14, 30, 46, 62.
 *
 * Implementation Notes:
 * 1) No iterators or [] for FixedString - please convert to std::string_view.
 * 2) For small N (e.g. less than 62), consider a change to always zero fill and
 *    potentially prevent always zero terminating (if one only does append).
 *
 * Possible arguments to create/append:
 * 1) A FixedString.
 * 2) A single char.
 * 3) A char * pointer.
 * 4) A std::string.
 * 5) A std::string_view (or something convertible to it).
 *
 * Example:
 *
 * FixedString s1(std::string("a"));    // ctor
 * s1 << "bc" << 'd' << '\n';           // streaming append
 * s1 += "hello";                       // += append
 * ASSERT_EQ(s1, "abcd\nhello");
 */
template <uint32_t N>
struct FixedString
{
    // Find the best size type.
    using strsize_t = std::conditional_t<(N > 255), uint32_t, uint8_t>;

    // constructors
    FixedString() { // override default
        buffer_[0] = '\0';
    }

    FixedString(const FixedString& other) { // override default.
        copyFrom<N>(other);
    }

    // The following constructor is not explicit to allow
    // FixedString<8> s = "abcd";
    template <typename ...Types>
    FixedString(Types&&... args) {
        append(std::forward<Types>(args)...);
    }

    // copy assign (copyFrom checks for equality and returns *this).
    FixedString& operator=(const FixedString& other) { // override default.
        return copyFrom<N>(other);
    }

    template <typename ...Types>
    FixedString& operator=(Types&&... args) {
        size_ = 0;
        return append(std::forward<Types>(args)...);
    }

    // operator equals
    bool operator==(const char *s) const {
        return strncmp(c_str(), s, capacity() + 1) == 0;
    }

    bool operator==(std::string_view s) const {
        return size() == s.size() && memcmp(data(), s.data(), size()) == 0;
    }

    // operator not-equals
    template <typename T>
    bool operator!=(const T& other) const {
        return !operator==(other);
    }

    // operator +=
    template <typename ...Types>
    FixedString& operator+=(Types&&... args) {
        return append(std::forward<Types>(args)...);
    }

    // conversion to std::string_view.
    operator std::string_view() const {
        return asStringView();
    }

    // basic observers
    size_t buffer_offset() const { return offsetof(std::decay_t<decltype(*this)>, buffer_); }
    static constexpr uint32_t capacity() { return N; }
    uint32_t size() const { return size_; }
    uint32_t remaining() const { return size_ >= N ? 0 : N - size_; }
    bool empty() const { return size_ == 0; }
    bool full() const { return size_ == N; }  // when full, possible truncation risk.
    char * data() { return buffer_; }
    const char * data() const { return buffer_; }
    const char * c_str() const { return buffer_; }

    inline std::string_view asStringView() const {
        return { buffer_, static_cast<size_t>(size_) };
    }
    inline std::string asString() const {
        return { buffer_, static_cast<size_t>(size_) };
    }

    void clear() { size_ = 0; buffer_[0] = 0; }

    // Implementation of append - using templates
    // to guarantee precedence in the presence of ambiguity.
    //
    // Consider C++20 template overloading through constraints and concepts.
    template <typename T>
    FixedString& append(const T& t) {
        using decayT = std::decay_t<T>;
        if constexpr (is_specialization_v<decayT, FixedString>) {
            // A FixedString<U>
            if (size_ == 0) {
                // optimization to erase everything.
                return copyFrom(t);
            } else {
                return appendStringView({t.data(), t.size()});
            }
        } else if constexpr(std::is_same_v<decayT, char>) {
            if (size_ < N) {
                buffer_[size_++] = t;
                buffer_[size_] = '\0';
            }
            return *this;
        } else if constexpr(std::is_same_v<decayT, char *>) {
            // Some char* ptr.
            return appendString(t);
        } else if constexpr (std::is_convertible_v<decayT, std::string_view>) {
            // std::string_view, std::string, or some other convertible type.
            return appendStringView(t);
        } else /* constexpr */ {
            static_assert(dependent_false_v<T>, "non-matching append type");
        }
    }

    FixedString& appendStringView(std::string_view s) {
        uint32_t total = std::min(static_cast<size_t>(N - size_), s.size());
        memcpy(buffer_ + size_, s.data(), total);
        size_ += total;
        buffer_[size_] = '\0';
        return *this;
    }

    FixedString& appendString(const char *s) {
        // strncpy zero pads to the end,
        // strlcpy returns total expected length,
        // we don't have strncpy_s in Bionic,
        // so we write our own here.
        while (size_ < N && *s != '\0') {
            buffer_[size_++] = *s++;
        }
        buffer_[size_] = '\0';
        return *this;
    }

    // Copy initialize the struct.
    // Note: We are POD but customize the copying for acceleration
    // of moving small strings embedded in a large buffers.
    template <uint32_t U>
    FixedString& copyFrom(const FixedString<U>& other) {
        if ((void*)this != (void*)&other) { // not a self-assignment
            if (other.size() == 0) {
                size_ = 0;
                buffer_[0] = '\0';
                return *this;
            }
            constexpr size_t kSizeToCopyWhole = 64;
            if constexpr (N == U &&
                    sizeof(*this) == sizeof(other) &&
                    sizeof(*this) <= kSizeToCopyWhole) {
                // As we have the same str size type, we can just
                // memcpy with fixed size, which can be easily optimized.
                memcpy(static_cast<void*>(this), static_cast<const void*>(&other), sizeof(*this));
                return *this;
            }
            if constexpr (std::is_same_v<strsize_t, typename FixedString<U>::strsize_t>) {
                constexpr size_t kAlign = 8;  // align to a multiple of 8.
                static_assert((kAlign & (kAlign - 1)) == 0); // power of 2.
                // we check any alignment issues.
                if (buffer_offset() == other.buffer_offset() && other.size() <= capacity()) {
                    // improve on standard POD copying by reducing size.
                    const size_t mincpy = buffer_offset() + other.size() + 1 /* nul */;
                    const size_t maxcpy = std::min(sizeof(*this), sizeof(other));
                    const size_t cpysize = std::min(mincpy + kAlign - 1 & ~(kAlign - 1), maxcpy);
                    memcpy(static_cast<void*>(this), static_cast<const void*>(&other), cpysize);
                    return *this;
                }
            }
            size_ = std::min(other.size(), capacity());
            memcpy(buffer_, other.data(), size_);
            buffer_[size_] = '\0';  // zero terminate.
        }
        return *this;
    }

private:
    //  Template helper methods

    template <typename Test, template <uint32_t> class Ref>
    struct is_specialization : std::false_type {};

    template <template <uint32_t> class Ref, uint32_t UU>
    struct is_specialization<Ref<UU>, Ref>: std::true_type {};

    template <typename Test, template <uint32_t> class Ref>
    static inline constexpr bool is_specialization_v = is_specialization<Test, Ref>::value;

    // For static assert(false) we need a template version to avoid early failure.
    template <typename T>
    static inline constexpr bool dependent_false_v = false;

    // POD variables
    strsize_t size_ = 0;
    char buffer_[N + 1 /* allow zero termination */];
};

// Stream operator syntactic sugar.
// Example:
// s << 'b' << "c" << "d" << '\n';
template <uint32_t N, typename ...Types>
FixedString<N>& operator<<(FixedString<N>& fs, Types&&... args) {
    return fs.append(std::forward<Types>(args)...);
}

// We do not use a default size for fixed string as changing
// the default size would lead to different behavior - we want the
// size to be explicitly known.

// FixedString62 of 62 chars fits in one typical cache line.
using FixedString62 = FixedString<62>;

// Slightly smaller
using FixedString30 = FixedString<30>;

// Since we have added copy and assignment optimizations,
// we are no longer trivially assignable and copyable.
// But we check standard layout here to prevent inclusion of unacceptable members or virtuals.
static_assert(std::is_standard_layout_v<FixedString62>);
static_assert(std::is_standard_layout_v<FixedString30>);

}  // namespace android::mediautils
