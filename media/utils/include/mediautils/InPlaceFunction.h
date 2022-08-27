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

#include <cstdlib>
#include <functional>
#include <memory>
#include <type_traits>

namespace android::mediautils {

namespace detail {
// Vtable interface for erased types
template <typename Ret, typename... Args>
struct ICallableTable {
    // Destroy the erased type
    void (*destroy)(void* storage) = nullptr;
    // Call the erased object
    Ret (*invoke)(void* storage, Args...) = nullptr;
    // **Note** the next two functions only copy object data, not the vptr
    // Copy the erased object to a new InPlaceFunction buffer
    void (*copy_to)(const void* storage, void* other) = nullptr;
    // Move the erased object to a new InPlaceFunction buffer
    void (*move_to)(void* storage, void* other) = nullptr;
};
}  // namespace detail

// This class is an *almost* drop-in replacement for std::function which is guaranteed to never
// allocate, and always holds the type erased functional object in an in-line small buffer of
// templated size. If the object is too large to hold, the type will fail to instantiate.
//
// Two notable differences are:
// - operator() is not const (unlike std::function where the call operator is
// const even if the erased type is not const callable). This retains const
// correctness by default. A workaround is keeping InPlaceFunction mutable.
// - Moving from an InPlaceFunction leaves the object in a valid state (operator
// bool remains true), similar to std::optional/std::variant.
// Calls to the object are still defined (and are equivalent
// to calling the underlying type after it has been moved from). To opt-out
// (and/or ensure safety), clearing the object is recommended:
//      func1 = std::move(func2); // func2 still valid (and moved-from) after this line
//      func2 = nullptr; // calling func2 will now abort
template <typename, size_t BufferSize = 32>
class InPlaceFunction;
// We partially specialize to match types which are spelled like functions
template <typename Ret, typename... Args, size_t BufferSize>
class InPlaceFunction<Ret(Args...), BufferSize> {
  public:
    // Storage Type Details
    static constexpr size_t Size = BufferSize;
    static constexpr size_t Alignment = alignof(std::max_align_t);
    using Buffer_t = std::aligned_storage_t<Size, Alignment>;
    template <typename T, size_t Other>
    friend class InPlaceFunction;

  private:
    // Callable which is used for empty InPlaceFunction objects (to match the
    // std::function interface).
    struct BadCallable {
        [[noreturn]] Ret operator()(Args...) { std::abort(); }
    };
    static_assert(std::is_trivially_destructible_v<BadCallable>);

    // Implementation of vtable interface for erased types.
    // Contains only static vtable instantiated once for each erased type and
    // static helpers.
    template <typename T>
    struct TableImpl {
        // T should be a decayed type
        static_assert(std::is_same_v<T, std::decay_t<T>>);

        // Helper functions to get an unerased reference to the type held in the
        // buffer. std::launder is required to avoid strict aliasing rules.
        // The cast is always defined, as a precondition for these calls is that
        // (exactly) a T was placement new constructed into the buffer.
        constexpr static T& getRef(void* storage) {
            return *std::launder(reinterpret_cast<T*>(storage));
        }

        constexpr static const T& getRef(const void* storage) {
            return *std::launder(reinterpret_cast<const T*>(storage));
        }

        // Constexpr implies inline
        constexpr static detail::ICallableTable<Ret, Args...> table = {
                // Stateless lambdas are convertible to function ptrs
                .destroy = [](void* storage) { getRef(storage).~T(); },
                .invoke = [](void* storage, Args... args) -> Ret {
                    return std::invoke(getRef(storage), args...);
                },
                .copy_to = [](const void* storage,
                              void* other) { ::new (other) T(getRef(storage)); },
                .move_to = [](void* storage,
                              void* other) { ::new (other) T(std::move(getRef(storage))); },
        };
    };

    // Check size/align requirements for the T in Buffer_t. We use a templated
    // struct to enable std::conjunction (see below).
    template <typename T>
    struct WillFit : std::integral_constant<bool, sizeof(T) <= Size && alignof(T) <= Alignment> {};

    // Check size/align requirements for a function to function conversion
    template <typename T>
    struct ConversionWillFit
        : std::integral_constant<bool, (T::Size < Size) && (T::Alignment <= Alignment)> {};
    template <typename T>
    struct IsInPlaceFunction : std::false_type {};

    template <size_t BufferSize_>
    struct IsInPlaceFunction<InPlaceFunction<Ret(Args...), BufferSize_>> : std::true_type {};

    // Pred is true iff T is a valid type to construct an InPlaceFunction with
    // We use std::conjunction for readability and short-circuit behavior
    // (checks are ordered).
    // The actual target type is the decay of T.
    template <typename T>
    static constexpr bool Pred = std::conjunction_v<
            std::negation<IsInPlaceFunction<std::decay_t<T>>>,   // T is not also an InPlaceFunction
                                                                 // of the same signature.
            std::is_invocable_r<Ret, std::decay_t<T>, Args...>,  // correct signature callable
            WillFit<std::decay_t<T>>  // The target type fits in local storage
            >;

    template <typename T>
    static constexpr bool ConvertibleFunc =
            std::conjunction_v<IsInPlaceFunction<std::decay_t<T>>,  // implies correctly invokable
                               ConversionWillFit<std::decay_t<T>>>;

    // Members below
    // This must come first for alignment
    Buffer_t storage_;
    const detail::ICallableTable<Ret, Args...>* vptr_;

    constexpr void copy_to(InPlaceFunction& other) const {
        vptr_->copy_to(std::addressof(storage_), std::addressof(other.storage_));
        other.vptr_ = vptr_;
    }

    constexpr void move_to(InPlaceFunction& other) {
        vptr_->move_to(std::addressof(storage_), std::addressof(other.storage_));
        other.vptr_ = vptr_;
    }

    constexpr void destroy() { vptr_->destroy(std::addressof(storage_)); }

    template <typename T, typename Target = std::decay_t<T>>
    constexpr void genericInit(T&& t) {
        vptr_ = &TableImpl<Target>::table;
        ::new (std::addressof(storage_)) Target(std::forward<T>(t));
    }

    template <typename T, typename Target = std::decay_t<T>>
    constexpr void convertingInit(T&& smallerFunc) {
        // Redundant, but just in-case
        static_assert(Target::Size < Size && Target::Alignment <= Alignment);
        if constexpr (std::is_lvalue_reference_v<T>) {
            smallerFunc.vptr_->copy_to(std::addressof(smallerFunc.storage_),
                                         std::addressof(storage_));
        } else {
            smallerFunc.vptr_->move_to(std::addressof(smallerFunc.storage_),
                                         std::addressof(storage_));
        }
        vptr_ = smallerFunc.vptr_;
    }

  public:
    // Public interface
    template <typename T, std::enable_if_t<Pred<T>>* = nullptr>
    constexpr InPlaceFunction(T&& t) {
        genericInit(std::forward<T>(t));
    }

    // Conversion from smaller functions.
    template <typename T, std::enable_if_t<ConvertibleFunc<T>>* = nullptr>
    constexpr InPlaceFunction(T&& t) {
        convertingInit(std::forward<T>(t));
    }

    constexpr InPlaceFunction(const InPlaceFunction& other) { other.copy_to(*this); }

    constexpr InPlaceFunction(InPlaceFunction&& other) { other.move_to(*this); }

    // Making functions default constructible has pros and cons, we will align
    // with the standard
    constexpr InPlaceFunction() : InPlaceFunction(BadCallable{}) {}

    constexpr InPlaceFunction(std::nullptr_t) : InPlaceFunction(BadCallable{}) {}
#if __cplusplus >= 202002L
    constexpr
#endif
    ~InPlaceFunction() {
        destroy();
    }

    // The std::function call operator is marked const, but this violates const
    // correctness. We deviate from the standard and do not mark the operator as
    // const. Collections of InPlaceFunctions should probably be mutable.
    constexpr Ret operator()(Args... args) {
        return vptr_->invoke(std::addressof(storage_), args...);
    }

    constexpr InPlaceFunction& operator=(const InPlaceFunction& other) {
        if (std::addressof(other) == this) return *this;
        destroy();
        other.copy_to(*this);
        return *this;
    }

    constexpr InPlaceFunction& operator=(InPlaceFunction&& other) {
        if (std::addressof(other) == this) return *this;
        destroy();
        other.move_to(*this);
        return *this;
    }

    template <typename T, std::enable_if_t<Pred<T>>* = nullptr>
    constexpr InPlaceFunction& operator=(T&& t) {
        // We can't assign to ourselves, since T is a different type
        destroy();
        genericInit(std::forward<T>(t));
        return *this;
    }

    // Explicitly defining this function saves a move/dtor
    template <typename T, std::enable_if_t<ConvertibleFunc<T>>* = nullptr>
    constexpr InPlaceFunction& operator=(T&& t) {
        // We can't assign to ourselves, since T is different type
        destroy();
        convertingInit(std::forward<T>(t));
        return *this;
    }

    constexpr InPlaceFunction& operator=(std::nullptr_t) { return operator=(BadCallable{}); }

    // Moved from InPlaceFunctions are still considered valid (similar to
    // std::optional). If using std::move on a function object explicitly, it is
    // recommended that the object is reset using nullptr.
    constexpr explicit operator bool() const { return vptr_ != &TableImpl<BadCallable>::table; }

    constexpr void swap(InPlaceFunction& other) {
        if (std::addressof(other) == this) return;
        InPlaceFunction tmp{std::move(other)};
        other.destroy();
        move_to(other);
        destroy();
        tmp.move_to(*this);
    }

    friend constexpr void swap(InPlaceFunction& lhs, InPlaceFunction& rhs) { lhs.swap(rhs); }
};

}   // namespace android::mediautils
