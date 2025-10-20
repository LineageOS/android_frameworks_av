/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace android::mediautils {
// Essentially std::function <void()>, but supports moveable types (and binds to any return type).
// The lack of moveable is fixed in C++23, but we don't yet have it.
// Also, SBO for std::packaged_task size, which is what we are using this for
class Runnable {
  private:
    // src == nullptr => destroy the dest, otherwise move from src storage to dst, destroying src
    using move_destroy_fptr_t = void (*)(std::byte* dest, std::byte* src) noexcept;
    using call_fptr_t = void (*)(std::byte* storage);

    struct VTable {
        move_destroy_fptr_t move_destroy;
        call_fptr_t invoke;
    };

    static void empty_move_destroy(std::byte*, std::byte*) noexcept {}
    static constexpr VTable empty_vtable{.move_destroy = empty_move_destroy, .invoke = nullptr};

    template <typename T>
    static T& transmogrify(std::byte* addr) {
        return *std::launder(reinterpret_cast<T*>(addr));
    }

    template <typename T>
    static void move_destroy_impl(std::byte* dest, std::byte* src) noexcept {
        if (src) {
            std::construct_at(&transmogrify<T>(dest), std::move(transmogrify<T>(src)));
            transmogrify<T>(src).~T();
        } else {
            transmogrify<T>(dest).~T();
        }
    }

    template <typename T>
    static void call_impl(std::byte* addr) {
        std::invoke(transmogrify<T>(addr));
    }

  public:
    static constexpr size_t STORAGE_SIZE = sizeof(std::packaged_task<int()>);

    Runnable() = default;

    Runnable(std::nullptr_t) {}

    Runnable(const Runnable& o) = delete;

    Runnable(Runnable&& o) noexcept {
        // ask other vtable to move their storage into ours
        o.v.move_destroy(storage_, o.storage_);
        std::swap(v, o.v);
    }

    template <typename F>
        requires(std::is_invocable_v<std::decay_t<F>> &&
                 !std::is_same_v<std::decay_t<F>, Runnable> &&
                 std::is_move_constructible_v<std::decay_t<F>> &&
                 sizeof(std::decay_t<F>) <= STORAGE_SIZE)
    explicit Runnable(F&& task)
        : v{move_destroy_impl<std::decay_t<F>>, call_impl<std::decay_t<F>>} {
        std::construct_at(&transmogrify<std::decay_t<F>>(storage_), std::forward<F>(task));
    }

    Runnable& operator=(const Runnable& o) = delete;

    Runnable& operator=(Runnable&& o) {
        // destroy ourselves
        v.move_destroy(storage_, nullptr);
        v = empty_vtable;
        // ask other vtable to move their storage into ours
        o.v.move_destroy(storage_, o.storage_);
        std::swap(v, o.v);
        return *this;
    }

    ~Runnable() { v.move_destroy(storage_, nullptr); }

    operator bool() const { return v.invoke != nullptr; }

    void operator()() {
        if (*this) v.invoke(storage_);
    }

  private:
    VTable v = empty_vtable;
    alignas(alignof(std::max_align_t)) std::byte storage_[STORAGE_SIZE];
};

// Wraps executor submission in a std::packaged_task to generate a future on the result of the
// runnable
template <typename Executor, typename F> requires requires (F f) { f(); }
auto submit(Executor& e, F&& f) {
    std::packaged_task task{ f };
    auto future = task.get_future();
    e.enqueue(Runnable{std::move(task)});
    return future;
}

}  // namespace android::mediautils
