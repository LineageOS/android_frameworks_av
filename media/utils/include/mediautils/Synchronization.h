/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once
#include <mutex>
#include <utils/RefBase.h>

namespace android::mediautils {

/**
 * The LockItem class introduces a simple template which mimics atomic<T>
 * for non-trivially copyable types.  For trivially copyable types,
 * the LockItem will statically assert that an atomic<T> should be used instead.
 *
 * The default lock mutex is std::mutex which is suitable for all but rare cases
 * e.g. recursive constructors that might be found in tree construction,
 * setters that might recurse onto the same object.
 */

template <typename T, typename L = std::mutex, int FLAGS = 0>
class LockItem {
protected:
    mutable L mLock;
    mutable T mT;

public:
    enum {
        // Best practices for smart pointers and complex containers is to move to a temp
        // and invoke destructor outside of lock.  This reduces time under lock and in
        // some cases eliminates deadlock.
        FLAG_DTOR_OUT_OF_LOCK = 1,
    };

    // Check type, suggest std::atomic if possible.
    static_assert(!std::is_trivially_copyable_v<T>,
            "type is trivially copyable, please use std::atomic instead");

    // Allow implicit conversions as expected for some types, e.g. sp -> wp.
    template <typename... Args>
    LockItem(Args&&... args) : mT(std::forward<Args>(args)...) {
    }

    // NOT copy or move / assignable or constructible.

    // Do not enable this because it may lead to confusion because it returns
    // a copy-value not a reference.
    // operator T() const { return load(); }

    // any conversion done under lock.
    template <typename U>
    void operator=(U&& u) {
        store(std::forward<U>(u));
    }

    // returns a copy-value not a reference.
    T load() const {
        std::lock_guard lock(mLock);
        return mT;
    }

    // any conversion done under lock.
    template <typename U>
    void store(U&& u) {
        if constexpr ((FLAGS & FLAG_DTOR_OUT_OF_LOCK) != 0) {
             std::unique_lock lock(mLock);
             T temp = std::move(mT);
             mT = std::forward<U>(u);
             lock.unlock();
        } else {
            std::lock_guard lock(mLock);
            mT = std::forward<U>(u);
        }
    }
};

/**
 * atomic_wp<> and atomic_sp<> are used for concurrent access to Android
 * sp<> and wp<> smart pointers, including their modifiers.  We
 * return a copy of the smart pointer with load().
 *
 * Historical: The importance of an atomic<std::shared_ptr<T>> class is described
 * by Herb Sutter in the following ISO document https://isocpp.org/files/papers/N4162.pdf
 * and is part of C++20.  Lock free versions of atomic smart pointers are available
 * publicly but usually require specialized smart pointer structs.
 * See also https://en.cppreference.com/w/cpp/memory/shared_ptr/atomic
 * and https://en.cppreference.com/w/cpp/memory/shared_ptr/atomic2
 *
 * We offer lock based atomic_wp<> and atomic_sp<> objects here. This is useful to
 * copy the Android smart pointer to a different variable for subsequent local access,
 * where the change of the original object after copy is acceptable.
 *
 * Note: Instead of atomics, it is often preferrable to create an explicit visible lock to
 * ensure complete transaction consistency.  For example, one might want to ensure
 * that the method called from the smart pointer is also done under lock.
 * This may not be possible for callbacks due to inverted lock ordering.
 */

template <typename T>
using atomic_wp = LockItem<::android::wp<T>>;

template <typename T>
using atomic_sp = LockItem<
        ::android::sp<T>, std::mutex, LockItem<::android::sp<T>>::FLAG_DTOR_OUT_OF_LOCK>;

/**
 * Defers a function to run in the RAII destructor.
 * A C++ implementation of Go _defer_ https://golangr.com/defer/.
 */
class Defer {
public:
    template <typename U>
    explicit Defer(U &&f) : mThunk(std::forward<U>(f)) {}
    ~Defer() { mThunk(); }

private:
    const std::function<void()> mThunk;
};

} // namespace android::mediautils

