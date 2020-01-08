/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <memory>
#include <mutex>

namespace android::mediametrics {

/**
 * Wraps a shared-ptr for which member access through operator->() behaves
 * as if the shared-ptr is atomically copied and then (without a lock) -> called.
 *
 * See related C++ 20:
 * https://en.cppreference.com/w/cpp/memory/shared_ptr/atomic2
 *
 * EXAMPLE:
 *
 * SharedPtrWrap<T> t{};
 *
 * thread1() {
 *   t->func();  // safely executes either the original t or the one created by thread2.
 * }
 *
 * thread2() {
 *  t.set(std::make_shared<T>()); // overwrites the original t.
 * }
 */
template <typename T>
class SharedPtrWrap {
    mutable std::mutex mLock;
    std::shared_ptr<T> mPtr;

public:
    template <typename... Args>
    explicit SharedPtrWrap(Args&&... args)
        : mPtr(std::make_shared<T>(std::forward<Args>(args)...))
    {}

    /**
     * Gets the current shared pointer.  This must return a value, not a reference.
     *
     * For compatibility with existing shared_ptr, we do not pass back a
     * shared_ptr<const T> for the const getter.
     */
    std::shared_ptr<T> get() const {
        std::lock_guard lock(mLock);
        return mPtr;
    }

    /**
     * Sets the current shared pointer, returning the previous shared pointer.
     */
    std::shared_ptr<T> set(std::shared_ptr<T> ptr) { // pass by value as we use swap.
        std::lock_guard lock(mLock);
        std::swap(ptr, mPtr);
        return ptr;
    }

    /**
     * Returns a shared pointer value representing T at the instant of time when
     * the call executes. The lifetime of the shared pointer will
     * be extended as we are returning an instance of the shared_ptr
     * not a reference to it.  The destructor to the returned shared_ptr
     * will be called sometime after the expression including the member function or
     * the member variable is evaluated. Do not change to a reference!
     */

    // For compatibility with existing shared_ptr, we do not pass back a
    // shared_ptr<const T> for the const operator pointer access.
    std::shared_ptr<T> operator->() const {
        return get();
    }
    /**
     * We do not overload operator*() as the reference is not stable if the
     * lock is not held.
     */
};

/**
 * Wraps member access to the class T by a lock.
 *
 * The object T is constructed within the LockWrap to guarantee
 * locked access at all times.  When T's methods are accessed through ->,
 * a monitor style lock is obtained to prevent multiple threads from executing
 * methods in the object T at the same time.
 * Suggested by Kevin R.
 *
 * EXAMPLE:
 *
 * // Accumulator class which is very slow, requires locking for multiple threads.
 *
 * class Accumulator {
 *   int32_t value_ = 0;
 * public:
 *   void add(int32_t incr) {
 *     const int32_t temp = value_;
 *     sleep(0);  // yield
 *     value_ = temp + incr;
 *   }
 *   int32_t get() { return value_; }
 * };
 *
 * // We use LockWrap on Accumulator to have safe multithread access.
 * android::mediametrics::LockWrap<Accumulator> a{}; // locked accumulator succeeds
 *
 * // Conversely, the following line fails:
 * // auto a = std::make_shared<Accumulator>(); // this fails, only 50% adds atomic.
 *
 * constexpr size_t THREADS = 100;
 * constexpr size_t ITERATIONS = 10;
 * constexpr int32_t INCREMENT = 1;
 *
 * // Test by generating multiple threads, all adding simultaneously.
 * std::vector<std::future<void>> threads(THREADS);
 * for (size_t i = 0; i < THREADS; ++i) {
 *     threads.push_back(std::async(std::launch::async, [&] {
 *         for (size_t j = 0; j < ITERATIONS; ++j) {
 *             a->add(INCREMENT);  // add needs locked access here.
 *         }
 *     }));
 * }
 * threads.clear();
 *
 * // If the add operations are not atomic, value will be smaller than expected.
 * ASSERT_EQ(INCREMENT * THREADS * ITERATIONS, (size_t)a->get());
 *
 */
template <typename T>
class LockWrap {
    /**
      * Holding class that keeps the pointer and the lock.
      *
      * We return this holding class from operator->() to keep the lock until the
      * method function or method variable access is completed.
      */
    class LockedPointer {
        friend LockWrap;
        LockedPointer(T *t, std::mutex *lock)
            : mT(t), mLock(*lock) {}
        T* const mT;
        std::lock_guard<std::mutex> mLock;
    public:
        const T* operator->() const {
            return mT;
        }
        T* operator->() {
            return mT;
        }
    };

    mutable std::mutex mLock;
    mutable T mT;

public:
    template <typename... Args>
    explicit LockWrap(Args&&... args) : mT(std::forward<Args>(args)...) {}

    const LockedPointer operator->() const {
        return LockedPointer(&mT, &mLock);
    }
    LockedPointer operator->() {
        return LockedPointer(&mT, &mLock);
    }

    // @TestApi
    bool isLocked() const {
        if (mLock.try_lock()) {
            mLock.unlock();
            return false; // we were able to get the lock.
        }
        return true; // we were NOT able to get the lock.
    }
};

} // namespace android::mediametrics
