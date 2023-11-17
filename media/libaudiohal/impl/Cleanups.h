/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <forward_list>
#include <mutex>
#include <utility>

namespace android {

// This class implements the "monitor" idiom for providing locked access to a class instance.
// This is how it is intended to be used. Let's assume there is a "Main" class which owns
// an instance of a "Resource" class, which is protected by a mutex. We add an instance of
// "LockedAccessor<Resource>" as a member of "Main":
//
// class Resource;
//
// class Main {
//     Main() : mAccessor(mResource, mLock) {}
//   private:
//     std::mutex mLock;
//     Resource mResource GUARDED_BY(mLock);  // owns the resource
//     LockedAccessor<Resource> mAccessor;
// };
//
// The accessor is initialized in the constructor when no locking is needed. The accessor
// defers locking until the resource is accessed.
//
// Although "mAccessor" can be used by the methods of "Main" for scoped access to the resource,
// its main role is for granting access to the resource to other classes. This is achieved by
// making a copy of "mAccessor" and giving it away to another class. This obviously does not
// transfer ownership of the resource. The intent is to allow another class to use the resource
// with proper locking in a "lazy" fashion:
//
// class Another {
//   public:
//     Another(const LockedAccessor<Resource>& accessor) : mAccessor(accessor) {}
//     void doItLater() {  // Use explicit 'lock' / 'unlock'
//         auto resource = mAccessor.lock();
//         resource.use();
//         mAccessor.unlock();
//     }
//     void doItLaterScoped() {  // Rely on the scoped accessor do perform unlocking.
//         LockedAccessor<Resource> scopedAccessor(mAccessor);
//         auto resource = scopedAccessor.lock();
//         resource.use();
//     }
//   private:
//     LockedAccessor<Resource> mAccessor;
// };
//
template<class C>
class LockedAccessor {
  public:
    LockedAccessor(C& instance, std::mutex& mutex)
            : mInstance(instance), mMutex(mutex), mLock(mMutex, std::defer_lock) {}
    LockedAccessor(const LockedAccessor& other)
            : mInstance(other.mInstance), mMutex(other.mMutex), mLock(mMutex, std::defer_lock) {}
    ~LockedAccessor() { if (mLock.owns_lock()) mLock.unlock(); }
    C& lock() { mLock.lock(); return mInstance; }
    void unlock() { mLock.unlock(); }
  private:
    C& mInstance;
    std::mutex& mMutex;
    std::unique_lock<std::mutex> mLock;
};

// This class implements scoped cleanups. A "cleanup" is a call to a method of class "C" which
// takes an integer parameter. Cleanups are executed in the reverse order to how they were added.
// For executing cleanups, the instance of "C" is retrieved via the provided "LockedAccessor".
template<class C>
class Cleanups {
  public:
    typedef void (C::*Cleaner)(int32_t);  // A member function of "C" performing a cleanup action.
    explicit Cleanups(const LockedAccessor<C>& accessor) : mAccessor(accessor) {}
    ~Cleanups() {
        if (!mCleanups.empty()) {
            C& c = mAccessor.lock();
            for (auto& cleanup : mCleanups) (c.*cleanup.first)(cleanup.second);
            mAccessor.unlock();
        }
    }
    void add(Cleaner cleaner, int32_t id) {
        mCleanups.emplace_front(cleaner, id);
    }
    void disarmAll() { mCleanups.clear(); }
  private:
    using Cleanup = std::pair<Cleaner, int32_t>;
    LockedAccessor<C> mAccessor;
    std::forward_list<Cleanup> mCleanups;
};

}  // namespace android
