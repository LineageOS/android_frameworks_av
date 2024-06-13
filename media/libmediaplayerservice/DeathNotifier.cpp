/*
 * Copyright 2019 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaPlayerService-DeathNotifier"
#include <android-base/logging.h>
#include <map>

#include "DeathNotifier.h"

namespace android {

// Only dereference the cookie if it's valid (if it's in this set)
// Only used with ndk
static uintptr_t sCookieKeyCounter = 0;
static std::map<uintptr_t, wp<DeathNotifier::DeathRecipient>> sCookies;
static std::mutex sCookiesMutex;

class DeathNotifier::DeathRecipient :
        public IBinder::DeathRecipient,
        public hardware::hidl_death_recipient {
public:
    using Notify = DeathNotifier::Notify;

    DeathRecipient(Notify const& notify): mNotify{notify} {
    }

    void initNdk() {
        mNdkRecipient.set(AIBinder_DeathRecipient_new(OnBinderDied));
    }

    virtual void binderDied(wp<IBinder> const&) override {
        mNotify();
    }

    virtual void serviceDied(uint64_t, wp<HBase> const&) override {
        mNotify();
    }

    static void OnBinderDied(void *cookie) {
        std::unique_lock<std::mutex> guard(sCookiesMutex);
        if (auto it = sCookies.find(reinterpret_cast<uintptr_t>(cookie)); it != sCookies.end()) {
            sp<DeathRecipient> recipient = it->second.promote();
            sCookies.erase(it);
            guard.unlock();

            if (recipient) {
                LOG(INFO) << "Notifying DeathRecipient from OnBinderDied.";
                recipient->mNotify();
            } else {
                LOG(INFO) <<
                    "Tried to notify DeathRecipient from OnBinderDied but could not promote.";
            }
        }
    }

    AIBinder_DeathRecipient *getNdkRecipient() {
        return mNdkRecipient.get();;
    }
    ~DeathRecipient() {
        // lock must be taken so object is not used in OnBinderDied"
        std::lock_guard<std::mutex> guard(sCookiesMutex);
        sCookies.erase(mCookieKey);
    }

    uintptr_t mCookieKey;

private:
    Notify mNotify;
    ::ndk::ScopedAIBinder_DeathRecipient mNdkRecipient;
};

DeathNotifier::DeathNotifier(sp<IBinder> const& service, Notify const& notify)
      : mService{std::in_place_index<1>, service},
        mDeathRecipient{new DeathRecipient(notify)} {
    service->linkToDeath(mDeathRecipient);
}

DeathNotifier::DeathNotifier(sp<HBase> const& service, Notify const& notify)
      : mService{std::in_place_index<2>, service},
        mDeathRecipient{new DeathRecipient(notify)} {
    service->linkToDeath(mDeathRecipient, 0);
}

DeathNotifier::DeathNotifier(::ndk::SpAIBinder const& service, Notify const& notify)
      : mService{std::in_place_index<3>, service},
        mDeathRecipient{new DeathRecipient(notify)} {
    mDeathRecipient->initNdk();
    {
        std::lock_guard<std::mutex> guard(sCookiesMutex);
        mDeathRecipient->mCookieKey = sCookieKeyCounter++;
        sCookies[mDeathRecipient->mCookieKey] = mDeathRecipient;
    }
    AIBinder_linkToDeath(
            service.get(),
            mDeathRecipient->getNdkRecipient(),
            reinterpret_cast<void*>(mDeathRecipient->mCookieKey));
}

DeathNotifier::DeathNotifier(DeathNotifier&& other)
      : mService{other.mService}, mDeathRecipient{other.mDeathRecipient} {
    other.mService.emplace<0>();
    other.mDeathRecipient = nullptr;
}

DeathNotifier::~DeathNotifier() {
    switch (mService.index()) {
    case 0:
        break;
    case 1:
        std::get<1>(mService)->unlinkToDeath(mDeathRecipient);
        break;
    case 2:
        std::get<2>(mService)->unlinkToDeath(mDeathRecipient);
        break;
    case 3:

        AIBinder_unlinkToDeath(
                std::get<3>(mService).get(),
                mDeathRecipient->getNdkRecipient(),
                reinterpret_cast<void*>(mDeathRecipient->mCookieKey));
        break;
    default:
        CHECK(false) << "Corrupted service type during destruction.";
    }
}

} // namespace android

