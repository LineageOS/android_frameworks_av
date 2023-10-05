/*
**
** Copyright 2023, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

//#define LOG_NDEBUG 0
#define LOG_TAG "ResourceManagerMetrics"

#include <android/binder_process.h>
#include <mediautils/ProcessInfo.h>
#include "UidObserver.h"

namespace {
const char* kActivityServiceName = "activity";
}; // namespace anonymous

namespace android {

UidObserver::UidObserver(const sp<ProcessInfoInterface>& processInfo,
                         OnProcessTerminated onProcessTerminated) :
     mRegistered(false),
     mOnProcessTerminated(std::move(onProcessTerminated)),
     mProcessInfo(processInfo) {
}

UidObserver::~UidObserver() {
    stop();
}

void UidObserver::start() {
    // Use check service to see if the activity service is available
    // If not available then register for notifications, instead of blocking
    // till the service is ready
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->checkService(String16(kActivityServiceName));
    if (!binder) {
        sm->registerForNotifications(String16(kActivityServiceName), this);
    } else {
        registerWithActivityManager();
    }
}

void UidObserver::stop() {
    std::scoped_lock lock{mLock};

    if (mRegistered) {
        // Unregistered with ActivityManager
        mAm.unregisterUidObserver(this);
        mAm.unlinkToDeath(this);
        mRegistered = false;
    }
}

void UidObserver::add(int pid, uid_t uid) {
    bool needToRegister = false;
    {
        std::scoped_lock lock(mLock);
        std::map<uid_t, std::set<int32_t>>::iterator found = mUids.find(uid);
        if (found != mUids.end()) {
            found->second.insert(pid);
        } else {
            std::set<int32_t> pids{pid};
            mUids.emplace(uid, std::move(pids));
        }
        needToRegister = !mRegistered;
    }
    if (needToRegister) {
        start();
    }
}

void UidObserver::registerWithActivityManager() {
    std::scoped_lock lock{mLock};

    if (mRegistered) {
        return;
    }
    status_t res = mAm.linkToDeath(this);
    // Register for UID gone.
    mAm.registerUidObserver(this, ActivityManager::UID_OBSERVER_GONE,
                            ActivityManager::PROCESS_STATE_UNKNOWN,
                            String16("mediaserver"));
    if (res == OK) {
        mRegistered = true;
        ALOGV("UidObserver: Registered with ActivityManager");
    }
}

void UidObserver::onServiceRegistration(const String16& name, const sp<IBinder>&) {
    if (name != String16(kActivityServiceName)) {
        return;
    }

    registerWithActivityManager();
}

void UidObserver::getTerminatedProcesses(const std::vector<int32_t>& pids,
                                         std::vector<int32_t>& terminatedPids) {
    std::vector<bool> existent;
    terminatedPids.clear();
    if (mProcessInfo->checkProcessExistent(pids, &existent)) {
        for (size_t index = 0; index < existent.size(); index++) {
            if (!existent[index]) {
                // This process has been terminated already.
                terminatedPids.push_back(pids[index]);
            }
        }
    }
}

// This callback will be issued for every UID that is gone/terminated.
// Since one UID could have multiple PIDs, this callback can be issued
// multiple times with that same UID for each activity/pid.
// So, we need to check which one among the PIDs (that share the same UID)
// is gone.
void UidObserver::onUidGone(uid_t uid, bool /*disabled*/) {
    std::vector<int32_t> terminatedPids;
    {
        std::scoped_lock lock{mLock};
        std::map<uid_t, std::set<int32_t>>::iterator found = mUids.find(uid);
        if (found != mUids.end()) {
            if (found->second.size() == 1) {
                terminatedPids.push_back(*(found->second.begin()));
                // Only one PID. So we can remove this UID entry.
                mUids.erase(found);
            } else {
                // There are multiple PIDs with the same UID.
                // Get the list of all terminated PIDs (with the same UID)
                std::vector<int32_t> pids;
                std::copy(found->second.begin(), found->second.end(), std::back_inserter(pids));
                getTerminatedProcesses(pids, terminatedPids);
                for (int32_t pid : terminatedPids) {
                    // Remove all the terminated PIDs
                    found->second.erase(pid);
                }
                // If all PIDs under this UID have terminated, remove this UID entry.
                if (found->second.size() == 0) {
                    mUids.erase(uid);
                }
            }
        }
    }

    for (int32_t pid : terminatedPids) {
        mOnProcessTerminated(pid, uid);
    }
}

void UidObserver::onUidActive(uid_t /*uid*/) {
}

void UidObserver::onUidIdle(uid_t /*uid*/, bool /*disabled*/) {
}

void UidObserver::onUidStateChanged(uid_t /*uid*/,
                                    int32_t /*procState*/,
                                    int64_t /*procStateSeq*/,
                                    int32_t /*capability*/) {
}

void UidObserver::onUidProcAdjChanged(uid_t /*uid*/, int32_t /*adj*/) {
}

void UidObserver::binderDied(const wp<IBinder>& /*who*/) {
    std::scoped_lock lock{mLock};
    ALOGE("UidObserver: ActivityManager has died");
    mRegistered = false;
}

}  // namespace android
