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

#ifndef ANDROID_MEDIA_UIDOBSERVER_H_
#define ANDROID_MEDIA_UIDOBSERVER_H_

#include <map>
#include <set>
#include <mutex>
#include <functional>
#include <binder/ActivityManager.h>
#include <binder/IUidObserver.h>
#include <binder/BinderService.h>

namespace android {

using OnProcessTerminated = std::function<void(int32_t pid, uid_t)>;

struct ProcessInfoInterface;

//
// UidObserver class
//
// This class implements a callback mechanism to notify the termination of the
// process/applications that are registered with this class.
//
// It uses ActivityManager get notification on when an UID is not existent
// anymore.
// Since one UID could have multiple PIDs, it uses ActivityManager
// (through ProcessInfoInterface) to query for the process/application
// state for the pids.
//
class UidObserver :
        public BnUidObserver,
        public virtual IBinder::DeathRecipient,
        public virtual IServiceManager::LocalRegistrationCallback {
public:
    explicit UidObserver(const sp<ProcessInfoInterface>& processInfo,
                         OnProcessTerminated onProcessTerminated);
    virtual ~UidObserver();

    // Start registration (with Application Manager)
    void start();
    // Stop registration (with Application Manager)
    void stop();

    // Add this pid/uid to set of Uid to be observed.
    void add(int pid, uid_t uid);

private:
    UidObserver() = delete;
    UidObserver(const UidObserver&) = delete;
    UidObserver(UidObserver&&) = delete;
    UidObserver& operator=(const UidObserver&) = delete;
    UidObserver& operator=(UidObserver&&) = delete;

    // IUidObserver implementation.
    void onUidGone(uid_t uid, bool disabled) override;
    void onUidActive(uid_t uid) override;
    void onUidIdle(uid_t uid, bool disabled) override;
    void onUidStateChanged(uid_t uid, int32_t procState, int64_t procStateSeq,
            int32_t capability) override;
    void onUidProcAdjChanged(uid_t uid, int32_t adj) override;

    // IServiceManager::LocalRegistrationCallback implementation.
    void onServiceRegistration(const String16& name,
                    const sp<IBinder>& binder) override;

    // IBinder::DeathRecipient implementation.
    void binderDied(const wp<IBinder> &who) override;

    // Registers with Application Manager for UID gone event
    // to track the termination of Applications.
    void registerWithActivityManager();

    /*
     * For a list of input pids, it will check whether the corresponding
     * processes are already terminated or not.
     *
     * @param[in] pids List of pids to check whether they are terminated.
     * @param[out] terminatedPids List of pid of terminated processes.
     *
     * Upon return, terminatedPids returns list of all the termibated pids
     * that will be a subset of input pids (in that order).
     * If none of the input pids have terminated, terminatedPids will be empty.
     */
    void getTerminatedProcesses(const std::vector<int32_t>& pids,
                                std::vector<int32_t>& terminatedPids);

    bool mRegistered = false;
    std::mutex mLock;
    ActivityManager mAm;
    // map of UID and all the PIDs associated with it
    // as one UID could have multiple PIDs.
    std::map<uid_t, std::set<int32_t>> mUids;
    OnProcessTerminated mOnProcessTerminated;
    sp<ProcessInfoInterface> mProcessInfo;
};

}  // namespace android

#endif  //ANDROID_MEDIA_UIDOBSERVER_H_
