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

#ifndef ANDROID_MEDIA_UID_POLICY_INTERFACE_H
#define ANDROID_MEDIA_UID_POLICY_INTERFACE_H

#include <unordered_set>

namespace android {

class UidPolicyCallbackInterface;

// Interface for the controller to query a uid's info.
class UidPolicyInterface {
public:
    // Instruct the uid policy to start monitoring a uid.
    virtual void registerMonitorUid(uid_t uid) = 0;
    // Instruct the uid policy to stop monitoring a uid.
    virtual void unregisterMonitorUid(uid_t uid) = 0;
    // Whether a uid is among the set of uids that's currently top priority.
    virtual bool isUidOnTop(uid_t uid) = 0;
    // Retrieves the set of uids that's currently top priority.
    virtual std::unordered_set<uid_t> getTopUids() const = 0;
    // Set the associated callback interface to send the events when uid states change.
    virtual void setCallback(const std::shared_ptr<UidPolicyCallbackInterface>& cb) = 0;

protected:
    virtual ~UidPolicyInterface() = default;
};

// Interface for notifying the controller of a change in uid states.
class UidPolicyCallbackInterface {
public:
    // Called when the set of uids that's top priority among the uids of interest
    // has changed. The receiver of this callback should adjust accordingly.
    virtual void onTopUidsChanged(const std::unordered_set<uid_t>& uids) = 0;

    // Called when a uid is gone.
    virtual void onUidGone(uid_t goneUid) = 0;

protected:
    virtual ~UidPolicyCallbackInterface() = default;
};

}  // namespace android
#endif  // ANDROID_MEDIA_UID_POLICY_INTERFACE_H
