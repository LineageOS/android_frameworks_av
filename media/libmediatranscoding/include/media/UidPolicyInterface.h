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

namespace android {

// Interface for the scheduler to query a uid's info.
class UidPolicyInterface {
public:
    // Determines if a uid is currently running as top.
    // TODO(chz): this should probably be replaced by a query that determines
    // which uid has the highest priority among a given set of uids.
    virtual bool isUidOnTop(uid_t uid) = 0;

protected:
    virtual ~UidPolicyInterface() = default;
};

// Interface for notifying the scheduler of a change in a uid's state or
// transcoding resource availability.
class UidPolicyCallbackInterface {
public:
    // Called when a uid is brought to top.
    // TODO(chz): this should probably be replace by a callback when the uid
    // that was previously identified being the highest priority as in
    // UidPolicyInterface::isUidOnTop() has changed in priority.
    virtual void onTopUidChanged(uid_t uid) = 0;

    // Called when resources become available for transcoding use. The scheduler
    // may use this as a signal to attempt restart transcoding activity that
    // were previously paused due to temporary resource loss.
    virtual void onResourceAvailable() = 0;

protected:
    virtual ~UidPolicyCallbackInterface() = default;
};

}  // namespace android
#endif  // ANDROID_MEDIA_UID_POLICY_INTERFACE_H
