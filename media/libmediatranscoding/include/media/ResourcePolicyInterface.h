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

#ifndef ANDROID_MEDIA_RESOURCE_POLICY_INTERFACE_H
#define ANDROID_MEDIA_RESOURCE_POLICY_INTERFACE_H
#include <memory>
namespace android {

class ResourcePolicyCallbackInterface;

// Interface for the SessionController to control the resource status updates.
class ResourcePolicyInterface {
public:
    // Set the associated callback interface to send the events when resource
    // status changes. (Set to nullptr will stop the updates.)
    virtual void setCallback(const std::shared_ptr<ResourcePolicyCallbackInterface>& cb) = 0;
    virtual void setPidResourceLost(pid_t pid) = 0;

protected:
    virtual ~ResourcePolicyInterface() = default;
};

// Interface for notifying the SessionController of a change in resource status.
class ResourcePolicyCallbackInterface {
public:
    // Called when codec resources become available. The controller may use this
    // as a signal to attempt restart transcoding sessions that were previously
    // paused due to temporary resource loss.
    virtual void onResourceAvailable() = 0;

protected:
    virtual ~ResourcePolicyCallbackInterface() = default;
};

}  // namespace android
#endif  // ANDROID_MEDIA_RESOURCE_POLICY_INTERFACE_H
