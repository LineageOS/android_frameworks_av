/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef ANDROID_MEDIA_THERMAL_POLICY_INTERFACE_H
#define ANDROID_MEDIA_THERMAL_POLICY_INTERFACE_H
#include <memory>

namespace android {

class ThermalPolicyCallbackInterface;

// Interface for the SessionController to control the thermal policy.
class ThermalPolicyInterface {
public:
    // Set the associated callback interface to send the events when the thermal
    // status changes.
    virtual void setCallback(const std::shared_ptr<ThermalPolicyCallbackInterface>& cb) = 0;

    // Get the current thermal throttling status. Returns true if throttling is on,
    // false otherwise.
    virtual bool getThrottlingStatus() = 0;

protected:
    virtual ~ThermalPolicyInterface() = default;
};

// Interface for notifying the SessionController of thermal throttling status.
class ThermalPolicyCallbackInterface {
public:
    // Called when the session controller should start or stop thermal throttling.
    virtual void onThrottlingStarted() = 0;
    virtual void onThrottlingStopped() = 0;

protected:
    virtual ~ThermalPolicyCallbackInterface() = default;
};

}  // namespace android
#endif  // ANDROID_MEDIA_THERMAL_POLICY_INTERFACE_H
