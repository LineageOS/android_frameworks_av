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

#ifndef ANDROID_MEDIA_TRANSCODING_THERMAL_POLICY_H
#define ANDROID_MEDIA_TRANSCODING_THERMAL_POLICY_H

#include <android/thermal.h>
#include <media/ThermalPolicyInterface.h>
#include <utils/Condition.h>

#include <mutex>

namespace android {

class TranscodingThermalPolicy : public ThermalPolicyInterface {
public:
    explicit TranscodingThermalPolicy();
    ~TranscodingThermalPolicy();

    void setCallback(const std::shared_ptr<ThermalPolicyCallbackInterface>& cb) override;
    bool getThrottlingStatus() override;

private:
    mutable std::mutex mRegisteredLock;
    bool mRegistered GUARDED_BY(mRegisteredLock);

    mutable std::mutex mCallbackLock;
    std::weak_ptr<ThermalPolicyCallbackInterface> mThermalPolicyCallback GUARDED_BY(mCallbackLock);

    AThermalManager* mThermalManager;
    bool mIsThrottling;

    static void onStatusChange(void* data, AThermalStatus status);
    void onStatusChange(AThermalStatus status);
    void registerSelf();
    void unregisterSelf();
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRANSCODING_THERMAL_POLICY_H
