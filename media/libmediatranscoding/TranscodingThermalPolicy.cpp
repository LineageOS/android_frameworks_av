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

//#define LOG_NDEBUG 0
#define LOG_TAG "TranscodingThermalPolicy"

#include <media/TranscodingDefs.h>
#include <media/TranscodingThermalPolicy.h>
#include <media/TranscodingUidPolicy.h>
#include <utils/Log.h>

namespace android {

static bool needThrottling(AThermalStatus status) {
    return (status >= ATHERMAL_STATUS_SEVERE);
}

//static
void TranscodingThermalPolicy::onStatusChange(void* data, AThermalStatus status) {
    TranscodingThermalPolicy* policy = static_cast<TranscodingThermalPolicy*>(data);
    policy->onStatusChange(status);
}

TranscodingThermalPolicy::TranscodingThermalPolicy()
      : mRegistered(false), mThermalManager(nullptr), mIsThrottling(false) {
    registerSelf();
}

TranscodingThermalPolicy::~TranscodingThermalPolicy() {
    unregisterSelf();
}

void TranscodingThermalPolicy::registerSelf() {
    ALOGI("TranscodingThermalPolicy: registerSelf");

    std::scoped_lock lock{mRegisteredLock};

    if (mRegistered) {
        return;
    }

    if (__builtin_available(android __TRANSCODING_MIN_API__, *)) {
        AThermalManager* thermalManager = AThermal_acquireManager();
        if (thermalManager == nullptr) {
            ALOGE("Failed to acquire thermal manager");
            return;
        }

        int ret = AThermal_registerThermalStatusListener(thermalManager, onStatusChange, this);
        if (ret != 0) {
            ALOGE("Failed to register thermal status listener");
            AThermal_releaseManager(thermalManager);
            return;
        }

        mIsThrottling = needThrottling(AThermal_getCurrentThermalStatus(thermalManager));
        mThermalManager = thermalManager;
    }

    mRegistered = true;
}

void TranscodingThermalPolicy::unregisterSelf() {
    ALOGI("TranscodingThermalPolicy: unregisterSelf");

    std::scoped_lock lock{mRegisteredLock};

    if (!mRegistered) {
        return;
    }

    if (__builtin_available(android __TRANSCODING_MIN_API__, *)) {
        if (mThermalManager != nullptr) {
            // Unregister listener
            int ret =
                    AThermal_unregisterThermalStatusListener(mThermalManager, onStatusChange, this);
            if (ret != 0) {
                ALOGW("Failed to unregister thermal status listener");
            }
            AThermal_releaseManager(mThermalManager);
            mThermalManager = nullptr;
        }
    }

    mRegistered = false;
}

void TranscodingThermalPolicy::setCallback(
        const std::shared_ptr<ThermalPolicyCallbackInterface>& cb) {
    std::scoped_lock lock{mCallbackLock};
    mThermalPolicyCallback = cb;
}

bool TranscodingThermalPolicy::getThrottlingStatus() {
    std::scoped_lock lock{mRegisteredLock};
    return mIsThrottling;
}

void TranscodingThermalPolicy::onStatusChange(AThermalStatus status) {
    bool isThrottling = needThrottling(status);

    {
        std::scoped_lock lock{mRegisteredLock};
        if (isThrottling == mIsThrottling) {
            return;
        }
        ALOGI("Transcoding thermal throttling changed: %d", isThrottling);
        mIsThrottling = isThrottling;
    }

    std::scoped_lock lock{mCallbackLock};
    std::shared_ptr<ThermalPolicyCallbackInterface> cb;
    if ((cb = mThermalPolicyCallback.lock()) != nullptr) {
        if (isThrottling) {
            cb->onThrottlingStarted();
        } else {
            cb->onThrottlingStopped();
        }
    }
}
}  // namespace android
