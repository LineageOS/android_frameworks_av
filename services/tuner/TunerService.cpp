/**
 * Copyright (c) 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "TunerService"

#include <android/binder_manager.h>
#include <utils/Log.h>
#include "TunerService.h"

using ::android::hardware::hidl_vec;
using ::android::hardware::tv::tuner::V1_0::FrontendId;
using ::android::hardware::tv::tuner::V1_0::Result;

namespace android {

sp<ITuner> TunerService::mTuner;

TunerService::TunerService() {}
TunerService::~TunerService() {}

void TunerService::instantiate() {
    std::shared_ptr<TunerService> service =
            ::ndk::SharedRefBase::make<TunerService>();
    AServiceManager_addService(service->asBinder().get(), getServiceName());
}

Status TunerService::getFrontendIds(std::vector<int32_t>* ids, int32_t* /* _aidl_return */) {
    if (mTuner == nullptr) {
        // TODO: create a method for init.
        mTuner = ITuner::getService();
        if (mTuner == nullptr) {
            ALOGE("Failed to get ITuner service.");
            return ::ndk::ScopedAStatus::fromServiceSpecificError(
                    static_cast<int32_t>(Result::UNAVAILABLE));
        }
    }
    hidl_vec<FrontendId> feIds;
    Result res;
    mTuner->getFrontendIds([&](Result r, const hidl_vec<FrontendId>& frontendIds) {
        feIds = frontendIds;
        res = r;
    });
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    ids->resize(feIds.size());
    std::copy(feIds.begin(), feIds.end(), ids->begin());

    return ::ndk::ScopedAStatus::ok();
}

} // namespace android
