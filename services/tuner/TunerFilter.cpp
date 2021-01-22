/**
 * Copyright 2021, The Android Open Source Project
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

#define LOG_TAG "TunerFilter"

#include "TunerFilter.h"

using ::android::hardware::tv::tuner::V1_0::Result;

namespace android {

TunerFilter::TunerFilter(sp<IFilter> filter, sp<IFilterCallback> callback) {
    mFilter = filter;
    mFilterCallback = callback;
}

TunerFilter::~TunerFilter() {
    mFilter = nullptr;
    mFilterCallback = nullptr;
}

Status TunerFilter::getId(int32_t* _aidl_return) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res;
    mFilter->getId([&](Result r, uint32_t filterId) {
        res = r;
        mId = filterId;
    });
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    *_aidl_return = mId;
    return Status::ok();
}

/////////////// FilterCallback ///////////////////////

Return<void> TunerFilter::FilterCallback::onFilterStatus(DemuxFilterStatus status) {
    mTunerFilterCallback->onFilterStatus((int)status);
    return Void();
}

Return<void> TunerFilter::FilterCallback::onFilterEvent(const DemuxFilterEvent&) {
    return Void();
}

}  // namespace android
