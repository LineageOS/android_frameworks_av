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

#define LOG_TAG "TunerTimeFilter"

#include "TunerTimeFilter.h"

using ::android::hardware::tv::tuner::V1_0::Result;
using ::android::hardware::tv::tuner::V1_1::Constant64Bit;

namespace android {

TunerTimeFilter::TunerTimeFilter(sp<ITimeFilter> timeFilter) {
    mTimeFilter = timeFilter;
}

TunerTimeFilter::~TunerTimeFilter() {
    mTimeFilter = NULL;
}

Status TunerTimeFilter::setTimeStamp(int64_t timeStamp) {
    if (mTimeFilter == NULL) {
        ALOGE("ITimeFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status = mTimeFilter->setTimeStamp(timeStamp);
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return Status::ok();
}

Status TunerTimeFilter::clearTimeStamp() {
    if (mTimeFilter == NULL) {
        ALOGE("ITimeFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status = mTimeFilter->clearTimeStamp();
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return Status::ok();
}

Status TunerTimeFilter::getSourceTime(int64_t* _aidl_return) {
    if (mTimeFilter == NULL) {
        *_aidl_return = (int64_t)Constant64Bit::INVALID_PRESENTATION_TIME_STAMP;
        ALOGE("ITimeFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status;
    mTimeFilter->getSourceTime(
            [&](Result r, uint64_t t) {
                status = r;
                *_aidl_return = t;
            });
    if (status != Result::SUCCESS) {
        *_aidl_return = (int64_t)Constant64Bit::INVALID_PRESENTATION_TIME_STAMP;
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return Status::ok();
}

Status TunerTimeFilter::getTimeStamp(int64_t* _aidl_return) {
    if (mTimeFilter == NULL) {
        *_aidl_return = (int64_t)Constant64Bit::INVALID_PRESENTATION_TIME_STAMP;
        ALOGE("ITimeFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status;
    mTimeFilter->getTimeStamp(
            [&](Result r, uint64_t t) {
                status = r;
                *_aidl_return = t;
            });
    if (status != Result::SUCCESS) {
        *_aidl_return = (int64_t)Constant64Bit::INVALID_PRESENTATION_TIME_STAMP;
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return Status::ok();
}

Status TunerTimeFilter::close() {
    if (mTimeFilter == NULL) {
        ALOGE("ITimeFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mTimeFilter->close();
    mTimeFilter = NULL;

    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}
}  // namespace android
