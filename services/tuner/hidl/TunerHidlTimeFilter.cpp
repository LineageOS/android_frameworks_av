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

#define LOG_TAG "TunerHidlTimeFilter"

#include "TunerHidlTimeFilter.h"

#include <aidl/android/hardware/tv/tuner/Constant64Bit.h>
#include <aidl/android/hardware/tv/tuner/Result.h>

using ::aidl::android::hardware::tv::tuner::Constant64Bit;
using ::aidl::android::hardware::tv::tuner::Result;

using HidlResult = ::android::hardware::tv::tuner::V1_0::Result;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerHidlTimeFilter::TunerHidlTimeFilter(sp<HidlITimeFilter> timeFilter) {
    mTimeFilter = timeFilter;
}

TunerHidlTimeFilter::~TunerHidlTimeFilter() {
    mTimeFilter = nullptr;
}

::ndk::ScopedAStatus TunerHidlTimeFilter::setTimeStamp(int64_t timeStamp) {
    HidlResult status = mTimeFilter->setTimeStamp(static_cast<uint64_t>(timeStamp));
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlTimeFilter::clearTimeStamp() {
    HidlResult status = mTimeFilter->clearTimeStamp();
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlTimeFilter::getSourceTime(int64_t* _aidl_return) {
    HidlResult status;
    mTimeFilter->getSourceTime([&](HidlResult r, uint64_t t) {
        status = r;
        *_aidl_return = static_cast<int64_t>(t);
    });
    if (status != HidlResult::SUCCESS) {
        *_aidl_return = static_cast<int64_t>(Constant64Bit::INVALID_PRESENTATION_TIME_STAMP);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlTimeFilter::getTimeStamp(int64_t* _aidl_return) {
    HidlResult status;
    mTimeFilter->getTimeStamp([&](HidlResult r, uint64_t t) {
        status = r;
        *_aidl_return = static_cast<int64_t>(t);
    });
    if (status != HidlResult::SUCCESS) {
        *_aidl_return = static_cast<int64_t>(Constant64Bit::INVALID_PRESENTATION_TIME_STAMP);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlTimeFilter::close() {
    HidlResult res = mTimeFilter->close();
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
