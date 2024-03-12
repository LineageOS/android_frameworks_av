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

#include <aidl/android/hardware/tv/tuner/Constant64Bit.h>
#include <aidl/android/hardware/tv/tuner/Result.h>

using ::aidl::android::hardware::tv::tuner::Constant64Bit;
using ::aidl::android::hardware::tv::tuner::Result;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerTimeFilter::TunerTimeFilter(shared_ptr<ITimeFilter> timeFilter) {
    mTimeFilter = timeFilter;
}

TunerTimeFilter::~TunerTimeFilter() {
    if (!isClosed) {
        close();
    }
    mTimeFilter = nullptr;
}

::ndk::ScopedAStatus TunerTimeFilter::setTimeStamp(int64_t timeStamp) {
    return mTimeFilter->setTimeStamp(timeStamp);
}

::ndk::ScopedAStatus TunerTimeFilter::clearTimeStamp() {
    return mTimeFilter->clearTimeStamp();
}

::ndk::ScopedAStatus TunerTimeFilter::getSourceTime(int64_t* _aidl_return) {
    auto status = mTimeFilter->getSourceTime(_aidl_return);
    if (!status.isOk()) {
        *_aidl_return = (int64_t)Constant64Bit::INVALID_PRESENTATION_TIME_STAMP;
    }
    return status;
}

::ndk::ScopedAStatus TunerTimeFilter::getTimeStamp(int64_t* _aidl_return) {
    auto status = mTimeFilter->getTimeStamp(_aidl_return);
    if (!status.isOk()) {
        *_aidl_return = (int64_t)Constant64Bit::INVALID_PRESENTATION_TIME_STAMP;
    }
    return status;
}

::ndk::ScopedAStatus TunerTimeFilter::close() {
    isClosed = true;
    return mTimeFilter->close();
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
