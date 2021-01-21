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

namespace android {

TunerTimeFilter::TunerTimeFilter(sp<ITimeFilter> timeFilter) {
    mTimeFilter = timeFilter;
}

TunerTimeFilter::~TunerTimeFilter() {
    mTimeFilter = NULL;
}

Status TunerTimeFilter::setTimeStamp(int64_t /*timeStamp*/) {
    return Status::ok();
}

Status TunerTimeFilter::clearTimeStamp() {
    return Status::ok();
}

Status TunerTimeFilter::getSourceTime(int64_t* /*_aidl_return*/) {
    return Status::ok();
}

Status TunerTimeFilter::getTimeStamp(int64_t* /*_aidl_return*/) {
    return Status::ok();
}

Status TunerTimeFilter::close() {
    return Status::ok();
}
}  // namespace android
