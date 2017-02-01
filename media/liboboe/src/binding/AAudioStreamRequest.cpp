/*
 * Copyright 2016 The Android Open Source Project
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

#include <stdint.h>

#include <sys/mman.h>
#include <binder/Parcel.h>
#include <binder/Parcelable.h>

#include <aaudio/AAudioDefinitions.h>

#include "binding/AAudioStreamConfiguration.h"
#include "binding/AAudioStreamRequest.h"

using android::NO_ERROR;
using android::status_t;
using android::Parcel;
using android::Parcelable;

using namespace aaudio;

AAudioStreamRequest::AAudioStreamRequest()
    : mConfiguration()
    {}

AAudioStreamRequest::~AAudioStreamRequest() {}

status_t AAudioStreamRequest::writeToParcel(Parcel* parcel) const {
    parcel->writeInt32((int32_t) mUserId);
    parcel->writeInt32((int32_t) mProcessId);
    mConfiguration.writeToParcel(parcel);
    return NO_ERROR; // TODO check for errors above
}

status_t AAudioStreamRequest::readFromParcel(const Parcel* parcel) {
    int32_t temp;
    parcel->readInt32(&temp);
    mUserId = (uid_t) temp;
    parcel->readInt32(&temp);
    mProcessId = (pid_t) temp;
    mConfiguration.readFromParcel(parcel);
    return NO_ERROR; // TODO check for errors above
}

aaudio_result_t AAudioStreamRequest::validate() {
    return mConfiguration.validate();
}

void AAudioStreamRequest::dump() {
    ALOGD("AAudioStreamRequest mUserId = %d -----", mUserId);
    ALOGD("AAudioStreamRequest mProcessId = %d", mProcessId);
    mConfiguration.dump();
}
