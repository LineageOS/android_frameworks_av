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

#define LOG_TAG "AAudioStreamRequest"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>

#include <sys/mman.h>

#include <aaudio/AAudio.h>

#include "binding/AAudioStreamConfiguration.h"
#include "binding/AAudioStreamRequest.h"

using namespace aaudio;

AAudioStreamRequest::AAudioStreamRequest(const StreamRequest& parcelable) :
        mConfiguration(std::move(parcelable.params)),
        mUserId(parcelable.userId),
        mProcessId(parcelable.processId),
        mSharingModeMatchRequired(parcelable.sharingModeMatchRequired),
        mInService(parcelable.inService) {
    static_assert(sizeof(mUserId) == sizeof(parcelable.userId));
    static_assert(sizeof(mProcessId) == sizeof(parcelable.processId));
}

StreamRequest AAudioStreamRequest::parcelable() const {
    StreamRequest result;
    result.params = std::move(mConfiguration).parcelable();
    result.userId = mUserId;
    result.processId = mProcessId;
    result.sharingModeMatchRequired = mSharingModeMatchRequired;
    result.inService = mInService;
    return result;
}

aaudio_result_t AAudioStreamRequest::validate() const {
    return mConfiguration.validate();
}

void AAudioStreamRequest::dump() const {
    ALOGD("mUserId    = %d", mUserId);
    ALOGD("mProcessId = %d", mProcessId);
    ALOGD("mSharingModeMatchRequired = %d", mSharingModeMatchRequired);
    ALOGD("mInService = %d", mInService);
    mConfiguration.dump();
}
