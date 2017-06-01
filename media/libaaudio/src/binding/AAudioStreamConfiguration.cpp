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
#include <aaudio/AAudio.h>

#include <binder/Parcel.h>
#include <binder/Parcelable.h>

#include "binding/AAudioStreamConfiguration.h"

using android::NO_ERROR;
using android::status_t;
using android::Parcel;
using android::Parcelable;

using namespace aaudio;

AAudioStreamConfiguration::AAudioStreamConfiguration() {}
AAudioStreamConfiguration::~AAudioStreamConfiguration() {}

status_t AAudioStreamConfiguration::writeToParcel(Parcel* parcel) const {
    status_t status;
    status = parcel->writeInt32(mDeviceId);
    if (status != NO_ERROR) goto error;
    status = parcel->writeInt32(mSampleRate);
    if (status != NO_ERROR) goto error;
    status = parcel->writeInt32(mSamplesPerFrame);
    if (status != NO_ERROR) goto error;
    status = parcel->writeInt32((int32_t) mSharingMode);
    if (status != NO_ERROR) goto error;
    status = parcel->writeInt32((int32_t) mAudioFormat);
    if (status != NO_ERROR) goto error;
    status = parcel->writeInt32(mBufferCapacity);
    if (status != NO_ERROR) goto error;
    return NO_ERROR;
error:
    ALOGE("AAudioStreamConfiguration.writeToParcel(): write failed = %d", status);
    return status;
}

status_t AAudioStreamConfiguration::readFromParcel(const Parcel* parcel) {
    status_t status = parcel->readInt32(&mDeviceId);
    if (status != NO_ERROR) goto error;
    status = parcel->readInt32(&mSampleRate);
    if (status != NO_ERROR) goto error;
    status = parcel->readInt32(&mSamplesPerFrame);
    if (status != NO_ERROR) goto error;
    status = parcel->readInt32(&mSharingMode);
    if (status != NO_ERROR) goto error;
    status = parcel->readInt32(&mAudioFormat);
    if (status != NO_ERROR) goto error;
    status = parcel->readInt32(&mBufferCapacity);
    if (status != NO_ERROR) goto error;
    return NO_ERROR;
error:
    ALOGE("AAudioStreamConfiguration.readFromParcel(): read failed = %d", status);
    return status;
}

aaudio_result_t AAudioStreamConfiguration::validate() const {
    // Validate results of the open.
    if (mSampleRate < 0 || mSampleRate >= 8 * 48000) { // TODO review limits
        ALOGE("AAudioStreamConfiguration.validate(): invalid sampleRate = %d", mSampleRate);
        return AAUDIO_ERROR_INTERNAL;
    }

    if (mSamplesPerFrame < 1 || mSamplesPerFrame >= 32) { // TODO review limits
        ALOGE("AAudioStreamConfiguration.validate() invalid samplesPerFrame = %d", mSamplesPerFrame);
        return AAUDIO_ERROR_INTERNAL;
    }

    switch (mAudioFormat) {
    case AAUDIO_FORMAT_PCM_I16:
    case AAUDIO_FORMAT_PCM_FLOAT:
        break;
    default:
        ALOGE("AAudioStreamConfiguration.validate() invalid audioFormat = %d", mAudioFormat);
        return AAUDIO_ERROR_INTERNAL;
    }

    if (mBufferCapacity < 0) {
        ALOGE("AAudioStreamConfiguration.validate() invalid mBufferCapacity = %d", mBufferCapacity);
        return AAUDIO_ERROR_INTERNAL;
    }
    return AAUDIO_OK;
}

void AAudioStreamConfiguration::dump() const {
    ALOGD("AAudioStreamConfiguration mDeviceId        = %d", mDeviceId);
    ALOGD("AAudioStreamConfiguration mSampleRate      = %d", mSampleRate);
    ALOGD("AAudioStreamConfiguration mSamplesPerFrame = %d", mSamplesPerFrame);
    ALOGD("AAudioStreamConfiguration mSharingMode     = %d", (int)mSharingMode);
    ALOGD("AAudioStreamConfiguration mAudioFormat     = %d", (int)mAudioFormat);
    ALOGD("AAudioStreamConfiguration mBufferCapacity  = %d", mBufferCapacity);
}
