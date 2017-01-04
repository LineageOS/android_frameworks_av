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

#include <oboe/OboeDefinitions.h>

#include "binding/OboeStreamConfiguration.h"

using android::NO_ERROR;
using android::status_t;
using android::Parcel;
using android::Parcelable;

using namespace oboe;

OboeStreamConfiguration::OboeStreamConfiguration() {}
OboeStreamConfiguration::~OboeStreamConfiguration() {}

status_t OboeStreamConfiguration::writeToParcel(Parcel* parcel) const {
    parcel->writeInt32(mDeviceId);
    parcel->writeInt32(mSampleRate);
    parcel->writeInt32(mSamplesPerFrame);
    parcel->writeInt32((int32_t) mAudioFormat);
    return NO_ERROR; // TODO check for errors above
}

status_t OboeStreamConfiguration::readFromParcel(const Parcel* parcel) {
    int32_t temp;
    parcel->readInt32(&mDeviceId);
    parcel->readInt32(&mSampleRate);
    parcel->readInt32(&mSamplesPerFrame);
    parcel->readInt32(&temp);
    mAudioFormat = (oboe_audio_format_t) temp;
    return NO_ERROR; // TODO check for errors above
}

oboe_result_t OboeStreamConfiguration::validate() {
    // Validate results of the open.
    if (mSampleRate < 0 || mSampleRate >= 8 * 48000) { // TODO review limits
        ALOGE("OboeStreamConfiguration.validate(): invalid sampleRate = %d", mSampleRate);
        return OBOE_ERROR_INTERNAL;
    }

    if (mSamplesPerFrame < 1 || mSamplesPerFrame >= 32) { // TODO review limits
        ALOGE("OboeStreamConfiguration.validate() invalid samplesPerFrame = %d", mSamplesPerFrame);
        return OBOE_ERROR_INTERNAL;
    }

    switch (mAudioFormat) {
    case OBOE_AUDIO_FORMAT_PCM16:
    case OBOE_AUDIO_FORMAT_PCM_FLOAT:
    case OBOE_AUDIO_FORMAT_PCM824:
    case OBOE_AUDIO_FORMAT_PCM32:
        break;
    default:
        ALOGE("OboeStreamConfiguration.validate() invalid audioFormat = %d", mAudioFormat);
        return OBOE_ERROR_INTERNAL;
    }
    return OBOE_OK;
}

void OboeStreamConfiguration::dump() {
    ALOGD("OboeStreamConfiguration mSampleRate = %d -----", mSampleRate);
    ALOGD("OboeStreamConfiguration mSamplesPerFrame = %d", mSamplesPerFrame);
    ALOGD("OboeStreamConfiguration mAudioFormat = %d", (int)mAudioFormat);
}
