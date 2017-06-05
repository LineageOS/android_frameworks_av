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

#ifndef ANDROID_BINDING_AAUDIO_STREAM_CONFIGURATION_H
#define ANDROID_BINDING_AAUDIO_STREAM_CONFIGURATION_H

#include <stdint.h>

#include <aaudio/AAudio.h>
#include <binder/Parcel.h>
#include <binder/Parcelable.h>

using android::status_t;
using android::Parcel;
using android::Parcelable;

namespace aaudio {

class AAudioStreamConfiguration : public Parcelable {
public:
    AAudioStreamConfiguration();
    virtual ~AAudioStreamConfiguration();

    int32_t getDeviceId() const {
        return mDeviceId;
    }

    void setDeviceId(int32_t deviceId) {
        mDeviceId = deviceId;
    }

    int32_t getSampleRate() const {
        return mSampleRate;
    }

    void setSampleRate(int32_t sampleRate) {
        mSampleRate = sampleRate;
    }

    int32_t getSamplesPerFrame() const {
        return mSamplesPerFrame;
    }

    void setSamplesPerFrame(int32_t samplesPerFrame) {
        mSamplesPerFrame = samplesPerFrame;
    }

    aaudio_format_t getAudioFormat() const {
        return mAudioFormat;
    }

    void setAudioFormat(aaudio_format_t audioFormat) {
        mAudioFormat = audioFormat;
    }

    aaudio_sharing_mode_t getSharingMode() const {
        return mSharingMode;
    }

    void setSharingMode(aaudio_sharing_mode_t sharingMode) {
        mSharingMode = sharingMode;
    }

    int32_t getBufferCapacity() const {
        return mBufferCapacity;
    }

    void setBufferCapacity(int32_t frames) {
        mBufferCapacity = frames;
    }

    virtual status_t writeToParcel(Parcel* parcel) const override;

    virtual status_t readFromParcel(const Parcel* parcel) override;

    aaudio_result_t validate() const;

    void dump() const;

private:
    int32_t               mDeviceId        = AAUDIO_UNSPECIFIED;
    int32_t               mSampleRate      = AAUDIO_UNSPECIFIED;
    int32_t               mSamplesPerFrame = AAUDIO_UNSPECIFIED;
    aaudio_sharing_mode_t mSharingMode     = AAUDIO_SHARING_MODE_SHARED;
    aaudio_format_t       mAudioFormat     = AAUDIO_FORMAT_UNSPECIFIED;
    int32_t               mBufferCapacity  = AAUDIO_UNSPECIFIED;
};

} /* namespace aaudio */

#endif //ANDROID_BINDING_AAUDIO_STREAM_CONFIGURATION_H
