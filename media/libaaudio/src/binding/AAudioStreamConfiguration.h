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

#ifndef BINDING_AAUDIO_STREAM_CONFIGURATION_H
#define BINDING_AAUDIO_STREAM_CONFIGURATION_H

#include <stdint.h>

#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <aaudio/AAudioDefinitions.h>

using android::status_t;
using android::Parcel;
using android::Parcelable;

namespace aaudio {

class AAudioStreamConfiguration : public Parcelable {
public:
    AAudioStreamConfiguration();
    virtual ~AAudioStreamConfiguration();

    aaudio_device_id_t getDeviceId() const {
        return mDeviceId;
    }

    void setDeviceId(aaudio_device_id_t deviceId) {
        mDeviceId = deviceId;
    }

    aaudio_sample_rate_t getSampleRate() const {
        return mSampleRate;
    }

    void setSampleRate(aaudio_sample_rate_t sampleRate) {
        mSampleRate = sampleRate;
    }

    int32_t getSamplesPerFrame() const {
        return mSamplesPerFrame;
    }

    void setSamplesPerFrame(int32_t samplesPerFrame) {
        mSamplesPerFrame = samplesPerFrame;
    }

    aaudio_audio_format_t getAudioFormat() const {
        return mAudioFormat;
    }

    void setAudioFormat(aaudio_audio_format_t audioFormat) {
        mAudioFormat = audioFormat;
    }

    aaudio_size_frames_t getBufferCapacity() const {
        return mBufferCapacity;
    }

    void setBufferCapacity(aaudio_size_frames_t frames) {
        mBufferCapacity = frames;
    }

    virtual status_t writeToParcel(Parcel* parcel) const override;

    virtual status_t readFromParcel(const Parcel* parcel) override;

    aaudio_result_t validate();

    void dump();

protected:
    aaudio_device_id_t    mDeviceId        = AAUDIO_DEVICE_UNSPECIFIED;
    aaudio_sample_rate_t  mSampleRate      = AAUDIO_UNSPECIFIED;
    int32_t               mSamplesPerFrame = AAUDIO_UNSPECIFIED;
    aaudio_audio_format_t mAudioFormat     = AAUDIO_FORMAT_UNSPECIFIED;
    aaudio_size_frames_t  mBufferCapacity  = AAUDIO_UNSPECIFIED;
};

} /* namespace aaudio */

#endif //BINDING_AAUDIO_STREAM_CONFIGURATION_H
