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

#ifndef BINDING_OBOE_STREAM_CONFIGURATION_H
#define BINDING_OBOE_STREAM_CONFIGURATION_H

#include <stdint.h>

#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <oboe/OboeDefinitions.h>

using android::status_t;
using android::Parcel;
using android::Parcelable;

namespace oboe {

class OboeStreamConfiguration : public Parcelable {
public:
    OboeStreamConfiguration();
    virtual ~OboeStreamConfiguration();

    oboe_device_id_t getDeviceId() const {
        return mDeviceId;
    }

    void setDeviceId(oboe_device_id_t deviceId) {
        mDeviceId = deviceId;
    }

    oboe_sample_rate_t getSampleRate() const {
        return mSampleRate;
    }

    void setSampleRate(oboe_sample_rate_t sampleRate) {
        mSampleRate = sampleRate;
    }

    int32_t getSamplesPerFrame() const {
        return mSamplesPerFrame;
    }

    void setSamplesPerFrame(int32_t samplesPerFrame) {
        mSamplesPerFrame = samplesPerFrame;
    }

    oboe_audio_format_t getAudioFormat() const {
        return mAudioFormat;
    }

    void setAudioFormat(oboe_audio_format_t audioFormat) {
        mAudioFormat = audioFormat;
    }

    virtual status_t writeToParcel(Parcel* parcel) const override;

    virtual status_t readFromParcel(const Parcel* parcel) override;

    oboe_result_t validate();

    void dump();

protected:
    oboe_device_id_t    mDeviceId        = OBOE_DEVICE_UNSPECIFIED;
    oboe_sample_rate_t  mSampleRate      = OBOE_UNSPECIFIED;
    int32_t             mSamplesPerFrame = OBOE_UNSPECIFIED;
    oboe_audio_format_t mAudioFormat     = OBOE_AUDIO_FORMAT_UNSPECIFIED;
};

} /* namespace oboe */

#endif //BINDING_OBOE_STREAM_CONFIGURATION_H
