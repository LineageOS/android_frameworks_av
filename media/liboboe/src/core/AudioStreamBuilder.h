/*
 * Copyright 2015 The Android Open Source Project
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

#ifndef AAUDIO_AUDIOSTREAMBUILDER_H
#define AAUDIO_AUDIOSTREAMBUILDER_H

#include <stdint.h>

#include <aaudio/AAudioDefinitions.h>
#include <aaudio/AAudio.h>

#include "AudioStream.h"

namespace aaudio {

/**
 * Factory class for an AudioStream.
 */
class AudioStreamBuilder {
public:
    AudioStreamBuilder();

    ~AudioStreamBuilder();

    int getSamplesPerFrame() const {
        return mSamplesPerFrame;
    }

    /**
     * This is also known as channelCount.
     */
    AudioStreamBuilder* setSamplesPerFrame(int samplesPerFrame) {
        mSamplesPerFrame = samplesPerFrame;
        return this;
    }

    aaudio_direction_t getDirection() const {
        return mDirection;
    }

    AudioStreamBuilder* setDirection(aaudio_direction_t direction) {
        mDirection = direction;
        return this;
    }

    aaudio_sample_rate_t getSampleRate() const {
        return mSampleRate;
    }

    AudioStreamBuilder* setSampleRate(aaudio_sample_rate_t sampleRate) {
        mSampleRate = sampleRate;
        return this;
    }

    aaudio_audio_format_t getFormat() const {
        return mFormat;
    }

    AudioStreamBuilder *setFormat(aaudio_audio_format_t format) {
        mFormat = format;
        return this;
    }

    aaudio_sharing_mode_t getSharingMode() const {
        return mSharingMode;
    }

    AudioStreamBuilder* setSharingMode(aaudio_sharing_mode_t sharingMode) {
        mSharingMode = sharingMode;
        return this;
    }

    aaudio_device_id_t getDeviceId() const {
        return mDeviceId;
    }

    AudioStreamBuilder* setDeviceId(aaudio_device_id_t deviceId) {
        mDeviceId = deviceId;
        return this;
    }

    aaudio_result_t build(AudioStream **streamPtr);

private:
    int32_t              mSamplesPerFrame = AAUDIO_UNSPECIFIED;
    aaudio_sample_rate_t   mSampleRate = AAUDIO_UNSPECIFIED;
    aaudio_device_id_t     mDeviceId = AAUDIO_DEVICE_UNSPECIFIED;
    aaudio_sharing_mode_t  mSharingMode = AAUDIO_SHARING_MODE_LEGACY;
    aaudio_audio_format_t  mFormat = AAUDIO_FORMAT_UNSPECIFIED;
    aaudio_direction_t     mDirection = AAUDIO_DIRECTION_OUTPUT;
};

} /* namespace aaudio */

#endif /* AAUDIO_AUDIOSTREAMBUILDER_H */
