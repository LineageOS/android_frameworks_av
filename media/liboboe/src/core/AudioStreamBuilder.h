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

#ifndef OBOE_AUDIOSTREAMBUILDER_H
#define OBOE_AUDIOSTREAMBUILDER_H

#include <stdint.h>

#include <oboe/OboeDefinitions.h>
#include <oboe/OboeAudio.h>

#include "AudioStream.h"

namespace oboe {

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

    oboe_direction_t getDirection() const {
        return mDirection;
    }

    AudioStreamBuilder* setDirection(oboe_direction_t direction) {
        mDirection = direction;
        return this;
    }

    oboe_sample_rate_t getSampleRate() const {
        return mSampleRate;
    }

    AudioStreamBuilder* setSampleRate(oboe_sample_rate_t sampleRate) {
        mSampleRate = sampleRate;
        return this;
    }

    oboe_audio_format_t getFormat() const {
        return mFormat;
    }

    AudioStreamBuilder *setFormat(oboe_audio_format_t format) {
        mFormat = format;
        return this;
    }

    oboe_sharing_mode_t getSharingMode() const {
        return mSharingMode;
    }

    AudioStreamBuilder* setSharingMode(oboe_sharing_mode_t sharingMode) {
        mSharingMode = sharingMode;
        return this;
    }

    oboe_device_id_t getDeviceId() const {
        return mDeviceId;
    }

    AudioStreamBuilder* setDeviceId(oboe_device_id_t deviceId) {
        mDeviceId = deviceId;
        return this;
    }

    oboe_result_t build(AudioStream **streamPtr);

private:
    int32_t              mSamplesPerFrame = OBOE_UNSPECIFIED;
    oboe_sample_rate_t   mSampleRate = OBOE_UNSPECIFIED;
    oboe_device_id_t     mDeviceId = OBOE_DEVICE_UNSPECIFIED;
    oboe_sharing_mode_t  mSharingMode = OBOE_SHARING_MODE_LEGACY;
    oboe_audio_format_t  mFormat = OBOE_AUDIO_FORMAT_UNSPECIFIED;
    oboe_direction_t     mDirection = OBOE_DIRECTION_OUTPUT;
};

} /* namespace oboe */

#endif /* OBOE_AUDIOSTREAMBUILDER_H */
