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

#ifndef AAUDIO_AUDIO_STREAM_BUILDER_H
#define AAUDIO_AUDIO_STREAM_BUILDER_H

#include <stdint.h>

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

    int32_t getSampleRate() const {
        return mSampleRate;
    }

    AudioStreamBuilder* setSampleRate(int32_t sampleRate) {
        mSampleRate = sampleRate;
        return this;
    }

    aaudio_format_t getFormat() const {
        return mFormat;
    }

    AudioStreamBuilder *setFormat(aaudio_format_t format) {
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

    bool isSharingModeMatchRequired() const {
        return mSharingModeMatchRequired;
    }

    AudioStreamBuilder* setSharingModeMatchRequired(bool required) {
        mSharingModeMatchRequired = required;
        return this;
    }

    int32_t getBufferCapacity() const {
        return mBufferCapacity;
    }

    AudioStreamBuilder* setBufferCapacity(int32_t frames) {
        mBufferCapacity = frames;
        return this;
    }

    int32_t getPerformanceMode() const {
        return mPerformanceMode;
    }

    AudioStreamBuilder* setPerformanceMode(aaudio_performance_mode_t performanceMode) {
        mPerformanceMode = performanceMode;
        return this;
    }

    int32_t getDeviceId() const {
        return mDeviceId;
    }

    AudioStreamBuilder* setDeviceId(int32_t deviceId) {
        mDeviceId = deviceId;
        return this;
    }

    AAudioStream_dataCallback getDataCallbackProc() const {
        return mDataCallbackProc;
    }

    AudioStreamBuilder* setDataCallbackProc(AAudioStream_dataCallback proc) {
        mDataCallbackProc = proc;
        return this;
    }

    void *getDataCallbackUserData() const {
        return mDataCallbackUserData;
    }

    AudioStreamBuilder* setDataCallbackUserData(void *userData) {
        mDataCallbackUserData = userData;
        return this;
    }

    AAudioStream_errorCallback getErrorCallbackProc() const {
        return mErrorCallbackProc;
    }

    AudioStreamBuilder* setErrorCallbackProc(AAudioStream_errorCallback proc) {
        mErrorCallbackProc = proc;
        return this;
    }

    AudioStreamBuilder* setErrorCallbackUserData(void *userData) {
        mErrorCallbackUserData = userData;
        return this;
    }

    void *getErrorCallbackUserData() const {
        return mErrorCallbackUserData;
    }

    int32_t getFramesPerDataCallback() const {
        return mFramesPerDataCallback;
    }

    AudioStreamBuilder* setFramesPerDataCallback(int32_t sizeInFrames) {
        mFramesPerDataCallback = sizeInFrames;
        return this;
    }

    aaudio_result_t build(AudioStream **streamPtr);

private:
    int32_t                    mSamplesPerFrame = AAUDIO_UNSPECIFIED;
    int32_t                    mSampleRate = AAUDIO_UNSPECIFIED;
    int32_t                    mDeviceId = AAUDIO_UNSPECIFIED;
    aaudio_sharing_mode_t      mSharingMode = AAUDIO_SHARING_MODE_SHARED;
    bool                       mSharingModeMatchRequired = false; // must match sharing mode requested
    aaudio_format_t            mFormat = AAUDIO_FORMAT_UNSPECIFIED;
    aaudio_direction_t         mDirection = AAUDIO_DIRECTION_OUTPUT;
    int32_t                    mBufferCapacity = AAUDIO_UNSPECIFIED;
    aaudio_performance_mode_t  mPerformanceMode = AAUDIO_PERFORMANCE_MODE_NONE;

    AAudioStream_dataCallback  mDataCallbackProc = nullptr;  // external callback functions
    void                      *mDataCallbackUserData = nullptr;
    int32_t                    mFramesPerDataCallback = AAUDIO_UNSPECIFIED; // frames

    AAudioStream_errorCallback mErrorCallbackProc = nullptr;
    void                      *mErrorCallbackUserData = nullptr;
};

} /* namespace aaudio */

#endif //AAUDIO_AUDIO_STREAM_BUILDER_H
