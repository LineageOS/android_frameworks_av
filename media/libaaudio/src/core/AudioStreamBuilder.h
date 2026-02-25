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

// go/keep-sorted start
#include <aaudio/AAudio.h>
#include <core/AAudioStreamOpenRequest.h>
#include <core/AudioStream.h>
// go/keep-sorted end

// go/keep-sorted start
#include <set>
#include <stdint.h>
// go/keep-sorted end

namespace aaudio {

/**
 * Factory class for an AudioStream.
 */
class AudioStreamBuilder : public AAudioStreamOpenRequest {
public:
    AudioStreamBuilder()
            : AAudioStreamOpenRequest(nullptr /*parameters*/,
                                      false /*isSharingModeMatchRequired*/) { }

    ~AudioStreamBuilder() = default;

    AudioStreamBuilder* setSharingModeMatchRequired(bool required) {
        mSharingModeMatchRequired = required;
        return this;
    }

    AudioStreamBuilder* setDataCallbackProc(AAudioStream_dataCallback proc) {
        mDataCallbackProc = proc;
        mPartialDataCallbackProc = nullptr;
        return this;
    }

    AudioStreamBuilder* setPartialDataCallbackProc(AAudioStream_partialDataCallback proc) {
        setPartialDataCallbackProcVoid(proc);
        mDataCallbackProc = nullptr;
        return this;
    }

    AudioStreamBuilder* setDataCallbackUserData(void *userData) {
        setDataCallbackUserDataVoid(userData);
        return this;
    }

    AudioStreamBuilder* setErrorCallbackProc(AAudioStream_errorCallback proc) {
        mErrorCallbackProc = proc;
        return this;
    }

    AudioStreamBuilder* setErrorCallbackUserData(void *userData) {
        mErrorCallbackUserData = userData;
        return this;
    }

    AudioStreamBuilder* setPresentationEndCallbackProc(AAudioStream_presentationEndCallback proc) {
        setPresentationEndCallbackProcVoid(proc);
        return this;
    }

    AudioStreamBuilder* setPresentationEndCallbackUserData(void *userData) {
        setPresentationEndCallbackUserDataVoid(userData);
        return this;
    }

    AudioStreamBuilder* setRoutingChangedCallbackProc(AAudioStream_routingChangedCallback proc) {
        mRoutingChangedCallbackProc = proc;
        return this;
    }

    AudioStreamBuilder* setRoutingChangedCallbackUserData(void *userData) {
        mRoutingChangedCallbackUserData = userData;
        return this;
    }

    AudioStreamBuilder* setFramesPerDataCallback(int32_t sizeInFrames) {
        mFramesPerDataCallback = sizeInFrames;
        return this;
    }

    AudioStreamBuilder* setPrivacySensitiveRequest(bool privacySensitive) {
        mPrivacySensitiveReq =
            privacySensitive ? PRIVACY_SENSITIVE_ENABLED : PRIVACY_SENSITIVE_DISABLED;
        return this;
    }

    aaudio_result_t addTag(const char* tag);

    void clearTags();

    aaudio_result_t build(AudioStream **streamPtr);

    void logParameters() const;

    // Mark the stream so it can be deleted.
    static void stopUsingStream(AudioStream *stream);

private:
    // Extract a raw pointer that we can pass to a 'C' app.
    static AudioStream *startUsingStream(android::sp<AudioStream> &spAudioStream);
};

} /* namespace aaudio */

#endif //AAUDIO_AUDIO_STREAM_BUILDER_H
