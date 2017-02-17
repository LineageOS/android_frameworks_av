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

#ifndef LEGACY_AUDIO_STREAM_TRACK_H
#define LEGACY_AUDIO_STREAM_TRACK_H

#include <media/AudioTrack.h>
#include <aaudio/AAudio.h>

#include "AudioStreamBuilder.h"
#include "AudioStream.h"
#include "AAudioLegacy.h"

namespace aaudio {


/**
 * Internal stream that uses the legacy AudioTrack path.
 */
class AudioStreamTrack : public AudioStream {
public:
    AudioStreamTrack();

    virtual ~AudioStreamTrack();


    virtual aaudio_result_t open(const AudioStreamBuilder & builder) override;
    virtual aaudio_result_t close() override;

    virtual aaudio_result_t requestStart() override;
    virtual aaudio_result_t requestPause() override;
    virtual aaudio_result_t requestFlush() override;
    virtual aaudio_result_t requestStop() override;

    virtual aaudio_result_t getTimestamp(clockid_t clockId,
                                       int64_t *framePosition,
                                       int64_t *timeNanoseconds) override {
        return AAUDIO_ERROR_UNIMPLEMENTED; // TODO call getTimestamp(ExtendedTimestamp *timestamp);
    }

    virtual aaudio_result_t write(const void *buffer,
                             int32_t numFrames,
                             int64_t timeoutNanoseconds) override;

    virtual aaudio_result_t setBufferSize(int32_t requestedFrames) override;
    virtual int32_t getBufferSize() const override;
    virtual int32_t getBufferCapacity() const override;
    virtual int32_t getFramesPerBurst()const  override;
    virtual int32_t getXRunCount() const override;

    virtual int64_t getFramesRead() override;

    virtual aaudio_result_t updateState() override;

private:
    android::sp<android::AudioTrack> mAudioTrack;
    // TODO add 64-bit position reporting to AudioRecord and use it.
    aaudio_wrapping_frames_t         mPositionWhenStarting = 0;
    aaudio_wrapping_frames_t         mPositionWhenPausing = 0;
};

} /* namespace aaudio */

#endif /* LEGACY_AUDIO_STREAM_TRACK_H */
