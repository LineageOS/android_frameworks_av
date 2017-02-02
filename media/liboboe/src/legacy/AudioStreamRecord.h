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

#ifndef LEGACY_AUDIO_STREAM_RECORD_H
#define LEGACY_AUDIO_STREAM_RECORD_H

#include <media/AudioRecord.h>
#include <aaudio/AAudio.h>

#include "AudioStreamBuilder.h"
#include "AudioStream.h"
#include "AAudioLegacy.h"

namespace aaudio {

/**
 * Internal stream that uses the legacy AudioTrack path.
 */
class AudioStreamRecord : public AudioStream {
public:
    AudioStreamRecord();

    virtual ~AudioStreamRecord();

    virtual aaudio_result_t open(const AudioStreamBuilder & builder) override;
    virtual aaudio_result_t close() override;

    virtual aaudio_result_t requestStart() override;
    virtual aaudio_result_t requestPause() override;
    virtual aaudio_result_t requestFlush() override;
    virtual aaudio_result_t requestStop() override;

    virtual aaudio_result_t getTimestamp(clockid_t clockId,
                                       aaudio_position_frames_t *framePosition,
                                       aaudio_nanoseconds_t *timeNanoseconds) override {
        return AAUDIO_ERROR_UNIMPLEMENTED; // TODO
    }

    virtual aaudio_result_t read(void *buffer,
                             aaudio_size_frames_t numFrames,
                             aaudio_nanoseconds_t timeoutNanoseconds) override;

    virtual aaudio_result_t setBufferSize(aaudio_size_frames_t requestedFrames,
                                             aaudio_size_frames_t *actualFrames) override;

    virtual aaudio_size_frames_t getBufferSize() const override;

    virtual aaudio_size_frames_t getBufferCapacity() const override;

    virtual int32_t getXRunCount() const override;

    virtual aaudio_size_frames_t getFramesPerBurst() const override;

    virtual aaudio_result_t updateState() override;

private:
    android::sp<android::AudioRecord> mAudioRecord;
    // TODO add 64-bit position reporting to AudioRecord and use it.
    aaudio_wrapping_frames_t   mPositionWhenStarting = 0;
    android::String16        mOpPackageName;
};

} /* namespace aaudio */

#endif /* LEGACY_AUDIO_STREAM_RECORD_H */
