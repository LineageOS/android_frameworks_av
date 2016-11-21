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

#ifndef LEGACY_AUDIOSTREAMTRACK_H
#define LEGACY_AUDIOSTREAMTRACK_H

#include <media/AudioTrack.h>
#include <oboe/OboeAudio.h>

#include "AudioStreamBuilder.h"
#include "AudioStream.h"
#include "OboeLegacy.h"

namespace oboe {


/**
 * Internal stream that uses the legacy AudioTrack path.
 */
class AudioStreamTrack : public AudioStream {
public:
    AudioStreamTrack();

    virtual ~AudioStreamTrack();


    virtual oboe_result_t open(const AudioStreamBuilder & builder) override;
    virtual oboe_result_t close() override;

    virtual oboe_result_t requestStart() override;
    virtual oboe_result_t requestPause() override;
    virtual oboe_result_t requestFlush() override;
    virtual oboe_result_t requestStop() override;

    virtual oboe_result_t getTimestamp(clockid_t clockId,
                                       oboe_position_frames_t *framePosition,
                                       oboe_nanoseconds_t *timeNanoseconds) override {
        return OBOE_ERROR_UNIMPLEMENTED; // TODO call getTimestamp(ExtendedTimestamp *timestamp);
    }

    virtual oboe_result_t write(const void *buffer,
                             oboe_size_frames_t numFrames,
                             oboe_nanoseconds_t timeoutNanoseconds) override;

    virtual oboe_result_t setBufferSize(oboe_size_frames_t requestedFrames,
                                             oboe_size_frames_t *actualFrames) override;
    virtual oboe_size_frames_t getBufferSize() const override;
    virtual oboe_size_frames_t getBufferCapacity() const override;
    virtual oboe_size_frames_t getFramesPerBurst()const  override;
    virtual int32_t getXRunCount() const override;

    virtual oboe_position_frames_t getFramesRead() override;

    virtual oboe_result_t updateState() override;

private:
    android::sp<android::AudioTrack> mAudioTrack;
    // TODO add 64-bit position reporting to AudioRecord and use it.
    oboe_wrapping_frames_t           mPositionWhenStarting = 0;
    oboe_wrapping_frames_t           mPositionWhenPausing = 0;
};

} /* namespace oboe */

#endif /* LEGACY_AUDIOSTREAMTRACK_H */
