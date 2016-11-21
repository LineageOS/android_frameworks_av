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

#ifndef OBOE_AUDIOSTREAM_H
#define OBOE_AUDIOSTREAM_H

#include <unistd.h>
#include <sys/types.h>
#include <oboe/OboeAudio.h>
#include "OboeUtilities.h"
#include "MonotonicCounter.h"

namespace oboe {

class AudioStreamBuilder;

/**
 * Oboe audio stream.
 */
class AudioStream {
public:

    AudioStream();

    virtual ~AudioStream();


    // =========== Begin ABSTRACT methods ===========================

    /* Asynchronous requests.
     * Use waitForStateChange() to wait for completion.
     */
    virtual oboe_result_t requestStart() = 0;
    virtual oboe_result_t requestPause() = 0;
    virtual oboe_result_t requestFlush() = 0;
    virtual oboe_result_t requestStop() = 0;

    // TODO use oboe_clockid_t all the way down to AudioClock
    virtual oboe_result_t getTimestamp(clockid_t clockId,
                                       oboe_position_frames_t *framePosition,
                                       oboe_nanoseconds_t *timeNanoseconds) = 0;


    virtual oboe_result_t updateState() = 0;


    // =========== End ABSTRACT methods ===========================

    virtual oboe_result_t waitForStateChange(oboe_stream_state_t currentState,
                                          oboe_stream_state_t *nextState,
                                          oboe_nanoseconds_t timeoutNanoseconds);

    /**
     * Open the stream using the parameters in the builder.
     * Allocate the necessary resources.
     */
    virtual oboe_result_t open(const AudioStreamBuilder& builder);

    /**
     * Close the stream and deallocate any resources from the open() call.
     * It is safe to call close() multiple times.
     */
    virtual oboe_result_t close() {
        return OBOE_OK;
    }

    virtual oboe_result_t setBufferSize(oboe_size_frames_t requestedFrames,
                                        oboe_size_frames_t *actualFrames) {
        return OBOE_ERROR_UNIMPLEMENTED;
    }

    virtual oboe_result_t createThread(oboe_nanoseconds_t periodNanoseconds,
                                     void *(*start_routine)(void *), void *arg);

    virtual oboe_result_t joinThread(void **returnArg, oboe_nanoseconds_t timeoutNanoseconds);

    // ============== Queries ===========================

    virtual oboe_stream_state_t getState() const {
        return mState;
    }

    virtual oboe_size_frames_t getBufferSize() const {
        return OBOE_ERROR_UNIMPLEMENTED;
    }

    virtual oboe_size_frames_t getBufferCapacity() const {
        return OBOE_ERROR_UNIMPLEMENTED;
    }

    virtual oboe_size_frames_t getFramesPerBurst() const {
        return OBOE_ERROR_UNIMPLEMENTED;
    }

    virtual int32_t getXRunCount() const {
        return OBOE_ERROR_UNIMPLEMENTED;
    }

    bool isPlaying() const {
        return mState == OBOE_STREAM_STATE_STARTING || mState == OBOE_STREAM_STATE_STARTED;
    }

    oboe_result_t getSampleRate() const {
        return mSampleRate;
    }

    oboe_audio_format_t getFormat()  const {
        return mFormat;
    }

    oboe_result_t getSamplesPerFrame() const {
        return mSamplesPerFrame;
    }

    OboeDeviceId getDeviceId() const {
        return mDeviceId;
    }

    oboe_sharing_mode_t getSharingMode() const {
        return mSharingMode;
    }

    oboe_direction_t getDirection() const {
        return mDirection;
    }

    oboe_size_bytes_t getBytesPerFrame() const {
        return mSamplesPerFrame * getBytesPerSample();
    }

    oboe_size_bytes_t getBytesPerSample() const {
        return OboeConvert_formatToSizeInBytes(mFormat);
    }

    virtual oboe_position_frames_t getFramesWritten() {
        return mFramesWritten.get();
    }

    virtual oboe_position_frames_t getFramesRead() {
        return mFramesRead.get();
    }


    // ============== I/O ===========================
    // A Stream will only implement read() or write() depending on its direction.
    virtual oboe_result_t write(const void *buffer,
                             oboe_size_frames_t numFrames,
                             oboe_nanoseconds_t timeoutNanoseconds) {
        return OBOE_ERROR_UNIMPLEMENTED;
    }

    virtual oboe_result_t read(void *buffer,
                            oboe_size_frames_t numFrames,
                            oboe_nanoseconds_t timeoutNanoseconds) {
        return OBOE_ERROR_UNIMPLEMENTED;
    }

protected:

    virtual oboe_position_frames_t incrementFramesWritten(oboe_size_frames_t frames) {
        return static_cast<oboe_position_frames_t>(mFramesWritten.increment(frames));
    }

    virtual oboe_position_frames_t incrementFramesRead(oboe_size_frames_t frames) {
        return static_cast<oboe_position_frames_t>(mFramesRead.increment(frames));
    }

    /**
     * Wait for a transition from one state to another.
     * @return OBOE_OK if the endingState was observed, or OBOE_ERROR_UNEXPECTED_STATE
     *   if any state that was not the startingState or endingState was observed
     *   or OBOE_ERROR_TIMEOUT
     */
    virtual oboe_result_t waitForStateTransition(oboe_stream_state_t startingState,
                                              oboe_stream_state_t endingState,
                                              oboe_nanoseconds_t timeoutNanoseconds);

    /**
     * This should not be called after the open() call.
     */
    void setSampleRate(oboe_sample_rate_t sampleRate) {
        mSampleRate = sampleRate;
    }

    /**
     * This should not be called after the open() call.
     */
    void setSamplesPerFrame(int32_t samplesPerFrame) {
        mSamplesPerFrame = samplesPerFrame;
    }

    /**
     * This should not be called after the open() call.
     */
    void setSharingMode(oboe_sharing_mode_t sharingMode) {
        mSharingMode = sharingMode;
    }

    /**
     * This should not be called after the open() call.
     */
    void setFormat(oboe_audio_format_t format) {
        mFormat = format;
    }

    void setState(oboe_stream_state_t state) {
        mState = state;
    }

    MonotonicCounter     mFramesWritten;
    MonotonicCounter     mFramesRead;

private:
    // These do not change after open().
    int32_t              mSamplesPerFrame = OBOE_UNSPECIFIED;
    oboe_sample_rate_t   mSampleRate = OBOE_UNSPECIFIED;
    oboe_stream_state_t  mState = OBOE_STREAM_STATE_UNINITIALIZED;
    OboeDeviceId         mDeviceId = OBOE_UNSPECIFIED;
    oboe_sharing_mode_t  mSharingMode = OBOE_SHARING_MODE_LEGACY;
    oboe_audio_format_t  mFormat = OBOE_UNSPECIFIED;
    oboe_direction_t     mDirection = OBOE_DIRECTION_OUTPUT;

    bool                 mHasThread;
    pthread_t            mThread;
};

} /* namespace oboe */

#endif /* OBOE_AUDIOSTREAM_H */
