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

#ifndef AAUDIO_AUDIOSTREAM_H
#define AAUDIO_AUDIOSTREAM_H

#include <atomic>
#include <stdint.h>
#include <aaudio/AAudioDefinitions.h>
#include <aaudio/AAudio.h>

#include "AAudioUtilities.h"
#include "MonotonicCounter.h"

namespace aaudio {

class AudioStreamBuilder;

/**
 * AAudio audio stream.
 */
class AudioStream {
public:

    AudioStream();

    virtual ~AudioStream();


    // =========== Begin ABSTRACT methods ===========================

    /* Asynchronous requests.
     * Use waitForStateChange() to wait for completion.
     */
    virtual aaudio_result_t requestStart() = 0;
    virtual aaudio_result_t requestPause() = 0;
    virtual aaudio_result_t requestFlush() = 0;
    virtual aaudio_result_t requestStop() = 0;

    // TODO use aaudio_clockid_t all the way down to AudioClock
    virtual aaudio_result_t getTimestamp(clockid_t clockId,
                                       aaudio_position_frames_t *framePosition,
                                       aaudio_nanoseconds_t *timeNanoseconds) = 0;


    virtual aaudio_result_t updateState() = 0;


    // =========== End ABSTRACT methods ===========================

    virtual aaudio_result_t waitForStateChange(aaudio_stream_state_t currentState,
                                          aaudio_stream_state_t *nextState,
                                          aaudio_nanoseconds_t timeoutNanoseconds);

    /**
     * Open the stream using the parameters in the builder.
     * Allocate the necessary resources.
     */
    virtual aaudio_result_t open(const AudioStreamBuilder& builder);

    /**
     * Close the stream and deallocate any resources from the open() call.
     * It is safe to call close() multiple times.
     */
    virtual aaudio_result_t close() {
        return AAUDIO_OK;
    }

    virtual aaudio_result_t setBufferSize(aaudio_size_frames_t requestedFrames,
                                        aaudio_size_frames_t *actualFrames) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual aaudio_result_t createThread(aaudio_nanoseconds_t periodNanoseconds,
                                       aaudio_audio_thread_proc_t *threadProc,
                                       void *threadArg);

    virtual aaudio_result_t joinThread(void **returnArg, aaudio_nanoseconds_t timeoutNanoseconds);

    virtual aaudio_result_t registerThread() {
        return AAUDIO_OK;
    }

    virtual aaudio_result_t unregisterThread() {
        return AAUDIO_OK;
    }

    /**
     * Internal function used to call the audio thread passed by the user.
     * It is unfortunately public because it needs to be called by a static 'C' function.
     */
    void* wrapUserThread();

    // ============== Queries ===========================

    virtual aaudio_stream_state_t getState() const {
        return mState;
    }

    virtual aaudio_size_frames_t getBufferSize() const {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual aaudio_size_frames_t getBufferCapacity() const {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual aaudio_size_frames_t getFramesPerBurst() const {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual int32_t getXRunCount() const {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    bool isPlaying() const {
        return mState == AAUDIO_STREAM_STATE_STARTING || mState == AAUDIO_STREAM_STATE_STARTED;
    }

    aaudio_result_t getSampleRate() const {
        return mSampleRate;
    }

    aaudio_audio_format_t getFormat()  const {
        return mFormat;
    }

    aaudio_result_t getSamplesPerFrame() const {
        return mSamplesPerFrame;
    }

    aaudio_device_id_t getDeviceId() const {
        return mDeviceId;
    }

    aaudio_sharing_mode_t getSharingMode() const {
        return mSharingMode;
    }

    aaudio_direction_t getDirection() const {
        return mDirection;
    }

    aaudio_size_bytes_t getBytesPerFrame() const {
        return mSamplesPerFrame * getBytesPerSample();
    }

    aaudio_size_bytes_t getBytesPerSample() const {
        return AAudioConvert_formatToSizeInBytes(mFormat);
    }

    virtual aaudio_position_frames_t getFramesWritten() {
        return mFramesWritten.get();
    }

    virtual aaudio_position_frames_t getFramesRead() {
        return mFramesRead.get();
    }


    // ============== I/O ===========================
    // A Stream will only implement read() or write() depending on its direction.
    virtual aaudio_result_t write(const void *buffer,
                             aaudio_size_frames_t numFrames,
                             aaudio_nanoseconds_t timeoutNanoseconds) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual aaudio_result_t read(void *buffer,
                            aaudio_size_frames_t numFrames,
                            aaudio_nanoseconds_t timeoutNanoseconds) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

protected:

    virtual aaudio_position_frames_t incrementFramesWritten(aaudio_size_frames_t frames) {
        return static_cast<aaudio_position_frames_t>(mFramesWritten.increment(frames));
    }

    virtual aaudio_position_frames_t incrementFramesRead(aaudio_size_frames_t frames) {
        return static_cast<aaudio_position_frames_t>(mFramesRead.increment(frames));
    }

    /**
     * Wait for a transition from one state to another.
     * @return AAUDIO_OK if the endingState was observed, or AAUDIO_ERROR_UNEXPECTED_STATE
     *   if any state that was not the startingState or endingState was observed
     *   or AAUDIO_ERROR_TIMEOUT
     */
    virtual aaudio_result_t waitForStateTransition(aaudio_stream_state_t startingState,
                                              aaudio_stream_state_t endingState,
                                              aaudio_nanoseconds_t timeoutNanoseconds);

    /**
     * This should not be called after the open() call.
     */
    void setSampleRate(aaudio_sample_rate_t sampleRate) {
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
    void setSharingMode(aaudio_sharing_mode_t sharingMode) {
        mSharingMode = sharingMode;
    }

    /**
     * This should not be called after the open() call.
     */
    void setFormat(aaudio_audio_format_t format) {
        mFormat = format;
    }

    void setState(aaudio_stream_state_t state) {
        mState = state;
    }



protected:
    MonotonicCounter     mFramesWritten;
    MonotonicCounter     mFramesRead;

    void setPeriodNanoseconds(aaudio_nanoseconds_t periodNanoseconds) {
        mPeriodNanoseconds.store(periodNanoseconds, std::memory_order_release);
    }

    aaudio_nanoseconds_t getPeriodNanoseconds() {
        return mPeriodNanoseconds.load(std::memory_order_acquire);
    }

private:
    // These do not change after open().
    int32_t              mSamplesPerFrame = AAUDIO_UNSPECIFIED;
    aaudio_sample_rate_t   mSampleRate = AAUDIO_UNSPECIFIED;
    aaudio_stream_state_t  mState = AAUDIO_STREAM_STATE_UNINITIALIZED;
    aaudio_device_id_t     mDeviceId = AAUDIO_UNSPECIFIED;
    aaudio_sharing_mode_t  mSharingMode = AAUDIO_SHARING_MODE_LEGACY;
    aaudio_audio_format_t  mFormat = AAUDIO_FORMAT_UNSPECIFIED;
    aaudio_direction_t     mDirection = AAUDIO_DIRECTION_OUTPUT;

    // background thread ----------------------------------
    bool                 mHasThread = false;
    pthread_t            mThread; // initialized in constructor

    // These are set by the application thread and then read by the audio pthread.
    std::atomic<aaudio_nanoseconds_t>  mPeriodNanoseconds; // for tuning SCHED_FIFO threads
    // TODO make atomic?
    aaudio_audio_thread_proc_t* mThreadProc = nullptr;
    void*                mThreadArg = nullptr;
    aaudio_result_t        mThreadRegistrationResult = AAUDIO_OK;


};

} /* namespace aaudio */

#endif /* AAUDIO_AUDIOSTREAM_H */
