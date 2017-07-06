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
#include <mutex>
#include <stdint.h>
#include <aaudio/AAudio.h>

#include "utility/AAudioUtilities.h"
#include "utility/MonotonicCounter.h"

namespace aaudio {

typedef void *(*aaudio_audio_thread_proc_t)(void *);

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

    virtual aaudio_result_t requestPause()
    {
        // Only implement this for OUTPUT streams.
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual aaudio_result_t requestFlush() {
        // Only implement this for OUTPUT streams.
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual aaudio_result_t requestStop() = 0;

    virtual aaudio_result_t getTimestamp(clockid_t clockId,
                                       int64_t *framePosition,
                                       int64_t *timeNanoseconds) = 0;


    /**
     * Update state while in the middle of waitForStateChange()
     * @return
     */
    virtual aaudio_result_t updateStateWhileWaiting() = 0;


    // =========== End ABSTRACT methods ===========================

    virtual aaudio_result_t waitForStateChange(aaudio_stream_state_t currentState,
                                               aaudio_stream_state_t *nextState,
                                               int64_t timeoutNanoseconds);

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

    virtual aaudio_result_t setBufferSize(int32_t requestedFrames) = 0;

    virtual aaudio_result_t createThread(int64_t periodNanoseconds,
                                       aaudio_audio_thread_proc_t threadProc,
                                       void *threadArg);

    aaudio_result_t joinThread(void **returnArg, int64_t timeoutNanoseconds);

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

    aaudio_stream_state_t getState() const {
        return mState;
    }

    virtual int32_t getBufferSize() const {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual int32_t getBufferCapacity() const {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual int32_t getFramesPerBurst() const {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual int32_t getXRunCount() const {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    bool isActive() const {
        return mState == AAUDIO_STREAM_STATE_STARTING || mState == AAUDIO_STREAM_STATE_STARTED;
    }

    virtual bool isMMap() {
        return false;
    }

    aaudio_result_t getSampleRate() const {
        return mSampleRate;
    }

    aaudio_format_t getFormat()  const {
        return mFormat;
    }

    aaudio_result_t getSamplesPerFrame() const {
        return mSamplesPerFrame;
    }

    virtual int32_t getPerformanceMode() const {
        return mPerformanceMode;
    }

    void setPerformanceMode(aaudio_performance_mode_t performanceMode) {
        mPerformanceMode = performanceMode;
    }

    int32_t getDeviceId() const {
        return mDeviceId;
    }

    aaudio_sharing_mode_t getSharingMode() const {
        return mSharingMode;
    }

    bool isSharingModeMatchRequired() const {
        return mSharingModeMatchRequired;
    }

    virtual aaudio_direction_t getDirection() const = 0;

    /**
     * This is only valid after setSamplesPerFrame() and setFormat() have been called.
     */
    int32_t getBytesPerFrame() const {
        return mSamplesPerFrame * getBytesPerSample();
    }

    /**
     * This is only valid after setFormat() has been called.
     */
    int32_t getBytesPerSample() const {
        return AAudioConvert_formatToSizeInBytes(mFormat);
    }

    virtual int64_t getFramesWritten() = 0;

    virtual int64_t getFramesRead() = 0;

    AAudioStream_dataCallback getDataCallbackProc() const {
        return mDataCallbackProc;
    }
    AAudioStream_errorCallback getErrorCallbackProc() const {
        return mErrorCallbackProc;
    }

    void *getDataCallbackUserData() const {
        return mDataCallbackUserData;
    }
    void *getErrorCallbackUserData() const {
        return mErrorCallbackUserData;
    }

    int32_t getFramesPerDataCallback() const {
        return mFramesPerDataCallback;
    }

    bool isDataCallbackActive() {
        return (mDataCallbackProc != nullptr) && isActive();
    }

    // ============== I/O ===========================
    // A Stream will only implement read() or write() depending on its direction.
    virtual aaudio_result_t write(const void *buffer __unused,
                             int32_t numFrames __unused,
                             int64_t timeoutNanoseconds __unused) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual aaudio_result_t read(void *buffer __unused,
                            int32_t numFrames __unused,
                            int64_t timeoutNanoseconds __unused) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

protected:


    /**
     * This should not be called after the open() call.
     */
    void setSampleRate(int32_t sampleRate) {
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
    void setFormat(aaudio_format_t format) {
        mFormat = format;
    }

    void setState(aaudio_stream_state_t state) {
        mState = state;
    }

    void setDeviceId(int32_t deviceId) {
        mDeviceId = deviceId;
    }

    std::mutex           mStreamMutex;

    std::atomic<bool>    mCallbackEnabled;

protected:

    void setPeriodNanoseconds(int64_t periodNanoseconds) {
        mPeriodNanoseconds.store(periodNanoseconds, std::memory_order_release);
    }

    int64_t getPeriodNanoseconds() {
        return mPeriodNanoseconds.load(std::memory_order_acquire);
    }

private:
    // These do not change after open().
    int32_t                mSamplesPerFrame = AAUDIO_UNSPECIFIED;
    int32_t                mSampleRate = AAUDIO_UNSPECIFIED;
    int32_t                mDeviceId = AAUDIO_UNSPECIFIED;
    aaudio_sharing_mode_t  mSharingMode = AAUDIO_SHARING_MODE_SHARED;
    bool                   mSharingModeMatchRequired = false; // must match sharing mode requested
    aaudio_format_t        mFormat = AAUDIO_FORMAT_UNSPECIFIED;
    aaudio_stream_state_t  mState = AAUDIO_STREAM_STATE_UNINITIALIZED;

    aaudio_performance_mode_t mPerformanceMode = AAUDIO_PERFORMANCE_MODE_NONE;

    // callback ----------------------------------

    AAudioStream_dataCallback   mDataCallbackProc = nullptr;  // external callback functions
    void                       *mDataCallbackUserData = nullptr;
    int32_t                     mFramesPerDataCallback = AAUDIO_UNSPECIFIED; // frames

    AAudioStream_errorCallback  mErrorCallbackProc = nullptr;
    void                       *mErrorCallbackUserData = nullptr;

    // background thread ----------------------------------
    bool                   mHasThread = false;
    pthread_t              mThread; // initialized in constructor

    // These are set by the application thread and then read by the audio pthread.
    std::atomic<int64_t>   mPeriodNanoseconds; // for tuning SCHED_FIFO threads
    // TODO make atomic?
    aaudio_audio_thread_proc_t mThreadProc = nullptr;
    void*                  mThreadArg = nullptr;
    aaudio_result_t        mThreadRegistrationResult = AAUDIO_OK;


};

} /* namespace aaudio */

#endif /* AAUDIO_AUDIOSTREAM_H */
