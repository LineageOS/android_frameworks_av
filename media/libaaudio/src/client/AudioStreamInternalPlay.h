/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef ANDROID_AAUDIO_AUDIO_STREAM_INTERNAL_PLAY_H
#define ANDROID_AAUDIO_AUDIO_STREAM_INTERNAL_PLAY_H

// go/keep-sorted start
#include <aaudio/AAudio.h>
#include <aaudio/DrainType.h>
#include <audio_utils/TimerQueue.h>
// go/keep-sorted end

// go/keep-sorted start
#include <condition_variable>
#include <mutex>
#include <stdint.h>
#include <thread>
// go/keep-sorted end

// go/keep-sorted start
#include "AudioStreamInternal.h"
#include "binding/AAudioServiceInterface.h"
// go/keep-sorted end

using android::sp;

namespace aaudio {

// Keep this the same as AUDIO_PLAYBACK_RATE_INITIALIZER;
static constexpr AAudioPlaybackParameters AAUDIO_PLAYBACK_PARAMETERS_DEFAULT = {
        .fallbackMode = AAUDIO_FALLBACK_MODE_FAIL,
        .stretchMode = AAUDIO_STRETCH_MODE_DEFAULT,
        .pitch = 1.0f,
        .speed = 1.0f,
};

class AudioStreamInternalPlay : public AudioStreamInternal {
public:
    explicit AudioStreamInternalPlay(AAudioServiceInterface  &serviceInterface,
                                     bool inService = false);
    virtual ~AudioStreamInternalPlay() = default;

    aaudio_result_t open(const AAudioStreamOpenRequest& openRequest) override;

    aaudio_result_t requestPause_l() REQUIRES(mStreamMutex) override;

    aaudio_result_t requestFlush_l() REQUIRES(mStreamMutex) override;

    bool isFlushSupported() const override {
        // Only implement FLUSH for OUTPUT streams.
        return true;
    }

    bool isPauseSupported() const override {
        // Only implement PAUSE for OUTPUT streams.
        return true;
    }

    aaudio_result_t write(const void *buffer,
                          int32_t numFrames,
                          int64_t timeoutNanoseconds) EXCLUDES(mStreamMutex) override;

    int64_t getFramesRead() override;
    int64_t getFramesWritten() override;

    void *callbackLoop() override;

    aaudio_direction_t getDirection() const override {
        return AAUDIO_DIRECTION_OUTPUT;
    }

    aaudio_result_t setOffloadEndOfStream() EXCLUDES(mStreamMutex) final;

    void setPresentationEndCallbackProc(AAudioStream_presentationEndCallback proc) final {
        mPresentationEndCallbackProc = proc;
    }

    void setPresentationEndCallbackUserData(void *userData) final {
        mPresentationEndCallbackUserData = userData;
    }

    void setUseDataAvailableCallback() {
        mUseDataAvailableCallback = true;
    }

protected:

    void prepareBuffersForStart_l(StartType startType = DEFAULT) REQUIRES(mStreamMutex) final;

    aaudio_result_t prepareBuffersForStop_l() REQUIRES(mStreamMutex) final;

    void advanceClientToMatchServerPosition(int32_t serverMargin) override;

    void onFlushFromServer() override;

    android::status_t doSetVolume() override;

/**
 * Low level write that will not block. It will just write as much as it can.
 *
 * It passed back a recommended time to wake up if wakeTimePtr is not NULL.
 *
 * @return the number of frames written or a negative error code.
 */
    aaudio_result_t processDataNow(void *buffer,
                             int32_t numFrames,
                             int64_t currentTimeNanos,
                             int64_t *wakeTimePtr) override;

    aaudio_result_t requestStart_l() REQUIRES(mStreamMutex) final;
    aaudio_result_t requestStop_l() REQUIRES(mStreamMutex) final;

    void wakeupCallbackThread_l() REQUIRES(mStreamMutex) final;
    aaudio_result_t flushFromFrame_l(AAudio_FlushFromAccuracy accuracy, int64_t* position)
            REQUIRES(mStreamMutex) final;

    bool mayNeedToDrain() const final {
        return getPerformanceMode() == AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED &&
               isClockModelInControl() &&
               getDeviceBufferSize() > getDeviceSampleRate();
    }

    int32_t getMinOffloadCallbackProcessingPeriodMs() const final {
        return kOffloadFlushFromSafeMarginMs;
    }

    aaudio_result_t setPlaybackParameters_l(const AAudioPlaybackParameters* parameters)
            REQUIRES(mStreamMutex) final;
    aaudio_result_t getPlaybackParameters_l(AAudioPlaybackParameters* parameters)
            REQUIRES(mStreamMutex) final;

    void onWakeUp_l(android::audio_utils::TimerQueue::handle_t handle) REQUIRES(mStreamMutex) final;

private:
    /*
     * Asynchronous write with potental data conversion.
     * @param buffer
     * @param numFrames
     * @return frames written or negative error
     */
    // General dispatch method, finds the best method to use below.
    aaudio_result_t writeNowWithConversion(const void* buffer, int32_t numFrames);

    // Optimized for matched sample rate.
    aaudio_result_t writeNowWithConversionMatchedSampleRate(const void* buffer, int32_t numFrames);

    // Full conversion method, may be slower than optimized variants above.
    aaudio_result_t writeNowWithConversionFull(const void* buffer, int32_t numFrames);

    void updateReadCounter(int64_t currentNanoTime);

    bool shouldStopStream() EXCLUDES(mStreamMutex);
    void maybeCallPresentationEndCallback_l() REQUIRES(mStreamMutex);

    void dropPresentationEndCallback_l() REQUIRES(mStreamMutex);

    aaudio_result_t drainStream_l(int64_t wakeUpNanos, DrainType drainType) REQUIRES(mStreamMutex);
    aaudio_result_t activateStream_l() REQUIRES(mStreamMutex);
    aaudio_result_t drainStream(DrainType drainType) EXCLUDES(mStreamMutex);

    bool mOffloadEosPending GUARDED_BY(mStreamMutex){false};
    std::condition_variable mStreamEndCV;
    int64_t mOffloadEosNanosBoottime GUARDED_BY(mStreamMutex){0};

    AAudioStream_presentationEndCallback mPresentationEndCallbackProc = nullptr;
    void                                *mPresentationEndCallbackUserData = nullptr;
    std::atomic<pid_t>                   mPresentationEndCallbackThread{CALLBACK_THREAD_NONE};

    static constexpr int32_t kOffloadSafeMarginMs = 1000;
    static constexpr int32_t kOffloadFlushFromSafeMarginMs = 100;
    int32_t mOffloadSafeMarginInFrames = 0;
    int32_t mOffloadFlushFromSafeMarginInFrames = 0;
    std::condition_variable mCallbackCV;
    bool mDraining GUARDED_BY(mStreamMutex){false};
    DrainType mDrainType GUARDED_BY(mStreamMutex){DrainType::DRAIN_ALL_DATA};
    android::audio_utils::TimerQueue::handle_t mWakeUpHandle
            GUARDED_BY(mStreamMutex){android::audio_utils::TimerQueue::INVALID_HANDLE};

    std::mutex mEndpointMutex;

    AAudioPlaybackParameters mPlaybackParameters = AAUDIO_PLAYBACK_PARAMETERS_DEFAULT;

    bool mPendingStop GUARDED_BY(mStreamMutex){false};

    bool mUseDataAvailableCallback = false;
    // The following two values will only be used if `mUseDataAvailableCallback` is true.
    // When `mUseDataAvailableCallback` is true, the client won't provide data from data
    // callback. Instead, it will call write. To avoid the callback thread keep spinning,
    // the `mDrainingNanos` is set when drain is needed after a write. Then the data callback
    // thread can use this value to drainStream and suspend.
    int64_t mDrainingNanos GUARDED_BY(mStreamMutex){0};
    // `mNeedCallbackWakeup` set to true can wake up the callback thread if it is using data
    // available callback and waiting for client to write data or service to drain.
    bool mNeedCallbackWakeup GUARDED_BY(mStreamMutex){false};

    // This value is calculated when opening. It will not changed after open.
    int64_t mNanosPerBurst = 0;
};

} /* namespace aaudio */

#endif //ANDROID_AAUDIO_AUDIO_STREAM_INTERNAL_PLAY_H
