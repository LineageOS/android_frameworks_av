/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef AAUDIO_AAUDIO_SERVICE_STREAM_BASE_H
#define AAUDIO_AAUDIO_SERVICE_STREAM_BASE_H

#include <assert.h>
#include <mutex>

#include <android-base/thread_annotations.h>
#include <media/AidlConversion.h>
#include <media/AudioClient.h>
#include <utils/RefBase.h>

#include "fifo/FifoBuffer.h"
#include "binding/AudioEndpointParcelable.h"
#include "binding/AAudioServiceMessage.h"
#include "binding/AAudioStreamRequest.h"
#include "core/AAudioStreamParameters.h"
#include "utility/AAudioUtilities.h"
#include "utility/AudioClock.h"

#include "AAudioCommandQueue.h"
#include "AAudioThread.h"
#include "SharedRingBuffer.h"
#include "TimestampScheduler.h"

namespace android {
    class AAudioService;
}

namespace aaudio {

class AAudioServiceEndpoint;

// We expect the queue to only have a few commands.
// This should be way more than we need.
#define QUEUE_UP_CAPACITY_COMMANDS (128)

/**
 * Each instance of AAudioServiceStreamBase corresponds to a client stream.
 * It uses a subclass of AAudioServiceEndpoint to communicate with the underlying device or port.
 */
class AAudioServiceStreamBase
    : public virtual android::RefBase
    , public AAudioStreamParameters
    , public Runnable  {

public:
    explicit AAudioServiceStreamBase(android::AAudioService &aAudioService);

    ~AAudioServiceStreamBase() override;

    enum {
        ILLEGAL_THREAD_ID = 0
    };

    static std::string dumpHeader();

    // does not include EOL
    virtual std::string dump() const;

    /**
     * Open the device.
     */
    virtual aaudio_result_t open(const aaudio::AAudioStreamRequest &request)
            EXCLUDES(mUpMessageQueueLock);

    // We log the CLOSE from the close() method. We needed this separate method to log the OPEN
    // because we had to wait until we generated the handle.
    void logOpen(aaudio_handle_t streamHandle);

    aaudio_result_t close() EXCLUDES(mLock);

    /**
     * Start the flow of audio data.
     *
     * This is not guaranteed to be synchronous but it currently is.
     * An AAUDIO_SERVICE_EVENT_STARTED will be sent to the client when complete.
     */
    aaudio_result_t start() EXCLUDES(mLock);

    /**
     * Stop the flow of data so that start() can resume without loss of data.
     *
     * This is not guaranteed to be synchronous but it currently is.
     * An AAUDIO_SERVICE_EVENT_PAUSED will be sent to the client when complete.
    */
    aaudio_result_t pause() EXCLUDES(mLock);

    /**
     * Stop the flow of data after the currently queued data has finished playing.
     *
     * This is not guaranteed to be synchronous but it currently is.
     * An AAUDIO_SERVICE_EVENT_STOPPED will be sent to the client when complete.
     *
     */
    aaudio_result_t stop() EXCLUDES(mLock);

    /**
     * Discard any data held by the underlying HAL or Service.
     *
     * An AAUDIO_SERVICE_EVENT_FLUSHED will be sent to the client when complete.
     */
    aaudio_result_t flush() EXCLUDES(mLock);

    /**
     * Exit standby mode. The MMAP buffer will be reallocated.
     */
    aaudio_result_t exitStandby(AudioEndpointParcelable *parcelable) EXCLUDES(mLock);

    virtual aaudio_result_t startClient(const android::AudioClient& client,
                                        const audio_attributes_t *attr __unused,
                                        audio_port_handle_t *clientHandle __unused) {
        ALOGD("AAudioServiceStreamBase::startClient(%p, ...) AAUDIO_ERROR_UNAVAILABLE", &client);
        return AAUDIO_ERROR_UNAVAILABLE;
    }

    virtual aaudio_result_t stopClient(audio_port_handle_t clientHandle __unused) {
        ALOGD("AAudioServiceStreamBase::stopClient(%d) AAUDIO_ERROR_UNAVAILABLE", clientHandle);
        return AAUDIO_ERROR_UNAVAILABLE;
    }

    aaudio_result_t registerAudioThread(pid_t clientThreadId, int priority) EXCLUDES(mLock);

    aaudio_result_t unregisterAudioThread(pid_t clientThreadId) EXCLUDES(mLock);

    bool isRunning() const {
        return mState == AAUDIO_STREAM_STATE_STARTED;
    }

    /**
     * Fill in a parcelable description of stream.
     */
    aaudio_result_t getDescription(AudioEndpointParcelable &parcelable) EXCLUDES(mLock);

    void setRegisteredThread(pid_t pid) {
        mRegisteredClientThread = pid;
    }

    pid_t getRegisteredThread() const {
        return mRegisteredClientThread;
    }

    int32_t getFramesPerBurst() const {
        return mFramesPerBurst;
    }

    void run() override; // to implement Runnable

    void disconnect() EXCLUDES(mLock);

    const android::AudioClient &getAudioClient() {
        return mMmapClient;
    }

    uid_t getOwnerUserId() const {
        return VALUE_OR_FATAL(android::aidl2legacy_int32_t_uid_t(
                mMmapClient.attributionSource.uid));
    }

    pid_t getOwnerProcessId() const {
        return VALUE_OR_FATAL(android::aidl2legacy_int32_t_pid_t(
                mMmapClient.attributionSource.pid));
    }

    aaudio_handle_t getHandle() const {
        return mHandle;
    }
    void setHandle(aaudio_handle_t handle) {
        mHandle = handle;
    }

    audio_port_handle_t getPortHandle() const {
        return mClientHandle;
    }

    aaudio_stream_state_t getState() const {
        return mState;
    }

    void onVolumeChanged(float volume);

    /**
     * Set false when the stream is started.
     * Set true when data is first read from the stream.
     * @param b
     */
    void setFlowing(bool b) {
        mFlowing = b;
    }

    bool isFlowing() const {
        return mFlowing;
    }

    /**
     * Set false when the stream should not longer be processed.
     * This may be caused by a message queue overflow.
     * Set true when stream is started.
     * @param suspended
     */
    void setSuspended(bool suspended) {
        mSuspended = suspended;
    }

    bool isSuspended() const {
        return mSuspended;
    }

    virtual const char *getTypeText() const { return "Base"; }

protected:

    /**
     * Open the device.
     */
    aaudio_result_t open(const aaudio::AAudioStreamRequest &request,
                         aaudio_sharing_mode_t sharingMode);

    aaudio_result_t start_l() REQUIRES(mLock);
    virtual aaudio_result_t close_l() REQUIRES(mLock);
    virtual aaudio_result_t pause_l() REQUIRES(mLock);
    virtual aaudio_result_t stop_l() REQUIRES(mLock);
    void disconnect_l() REQUIRES(mLock);
    aaudio_result_t flush_l() REQUIRES(mLock);

    class RegisterAudioThreadParam : public AAudioCommandParam {
    public:
        RegisterAudioThreadParam(pid_t ownerPid, pid_t clientThreadId, int priority)
                : AAudioCommandParam(), mOwnerPid(ownerPid),
                  mClientThreadId(clientThreadId), mPriority(priority) { }
        ~RegisterAudioThreadParam() override = default;

        pid_t mOwnerPid;
        pid_t mClientThreadId;
        int mPriority;
    };
    aaudio_result_t registerAudioThread_l(
            pid_t ownerPid, pid_t clientThreadId, int priority) REQUIRES(mLock);

    class UnregisterAudioThreadParam : public AAudioCommandParam {
    public:
        explicit UnregisterAudioThreadParam(pid_t clientThreadId)
                : AAudioCommandParam(), mClientThreadId(clientThreadId) { }
        ~UnregisterAudioThreadParam() override = default;

        pid_t mClientThreadId;
    };
    aaudio_result_t unregisterAudioThread_l(pid_t clientThreadId) REQUIRES(mLock);

    class GetDescriptionParam : public AAudioCommandParam {
    public:
        explicit GetDescriptionParam(AudioEndpointParcelable* parcelable)
                : AAudioCommandParam(), mParcelable(parcelable) { }
        ~GetDescriptionParam() override = default;

        AudioEndpointParcelable* mParcelable;
    };
    aaudio_result_t getDescription_l(AudioEndpointParcelable* parcelable)
            REQUIRES(mLock) EXCLUDES(mUpMessageQueueLock);

    void setState(aaudio_stream_state_t state);

    /**
     * Device specific startup.
     * @return AAUDIO_OK or negative error.
     */
    virtual aaudio_result_t startDevice();

    aaudio_result_t writeUpMessageQueue(AAudioServiceMessage *command)
            EXCLUDES(mUpMessageQueueLock);

    aaudio_result_t sendCurrentTimestamp_l() REQUIRES(mLock);

    aaudio_result_t sendXRunCount(int32_t xRunCount);

    /**
     * @param positionFrames
     * @param timeNanos
     * @return AAUDIO_OK or AAUDIO_ERROR_UNAVAILABLE or other negative error
     */
    virtual aaudio_result_t getFreeRunningPosition_l(
            int64_t *positionFrames, int64_t *timeNanos) = 0;

    virtual aaudio_result_t getHardwareTimestamp_l(int64_t *positionFrames, int64_t *timeNanos) = 0;

    virtual aaudio_result_t getAudioDataDescription_l(AudioEndpointParcelable* parcelable) = 0;


    aaudio_stream_state_t   mState = AAUDIO_STREAM_STATE_UNINITIALIZED;

    bool isDisconnected_l() const REQUIRES(mLock) {
        return mDisconnected;
    }
    void setDisconnected_l(bool flag) REQUIRES(mLock) {
        mDisconnected = flag;
    }

    virtual aaudio_result_t standby_l() REQUIRES(mLock) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }
    class ExitStandbyParam : public AAudioCommandParam {
    public:
        explicit ExitStandbyParam(AudioEndpointParcelable* parcelable)
                : AAudioCommandParam(), mParcelable(parcelable) { }
        ~ExitStandbyParam() override = default;

        AudioEndpointParcelable* mParcelable;
    };
    virtual aaudio_result_t exitStandby_l(
            AudioEndpointParcelable* parcelable __unused) REQUIRES(mLock) {
        return AAUDIO_ERROR_UNAVAILABLE;
    }
    bool isStandby_l() const REQUIRES(mLock) {
        return mStandby;
    }
    void setStandby_l(bool standby) REQUIRES(mLock) {
        mStandby = standby;
    }

    bool isIdle_l() const REQUIRES(mLock) {
        return mState == AAUDIO_STREAM_STATE_OPEN || mState == AAUDIO_STREAM_STATE_PAUSED
                || mState == AAUDIO_STREAM_STATE_STOPPED;
    }

    virtual int64_t nextDataReportTime_l() REQUIRES(mLock) {
        return std::numeric_limits<int64_t>::max();
    }
    virtual void reportData_l() REQUIRES(mLock) { return; }

    pid_t                   mRegisteredClientThread = ILLEGAL_THREAD_ID;

    std::mutex              mUpMessageQueueLock;
    std::shared_ptr<SharedRingBuffer> mUpMessageQueue PT_GUARDED_BY(mUpMessageQueueLock);

    enum : int32_t {
        START,
        PAUSE,
        STOP,
        FLUSH,
        CLOSE,
        DISCONNECT,
        REGISTER_AUDIO_THREAD,
        UNREGISTER_AUDIO_THREAD,
        GET_DESCRIPTION,
        EXIT_STANDBY,
    };
    AAudioThread            mCommandThread;
    std::atomic_bool        mThreadEnabled{false};
    AAudioCommandQueue      mCommandQueue;

    int32_t                 mFramesPerBurst = 0;
    android::AudioClient    mMmapClient; // set in open, used in MMAP start()
    // TODO rename mClientHandle to mPortHandle to be more consistent with AudioFlinger.
    audio_port_handle_t     mClientHandle = AUDIO_PORT_HANDLE_NONE;

    SimpleDoubleBuffer<Timestamp>  mAtomicStreamTimestamp;

    android::AAudioService &mAudioService;

    // The mServiceEndpoint variable can be accessed by multiple threads.
    // So we access it by locally promoting a weak pointer to a smart pointer,
    // which is thread-safe.
    android::sp<AAudioServiceEndpoint> mServiceEndpoint;
    android::wp<AAudioServiceEndpoint> mServiceEndpointWeak;

    std::string mMetricsId;  // set once during open()

private:

    aaudio_result_t stopTimestampThread();

    /**
     * Send a message to the client with an int64_t data value.
     */
    aaudio_result_t sendServiceEvent(aaudio_service_event_t event,
                                     int64_t dataLong = 0);
    /**
     * Send a message to the client with a double data value.
     */
    aaudio_result_t sendServiceEvent(aaudio_service_event_t event,
                                     double dataDouble);

    aaudio_result_t sendCommand(aaudio_command_opcode opCode,
                                std::shared_ptr<AAudioCommandParam> param = nullptr,
                                bool waitForReply = false,
                                int64_t timeoutNanos = 0);

    void stopCommandThread();

    aaudio_result_t closeAndClear();

    /**
     * @return true if the queue is getting full.
     */
    bool isUpMessageQueueBusy() EXCLUDES(mUpMessageQueueLock);

    aaudio_handle_t         mHandle = -1;
    bool                    mFlowing = false;

    // This indicate that a running stream should not be processed because of an error,
    // for example a full message queue.
    std::atomic<bool>       mSuspended{false};

    bool                    mDisconnected GUARDED_BY(mLock) {false};

    bool                    mStandby GUARDED_BY(mLock) = false;

protected:
    // Locking order is important.
    // Acquire mLock before acquiring AAudioServiceEndpoint::mLockStreams
    // The lock will be held by the command thread. All operations needing the lock must run from
    // the command thread.
    std::mutex              mLock; // Prevent start/stop/close etcetera from colliding
};

} /* namespace aaudio */

#endif //AAUDIO_AAUDIO_SERVICE_STREAM_BASE_H
