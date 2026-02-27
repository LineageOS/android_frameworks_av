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

// go/keep-sorted start
#include <aaudio/AAudio.h>
#include <android-base/thread_annotations.h>
#include <binder/IServiceManager.h>
#include <binder/Status.h>
#include <media/AudioContainers.h>
#include <media/AudioResamplerPublic.h>
#include <media/PlayerBase.h>
#include <media/VolumeShaper.h>
#include <mediautils/SingleThreadExecutor.h>
#include <utility/AAudioUtilities.h>
#include <utility/MonotonicCounter.h>
#include <utils/StrongPointer.h>
// go/keep-sorted end

// go/keep-sorted start
#include <atomic>
#include <mutex>
#include <set>
#include <stdint.h>
// go/keep-sorted end

#include "AAudioStreamOpenRequest.h"

// Cannot get android::media::VolumeShaper to compile!
#define AAUDIO_USE_VOLUME_SHAPER  0

namespace aaudio {

typedef void *(*aaudio_audio_thread_proc_t)(void *);
typedef uint32_t aaudio_stream_id_t;

constexpr pid_t        CALLBACK_THREAD_NONE = 0;

/**
 * AAudio audio stream.
 */
class AudioStream : public virtual android::RefBase {
public:

    AudioStream();

    virtual ~AudioStream();

    static AAudio_FlushFromFrameSupport getFlushFromFrameSupport(
            const AAudioStreamOpenRequest& request);

protected:

    /**
     * Check the state to see if Pause is currently legal.
     *
     * @param result pointer to return code
     * @return true if OK to continue, if false then return result
     */
    bool checkPauseStateTransition(aaudio_result_t *result);

    virtual bool isFlushSupported() const {
        // Only implement FLUSH for OUTPUT streams.
        return false;
    }

    virtual bool isPauseSupported() const {
        // Only implement PAUSE for OUTPUT streams.
        return false;
    }

    /* Asynchronous requests.
     * Use waitForStateChange() to wait for completion.
     */
    virtual aaudio_result_t requestStart_l() REQUIRES(mStreamMutex) = 0;

    virtual aaudio_result_t requestPause_l() REQUIRES(mStreamMutex) {
        // Only implement this for OUTPUT streams.
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual aaudio_result_t requestFlush_l() REQUIRES(mStreamMutex) {
        // Only implement this for OUTPUT streams.
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual aaudio_result_t requestStop_l() REQUIRES(mStreamMutex) = 0;

    virtual aaudio_result_t flushFromFrame_l(AAudio_FlushFromAccuracy accuracy [[maybe_unused]],
                                             int64_t* position [[maybe_unused]])
                                             REQUIRES(mStreamMutex) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual aaudio_result_t setPlaybackParameters_l(
            const AAudioPlaybackParameters* parameters [[maybe_unused]])
            REQUIRES(mStreamMutex) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }
    virtual aaudio_result_t getPlaybackParameters_l(
            AAudioPlaybackParameters* parameters [[maybe_unused]])
            REQUIRES(mStreamMutex) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

public:
    virtual aaudio_result_t getTimestamp(clockid_t clockId,
                                       int64_t *framePosition,
                                       int64_t *timeNanoseconds) = 0;

    /**
     * Update state machine.
     * @return result of the operation.
     */
    aaudio_result_t updateStateMachine() {
        if (isDataCallbackActive()) {
            return AAUDIO_OK; // state is getting updated by the callback thread read/write call
        }
        return processCommands();
    };

    virtual aaudio_result_t processCommands() = 0;

    // =========== End ABSTRACT methods ===========================

    virtual aaudio_result_t waitForStateChange(aaudio_stream_state_t currentState,
                                               aaudio_stream_state_t *nextState,
                                               int64_t timeoutNanoseconds);

    /**
     * Open the stream using the parameters in the openRequest.
     * Allocate the necessary resources.
     */
    virtual aaudio_result_t open(const AAudioStreamOpenRequest& openRequest);

    // log to MediaMetrics
    virtual void logOpenActual();
    void logReleaseBufferState();

    /* Note about naming for "release"  and "close" related methods.
     *
     * These names are intended to match the public AAudio API.
     * The original AAudio API had an AAudioStream_close() function that
     * released the hardware and deleted the stream. That made it difficult
     * because apps want to release the HW ASAP but are not in a rush to delete
     * the stream object. So in R we added an AAudioStream_release() function
     * that just released the hardware.
     * The AAudioStream_close() method releases if needed and then closes.
     */

protected:
    /**
     * Free any hardware or system resources from the open() call.
     * It is safe to call release_l() multiple times.
     */
    virtual aaudio_result_t release_l() REQUIRES(mStreamMutex) {
        setState(AAUDIO_STREAM_STATE_CLOSING);
        return AAUDIO_OK;
    }

    /**
     * Free any resources not already freed by release_l().
     * Assume release_l() already called.
     */
    virtual void close_l() REQUIRES(mStreamMutex);

public:
    // This is only used to identify a stream in the logs without
    // revealing any pointers.
    aaudio_stream_id_t getId() {
        return mStreamId;
    }

    virtual aaudio_result_t setBufferSize(int32_t requestedFrames) = 0;

    aaudio_result_t createThread(int64_t periodNanoseconds,
                                 aaudio_audio_thread_proc_t threadProc,
                                 void *threadArg)
                                 EXCLUDES(mStreamMutex) {
        std::lock_guard<std::mutex> lock(mStreamMutex);
        return createThread_l(periodNanoseconds, threadProc, threadArg);
    }

    aaudio_result_t joinThread(void **returnArg) EXCLUDES(mStreamMutex);

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
        return mState.load();
    }

    aaudio_stream_state_t getStateExternal() const;

    virtual int32_t getBufferSize() const {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual int32_t getBufferCapacity() const {
        return mBufferCapacity;
    }

    virtual int32_t getDeviceBufferCapacity() const {
        return mDeviceBufferCapacity;
    }

    virtual int32_t getFramesPerBurst() const {
        return mFramesPerBurst;
    }

    virtual int32_t getDeviceFramesPerBurst() const {
        return mDeviceFramesPerBurst;
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

    aaudio_result_t getDeviceSampleRate() const {
        return mDeviceSampleRate;
    }

    aaudio_result_t getHardwareSampleRate() const {
        return mHardwareSampleRate;
    }

    audio_format_t getFormat()  const {
        return mFormat;
    }

    audio_format_t getHardwareFormat()  const {
        return mHardwareFormat;
    }

    aaudio_result_t getSamplesPerFrame() const {
        return mSamplesPerFrame;
    }

    aaudio_result_t getDeviceSamplesPerFrame() const {
        return mDeviceSamplesPerFrame;
    }

    aaudio_result_t getHardwareSamplesPerFrame() const {
        return mHardwareSamplesPerFrame;
    }

    virtual int32_t getPerformanceMode() const {
        return mPerformanceMode;
    }

    void setPerformanceMode(aaudio_performance_mode_t performanceMode) {
        mPerformanceMode = performanceMode;
    }

    android::DeviceIdVector getDeviceIds() const {
        return mDeviceIds;
    }

    aaudio_sharing_mode_t getSharingMode() const {
        return mSharingMode;
    }

    bool isSharingModeMatchRequired() const {
        return mSharingModeMatchRequired;
    }

    void setSharingModeMatchRequired(bool sharingModeMatchRequired) {
        mSharingModeMatchRequired = sharingModeMatchRequired;
    }

    virtual aaudio_direction_t getDirection() const = 0;

    aaudio_usage_t getUsage() const {
        return mUsage;
    }

    aaudio_content_type_t getContentType() const {
        return mContentType;
    }

    const std::set<std::string>& getTags() const {
        return mTags;
    }

    aaudio_spatialization_behavior_t getSpatializationBehavior() const {
        return mSpatializationBehavior;
    }

    bool isContentSpatialized() const {
        return mIsContentSpatialized;
    }

    aaudio_input_preset_t getInputPreset() const {
        return mInputPreset;
    }

    aaudio_allowed_capture_policy_t getAllowedCapturePolicy() const {
        return mAllowedCapturePolicy;
    }

    int32_t getSessionId() const {
        return mSessionId;
    }

    bool isPrivacySensitive() const {
        return mIsPrivacySensitive;
    }

    bool getRequireMonoBlend() const {
        return mRequireMonoBlend;
    }

    float getAudioBalance() const {
        return mAudioBalance;
    }

    /**
     * This is only valid after setChannelMask() and setFormat()
     * have been called.
     */
    int32_t getBytesPerFrame() const {
        return audio_bytes_per_frame(mSamplesPerFrame, mFormat);
    }

    /**
     * This is only valid after setFormat() has been called.
     */
    int32_t getBytesPerSample() const {
        return audio_bytes_per_sample(mFormat);
    }

    /**
     * This is only valid after setDeviceSamplesPerFrame() and setDeviceFormat() have been called.
     */
    int32_t getBytesPerDeviceFrame() const {
        return audio_bytes_per_frame(getDeviceSamplesPerFrame(), getDeviceFormat());
    }

    virtual int64_t getFramesWritten() = 0;

    virtual int64_t getFramesRead() = 0;

    typedef int (AudioStream::*DataCallbackWrapper)(void* audioData, int32_t numFrames);
    DataCallbackWrapper getDataCallbackWrapper() const {
        return mDataCallbackWrapper;
    }

    AAudioStream_errorCallback getErrorCallbackProc() const {
        return mErrorCallbackProc;
    }

    int32_t maybeCallDataCallback(void *audioData, int32_t numFrames);

    void maybeCallErrorCallback(aaudio_result_t result);

    void *getDataCallbackUserData() const {
        return mDataCallbackUserData;
    }

    void *getErrorCallbackUserData() const {
        return mErrorCallbackUserData;
    }

    int32_t getFramesPerDataCallback() const {
        return mFramesPerDataCallback;
    }

    aaudio_channel_mask_t getChannelMask() const {
        return mChannelMask;
    }

    void setChannelMask(aaudio_channel_mask_t channelMask) {
        mChannelMask = channelMask;
        mSamplesPerFrame = AAudioConvert_channelMaskToCount(channelMask);
    }

    void setDeviceSamplesPerFrame(int32_t deviceSamplesPerFrame) {
        mDeviceSamplesPerFrame = deviceSamplesPerFrame;
    }

    audio_format_t getDeviceFormat() const {
        return mDeviceFormat;
    }

    virtual aaudio_result_t setOffloadDelayPadding(int32_t delayInFrames [[maybe_unused]],
                                                   int32_t paddingInFrames [[maybe_unused]]) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual int32_t getOffloadDelay() {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual int32_t getOffloadPadding() {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual aaudio_result_t setOffloadEndOfStream() EXCLUDES(mStreamMutex) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual void setPresentationEndCallbackProc(
            AAudioStream_presentationEndCallback proc [[maybe_unused]]) { }
    virtual void setPresentationEndCallbackUserData(void* userData [[maybe_unused]]) { }

    /**
     * @return true if data callback has been specified
     */
    bool isDataCallbackSet() const {
        return mDataCallbackWrapper != nullptr;
    }

    /**
     * @return true if data callback has been specified and stream is running
     */
    bool isDataCallbackActive() const {
        return isDataCallbackSet() && isActive();
    }

    /**
     * @return true if called from the same thread as the callback
     */
    virtual bool collidesWithCallback() const;

    AAudioStream_routingChangedCallback getRoutingChangedCallback() const {
        return mRoutingChangedCallbackProc;
    }
    void* getRoutingChangedCallbackUserData() const {
        return mRoutingChangedCallbackUserData;
    }

    void maybeSignalRoutingChangedCallback();

    // ============== I/O ===========================
    // A Stream will only implement read() or write() depending on its direction.
    virtual aaudio_result_t write(const void *buffer __unused,
                             int32_t numFrames __unused,
                             int64_t timeoutNanoseconds __unused) EXCLUDES(mStreamMutex) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    virtual aaudio_result_t read(void *buffer __unused,
                            int32_t numFrames __unused,
                            int64_t timeoutNanoseconds __unused) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    // This is used by the AudioManager to duck and mute the stream when changing audio focus.
    void setDuckAndMuteVolume(float duckAndMuteVolume) EXCLUDES(mStreamMutex);

    float getDuckAndMuteVolume() const {
        return mDuckAndMuteVolume;
    }

    // Implement this in the output subclasses.
    virtual android::status_t doSetVolume() { return android::NO_ERROR; }

#if AAUDIO_USE_VOLUME_SHAPER
    virtual ::android::binder::Status applyVolumeShaper(
            const ::android::media::VolumeShaper::Configuration& configuration __unused,
            const ::android::media::VolumeShaper::Operation& operation __unused);
#endif

    /**
     * Register this stream's PlayerBase with the AudioManager if needed.
     * Only register output streams.
     * This should only be called for client streams and not for streams
     * that run in the service.
     */
    virtual void registerPlayerBase() {
        if (getDirection() == AAUDIO_DIRECTION_OUTPUT) {
            mPlayerBase->registerWithAudioManager(this);
        }
    }

    /**
     * Unregister this stream's PlayerBase with the AudioManager.
     * This will only unregister if already registered.
     */
    void unregisterPlayerBase() {
        mPlayerBase->unregisterWithAudioManager();
    }

    aaudio_result_t systemStart() EXCLUDES(mStreamMutex);

    aaudio_result_t systemPause() EXCLUDES(mStreamMutex);

    aaudio_result_t safeFlush() EXCLUDES(mStreamMutex);

    /**
     * This is called when an app calls AAudioStream_requestStop();
     * It prevents calls from a callback.
     */
    aaudio_result_t systemStopFromApp();

    /**
     * This is called internally when an app callback returns AAUDIO_CALLBACK_RESULT_STOP.
     */
    aaudio_result_t systemStopInternal() EXCLUDES(mStreamMutex);

    /**
     * Safely RELEASE a stream after taking mStreamMutex and checking
     * to make sure we are not being called from a callback.
     * @return AAUDIO_OK or a negative error
     */
    aaudio_result_t safeRelease() EXCLUDES(mStreamMutex);

    /**
     * Safely RELEASE and CLOSE a stream after taking mStreamMutex and checking
     * to make sure we are not being called from a callback.
     * @return AAUDIO_OK or a negative error
     */
    aaudio_result_t safeReleaseClose();

    aaudio_result_t safeReleaseCloseInternal() EXCLUDES(mStreamMutex);

    aaudio_result_t flushFromFrame(AAudio_FlushFromAccuracy accuracy, int64_t* position)
            EXCLUDES(mStreamMutex);

    aaudio_result_t setPlaybackParameters(const AAudioPlaybackParameters* parameters)
            EXCLUDES(mStreamMutex);
    aaudio_result_t getPlaybackParameters(struct AAudioPlaybackParameters* parameters)
            EXCLUDES(mStreamMutex);

protected:

    // PlayerBase allows the system to control the stream volume.
    class MyPlayerBase : public android::PlayerBase {
    public:
        MyPlayerBase() = default;

        virtual ~MyPlayerBase() = default;

        /**
         * Register for volume changes and remote control.
         */
        void registerWithAudioManager(const android::sp<AudioStream>& parent);

        /**
         * UnRegister.
         */
        void unregisterWithAudioManager();

        /**
         * Just calls unregisterWithAudioManager().
         */
        void destroy() override;

        // Just a stub. The ability to start audio through PlayerBase is being deprecated.
        android::status_t playerStart() override {
            return android::NO_ERROR;
        }

        // Just a stub. The ability to pause audio through PlayerBase is being deprecated.
        android::status_t playerPause() override {
            return android::NO_ERROR;
        }

        // Just a stub. The ability to stop audio through PlayerBase is being deprecated.
        android::status_t playerStop() override {
            return android::NO_ERROR;
        }

        android::status_t playerSetVolume() EXCLUDES(mSettingsMutex) override;

#if AAUDIO_USE_VOLUME_SHAPER
        ::android::binder::Status applyVolumeShaper();
#endif

        aaudio_result_t getResult() {
            return mResult;
        }

        // Returns the playerIId if registered, -1 otherwise.
        int32_t getPlayerIId() const {
            return mPIId;
        }

    private:
        // Use a weak pointer so the AudioStream can be deleted.
        std::mutex               mParentLock;
        android::wp<AudioStream> mParent GUARDED_BY(mParentLock);
        aaudio_result_t          mResult = AAUDIO_OK;
        bool                     mRegistered = false;
    };

    /**
     * This should not be called after the open() call.
     * TODO for multiple setters: assert(mState == AAUDIO_STREAM_STATE_UNINITIALIZED)
     */
    void setSampleRate(int32_t sampleRate) {
        mSampleRate = sampleRate;
    }

    // This should not be called after the open() call.
    void setDeviceSampleRate(int32_t deviceSampleRate) {
        mDeviceSampleRate = deviceSampleRate;
    }

    // This should not be called after the open() call.
    void setHardwareSampleRate(int32_t hardwareSampleRate) {
        mHardwareSampleRate = hardwareSampleRate;
    }

    // This should not be called after the open() call.
    void setFramesPerBurst(int32_t framesPerBurst) {
        mFramesPerBurst = framesPerBurst;
    }

    // This should not be called after the open() call.
    void setDeviceFramesPerBurst(int32_t deviceFramesPerBurst) {
        mDeviceFramesPerBurst = deviceFramesPerBurst;
    }

    // This should not be called after the open() call.
    void setBufferCapacity(int32_t bufferCapacity) {
        mBufferCapacity = bufferCapacity;
    }

    // This should not be called after the open() call.
    void setDeviceBufferCapacity(int32_t deviceBufferCapacity) {
        mDeviceBufferCapacity = deviceBufferCapacity;
    }

    // This should not be called after the open() call.
    void setSharingMode(aaudio_sharing_mode_t sharingMode) {
        mSharingMode = sharingMode;
    }

    // This should not be called after the open() call.
    void setFormat(audio_format_t format) {
        mFormat = format;
    }

    // This should not be called after the open() call.
    void setHardwareFormat(audio_format_t format) {
        mHardwareFormat = format;
    }

    // This should not be called after the open() call.
    void setHardwareSamplesPerFrame(int32_t hardwareSamplesPerFrame) {
        mHardwareSamplesPerFrame = hardwareSamplesPerFrame;
    }

    // This should not be called after the open() call.
    void setDeviceFormat(audio_format_t format) {
        mDeviceFormat = format;
    }

    void setState(aaudio_stream_state_t state);

    bool isDisconnected() const {
        return mDisconnected.load();
    }
    void setDisconnected();

    void setDeviceIds(const android::DeviceIdVector& deviceIds) {
        mDeviceIds = deviceIds;
    }

    // This should not be called after the open() call.
    void setSessionId(int32_t sessionId) {
        mSessionId = sessionId;
    }

    aaudio_result_t createThread_l(int64_t periodNanoseconds,
                                           aaudio_audio_thread_proc_t threadProc,
                                           void *threadArg)
                                           REQUIRES(mStreamMutex);

    aaudio_result_t joinThread_l(void **returnArg) REQUIRES(mStreamMutex);

    virtual aaudio_result_t systemStopInternal_l() REQUIRES(mStreamMutex);

    std::atomic<bool>    mCallbackEnabled{false};

    float                mDuckAndMuteVolume = 1.0f;

protected:

    /**
     * Either convert the data from device format to app format and return a pointer
     * to the conversion buffer,
     * OR just pass back the original pointer.
     *
     * Note that this is only used for the INPUT path.
     *
     * @param audioData
     * @param numFrames
     * @return original pointer or the conversion buffer
     */
    virtual const void * maybeConvertDeviceData(const void *audioData, int32_t /*numFrames*/) {
        return audioData;
    }

    void setPeriodNanoseconds(int64_t periodNanoseconds) {
        mPeriodNanoseconds.store(periodNanoseconds, std::memory_order_release);
    }

    int64_t getPeriodNanoseconds() {
        return mPeriodNanoseconds.load(std::memory_order_acquire);
    }

    /**
     * This should not be called after the open() call.
     */
    void setUsage(aaudio_usage_t usage) {
        mUsage = usage;
    }

    /**
     * This should not be called after the open() call.
     */
    void setContentType(aaudio_content_type_t contentType) {
        mContentType = contentType;
    }

    /**
     * This should not be called after the open() call.
     */
    void setTags(const std::set<std::string> &tags) {
        mTags = tags;
    }

    std::string getTagsAsString() const;

    void setSpatializationBehavior(aaudio_spatialization_behavior_t spatializationBehavior) {
        mSpatializationBehavior = spatializationBehavior;
    }

    void setIsContentSpatialized(bool isContentSpatialized) {
        mIsContentSpatialized = isContentSpatialized;
    }

    /**
     * This should not be called after the open() call.
     */
    void setInputPreset(aaudio_input_preset_t inputPreset) {
        mInputPreset = inputPreset;
    }

    /**
     * This should not be called after the open() call.
     */
    void setAllowedCapturePolicy(aaudio_allowed_capture_policy_t policy) {
        mAllowedCapturePolicy = policy;
    }

    /**
     * This should not be called after the open() call.
     */
    void setPrivacySensitive(bool privacySensitive) {
        mIsPrivacySensitive = privacySensitive;
    }

    /**
     * This should not be called after the open() call.
     */
    void setRequireMonoBlend(bool requireMonoBlend) {
        mRequireMonoBlend = requireMonoBlend;
    }

    /**
     * This should not be called after the open() call.
     */
    void setAudioBalance(float audioBalance) {
        mAudioBalance = audioBalance;
    }

    aaudio_result_t safeStop_l() REQUIRES(mStreamMutex);

    std::string mMetricsId; // set once during open()

    std::mutex                 mStreamMutex;

    const android::sp<MyPlayerBase>   mPlayerBase;

    std::optional<android::mediautils::SingleThreadExecutor> mEventExecutor;

private:

    /**
     * Release then close the stream.
     */
    void releaseCloseFinal_l() REQUIRES(mStreamMutex) {
        if (getState() != AAUDIO_STREAM_STATE_CLOSING) { // not already released?
            // Ignore result and keep closing.
            (void) release_l();
        }
        close_l();
    }

    int dataCallbackInternal(void* audioData, int32_t numFrames);
    int partialDataCallbackInternal(void* audioData, int32_t numFrames);

    std::atomic<aaudio_stream_state_t>          mState{AAUDIO_STREAM_STATE_UNINITIALIZED};

    std::atomic_bool            mDisconnected{false};

    // These do not change after open().
    int32_t                     mSamplesPerFrame = AAUDIO_UNSPECIFIED;
    int32_t                     mDeviceSamplesPerFrame = AAUDIO_UNSPECIFIED;
    int32_t                     mHardwareSamplesPerFrame = AAUDIO_UNSPECIFIED;
    aaudio_channel_mask_t       mChannelMask = AAUDIO_UNSPECIFIED;
    int32_t                     mSampleRate = AAUDIO_UNSPECIFIED;
    int32_t                     mDeviceSampleRate = AAUDIO_UNSPECIFIED;
    int32_t                     mHardwareSampleRate = AAUDIO_UNSPECIFIED;
    android::DeviceIdVector     mDeviceIds;
    aaudio_sharing_mode_t       mSharingMode = AAUDIO_SHARING_MODE_SHARED;
    bool                        mSharingModeMatchRequired = false; // must match sharing mode requested
    audio_format_t              mFormat = AUDIO_FORMAT_DEFAULT;
    audio_format_t              mHardwareFormat = AUDIO_FORMAT_DEFAULT;
    aaudio_performance_mode_t   mPerformanceMode = AAUDIO_PERFORMANCE_MODE_NONE;
    int32_t                     mFramesPerBurst = 0;
    int32_t                     mDeviceFramesPerBurst = 0;
    int32_t                     mBufferCapacity = 0;
    int32_t                     mDeviceBufferCapacity = 0;

    aaudio_usage_t              mUsage           = AAUDIO_UNSPECIFIED;
    aaudio_content_type_t       mContentType     = AAUDIO_UNSPECIFIED;
    std::set<std::string>       mTags;
    aaudio_spatialization_behavior_t mSpatializationBehavior = AAUDIO_UNSPECIFIED;
    bool                        mIsContentSpatialized = false;
    aaudio_input_preset_t       mInputPreset     = AAUDIO_UNSPECIFIED;
    aaudio_allowed_capture_policy_t mAllowedCapturePolicy = AAUDIO_ALLOW_CAPTURE_BY_ALL;
    bool                        mIsPrivacySensitive = false;
    bool                        mRequireMonoBlend = false;
    float                       mAudioBalance = 0;

    int32_t                     mSessionId = AAUDIO_UNSPECIFIED;

    // Sometimes the hardware is operating with a different format from the app.
    // Then we require conversion in AAudio.
    audio_format_t              mDeviceFormat = AUDIO_FORMAT_INVALID;

    // callback ----------------------------------

    AAudioStream_dataCallback   mDataCallbackProc = nullptr;  // external callback functions
    void                       *mDataCallbackUserData = nullptr;
    int32_t                     mFramesPerDataCallback = AAUDIO_UNSPECIFIED; // frames
    std::atomic<pid_t>          mDataCallbackThread{CALLBACK_THREAD_NONE};
    AAudioStream_partialDataCallback mPartialDataCallbackProc = nullptr;
    DataCallbackWrapper         mDataCallbackWrapper = nullptr;

    AAudioStream_errorCallback  mErrorCallbackProc = nullptr;
    void                       *mErrorCallbackUserData = nullptr;
    std::atomic<pid_t>          mErrorCallbackThread{CALLBACK_THREAD_NONE};

    AAudioStream_routingChangedCallback mRoutingChangedCallbackProc = nullptr;
    void                               *mRoutingChangedCallbackUserData = nullptr;

    // background thread ----------------------------------
    // Use mHasThread to prevent joining twice, which has undefined behavior.
    bool                        mHasThread GUARDED_BY(mStreamMutex) = false;
    pthread_t                   mThread  GUARDED_BY(mStreamMutex) = {};

    // These are set by the application thread and then read by the audio pthread.
    std::atomic<int64_t>        mPeriodNanoseconds; // for tuning SCHED_FIFO threads
    // TODO make atomic?
    aaudio_audio_thread_proc_t  mThreadProc = nullptr;
    void                       *mThreadArg = nullptr;
    aaudio_result_t             mThreadRegistrationResult = AAUDIO_OK;

    const aaudio_stream_id_t    mStreamId;

};

} /* namespace aaudio */

#endif /* AAUDIO_AUDIOSTREAM_H */
