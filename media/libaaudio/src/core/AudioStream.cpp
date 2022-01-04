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

#define LOG_TAG "AAudioStream"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <atomic>
#include <stdint.h>

#include <media/MediaMetricsItem.h>

#include <aaudio/AAudio.h>

#include "AudioStreamBuilder.h"
#include "AudioStream.h"
#include "AudioClock.h"
#include "AudioGlobal.h"

namespace aaudio {

// Sequential number assigned to streams solely for debugging purposes.
static aaudio_stream_id_t AAudio_getNextStreamId() {
    static std::atomic <aaudio_stream_id_t> nextStreamId{1};
    return nextStreamId++;
}

AudioStream::AudioStream()
        : mPlayerBase(new MyPlayerBase())
        , mStreamId(AAudio_getNextStreamId())
        {
    setPeriodNanoseconds(0);
}

AudioStream::~AudioStream() {
    // Please preserve these logs because there have been several bugs related to
    // AudioStream deletion and late callbacks.
    ALOGD("%s(s#%u) mPlayerBase strongCount = %d",
            __func__, getId(), mPlayerBase->getStrongCount());

    ALOGE_IF(pthread_equal(pthread_self(), mThread),
            "%s() destructor running in callback", __func__);

    ALOGE_IF(mHasThread, "%s() callback thread never join()ed", __func__);

    // If the stream is deleted when OPEN or in use then audio resources will leak.
    // This would indicate an internal error. So we want to find this ASAP.
    LOG_ALWAYS_FATAL_IF(!(getState() == AAUDIO_STREAM_STATE_CLOSED
                          || getState() == AAUDIO_STREAM_STATE_UNINITIALIZED
                          || getState() == AAUDIO_STREAM_STATE_DISCONNECTED),
                        "~AudioStream() - still in use, state = %s",
                        AudioGlobal_convertStreamStateToText(getState()));
}

aaudio_result_t AudioStream::open(const AudioStreamBuilder& builder)
{
    // Call here as well because the AAudioService will call this without calling build().
    aaudio_result_t result = builder.validate();
    if (result != AAUDIO_OK) {
        return result;
    }

    // Copy parameters from the Builder because the Builder may be deleted after this call.
    // TODO AudioStream should be a subclass of AudioStreamParameters
    mSamplesPerFrame = builder.getSamplesPerFrame();
    mChannelMask = builder.getChannelMask();
    mSampleRate = builder.getSampleRate();
    mDeviceId = builder.getDeviceId();
    mFormat = builder.getFormat();
    mSharingMode = builder.getSharingMode();
    mSharingModeMatchRequired = builder.isSharingModeMatchRequired();
    mPerformanceMode = builder.getPerformanceMode();

    mUsage = builder.getUsage();
    if (mUsage == AAUDIO_UNSPECIFIED) {
        mUsage = AAUDIO_USAGE_MEDIA;
    }
    mContentType = builder.getContentType();
    if (mContentType == AAUDIO_UNSPECIFIED) {
        mContentType = AAUDIO_CONTENT_TYPE_MUSIC;
    }
    mSpatializationBehavior = builder.getSpatializationBehavior();
    // for consistency with other properties, note UNSPECIFIED is the same as AUTO
    if (mSpatializationBehavior == AAUDIO_UNSPECIFIED) {
        mSpatializationBehavior = AAUDIO_SPATIALIZATION_BEHAVIOR_AUTO;
    }
    mIsContentSpatialized = builder.isContentSpatialized();
    mInputPreset = builder.getInputPreset();
    if (mInputPreset == AAUDIO_UNSPECIFIED) {
        mInputPreset = AAUDIO_INPUT_PRESET_VOICE_RECOGNITION;
    }
    mAllowedCapturePolicy = builder.getAllowedCapturePolicy();
    if (mAllowedCapturePolicy == AAUDIO_UNSPECIFIED) {
        mAllowedCapturePolicy = AAUDIO_ALLOW_CAPTURE_BY_ALL;
    }
    mIsPrivacySensitive = builder.isPrivacySensitive();

    // callbacks
    mFramesPerDataCallback = builder.getFramesPerDataCallback();
    mDataCallbackProc = builder.getDataCallbackProc();
    mErrorCallbackProc = builder.getErrorCallbackProc();
    mDataCallbackUserData = builder.getDataCallbackUserData();
    mErrorCallbackUserData = builder.getErrorCallbackUserData();

    return AAUDIO_OK;
}

void AudioStream::logOpenActual() {
    if (mMetricsId.size() > 0) {
        android::mediametrics::LogItem item(mMetricsId);
        item.set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_OPEN)
            .set(AMEDIAMETRICS_PROP_PERFORMANCEMODEACTUAL,
                AudioGlobal_convertPerformanceModeToText(getPerformanceMode()))
            .set(AMEDIAMETRICS_PROP_SHARINGMODEACTUAL,
                AudioGlobal_convertSharingModeToText(getSharingMode()))
            .set(AMEDIAMETRICS_PROP_BUFFERCAPACITYFRAMES, getBufferCapacity())
            .set(AMEDIAMETRICS_PROP_BURSTFRAMES, getFramesPerBurst())
            .set(AMEDIAMETRICS_PROP_DIRECTION,
                AudioGlobal_convertDirectionToText(getDirection()));

        if (getDirection() == AAUDIO_DIRECTION_OUTPUT) {
            item.set(AMEDIAMETRICS_PROP_PLAYERIID, mPlayerBase->getPlayerIId());
        }
        item.record();
    }
}

void AudioStream::logReleaseBufferState() {
    if (mMetricsId.size() > 0) {
        android::mediametrics::LogItem(mMetricsId)
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_RELEASE)
                .set(AMEDIAMETRICS_PROP_BUFFERSIZEFRAMES, (int32_t) getBufferSize())
                .set(AMEDIAMETRICS_PROP_UNDERRUN, (int32_t) getXRunCount())
                .record();
    }
}

aaudio_result_t AudioStream::systemStart() {
    if (collidesWithCallback()) {
        ALOGE("%s cannot be called from a callback!", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }

    std::lock_guard<std::mutex> lock(mStreamLock);

    switch (getState()) {
        // Is this a good time to start?
        case AAUDIO_STREAM_STATE_OPEN:
        case AAUDIO_STREAM_STATE_PAUSING:
        case AAUDIO_STREAM_STATE_PAUSED:
        case AAUDIO_STREAM_STATE_STOPPING:
        case AAUDIO_STREAM_STATE_STOPPED:
        case AAUDIO_STREAM_STATE_FLUSHING:
        case AAUDIO_STREAM_STATE_FLUSHED:
            break; // Proceed with starting.

        // Already started?
        case AAUDIO_STREAM_STATE_STARTING:
        case AAUDIO_STREAM_STATE_STARTED:
            ALOGW("%s() stream was already started, state = %s", __func__,
                  AudioGlobal_convertStreamStateToText(getState()));
            return AAUDIO_ERROR_INVALID_STATE;

        // Don't start when the stream is dead!
        case AAUDIO_STREAM_STATE_DISCONNECTED:
        case AAUDIO_STREAM_STATE_CLOSING:
        case AAUDIO_STREAM_STATE_CLOSED:
        default:
            ALOGW("%s() stream is dead, state = %s", __func__,
                  AudioGlobal_convertStreamStateToText(getState()));
            return AAUDIO_ERROR_INVALID_STATE;
    }

    aaudio_result_t result = requestStart_l();
    if (result == AAUDIO_OK) {
        // We only call this for logging in "dumpsys audio". So ignore return code.
        (void) mPlayerBase->startWithStatus(getDeviceId());
    }
    return result;
}

aaudio_result_t AudioStream::systemPause() {

    if (!isPauseSupported()) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    if (collidesWithCallback()) {
        ALOGE("%s cannot be called from a callback!", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }

    std::lock_guard<std::mutex> lock(mStreamLock);
    switch (getState()) {
        // Proceed with pausing.
        case AAUDIO_STREAM_STATE_STARTING:
        case AAUDIO_STREAM_STATE_STARTED:
        case AAUDIO_STREAM_STATE_DISCONNECTED:
            break;

            // Transition from one inactive state to another.
        case AAUDIO_STREAM_STATE_OPEN:
        case AAUDIO_STREAM_STATE_STOPPED:
        case AAUDIO_STREAM_STATE_FLUSHED:
            setState(AAUDIO_STREAM_STATE_PAUSED);
            return AAUDIO_OK;

            // Redundant?
        case AAUDIO_STREAM_STATE_PAUSING:
        case AAUDIO_STREAM_STATE_PAUSED:
            return AAUDIO_OK;

            // Don't interfere with transitional states or when closed.
        case AAUDIO_STREAM_STATE_STOPPING:
        case AAUDIO_STREAM_STATE_FLUSHING:
        case AAUDIO_STREAM_STATE_CLOSING:
        case AAUDIO_STREAM_STATE_CLOSED:
        default:
            ALOGW("%s() stream not running, state = %s",
                  __func__, AudioGlobal_convertStreamStateToText(getState()));
            return AAUDIO_ERROR_INVALID_STATE;
    }

    aaudio_result_t result = requestPause_l();
    if (result == AAUDIO_OK) {
        // We only call this for logging in "dumpsys audio". So ignore return code.
        (void) mPlayerBase->pauseWithStatus();
    }
    return result;
}

aaudio_result_t AudioStream::safeFlush() {
    if (!isFlushSupported()) {
        ALOGE("flush not supported for this stream");
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    if (collidesWithCallback()) {
        ALOGE("stream cannot be flushed from a callback!");
        return AAUDIO_ERROR_INVALID_STATE;
    }

    std::lock_guard<std::mutex> lock(mStreamLock);
    aaudio_result_t result = AAudio_isFlushAllowed(getState());
    if (result != AAUDIO_OK) {
        return result;
    }

    return requestFlush_l();
}

aaudio_result_t AudioStream::systemStopInternal() {
    std::lock_guard<std::mutex> lock(mStreamLock);
    aaudio_result_t result = safeStop_l();
    if (result == AAUDIO_OK) {
        // We only call this for logging in "dumpsys audio". So ignore return code.
        (void) mPlayerBase->stopWithStatus();
    }
    return result;
}

aaudio_result_t AudioStream::systemStopFromApp() {
    // This check can and should be done outside the lock.
    if (collidesWithCallback()) {
        ALOGE("stream cannot be stopped by calling from a callback!");
        return AAUDIO_ERROR_INVALID_STATE;
    }
    return systemStopInternal();
}

aaudio_result_t AudioStream::safeStop_l() {

    switch (getState()) {
        // Proceed with stopping.
        case AAUDIO_STREAM_STATE_STARTING:
        case AAUDIO_STREAM_STATE_STARTED:
        case AAUDIO_STREAM_STATE_DISCONNECTED:
            break;

        // Transition from one inactive state to another.
        case AAUDIO_STREAM_STATE_OPEN:
        case AAUDIO_STREAM_STATE_PAUSED:
        case AAUDIO_STREAM_STATE_FLUSHED:
            setState(AAUDIO_STREAM_STATE_STOPPED);
            return AAUDIO_OK;

        // Redundant?
        case AAUDIO_STREAM_STATE_STOPPING:
        case AAUDIO_STREAM_STATE_STOPPED:
            return AAUDIO_OK;

        // Don't interfere with transitional states or when closed.
        case AAUDIO_STREAM_STATE_PAUSING:
        case AAUDIO_STREAM_STATE_FLUSHING:
        case AAUDIO_STREAM_STATE_CLOSING:
        case AAUDIO_STREAM_STATE_CLOSED:
        default:
            ALOGW("%s() stream not running, state = %s", __func__,
                  AudioGlobal_convertStreamStateToText(getState()));
            return AAUDIO_ERROR_INVALID_STATE;
    }

    return requestStop_l();
}

aaudio_result_t AudioStream::safeRelease() {
    if (collidesWithCallback()) {
        ALOGE("%s cannot be called from a callback!", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }
    // This may get temporarily unlocked in the MMAP release() when joining callback threads.
    std::lock_guard<std::mutex> lock(mStreamLock);
    if (getState() == AAUDIO_STREAM_STATE_CLOSING) { // already released?
        return AAUDIO_OK;
    }
    return release_l();
}

aaudio_result_t AudioStream::safeReleaseClose() {
    if (collidesWithCallback()) {
        ALOGE("%s cannot be called from a callback!", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }
    return safeReleaseCloseInternal();
}

aaudio_result_t AudioStream::safeReleaseCloseInternal() {
    // This get temporarily unlocked in the MMAP release() when joining callback threads.
    std::lock_guard<std::mutex> lock(mStreamLock);
    releaseCloseFinal_l();
    return AAUDIO_OK;
}

void AudioStream::close_l() {
    // Releasing the stream will set the state to CLOSING.
    assert(getState() == AAUDIO_STREAM_STATE_CLOSING);
    // setState() prevents a transition from CLOSING to any state other than CLOSED.
    // State is checked by destructor.
    setState(AAUDIO_STREAM_STATE_CLOSED);

    if (!mMetricsId.empty()) {
        android::mediametrics::LogItem(mMetricsId)
                .set(AMEDIAMETRICS_PROP_FRAMESTRANSFERRED,
                        getDirection() == AAUDIO_DIRECTION_INPUT ? getFramesWritten()
                                                                 : getFramesRead())
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAAUDIOSTREAM)
                .record();
    }
}

void AudioStream::setState(aaudio_stream_state_t state) {
    ALOGD("%s(s#%d) from %d to %d", __func__, getId(), mState, state);
    if (state == mState) {
        return; // no change
    }
    // Track transition to DISCONNECTED state.
    if (state == AAUDIO_STREAM_STATE_DISCONNECTED) {
        android::mediametrics::LogItem(mMetricsId)
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_DISCONNECT)
                .set(AMEDIAMETRICS_PROP_STATE, AudioGlobal_convertStreamStateToText(getState()))
                .record();
    }
    // CLOSED is a final state
    if (mState == AAUDIO_STREAM_STATE_CLOSED) {
        ALOGW("%s(%d) tried to set to %d but already CLOSED", __func__, getId(), state);

    // Once CLOSING, we can only move to CLOSED state.
    } else if (mState == AAUDIO_STREAM_STATE_CLOSING
               && state != AAUDIO_STREAM_STATE_CLOSED) {
        ALOGW("%s(%d) tried to set to %d but already CLOSING", __func__, getId(), state);

    // Once DISCONNECTED, we can only move to CLOSING or CLOSED state.
    } else if (mState == AAUDIO_STREAM_STATE_DISCONNECTED
               && !(state == AAUDIO_STREAM_STATE_CLOSING
                   || state == AAUDIO_STREAM_STATE_CLOSED)) {
        ALOGW("%s(%d) tried to set to %d but already DISCONNECTED", __func__, getId(), state);

    } else {
        mState = state;
    }
}

aaudio_result_t AudioStream::waitForStateChange(aaudio_stream_state_t currentState,
                                                aaudio_stream_state_t *nextState,
                                                int64_t timeoutNanoseconds)
{
    aaudio_result_t result = updateStateMachine();
    if (result != AAUDIO_OK) {
        return result;
    }

    int64_t durationNanos = 20 * AAUDIO_NANOS_PER_MILLISECOND; // arbitrary
    aaudio_stream_state_t state = getState();
    while (state == currentState && timeoutNanoseconds > 0) {
        if (durationNanos > timeoutNanoseconds) {
            durationNanos = timeoutNanoseconds;
        }
        AudioClock::sleepForNanos(durationNanos);
        timeoutNanoseconds -= durationNanos;

        aaudio_result_t result = updateStateMachine();
        if (result != AAUDIO_OK) {
            return result;
        }

        state = getState();
    }
    if (nextState != nullptr) {
        *nextState = state;
    }
    return (state == currentState) ? AAUDIO_ERROR_TIMEOUT : AAUDIO_OK;
}

// This registers the callback thread with the server before
// passing control to the app. This gives the server an opportunity to boost
// the thread's performance characteristics.
void* AudioStream::wrapUserThread() {
    void* procResult = nullptr;
    mThreadRegistrationResult = registerThread();
    if (mThreadRegistrationResult == AAUDIO_OK) {
        // Run callback loop. This may take a very long time.
        procResult = mThreadProc(mThreadArg);
        mThreadRegistrationResult = unregisterThread();
    }
    return procResult;
}


// This is the entry point for the new thread created by createThread_l().
// It converts the 'C' function call to a C++ method call.
static void* AudioStream_internalThreadProc(void* threadArg) {
    AudioStream *audioStream = (AudioStream *) threadArg;
    // Prevent the stream from being deleted while being used.
    // This is just for extra safety. It is probably not needed because
    // this callback should be joined before the stream is closed.
    android::sp<AudioStream> protectedStream(audioStream);
    // Balance the incStrong() in createThread_l().
    protectedStream->decStrong(nullptr);
    return protectedStream->wrapUserThread();
}

// This is not exposed in the API.
// But it is still used internally to implement callbacks for MMAP mode.
aaudio_result_t AudioStream::createThread_l(int64_t periodNanoseconds,
                                            aaudio_audio_thread_proc_t threadProc,
                                            void* threadArg)
{
    if (mHasThread) {
        ALOGD("%s() - previous thread was not joined, join now to be safe", __func__);
        joinThread_l(nullptr);
    }
    if (threadProc == nullptr) {
        return AAUDIO_ERROR_NULL;
    }
    // Pass input parameters to the background thread.
    mThreadProc = threadProc;
    mThreadArg = threadArg;
    setPeriodNanoseconds(periodNanoseconds);
    mHasThread = true;
    // Prevent this object from getting deleted before the thread has a chance to create
    // its strong pointer. Assume the thread will call decStrong().
    this->incStrong(nullptr);
    int err = pthread_create(&mThread, nullptr, AudioStream_internalThreadProc, this);
    if (err != 0) {
        android::status_t status = -errno;
        ALOGE("%s() - pthread_create() failed, %d", __func__, status);
        this->decStrong(nullptr); // Because the thread won't do it.
        mHasThread = false;
        return AAudioConvert_androidToAAudioResult(status);
    } else {
        // TODO Use AAudioThread or maybe AndroidThread
        // Name the thread with an increasing index, "AAudio_#", for debugging.
        static std::atomic<uint32_t> nextThreadIndex{1};
        char name[16]; // max length for a pthread_name
        uint32_t index = nextThreadIndex++;
        // Wrap the index so that we do not hit the 16 char limit
        // and to avoid hard-to-read large numbers.
        index = index % 100000;  // arbitrary
        snprintf(name, sizeof(name), "AAudio_%u", index);
        err = pthread_setname_np(mThread, name);
        ALOGW_IF((err != 0), "Could not set name of AAudio thread. err = %d", err);

        return AAUDIO_OK;
    }
}

aaudio_result_t AudioStream::joinThread(void** returnArg) {
    // This may get temporarily unlocked in the MMAP release() when joining callback threads.
    std::lock_guard<std::mutex> lock(mStreamLock);
    return joinThread_l(returnArg);
}

// This must be called under mStreamLock.
aaudio_result_t AudioStream::joinThread_l(void** returnArg) {
    if (!mHasThread) {
        ALOGD("joinThread() - but has no thread or already join()ed");
        return AAUDIO_ERROR_INVALID_STATE;
    }
    aaudio_result_t result = AAUDIO_OK;
    // If the callback is stopping the stream because the app passed back STOP
    // then we don't need to join(). The thread is already about to exit.
    if (!pthread_equal(pthread_self(), mThread)) {
        // Called from an app thread. Not the callback.
        // Unlock because the callback may be trying to stop the stream but is blocked.
        mStreamLock.unlock();
        int err = pthread_join(mThread, returnArg);
        mStreamLock.lock();
        if (err) {
            ALOGE("%s() pthread_join() returns err = %d", __func__, err);
            result = AAudioConvert_androidToAAudioResult(-err);
        } else {
            ALOGD("%s() pthread_join succeeded", __func__);
            // Prevent joining a second time, which has undefined behavior.
            mHasThread = false;
        }
    } else {
        ALOGD("%s() pthread_join() called on itself!", __func__);
    }
    return (result != AAUDIO_OK) ? result : mThreadRegistrationResult;
}

aaudio_data_callback_result_t AudioStream::maybeCallDataCallback(void *audioData,
                                                                 int32_t numFrames) {
    aaudio_data_callback_result_t result = AAUDIO_CALLBACK_RESULT_STOP;
    AAudioStream_dataCallback dataCallback = getDataCallbackProc();
    if (dataCallback != nullptr) {
        // Store thread ID of caller to detect stop() and close() calls from callback.
        pid_t expected = CALLBACK_THREAD_NONE;
        if (mDataCallbackThread.compare_exchange_strong(expected, gettid())) {
            result = (*dataCallback)(
                    (AAudioStream *) this,
                    getDataCallbackUserData(),
                    audioData,
                    numFrames);
            mDataCallbackThread.store(CALLBACK_THREAD_NONE);
        } else {
            ALOGW("%s() data callback already running!", __func__);
        }
    }
    return result;
}

void AudioStream::maybeCallErrorCallback(aaudio_result_t result) {
    AAudioStream_errorCallback errorCallback = getErrorCallbackProc();
    if (errorCallback != nullptr) {
        // Store thread ID of caller to detect stop() and close() calls from callback.
        pid_t expected = CALLBACK_THREAD_NONE;
        if (mErrorCallbackThread.compare_exchange_strong(expected, gettid())) {
            (*errorCallback)(
                    (AAudioStream *) this,
                    getErrorCallbackUserData(),
                    result);
            mErrorCallbackThread.store(CALLBACK_THREAD_NONE);
        } else {
            ALOGW("%s() error callback already running!", __func__);
        }
    }
}

// Is this running on the same thread as a callback?
// Note: This cannot be implemented using a thread_local because that would
// require using a thread_local variable that is shared between streams.
// So a thread_local variable would prevent stopping or closing stream A from
// a callback on stream B, which is currently legal and not so terrible.
bool AudioStream::collidesWithCallback() const {
    pid_t thisThread = gettid();
    // Compare the current thread ID with the thread ID of the callback
    // threads to see it they match. If so then this code is being
    // called from one of the stream callback functions.
    return ((mErrorCallbackThread.load() == thisThread)
            || (mDataCallbackThread.load() == thisThread));
}

#if AAUDIO_USE_VOLUME_SHAPER
::android::binder::Status AudioStream::MyPlayerBase::applyVolumeShaper(
        const ::android::media::VolumeShaper::Configuration& configuration,
        const ::android::media::VolumeShaper::Operation& operation) {
    android::sp<AudioStream> audioStream;
    {
        std::lock_guard<std::mutex> lock(mParentLock);
        audioStream = mParent.promote();
    }
    if (audioStream) {
        return audioStream->applyVolumeShaper(configuration, operation);
    }
    return android::NO_ERROR;
}
#endif

void AudioStream::setDuckAndMuteVolume(float duckAndMuteVolume) {
    ALOGD("%s() to %f", __func__, duckAndMuteVolume);
    std::lock_guard<std::mutex> lock(mStreamLock);
    mDuckAndMuteVolume = duckAndMuteVolume;
    doSetVolume(); // apply this change
}

void AudioStream::MyPlayerBase::registerWithAudioManager(const android::sp<AudioStream>& parent) {
    std::lock_guard<std::mutex> lock(mParentLock);
    mParent = parent;
    if (!mRegistered) {
        init(android::PLAYER_TYPE_AAUDIO, AAudioConvert_usageToInternal(parent->getUsage()),
            (audio_session_t)parent->getSessionId());
        mRegistered = true;
    }
}

void AudioStream::MyPlayerBase::unregisterWithAudioManager() {
    std::lock_guard<std::mutex> lock(mParentLock);
    if (mRegistered) {
        baseDestroy();
        mRegistered = false;
    }
}

android::status_t AudioStream::MyPlayerBase::playerSetVolume() {
    android::sp<AudioStream> audioStream;
    {
        std::lock_guard<std::mutex> lock(mParentLock);
        audioStream = mParent.promote();
    }
    if (audioStream) {
        // No pan and only left volume is taken into account from IPLayer interface
        audioStream->setDuckAndMuteVolume(mVolumeMultiplierL  /* mPanMultiplierL */);
    }
    return android::NO_ERROR;
}

void AudioStream::MyPlayerBase::destroy() {
    unregisterWithAudioManager();
}

}  // namespace aaudio
