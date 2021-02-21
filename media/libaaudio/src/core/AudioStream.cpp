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
    // mThread is a pthread_t of unknown size so we need memset.
    memset(&mThread, 0, sizeof(mThread));
    setPeriodNanoseconds(0);
}

AudioStream::~AudioStream() {
    // Please preserve this log because there have been several bugs related to
    // AudioStream deletion and late callbacks.
    ALOGD("%s(s#%u) mPlayerBase strongCount = %d",
            __func__, getId(), mPlayerBase->getStrongCount());
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

void AudioStream::logOpen() {
    if (mMetricsId.size() > 0) {
        android::mediametrics::LogItem(mMetricsId)
                .set(AMEDIAMETRICS_PROP_PERFORMANCEMODE,
                     AudioGlobal_convertPerformanceModeToText(getPerformanceMode()))
                .set(AMEDIAMETRICS_PROP_SHARINGMODE,
                     AudioGlobal_convertSharingModeToText(getSharingMode()))
                .record();
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
    std::lock_guard<std::mutex> lock(mStreamLock);

    if (collidesWithCallback()) {
        ALOGE("%s cannot be called from a callback!", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }

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

    aaudio_result_t result = requestStart();
    if (result == AAUDIO_OK) {
        // We only call this for logging in "dumpsys audio". So ignore return code.
        (void) mPlayerBase->start();
    }
    return result;
}

aaudio_result_t AudioStream::systemPause() {
    std::lock_guard<std::mutex> lock(mStreamLock);

    if (!isPauseSupported()) {
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    if (collidesWithCallback()) {
        ALOGE("%s cannot be called from a callback!", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }

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

    aaudio_result_t result = requestPause();
    if (result == AAUDIO_OK) {
        // We only call this for logging in "dumpsys audio". So ignore return code.
        (void) mPlayerBase->pause();
    }
    return result;
}

aaudio_result_t AudioStream::safeFlush() {
    if (!isFlushSupported()) {
        ALOGE("flush not supported for this stream");
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    std::lock_guard<std::mutex> lock(mStreamLock);
    if (collidesWithCallback()) {
        ALOGE("stream cannot be flushed from a callback!");
        return AAUDIO_ERROR_INVALID_STATE;
    }

    aaudio_result_t result = AAudio_isFlushAllowed(getState());
    if (result != AAUDIO_OK) {
        return result;
    }

    return requestFlush();
}

aaudio_result_t AudioStream::systemStopFromCallback() {
    std::lock_guard<std::mutex> lock(mStreamLock);
    aaudio_result_t result = safeStop();
    if (result == AAUDIO_OK) {
        // We only call this for logging in "dumpsys audio". So ignore return code.
        (void) mPlayerBase->stop();
    }
    return result;
}

aaudio_result_t AudioStream::systemStopFromApp() {
    std::lock_guard<std::mutex> lock(mStreamLock);
    if (collidesWithCallback()) {
        ALOGE("stream cannot be stopped by calling from a callback!");
        return AAUDIO_ERROR_INVALID_STATE;
    }
    aaudio_result_t result = safeStop();
    if (result == AAUDIO_OK) {
        // We only call this for logging in "dumpsys audio". So ignore return code.
        (void) mPlayerBase->stop();
    }
    return result;
}

// This must be called under mStreamLock.
aaudio_result_t AudioStream::safeStop() {

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

    return requestStop();
}

aaudio_result_t AudioStream::safeRelease() {
    // This get temporarily unlocked in the MMAP release() when joining callback threads.
    std::lock_guard<std::mutex> lock(mStreamLock);
    if (collidesWithCallback()) {
        ALOGE("%s cannot be called from a callback!", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }
    if (getState() == AAUDIO_STREAM_STATE_CLOSING) { // already released?
        return AAUDIO_OK;
    }
    return release_l();
}

aaudio_result_t AudioStream::safeReleaseClose() {
    // This get temporarily unlocked in the MMAP release() when joining callback threads.
    std::lock_guard<std::mutex> lock(mStreamLock);
    if (collidesWithCallback()) {
        ALOGE("%s cannot be called from a callback!", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }
    releaseCloseFinal();
    return AAUDIO_OK;
}

void AudioStream::setState(aaudio_stream_state_t state) {
    ALOGD("%s(s#%d) from %d to %d", __func__, getId(), mState, state);
    // Track transition to DISCONNECTED state.
    if (state == AAUDIO_STREAM_STATE_DISCONNECTED && mState != state) {
        android::mediametrics::LogItem(mMetricsId)
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_DISCONNECT)
                .set(AMEDIAMETRICS_PROP_STATE, AudioGlobal_convertStreamStateToText(getState()))
                .record();
    }
    // CLOSED is a final state
    if (mState == AAUDIO_STREAM_STATE_CLOSED) {
        ALOGE("%s(%d) tried to set to %d but already CLOSED", __func__, getId(), state);

    // Once CLOSING, we can only move to CLOSED state.
    } else if (mState == AAUDIO_STREAM_STATE_CLOSING
               && state != AAUDIO_STREAM_STATE_CLOSED) {
        ALOGE("%s(%d) tried to set to %d but already CLOSING", __func__, getId(), state);

    // Once DISCONNECTED, we can only move to CLOSING or CLOSED state.
    } else if (mState == AAUDIO_STREAM_STATE_DISCONNECTED
               && !(state == AAUDIO_STREAM_STATE_CLOSING
                   || state == AAUDIO_STREAM_STATE_CLOSED)) {
        ALOGE("%s(%d) tried to set to %d but already DISCONNECTED", __func__, getId(), state);

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

// This is the entry point for the new thread created by createThread().
// It converts the 'C' function call to a C++ method call.
static void* AudioStream_internalThreadProc(void* threadArg) {
    AudioStream *audioStream = (AudioStream *) threadArg;
    // Use an sp<> to prevent the stream from being deleted while running.
    android::sp<AudioStream> protectedStream(audioStream);
    return protectedStream->wrapUserThread();
}

// This is not exposed in the API.
// But it is still used internally to implement callbacks for MMAP mode.
aaudio_result_t AudioStream::createThread(int64_t periodNanoseconds,
                                     aaudio_audio_thread_proc_t threadProc,
                                     void* threadArg)
{
    if (mHasThread) {
        ALOGE("createThread() - mHasThread already true");
        return AAUDIO_ERROR_INVALID_STATE;
    }
    if (threadProc == nullptr) {
        return AAUDIO_ERROR_NULL;
    }
    // Pass input parameters to the background thread.
    mThreadProc = threadProc;
    mThreadArg = threadArg;
    setPeriodNanoseconds(periodNanoseconds);
    int err = pthread_create(&mThread, nullptr, AudioStream_internalThreadProc, this);
    if (err != 0) {
        android::status_t status = -errno;
        ALOGE("createThread() - pthread_create() failed, %d", status);
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

        mHasThread = true;
        return AAUDIO_OK;
    }
}

// This must be called under mStreamLock.
aaudio_result_t AudioStream::joinThread(void** returnArg, int64_t timeoutNanoseconds __unused)
{
    if (!mHasThread) {
        ALOGE("joinThread() - but has no thread");
        return AAUDIO_ERROR_INVALID_STATE;
    }
    aaudio_result_t result = AAUDIO_OK;
    // If the callback is stopping the stream because the app passed back STOP
    // then we don't need to join(). The thread is already about to exit.
    if (pthread_self() != mThread) {
        // Called from an app thread. Not the callback.
        // Unlock because the callback may be trying to stop the stream but is blocked.
        mStreamLock.unlock();
#if 0
        // TODO implement equivalent of pthread_timedjoin_np()
        struct timespec abstime;
        int err = pthread_timedjoin_np(mThread, returnArg, &abstime);
#else
        int err = pthread_join(mThread, returnArg);
#endif
        mStreamLock.lock();
        if (err) {
            ALOGE("%s() pthread_join() returns err = %d", __func__, err);
            result = AAudioConvert_androidToAAudioResult(-err);
        }
    }
    // This must be set false so that the callback thread can be created
    // when the stream is restarted.
    mHasThread = false;
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
    mDuckAndMuteVolume = duckAndMuteVolume;
    doSetVolume(); // apply this change
}

void AudioStream::MyPlayerBase::registerWithAudioManager(const android::sp<AudioStream>& parent) {
    std::lock_guard<std::mutex> lock(mParentLock);
    mParent = parent;
    if (!mRegistered) {
        init(android::PLAYER_TYPE_AAUDIO, AAudioConvert_usageToInternal(parent->getUsage()));
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
        audioStream->setDuckAndMuteVolume(mVolumeMultiplierL  /* * mPanMultiplierL */);
    }
    return android::NO_ERROR;
}

void AudioStream::MyPlayerBase::destroy() {
    unregisterWithAudioManager();
}

}  // namespace aaudio
