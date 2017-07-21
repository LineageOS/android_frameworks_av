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

// This file is used in both client and server processes.
// This is needed to make sense of the logs more easily.
#define LOG_TAG (mInService ? "AudioStreamInternal_Service" : "AudioStreamInternal_Client")
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#define ATRACE_TAG ATRACE_TAG_AUDIO

#include <stdint.h>
#include <assert.h>

#include <binder/IServiceManager.h>

#include <aaudio/AAudio.h>
#include <cutils/properties.h>
#include <utils/String16.h>
#include <utils/Trace.h>

#include "AudioEndpointParcelable.h"
#include "binding/AAudioStreamRequest.h"
#include "binding/AAudioStreamConfiguration.h"
#include "binding/IAAudioService.h"
#include "binding/AAudioServiceMessage.h"
#include "core/AudioStreamBuilder.h"
#include "fifo/FifoBuffer.h"
#include "utility/AudioClock.h"
#include "utility/LinearRamp.h"

#include "AudioStreamInternal.h"

using android::String16;
using android::Mutex;
using android::WrappingBuffer;

using namespace aaudio;

#define MIN_TIMEOUT_NANOS        (1000 * AAUDIO_NANOS_PER_MILLISECOND)

// Wait at least this many times longer than the operation should take.
#define MIN_TIMEOUT_OPERATIONS    4

#define LOG_TIMESTAMPS   0

AudioStreamInternal::AudioStreamInternal(AAudioServiceInterface  &serviceInterface, bool inService)
        : AudioStream()
        , mClockModel()
        , mAudioEndpoint()
        , mServiceStreamHandle(AAUDIO_HANDLE_INVALID)
        , mFramesPerBurst(16)
        , mStreamVolume(1.0f)
        , mInService(inService)
        , mServiceInterface(serviceInterface)
        , mWakeupDelayNanos(AAudioProperty_getWakeupDelayMicros() * AAUDIO_NANOS_PER_MICROSECOND)
        , mMinimumSleepNanos(AAudioProperty_getMinimumSleepMicros() * AAUDIO_NANOS_PER_MICROSECOND)
        {
    ALOGD("AudioStreamInternal(): mWakeupDelayNanos = %d, mMinimumSleepNanos = %d",
          mWakeupDelayNanos, mMinimumSleepNanos);
}

AudioStreamInternal::~AudioStreamInternal() {
}

aaudio_result_t AudioStreamInternal::open(const AudioStreamBuilder &builder) {

    aaudio_result_t result = AAUDIO_OK;
    AAudioStreamRequest request;
    AAudioStreamConfiguration configuration;

    result = AudioStream::open(builder);
    if (result < 0) {
        return result;
    }

    // We have to do volume scaling. So we prefer FLOAT format.
    if (getFormat() == AAUDIO_FORMAT_UNSPECIFIED) {
        setFormat(AAUDIO_FORMAT_PCM_FLOAT);
    }
    // Request FLOAT for the shared mixer.
    request.getConfiguration().setFormat(AAUDIO_FORMAT_PCM_FLOAT);

    // Build the request to send to the server.
    request.setUserId(getuid());
    request.setProcessId(getpid());
    request.setDirection(getDirection());
    request.setSharingModeMatchRequired(isSharingModeMatchRequired());
    request.setInService(mInService);

    request.getConfiguration().setDeviceId(getDeviceId());
    request.getConfiguration().setSampleRate(getSampleRate());
    request.getConfiguration().setSamplesPerFrame(getSamplesPerFrame());
    request.getConfiguration().setSharingMode(getSharingMode());

    request.getConfiguration().setBufferCapacity(builder.getBufferCapacity());

    mServiceStreamHandle = mServiceInterface.openStream(request, configuration);
    if (mServiceStreamHandle < 0) {
        result = mServiceStreamHandle;
        ALOGE("AudioStreamInternal.open(): openStream() returned %d", result);
    } else {
        result = configuration.validate();
        if (result != AAUDIO_OK) {
            close();
            return result;
        }
        // Save results of the open.
        setSampleRate(configuration.getSampleRate());
        setSamplesPerFrame(configuration.getSamplesPerFrame());
        setDeviceId(configuration.getDeviceId());
        setSharingMode(configuration.getSharingMode());

        // Save device format so we can do format conversion and volume scaling together.
        mDeviceFormat = configuration.getFormat();

        result = mServiceInterface.getStreamDescription(mServiceStreamHandle, mEndPointParcelable);
        if (result != AAUDIO_OK) {
            mServiceInterface.closeStream(mServiceStreamHandle);
            return result;
        }

        // resolve parcelable into a descriptor
        result = mEndPointParcelable.resolve(&mEndpointDescriptor);
        if (result != AAUDIO_OK) {
            mServiceInterface.closeStream(mServiceStreamHandle);
            return result;
        }

        // Configure endpoint based on descriptor.
        mAudioEndpoint.configure(&mEndpointDescriptor, getDirection());

        mFramesPerBurst = mEndpointDescriptor.dataQueueDescriptor.framesPerBurst;
        int32_t capacity = mEndpointDescriptor.dataQueueDescriptor.capacityInFrames;

        // Validate result from server.
        if (mFramesPerBurst < 16 || mFramesPerBurst > 16 * 1024) {
            ALOGE("AudioStream::open(): framesPerBurst out of range = %d", mFramesPerBurst);
            return AAUDIO_ERROR_OUT_OF_RANGE;
        }
        if (capacity < mFramesPerBurst || capacity > 32 * 1024) {
            ALOGE("AudioStream::open(): bufferCapacity out of range = %d", capacity);
            return AAUDIO_ERROR_OUT_OF_RANGE;
        }

        mClockModel.setSampleRate(getSampleRate());
        mClockModel.setFramesPerBurst(mFramesPerBurst);

        if (getDataCallbackProc()) {
            mCallbackFrames = builder.getFramesPerDataCallback();
            if (mCallbackFrames > getBufferCapacity() / 2) {
                ALOGE("AudioStreamInternal::open(): framesPerCallback too big = %d, capacity = %d",
                      mCallbackFrames, getBufferCapacity());
                mServiceInterface.closeStream(mServiceStreamHandle);
                return AAUDIO_ERROR_OUT_OF_RANGE;

            } else if (mCallbackFrames < 0) {
                ALOGE("AudioStreamInternal::open(): framesPerCallback negative");
                mServiceInterface.closeStream(mServiceStreamHandle);
                return AAUDIO_ERROR_OUT_OF_RANGE;

            }
            if (mCallbackFrames == AAUDIO_UNSPECIFIED) {
                mCallbackFrames = mFramesPerBurst;
            }

            int32_t bytesPerFrame = getSamplesPerFrame()
                                    * AAudioConvert_formatToSizeInBytes(getFormat());
            int32_t callbackBufferSize = mCallbackFrames * bytesPerFrame;
            mCallbackBuffer = new uint8_t[callbackBufferSize];
        }

        setState(AAUDIO_STREAM_STATE_OPEN);
        // only connect to AudioManager if this is a playback stream running in client process
        if (!mInService && getDirection() == AAUDIO_DIRECTION_OUTPUT) {
            init(android::PLAYER_TYPE_AAUDIO, AUDIO_USAGE_MEDIA);
        }
    }
    return result;
}

aaudio_result_t AudioStreamInternal::close() {
    ALOGD("AudioStreamInternal::close(): mServiceStreamHandle = 0x%08X",
             mServiceStreamHandle);
    if (mServiceStreamHandle != AAUDIO_HANDLE_INVALID) {
        // Don't close a stream while it is running.
        aaudio_stream_state_t currentState = getState();
        if (isActive()) {
            requestStop();
            aaudio_stream_state_t nextState;
            int64_t timeoutNanoseconds = MIN_TIMEOUT_NANOS;
            aaudio_result_t result = waitForStateChange(currentState, &nextState,
                                                       timeoutNanoseconds);
            if (result != AAUDIO_OK) {
                ALOGE("AudioStreamInternal::close() waitForStateChange() returned %d %s",
                result, AAudio_convertResultToText(result));
            }
        }
        setState(AAUDIO_STREAM_STATE_CLOSING);
        aaudio_handle_t serviceStreamHandle = mServiceStreamHandle;
        mServiceStreamHandle = AAUDIO_HANDLE_INVALID;

        mServiceInterface.closeStream(serviceStreamHandle);
        delete[] mCallbackBuffer;
        mCallbackBuffer = nullptr;
        setState(AAUDIO_STREAM_STATE_CLOSED);
        return mEndPointParcelable.close();
    } else {
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
}


static void *aaudio_callback_thread_proc(void *context)
{
    AudioStreamInternal *stream = (AudioStreamInternal *)context;
    //LOGD("AudioStreamInternal(): oboe_callback_thread, stream = %p", stream);
    if (stream != NULL) {
        return stream->callbackLoop();
    } else {
        return NULL;
    }
}

aaudio_result_t AudioStreamInternal::requestStart()
{
    int64_t startTime;
    ALOGD("AudioStreamInternal()::requestStart()");
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    if (isActive()) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    aaudio_stream_state_t originalState = getState();

    setState(AAUDIO_STREAM_STATE_STARTING);
    aaudio_result_t result = AAudioConvert_androidToAAudioResult(startWithStatus());

    startTime = AudioClock::getNanoseconds();
    mClockModel.start(startTime);

    if (result == AAUDIO_OK && getDataCallbackProc() != nullptr) {
        // Launch the callback loop thread.
        int64_t periodNanos = mCallbackFrames
                              * AAUDIO_NANOS_PER_SECOND
                              / getSampleRate();
        mCallbackEnabled.store(true);
        result = createThread(periodNanos, aaudio_callback_thread_proc, this);
    }
    if (result != AAUDIO_OK) {
        setState(originalState);
    }
    return result;
}

int64_t AudioStreamInternal::calculateReasonableTimeout(int32_t framesPerOperation) {

    // Wait for at least a second or some number of callbacks to join the thread.
    int64_t timeoutNanoseconds = (MIN_TIMEOUT_OPERATIONS
                                  * framesPerOperation
                                  * AAUDIO_NANOS_PER_SECOND)
                                  / getSampleRate();
    if (timeoutNanoseconds < MIN_TIMEOUT_NANOS) { // arbitrary number of seconds
        timeoutNanoseconds = MIN_TIMEOUT_NANOS;
    }
    return timeoutNanoseconds;
}

int64_t AudioStreamInternal::calculateReasonableTimeout() {
    return calculateReasonableTimeout(getFramesPerBurst());
}

aaudio_result_t AudioStreamInternal::stopCallback()
{
    if (isDataCallbackActive()) {
        mCallbackEnabled.store(false);
        return joinThread(NULL);
    } else {
        return AAUDIO_OK;
    }
}

aaudio_result_t AudioStreamInternal::requestStopInternal()
{
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        ALOGE("AudioStreamInternal::requestStopInternal() mServiceStreamHandle invalid = 0x%08X",
              mServiceStreamHandle);
        return AAUDIO_ERROR_INVALID_STATE;
    }

    mClockModel.stop(AudioClock::getNanoseconds());
    setState(AAUDIO_STREAM_STATE_STOPPING);
    return AAudioConvert_androidToAAudioResult(stopWithStatus());
}

aaudio_result_t AudioStreamInternal::requestStop()
{
    aaudio_result_t result = stopCallback();
    if (result != AAUDIO_OK) {
        return result;
    }
    result = requestStopInternal();
    return result;
}

aaudio_result_t AudioStreamInternal::registerThread() {
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    return mServiceInterface.registerAudioThread(mServiceStreamHandle,
                                              gettid(),
                                              getPeriodNanoseconds());
}

aaudio_result_t AudioStreamInternal::unregisterThread() {
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    return mServiceInterface.unregisterAudioThread(mServiceStreamHandle, gettid());
}

aaudio_result_t AudioStreamInternal::startClient(const android::AudioClient& client,
                                                 audio_port_handle_t *clientHandle) {
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    return mServiceInterface.startClient(mServiceStreamHandle, client, clientHandle);
}

aaudio_result_t AudioStreamInternal::stopClient(audio_port_handle_t clientHandle) {
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    return mServiceInterface.stopClient(mServiceStreamHandle, clientHandle);
}

aaudio_result_t AudioStreamInternal::getTimestamp(clockid_t clockId,
                           int64_t *framePosition,
                           int64_t *timeNanoseconds) {
    // TODO Generate in server and pass to client. Return latest.
    int64_t time = AudioClock::getNanoseconds();
    *framePosition = mClockModel.convertTimeToPosition(time) + mFramesOffsetFromService;
    // TODO Get a more accurate timestamp from the service. This code just adds a fudge factor.
    *timeNanoseconds = time + (6 * AAUDIO_NANOS_PER_MILLISECOND);
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamInternal::updateStateWhileWaiting() {
    if (isDataCallbackActive()) {
        return AAUDIO_OK; // state is getting updated by the callback thread read/write call
    }
    return processCommands();
}

void AudioStreamInternal::logTimestamp(AAudioServiceMessage &command) {
    static int64_t oldPosition = 0;
    static int64_t oldTime = 0;
    int64_t framePosition = command.timestamp.position;
    int64_t nanoTime = command.timestamp.timestamp;
    ALOGD("AudioStreamInternal: timestamp says framePosition = %08lld at nanoTime %lld",
         (long long) framePosition,
         (long long) nanoTime);
    int64_t nanosDelta = nanoTime - oldTime;
    if (nanosDelta > 0 && oldTime > 0) {
        int64_t framesDelta = framePosition - oldPosition;
        int64_t rate = (framesDelta * AAUDIO_NANOS_PER_SECOND) / nanosDelta;
        ALOGD("AudioStreamInternal: framesDelta = %08lld, nanosDelta = %08lld, rate = %lld",
              (long long) framesDelta, (long long) nanosDelta, (long long) rate);
    }
    oldPosition = framePosition;
    oldTime = nanoTime;
}

aaudio_result_t AudioStreamInternal::onTimestampFromServer(AAudioServiceMessage *message) {
#if LOG_TIMESTAMPS
    logTimestamp(*message);
#endif
    processTimestamp(message->timestamp.position, message->timestamp.timestamp);
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamInternal::onEventFromServer(AAudioServiceMessage *message) {
    aaudio_result_t result = AAUDIO_OK;
    switch (message->event.event) {
        case AAUDIO_SERVICE_EVENT_STARTED:
            ALOGD("AudioStreamInternal::onEventFromServergot() AAUDIO_SERVICE_EVENT_STARTED");
            if (getState() == AAUDIO_STREAM_STATE_STARTING) {
                setState(AAUDIO_STREAM_STATE_STARTED);
            }
            break;
        case AAUDIO_SERVICE_EVENT_PAUSED:
            ALOGD("AudioStreamInternal::onEventFromServergot() AAUDIO_SERVICE_EVENT_PAUSED");
            if (getState() == AAUDIO_STREAM_STATE_PAUSING) {
                setState(AAUDIO_STREAM_STATE_PAUSED);
            }
            break;
        case AAUDIO_SERVICE_EVENT_STOPPED:
            ALOGD("AudioStreamInternal::onEventFromServergot() AAUDIO_SERVICE_EVENT_STOPPED");
            if (getState() == AAUDIO_STREAM_STATE_STOPPING) {
                setState(AAUDIO_STREAM_STATE_STOPPED);
            }
            break;
        case AAUDIO_SERVICE_EVENT_FLUSHED:
            ALOGD("AudioStreamInternal::onEventFromServer() got AAUDIO_SERVICE_EVENT_FLUSHED");
            if (getState() == AAUDIO_STREAM_STATE_FLUSHING) {
                setState(AAUDIO_STREAM_STATE_FLUSHED);
                onFlushFromServer();
            }
            break;
        case AAUDIO_SERVICE_EVENT_CLOSED:
            ALOGD("AudioStreamInternal::onEventFromServer() got AAUDIO_SERVICE_EVENT_CLOSED");
            setState(AAUDIO_STREAM_STATE_CLOSED);
            break;
        case AAUDIO_SERVICE_EVENT_DISCONNECTED:
            result = AAUDIO_ERROR_DISCONNECTED;
            setState(AAUDIO_STREAM_STATE_DISCONNECTED);
            ALOGW("WARNING - AudioStreamInternal::onEventFromServer()"
                          " AAUDIO_SERVICE_EVENT_DISCONNECTED");
            break;
        case AAUDIO_SERVICE_EVENT_VOLUME:
            mStreamVolume = (float)message->event.dataDouble;
            doSetVolume();
            ALOGD("AudioStreamInternal::onEventFromServer() AAUDIO_SERVICE_EVENT_VOLUME %lf",
                     message->event.dataDouble);
            break;
        default:
            ALOGW("WARNING - AudioStreamInternal::onEventFromServer() Unrecognized event = %d",
                 (int) message->event.event);
            break;
    }
    return result;
}

// Process all the commands coming from the server.
aaudio_result_t AudioStreamInternal::processCommands() {
    aaudio_result_t result = AAUDIO_OK;

    while (result == AAUDIO_OK) {
        //ALOGD("AudioStreamInternal::processCommands() - looping, %d", result);
        AAudioServiceMessage message;
        if (mAudioEndpoint.readUpCommand(&message) != 1) {
            break; // no command this time, no problem
        }
        switch (message.what) {
        case AAudioServiceMessage::code::TIMESTAMP:
            result = onTimestampFromServer(&message);
            break;

        case AAudioServiceMessage::code::EVENT:
            result = onEventFromServer(&message);
            break;

        default:
            ALOGE("WARNING - AudioStreamInternal::processCommands() Unrecognized what = %d",
                 (int) message.what);
            result = AAUDIO_ERROR_INTERNAL;
            break;
        }
    }
    return result;
}

// Read or write the data, block if needed and timeoutMillis > 0
aaudio_result_t AudioStreamInternal::processData(void *buffer, int32_t numFrames,
                                                 int64_t timeoutNanoseconds)
{
    const char * traceName = "aaProc";
    const char * fifoName = "aaRdy";
    ATRACE_BEGIN(traceName);
    if (ATRACE_ENABLED()) {
        int32_t fullFrames = mAudioEndpoint.getFullFramesAvailable();
        ATRACE_INT(fifoName, fullFrames);
    }

    aaudio_result_t result = AAUDIO_OK;
    int32_t loopCount = 0;
    uint8_t* audioData = (uint8_t*)buffer;
    int64_t currentTimeNanos = AudioClock::getNanoseconds();
    const int64_t entryTimeNanos = currentTimeNanos;
    const int64_t deadlineNanos = currentTimeNanos + timeoutNanoseconds;
    int32_t framesLeft = numFrames;

    // Loop until all the data has been processed or until a timeout occurs.
    while (framesLeft > 0) {
        // The call to processDataNow() will not block. It will just process as much as it can.
        int64_t wakeTimeNanos = 0;
        aaudio_result_t framesProcessed = processDataNow(audioData, framesLeft,
                                                  currentTimeNanos, &wakeTimeNanos);
        if (framesProcessed < 0) {
            result = framesProcessed;
            break;
        }
        framesLeft -= (int32_t) framesProcessed;
        audioData += framesProcessed * getBytesPerFrame();

        // Should we block?
        if (timeoutNanoseconds == 0) {
            break; // don't block
        } else if (framesLeft > 0) {
            if (!mAudioEndpoint.isFreeRunning()) {
                // If there is software on the other end of the FIFO then it may get delayed.
                // So wake up just a little after we expect it to be ready.
                wakeTimeNanos += mWakeupDelayNanos;
            }

            if (wakeTimeNanos > deadlineNanos) {
                // If we time out, just return the framesWritten so far.
                // TODO remove after we fix the deadline bug
                ALOGW("AudioStreamInternal::processData(): entered at %lld nanos, currently %lld",
                      (long long) entryTimeNanos, (long long) currentTimeNanos);
                ALOGW("AudioStreamInternal::processData(): timed out after %lld nanos",
                      (long long) timeoutNanoseconds);
                ALOGW("AudioStreamInternal::processData(): wakeTime = %lld, deadline = %lld nanos",
                      (long long) wakeTimeNanos, (long long) deadlineNanos);
                ALOGW("AudioStreamInternal::processData(): past deadline by %d micros",
                      (int)((wakeTimeNanos - deadlineNanos) / AAUDIO_NANOS_PER_MICROSECOND));
                mClockModel.dump();
                mAudioEndpoint.dump();
                break;
            }

            currentTimeNanos = AudioClock::getNanoseconds();
            int64_t earliestWakeTime = currentTimeNanos + mMinimumSleepNanos;
            // Guarantee a minimum sleep time.
            if (wakeTimeNanos < earliestWakeTime) {
                wakeTimeNanos = earliestWakeTime;
            }

            if (ATRACE_ENABLED()) {
                int32_t fullFrames = mAudioEndpoint.getFullFramesAvailable();
                ATRACE_INT(fifoName, fullFrames);
                int64_t sleepForNanos = wakeTimeNanos - currentTimeNanos;
                ATRACE_INT("aaSlpNs", (int32_t)sleepForNanos);
            }

            AudioClock::sleepUntilNanoTime(wakeTimeNanos);
            currentTimeNanos = AudioClock::getNanoseconds();
        }
    }

    if (ATRACE_ENABLED()) {
        int32_t fullFrames = mAudioEndpoint.getFullFramesAvailable();
        ATRACE_INT(fifoName, fullFrames);
    }

    // return error or framesProcessed
    (void) loopCount;
    ATRACE_END();
    return (result < 0) ? result : numFrames - framesLeft;
}

void AudioStreamInternal::processTimestamp(uint64_t position, int64_t time) {
    mClockModel.processTimestamp(position, time);
}

aaudio_result_t AudioStreamInternal::setBufferSize(int32_t requestedFrames) {
    int32_t actualFrames = 0;
    // Round to the next highest burst size.
    if (getFramesPerBurst() > 0) {
        int32_t numBursts = (requestedFrames + getFramesPerBurst() - 1) / getFramesPerBurst();
        requestedFrames = numBursts * getFramesPerBurst();
    }

    aaudio_result_t result = mAudioEndpoint.setBufferSizeInFrames(requestedFrames, &actualFrames);
    ALOGD("AudioStreamInternal::setBufferSize() req = %d => %d", requestedFrames, actualFrames);
    if (result < 0) {
        return result;
    } else {
        return (aaudio_result_t) actualFrames;
    }
}

int32_t AudioStreamInternal::getBufferSize() const {
    return mAudioEndpoint.getBufferSizeInFrames();
}

int32_t AudioStreamInternal::getBufferCapacity() const {
    return mAudioEndpoint.getBufferCapacityInFrames();
}

int32_t AudioStreamInternal::getFramesPerBurst() const {
    return mEndpointDescriptor.dataQueueDescriptor.framesPerBurst;
}

aaudio_result_t AudioStreamInternal::joinThread(void** returnArg) {
    return AudioStream::joinThread(returnArg, calculateReasonableTimeout(getFramesPerBurst()));
}

void AudioStreamInternal::doSetVolume() {
    // No pan and only left volume is taken into account from IPLayer interface
    mVolumeRamp.setTarget(mStreamVolume * mVolumeMultiplierL /* * mPanMultiplierL */);
}


//------------------------------------------------------------------------------
// Implementation of PlayerBase
status_t AudioStreamInternal::playerStart() {
    return AAudioConvert_aaudioToAndroidStatus(mServiceInterface.startStream(mServiceStreamHandle));
}

status_t AudioStreamInternal::playerPause() {
    return AAudioConvert_aaudioToAndroidStatus(mServiceInterface.pauseStream(mServiceStreamHandle));
}

status_t AudioStreamInternal::playerStop() {
    return AAudioConvert_aaudioToAndroidStatus(mServiceInterface.stopStream(mServiceStreamHandle));
}

status_t AudioStreamInternal::playerSetVolume() {
    doSetVolume();
    return NO_ERROR;
}

void AudioStreamInternal::destroy() {
    baseDestroy();
}
