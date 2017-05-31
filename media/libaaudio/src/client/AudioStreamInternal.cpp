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
#define LOG_TAG (mInService ? "AAudioService" : "AAudio")
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#define ATRACE_TAG ATRACE_TAG_AUDIO

#include <stdint.h>
#include <assert.h>

#include <binder/IServiceManager.h>

#include <aaudio/AAudio.h>
#include <utils/String16.h>
#include <utils/Trace.h>

#include "AudioClock.h"
#include "AudioEndpointParcelable.h"
#include "binding/AAudioStreamRequest.h"
#include "binding/AAudioStreamConfiguration.h"
#include "binding/IAAudioService.h"
#include "binding/AAudioServiceMessage.h"
#include "core/AudioStreamBuilder.h"
#include "fifo/FifoBuffer.h"
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
        , mServiceInterface(serviceInterface)
        , mInService(inService) {
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
    if (getFormat() == AAUDIO_UNSPECIFIED) {
        setFormat(AAUDIO_FORMAT_PCM_FLOAT);
    }
    // Request FLOAT for the shared mixer.
    request.getConfiguration().setAudioFormat(AAUDIO_FORMAT_PCM_FLOAT);

    // Build the request to send to the server.
    request.setUserId(getuid());
    request.setProcessId(getpid());
    request.setDirection(getDirection());
    request.setSharingModeMatchRequired(isSharingModeMatchRequired());

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

        // Save device format so we can do format conversion and volume scaling together.
        mDeviceFormat = configuration.getAudioFormat();

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
        mAudioEndpoint.configure(&mEndpointDescriptor);

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
                ALOGE("AudioStreamInternal.open(): framesPerCallback too large = %d, capacity = %d",
                      mCallbackFrames, getBufferCapacity());
                mServiceInterface.closeStream(mServiceStreamHandle);
                return AAUDIO_ERROR_OUT_OF_RANGE;

            } else if (mCallbackFrames < 0) {
                ALOGE("AudioStreamInternal.open(): framesPerCallback negative");
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
    }
    return result;
}

aaudio_result_t AudioStreamInternal::close() {
    ALOGD("AudioStreamInternal.close(): mServiceStreamHandle = 0x%08X",
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
        aaudio_handle_t serviceStreamHandle = mServiceStreamHandle;
        mServiceStreamHandle = AAUDIO_HANDLE_INVALID;

        mServiceInterface.closeStream(serviceStreamHandle);
        delete[] mCallbackBuffer;
        mCallbackBuffer = nullptr;
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
    ALOGD("AudioStreamInternal(): start()");
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }

    startTime = AudioClock::getNanoseconds();
    mClockModel.start(startTime);
    setState(AAUDIO_STREAM_STATE_STARTING);
    aaudio_result_t result = mServiceInterface.startStream(mServiceStreamHandle);;

    if (result == AAUDIO_OK && getDataCallbackProc() != nullptr) {
        // Launch the callback loop thread.
        int64_t periodNanos = mCallbackFrames
                              * AAUDIO_NANOS_PER_SECOND
                              / getSampleRate();
        mCallbackEnabled.store(true);
        result = createThread(periodNanos, aaudio_callback_thread_proc, this);
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

aaudio_result_t AudioStreamInternal::requestPauseInternal()
{
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        ALOGE("AudioStreamInternal(): requestPauseInternal() mServiceStreamHandle invalid = 0x%08X",
              mServiceStreamHandle);
        return AAUDIO_ERROR_INVALID_STATE;
    }

    mClockModel.stop(AudioClock::getNanoseconds());
    setState(AAUDIO_STREAM_STATE_PAUSING);
    return mServiceInterface.pauseStream(mServiceStreamHandle);
}

aaudio_result_t AudioStreamInternal::requestPause()
{
    aaudio_result_t result = stopCallback();
    if (result != AAUDIO_OK) {
        return result;
    }
    result = requestPauseInternal();
    return result;
}

aaudio_result_t AudioStreamInternal::requestFlush() {
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        ALOGE("AudioStreamInternal(): requestFlush() mServiceStreamHandle invalid = 0x%08X",
              mServiceStreamHandle);
        return AAUDIO_ERROR_INVALID_STATE;
    }

    setState(AAUDIO_STREAM_STATE_FLUSHING);
    return mServiceInterface.flushStream(mServiceStreamHandle);
}

// TODO for Play only
void AudioStreamInternal::onFlushFromServer() {
    ALOGD("AudioStreamInternal(): onFlushFromServer()");
    int64_t readCounter = mAudioEndpoint.getDataReadCounter();
    int64_t writeCounter = mAudioEndpoint.getDataWriteCounter();

    // Bump offset so caller does not see the retrograde motion in getFramesRead().
    int64_t framesFlushed = writeCounter - readCounter;
    mFramesOffsetFromService += framesFlushed;

    // Flush written frames by forcing writeCounter to readCounter.
    // This is because we cannot move the read counter in the hardware.
    mAudioEndpoint.setDataWriteCounter(readCounter);
}

aaudio_result_t AudioStreamInternal::requestStopInternal()
{
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        ALOGE("AudioStreamInternal(): requestStopInternal() mServiceStreamHandle invalid = 0x%08X",
              mServiceStreamHandle);
        return AAUDIO_ERROR_INVALID_STATE;
    }

    mClockModel.stop(AudioClock::getNanoseconds());
    setState(AAUDIO_STREAM_STATE_STOPPING);
    return mServiceInterface.stopStream(mServiceStreamHandle);
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
                                              getpid(),
                                              gettid(),
                                              getPeriodNanoseconds());
}

aaudio_result_t AudioStreamInternal::unregisterThread() {
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    return mServiceInterface.unregisterAudioThread(mServiceStreamHandle, getpid(), gettid());
}

aaudio_result_t AudioStreamInternal::getTimestamp(clockid_t clockId,
                           int64_t *framePosition,
                           int64_t *timeNanoseconds) {
    // TODO Generate in server and pass to client. Return latest.
    int64_t time = AudioClock::getNanoseconds();
    *framePosition = mClockModel.convertTimeToPosition(time);
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

#if LOG_TIMESTAMPS
static void AudioStreamInternal_logTimestamp(AAudioServiceMessage &command) {
    static int64_t oldPosition = 0;
    static int64_t oldTime = 0;
    int64_t framePosition = command.timestamp.position;
    int64_t nanoTime = command.timestamp.timestamp;
    ALOGD("AudioStreamInternal() timestamp says framePosition = %08lld at nanoTime %lld",
         (long long) framePosition,
         (long long) nanoTime);
    int64_t nanosDelta = nanoTime - oldTime;
    if (nanosDelta > 0 && oldTime > 0) {
        int64_t framesDelta = framePosition - oldPosition;
        int64_t rate = (framesDelta * AAUDIO_NANOS_PER_SECOND) / nanosDelta;
        ALOGD("AudioStreamInternal() - framesDelta = %08lld", (long long) framesDelta);
        ALOGD("AudioStreamInternal() - nanosDelta = %08lld", (long long) nanosDelta);
        ALOGD("AudioStreamInternal() - measured rate = %lld", (long long) rate);
    }
    oldPosition = framePosition;
    oldTime = nanoTime;
}
#endif

aaudio_result_t AudioStreamInternal::onTimestampFromServer(AAudioServiceMessage *message) {
#if LOG_TIMESTAMPS
    AudioStreamInternal_logTimestamp(*message);
#endif
    processTimestamp(message->timestamp.position, message->timestamp.timestamp);
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamInternal::onEventFromServer(AAudioServiceMessage *message) {
    aaudio_result_t result = AAUDIO_OK;
    switch (message->event.event) {
        case AAUDIO_SERVICE_EVENT_STARTED:
            ALOGD("processCommands() got AAUDIO_SERVICE_EVENT_STARTED");
            if (getState() == AAUDIO_STREAM_STATE_STARTING) {
                setState(AAUDIO_STREAM_STATE_STARTED);
            }
            break;
        case AAUDIO_SERVICE_EVENT_PAUSED:
            ALOGD("processCommands() got AAUDIO_SERVICE_EVENT_PAUSED");
            if (getState() == AAUDIO_STREAM_STATE_PAUSING) {
                setState(AAUDIO_STREAM_STATE_PAUSED);
            }
            break;
        case AAUDIO_SERVICE_EVENT_STOPPED:
            ALOGD("processCommands() got AAUDIO_SERVICE_EVENT_STOPPED");
            if (getState() == AAUDIO_STREAM_STATE_STOPPING) {
                setState(AAUDIO_STREAM_STATE_STOPPED);
            }
            break;
        case AAUDIO_SERVICE_EVENT_FLUSHED:
            ALOGD("processCommands() got AAUDIO_SERVICE_EVENT_FLUSHED");
            if (getState() == AAUDIO_STREAM_STATE_FLUSHING) {
                setState(AAUDIO_STREAM_STATE_FLUSHED);
                onFlushFromServer();
            }
            break;
        case AAUDIO_SERVICE_EVENT_CLOSED:
            ALOGD("processCommands() got AAUDIO_SERVICE_EVENT_CLOSED");
            setState(AAUDIO_STREAM_STATE_CLOSED);
            break;
        case AAUDIO_SERVICE_EVENT_DISCONNECTED:
            result = AAUDIO_ERROR_DISCONNECTED;
            setState(AAUDIO_STREAM_STATE_DISCONNECTED);
            ALOGW("WARNING - processCommands() AAUDIO_SERVICE_EVENT_DISCONNECTED");
            break;
        case AAUDIO_SERVICE_EVENT_VOLUME:
            mVolumeRamp.setTarget((float) message->event.dataDouble);
            ALOGD("processCommands() AAUDIO_SERVICE_EVENT_VOLUME %lf",
                     message->event.dataDouble);
            break;
        default:
            ALOGW("WARNING - processCommands() Unrecognized event = %d",
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
            result = AAUDIO_ERROR_UNEXPECTED_VALUE;
            break;
        }
    }
    return result;
}

// Read or write the data, block if needed and timeoutMillis > 0
aaudio_result_t AudioStreamInternal::processData(void *buffer, int32_t numFrames,
                                                 int64_t timeoutNanoseconds)
{
    const char * traceName = (mInService) ? "aaWrtS" : "aaWrtC";
    ATRACE_BEGIN(traceName);
    aaudio_result_t result = AAUDIO_OK;
    int32_t loopCount = 0;
    uint8_t* audioData = (uint8_t*)buffer;
    int64_t currentTimeNanos = AudioClock::getNanoseconds();
    int64_t deadlineNanos = currentTimeNanos + timeoutNanoseconds;
    int32_t framesLeft = numFrames;

    int32_t fullFrames = mAudioEndpoint.getFullFramesAvailable();
    if (ATRACE_ENABLED()) {
        const char * traceName = (mInService) ? "aaFullS" : "aaFullC";
        ATRACE_INT(traceName, fullFrames);
    }

    // Loop until all the data has been processed or until a timeout occurs.
    while (framesLeft > 0) {
        // The call to processDataNow() will not block. It will just read as much as it can.
        int64_t wakeTimeNanos = 0;
        aaudio_result_t framesProcessed = processDataNow(audioData, framesLeft,
                                                  currentTimeNanos, &wakeTimeNanos);
        if (framesProcessed < 0) {
            ALOGE("AudioStreamInternal::processData() loop: framesProcessed = %d", framesProcessed);
            result = framesProcessed;
            break;
        }
        framesLeft -= (int32_t) framesProcessed;
        audioData += framesProcessed * getBytesPerFrame();

        // Should we block?
        if (timeoutNanoseconds == 0) {
            break; // don't block
        } else if (framesLeft > 0) {
            // clip the wake time to something reasonable
            if (wakeTimeNanos < currentTimeNanos) {
                wakeTimeNanos = currentTimeNanos;
            }
            if (wakeTimeNanos > deadlineNanos) {
                // If we time out, just return the framesWritten so far.
                // TODO remove after we fix the deadline bug
                ALOGE("AudioStreamInternal::processData(): timed out after %lld nanos",
                      (long long) timeoutNanoseconds);
                ALOGE("AudioStreamInternal::processData(): wakeTime = %lld, deadline = %lld nanos",
                      (long long) wakeTimeNanos, (long long) deadlineNanos);
                ALOGE("AudioStreamInternal::processData(): past deadline by %d micros",
                      (int)((wakeTimeNanos - deadlineNanos) / AAUDIO_NANOS_PER_MICROSECOND));
                break;
            }

            int64_t sleepForNanos = wakeTimeNanos - currentTimeNanos;
            AudioClock::sleepForNanos(sleepForNanos);
            currentTimeNanos = AudioClock::getNanoseconds();
        }
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
