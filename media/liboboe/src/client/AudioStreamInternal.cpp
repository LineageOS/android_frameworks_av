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

#define LOG_TAG "OboeAudio"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <assert.h>

#include <binder/IServiceManager.h>

#include <oboe/OboeAudio.h>

#include "AudioClock.h"
#include "AudioEndpointParcelable.h"
#include "binding/OboeStreamRequest.h"
#include "binding/OboeStreamConfiguration.h"
#include "binding/IOboeAudioService.h"
#include "binding/OboeServiceMessage.h"

#include "AudioStreamInternal.h"

#define LOG_TIMESTAMPS   0

using android::String16;
using android::IServiceManager;
using android::defaultServiceManager;
using android::interface_cast;

using namespace oboe;

// Helper function to get access to the "OboeAudioService" service.
static sp<IOboeAudioService> getOboeAudioService() {
    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16("OboeAudioService"));
    // TODO: If the "OboeHack" service is not running, getService times out and binder == 0.
    sp<IOboeAudioService> service = interface_cast<IOboeAudioService>(binder);
    return service;
}

AudioStreamInternal::AudioStreamInternal()
        : AudioStream()
        , mClockModel()
        , mAudioEndpoint()
        , mServiceStreamHandle(OBOE_HANDLE_INVALID)
        , mFramesPerBurst(16)
{
    // TODO protect against mService being NULL;
    // TODO Model access to the service on frameworks/av/media/libaudioclient/AudioSystem.cpp
    mService = getOboeAudioService();
}

AudioStreamInternal::~AudioStreamInternal() {
}

oboe_result_t AudioStreamInternal::open(const AudioStreamBuilder &builder) {

    oboe_result_t result = OBOE_OK;
    OboeStreamRequest request;
    OboeStreamConfiguration configuration;

    result = AudioStream::open(builder);
    if (result < 0) {
        return result;
    }

    // Build the request.
    request.setUserId(getuid());
    request.setProcessId(getpid());
    request.getConfiguration().setDeviceId(getDeviceId());
    request.getConfiguration().setSampleRate(getSampleRate());
    request.getConfiguration().setSamplesPerFrame(getSamplesPerFrame());
    request.getConfiguration().setAudioFormat(getFormat());
    request.dump();

    mServiceStreamHandle = mService->openStream(request, configuration);
    ALOGD("AudioStreamInternal.open(): openStream returned mServiceStreamHandle = 0x%08X",
         (unsigned int)mServiceStreamHandle);
    if (mServiceStreamHandle < 0) {
        result = mServiceStreamHandle;
        ALOGE("AudioStreamInternal.open(): acquireRealtimeStream oboe_result_t = 0x%08X", result);
    } else {
        result = configuration.validate();
        if (result != OBOE_OK) {
            close();
            return result;
        }
        // Save results of the open.
        setSampleRate(configuration.getSampleRate());
        setSamplesPerFrame(configuration.getSamplesPerFrame());
        setFormat(configuration.getAudioFormat());

        oboe::AudioEndpointParcelable parcelable;
        result = mService->getStreamDescription(mServiceStreamHandle, parcelable);
        if (result != OBOE_OK) {
            ALOGE("AudioStreamInternal.open(): getStreamDescriptor returns %d", result);
            mService->closeStream(mServiceStreamHandle);
            return result;
        }
        // resolve parcelable into a descriptor
        parcelable.resolve(&mEndpointDescriptor);

        // Configure endpoint based on descriptor.
        mAudioEndpoint.configure(&mEndpointDescriptor);


        mFramesPerBurst = mEndpointDescriptor.downDataQueueDescriptor.framesPerBurst;
        assert(mFramesPerBurst >= 16);
        assert(mEndpointDescriptor.downDataQueueDescriptor.capacityInFrames < 10 * 1024);

        mClockModel.setSampleRate(getSampleRate());
        mClockModel.setFramesPerBurst(mFramesPerBurst);

        setState(OBOE_STREAM_STATE_OPEN);
    }
    return result;
}

oboe_result_t AudioStreamInternal::close() {
    ALOGD("AudioStreamInternal.close(): mServiceStreamHandle = 0x%08X", mServiceStreamHandle);
    if (mServiceStreamHandle != OBOE_HANDLE_INVALID) {
        mService->closeStream(mServiceStreamHandle);
        mServiceStreamHandle = OBOE_HANDLE_INVALID;
        return OBOE_OK;
    } else {
        return OBOE_ERROR_INVALID_STATE;
    }
}

oboe_result_t AudioStreamInternal::requestStart()
{
    oboe_nanoseconds_t startTime;
    ALOGD("AudioStreamInternal(): start()");
    if (mServiceStreamHandle == OBOE_HANDLE_INVALID) {
        return OBOE_ERROR_INVALID_STATE;
    }
    startTime = Oboe_getNanoseconds(OBOE_CLOCK_MONOTONIC);
    mClockModel.start(startTime);
    processTimestamp(0, startTime);
    setState(OBOE_STREAM_STATE_STARTING);
    return mService->startStream(mServiceStreamHandle);
}

oboe_result_t AudioStreamInternal::requestPause()
{
    ALOGD("AudioStreamInternal(): pause()");
    if (mServiceStreamHandle == OBOE_HANDLE_INVALID) {
        return OBOE_ERROR_INVALID_STATE;
    }
    mClockModel.stop(Oboe_getNanoseconds(OBOE_CLOCK_MONOTONIC));
    setState(OBOE_STREAM_STATE_PAUSING);
    return mService->pauseStream(mServiceStreamHandle);
}

oboe_result_t AudioStreamInternal::requestFlush() {
    ALOGD("AudioStreamInternal(): flush()");
    if (mServiceStreamHandle == OBOE_HANDLE_INVALID) {
        return OBOE_ERROR_INVALID_STATE;
    }
    setState(OBOE_STREAM_STATE_FLUSHING);
    return mService->flushStream(mServiceStreamHandle);
}

void AudioStreamInternal::onFlushFromServer() {
    ALOGD("AudioStreamInternal(): onFlushFromServer()");
    oboe_position_frames_t readCounter = mAudioEndpoint.getDownDataReadCounter();
    oboe_position_frames_t writeCounter = mAudioEndpoint.getDownDataWriteCounter();
    // Bump offset so caller does not see the retrograde motion in getFramesRead().
    oboe_position_frames_t framesFlushed = writeCounter - readCounter;
    mFramesOffsetFromService += framesFlushed;
    // Flush written frames by forcing writeCounter to readCounter.
    // This is because we cannot move the read counter in the hardware.
    mAudioEndpoint.setDownDataWriteCounter(readCounter);
}

oboe_result_t AudioStreamInternal::requestStop()
{
    // TODO better implementation of requestStop()
    oboe_result_t result = requestPause();
    if (result == OBOE_OK) {
        oboe_stream_state_t state;
        result = waitForStateChange(OBOE_STREAM_STATE_PAUSING,
                                    &state,
                                    500 * OBOE_NANOS_PER_MILLISECOND);// TODO temporary code
        if (result == OBOE_OK) {
            result = requestFlush();
        }
    }
    return result;
}

oboe_result_t AudioStreamInternal::registerThread() {
    ALOGD("AudioStreamInternal(): registerThread()");
    if (mServiceStreamHandle == OBOE_HANDLE_INVALID) {
        return OBOE_ERROR_INVALID_STATE;
    }
    return mService->registerAudioThread(mServiceStreamHandle,
                                         gettid(),
                                         getPeriodNanoseconds());
}

oboe_result_t AudioStreamInternal::unregisterThread() {
    ALOGD("AudioStreamInternal(): unregisterThread()");
    if (mServiceStreamHandle == OBOE_HANDLE_INVALID) {
        return OBOE_ERROR_INVALID_STATE;
    }
    return mService->unregisterAudioThread(mServiceStreamHandle, gettid());
}

// TODO use oboe_clockid_t all the way down to AudioClock
oboe_result_t AudioStreamInternal::getTimestamp(clockid_t clockId,
                           oboe_position_frames_t *framePosition,
                           oboe_nanoseconds_t *timeNanoseconds) {
// TODO implement using real HAL
    oboe_nanoseconds_t time = AudioClock::getNanoseconds();
    *framePosition = mClockModel.convertTimeToPosition(time);
    *timeNanoseconds = time + (10 * OBOE_NANOS_PER_MILLISECOND); // Fake hardware delay
    return OBOE_OK;
}

oboe_result_t AudioStreamInternal::updateState() {
    return processCommands();
}

#if LOG_TIMESTAMPS
static void AudioStreamInternal_LogTimestamp(OboeServiceMessage &command) {
    static int64_t oldPosition = 0;
    static oboe_nanoseconds_t oldTime = 0;
    int64_t framePosition = command.timestamp.position;
    oboe_nanoseconds_t nanoTime = command.timestamp.timestamp;
    ALOGD("AudioStreamInternal() timestamp says framePosition = %08lld at nanoTime %llu",
         (long long) framePosition,
         (long long) nanoTime);
    int64_t nanosDelta = nanoTime - oldTime;
    if (nanosDelta > 0 && oldTime > 0) {
        int64_t framesDelta = framePosition - oldPosition;
        int64_t rate = (framesDelta * OBOE_NANOS_PER_SECOND) / nanosDelta;
        ALOGD("AudioStreamInternal() - framesDelta = %08lld", (long long) framesDelta);
        ALOGD("AudioStreamInternal() - nanosDelta = %08lld", (long long) nanosDelta);
        ALOGD("AudioStreamInternal() - measured rate = %llu", (unsigned long long) rate);
    }
    oldPosition = framePosition;
    oldTime = nanoTime;
}
#endif

oboe_result_t AudioStreamInternal::onTimestampFromServer(OboeServiceMessage *message) {
    oboe_position_frames_t framePosition = 0;
#if LOG_TIMESTAMPS
    AudioStreamInternal_LogTimestamp(command);
#endif
    framePosition = message->timestamp.position;
    processTimestamp(framePosition, message->timestamp.timestamp);
    return OBOE_OK;
}

oboe_result_t AudioStreamInternal::onEventFromServer(OboeServiceMessage *message) {
    oboe_result_t result = OBOE_OK;
    ALOGD("processCommands() got event %d", message->event.event);
    switch (message->event.event) {
        case OBOE_SERVICE_EVENT_STARTED:
            ALOGD("processCommands() got OBOE_SERVICE_EVENT_STARTED");
            setState(OBOE_STREAM_STATE_STARTED);
            break;
        case OBOE_SERVICE_EVENT_PAUSED:
            ALOGD("processCommands() got OBOE_SERVICE_EVENT_PAUSED");
            setState(OBOE_STREAM_STATE_PAUSED);
            break;
        case OBOE_SERVICE_EVENT_FLUSHED:
            ALOGD("processCommands() got OBOE_SERVICE_EVENT_FLUSHED");
            setState(OBOE_STREAM_STATE_FLUSHED);
            onFlushFromServer();
            break;
        case OBOE_SERVICE_EVENT_CLOSED:
            ALOGD("processCommands() got OBOE_SERVICE_EVENT_CLOSED");
            setState(OBOE_STREAM_STATE_CLOSED);
            break;
        case OBOE_SERVICE_EVENT_DISCONNECTED:
            result = OBOE_ERROR_DISCONNECTED;
            ALOGW("WARNING - processCommands() OBOE_SERVICE_EVENT_DISCONNECTED");
            break;
        default:
            ALOGW("WARNING - processCommands() Unrecognized event = %d",
                 (int) message->event.event);
            break;
    }
    return result;
}

// Process all the commands coming from the server.
oboe_result_t AudioStreamInternal::processCommands() {
    oboe_result_t result = OBOE_OK;

    // Let the service run in case it is a fake service simulator.
    mService->tickle(); // TODO use real service thread

    while (result == OBOE_OK) {
        OboeServiceMessage message;
        if (mAudioEndpoint.readUpCommand(&message) != 1) {
            break; // no command this time, no problem
        }
        switch (message.what) {
        case OboeServiceMessage::code::TIMESTAMP:
            result = onTimestampFromServer(&message);
            break;

        case OboeServiceMessage::code::EVENT:
            result = onEventFromServer(&message);
            break;

        default:
            ALOGW("WARNING - AudioStreamInternal::processCommands() Unrecognized what = %d",
                 (int) message.what);
            result = OBOE_ERROR_UNEXPECTED_VALUE;
            break;
        }
    }
    return result;
}

// Write the data, block if needed and timeoutMillis > 0
oboe_result_t AudioStreamInternal::write(const void *buffer, int32_t numFrames,
                                         oboe_nanoseconds_t timeoutNanoseconds)
{
    oboe_result_t result = OBOE_OK;
    uint8_t* source = (uint8_t*)buffer;
    oboe_nanoseconds_t currentTimeNanos = AudioClock::getNanoseconds();
    oboe_nanoseconds_t deadlineNanos = currentTimeNanos + timeoutNanoseconds;
    int32_t framesLeft = numFrames;
//    ALOGD("AudioStreamInternal::write(%p, %d) at time %08llu , mState = %d ------------------",
//         buffer, numFrames, (unsigned long long) currentTimeNanos, mState);

    // Write until all the data has been written or until a timeout occurs.
    while (framesLeft > 0) {
        // The call to writeNow() will not block. It will just write as much as it can.
        oboe_nanoseconds_t wakeTimeNanos = 0;
        oboe_result_t framesWritten = writeNow(source, framesLeft,
                                               currentTimeNanos, &wakeTimeNanos);
//        ALOGD("AudioStreamInternal::write() writeNow() framesLeft = %d --> framesWritten = %d", framesLeft, framesWritten);
        if (framesWritten < 0) {
            result = framesWritten;
            break;
        }
        framesLeft -= (int32_t) framesWritten;
        source += framesWritten * getBytesPerFrame();

        // Should we block?
        if (timeoutNanoseconds == 0) {
            break; // don't block
        } else if (framesLeft > 0) {
            //ALOGD("AudioStreamInternal:: original wakeTimeNanos %lld", (long long) wakeTimeNanos);
            // clip the wake time to something reasonable
            if (wakeTimeNanos < currentTimeNanos) {
                wakeTimeNanos = currentTimeNanos;
            }
            if (wakeTimeNanos > deadlineNanos) {
                // If we time out, just return the framesWritten so far.
                ALOGE("AudioStreamInternal::write(): timed out after %lld nanos", (long long) timeoutNanoseconds);
                break;
            }

            //ALOGD("AudioStreamInternal:: sleep until %lld, dur = %lld", (long long) wakeTimeNanos,
            //        (long long) (wakeTimeNanos - currentTimeNanos));
            AudioClock::sleepForNanos(wakeTimeNanos - currentTimeNanos);
            currentTimeNanos = AudioClock::getNanoseconds();
        }
    }

    // return error or framesWritten
    return (result < 0) ? result : numFrames - framesLeft;
}

// Write as much data as we can without blocking.
oboe_result_t AudioStreamInternal::writeNow(const void *buffer, int32_t numFrames,
                                         oboe_nanoseconds_t currentNanoTime, oboe_nanoseconds_t *wakeTimePtr) {
    {
        oboe_result_t result = processCommands();
        if (result != OBOE_OK) {
            return result;
        }
    }

    if (mAudioEndpoint.isOutputFreeRunning()) {
        // Update data queue based on the timing model.
        int64_t estimatedReadCounter = mClockModel.convertTimeToPosition(currentNanoTime);
        mAudioEndpoint.setDownDataReadCounter(estimatedReadCounter);
        // If the read index passed the write index then consider it an underrun.
        if (mAudioEndpoint.getFullFramesAvailable() < 0) {
            mXRunCount++;
        }
    }
    // TODO else query from endpoint cuz set by actual reader, maybe

    // Write some data to the buffer.
    int32_t framesWritten = mAudioEndpoint.writeDataNow(buffer, numFrames);
    if (framesWritten > 0) {
        incrementFramesWritten(framesWritten);
    }
    //ALOGD("AudioStreamInternal::writeNow() - tried to write %d frames, wrote %d",
    //    numFrames, framesWritten);

    // Calculate an ideal time to wake up.
    if (wakeTimePtr != nullptr && framesWritten >= 0) {
        // By default wake up a few milliseconds from now.  // TODO review
        oboe_nanoseconds_t wakeTime = currentNanoTime + (2 * OBOE_NANOS_PER_MILLISECOND);
        switch (getState()) {
            case OBOE_STREAM_STATE_OPEN:
            case OBOE_STREAM_STATE_STARTING:
                if (framesWritten != 0) {
                    // Don't wait to write more data. Just prime the buffer.
                    wakeTime = currentNanoTime;
                }
                break;
            case OBOE_STREAM_STATE_STARTED:   // When do we expect the next read burst to occur?
                {
                    uint32_t burstSize = mFramesPerBurst;
                    if (burstSize < 32) {
                        burstSize = 32; // TODO review
                    }

                    uint64_t nextReadPosition = mAudioEndpoint.getDownDataReadCounter() + burstSize;
                    wakeTime = mClockModel.convertPositionToTime(nextReadPosition);
                }
                break;
            default:
                break;
        }
        *wakeTimePtr = wakeTime;

    }
//    ALOGD("AudioStreamInternal::writeNow finished: now = %llu, read# = %llu, wrote# = %llu",
//         (unsigned long long)currentNanoTime,
//         (unsigned long long)mAudioEndpoint.getDownDataReadCounter(),
//         (unsigned long long)mAudioEndpoint.getDownDataWriteCounter());
    return framesWritten;
}

oboe_result_t AudioStreamInternal::waitForStateChange(oboe_stream_state_t currentState,
                                                      oboe_stream_state_t *nextState,
                                                      oboe_nanoseconds_t timeoutNanoseconds)

{
    oboe_result_t result = processCommands();
//    ALOGD("AudioStreamInternal::waitForStateChange() - processCommands() returned %d", result);
    if (result != OBOE_OK) {
        return result;
    }
    // TODO replace this polling with a timed sleep on a futex on the message queue
    int32_t durationNanos = 5 * OBOE_NANOS_PER_MILLISECOND;
    oboe_stream_state_t state = getState();
//    ALOGD("AudioStreamInternal::waitForStateChange() - state = %d", state);
    while (state == currentState && timeoutNanoseconds > 0) {
        // TODO use futex from service message queue
        if (durationNanos > timeoutNanoseconds) {
            durationNanos = timeoutNanoseconds;
        }
        AudioClock::sleepForNanos(durationNanos);
        timeoutNanoseconds -= durationNanos;

        result = processCommands();
        if (result != OBOE_OK) {
            return result;
        }

        state = getState();
//        ALOGD("AudioStreamInternal::waitForStateChange() - state = %d", state);
    }
    if (nextState != nullptr) {
        *nextState = state;
    }
    return (state == currentState) ? OBOE_ERROR_TIMEOUT : OBOE_OK;
}


void AudioStreamInternal::processTimestamp(uint64_t position, oboe_nanoseconds_t time) {
    mClockModel.processTimestamp( position, time);
}

oboe_result_t AudioStreamInternal::setBufferSize(oboe_size_frames_t requestedFrames,
                                        oboe_size_frames_t *actualFrames) {
    return mAudioEndpoint.setBufferSizeInFrames(requestedFrames, actualFrames);
}

oboe_size_frames_t AudioStreamInternal::getBufferSize() const
{
    return mAudioEndpoint.getBufferSizeInFrames();
}

oboe_size_frames_t AudioStreamInternal::getBufferCapacity() const
{
    return mAudioEndpoint.getBufferCapacityInFrames();
}

oboe_size_frames_t AudioStreamInternal::getFramesPerBurst() const
{
    return mEndpointDescriptor.downDataQueueDescriptor.framesPerBurst;
}

oboe_position_frames_t AudioStreamInternal::getFramesRead()
{
    oboe_position_frames_t framesRead =
            mClockModel.convertTimeToPosition(AudioClock::getNanoseconds())
            + mFramesOffsetFromService;
    // Prevent retrograde motion.
    if (framesRead < mLastFramesRead) {
        framesRead = mLastFramesRead;
    } else {
        mLastFramesRead = framesRead;
    }
    ALOGD("AudioStreamInternal::getFramesRead() returns %lld", (long long)framesRead);
    return framesRead;
}

// TODO implement getTimestamp
