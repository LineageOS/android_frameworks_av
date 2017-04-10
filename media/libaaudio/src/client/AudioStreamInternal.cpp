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

#define LOG_TAG "AAudio"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <assert.h>

#include <binder/IServiceManager.h>

#include <aaudio/AAudio.h>
#include <utils/String16.h>

#include "AudioClock.h"
#include "AudioEndpointParcelable.h"
#include "binding/AAudioStreamRequest.h"
#include "binding/AAudioStreamConfiguration.h"
#include "binding/IAAudioService.h"
#include "binding/AAudioServiceMessage.h"
#include "fifo/FifoBuffer.h"

#include "core/AudioStreamBuilder.h"
#include "AudioStreamInternal.h"

#define LOG_TIMESTAMPS   0

using android::String16;
using android::IServiceManager;
using android::defaultServiceManager;
using android::interface_cast;
using android::Mutex;
using android::WrappingBuffer;

using namespace aaudio;

#define MIN_TIMEOUT_NANOS        (1000 * AAUDIO_NANOS_PER_MILLISECOND)

// Wait at least this many times longer than the operation should take.
#define MIN_TIMEOUT_OPERATIONS    4

#define ALOG_CONDITION   (mInService == false)

AudioStreamInternal::AudioStreamInternal(AAudioServiceInterface  &serviceInterface, bool inService)
        : AudioStream()
        , mClockModel()
        , mAudioEndpoint()
        , mServiceStreamHandle(AAUDIO_HANDLE_INVALID)
        , mFramesPerBurst(16)
        , mServiceInterface(serviceInterface)
        , mInService(inService)
{
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

    // Build the request to send to the server.
    request.setUserId(getuid());
    request.setProcessId(getpid());
    request.setDirection(getDirection());

    request.getConfiguration().setDeviceId(getDeviceId());
    request.getConfiguration().setSampleRate(getSampleRate());
    request.getConfiguration().setSamplesPerFrame(getSamplesPerFrame());
    request.getConfiguration().setAudioFormat(getFormat());
    aaudio_sharing_mode_t sharingMode = getSharingMode();
    ALOGE("AudioStreamInternal.open(): sharingMode %d", sharingMode);
    request.getConfiguration().setSharingMode(sharingMode);
    request.getConfiguration().setBufferCapacity(builder.getBufferCapacity());

    mServiceStreamHandle = mServiceInterface.openStream(request, configuration);
    ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal.open(): openStream returned mServiceStreamHandle = 0x%08X",
         (unsigned int)mServiceStreamHandle);
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
        ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal.open(): getStreamDescriptor(0x%08X) returns %d",
              mServiceStreamHandle, result);
        if (result != AAUDIO_OK) {
            ALOGE("AudioStreamInternal.open(): getStreamDescriptor returns %d", result);
            mServiceInterface.closeStream(mServiceStreamHandle);
            return result;
        }

        // resolve parcelable into a descriptor
        result = mEndPointParcelable.resolve(&mEndpointDescriptor);
        if (result != AAUDIO_OK) {
            ALOGE("AudioStreamInternal.open(): resolve() returns %d", result);
            mServiceInterface.closeStream(mServiceStreamHandle);
            return result;
        }

        // Configure endpoint based on descriptor.
        mAudioEndpoint.configure(&mEndpointDescriptor);

        mFramesPerBurst = mEndpointDescriptor.downDataQueueDescriptor.framesPerBurst;
        assert(mFramesPerBurst >= 16);
        assert(mEndpointDescriptor.downDataQueueDescriptor.capacityInFrames < 10 * 1024);

        mClockModel.setSampleRate(getSampleRate());
        mClockModel.setFramesPerBurst(mFramesPerBurst);

        if (getDataCallbackProc()) {
            mCallbackFrames = builder.getFramesPerDataCallback();
            if (mCallbackFrames > getBufferCapacity() / 2) {
                ALOGE("AudioStreamInternal.open(): framesPerCallback too large");
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
    ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal.close(): mServiceStreamHandle = 0x%08X", mServiceStreamHandle);
    if (mServiceStreamHandle != AAUDIO_HANDLE_INVALID) {
        aaudio_handle_t serviceStreamHandle = mServiceStreamHandle;
        mServiceStreamHandle = AAUDIO_HANDLE_INVALID;

        mServiceInterface.closeStream(serviceStreamHandle);
        delete[] mCallbackBuffer;
        return mEndPointParcelable.close();
    } else {
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
}


// Render audio in the application callback and then write the data to the stream.
void *AudioStreamInternal::callbackLoop() {
    aaudio_result_t result = AAUDIO_OK;
    aaudio_data_callback_result_t callbackResult = AAUDIO_CALLBACK_RESULT_CONTINUE;
    int32_t framesWritten = 0;
    AAudioStream_dataCallback appCallback = getDataCallbackProc();
    if (appCallback == nullptr) return NULL;

    while (mCallbackEnabled.load() && isPlaying() && (result >= 0)) { // result might be a frame count
        // Call application using the AAudio callback interface.
        callbackResult = (*appCallback)(
                (AAudioStream *) this,
                getDataCallbackUserData(),
                mCallbackBuffer,
                mCallbackFrames);

        if (callbackResult == AAUDIO_CALLBACK_RESULT_CONTINUE) {
            // Write audio data to stream
            int64_t timeoutNanos = calculateReasonableTimeout(mCallbackFrames);
            result = write(mCallbackBuffer, mCallbackFrames, timeoutNanos);
            if (result == AAUDIO_ERROR_DISCONNECTED) {
                if (getErrorCallbackProc() != nullptr) {
                    ALOGD("AudioStreamAAudio(): callbackLoop() stream disconnected");
                    (*getErrorCallbackProc())(
                            (AAudioStream *) this,
                            getErrorCallbackUserData(),
                            AAUDIO_OK);
                }
                break;
            } else if (result != mCallbackFrames) {
                ALOGE("AudioStreamAAudio(): callbackLoop() wrote %d / %d",
                      framesWritten, mCallbackFrames);
                break;
            }
        } else if (callbackResult == AAUDIO_CALLBACK_RESULT_STOP) {
            ALOGD("AudioStreamAAudio(): callback returned AAUDIO_CALLBACK_RESULT_STOP");
            break;
        }
    }

    ALOGD("AudioStreamAAudio(): callbackLoop() exiting, result = %d, isPlaying() = %d",
          result, (int) isPlaying());
    return NULL; // TODO review
}

static void *aaudio_callback_thread_proc(void *context)
{
    AudioStreamInternal *stream = (AudioStreamInternal *)context;
    //LOGD("AudioStreamAAudio(): oboe_callback_thread, stream = %p", stream);
    if (stream != NULL) {
        return stream->callbackLoop();
    } else {
        return NULL;
    }
}

aaudio_result_t AudioStreamInternal::requestStart()
{
    int64_t startTime;
    ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal(): start()");
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }

    startTime = AudioClock::getNanoseconds();
    mClockModel.start(startTime);
    processTimestamp(0, startTime);
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
    int64_t timeoutNanoseconds = (MIN_TIMEOUT_OPERATIONS * framesPerOperation * AAUDIO_NANOS_PER_SECOND)
                         / getSampleRate();
    if (timeoutNanoseconds < MIN_TIMEOUT_NANOS) { // arbitrary number of seconds
        timeoutNanoseconds = MIN_TIMEOUT_NANOS;
    }
    return timeoutNanoseconds;
}

aaudio_result_t AudioStreamInternal::stopCallback()
{
    if (isDataCallbackActive()) {
        mCallbackEnabled.store(false);
        return joinThread(NULL, calculateReasonableTimeout(mCallbackFrames));
    } else {
        return AAUDIO_OK;
    }
}

aaudio_result_t AudioStreamInternal::requestPauseInternal()
{
    ALOGD("AudioStreamInternal(): pause()");
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }

    mClockModel.stop(AudioClock::getNanoseconds());
    setState(AAUDIO_STREAM_STATE_PAUSING);
    return mServiceInterface.startStream(mServiceStreamHandle);
}

aaudio_result_t AudioStreamInternal::requestPause()
{
    aaudio_result_t result = stopCallback();
    if (result != AAUDIO_OK) {
        return result;
    }
    return requestPauseInternal();
}

aaudio_result_t AudioStreamInternal::requestFlush() {
    ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal(): flush()");
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }

    setState(AAUDIO_STREAM_STATE_FLUSHING);
    return mServiceInterface.flushStream(mServiceStreamHandle);
}

void AudioStreamInternal::onFlushFromServer() {
    ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal(): onFlushFromServer()");
    int64_t readCounter = mAudioEndpoint.getDownDataReadCounter();
    int64_t writeCounter = mAudioEndpoint.getDownDataWriteCounter();
    // Bump offset so caller does not see the retrograde motion in getFramesRead().
    int64_t framesFlushed = writeCounter - readCounter;
    mFramesOffsetFromService += framesFlushed;
    // Flush written frames by forcing writeCounter to readCounter.
    // This is because we cannot move the read counter in the hardware.
    mAudioEndpoint.setDownDataWriteCounter(readCounter);
}

aaudio_result_t AudioStreamInternal::requestStop()
{
    // TODO better implementation of requestStop()
    aaudio_result_t result = requestPause();
    if (result == AAUDIO_OK) {
        aaudio_stream_state_t state;
        result = waitForStateChange(AAUDIO_STREAM_STATE_PAUSING,
                                    &state,
                                    500 * AAUDIO_NANOS_PER_MILLISECOND);// TODO temporary code
        if (result == AAUDIO_OK) {
            result = requestFlush();
        }
    }
    return result;
}

aaudio_result_t AudioStreamInternal::registerThread() {
    ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal(): registerThread()");
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    return mServiceInterface.registerAudioThread(mServiceStreamHandle,
                                              getpid(),
                                              gettid(),
                                              getPeriodNanoseconds());
}

aaudio_result_t AudioStreamInternal::unregisterThread() {
    ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal(): unregisterThread()");
    if (mServiceStreamHandle == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    return mServiceInterface.unregisterAudioThread(mServiceStreamHandle, getpid(), gettid());
}

aaudio_result_t AudioStreamInternal::getTimestamp(clockid_t clockId,
                           int64_t *framePosition,
                           int64_t *timeNanoseconds) {
    // TODO implement using real HAL
    int64_t time = AudioClock::getNanoseconds();
    *framePosition = mClockModel.convertTimeToPosition(time);
    *timeNanoseconds = time + (10 * AAUDIO_NANOS_PER_MILLISECOND); // Fake hardware delay
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamInternal::updateStateWhileWaiting() {
    if (isDataCallbackActive()) {
        return AAUDIO_OK; // state is getting updated by the callback thread read/write call
    }
    return processCommands();
}

#if LOG_TIMESTAMPS
static void AudioStreamInternal_LogTimestamp(AAudioServiceMessage &command) {
    static int64_t oldPosition = 0;
    static int64_t oldTime = 0;
    int64_t framePosition = command.timestamp.position;
    int64_t nanoTime = command.timestamp.timestamp;
    ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal() timestamp says framePosition = %08lld at nanoTime %llu",
         (long long) framePosition,
         (long long) nanoTime);
    int64_t nanosDelta = nanoTime - oldTime;
    if (nanosDelta > 0 && oldTime > 0) {
        int64_t framesDelta = framePosition - oldPosition;
        int64_t rate = (framesDelta * AAUDIO_NANOS_PER_SECOND) / nanosDelta;
        ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal() - framesDelta = %08lld", (long long) framesDelta);
        ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal() - nanosDelta = %08lld", (long long) nanosDelta);
        ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal() - measured rate = %llu", (unsigned long long) rate);
    }
    oldPosition = framePosition;
    oldTime = nanoTime;
}
#endif

aaudio_result_t AudioStreamInternal::onTimestampFromServer(AAudioServiceMessage *message) {
    int64_t framePosition = 0;
#if LOG_TIMESTAMPS
    AudioStreamInternal_LogTimestamp(command);
#endif
    framePosition = message->timestamp.position;
    processTimestamp(framePosition, message->timestamp.timestamp);
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamInternal::onEventFromServer(AAudioServiceMessage *message) {
    aaudio_result_t result = AAUDIO_OK;
    ALOGD_IF(ALOG_CONDITION, "processCommands() got event %d", message->event.event);
    switch (message->event.event) {
        case AAUDIO_SERVICE_EVENT_STARTED:
            ALOGD_IF(ALOG_CONDITION, "processCommands() got AAUDIO_SERVICE_EVENT_STARTED");
            setState(AAUDIO_STREAM_STATE_STARTED);
            break;
        case AAUDIO_SERVICE_EVENT_PAUSED:
            ALOGD_IF(ALOG_CONDITION, "processCommands() got AAUDIO_SERVICE_EVENT_PAUSED");
            setState(AAUDIO_STREAM_STATE_PAUSED);
            break;
        case AAUDIO_SERVICE_EVENT_FLUSHED:
            ALOGD_IF(ALOG_CONDITION, "processCommands() got AAUDIO_SERVICE_EVENT_FLUSHED");
            setState(AAUDIO_STREAM_STATE_FLUSHED);
            onFlushFromServer();
            break;
        case AAUDIO_SERVICE_EVENT_CLOSED:
            ALOGD_IF(ALOG_CONDITION, "processCommands() got AAUDIO_SERVICE_EVENT_CLOSED");
            setState(AAUDIO_STREAM_STATE_CLOSED);
            break;
        case AAUDIO_SERVICE_EVENT_DISCONNECTED:
            result = AAUDIO_ERROR_DISCONNECTED;
            setState(AAUDIO_STREAM_STATE_DISCONNECTED);
            ALOGW("WARNING - processCommands() AAUDIO_SERVICE_EVENT_DISCONNECTED");
            break;
        case AAUDIO_SERVICE_EVENT_VOLUME:
            mVolume = message->event.dataDouble;
            ALOGD_IF(ALOG_CONDITION, "processCommands() AAUDIO_SERVICE_EVENT_VOLUME %f", mVolume);
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
        //ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::processCommands() - looping, %d", result);
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
            ALOGW("WARNING - AudioStreamInternal::processCommands() Unrecognized what = %d",
                 (int) message.what);
            result = AAUDIO_ERROR_UNEXPECTED_VALUE;
            break;
        }
    }
    return result;
}

// Write the data, block if needed and timeoutMillis > 0
aaudio_result_t AudioStreamInternal::write(const void *buffer, int32_t numFrames,
                                         int64_t timeoutNanoseconds)
{
    aaudio_result_t result = AAUDIO_OK;
    int32_t loopCount = 0;
    uint8_t* source = (uint8_t*)buffer;
    int64_t currentTimeNanos = AudioClock::getNanoseconds();
    int64_t deadlineNanos = currentTimeNanos + timeoutNanoseconds;
    int32_t framesLeft = numFrames;
    //ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::write(%p, %d) at time %08llu , mState = %s",
    //      buffer, numFrames, (unsigned long long) currentTimeNanos,
    //      AAudio_convertStreamStateToText(getState()));

    // Write until all the data has been written or until a timeout occurs.
    while (framesLeft > 0) {
        //ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::write() loop: framesLeft = %d, loopCount = %d  =====",
        //      framesLeft, loopCount++);
        // The call to writeNow() will not block. It will just write as much as it can.
        int64_t wakeTimeNanos = 0;
        aaudio_result_t framesWritten = writeNow(source, framesLeft,
                                               currentTimeNanos, &wakeTimeNanos);
        //ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::write() loop: framesWritten = %d", framesWritten);
        if (framesWritten < 0) {
            ALOGE("AudioStreamInternal::write() loop: writeNow returned %d", framesWritten);
            result = framesWritten;
            break;
        }
        framesLeft -= (int32_t) framesWritten;
        source += framesWritten * getBytesPerFrame();

        // Should we block?
        if (timeoutNanoseconds == 0) {
            break; // don't block
        } else if (framesLeft > 0) {
            //ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal:: original wakeTimeNanos %lld", (long long) wakeTimeNanos);
            // clip the wake time to something reasonable
            if (wakeTimeNanos < currentTimeNanos) {
                wakeTimeNanos = currentTimeNanos;
            }
            if (wakeTimeNanos > deadlineNanos) {
                // If we time out, just return the framesWritten so far.
                ALOGE("AudioStreamInternal::write(): timed out after %lld nanos",
                      (long long) timeoutNanoseconds);
                break;
            }

            //ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal:: sleep until %lld, dur = %lld", (long long) wakeTimeNanos,
            //        (long long) (wakeTimeNanos - currentTimeNanos));
            AudioClock::sleepForNanos(wakeTimeNanos - currentTimeNanos);
            currentTimeNanos = AudioClock::getNanoseconds();
        }
    }

    // return error or framesWritten
    //ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::write() result = %d, framesLeft = %d, #%d",
    //      result, framesLeft, loopCount);
    (void) loopCount;
    return (result < 0) ? result : numFrames - framesLeft;
}

// Write as much data as we can without blocking.
aaudio_result_t AudioStreamInternal::writeNow(const void *buffer, int32_t numFrames,
                                         int64_t currentNanoTime, int64_t *wakeTimePtr) {

    //ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::writeNow(%p) - enter", buffer);
    {
        aaudio_result_t result = processCommands();
        //ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::writeNow() - processCommands() returned %d", result);
        if (result != AAUDIO_OK) {
            return result;
        }
    }

    if (mAudioEndpoint.isOutputFreeRunning()) {
        ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::writeNow() - update read counter");
        // Update data queue based on the timing model.
        int64_t estimatedReadCounter = mClockModel.convertTimeToPosition(currentNanoTime);
        mAudioEndpoint.setDownDataReadCounter(estimatedReadCounter);
    }
    // TODO else query from endpoint cuz set by actual reader, maybe

    // If the read index passed the write index then consider it an underrun.
    if (mAudioEndpoint.getFullFramesAvailable() < 0) {
        mXRunCount++;
    }

    // Write some data to the buffer.
    //ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::writeNow() - writeNowWithConversion(%d)", numFrames);
    int32_t framesWritten = writeNowWithConversion(buffer, numFrames);
    //ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::writeNow() - tried to write %d frames, wrote %d",
    //    numFrames, framesWritten);

    // Calculate an ideal time to wake up.
    if (wakeTimePtr != nullptr && framesWritten >= 0) {
        // By default wake up a few milliseconds from now.  // TODO review
        int64_t wakeTime = currentNanoTime + (1 * AAUDIO_NANOS_PER_MILLISECOND);
        aaudio_stream_state_t state = getState();
        //ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::writeNow() - wakeTime based on %s",
        //      AAudio_convertStreamStateToText(state));
        switch (state) {
            case AAUDIO_STREAM_STATE_OPEN:
            case AAUDIO_STREAM_STATE_STARTING:
                if (framesWritten != 0) {
                    // Don't wait to write more data. Just prime the buffer.
                    wakeTime = currentNanoTime;
                }
                break;
            case AAUDIO_STREAM_STATE_STARTED:   // When do we expect the next read burst to occur?
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
//    ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::writeNow finished: now = %llu, read# = %llu, wrote# = %llu",
//         (unsigned long long)currentNanoTime,
//         (unsigned long long)mAudioEndpoint.getDownDataReadCounter(),
//         (unsigned long long)mAudioEndpoint.getDownDataWriteCounter());
    return framesWritten;
}


// TODO this function needs a major cleanup.
aaudio_result_t AudioStreamInternal::writeNowWithConversion(const void *buffer,
                                       int32_t numFrames) {
    // ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::writeNowWithConversion(%p, %d)", buffer, numFrames);
    WrappingBuffer wrappingBuffer;
    mAudioEndpoint.getEmptyRoomAvailable(&wrappingBuffer);
    uint8_t *source = (uint8_t *) buffer;
    int32_t framesLeft = numFrames;

    mAudioEndpoint.getEmptyRoomAvailable(&wrappingBuffer);

    // Read data in one or two parts.
    int partIndex = 0;
    while (framesLeft > 0 && partIndex < WrappingBuffer::SIZE) {
        int32_t framesToWrite = framesLeft;
        int32_t framesAvailable = wrappingBuffer.numFrames[partIndex];
        if (framesAvailable > 0) {
            if (framesToWrite > framesAvailable) {
                framesToWrite = framesAvailable;
            }
            int32_t numBytes = getBytesPerFrame();
            // TODO handle volume scaling
            if (getFormat() == mDeviceFormat) {
                // Copy straight through.
                memcpy(wrappingBuffer.data[partIndex], source, numBytes);
            } else if (getFormat() == AAUDIO_FORMAT_PCM_FLOAT
                    && mDeviceFormat == AAUDIO_FORMAT_PCM_I16) {
                // Data conversion.
                AAudioConvert_floatToPcm16(
                        (const float *) source,
                        framesToWrite * getSamplesPerFrame(),
                        (int16_t *) wrappingBuffer.data[partIndex]);
            } else {
                // TODO handle more conversions
                ALOGE("AudioStreamInternal::writeNowWithConversion() unsupported formats: %d, %d",
                      getFormat(), mDeviceFormat);
                return AAUDIO_ERROR_UNEXPECTED_VALUE;
            }

            source += numBytes;
            framesLeft -= framesToWrite;
        }
        partIndex++;
    }
    int32_t framesWritten = numFrames - framesLeft;
    mAudioEndpoint.advanceWriteIndex(framesWritten);

    if (framesWritten > 0) {
        incrementFramesWritten(framesWritten);
    }
    // ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::writeNowWithConversion() returns %d", framesWritten);
    return framesWritten;
}

void AudioStreamInternal::processTimestamp(uint64_t position, int64_t time) {
    mClockModel.processTimestamp( position, time);
}

aaudio_result_t AudioStreamInternal::setBufferSize(int32_t requestedFrames) {
    int32_t actualFrames = 0;
    aaudio_result_t result = mAudioEndpoint.setBufferSizeInFrames(requestedFrames, &actualFrames);
    if (result < 0) {
        return result;
    } else {
        return (aaudio_result_t) actualFrames;
    }
}

int32_t AudioStreamInternal::getBufferSize() const
{
    return mAudioEndpoint.getBufferSizeInFrames();
}

int32_t AudioStreamInternal::getBufferCapacity() const
{
    return mAudioEndpoint.getBufferCapacityInFrames();
}

int32_t AudioStreamInternal::getFramesPerBurst() const
{
    return mEndpointDescriptor.downDataQueueDescriptor.framesPerBurst;
}

int64_t AudioStreamInternal::getFramesRead()
{
    int64_t framesRead =
            mClockModel.convertTimeToPosition(AudioClock::getNanoseconds())
            + mFramesOffsetFromService;
    // Prevent retrograde motion.
    if (framesRead < mLastFramesRead) {
        framesRead = mLastFramesRead;
    } else {
        mLastFramesRead = framesRead;
    }
    ALOGD_IF(ALOG_CONDITION, "AudioStreamInternal::getFramesRead() returns %lld", (long long)framesRead);
    return framesRead;
}

// TODO implement getTimestamp
