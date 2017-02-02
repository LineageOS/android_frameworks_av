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

#include <time.h>
#include <pthread.h>

#include <aaudio/AAudioDefinitions.h>
#include <aaudio/AAudio.h>

#include "AudioStreamBuilder.h"
#include "AudioStream.h"
#include "AudioClock.h"
#include "client/AudioStreamInternal.h"
#include "HandleTracker.h"

using namespace aaudio;

// This is not the maximum theoretic possible number of handles that the HandlerTracker
// class could support; instead it is the maximum number of handles that we are configuring
// for our HandleTracker instance (sHandleTracker).
#define AAUDIO_MAX_HANDLES  64

// Macros for common code that includes a return.
// TODO Consider using do{}while(0) construct. I tried but it hung AndroidStudio
#define CONVERT_BUILDER_HANDLE_OR_RETURN() \
    convertAAudioBuilderToStreamBuilder(builder); \
    if (streamBuilder == nullptr) { \
        return AAUDIO_ERROR_INVALID_HANDLE; \
    }

#define COMMON_GET_FROM_BUILDER_OR_RETURN(resultPtr) \
    CONVERT_BUILDER_HANDLE_OR_RETURN() \
    if ((resultPtr) == nullptr) { \
        return AAUDIO_ERROR_NULL; \
    }

#define CONVERT_STREAM_HANDLE_OR_RETURN() \
    convertAAudioStreamToAudioStream(stream); \
    if (audioStream == nullptr) { \
        return AAUDIO_ERROR_INVALID_HANDLE; \
    }

#define COMMON_GET_FROM_STREAM_OR_RETURN(resultPtr) \
    CONVERT_STREAM_HANDLE_OR_RETURN(); \
    if ((resultPtr) == nullptr) { \
        return AAUDIO_ERROR_NULL; \
    }

// Static data.
// TODO static constructors are discouraged, alternatives?
static HandleTracker sHandleTracker(AAUDIO_MAX_HANDLES);

typedef enum
{
    AAUDIO_HANDLE_TYPE_STREAM,
    AAUDIO_HANDLE_TYPE_STREAM_BUILDER,
    AAUDIO_HANDLE_TYPE_COUNT
} aaudio_handle_type_t;
static_assert(AAUDIO_HANDLE_TYPE_COUNT <= HANDLE_TRACKER_MAX_TYPES, "Too many handle types.");


#define AAUDIO_CASE_ENUM(name) case name: return #name

AAUDIO_API const char * AAudio_convertResultToText(aaudio_result_t returnCode) {
    switch (returnCode) {
        AAUDIO_CASE_ENUM(AAUDIO_OK);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_ILLEGAL_ARGUMENT);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_INCOMPATIBLE);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_INTERNAL);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_INVALID_STATE);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_INVALID_HANDLE);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_INVALID_QUERY);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_UNIMPLEMENTED);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_UNAVAILABLE);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_NO_FREE_HANDLES);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_NO_MEMORY);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_NULL);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_TIMEOUT);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_WOULD_BLOCK);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_INVALID_ORDER);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_OUT_OF_RANGE);
        AAUDIO_CASE_ENUM(AAUDIO_ERROR_NO_SERVICE);
    }
    return "Unrecognized AAudio error.";
}

AAUDIO_API const char * AAudio_convertStreamStateToText(aaudio_stream_state_t state) {
    switch (state) {
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_UNINITIALIZED);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_OPEN);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_STARTING);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_STARTED);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_PAUSING);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_PAUSED);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_FLUSHING);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_FLUSHED);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_STOPPING);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_STOPPED);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_CLOSING);
        AAUDIO_CASE_ENUM(AAUDIO_STREAM_STATE_CLOSED);
    }
    return "Unrecognized AAudio state.";
}

#undef AAUDIO_CASE_ENUM

static AudioStream *convertAAudioStreamToAudioStream(AAudioStream stream)
{
    return (AudioStream *) sHandleTracker.get(AAUDIO_HANDLE_TYPE_STREAM,
                                              (aaudio_handle_t) stream);
}

static AudioStreamBuilder *convertAAudioBuilderToStreamBuilder(AAudioStreamBuilder builder)
{
    return (AudioStreamBuilder *) sHandleTracker.get(AAUDIO_HANDLE_TYPE_STREAM_BUILDER,
                                                     (aaudio_handle_t) builder);
}

AAUDIO_API aaudio_result_t AAudio_createStreamBuilder(AAudioStreamBuilder *builder)
{
    ALOGD("AAudio_createStreamBuilder(): check sHandleTracker.isInitialized ()");
    if (!sHandleTracker.isInitialized()) {
        return AAUDIO_ERROR_NO_MEMORY;
    }
    AudioStreamBuilder *audioStreamBuilder =  new AudioStreamBuilder();
    if (audioStreamBuilder == nullptr) {
        return AAUDIO_ERROR_NO_MEMORY;
    }
    ALOGD("AAudio_createStreamBuilder(): created AudioStreamBuilder = %p", audioStreamBuilder);
    // TODO protect the put() with a Mutex
    AAudioStreamBuilder handle = sHandleTracker.put(AAUDIO_HANDLE_TYPE_STREAM_BUILDER,
            audioStreamBuilder);
    if (handle < 0) {
        delete audioStreamBuilder;
        return static_cast<aaudio_result_t>(handle);
    } else {
        *builder = handle;
    }
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_setDeviceId(AAudioStreamBuilder builder,
                                                     aaudio_device_id_t deviceId)
{
    AudioStreamBuilder *streamBuilder = CONVERT_BUILDER_HANDLE_OR_RETURN();
    streamBuilder->setDeviceId(deviceId);
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_getDeviceId(AAudioStreamBuilder builder,
                                              aaudio_device_id_t *deviceId)
{
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(deviceId);
    *deviceId = streamBuilder->getDeviceId();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_setSampleRate(AAudioStreamBuilder builder,
                                              aaudio_sample_rate_t sampleRate)
{
    AudioStreamBuilder *streamBuilder = CONVERT_BUILDER_HANDLE_OR_RETURN();
    streamBuilder->setSampleRate(sampleRate);
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_getSampleRate(AAudioStreamBuilder builder,
                                              aaudio_sample_rate_t *sampleRate)
{
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(sampleRate);
    *sampleRate = streamBuilder->getSampleRate();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_setSamplesPerFrame(AAudioStreamBuilder builder,
                                                   int32_t samplesPerFrame)
{
    AudioStreamBuilder *streamBuilder = CONVERT_BUILDER_HANDLE_OR_RETURN();
    streamBuilder->setSamplesPerFrame(samplesPerFrame);
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_getSamplesPerFrame(AAudioStreamBuilder builder,
                                                   int32_t *samplesPerFrame)
{
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(samplesPerFrame);
    *samplesPerFrame = streamBuilder->getSamplesPerFrame();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_setDirection(AAudioStreamBuilder builder,
                                             aaudio_direction_t direction)
{
    AudioStreamBuilder *streamBuilder = CONVERT_BUILDER_HANDLE_OR_RETURN();
    streamBuilder->setDirection(direction);
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_getDirection(AAudioStreamBuilder builder,
                                             aaudio_direction_t *direction)
{
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(direction);
    *direction = streamBuilder->getDirection();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_setFormat(AAudioStreamBuilder builder,
                                                   aaudio_audio_format_t format)
{
    AudioStreamBuilder *streamBuilder = CONVERT_BUILDER_HANDLE_OR_RETURN();
    streamBuilder->setFormat(format);
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_getFormat(AAudioStreamBuilder builder,
                                                   aaudio_audio_format_t *format)
{
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(format);
    *format = streamBuilder->getFormat();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_setSharingMode(AAudioStreamBuilder builder,
                                                        aaudio_sharing_mode_t sharingMode)
{
    AudioStreamBuilder *streamBuilder = CONVERT_BUILDER_HANDLE_OR_RETURN();
    if ((sharingMode < 0) || (sharingMode >= AAUDIO_SHARING_MODE_COUNT)) {
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    } else {
        streamBuilder->setSharingMode(sharingMode);
        return AAUDIO_OK;
    }
}

AAUDIO_API aaudio_result_t AAudioStreamBuilder_getSharingMode(AAudioStreamBuilder builder,
                                                        aaudio_sharing_mode_t *sharingMode)
{
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(sharingMode);
    *sharingMode = streamBuilder->getSharingMode();
    return AAUDIO_OK;
}

static aaudio_result_t  AAudioInternal_openStream(AudioStreamBuilder *streamBuilder,
                                              AAudioStream *streamPtr)
{
    AudioStream *audioStream = nullptr;
    aaudio_result_t result = streamBuilder->build(&audioStream);
    if (result != AAUDIO_OK) {
        return result;
    } else {
        // Create a handle for referencing the object.
        // TODO protect the put() with a Mutex
        AAudioStream handle = sHandleTracker.put(AAUDIO_HANDLE_TYPE_STREAM, audioStream);
        if (handle < 0) {
            delete audioStream;
            return static_cast<aaudio_result_t>(handle);
        }
        *streamPtr = handle;
        return AAUDIO_OK;
    }
}

AAUDIO_API aaudio_result_t  AAudioStreamBuilder_openStream(AAudioStreamBuilder builder,
                                                     AAudioStream *streamPtr)
{
    ALOGD("AAudioStreamBuilder_openStream(): builder = 0x%08X", builder);
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(streamPtr);
    return AAudioInternal_openStream(streamBuilder, streamPtr);
}

AAUDIO_API aaudio_result_t  AAudioStreamBuilder_delete(AAudioStreamBuilder builder)
{
    AudioStreamBuilder *streamBuilder = (AudioStreamBuilder *)
            sHandleTracker.remove(AAUDIO_HANDLE_TYPE_STREAM_BUILDER, builder);
    if (streamBuilder != nullptr) {
        delete streamBuilder;
        return AAUDIO_OK;
    }
    return AAUDIO_ERROR_INVALID_HANDLE;
}

AAUDIO_API aaudio_result_t  AAudioStream_close(AAudioStream stream)
{
    AudioStream *audioStream = (AudioStream *)
            sHandleTracker.remove(AAUDIO_HANDLE_TYPE_STREAM, (aaudio_handle_t)stream);
    ALOGD("AAudioStream_close(0x%08X), audioStream = %p", stream, audioStream);
    if (audioStream != nullptr) {
        audioStream->close();
        delete audioStream;
        return AAUDIO_OK;
    }
    return AAUDIO_ERROR_INVALID_HANDLE;
}

AAUDIO_API aaudio_result_t  AAudioStream_requestStart(AAudioStream stream)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    ALOGD("AAudioStream_requestStart(0x%08X), audioStream = %p", stream, audioStream);
    return audioStream->requestStart();
}

AAUDIO_API aaudio_result_t  AAudioStream_requestPause(AAudioStream stream)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    ALOGD("AAudioStream_requestPause(0x%08X), audioStream = %p", stream, audioStream);
    return audioStream->requestPause();
}

AAUDIO_API aaudio_result_t  AAudioStream_requestFlush(AAudioStream stream)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    ALOGD("AAudioStream_requestFlush(0x%08X), audioStream = %p", stream, audioStream);
    return audioStream->requestFlush();
}

AAUDIO_API aaudio_result_t  AAudioStream_requestStop(AAudioStream stream)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    ALOGD("AAudioStream_requestStop(0x%08X), audioStream = %p", stream, audioStream);
    return audioStream->requestStop();
}

AAUDIO_API aaudio_result_t AAudioStream_waitForStateChange(AAudioStream stream,
                                            aaudio_stream_state_t inputState,
                                            aaudio_stream_state_t *nextState,
                                            aaudio_nanoseconds_t timeoutNanoseconds)
{

    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    return audioStream->waitForStateChange(inputState, nextState, timeoutNanoseconds);
}

// ============================================================
// Stream - non-blocking I/O
// ============================================================

AAUDIO_API aaudio_result_t AAudioStream_read(AAudioStream stream,
                               void *buffer,
                               aaudio_size_frames_t numFrames,
                               aaudio_nanoseconds_t timeoutNanoseconds)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    if (buffer == nullptr) {
        return AAUDIO_ERROR_NULL;
    }
    if (numFrames < 0) {
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    } else if (numFrames == 0) {
        return 0;
    }

    aaudio_result_t result = audioStream->read(buffer, numFrames, timeoutNanoseconds);
    // ALOGD("AAudioStream_read(): read returns %d", result);

    return result;
}

AAUDIO_API aaudio_result_t AAudioStream_write(AAudioStream stream,
                               const void *buffer,
                               aaudio_size_frames_t numFrames,
                               aaudio_nanoseconds_t timeoutNanoseconds)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    if (buffer == nullptr) {
        return AAUDIO_ERROR_NULL;
    }
    if (numFrames < 0) {
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    } else if (numFrames == 0) {
        return 0;
    }

    aaudio_result_t result = audioStream->write(buffer, numFrames, timeoutNanoseconds);
    // ALOGD("AAudioStream_write(): write returns %d", result);

    return result;
}

// ============================================================
// Miscellaneous
// ============================================================

AAUDIO_API aaudio_result_t AAudioStream_createThread(AAudioStream stream,
                                     aaudio_nanoseconds_t periodNanoseconds,
                                     aaudio_audio_thread_proc_t *threadProc, void *arg)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    return audioStream->createThread(periodNanoseconds, threadProc, arg);
}

AAUDIO_API aaudio_result_t AAudioStream_joinThread(AAudioStream stream,
                                   void **returnArg,
                                   aaudio_nanoseconds_t timeoutNanoseconds)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    return audioStream->joinThread(returnArg, timeoutNanoseconds);
}

// ============================================================
// Stream - queries
// ============================================================

// TODO Use aaudio_clockid_t all the way down through the C++ streams.
static clockid_t AAudioConvert_fromAAudioClockId(aaudio_clockid_t clockid)
{
    clockid_t hostClockId;
    switch (clockid) {
        case AAUDIO_CLOCK_MONOTONIC:
            hostClockId = CLOCK_MONOTONIC;
            break;
        case AAUDIO_CLOCK_BOOTTIME:
            hostClockId = CLOCK_BOOTTIME;
            break;
        default:
            hostClockId = 0; // TODO review
    }
    return hostClockId;
}

aaudio_nanoseconds_t AAudio_getNanoseconds(aaudio_clockid_t clockid)
{
    clockid_t hostClockId = AAudioConvert_fromAAudioClockId(clockid);
   return AudioClock::getNanoseconds(hostClockId);
}

AAUDIO_API aaudio_result_t AAudioStream_getSampleRate(AAudioStream stream, aaudio_sample_rate_t *sampleRate)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(sampleRate);
    *sampleRate = audioStream->getSampleRate();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_getSamplesPerFrame(AAudioStream stream, int32_t *samplesPerFrame)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(samplesPerFrame);
    *samplesPerFrame = audioStream->getSamplesPerFrame();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_getState(AAudioStream stream, aaudio_stream_state_t *state)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(state);
    *state = audioStream->getState();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_getFormat(AAudioStream stream, aaudio_audio_format_t *format)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(format);
    *format = audioStream->getFormat();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_setBufferSize(AAudioStream stream,
                                                aaudio_size_frames_t requestedFrames,
                                                aaudio_size_frames_t *actualFrames)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    return audioStream->setBufferSize(requestedFrames, actualFrames);
}

AAUDIO_API aaudio_result_t AAudioStream_getBufferSize(AAudioStream stream, aaudio_size_frames_t *frames)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(frames);
    *frames = audioStream->getBufferSize();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_getDirection(AAudioStream stream, int32_t *direction)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(direction);
    *direction = audioStream->getDirection();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_getFramesPerBurst(AAudioStream stream,
                                                    aaudio_size_frames_t *framesPerBurst)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(framesPerBurst);
    *framesPerBurst = audioStream->getFramesPerBurst();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_getBufferCapacity(AAudioStream stream,
                                           aaudio_size_frames_t *capacity)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(capacity);
    *capacity = audioStream->getBufferCapacity();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_getXRunCount(AAudioStream stream, int32_t *xRunCount)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(xRunCount);
    *xRunCount = audioStream->getXRunCount();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_getDeviceId(AAudioStream stream,
                                                 aaudio_device_id_t *deviceId)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(deviceId);
    *deviceId = audioStream->getDeviceId();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_getSharingMode(AAudioStream stream,
                                                 aaudio_sharing_mode_t *sharingMode)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(sharingMode);
    *sharingMode = audioStream->getSharingMode();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_getFramesWritten(AAudioStream stream,
                                                   aaudio_position_frames_t *frames)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(frames);
    *frames = audioStream->getFramesWritten();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_getFramesRead(AAudioStream stream, aaudio_position_frames_t *frames)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(frames);
    *frames = audioStream->getFramesRead();
    return AAUDIO_OK;
}

AAUDIO_API aaudio_result_t AAudioStream_getTimestamp(AAudioStream stream,
                                      aaudio_clockid_t clockid,
                                      aaudio_position_frames_t *framePosition,
                                      aaudio_nanoseconds_t *timeNanoseconds)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    if (framePosition == nullptr) {
        return AAUDIO_ERROR_NULL;
    } else if (timeNanoseconds == nullptr) {
        return AAUDIO_ERROR_NULL;
    } else if (clockid != AAUDIO_CLOCK_MONOTONIC && clockid != AAUDIO_CLOCK_BOOTTIME) {
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }

    clockid_t hostClockId = AAudioConvert_fromAAudioClockId(clockid);
    return audioStream->getTimestamp(hostClockId, framePosition, timeNanoseconds);
}
