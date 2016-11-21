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

#include <time.h>
#include <pthread.h>

#include <oboe/OboeDefinitions.h>
#include <oboe/OboeAudio.h>
#include "AudioStreamBuilder.h"
#include "AudioStream.h"
#include "AudioClock.h"
#include "HandleTracker.h"

// temporary, as I stage in the MMAP/NOIRQ support, do not review
#ifndef OBOE_SUPPORT_MMAP
#define OBOE_SUPPORT_MMAP 0
#endif

#if OBOE_SUPPORT_MMAP
#include "AudioStreamInternal.h"
#include "OboeServiceGateway.h"
#endif

using namespace oboe;

// This is not the maximum theoretic possible number of handles that the HandlerTracker
// class could support; instead it is the maximum number of handles that we are configuring
// for our HandleTracker instance (sHandleTracker).
#define OBOE_MAX_HANDLES  64

// Macros for common code that includes a return.
// TODO Consider using do{}while(0) construct. I tried but it hung AndroidStudio
#define CONVERT_BUILDER_HANDLE_OR_RETURN() \
    convertOboeBuilderToStreamBuilder(builder); \
    if (streamBuilder == nullptr) { \
        return OBOE_ERROR_INVALID_HANDLE; \
    }

#define COMMON_GET_FROM_BUILDER_OR_RETURN(resultPtr) \
    CONVERT_BUILDER_HANDLE_OR_RETURN() \
    if ((resultPtr) == nullptr) { \
        return OBOE_ERROR_NULL; \
    }

#define CONVERT_STREAM_HANDLE_OR_RETURN() \
    convertOboeStreamToAudioStream(stream); \
    if (audioStream == nullptr) { \
        return OBOE_ERROR_INVALID_HANDLE; \
    }

#define COMMON_GET_FROM_STREAM_OR_RETURN(resultPtr) \
    CONVERT_STREAM_HANDLE_OR_RETURN(); \
    if ((resultPtr) == nullptr) { \
        return OBOE_ERROR_NULL; \
    }

static HandleTracker sHandleTracker(OBOE_MAX_HANDLES);

typedef enum
{
    OBOE_HANDLE_TYPE_STREAM,
    OBOE_HANDLE_TYPE_STREAM_BUILDER,
    OBOE_HANDLE_TYPE_COUNT
} oboe_handle_type_t;
static_assert(OBOE_HANDLE_TYPE_COUNT <= HANDLE_TRACKER_MAX_TYPES, "Too many handle types.");

#if OBOE_SUPPORT_MMAP
static OboeServiceGateway sOboeServiceGateway;
#endif

#define OBOE_CASE_ENUM(name) case name: return #name

OBOE_API const char * Oboe_convertResultToText(oboe_result_t returnCode) {
    switch (returnCode) {
        OBOE_CASE_ENUM(OBOE_OK);
        OBOE_CASE_ENUM(OBOE_ERROR_ILLEGAL_ARGUMENT);
        OBOE_CASE_ENUM(OBOE_ERROR_INCOMPATIBLE);
        OBOE_CASE_ENUM(OBOE_ERROR_INTERNAL);
        OBOE_CASE_ENUM(OBOE_ERROR_INVALID_STATE);
        OBOE_CASE_ENUM(OBOE_ERROR_INVALID_HANDLE);
        OBOE_CASE_ENUM(OBOE_ERROR_INVALID_QUERY);
        OBOE_CASE_ENUM(OBOE_ERROR_UNIMPLEMENTED);
        OBOE_CASE_ENUM(OBOE_ERROR_UNAVAILABLE);
        OBOE_CASE_ENUM(OBOE_ERROR_NO_FREE_HANDLES);
        OBOE_CASE_ENUM(OBOE_ERROR_NO_MEMORY);
        OBOE_CASE_ENUM(OBOE_ERROR_NULL);
        OBOE_CASE_ENUM(OBOE_ERROR_TIMEOUT);
        OBOE_CASE_ENUM(OBOE_ERROR_WOULD_BLOCK);
        OBOE_CASE_ENUM(OBOE_ERROR_INVALID_ORDER);
        OBOE_CASE_ENUM(OBOE_ERROR_OUT_OF_RANGE);
    }
    return "Unrecognized Oboe error.";
}

OBOE_API const char * Oboe_convertStreamStateToText(oboe_stream_state_t state) {
    switch (state) {
        OBOE_CASE_ENUM(OBOE_STREAM_STATE_UNINITIALIZED);
        OBOE_CASE_ENUM(OBOE_STREAM_STATE_OPEN);
        OBOE_CASE_ENUM(OBOE_STREAM_STATE_STARTING);
        OBOE_CASE_ENUM(OBOE_STREAM_STATE_STARTED);
        OBOE_CASE_ENUM(OBOE_STREAM_STATE_PAUSING);
        OBOE_CASE_ENUM(OBOE_STREAM_STATE_PAUSED);
        OBOE_CASE_ENUM(OBOE_STREAM_STATE_FLUSHING);
        OBOE_CASE_ENUM(OBOE_STREAM_STATE_FLUSHED);
        OBOE_CASE_ENUM(OBOE_STREAM_STATE_STOPPING);
        OBOE_CASE_ENUM(OBOE_STREAM_STATE_STOPPED);
        OBOE_CASE_ENUM(OBOE_STREAM_STATE_CLOSING);
        OBOE_CASE_ENUM(OBOE_STREAM_STATE_CLOSED);
    }
    return "Unrecognized Oboe state.";
}

#undef OBOE_CASE_ENUM

static AudioStream *convertOboeStreamToAudioStream(OboeStream stream)
{
    return (AudioStream *) sHandleTracker.get(OBOE_HANDLE_TYPE_STREAM,
                                              (oboe_handle_t) stream);
}

static AudioStreamBuilder *convertOboeBuilderToStreamBuilder(OboeStreamBuilder builder)
{
    return (AudioStreamBuilder *) sHandleTracker.get(OBOE_HANDLE_TYPE_STREAM_BUILDER,
                                                     (oboe_handle_t) builder);
}

OBOE_API oboe_result_t Oboe_createStreamBuilder(OboeStreamBuilder *builder)
{
    ALOGD("Oboe_createStreamBuilder(): check sHandleTracker.isInitialized ()");
    if (!sHandleTracker.isInitialized()) {
        return OBOE_ERROR_NO_MEMORY;
    }
    AudioStreamBuilder *audioStreamBuilder =  new AudioStreamBuilder();
    if (audioStreamBuilder == nullptr) {
        return OBOE_ERROR_NO_MEMORY;
    }
    ALOGD("Oboe_createStreamBuilder(): created AudioStreamBuilder = %p", audioStreamBuilder);
    // TODO protect the put() with a Mutex
    OboeStreamBuilder handle = sHandleTracker.put(OBOE_HANDLE_TYPE_STREAM_BUILDER,
            audioStreamBuilder);
    if (handle < 0) {
        delete audioStreamBuilder;
        return static_cast<oboe_result_t>(handle);
    } else {
        *builder = handle;
    }
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStreamBuilder_setDeviceId(OboeStreamBuilder builder,
                                                     OboeDeviceId deviceId)
{
    AudioStreamBuilder *streamBuilder = CONVERT_BUILDER_HANDLE_OR_RETURN();
    streamBuilder->setDeviceId(deviceId);
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStreamBuilder_setSampleRate(OboeStreamBuilder builder,
                                              oboe_sample_rate_t sampleRate)
{
    AudioStreamBuilder *streamBuilder = CONVERT_BUILDER_HANDLE_OR_RETURN();
    streamBuilder->setSampleRate(sampleRate);
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStreamBuilder_getSampleRate(OboeStreamBuilder builder,
                                              oboe_sample_rate_t *sampleRate)
{
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(sampleRate);
    *sampleRate = streamBuilder->getSampleRate();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStreamBuilder_setSamplesPerFrame(OboeStreamBuilder builder,
                                                   int32_t samplesPerFrame)
{
    AudioStreamBuilder *streamBuilder = CONVERT_BUILDER_HANDLE_OR_RETURN();
    streamBuilder->setSamplesPerFrame(samplesPerFrame);
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStreamBuilder_getSamplesPerFrame(OboeStreamBuilder builder,
                                                   int32_t *samplesPerFrame)
{
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(samplesPerFrame);
    *samplesPerFrame = streamBuilder->getSamplesPerFrame();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStreamBuilder_setDirection(OboeStreamBuilder builder,
                                             oboe_direction_t direction)
{
    AudioStreamBuilder *streamBuilder = CONVERT_BUILDER_HANDLE_OR_RETURN();
    streamBuilder->setDirection(direction);
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStreamBuilder_getDirection(OboeStreamBuilder builder,
                                             oboe_direction_t *direction)
{
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(direction);
    *direction = streamBuilder->getDirection();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStreamBuilder_setFormat(OboeStreamBuilder builder,
                                                   oboe_audio_format_t format)
{
    AudioStreamBuilder *streamBuilder = CONVERT_BUILDER_HANDLE_OR_RETURN();
    streamBuilder->setFormat(format);
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStreamBuilder_getFormat(OboeStreamBuilder builder,
                                                   oboe_audio_format_t *format)
{
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(format);
    *format = streamBuilder->getFormat();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStreamBuilder_setSharingMode(OboeStreamBuilder builder,
                                                        oboe_sharing_mode_t sharingMode)
{
    AudioStreamBuilder *streamBuilder = CONVERT_BUILDER_HANDLE_OR_RETURN();
    if ((sharingMode < 0) || (sharingMode >= OBOE_SHARING_MODE_COUNT)) {
        return OBOE_ERROR_ILLEGAL_ARGUMENT;
    } else {
        streamBuilder->setSharingMode(sharingMode);
        return OBOE_OK;
    }
}

OBOE_API oboe_result_t OboeStreamBuilder_getSharingMode(OboeStreamBuilder builder,
                                                        oboe_sharing_mode_t *sharingMode)
{
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(sharingMode);
    *sharingMode = streamBuilder->getSharingMode();
    return OBOE_OK;
}

static oboe_result_t  OboeInternal_openStream(AudioStreamBuilder *streamBuilder,
                                              OboeStream *streamPtr)
{
    AudioStream *audioStream = nullptr;
    oboe_result_t result = streamBuilder->build(&audioStream);
    if (result != OBOE_OK) {
        return result;
    } else {
        // Create a handle for referencing the object.
        // TODO protect the put() with a Mutex
        OboeStream handle = sHandleTracker.put(OBOE_HANDLE_TYPE_STREAM, audioStream);
        if (handle < 0) {
            delete audioStream;
            return static_cast<oboe_result_t>(handle);
        }
        *streamPtr = handle;
        return OBOE_OK;
    }
}

OBOE_API oboe_result_t  OboeStreamBuilder_openStream(OboeStreamBuilder builder,
                                                     OboeStream *streamPtr)
{
    ALOGD("OboeStreamBuilder_openStream(): builder = 0x%08X", builder);
    AudioStreamBuilder *streamBuilder = COMMON_GET_FROM_BUILDER_OR_RETURN(streamPtr);
    return OboeInternal_openStream(streamBuilder, streamPtr);
}

OBOE_API oboe_result_t  OboeStreamBuilder_delete(OboeStreamBuilder builder)
{
    // TODO protect the remove() with a Mutex
    AudioStreamBuilder *streamBuilder = (AudioStreamBuilder *)
            sHandleTracker.remove(OBOE_HANDLE_TYPE_STREAM_BUILDER, builder);
    if (streamBuilder != nullptr) {
        delete streamBuilder;
        return OBOE_OK;
    }
    return OBOE_ERROR_INVALID_HANDLE;
}

OBOE_API oboe_result_t  OboeStream_close(OboeStream stream)
{
    // TODO protect the remove() with a Mutex
    AudioStream *audioStream = (AudioStream *)
            sHandleTracker.remove(OBOE_HANDLE_TYPE_STREAM, (oboe_handle_t)stream);
    if (audioStream != nullptr) {
        audioStream->close();
        delete audioStream;
        return OBOE_OK;
    }
    return OBOE_ERROR_INVALID_HANDLE;
}

OBOE_API oboe_result_t  OboeStream_requestStart(OboeStream stream)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    ALOGD("OboeStream_requestStart(0x%08X), audioStream = %p", stream, audioStream);
    return audioStream->requestStart();
}

OBOE_API oboe_result_t  OboeStream_requestPause(OboeStream stream)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    ALOGD("OboeStream_requestPause(0x%08X), audioStream = %p", stream, audioStream);
    return audioStream->requestPause();
}

OBOE_API oboe_result_t  OboeStream_requestFlush(OboeStream stream)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    ALOGD("OboeStream_requestFlush(0x%08X), audioStream = %p", stream, audioStream);
    return audioStream->requestFlush();
}

OBOE_API oboe_result_t  OboeStream_requestStop(OboeStream stream)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    ALOGD("OboeStream_requestStop(0x%08X), audioStream = %p", stream, audioStream);
    return audioStream->requestStop();
}

OBOE_API oboe_result_t OboeStream_waitForStateChange(OboeStream stream,
                                            oboe_stream_state_t inputState,
                                            oboe_stream_state_t *nextState,
                                            oboe_nanoseconds_t timeoutNanoseconds)
{

    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    return audioStream->waitForStateChange(inputState, nextState, timeoutNanoseconds);
}

// ============================================================
// Stream - non-blocking I/O
// ============================================================

OBOE_API oboe_result_t OboeStream_read(OboeStream stream,
                               void *buffer,
                               oboe_size_frames_t numFrames,
                               oboe_nanoseconds_t timeoutNanoseconds)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    if (buffer == nullptr) {
        return OBOE_ERROR_NULL;
    }
    if (numFrames < 0) {
        return OBOE_ERROR_ILLEGAL_ARGUMENT;
    } else if (numFrames == 0) {
        return 0;
    }

    oboe_result_t result = audioStream->read(buffer, numFrames, timeoutNanoseconds);
    // ALOGD("OboeStream_read(): read returns %d", result);

    return result;
}

OBOE_API oboe_result_t OboeStream_write(OboeStream stream,
                               const void *buffer,
                               oboe_size_frames_t numFrames,
                               oboe_nanoseconds_t timeoutNanoseconds)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    if (buffer == nullptr) {
        return OBOE_ERROR_NULL;
    }
    if (numFrames < 0) {
        return OBOE_ERROR_ILLEGAL_ARGUMENT;
    } else if (numFrames == 0) {
        return 0;
    }

    oboe_result_t result = audioStream->write(buffer, numFrames, timeoutNanoseconds);
    // ALOGD("OboeStream_write(): write returns %d", result);

    return result;
}

// ============================================================
// Miscellaneous
// ============================================================

OBOE_API oboe_result_t OboeStream_createThread(OboeStream stream,
                                     oboe_nanoseconds_t periodNanoseconds,
                                     void *(*startRoutine)(void *), void *arg)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    return audioStream->createThread(periodNanoseconds, startRoutine, arg);
}

OBOE_API oboe_result_t Oboe_joinThread(OboeStream stream,
                                   void **returnArg,
                                   oboe_nanoseconds_t timeoutNanoseconds)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    return audioStream->joinThread(returnArg, timeoutNanoseconds);
}

// ============================================================
// Stream - queries
// ============================================================

// TODO Use oboe_clockid_t all the way down through the C++ streams.
static clockid_t OboeConvert_fromOboeClockId(oboe_clockid_t clockid)
{
    clockid_t hostClockId;
    switch (clockid) {
        case OBOE_CLOCK_MONOTONIC:
            hostClockId = CLOCK_MONOTONIC;
            break;
        case OBOE_CLOCK_BOOTTIME:
            hostClockId = CLOCK_BOOTTIME;
            break;
        default:
            hostClockId = 0; // TODO review
    }
    return hostClockId;
}

oboe_nanoseconds_t Oboe_getNanoseconds(oboe_clockid_t clockid)
{
    clockid_t hostClockId = OboeConvert_fromOboeClockId(clockid);
   return AudioClock::getNanoseconds(hostClockId);
}

OBOE_API oboe_result_t OboeStream_getSampleRate(OboeStream stream, oboe_sample_rate_t *sampleRate)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(sampleRate);
    *sampleRate = audioStream->getSampleRate();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStream_getSamplesPerFrame(OboeStream stream, int32_t *samplesPerFrame)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(samplesPerFrame);
    *samplesPerFrame = audioStream->getSamplesPerFrame();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStream_getState(OboeStream stream, oboe_stream_state_t *state)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(state);
    *state = audioStream->getState();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStream_getFormat(OboeStream stream, oboe_audio_format_t *format)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(format);
    *format = audioStream->getFormat();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStream_setBufferSize(OboeStream stream,
                                                oboe_size_frames_t requestedFrames,
                                                oboe_size_frames_t *actualFrames)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    return audioStream->setBufferSize(requestedFrames, actualFrames);
}

OBOE_API oboe_result_t OboeStream_getBufferSize(OboeStream stream, oboe_size_frames_t *frames)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(frames);
    *frames = audioStream->getBufferSize();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStream_getDirection(OboeStream stream, int32_t *direction)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(direction);
    *direction = audioStream->getDirection();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStream_getFramesPerBurst(OboeStream stream,
                                                    oboe_size_frames_t *framesPerBurst)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(framesPerBurst);
    *framesPerBurst = audioStream->getFramesPerBurst();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStream_getBufferCapacity(OboeStream stream,
                                           oboe_size_frames_t *capacity)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(capacity);
    *capacity = audioStream->getBufferCapacity();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStream_getXRunCount(OboeStream stream, int32_t *xRunCount)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(xRunCount);
    *xRunCount = audioStream->getXRunCount();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStream_getSharingMode(OboeStream stream,
                                                 oboe_sharing_mode_t *sharingMode)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(sharingMode);
    *sharingMode = audioStream->getSharingMode();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStream_getFramesWritten(OboeStream stream,
                                                   oboe_position_frames_t *frames)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(frames);
    *frames = audioStream->getFramesWritten();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStream_getFramesRead(OboeStream stream, oboe_position_frames_t *frames)
{
    AudioStream *audioStream = COMMON_GET_FROM_STREAM_OR_RETURN(frames);
    *frames = audioStream->getFramesRead();
    return OBOE_OK;
}

OBOE_API oboe_result_t OboeStream_getTimestamp(OboeStream stream,
                                      oboe_clockid_t clockid,
                                      oboe_position_frames_t *framePosition,
                                      oboe_nanoseconds_t *timeNanoseconds)
{
    AudioStream *audioStream = CONVERT_STREAM_HANDLE_OR_RETURN();
    if (framePosition == nullptr) {
        return OBOE_ERROR_NULL;
    } else if (timeNanoseconds == nullptr) {
        return OBOE_ERROR_NULL;
    } else if (clockid != OBOE_CLOCK_MONOTONIC && clockid != OBOE_CLOCK_BOOTTIME) {
        return OBOE_ERROR_ILLEGAL_ARGUMENT;
    }

    clockid_t hostClockId = OboeConvert_fromOboeClockId(clockid);
    return audioStream->getTimestamp(hostClockId, framePosition, timeNanoseconds);
}
