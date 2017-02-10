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

/**
 * This is the 'C' ABI for AAudio.
 */
#ifndef AAUDIO_AAUDIO_H
#define AAUDIO_AAUDIO_H

#include "AAudioDefinitions.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef aaudio_handle_t AAudioStream;
typedef aaudio_handle_t AAudioStreamBuilder;

#define AAUDIO_STREAM_NONE         ((AAudioStream)AAUDIO_HANDLE_INVALID)
#define AAUDIO_STREAM_BUILDER_NONE ((AAudioStreamBuilder)AAUDIO_HANDLE_INVALID)

/* AAUDIO_API will probably get defined in a Makefile for a specific platform. */
#ifndef AAUDIO_API
#define AAUDIO_API /* for exporting symbols */
#endif

// ============================================================
// Audio System
// ============================================================

/**
 * @return time in the same clock domain as the timestamps
 */
AAUDIO_API aaudio_nanoseconds_t AAudio_getNanoseconds(aaudio_clockid_t clockid);

/**
 * The text is the ASCII symbol corresponding to the returnCode,
 * or an English message saying the returnCode is unrecognized.
 * This is intended for developers to use when debugging.
 * It is not for display to users.
 *
 * @return pointer to a text representation of an AAudio result code.
 */
AAUDIO_API const char * AAudio_convertResultToText(aaudio_result_t returnCode);

/**
 * The text is the ASCII symbol corresponding to the stream state,
 * or an English message saying the state is unrecognized.
 * This is intended for developers to use when debugging.
 * It is not for display to users.
 *
 * @return pointer to a text representation of an AAudio state.
 */
AAUDIO_API const char * AAudio_convertStreamStateToText(aaudio_stream_state_t state);

// ============================================================
// StreamBuilder
// ============================================================

/**
 * Create a StreamBuilder that can be used to open a Stream.
 *
 * The deviceId is initially unspecified, meaning that the current default device will be used.
 *
 * The default direction is AAUDIO_DIRECTION_OUTPUT.
 * The default sharing mode is AAUDIO_SHARING_MODE_LEGACY.
 * The data format, samplesPerFrames and sampleRate are unspecified and will be
 * chosen by the device when it is opened.
 *
 * AAudioStreamBuilder_delete() must be called when you are done using the builder.
 */
AAUDIO_API aaudio_result_t AAudio_createStreamBuilder(AAudioStreamBuilder *builder);

/**
 * Request an audio device identified device using an ID.
 * The ID is platform specific.
 * On Android, for example, the ID could be obtained from the Java AudioManager.
 *
 * By default, the primary device will be used.
 *
 * @param builder handle provided by AAudio_createStreamBuilder()
 * @param deviceId platform specific identifier or AAUDIO_DEVICE_UNSPECIFIED
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_setDeviceId(AAudioStreamBuilder builder,
                                                     aaudio_device_id_t deviceId);
/**
 * Passes back requested device ID.
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_getDeviceId(AAudioStreamBuilder builder,
                                                     aaudio_device_id_t *deviceId);

/**
 * Request a sample rate in Hz.
 * The stream may be opened with a different sample rate.
 * So the application should query for the actual rate after the stream is opened.
 *
 * Technically, this should be called the "frame rate" or "frames per second",
 * because it refers to the number of complete frames transferred per second.
 * But it is traditionally called "sample rate". Se we use that term.
 *
 * Default is AAUDIO_UNSPECIFIED.
 *
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_setSampleRate(AAudioStreamBuilder builder,
                                                       aaudio_sample_rate_t sampleRate);

/**
 * Returns sample rate in Hertz (samples per second).
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_getSampleRate(AAudioStreamBuilder builder,
                                                       aaudio_sample_rate_t *sampleRate);


/**
 * Request a number of samples per frame.
 * The stream may be opened with a different value.
 * So the application should query for the actual value after the stream is opened.
 *
 * Default is AAUDIO_UNSPECIFIED.
 *
 * Note, this quantity is sometimes referred to as "channel count".
 *
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_setSamplesPerFrame(AAudioStreamBuilder builder,
                                                   int32_t samplesPerFrame);

/**
 * Note, this quantity is sometimes referred to as "channel count".
 *
 * @param builder handle provided by AAudio_createStreamBuilder()
 * @param samplesPerFrame pointer to a variable to be set to samplesPerFrame.
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_getSamplesPerFrame(AAudioStreamBuilder builder,
                                                   int32_t *samplesPerFrame);


/**
 * Request a sample data format, for example AAUDIO_FORMAT_PCM_I16.
 * The application should query for the actual format after the stream is opened.
 *
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_setFormat(AAudioStreamBuilder builder,
                                                   aaudio_audio_format_t format);

/**
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_getFormat(AAudioStreamBuilder builder,
                                                   aaudio_audio_format_t *format);

/**
 * Request a mode for sharing the device.
 * The requested sharing mode may not be available.
 * So the application should query for the actual mode after the stream is opened.
 *
 * @param builder handle provided by AAudio_createStreamBuilder()
 * @param sharingMode AAUDIO_SHARING_MODE_LEGACY or AAUDIO_SHARING_MODE_EXCLUSIVE
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_setSharingMode(AAudioStreamBuilder builder,
                                                        aaudio_sharing_mode_t sharingMode);

/**
 * Return requested sharing mode.
 * @return AAUDIO_OK or a negative error
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_getSharingMode(AAudioStreamBuilder builder,
                                                        aaudio_sharing_mode_t *sharingMode);

/**
 * Request the direction for a stream. The default is AAUDIO_DIRECTION_OUTPUT.
 *
 * @param builder handle provided by AAudio_createStreamBuilder()
 * @param direction AAUDIO_DIRECTION_OUTPUT or AAUDIO_DIRECTION_INPUT
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_setDirection(AAudioStreamBuilder builder,
                                                            aaudio_direction_t direction);

/**
 * @param builder handle provided by AAudio_createStreamBuilder()
 * @param direction pointer to a variable to be set to the currently requested direction.
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_getDirection(AAudioStreamBuilder builder,
                                                            aaudio_direction_t *direction);

/**
 * Set the requested maximum buffer capacity in frames.
 * The final AAudioStream capacity may differ, but will probably be at least this big.
 *
 * Default is AAUDIO_UNSPECIFIED.
 *
 * @param builder handle provided by AAudio_createStreamBuilder()
 * @param frames the desired buffer capacity in frames or AAUDIO_UNSPECIFIED
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_setBufferCapacity(AAudioStreamBuilder builder,
                                                                 aaudio_size_frames_t frames);

/**
 * Query the requested maximum buffer capacity in frames that was passed to
 * AAudioStreamBuilder_setBufferCapacity().
 *
 * @param builder handle provided by AAudio_createStreamBuilder()
 * @param frames pointer to variable to receive the requested buffer capacity
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStreamBuilder_getBufferCapacity(AAudioStreamBuilder builder,
                                                                 aaudio_size_frames_t *frames);

/**
 * Open a stream based on the options in the StreamBuilder.
 *
 * AAudioStream_close must be called when finished with the stream to recover
 * the memory and to free the associated resources.
 *
 * @param builder handle provided by AAudio_createStreamBuilder()
 * @param stream pointer to a variable to receive the new stream handle
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t  AAudioStreamBuilder_openStream(AAudioStreamBuilder builder,
                                                     AAudioStream *stream);

/**
 * Delete the resources associated with the StreamBuilder.
 *
 * @param builder handle provided by AAudio_createStreamBuilder()
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t  AAudioStreamBuilder_delete(AAudioStreamBuilder builder);

// ============================================================
// Stream Control
// ============================================================

/**
 * Free the resources associated with a stream created by AAudioStreamBuilder_openStream()
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t  AAudioStream_close(AAudioStream stream);

/**
 * Asynchronously request to start playing the stream. For output streams, one should
 * write to the stream to fill the buffer before starting.
 * Otherwise it will underflow.
 * After this call the state will be in AAUDIO_STREAM_STATE_STARTING or AAUDIO_STREAM_STATE_STARTED.
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t  AAudioStream_requestStart(AAudioStream stream);

/**
 * Asynchronous request for the stream to pause.
 * Pausing a stream will freeze the data flow but not flush any buffers.
 * Use AAudioStream_Start() to resume playback after a pause.
 * After this call the state will be in AAUDIO_STREAM_STATE_PAUSING or AAUDIO_STREAM_STATE_PAUSED.
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t  AAudioStream_requestPause(AAudioStream stream);

/**
 * Asynchronous request for the stream to flush.
 * Flushing will discard any pending data.
 * This call only works if the stream is pausing or paused. TODO review
 * Frame counters are not reset by a flush. They may be advanced.
 * After this call the state will be in AAUDIO_STREAM_STATE_FLUSHING or AAUDIO_STREAM_STATE_FLUSHED.
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t  AAudioStream_requestFlush(AAudioStream stream);

/**
 * Asynchronous request for the stream to stop.
 * The stream will stop after all of the data currently buffered has been played.
 * After this call the state will be in AAUDIO_STREAM_STATE_STOPPING or AAUDIO_STREAM_STATE_STOPPED.
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t  AAudioStream_requestStop(AAudioStream stream);

/**
 * Query the current state, eg. AAUDIO_STREAM_STATE_PAUSING
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param state pointer to a variable that will be set to the current state
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getState(AAudioStream stream, aaudio_stream_state_t *state);

/**
 * Wait until the current state no longer matches the input state.
 *
 * <pre><code>
 * aaudio_stream_state_t currentState;
 * aaudio_result_t result = AAudioStream_getState(stream, &currentState);
 * while (result == AAUDIO_OK && currentState != AAUDIO_STREAM_STATE_PAUSING) {
 *     result = AAudioStream_waitForStateChange(
 *                                   stream, currentState, &currentState, MY_TIMEOUT_NANOS);
 * }
 * </code></pre>
 *
 * @param stream A handle provided by AAudioStreamBuilder_openStream()
 * @param inputState The state we want to avoid.
 * @param nextState Pointer to a variable that will be set to the new state.
 * @param timeoutNanoseconds Maximum number of nanoseconds to wait for completion.
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_waitForStateChange(AAudioStream stream,
                                            aaudio_stream_state_t inputState,
                                            aaudio_stream_state_t *nextState,
                                            aaudio_nanoseconds_t timeoutNanoseconds);

// ============================================================
// Stream I/O
// ============================================================

/**
 * Read data from the stream.
 *
 * The call will wait until the read is complete or until it runs out of time.
 * If timeoutNanos is zero then this call will not wait.
 *
 * Note that timeoutNanoseconds is a relative duration in wall clock time.
 * Time will not stop if the thread is asleep.
 * So it will be implemented using CLOCK_BOOTTIME.
 *
 * This call is "strong non-blocking" unless it has to wait for data.
 *
 * @param stream A stream created using AAudioStreamBuilder_openStream().
 * @param buffer The address of the first sample.
 * @param numFrames Number of frames to read. Only complete frames will be written.
 * @param timeoutNanoseconds Maximum number of nanoseconds to wait for completion.
 * @return The number of frames actually written or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_read(AAudioStream stream,
                               void *buffer,
                               aaudio_size_frames_t numFrames,
                               aaudio_nanoseconds_t timeoutNanoseconds);

/**
 * Write data to the stream.
 *
 * The call will wait until the write is complete or until it runs out of time.
 * If timeoutNanos is zero then this call will not wait.
 *
 * Note that timeoutNanoseconds is a relative duration in wall clock time.
 * Time will not stop if the thread is asleep.
 * So it will be implemented using CLOCK_BOOTTIME.
 *
 * This call is "strong non-blocking" unless it has to wait for room in the buffer.
 *
 * @param stream A stream created using AAudioStreamBuilder_openStream().
 * @param buffer The address of the first sample.
 * @param numFrames Number of frames to write. Only complete frames will be written.
 * @param timeoutNanoseconds Maximum number of nanoseconds to wait for completion.
 * @return The number of frames actually written or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_write(AAudioStream stream,
                               const void *buffer,
                               aaudio_size_frames_t numFrames,
                               aaudio_nanoseconds_t timeoutNanoseconds);


// ============================================================
// High priority audio threads
// ============================================================

typedef void *(aaudio_audio_thread_proc_t)(void *);

/**
 * Create a thread associated with a stream. The thread has special properties for
 * low latency audio performance. This thread can be used to implement a callback API.
 *
 * Only one thread may be associated with a stream.
 *
 * Note that this API is in flux.
 *
 * @param stream A stream created using AAudioStreamBuilder_openStream().
 * @param periodNanoseconds the estimated period at which the audio thread will need to wake up
 * @param startRoutine your thread entry point
 * @param arg an argument that will be passed to your thread entry point
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_createThread(AAudioStream stream,
                                     aaudio_nanoseconds_t periodNanoseconds,
                                     aaudio_audio_thread_proc_t *threadProc,
                                     void *arg);

/**
 * Wait until the thread exits or an error occurs.
 * The thread handle will be deleted.
 *
 * @param stream A stream created using AAudioStreamBuilder_openStream().
 * @param returnArg a pointer to a variable to receive the return value
 * @param timeoutNanoseconds Maximum number of nanoseconds to wait for completion.
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_joinThread(AAudioStream stream,
                                   void **returnArg,
                                   aaudio_nanoseconds_t timeoutNanoseconds);

// ============================================================
// Stream - queries
// ============================================================


/**
 * This can be used to adjust the latency of the buffer by changing
 * the threshold where blocking will occur.
 * By combining this with AAudioStream_getUnderrunCount(), the latency can be tuned
 * at run-time for each device.
 *
 * This cannot be set higher than AAudioStream_getBufferCapacity().
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param requestedFrames requested number of frames that can be filled without blocking
 * @param actualFrames receives final number of frames
 * @return AAUDIO_OK or a negative error
 */
AAUDIO_API aaudio_result_t AAudioStream_setBufferSize(AAudioStream stream,
                                                      aaudio_size_frames_t requestedFrames,
                                                      aaudio_size_frames_t *actualFrames);

/**
 * Query the maximum number of frames that can be filled without blocking.
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param frames pointer to variable to receive the buffer size
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getBufferSize(AAudioStream stream,
                                                      aaudio_size_frames_t *frames);

/**
 * Query the number of frames that are read or written by the endpoint at one time.
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param frames pointer to variable to receive the burst size
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getFramesPerBurst(AAudioStream stream,
                                                          aaudio_size_frames_t *frames);

/**
 * Query maximum buffer capacity in frames.
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param frames pointer to variable to receive the buffer capacity
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getBufferCapacity(AAudioStream stream,
                                                          aaudio_size_frames_t *frames);

/**
 * An XRun is an Underrun or an Overrun.
 * During playing, an underrun will occur if the stream is not written in time
 * and the system runs out of valid data.
 * During recording, an overrun will occur if the stream is not read in time
 * and there is no place to put the incoming data so it is discarded.
 *
 * An underrun or overrun can cause an audible "pop" or "glitch".
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param xRunCount pointer to variable to receive the underrun or overrun count
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getXRunCount(AAudioStream stream, int32_t *xRunCount);

/**
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param sampleRate pointer to variable to receive the actual sample rate
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getSampleRate(AAudioStream stream,
                                                      aaudio_sample_rate_t *sampleRate);

/**
 * The samplesPerFrame is also known as channelCount.
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param samplesPerFrame pointer to variable to receive the actual samples per frame
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getSamplesPerFrame(AAudioStream stream,
                                                           int32_t *samplesPerFrame);

/**
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param deviceId pointer to variable to receive the actual device ID
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getDeviceId(AAudioStream stream,
                                                    aaudio_device_id_t *deviceId);

/**
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param format pointer to variable to receive the actual data format
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getFormat(AAudioStream stream,
                                                  aaudio_audio_format_t *format);

/**
 * Provide actual sharing mode.
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param sharingMode pointer to variable to receive the actual sharing mode
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getSharingMode(AAudioStream stream,
                                        aaudio_sharing_mode_t *sharingMode);

/**
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param direction pointer to a variable to be set to the current direction.
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getDirection(AAudioStream stream,
                                                     aaudio_direction_t *direction);

/**
 * Passes back the number of frames that have been written since the stream was created.
 * For an output stream, this will be advanced by the application calling write().
 * For an input stream, this will be advanced by the device or service.
 *
 * The frame position is monotonically increasing.
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param frames pointer to variable to receive the frames written
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getFramesWritten(AAudioStream stream,
                                                   aaudio_position_frames_t *frames);

/**
 * Passes back the number of frames that have been read since the stream was created.
 * For an output stream, this will be advanced by the device or service.
 * For an input stream, this will be advanced by the application calling read().
 *
 * The frame position is monotonically increasing.
 *
 * @param stream handle provided by AAudioStreamBuilder_openStream()
 * @param frames pointer to variable to receive the frames written
 * @return AAUDIO_OK or a negative error.
 */
AAUDIO_API aaudio_result_t AAudioStream_getFramesRead(AAudioStream stream,
                                                      aaudio_position_frames_t *frames);

/**
 * Passes back the time at which a particular frame was presented.
 * This can be used to synchronize audio with video or MIDI.
 * It can also be used to align a recorded stream with a playback stream.
 *
 * Timestamps are only valid when the stream is in AAUDIO_STREAM_STATE_STARTED.
 * AAUDIO_ERROR_INVALID_STATE will be returned if the stream is not started.
 * Note that because requestStart() is asynchronous, timestamps will not be valid until
 * a short time after calling requestStart().
 * So AAUDIO_ERROR_INVALID_STATE should not be considered a fatal error.
 * Just try calling again later.
 *
 * If an error occurs, then the position and time will not be modified.
 *
 * The position and time passed back are monotonically increasing.
 *
 * @param stream A handle provided by AAudioStreamBuilder_openStream()
 * @param clockid AAUDIO_CLOCK_MONOTONIC or AAUDIO_CLOCK_BOOTTIME
 * @param framePosition pointer to a variable to receive the position
 * @param timeNanoseconds pointer to a variable to receive the time
 * @return AAUDIO_OK or a negative error
 */
AAUDIO_API aaudio_result_t AAudioStream_getTimestamp(AAudioStream stream,
                                      aaudio_clockid_t clockid,
                                      aaudio_position_frames_t *framePosition,
                                      aaudio_nanoseconds_t *timeNanoseconds);

#ifdef __cplusplus
}
#endif

#endif //AAUDIO_AAUDIO_H
