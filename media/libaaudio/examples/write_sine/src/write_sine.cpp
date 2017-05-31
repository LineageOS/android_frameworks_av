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

// Play sine waves using AAudio.

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>
#include "AAudioExampleUtils.h"
#include "AAudioSimplePlayer.h"

#define SAMPLE_RATE           48000
#define NUM_SECONDS           20

#define MMAP_POLICY              AAUDIO_UNSPECIFIED
//#define MMAP_POLICY              AAUDIO_POLICY_NEVER
//#define MMAP_POLICY              AAUDIO_POLICY_AUTO
//#define MMAP_POLICY              AAUDIO_POLICY_ALWAYS

#define REQUESTED_FORMAT         AAUDIO_FORMAT_PCM_I16

#define REQUESTED_SHARING_MODE   AAUDIO_SHARING_MODE_SHARED
//#define REQUESTED_SHARING_MODE   AAUDIO_SHARING_MODE_EXCLUSIVE


int main(int argc, char **argv)
{
    (void)argc; // unused

    AAudioSimplePlayer player;
    SineThreadedData_t myData;
    aaudio_result_t result = AAUDIO_OK;

    const int requestedChannelCount = 2;
    int actualChannelCount = 0;
    const int requestedSampleRate = SAMPLE_RATE;
    int actualSampleRate = 0;
    aaudio_format_t requestedDataFormat = REQUESTED_FORMAT;
    aaudio_format_t actualDataFormat = AAUDIO_FORMAT_UNSPECIFIED;
    aaudio_sharing_mode_t actualSharingMode = AAUDIO_SHARING_MODE_SHARED;

    AAudioStream *aaudioStream = nullptr;
    aaudio_stream_state_t state = AAUDIO_STREAM_STATE_UNINITIALIZED;
    int32_t  framesPerBurst = 0;
    int32_t  framesPerWrite = 0;
    int32_t  bufferCapacity = 0;
    int32_t  framesToPlay = 0;
    int32_t  framesLeft = 0;
    int32_t  xRunCount = 0;
    float   *floatData = nullptr;
    int16_t *shortData = nullptr;

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, nullptr, _IONBF, (size_t) 0);

    printf("%s - Play a sine wave using AAudio\n", argv[0]);

    AAudio_setMMapPolicy(MMAP_POLICY);
    printf("requested MMapPolicy = %d\n", AAudio_getMMapPolicy());

    player.setSharingMode(REQUESTED_SHARING_MODE);

    result = player.open(requestedChannelCount, requestedSampleRate, requestedDataFormat,
                         nullptr, nullptr, &myData);
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR -  player.open() returned %d\n", result);
        goto finish;
    }

    aaudioStream = player.getStream();
    // Request stream properties.

    state = AAudioStream_getState(aaudioStream);
    printf("after open, state = %s\n", AAudio_convertStreamStateToText(state));

    // Check to see what kind of stream we actually got.
    actualSampleRate = AAudioStream_getSampleRate(aaudioStream);
    printf("SampleRate: requested = %d, actual = %d\n", requestedSampleRate, actualSampleRate);

    myData.sineOsc1.setup(440.0, actualSampleRate);
    myData.sineOsc2.setup(660.0, actualSampleRate);

    actualChannelCount = AAudioStream_getChannelCount(aaudioStream);
    printf("ChannelCount: requested = %d, actual = %d\n",
            requestedChannelCount, actualChannelCount);

    actualSharingMode = AAudioStream_getSharingMode(aaudioStream);
    printf("SharingMode: requested = %s, actual = %s\n",
            getSharingModeText(REQUESTED_SHARING_MODE),
            getSharingModeText(actualSharingMode));

    // This is the number of frames that are read in one chunk by a DMA controller
    // or a DSP or a mixer.
    framesPerBurst = AAudioStream_getFramesPerBurst(aaudioStream);
    printf("Buffer: bufferSize     = %d\n", AAudioStream_getBufferSizeInFrames(aaudioStream));
    bufferCapacity = AAudioStream_getBufferCapacityInFrames(aaudioStream);
    printf("Buffer: bufferCapacity = %d, remainder = %d\n",
           bufferCapacity, bufferCapacity % framesPerBurst);

    // Some DMA might use very short bursts of 16 frames. We don't need to write such small
    // buffers. But it helps to use a multiple of the burst size for predictable scheduling.
    framesPerWrite = framesPerBurst;
    while (framesPerWrite < 48) {
        framesPerWrite *= 2;
    }
    printf("Buffer: framesPerBurst = %d\n",framesPerBurst);
    printf("Buffer: framesPerWrite = %d\n",framesPerWrite);

    printf("PerformanceMode        = %d\n", AAudioStream_getPerformanceMode(aaudioStream));
    printf("is MMAP used?          = %s\n", AAudioStream_isMMapUsed(aaudioStream) ? "yes" : "no");

    actualDataFormat = AAudioStream_getFormat(aaudioStream);
    printf("DataFormat: requested  = %d, actual = %d\n", REQUESTED_FORMAT, actualDataFormat);
    // TODO handle other data formats

    // Allocate a buffer for the audio data.
    if (actualDataFormat == AAUDIO_FORMAT_PCM_FLOAT) {
        floatData = new float[framesPerWrite * actualChannelCount];
    } else if (actualDataFormat == AAUDIO_FORMAT_PCM_I16) {
        shortData = new int16_t[framesPerWrite * actualChannelCount];
    } else {
        printf("ERROR Unsupported data format!\n");
        goto finish;
    }

    // Start the stream.
    printf("call player.start()\n");
    result = player.start();
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR - AAudioStream_requestStart() returned %d\n", result);
        goto finish;
    }

    state = AAudioStream_getState(aaudioStream);
    printf("after start, state = %s\n", AAudio_convertStreamStateToText(state));

    // Play for a while.
    framesToPlay = actualSampleRate * NUM_SECONDS;
    framesLeft = framesToPlay;
    while (framesLeft > 0) {

        if (actualDataFormat == AAUDIO_FORMAT_PCM_FLOAT) {
            // Render sine waves to left and right channels.
            myData.sineOsc1.render(&floatData[0], actualChannelCount, framesPerWrite);
            if (actualChannelCount > 1) {
                myData.sineOsc2.render(&floatData[1], actualChannelCount, framesPerWrite);
            }
        } else if (actualDataFormat == AAUDIO_FORMAT_PCM_I16) {
            // Render sine waves to left and right channels.
            myData.sineOsc1.render(&shortData[0], actualChannelCount, framesPerWrite);
            if (actualChannelCount > 1) {
                myData.sineOsc2.render(&shortData[1], actualChannelCount, framesPerWrite);
            }
        }

        // Write audio data to the stream.
        int64_t timeoutNanos = 1000 * NANOS_PER_MILLISECOND;
        int32_t minFrames = (framesToPlay < framesPerWrite) ? framesToPlay : framesPerWrite;
        int32_t actual = 0;
        if (actualDataFormat == AAUDIO_FORMAT_PCM_FLOAT) {
            actual = AAudioStream_write(aaudioStream, floatData, minFrames, timeoutNanos);
        } else if (actualDataFormat == AAUDIO_FORMAT_PCM_I16) {
            actual = AAudioStream_write(aaudioStream, shortData, minFrames, timeoutNanos);
        }
        if (actual < 0) {
            fprintf(stderr, "ERROR - AAudioStream_write() returned %d\n", actual);
            goto finish;
        } else if (actual == 0) {
            fprintf(stderr, "WARNING - AAudioStream_write() returned %d\n", actual);
            goto finish;
        }
        framesLeft -= actual;

        // Use timestamp to estimate latency.
        /*
        {
            int64_t presentationFrame;
            int64_t presentationTime;
            result = AAudioStream_getTimestamp(aaudioStream,
                                               CLOCK_MONOTONIC,
                                               &presentationFrame,
                                               &presentationTime
                                               );
            if (result == AAUDIO_OK) {
                int64_t elapsedNanos = getNanoseconds() - presentationTime;
                int64_t elapsedFrames = actualSampleRate * elapsedNanos / NANOS_PER_SECOND;
                int64_t currentFrame = presentationFrame + elapsedFrames;
                int64_t framesWritten = AAudioStream_getFramesWritten(aaudioStream);
                int64_t estimatedLatencyFrames = framesWritten - currentFrame;
                int64_t estimatedLatencyMillis = estimatedLatencyFrames * 1000 / actualSampleRate;
                printf("estimatedLatencyMillis %d\n", (int)estimatedLatencyMillis);
            }
        }
         */
    }

    xRunCount = AAudioStream_getXRunCount(aaudioStream);
    printf("AAudioStream_getXRunCount %d\n", xRunCount);

    printf("call stop()\n");
    result = player.stop();
    if (result != AAUDIO_OK) {
        goto finish;
    }

finish:
    player.close();
    delete[] floatData;
    delete[] shortData;
    printf("exiting - AAudio result = %d = %s\n", result, AAudio_convertResultToText(result));
    return (result != AAUDIO_OK) ? EXIT_FAILURE : EXIT_SUCCESS;
}

