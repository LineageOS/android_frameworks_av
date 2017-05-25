/*
 * Copyright (C) 2017 The Android Open Source Project
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

// Record input using AAudio and display the peak amplitudes.

#include <new>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <aaudio/AAudio.h>

#define SAMPLE_RATE        48000
#define NUM_SECONDS        5
#define NANOS_PER_MICROSECOND ((int64_t)1000)
#define NANOS_PER_MILLISECOND (NANOS_PER_MICROSECOND * 1000)
#define NANOS_PER_SECOND      (NANOS_PER_MILLISECOND * 1000)

#define MIN_FRAMES_TO_READ    48  /* arbitrary, 1 msec at 48000 Hz */

static const char *getSharingModeText(aaudio_sharing_mode_t mode) {
    const char *modeText = "unknown";
    switch (mode) {
    case AAUDIO_SHARING_MODE_EXCLUSIVE:
        modeText = "EXCLUSIVE";
        break;
    case AAUDIO_SHARING_MODE_SHARED:
        modeText = "SHARED";
        break;
    default:
        break;
    }
    return modeText;
}

int main(int argc, char **argv)
{
    (void)argc; // unused

    aaudio_result_t result;

    int actualSamplesPerFrame;
    int actualSampleRate;
    const aaudio_audio_format_t requestedDataFormat = AAUDIO_FORMAT_PCM_I16;
    aaudio_audio_format_t actualDataFormat;

    const int requestedInputChannelCount = 1; // Can affect whether we get a FAST path.

    //aaudio_performance_mode_t requestedPerformanceMode = AAUDIO_PERFORMANCE_MODE_NONE;
    const aaudio_performance_mode_t requestedPerformanceMode = AAUDIO_PERFORMANCE_MODE_LOW_LATENCY;
    //aaudio_performance_mode_t requestedPerformanceMode = AAUDIO_PERFORMANCE_MODE_POWER_SAVING;
    const aaudio_sharing_mode_t requestedSharingMode = AAUDIO_SHARING_MODE_SHARED;
    //const aaudio_sharing_mode_t requestedSharingMode = AAUDIO_SHARING_MODE_EXCLUSIVE;
    aaudio_sharing_mode_t actualSharingMode;

    AAudioStreamBuilder *aaudioBuilder = nullptr;
    AAudioStream *aaudioStream = nullptr;
    aaudio_stream_state_t state;
    int32_t framesPerBurst = 0;
    int32_t framesPerRead = 0;
    int32_t framesToRecord = 0;
    int32_t framesLeft = 0;
    int32_t xRunCount = 0;
    int16_t *data = nullptr;
    float peakLevel = 0.0;
    int loopCounter = 0;

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, nullptr, _IONBF, (size_t) 0);

    printf("%s - Monitor input level using AAudio\n", argv[0]);

    // Use an AAudioStreamBuilder to contain requested parameters.
    result = AAudio_createStreamBuilder(&aaudioBuilder);
    if (result != AAUDIO_OK) {
        goto finish;
    }

    // Request stream properties.
    AAudioStreamBuilder_setDirection(aaudioBuilder, AAUDIO_DIRECTION_INPUT);
    AAudioStreamBuilder_setFormat(aaudioBuilder, requestedDataFormat);
    AAudioStreamBuilder_setSharingMode(aaudioBuilder, requestedSharingMode);
    AAudioStreamBuilder_setPerformanceMode(aaudioBuilder, requestedPerformanceMode);
    AAudioStreamBuilder_setChannelCount(aaudioBuilder, requestedInputChannelCount);

    // Create an AAudioStream using the Builder.
    result = AAudioStreamBuilder_openStream(aaudioBuilder, &aaudioStream);
    if (result != AAUDIO_OK) {
        goto finish;
    }

    actualSamplesPerFrame = AAudioStream_getSamplesPerFrame(aaudioStream);
    printf("SamplesPerFrame = %d\n", actualSamplesPerFrame);
    actualSampleRate = AAudioStream_getSampleRate(aaudioStream);
    printf("SamplesPerFrame = %d\n", actualSampleRate);

    actualSharingMode = AAudioStream_getSharingMode(aaudioStream);
    printf("SharingMode: requested = %s, actual = %s\n",
            getSharingModeText(requestedSharingMode),
            getSharingModeText(actualSharingMode));

    // This is the number of frames that are written in one chunk by a DMA controller
    // or a DSP.
    framesPerBurst = AAudioStream_getFramesPerBurst(aaudioStream);
    printf("DataFormat: framesPerBurst = %d\n",framesPerBurst);

    // Some DMA might use very short bursts of 16 frames. We don't need to read such small
    // buffers. But it helps to use a multiple of the burst size for predictable scheduling.
    framesPerRead = framesPerBurst;
    while (framesPerRead < MIN_FRAMES_TO_READ) {
        framesPerRead *= 2;
    }
    printf("DataFormat: framesPerRead  = %d\n",framesPerRead);

    actualDataFormat = AAudioStream_getFormat(aaudioStream);
    printf("DataFormat: requested      = %d, actual = %d\n", requestedDataFormat, actualDataFormat);
    // TODO handle other data formats
    assert(actualDataFormat == AAUDIO_FORMAT_PCM_I16);

    printf("PerformanceMode: requested = %d, actual = %d\n", requestedPerformanceMode,
           AAudioStream_getPerformanceMode(aaudioStream));

    // Allocate a buffer for the audio data.
    data = new(std::nothrow) int16_t[framesPerRead * actualSamplesPerFrame];
    if (data == nullptr) {
        fprintf(stderr, "ERROR - could not allocate data buffer\n");
        result = AAUDIO_ERROR_NO_MEMORY;
        goto finish;
    }

    // Start the stream.
    printf("call AAudioStream_requestStart()\n");
    result = AAudioStream_requestStart(aaudioStream);
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR - AAudioStream_requestStart() returned %d\n", result);
        goto finish;
    }

    state = AAudioStream_getState(aaudioStream);
    printf("after start, state = %s\n", AAudio_convertStreamStateToText(state));

    // Record for a while.
    framesToRecord = actualSampleRate * NUM_SECONDS;
    framesLeft = framesToRecord;
    while (framesLeft > 0) {
        // Read audio data from the stream.
        const int64_t timeoutNanos = 100 * NANOS_PER_MILLISECOND;
        int minFrames = (framesToRecord < framesPerRead) ? framesToRecord : framesPerRead;
        int actual = AAudioStream_read(aaudioStream, data, minFrames, timeoutNanos);
        if (actual < 0) {
            fprintf(stderr, "ERROR - AAudioStream_read() returned %d\n", actual);
            result = actual;
            goto finish;
        } else if (actual == 0) {
            fprintf(stderr, "WARNING - AAudioStream_read() returned %d\n", actual);
            goto finish;
        }
        framesLeft -= actual;

        // Peak finder.
        for (int frameIndex = 0; frameIndex < actual; frameIndex++) {
            float sample = data[frameIndex * actualSamplesPerFrame] * (1.0/32768);
            if (sample > peakLevel) {
                peakLevel = sample;
            }
        }

        // Display level as stars, eg. "******".
        if ((loopCounter++ % 10) == 0) {
            printf("%5.3f ", peakLevel);
            int numStars = (int)(peakLevel * 50);
            for (int i = 0; i < numStars; i++) {
                printf("*");
            }
            printf("\n");
            peakLevel = 0.0;
        }
    }

    xRunCount = AAudioStream_getXRunCount(aaudioStream);
    printf("AAudioStream_getXRunCount %d\n", xRunCount);

finish:
    AAudioStream_close(aaudioStream);
    AAudioStreamBuilder_delete(aaudioBuilder);
    delete[] data;
    printf("exiting - AAudio result = %d = %s\n", result, AAudio_convertResultToText(result));
    return (result != AAUDIO_OK) ? EXIT_FAILURE : EXIT_SUCCESS;
}

