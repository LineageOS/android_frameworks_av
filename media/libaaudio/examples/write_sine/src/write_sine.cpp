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
#include <aaudio/AAudioDefinitions.h>
#include <aaudio/AAudio.h>
#include "SineGenerator.h"

#define SAMPLE_RATE   48000
#define NUM_SECONDS   10
#define NANOS_PER_MICROSECOND ((int64_t)1000)
#define NANOS_PER_MILLISECOND (NANOS_PER_MICROSECOND * 1000)

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

    aaudio_result_t result = AAUDIO_OK;

    const int requestedSamplesPerFrame = 2;
    int actualSamplesPerFrame = 0;
    const int requestedSampleRate = SAMPLE_RATE;
    int actualSampleRate = 0;
    const aaudio_audio_format_t requestedDataFormat = AAUDIO_FORMAT_PCM_I16;
    aaudio_audio_format_t actualDataFormat = AAUDIO_FORMAT_PCM_I16;

    const aaudio_sharing_mode_t requestedSharingMode = AAUDIO_SHARING_MODE_EXCLUSIVE;
    aaudio_sharing_mode_t actualSharingMode = AAUDIO_SHARING_MODE_SHARED;

    AAudioStreamBuilder *aaudioBuilder = nullptr;
    AAudioStream *aaudioStream = nullptr;
    aaudio_stream_state_t state = AAUDIO_STREAM_STATE_UNINITIALIZED;
    int32_t framesPerBurst = 0;
    int32_t framesToPlay = 0;
    int32_t framesLeft = 0;
    int32_t xRunCount = 0;
    int16_t *data = nullptr;

    SineGenerator sineOsc1;
    SineGenerator sineOsc2;

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, nullptr, _IONBF, (size_t) 0);

    printf("%s - Play a sine wave using AAudio\n", argv[0]);

    // Use an AAudioStreamBuilder to contain requested parameters.
    result = AAudio_createStreamBuilder(&aaudioBuilder);
    if (result != AAUDIO_OK) {
        goto finish;
    }

    // Request stream properties.
    AAudioStreamBuilder_setSampleRate(aaudioBuilder, requestedSampleRate);
    AAudioStreamBuilder_setSamplesPerFrame(aaudioBuilder, requestedSamplesPerFrame);
    AAudioStreamBuilder_setFormat(aaudioBuilder, requestedDataFormat);
    AAudioStreamBuilder_setSharingMode(aaudioBuilder, requestedSharingMode);


    // Create an AAudioStream using the Builder.
    result = AAudioStreamBuilder_openStream(aaudioBuilder, &aaudioStream);
    if (result != AAUDIO_OK) {
        goto finish;
    }

    state = AAudioStream_getState(aaudioStream);
    printf("after open, state = %s\n", AAudio_convertStreamStateToText(state));

    // Check to see what kind of stream we actually got.
    actualSampleRate = AAudioStream_getSampleRate(aaudioStream);
    printf("SampleRate: requested = %d, actual = %d\n", requestedSampleRate, actualSampleRate);

    sineOsc1.setup(440.0, actualSampleRate);
    sineOsc2.setup(660.0, actualSampleRate);

    actualSamplesPerFrame = AAudioStream_getSamplesPerFrame(aaudioStream);
    printf("SamplesPerFrame: requested = %d, actual = %d\n",
            requestedSamplesPerFrame, actualSamplesPerFrame);

    actualSharingMode = AAudioStream_getSharingMode(aaudioStream);
    printf("SharingMode: requested = %s, actual = %s\n",
            getSharingModeText(requestedSharingMode),
            getSharingModeText(actualSharingMode));

    // This is the number of frames that are read in one chunk by a DMA controller
    // or a DSP or a mixer.
    framesPerBurst = AAudioStream_getFramesPerBurst(aaudioStream);
    printf("DataFormat: original framesPerBurst = %d\n",framesPerBurst);

    // Some DMA might use very short bursts of 16 frames. We don't need to write such small
    // buffers. But it helps to use a multiple of the burst size for predictable scheduling.
    while (framesPerBurst < 48) {
        framesPerBurst *= 2;
    }
    printf("DataFormat: final framesPerBurst = %d\n",framesPerBurst);

    actualDataFormat = AAudioStream_getFormat(aaudioStream);
    printf("DataFormat: requested = %d, actual = %d\n", requestedDataFormat, actualDataFormat);
    // TODO handle other data formats

    // Allocate a buffer for the audio data.
    data = new int16_t[framesPerBurst * actualSamplesPerFrame];
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

    // Play for a while.
    framesToPlay = actualSampleRate * NUM_SECONDS;
    framesLeft = framesToPlay;
    while (framesLeft > 0) {
        // Render sine waves to left and right channels.
        sineOsc1.render(&data[0], actualSamplesPerFrame, framesPerBurst);
        if (actualSamplesPerFrame > 1) {
            sineOsc2.render(&data[1], actualSamplesPerFrame, framesPerBurst);
        }

        // Write audio data to the stream.
        int64_t timeoutNanos = 100 * NANOS_PER_MILLISECOND;
        int minFrames = (framesToPlay < framesPerBurst) ? framesToPlay : framesPerBurst;
        int actual = AAudioStream_write(aaudioStream, data, minFrames, timeoutNanos);
        if (actual < 0) {
            fprintf(stderr, "ERROR - AAudioStream_write() returned %zd\n", actual);
            goto finish;
        } else if (actual == 0) {
            fprintf(stderr, "WARNING - AAudioStream_write() returned %zd\n", actual);
            goto finish;
        }
        framesLeft -= actual;
    }

    xRunCount = AAudioStream_getXRunCount(aaudioStream);
    printf("AAudioStream_getXRunCount %d\n", xRunCount);

finish:
    delete[] data;
    AAudioStream_close(aaudioStream);
    AAudioStreamBuilder_delete(aaudioBuilder);
    printf("exiting - AAudio result = %d = %s\n", result, AAudio_convertResultToText(result));
    return (result != AAUDIO_OK) ? EXIT_FAILURE : EXIT_SUCCESS;
}

