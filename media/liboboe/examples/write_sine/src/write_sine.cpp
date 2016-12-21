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

// Play sine waves using Oboe.

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <oboe/OboeDefinitions.h>
#include <oboe/OboeAudio.h>
#include "SineGenerator.h"

#define SAMPLE_RATE   48000
#define NUM_SECONDS   10

static const char *getSharingModeText(oboe_sharing_mode_t mode) {
    const char *modeText = "unknown";
    switch (mode) {
    case OBOE_SHARING_MODE_EXCLUSIVE:
        modeText = "EXCLUSIVE";
        break;
    case OBOE_SHARING_MODE_LEGACY:
        modeText = "LEGACY";
        break;
    case OBOE_SHARING_MODE_SHARED:
        modeText = "SHARED";
        break;
    case OBOE_SHARING_MODE_PUBLIC_MIX:
        modeText = "PUBLIC_MIX";
        break;
    default:
        break;
    }
    return modeText;
}

int main(int argc, char **argv)
{
    (void)argc; // unused

    oboe_result_t result = OBOE_OK;

    const int requestedSamplesPerFrame = 2;
    int actualSamplesPerFrame = 0;
    const int requestedSampleRate = SAMPLE_RATE;
    int actualSampleRate = 0;
    const oboe_audio_format_t requestedDataFormat = OBOE_AUDIO_FORMAT_PCM16;
    oboe_audio_format_t actualDataFormat = OBOE_AUDIO_FORMAT_PCM16;

    const oboe_sharing_mode_t requestedSharingMode = OBOE_SHARING_MODE_EXCLUSIVE;
    //const oboe_sharing_mode_t requestedSharingMode = OBOE_SHARING_MODE_LEGACY;
    oboe_sharing_mode_t actualSharingMode = OBOE_SHARING_MODE_LEGACY;

    OboeStreamBuilder oboeBuilder = OBOE_STREAM_BUILDER_NONE;
    OboeStream oboeStream = OBOE_STREAM_NONE;
    oboe_stream_state_t state = OBOE_STREAM_STATE_UNINITIALIZED;
    oboe_size_frames_t framesPerBurst = 0;
    oboe_size_frames_t framesToPlay = 0;
    oboe_size_frames_t framesLeft = 0;
    int32_t xRunCount = 0;
    int16_t *data = nullptr;

    SineGenerator sineOsc1;
    SineGenerator sineOsc2;

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, nullptr, _IONBF, (size_t) 0);

    printf("%s - Play a sine wave using Oboe\n", argv[0]);

    // Use an OboeStreamBuilder to contain requested parameters.
    result = Oboe_createStreamBuilder(&oboeBuilder);
    if (result != OBOE_OK) {
        goto finish;
    }

    // Request stream properties.
    result = OboeStreamBuilder_setSampleRate(oboeBuilder, requestedSampleRate);
    if (result != OBOE_OK) {
        goto finish;
    }
    result = OboeStreamBuilder_setSamplesPerFrame(oboeBuilder, requestedSamplesPerFrame);
    if (result != OBOE_OK) {
        goto finish;
    }
    result = OboeStreamBuilder_setFormat(oboeBuilder, requestedDataFormat);
    if (result != OBOE_OK) {
        goto finish;
    }
    result = OboeStreamBuilder_setSharingMode(oboeBuilder, requestedSharingMode);
    if (result != OBOE_OK) {
        goto finish;
    }

    // Create an OboeStream using the Builder.
    result = OboeStreamBuilder_openStream(oboeBuilder, &oboeStream);
    printf("oboeStream 0x%08x\n", oboeStream);
    if (result != OBOE_OK) {
        goto finish;
    }

    result = OboeStream_getState(oboeStream, &state);
    printf("after open, state = %s\n", Oboe_convertStreamStateToText(state));

    // Check to see what kind of stream we actually got.
    result = OboeStream_getSampleRate(oboeStream, &actualSampleRate);
    printf("SampleRate: requested = %d, actual = %d\n", requestedSampleRate, actualSampleRate);

    sineOsc1.setup(440.0, actualSampleRate);
    sineOsc2.setup(660.0, actualSampleRate);

    result = OboeStream_getSamplesPerFrame(oboeStream, &actualSamplesPerFrame);
    printf("SamplesPerFrame: requested = %d, actual = %d\n",
            requestedSamplesPerFrame, actualSamplesPerFrame);

    result = OboeStream_getSharingMode(oboeStream, &actualSharingMode);
    printf("SharingMode: requested = %s, actual = %s\n",
            getSharingModeText(requestedSharingMode),
            getSharingModeText(actualSharingMode));

    // This is the number of frames that are read in one chunk by a DMA controller
    // or a DSP or a mixer.
    result = OboeStream_getFramesPerBurst(oboeStream, &framesPerBurst);
    printf("DataFormat: original framesPerBurst = %d\n",framesPerBurst);
    if (result != OBOE_OK) {
        fprintf(stderr, "ERROR - OboeStream_getFramesPerBurst() returned %d\n", result);
        goto finish;
    }
    // Some DMA might use very short bursts of 16 frames. We don't need to write such small
    // buffers. But it helps to use a multiple of the burst size for predictable scheduling.
    while (framesPerBurst < 48) {
        framesPerBurst *= 2;
    }
    printf("DataFormat: final framesPerBurst = %d\n",framesPerBurst);

    OboeStream_getFormat(oboeStream, &actualDataFormat);
    printf("DataFormat: requested = %d, actual = %d\n", requestedDataFormat, actualDataFormat);
    // TODO handle other data formats

    // Allocate a buffer for the audio data.
    data = new int16_t[framesPerBurst * actualSamplesPerFrame];
    if (data == nullptr) {
        fprintf(stderr, "ERROR - could not allocate data buffer\n");
        result = OBOE_ERROR_NO_MEMORY;
        goto finish;
    }

    // Start the stream.
    printf("call OboeStream_requestStart()\n");
    result = OboeStream_requestStart(oboeStream);
    if (result != OBOE_OK) {
        fprintf(stderr, "ERROR - OboeStream_requestStart() returned %d\n", result);
        goto finish;
    }

    result = OboeStream_getState(oboeStream, &state);
    printf("after start, state = %s\n", Oboe_convertStreamStateToText(state));

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
        oboe_nanoseconds_t timeoutNanos = 100 * OBOE_NANOS_PER_MILLISECOND;
        int minFrames = (framesToPlay < framesPerBurst) ? framesToPlay : framesPerBurst;
        int actual = OboeStream_write(oboeStream, data, minFrames, timeoutNanos);
        if (actual < 0) {
            fprintf(stderr, "ERROR - OboeStream_write() returned %zd\n", actual);
            goto finish;
        } else if (actual == 0) {
            fprintf(stderr, "WARNING - OboeStream_write() returned %zd\n", actual);
            goto finish;
        }
        framesLeft -= actual;
    }

    result = OboeStream_getXRunCount(oboeStream, &xRunCount);
    printf("OboeStream_getXRunCount %d\n", xRunCount);

finish:
    delete[] data;
    OboeStream_close(oboeStream);
    OboeStreamBuilder_delete(oboeBuilder);
    printf("exiting - Oboe result = %d = %s\n", result, Oboe_convertResultToText(result));
    return (result != OBOE_OK) ? EXIT_FAILURE : EXIT_SUCCESS;
}

