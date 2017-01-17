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

// Play sine waves using an Oboe background thread.

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <oboe/OboeDefinitions.h>
#include <oboe/OboeAudio.h>
#include "SineGenerator.h"

#define NUM_SECONDS   10

#define SHARING_MODE  OBOE_SHARING_MODE_EXCLUSIVE
//#define SHARING_MODE  OBOE_SHARING_MODE_LEGACY

// Prototype for a callback.
typedef int audio_callback_proc_t(float *outputBuffer,
                                     oboe_size_frames_t numFrames,
                                     void *userContext);

static void *SimpleOboePlayerThreadProc(void *arg);

/**
 * Simple wrapper for Oboe that opens a default stream and then calls
 * a callback function to fill the output buffers.
 */
class SimpleOboePlayer {
public:
    SimpleOboePlayer() {}
    virtual ~SimpleOboePlayer() {
        close();
    };

    void setSharingMode(oboe_sharing_mode_t requestedSharingMode) {
        mRequestedSharingMode = requestedSharingMode;
    }

    /** Also known as "sample rate"
     */
    int32_t getFramesPerSecond() {
        return mFramesPerSecond;
    }

    int32_t getSamplesPerFrame() {
        return mSamplesPerFrame;
    }

    /**
     * Open a stream
     */
    oboe_result_t open(audio_callback_proc_t *proc, void *userContext) {
        mCallbackProc = proc;
        mUserContext = userContext;
        oboe_result_t result = OBOE_OK;

        // Use an OboeStreamBuilder to contain requested parameters.
        result = Oboe_createStreamBuilder(&mBuilder);
        if (result != OBOE_OK) return result;

        result = OboeStreamBuilder_setSharingMode(mBuilder, mRequestedSharingMode);
        if (result != OBOE_OK) goto finish1;

        // Open an OboeStream using the Builder.
        result = OboeStreamBuilder_openStream(mBuilder, &mStream);
        if (result != OBOE_OK) goto finish1;

        // Check to see what kind of stream we actually got.
        result = OboeStream_getSampleRate(mStream, &mFramesPerSecond);
        printf("open() mFramesPerSecond = %d\n", mFramesPerSecond);
        if (result != OBOE_OK) goto finish2;
        result = OboeStream_getSamplesPerFrame(mStream, &mSamplesPerFrame);
        printf("open() mSamplesPerFrame = %d\n", mSamplesPerFrame);
        if (result != OBOE_OK) goto finish2;

        // This is the number of frames that are read in one chunk by a DMA controller
        // or a DSP or a mixer.
        result = OboeStream_getFramesPerBurst(mStream, &mFramesPerBurst);
        if (result != OBOE_OK) goto finish2;
        // Some DMA might use very short bursts. We don't need to write such small
        // buffers. But it helps to use a multiple of the burst size for predictable scheduling.
        while (mFramesPerBurst < 48) {
            mFramesPerBurst *= 2;
        }
        printf("DataFormat: final framesPerBurst = %d\n",mFramesPerBurst);

        result = OboeStream_getFormat(mStream, &mDataFormat);
        if (result != OBOE_OK) {
            fprintf(stderr, "ERROR - OboeStream_getFormat() returned %d\n", result);
            goto finish2;
        }

        // Allocate a buffer for the audio data.
        mOutputBuffer = new float[mFramesPerBurst * mSamplesPerFrame];
        if (mOutputBuffer == nullptr) {
            fprintf(stderr, "ERROR - could not allocate data buffer\n");
            result = OBOE_ERROR_NO_MEMORY;
        }

        // If needed allocate a buffer for converting float to int16_t.
        if (mDataFormat == OBOE_AUDIO_FORMAT_PCM16) {
            mConversionBuffer = new int16_t[mFramesPerBurst * mSamplesPerFrame];
            if (mConversionBuffer == nullptr) {
                fprintf(stderr, "ERROR - could not allocate conversion buffer\n");
                result = OBOE_ERROR_NO_MEMORY;
            }
        }
        return result;

     finish2:
        OboeStream_close(mStream);
        mStream = OBOE_HANDLE_INVALID;
     finish1:
        OboeStreamBuilder_delete(mBuilder);
        mBuilder = OBOE_HANDLE_INVALID;
        return result;
    }

    oboe_result_t close() {
        if (mStream != OBOE_HANDLE_INVALID) {
            stop();
            printf("call OboeStream_close(0x%08x)\n", mStream);  fflush(stdout);
            OboeStream_close(mStream);
            mStream = OBOE_HANDLE_INVALID;
            OboeStreamBuilder_delete(mBuilder);
            mBuilder = OBOE_HANDLE_INVALID;
            delete mOutputBuffer;
            mOutputBuffer = nullptr;
            delete mConversionBuffer;
            mConversionBuffer = nullptr;
        }
        return OBOE_OK;
    }

    // Start a thread that will call the callback proc.
    oboe_result_t start() {
        mEnabled = true;
        oboe_nanoseconds_t nanosPerBurst = mFramesPerBurst * OBOE_NANOS_PER_SECOND
                                           / mFramesPerSecond;
        return OboeStream_createThread(mStream, nanosPerBurst,
                                       SimpleOboePlayerThreadProc,
                                       this);
    }

    // Tell the thread to stop.
    oboe_result_t stop() {
        mEnabled = false;
        return OboeStream_joinThread(mStream, nullptr, 2 * OBOE_NANOS_PER_SECOND);
    }

    oboe_result_t callbackLoop() {
        int32_t framesWritten = 0;
        int32_t xRunCount = 0;
        oboe_result_t result = OBOE_OK;

        result = OboeStream_requestStart(mStream);
        if (result != OBOE_OK) {
            fprintf(stderr, "ERROR - OboeStream_requestStart() returned %d\n", result);
            return result;
        }

        // Give up after several burst periods have passed.
        const int burstsPerTimeout = 8;
        oboe_nanoseconds_t nanosPerTimeout =
                        burstsPerTimeout * mFramesPerBurst * OBOE_NANOS_PER_SECOND
                        / mFramesPerSecond;

        while (mEnabled && result >= 0) {
            // Call application's callback function to fill the buffer.
            if (mCallbackProc(mOutputBuffer, mFramesPerBurst, mUserContext)) {
                mEnabled = false;
            }
            // if needed, convert from float to int16_t PCM
            if (mConversionBuffer != nullptr) {
                int32_t numSamples = mFramesPerBurst * mSamplesPerFrame;
                for (int i = 0; i < numSamples; i++) {
                    mConversionBuffer[i] = (int16_t)(32767.0 * mOutputBuffer[i]);
                }
                // Write the application data to stream.
                result = OboeStream_write(mStream, mConversionBuffer, mFramesPerBurst, nanosPerTimeout);
            } else {
                // Write the application data to stream.
                result = OboeStream_write(mStream, mOutputBuffer, mFramesPerBurst, nanosPerTimeout);
            }
            framesWritten += result;
            if (result < 0) {
                fprintf(stderr, "ERROR - OboeStream_write() returned %zd\n", result);
            }
        }

        result = OboeStream_getXRunCount(mStream, &xRunCount);
        printf("OboeStream_getXRunCount %d\n", xRunCount);

        result = OboeStream_requestStop(mStream);
        if (result != OBOE_OK) {
            fprintf(stderr, "ERROR - OboeStream_requestStart() returned %d\n", result);
            return result;
        }

        return result;
    }

private:
    OboeStreamBuilder   mBuilder = OBOE_HANDLE_INVALID;
    OboeStream          mStream = OBOE_HANDLE_INVALID;
    float            *  mOutputBuffer = nullptr;
    int16_t          *  mConversionBuffer = nullptr;

    audio_callback_proc_t * mCallbackProc = nullptr;
    void             *  mUserContext = nullptr;
    oboe_sharing_mode_t mRequestedSharingMode = SHARING_MODE;
    int32_t             mSamplesPerFrame = 0;
    int32_t             mFramesPerSecond = 0;
    oboe_size_frames_t  mFramesPerBurst = 0;
    oboe_audio_format_t mDataFormat = OBOE_AUDIO_FORMAT_PCM16;

    volatile bool       mEnabled = false; // used to request that callback exit its loop
};

static void *SimpleOboePlayerThreadProc(void *arg) {
    SimpleOboePlayer *player = (SimpleOboePlayer *) arg;
    player->callbackLoop();
    return nullptr;
}

// Application data that gets passed to the callback.
typedef struct SineThreadedData_s {
    SineGenerator  sineOsc1;
    SineGenerator  sineOsc2;
    int32_t        samplesPerFrame = 0;
} SineThreadedData_t;

// Callback function that fills the audio output buffer.
int MyCallbackProc(float *outputBuffer, int32_t numFrames, void *userContext) {
    SineThreadedData_t *data = (SineThreadedData_t *) userContext;
    // Render sine waves to left and right channels.
    data->sineOsc1.render(&outputBuffer[0], data->samplesPerFrame, numFrames);
    if (data->samplesPerFrame > 1) {
        data->sineOsc2.render(&outputBuffer[1], data->samplesPerFrame, numFrames);
    }
    return 0;
}

int main(int argc, char **argv)
{
    (void)argc; // unused
    SimpleOboePlayer player;
    SineThreadedData_t myData;
    oboe_result_t result;

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, nullptr, _IONBF, (size_t) 0);
    printf("%s - Play a sine wave using an Oboe Thread\n", argv[0]);

    result = player.open(MyCallbackProc, &myData);
    if (result != OBOE_OK) {
        fprintf(stderr, "ERROR -  player.open() returned %d\n", result);
        goto error;
    }
    printf("player.getFramesPerSecond() = %d\n", player.getFramesPerSecond());
    printf("player.getSamplesPerFrame() = %d\n", player.getSamplesPerFrame());
    myData.sineOsc1.setup(440.0, 48000);
    myData.sineOsc1.setSweep(300.0, 600.0, 5.0);
    myData.sineOsc2.setup(660.0, 48000);
    myData.sineOsc2.setSweep(350.0, 900.0, 7.0);
    myData.samplesPerFrame = player.getSamplesPerFrame();

    result = player.start();
    if (result != OBOE_OK) {
        fprintf(stderr, "ERROR -  player.start() returned %d\n", result);
        goto error;
    }

    printf("Sleep for %d seconds while audio plays in a background thread.\n", NUM_SECONDS);
    {
        // FIXME sleep is not an NDK API
        // sleep(NUM_SECONDS);
        const struct timespec request = { .tv_sec = NUM_SECONDS, .tv_nsec = 0 };
        (void) clock_nanosleep(CLOCK_MONOTONIC, 0 /*flags*/, &request, NULL /*remain*/);
    }
    printf("Woke up now.\n");

    result = player.stop();
    if (result != OBOE_OK) {
        fprintf(stderr, "ERROR -  player.stop() returned %d\n", result);
        goto error;
    }
    result = player.close();
    if (result != OBOE_OK) {
        fprintf(stderr, "ERROR -  player.close() returned %d\n", result);
        goto error;
    }

    printf("SUCCESS\n");
    return EXIT_SUCCESS;
error:
    player.close();
    printf("exiting - Oboe result = %d = %s\n", result, Oboe_convertResultToText(result));
    return EXIT_FAILURE;
}

