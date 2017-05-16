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

// Play sine waves using an AAudio callback.

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <aaudio/AAudio.h>
#include "SineGenerator.h"

#define NUM_SECONDS              5

//#define SHARING_MODE  AAUDIO_SHARING_MODE_EXCLUSIVE
#define SHARING_MODE  AAUDIO_SHARING_MODE_SHARED

// TODO refactor common code into a single SimpleAAudio class
/**
 * Simple wrapper for AAudio that opens a default stream and then calls
 * a callback function to fill the output buffers.
 */
class SimpleAAudioPlayer {
public:
    SimpleAAudioPlayer() {}
    ~SimpleAAudioPlayer() {
        close();
    };

    /**
     * Call this before calling open().
     * @param requestedSharingMode
     */
    void setSharingMode(aaudio_sharing_mode_t requestedSharingMode) {
        mRequestedSharingMode = requestedSharingMode;
    }

    /**
     * Also known as "sample rate"
     * Only call this after open() has been called.
     */
    int32_t getFramesPerSecond() {
        if (mStream == nullptr) {
            return AAUDIO_ERROR_INVALID_STATE;
        }
        return AAudioStream_getSampleRate(mStream);;
    }

    /**
     * Only call this after open() has been called.
     */
    int32_t getChannelCount() {
        if (mStream == nullptr) {
            return AAUDIO_ERROR_INVALID_STATE;
        }
        return AAudioStream_getChannelCount(mStream);;
    }

    /**
     * Open a stream
     */
    aaudio_result_t open(AAudioStream_dataCallback dataProc, void *userContext) {
        aaudio_result_t result = AAUDIO_OK;

        // Use an AAudioStreamBuilder to contain requested parameters.
        result = AAudio_createStreamBuilder(&mBuilder);
        if (result != AAUDIO_OK) return result;

        //AAudioStreamBuilder_setSampleRate(mBuilder, 44100);
        AAudioStreamBuilder_setSharingMode(mBuilder, mRequestedSharingMode);
        AAudioStreamBuilder_setDataCallback(mBuilder, dataProc, userContext);
        AAudioStreamBuilder_setFormat(mBuilder, AAUDIO_FORMAT_PCM_FLOAT);
        //AAudioStreamBuilder_setFramesPerDataCallback(mBuilder, CALLBACK_SIZE_FRAMES);
        AAudioStreamBuilder_setBufferCapacityInFrames(mBuilder, 48 * 8);

        //aaudio_performance_mode_t perfMode = AAUDIO_PERFORMANCE_MODE_NONE;
        aaudio_performance_mode_t perfMode = AAUDIO_PERFORMANCE_MODE_LOW_LATENCY;
        //aaudio_performance_mode_t perfMode = AAUDIO_PERFORMANCE_MODE_POWER_SAVING;
        AAudioStreamBuilder_setPerformanceMode(mBuilder, perfMode);

        // Open an AAudioStream using the Builder.
        result = AAudioStreamBuilder_openStream(mBuilder, &mStream);
        if (result != AAUDIO_OK) goto finish1;

        printf("AAudioStream_getFramesPerBurst() = %d\n",
               AAudioStream_getFramesPerBurst(mStream));
        printf("AAudioStream_getBufferSizeInFrames() = %d\n",
               AAudioStream_getBufferSizeInFrames(mStream));
        printf("AAudioStream_getBufferCapacityInFrames() = %d\n",
               AAudioStream_getBufferCapacityInFrames(mStream));
        printf("AAudioStream_getPerformanceMode() = %d, requested %d\n",
               AAudioStream_getPerformanceMode(mStream), perfMode);

     finish1:
        AAudioStreamBuilder_delete(mBuilder);
        mBuilder = nullptr;
        return result;
    }

    aaudio_result_t close() {
        if (mStream != nullptr) {
            printf("call AAudioStream_close(%p)\n", mStream);  fflush(stdout);
            AAudioStream_close(mStream);
            mStream = nullptr;
            AAudioStreamBuilder_delete(mBuilder);
            mBuilder = nullptr;
        }
        return AAUDIO_OK;
    }

    // Write zero data to fill up the buffer and prevent underruns.
    aaudio_result_t prime() {
        int32_t samplesPerFrame = AAudioStream_getChannelCount(mStream);
        const int numFrames = 32;
        float zeros[numFrames * samplesPerFrame];
        memset(zeros, 0, sizeof(zeros));
        aaudio_result_t result = numFrames;
        while (result == numFrames) {
            result = AAudioStream_write(mStream, zeros, numFrames, 0);
        }
        return result;
    }

    // Start the stream. AAudio will start calling your callback function.
     aaudio_result_t start() {
        aaudio_result_t result = AAudioStream_requestStart(mStream);
        if (result != AAUDIO_OK) {
            printf("ERROR - AAudioStream_requestStart() returned %d %s\n",
                    result, AAudio_convertResultToText(result));
        }
        return result;
    }

    // Stop the stream. AAudio will stop calling your callback function.
    aaudio_result_t stop() {
        aaudio_result_t result = AAudioStream_requestStop(mStream);
        if (result != AAUDIO_OK) {
            printf("ERROR - AAudioStream_requestStop() returned %d %s\n",
                    result, AAudio_convertResultToText(result));
        }
        int32_t xRunCount = AAudioStream_getXRunCount(mStream);
        printf("AAudioStream_getXRunCount %d\n", xRunCount);
        return result;
    }

    AAudioStream *getStream() const {
        return mStream;
    }

private:
    AAudioStreamBuilder    *mBuilder = nullptr;
    AAudioStream           *mStream = nullptr;
    aaudio_sharing_mode_t   mRequestedSharingMode = SHARING_MODE;
};

// Application data that gets passed to the callback.
#define MAX_FRAME_COUNT_RECORDS    256
typedef struct SineThreadedData_s {
    SineGenerator  sineOsc1;
    SineGenerator  sineOsc2;
    int            scheduler;
    bool           schedulerChecked;
} SineThreadedData_t;

// Callback function that fills the audio output buffer.
aaudio_data_callback_result_t MyDataCallbackProc(
        AAudioStream *stream,
        void *userData,
        void *audioData,
        int32_t numFrames
        ) {

    SineThreadedData_t *sineData = (SineThreadedData_t *) userData;

    if (!sineData->schedulerChecked) {
        sineData->scheduler = sched_getscheduler(gettid());
        sineData->schedulerChecked = true;
    }

    int32_t samplesPerFrame = AAudioStream_getChannelCount(stream);
    // This code only plays on the first one or two channels.
    // TODO Support arbitrary number of channels.
    switch (AAudioStream_getFormat(stream)) {
        case AAUDIO_FORMAT_PCM_I16: {
            int16_t *audioBuffer = (int16_t *) audioData;
            // Render sine waves as shorts to first channel.
            sineData->sineOsc1.render(&audioBuffer[0], samplesPerFrame, numFrames);
            // Render sine waves to second channel if there is one.
            if (samplesPerFrame > 1) {
                sineData->sineOsc2.render(&audioBuffer[1], samplesPerFrame, numFrames);
            }
        }
        break;
        case AAUDIO_FORMAT_PCM_FLOAT: {
            float *audioBuffer = (float *) audioData;
            // Render sine waves as floats to first channel.
            sineData->sineOsc1.render(&audioBuffer[0], samplesPerFrame, numFrames);
            // Render sine waves to second channel if there is one.
            if (samplesPerFrame > 1) {
                sineData->sineOsc2.render(&audioBuffer[1], samplesPerFrame, numFrames);
            }
        }
        break;
        default:
            return AAUDIO_CALLBACK_RESULT_STOP;
    }

    return AAUDIO_CALLBACK_RESULT_CONTINUE;
}

int main(int argc, char **argv)
{
    (void)argc; // unused
    SimpleAAudioPlayer player;
    SineThreadedData_t myData;
    aaudio_result_t result;

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, nullptr, _IONBF, (size_t) 0);
    printf("%s - Play a sine sweep using an AAudio callback\n", argv[0]);

    player.setSharingMode(SHARING_MODE);

    myData.schedulerChecked = false;

    result = player.open(MyDataCallbackProc, &myData);
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR -  player.open() returned %d\n", result);
        goto error;
    }
    printf("player.getFramesPerSecond() = %d\n", player.getFramesPerSecond());
    printf("player.getChannelCount() = %d\n", player.getChannelCount());
    myData.sineOsc1.setup(440.0, 48000);
    myData.sineOsc1.setSweep(300.0, 600.0, 5.0);
    myData.sineOsc2.setup(660.0, 48000);
    myData.sineOsc2.setSweep(350.0, 900.0, 7.0);

#if 0
    result = player.prime(); // FIXME crashes AudioTrack.cpp
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR - player.prime() returned %d\n", result);
        goto error;
    }
#endif

    result = player.start();
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR - player.start() returned %d\n", result);
        goto error;
    }

    printf("Sleep for %d seconds while audio plays in a callback thread.\n", NUM_SECONDS);
    for (int second = 0; second < NUM_SECONDS; second++)
    {
        const struct timespec request = { .tv_sec = 1, .tv_nsec = 0 };
        (void) clock_nanosleep(CLOCK_MONOTONIC, 0 /*flags*/, &request, NULL /*remain*/);

        aaudio_stream_state_t state;
        result = AAudioStream_waitForStateChange(player.getStream(),
                                                 AAUDIO_STREAM_STATE_CLOSED,
                                                 &state,
                                                 0);
        if (result != AAUDIO_OK) {
            fprintf(stderr, "ERROR - AAudioStream_waitForStateChange() returned %d\n", result);
            goto error;
        }
        if (state != AAUDIO_STREAM_STATE_STARTING && state != AAUDIO_STREAM_STATE_STARTED) {
            printf("Stream state is %d %s!\n", state, AAudio_convertStreamStateToText(state));
            break;
        }
        printf("framesWritten = %d\n", (int) AAudioStream_getFramesWritten(player.getStream()));
    }
    printf("Woke up now.\n");

    printf("call stop()\n");
    result = player.stop();
    if (result != AAUDIO_OK) {
        goto error;
    }
    printf("call close()\n");
    result = player.close();
    if (result != AAUDIO_OK) {
        goto error;
    }

    if (myData.schedulerChecked) {
        printf("scheduler = 0x%08x, SCHED_FIFO = 0x%08X\n",
               myData.scheduler,
               SCHED_FIFO);
    }

    printf("SUCCESS\n");
    return EXIT_SUCCESS;
error:
    player.close();
    printf("exiting - AAudio result = %d = %s\n", result, AAudio_convertResultToText(result));
    return EXIT_FAILURE;
}

