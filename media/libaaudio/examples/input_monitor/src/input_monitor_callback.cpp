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

#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <aaudio/AAudio.h>

#define NUM_SECONDS           5
#define NANOS_PER_MICROSECOND ((int64_t)1000)
#define NANOS_PER_MILLISECOND (NANOS_PER_MICROSECOND * 1000)
#define NANOS_PER_SECOND      (NANOS_PER_MILLISECOND * 1000)

//#define SHARING_MODE  AAUDIO_SHARING_MODE_EXCLUSIVE
#define SHARING_MODE  AAUDIO_SHARING_MODE_SHARED

/**
 * Simple wrapper for AAudio that opens an input stream and then calls
 * a callback function to process the input data.
 */
class SimpleAAudioRecorder {
public:
    SimpleAAudioRecorder() {}
    ~SimpleAAudioRecorder() {
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
    int32_t getSamplesPerFrame() {
        if (mStream == nullptr) {
            return AAUDIO_ERROR_INVALID_STATE;
        }
        return AAudioStream_getSamplesPerFrame(mStream);;
    }
    /**
     * Only call this after open() has been called.
     */
    int64_t getFramesRead() {
        if (mStream == nullptr) {
            return AAUDIO_ERROR_INVALID_STATE;
        }
        return AAudioStream_getFramesRead(mStream);;
    }

    /**
     * Open a stream
     */
    aaudio_result_t open(AAudioStream_dataCallback proc, void *userContext) {
        aaudio_result_t result = AAUDIO_OK;

        // Use an AAudioStreamBuilder to contain requested parameters.
        result = AAudio_createStreamBuilder(&mBuilder);
        if (result != AAUDIO_OK) return result;

        AAudioStreamBuilder_setDirection(mBuilder, AAUDIO_DIRECTION_INPUT);
        AAudioStreamBuilder_setSharingMode(mBuilder, mRequestedSharingMode);
        AAudioStreamBuilder_setDataCallback(mBuilder, proc, userContext);
        AAudioStreamBuilder_setFormat(mBuilder, AAUDIO_FORMAT_PCM_I16);

        // Open an AAudioStream using the Builder.
        result = AAudioStreamBuilder_openStream(mBuilder, &mStream);
        if (result != AAUDIO_OK) {
            fprintf(stderr, "ERROR - AAudioStreamBuilder_openStream() returned %d %s\n",
                    result, AAudio_convertResultToText(result));
            goto finish1;
        }

        printf("AAudioStream_getFramesPerBurst()         = %d\n",
               AAudioStream_getFramesPerBurst(mStream));
        printf("AAudioStream_getBufferSizeInFrames()     = %d\n",
               AAudioStream_getBufferSizeInFrames(mStream));
        printf("AAudioStream_getBufferCapacityInFrames() = %d\n",
               AAudioStream_getBufferCapacityInFrames(mStream));
        return result;

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
        int32_t samplesPerFrame = AAudioStream_getSamplesPerFrame(mStream);
        const int numFrames = 32; // arbitrary
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
            fprintf(stderr, "ERROR - AAudioStream_requestStart() returned %d %s\n",
                    result, AAudio_convertResultToText(result));
        }
        return result;
    }

    // Stop the stream. AAudio will stop calling your callback function.
    aaudio_result_t stop() {
        aaudio_result_t result = AAudioStream_requestStop(mStream);
        if (result != AAUDIO_OK) {
            fprintf(stderr, "ERROR - AAudioStream_requestStop() returned %d %s\n",
                    result, AAudio_convertResultToText(result));
        }
        return result;
    }

    // Pause the stream. AAudio will stop calling your callback function.
    aaudio_result_t pause() {
        aaudio_result_t result = AAudioStream_requestPause(mStream);
        if (result != AAUDIO_OK) {
            fprintf(stderr, "ERROR - AAudioStream_requestPause() returned %d %s\n",
                    result, AAudio_convertResultToText(result));
        }
        return result;
    }

private:
    AAudioStreamBuilder    *mBuilder = nullptr;
    AAudioStream           *mStream = nullptr;
    aaudio_sharing_mode_t   mRequestedSharingMode = SHARING_MODE;
};

// Application data that gets passed to the callback.
typedef struct PeakTrackerData {
    float peakLevel;
} PeakTrackerData_t;

#define DECAY_FACTOR   0.999

// Callback function that fills the audio output buffer.
aaudio_data_callback_result_t MyDataCallbackProc(
        AAudioStream *stream,
        void *userData,
        void *audioData,
        int32_t numFrames
        ) {

    PeakTrackerData_t *data = (PeakTrackerData_t *) userData;
    // printf("MyCallbackProc(): frameCount = %d\n", numFrames);
    int32_t samplesPerFrame = AAudioStream_getSamplesPerFrame(stream);
    float sample;
    // This code assume mono or stereo.
    switch (AAudioStream_getFormat(stream)) {
        case AAUDIO_FORMAT_PCM_I16: {
            int16_t *audioBuffer = (int16_t *) audioData;
            // Peak follower
            for (int frameIndex = 0; frameIndex < numFrames; frameIndex++) {
                sample = audioBuffer[frameIndex * samplesPerFrame] * (1.0/32768);
                data->peakLevel *= DECAY_FACTOR;
                if (sample > data->peakLevel) {
                    data->peakLevel = sample;
                }
            }
        }
        break;
        case AAUDIO_FORMAT_PCM_FLOAT: {
            float *audioBuffer = (float *) audioData;
            // Peak follower
            for (int frameIndex = 0; frameIndex < numFrames; frameIndex++) {
                sample = audioBuffer[frameIndex * samplesPerFrame];
                data->peakLevel *= DECAY_FACTOR;
                if (sample > data->peakLevel) {
                    data->peakLevel = sample;
                }
            }
        }
        break;
        default:
            return AAUDIO_CALLBACK_RESULT_STOP;
    }

    return AAUDIO_CALLBACK_RESULT_CONTINUE;
}

void displayPeakLevel(float peakLevel) {
    printf("%5.3f ", peakLevel);
    const int maxStars = 50; // arbitrary, fits on one line
    int numStars = (int) (peakLevel * maxStars);
    for (int i = 0; i < numStars; i++) {
        printf("*");
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    (void)argc; // unused
    SimpleAAudioRecorder recorder;
    PeakTrackerData_t myData = {0.0};
    aaudio_result_t result;
    const int displayRateHz = 20; // arbitrary
    const int loopsNeeded = NUM_SECONDS * displayRateHz;

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, nullptr, _IONBF, (size_t) 0);
    printf("%s - Display audio input using an AAudio callback\n", argv[0]);

    recorder.setSharingMode(SHARING_MODE);

    result = recorder.open(MyDataCallbackProc, &myData);
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR -  recorder.open() returned %d\n", result);
        goto error;
    }
    printf("recorder.getFramesPerSecond() = %d\n", recorder.getFramesPerSecond());
    printf("recorder.getSamplesPerFrame() = %d\n", recorder.getSamplesPerFrame());

    result = recorder.start();
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR -  recorder.start() returned %d\n", result);
        goto error;
    }

    printf("Sleep for %d seconds while audio record in a callback thread.\n", NUM_SECONDS);
    for (int i = 0; i < loopsNeeded; i++)
    {
        const struct timespec request = { .tv_sec = 0,
                .tv_nsec = NANOS_PER_SECOND / displayRateHz };
        (void) clock_nanosleep(CLOCK_MONOTONIC, 0 /*flags*/, &request, NULL /*remain*/);
        printf("%08d: ", (int)recorder.getFramesRead());
        displayPeakLevel(myData.peakLevel);
    }
    printf("Woke up. Stop for a moment.\n");

    result = recorder.stop();
    if (result != AAUDIO_OK) {
        goto error;
    }
    usleep(2000 * 1000);
    result = recorder.start();
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR -  recorder.start() returned %d\n", result);
        goto error;
    }

    printf("Sleep for %d seconds while audio records in a callback thread.\n", NUM_SECONDS);
    for (int i = 0; i < loopsNeeded; i++)
    {
        const struct timespec request = { .tv_sec = 0,
                .tv_nsec = NANOS_PER_SECOND / displayRateHz };
        (void) clock_nanosleep(CLOCK_MONOTONIC, 0 /*flags*/, &request, NULL /*remain*/);
        printf("%08d: ", (int)recorder.getFramesRead());
        displayPeakLevel(myData.peakLevel);
    }
    printf("Woke up now.\n");

    result = recorder.stop();
    if (result != AAUDIO_OK) {
        goto error;
    }
    result = recorder.close();
    if (result != AAUDIO_OK) {
        goto error;
    }

    printf("SUCCESS\n");
    return EXIT_SUCCESS;
error:
    recorder.close();
    printf("exiting - AAudio result = %d = %s\n", result, AAudio_convertResultToText(result));
    return EXIT_FAILURE;
}

