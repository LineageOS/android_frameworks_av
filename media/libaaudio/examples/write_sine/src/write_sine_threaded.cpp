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

// Play sine waves using an AAudio background thread.

//#include <assert.h>
#include <atomic>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <aaudio/AAudio.h>
#include "SineGenerator.h"

#define NUM_SECONDS           5
#define NANOS_PER_MICROSECOND ((int64_t)1000)
#define NANOS_PER_MILLISECOND (NANOS_PER_MICROSECOND * 1000)
#define MILLIS_PER_SECOND     1000
#define NANOS_PER_SECOND      (NANOS_PER_MILLISECOND * MILLIS_PER_SECOND)

#define SHARING_MODE  AAUDIO_SHARING_MODE_EXCLUSIVE
//#define SHARING_MODE  AAUDIO_SHARING_MODE_SHARED

// Prototype for a callback.
typedef int audio_callback_proc_t(float *outputBuffer,
                                     int32_t numFrames,
                                     void *userContext);

static void *SimpleAAudioPlayerThreadProc(void *arg);

// TODO merge into common code
static int64_t getNanoseconds(clockid_t clockId = CLOCK_MONOTONIC) {
    struct timespec time;
    int result = clock_gettime(clockId, &time);
    if (result < 0) {
        return -errno; // TODO standardize return value
    }
    return (time.tv_sec * NANOS_PER_SECOND) + time.tv_nsec;
}

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

    void setSharingMode(aaudio_sharing_mode_t requestedSharingMode) {
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
    aaudio_result_t open(audio_callback_proc_t *proc, void *userContext) {
        mCallbackProc = proc;
        mUserContext = userContext;
        aaudio_result_t result = AAUDIO_OK;

        // Use an AAudioStreamBuilder to contain requested parameters.
        result = AAudio_createStreamBuilder(&mBuilder);
        if (result != AAUDIO_OK) return result;

        AAudioStreamBuilder_setSharingMode(mBuilder, mRequestedSharingMode);
        AAudioStreamBuilder_setSampleRate(mBuilder, 48000);

        // Open an AAudioStream using the Builder.
        result = AAudioStreamBuilder_openStream(mBuilder, &mStream);
        if (result != AAUDIO_OK) goto error;

        printf("Requested sharing mode = %d\n", mRequestedSharingMode);
        printf("Actual    sharing mode = %d\n", AAudioStream_getSharingMode(mStream));

        // Check to see what kind of stream we actually got.
        mFramesPerSecond = AAudioStream_getSampleRate(mStream);
        printf("Actual    framesPerSecond = %d\n", mFramesPerSecond);

        mSamplesPerFrame = AAudioStream_getSamplesPerFrame(mStream);
        printf("Actual    samplesPerFrame = %d\n", mSamplesPerFrame);

        {
            int32_t bufferCapacity = AAudioStream_getBufferCapacityInFrames(mStream);
            printf("Actual    bufferCapacity = %d\n", bufferCapacity);
        }

        // This is the number of frames that are read in one chunk by a DMA controller
        // or a DSP or a mixer.
        mFramesPerBurst = AAudioStream_getFramesPerBurst(mStream);
        // Some DMA might use very short bursts. We don't need to write such small
        // buffers. But it helps to use a multiple of the burst size for predictable scheduling.
        while (mFramesPerBurst < 48) {
            mFramesPerBurst *= 2;
        }
        printf("Actual    framesPerBurst = %d\n",mFramesPerBurst);

        mDataFormat = AAudioStream_getFormat(mStream);
        printf("Actual    dataFormat = %d\n", mDataFormat);

        // Allocate a buffer for the audio data.
        mOutputBuffer = new float[mFramesPerBurst * mSamplesPerFrame];
        if (mOutputBuffer == nullptr) {
            fprintf(stderr, "ERROR - could not allocate data buffer\n");
            result = AAUDIO_ERROR_NO_MEMORY;
        }

        // If needed allocate a buffer for converting float to int16_t.
        if (mDataFormat == AAUDIO_FORMAT_PCM_I16) {
            printf("Allocate data conversion buffer for float=>pcm16\n");
            mConversionBuffer = new int16_t[mFramesPerBurst * mSamplesPerFrame];
            if (mConversionBuffer == nullptr) {
                fprintf(stderr, "ERROR - could not allocate conversion buffer\n");
                result = AAUDIO_ERROR_NO_MEMORY;
            }
        }
        return result;

    error:
        AAudioStreamBuilder_delete(mBuilder);
        mBuilder = nullptr;
        return result;
    }

    aaudio_result_t close() {
        if (mStream != nullptr) {
            stop();
            printf("call AAudioStream_close(%p)\n", mStream);  fflush(stdout);
            AAudioStream_close(mStream);
            mStream = nullptr;
            AAudioStreamBuilder_delete(mBuilder);
            mBuilder = nullptr;
            delete mOutputBuffer;
            mOutputBuffer = nullptr;
            delete mConversionBuffer;
            mConversionBuffer = nullptr;
        }
        return AAUDIO_OK;
    }

    // Start a thread that will call the callback proc.
    aaudio_result_t start() {
        mEnabled.store(true);
        int64_t nanosPerBurst = mFramesPerBurst * NANOS_PER_SECOND
                                           / mFramesPerSecond;
        return AAudioStream_createThread(mStream, nanosPerBurst,
                                       SimpleAAudioPlayerThreadProc,
                                       this);
    }

    // Tell the thread to stop.
    aaudio_result_t stop() {
        mEnabled.store(false);
        return AAudioStream_joinThread(mStream, nullptr, 2 * NANOS_PER_SECOND);
    }

    bool isEnabled() const {
        return mEnabled.load();
    }

    aaudio_result_t callbackLoop() {
        aaudio_result_t result = 0;
        int64_t framesWritten = 0;
        int32_t xRunCount = 0;
        bool    started = false;
        int64_t framesInBuffer =
                AAudioStream_getFramesWritten(mStream) -
                AAudioStream_getFramesRead(mStream);
        int64_t framesAvailable =
                AAudioStream_getBufferSizeInFrames(mStream) - framesInBuffer;

        int64_t startTime = 0;
        int64_t startPosition = 0;
        int32_t loopCount = 0;

        // Give up after several burst periods have passed.
        const int burstsPerTimeout = 8;
        int64_t nanosPerTimeout = 0;
        int64_t runningNanosPerTimeout = 500 * NANOS_PER_MILLISECOND;

        while (isEnabled() && result >= 0) {
            // Call application's callback function to fill the buffer.
            if (mCallbackProc(mOutputBuffer, mFramesPerBurst, mUserContext)) {
                mEnabled.store(false);
            }

            // if needed, convert from float to int16_t PCM
            //printf("app callbackLoop writing %d frames, state = %s\n", mFramesPerBurst,
            //       AAudio_convertStreamStateToText(AAudioStream_getState(mStream)));
            if (mConversionBuffer != nullptr) {
                int32_t numSamples = mFramesPerBurst * mSamplesPerFrame;
                for (int i = 0; i < numSamples; i++) {
                    mConversionBuffer[i] = (int16_t)(32767.0 * mOutputBuffer[i]);
                }
                // Write the application data to stream.
                result = AAudioStream_write(mStream, mConversionBuffer,
                                            mFramesPerBurst, nanosPerTimeout);
            } else {
                // Write the application data to stream.
                result = AAudioStream_write(mStream, mOutputBuffer,
                                            mFramesPerBurst, nanosPerTimeout);
            }

            if (result < 0) {
                fprintf(stderr, "ERROR - AAudioStream_write() returned %d %s\n", result,
                        AAudio_convertResultToText(result));
                break;
            } else if (started && result != mFramesPerBurst) {
                fprintf(stderr, "ERROR - AAudioStream_write() timed out! %d\n", result);
                break;
            } else {
                framesWritten += result;
            }

            if (startTime > 0 && ((loopCount & 0x01FF) == 0)) {
                double elapsedFrames = (double)(framesWritten - startPosition);
                int64_t elapsedTime = getNanoseconds() - startTime;
                double measuredRate = elapsedFrames * NANOS_PER_SECOND / elapsedTime;
                printf("app callbackLoop write() measured rate %f\n", measuredRate);
            }
            loopCount++;

            if (!started && framesWritten >= framesAvailable) {
                // Start buffer if fully primed.{
                result = AAudioStream_requestStart(mStream);
                printf("app callbackLoop requestStart returned %d\n", result);
                if (result != AAUDIO_OK) {
                    fprintf(stderr, "ERROR - AAudioStream_requestStart() returned %d %s\n", result,
                            AAudio_convertResultToText(result));
                    mEnabled.store(false);
                    return result;
                }
                started = true;
                nanosPerTimeout = runningNanosPerTimeout;
                startPosition = framesWritten;
                startTime = getNanoseconds();
            }

            {
                int32_t tempXRunCount = AAudioStream_getXRunCount(mStream);
                if (tempXRunCount != xRunCount) {
                    xRunCount = tempXRunCount;
                    printf("AAudioStream_getXRunCount returns %d at frame %d\n",
                           xRunCount, (int) framesWritten);
                }
            }
        }

        result = AAudioStream_requestStop(mStream);
        if (result != AAUDIO_OK) {
            fprintf(stderr, "ERROR - AAudioStream_requestStop() returned %d %s\n", result,
                    AAudio_convertResultToText(result));
            return result;
        }

        return result;
    }

private:
    AAudioStreamBuilder  *mBuilder = nullptr;
    AAudioStream         *mStream = nullptr;
    float                *mOutputBuffer = nullptr;
    int16_t              *mConversionBuffer = nullptr;

    audio_callback_proc_t *mCallbackProc = nullptr;
    void                 *mUserContext = nullptr;
    aaudio_sharing_mode_t mRequestedSharingMode = SHARING_MODE;
    int32_t               mSamplesPerFrame = 0;
    int32_t               mFramesPerSecond = 0;
    int32_t               mFramesPerBurst = 0;
    aaudio_audio_format_t mDataFormat = AAUDIO_FORMAT_PCM_I16;

    std::atomic<bool>     mEnabled; // used to request that callback exit its loop
};

static void *SimpleAAudioPlayerThreadProc(void *arg) {
    SimpleAAudioPlayer *player = (SimpleAAudioPlayer *) arg;
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
    SimpleAAudioPlayer player;
    SineThreadedData_t myData;
    aaudio_result_t result;

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, nullptr, _IONBF, (size_t) 0);
    printf("%s - Play a sine wave using an AAudio Thread\n", argv[0]);

    result = player.open(MyCallbackProc, &myData);
    if (result != AAUDIO_OK) {
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
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR -  player.start() returned %d\n", result);
        goto error;
    }

    printf("Sleep for %d seconds while audio plays in a background thread.\n", NUM_SECONDS);
    for (int i = 0; i < NUM_SECONDS && player.isEnabled(); i++) {
        // FIXME sleep is not an NDK API
        // sleep(NUM_SECONDS);
        const struct timespec request = { .tv_sec = 1, .tv_nsec = 0 };
        (void) clock_nanosleep(CLOCK_MONOTONIC, 0 /*flags*/, &request, NULL /*remain*/);
    }
    printf("Woke up now!\n");

    result = player.stop();
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR -  player.stop() returned %d\n", result);
        goto error;
    }

    printf("Player stopped.\n");
    result = player.close();
    if (result != AAUDIO_OK) {
        fprintf(stderr, "ERROR -  player.close() returned %d\n", result);
        goto error;
    }

    printf("SUCCESS\n");
    return EXIT_SUCCESS;
error:
    player.close();
    printf("exiting - AAudio result = %d = %s\n", result, AAudio_convertResultToText(result));
    return EXIT_FAILURE;
}

