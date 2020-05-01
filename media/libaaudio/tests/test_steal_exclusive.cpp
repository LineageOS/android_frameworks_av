/*
 * Copyright (C) 2020 The Android Open Source Project
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
 * This test starts an exclusive stream.
 * Then a few seconds later it starts a second exclusive stream.
 * The first stream should get stolen and they should both end up
 * as SHARED streams.
 * The test will print PASS or FAIL.
 *
 * If you plug in a headset during the test then you can get them to both
 * open at almost the same time. This can result in a race condition.
 * Both streams may try to automatically reopen their streams in EXCLUSIVE mode.
 * The first stream will have its EXCLUSIVE stream stolen by the second stream.
 * It will usually get disconnected between its Open and Start calls.
 * This can also occur in normal use. But is unlikely because the window is very narrow.
 * In this case, where two streams are responding to the same disconnect event,
 * it will usually happen.
 *
 * Because the stream has not started, this condition will not trigger an onError callback.
 * But the stream will get an error returned from AAudioStream_requestStart().
 * The test uses this result to trigger a retry in the onError callback.
 * That is the best practice for any app restarting a stream.
 *
 * You should see that both streams are advancing after the disconnect.
 *
 * The headset can connect using a 3.5 mm jack, or USB-C or Bluetooth.
 *
 * This test can be used with INPUT by using the -i command line option.
 * Before running the test you will need to enter "adb root" so that
 * you can have permission to record.
 * Also the headset needs to have a microphone.
 * Then the test should behave essentially the same.
 */

#include <atomic>
#include <stdio.h>
#include <thread>
#include <unistd.h>

#include <aaudio/AAudio.h>

#define DEFAULT_TIMEOUT_NANOS  ((int64_t)1000000000)
#define SOLO_DURATION_MSEC    2000
#define DUET_DURATION_MSEC    8000
#define SLEEP_DURATION_MSEC    500

static const char * s_sharingModeToText(aaudio_sharing_mode_t mode) {
    return (mode == AAUDIO_SHARING_MODE_EXCLUSIVE) ? "EXCLUSIVE"
        : ((mode == AAUDIO_SHARING_MODE_SHARED)  ? "SHARED"
            : AAudio_convertResultToText(mode));
}

static void s_myErrorCallbackProc(
        AAudioStream *stream,
        void *userData,
        aaudio_result_t error);

struct AudioEngine {
    AAudioStream        *stream = nullptr;
    std::thread         *thread = nullptr;
    aaudio_direction_t   direction = AAUDIO_DIRECTION_OUTPUT;

    // These counters are read and written by the callback and the main thread.
    std::atomic<int32_t> framesRead{};
    std::atomic<int32_t> framesCalled{};
    std::atomic<int32_t> callbackCount{};

    void reset() {
        framesRead.store(0);
        framesCalled.store(0);
        callbackCount.store(0);
    }
};

// Callback function that fills the audio output buffer.
static aaudio_data_callback_result_t s_myDataCallbackProc(
        AAudioStream *stream,
        void *userData,
        void *audioData,
        int32_t numFrames
) {
    (void) audioData;
    (void) numFrames;
    AudioEngine *engine = (struct AudioEngine *)userData;
    engine->callbackCount++;

    engine->framesRead = (int32_t)AAudioStream_getFramesRead(stream);
    engine->framesCalled += numFrames;
    return AAUDIO_CALLBACK_RESULT_CONTINUE;
}

static aaudio_result_t s_OpenAudioStream(struct AudioEngine *engine,
                                         aaudio_direction_t direction) {
    AAudioStreamBuilder *builder = nullptr;
    engine->direction = direction;

    // Use an AAudioStreamBuilder to contain requested parameters.
    aaudio_result_t result = AAudio_createStreamBuilder(&builder);
    if (result != AAUDIO_OK) {
        printf("AAudio_createStreamBuilder returned %s",
               AAudio_convertResultToText(result));
        return result;
    }

    // Request stream properties.
    AAudioStreamBuilder_setFormat(builder, AAUDIO_FORMAT_PCM_FLOAT);
    AAudioStreamBuilder_setPerformanceMode(builder, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
    AAudioStreamBuilder_setSharingMode(builder, AAUDIO_SHARING_MODE_EXCLUSIVE);
    AAudioStreamBuilder_setDirection(builder, direction);
    AAudioStreamBuilder_setDataCallback(builder, s_myDataCallbackProc, engine);
    AAudioStreamBuilder_setErrorCallback(builder, s_myErrorCallbackProc, engine);

    // Create an AAudioStream using the Builder.
    result = AAudioStreamBuilder_openStream(builder, &engine->stream);
    AAudioStreamBuilder_delete(builder);
    builder = nullptr;
    if (result != AAUDIO_OK) {
        printf("AAudioStreamBuilder_openStream returned %s",
               AAudio_convertResultToText(result));
    }

    // See see what kind of stream we actually opened.
    int32_t deviceId = AAudioStream_getDeviceId(engine->stream);
    aaudio_sharing_mode_t actualSharingMode = AAudioStream_getSharingMode(engine->stream);
    printf("-------- opened: deviceId = %3d, actualSharingMode = %s\n",
           deviceId,
           s_sharingModeToText(actualSharingMode));

    return result;
}

static aaudio_result_t s_CloseAudioStream(struct AudioEngine *engine) {
    aaudio_result_t result = AAUDIO_OK;
    if (engine->stream != nullptr) {
        result = AAudioStream_close(engine->stream);
        if (result != AAUDIO_OK) {
            printf("AAudioStream_close returned %s\n",
                   AAudio_convertResultToText(result));
        }
        engine->stream = nullptr;
    }
    return result;
}

static void s_myRestartStreamProc(void *userData) {
    printf("%s() - restart in separate thread\n", __func__);
    AudioEngine *engine = (AudioEngine *) userData;
    int retriesLeft = 1;
    aaudio_result_t result;
    do {
        s_CloseAudioStream(engine);
        s_OpenAudioStream(engine, engine->direction);
        // It is possible for the stream to be disconnected, or stolen between the time
        // it is opened and when it is started. If that happens then try again.
        // If it was stolen then it should succeed the second time because there will already be
        // a SHARED stream, which will not get stolen.
        result = AAudioStream_requestStart(engine->stream);
        printf("%s() - AAudioStream_requestStart() returns %s\n", __func__,
                AAudio_convertResultToText(result));
    } while (retriesLeft-- > 0 && result != AAUDIO_OK);
}

static void s_myErrorCallbackProc(
        AAudioStream * /* stream */,
        void *userData,
        aaudio_result_t error) {
    printf("%s() - error = %s\n", __func__, AAudio_convertResultToText(error));
    // Handle error on a separate thread.
    std::thread t(s_myRestartStreamProc, userData);
    t.detach();
}

static void s_usage() {
    printf("test_steal_exclusive [-i]\n");
    printf("     -i direction INPUT, otherwise OUTPUT\n");
}

/**
 * @return 0 is OK, -1 for error
 */
static int s_checkEnginePositions(AudioEngine *engine) {
    if (engine->stream == nullptr) return 0; // race condition with onError procs!

    const int64_t framesRead = AAudioStream_getFramesRead(engine->stream);
    const int64_t framesWritten = AAudioStream_getFramesWritten(engine->stream);
    const int32_t delta = (int32_t)(framesWritten - framesRead);
    printf("playing framesRead = %7d, framesWritten = %7d"
           ", delta = %4d, framesCalled = %6d, callbackCount = %4d\n",
           (int32_t) framesRead,
           (int32_t) framesWritten,
           delta,
           engine->framesCalled.load(),
           engine->callbackCount.load()
    );
    if (delta > AAudioStream_getBufferCapacityInFrames(engine->stream)) {
        printf("ERROR - delta > capacity\n");
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    (void) argc;
    (void) argv;
    struct AudioEngine victim;
    struct AudioEngine thief;
    aaudio_direction_t direction = AAUDIO_DIRECTION_OUTPUT;
    aaudio_result_t result = AAUDIO_OK;
    int errorCount = 0;

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, nullptr, _IONBF, (size_t) 0);

    printf("Test Stealing an EXCLUSIVE stream V1.0\n");
    printf("\n");

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (arg[0] == '-') {
            char option = arg[1];
            switch (option) {
                case 'i':
                    direction = AAUDIO_DIRECTION_INPUT;
                    break;
                default:
                    s_usage();
                    exit(EXIT_FAILURE);
                    break;
            }
        } else {
            s_usage();
            exit(EXIT_FAILURE);
            break;
        }
    }

    result = s_OpenAudioStream(&victim, direction);
    if (result != AAUDIO_OK) {
        printf("s_OpenAudioStream victim returned %s\n",
               AAudio_convertResultToText(result));
        errorCount++;
    }
    victim.reset();

    // Start stream.
    result = AAudioStream_requestStart(victim.stream);
    printf("AAudioStream_requestStart(VICTIM) returned %d >>>>>>>>>>>>>>>>>>>>>>\n", result);
    if (result != AAUDIO_OK) {
        errorCount++;
    }

    if (result == AAUDIO_OK) {
        const int watchLoops = SOLO_DURATION_MSEC / SLEEP_DURATION_MSEC;
        for (int i = watchLoops; i > 0; i--) {
            errorCount += s_checkEnginePositions(&victim) ? 1 : 0;
            usleep(SLEEP_DURATION_MSEC * 1000);
        }
    }

    printf("Try to start the THIEF stream that may steal the VICTIM MMAP resource -----\n");
    result = s_OpenAudioStream(&thief, direction);
    if (result != AAUDIO_OK) {
        printf("s_OpenAudioStream victim returned %s\n",
               AAudio_convertResultToText(result));
        errorCount++;
    }
    thief.reset();

    // Start stream.
    result = AAudioStream_requestStart(thief.stream);
    printf("AAudioStream_requestStart(THIEF) returned %d >>>>>>>>>>>>>>>>>>>>>>\n", result);
    if (result != AAUDIO_OK) {
        errorCount++;
    }
    printf("You might enjoy plugging in a headset now to see what happens...\n");

    if (result == AAUDIO_OK) {
        const int watchLoops = DUET_DURATION_MSEC / SLEEP_DURATION_MSEC;
        for (int i = watchLoops; i > 0; i--) {
            printf("victim: ");
            errorCount += s_checkEnginePositions(&victim) ? 1 : 0;
            printf(" thief: ");
            errorCount += s_checkEnginePositions(&thief) ? 1 : 0;
            usleep(SLEEP_DURATION_MSEC * 1000);
        }
    }

    // Check for PASS/FAIL
    aaudio_sharing_mode_t victimSharingMode = AAudioStream_getSharingMode(victim.stream);
    aaudio_sharing_mode_t thiefSharingMode = AAudioStream_getSharingMode(thief.stream);
    printf("victimSharingMode = %s, thiefSharingMode = %s, - ",
           s_sharingModeToText(victimSharingMode),
           s_sharingModeToText(thiefSharingMode));
    if ((victimSharingMode == AAUDIO_SHARING_MODE_SHARED)
            && (thiefSharingMode == AAUDIO_SHARING_MODE_SHARED)) {
        printf("Both modes are SHARED => PASS\n");
    } else {
        errorCount++;
        printf("Both modes should be SHARED => FAIL!!\n");
    }

    const int64_t victimFramesRead = AAudioStream_getFramesRead(victim.stream);
    const int64_t thiefFramesRead = AAudioStream_getFramesRead(thief.stream);
    printf("victimFramesRead = %d, thiefFramesRead = %d, - ",
           (int)victimFramesRead, (int)thiefFramesRead);
    if (victimFramesRead > 0 && thiefFramesRead > 0) {
        printf("Both streams are running => PASS\n");
    } else {
        errorCount++;
        printf("Both streams should be running => FAIL!!\n");
    }

    result = AAudioStream_requestStop(victim.stream);
    printf("AAudioStream_requestStop() returned %d <<<<<<<<<<<<<<<<<<<<<\n", result);
    if (result != AAUDIO_OK) {
        errorCount++;
    }
    result = AAudioStream_requestStop(thief.stream);
    printf("AAudioStream_requestStop() returned %d <<<<<<<<<<<<<<<<<<<<<\n", result);
    if (result != AAUDIO_OK) {
        errorCount++;
    }

    s_CloseAudioStream(&victim);
    s_CloseAudioStream(&thief);

    printf("aaudio result = %d = %s\n", result, AAudio_convertResultToText(result));
    printf("test %s\n", errorCount ? "FAILED" : "PASSED");

    return errorCount ? EXIT_FAILURE : EXIT_SUCCESS;
}
