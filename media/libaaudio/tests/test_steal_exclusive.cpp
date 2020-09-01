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
#include <mutex>
#include <stdio.h>
#include <thread>
#include <unistd.h>

#include <android/log.h>

#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>

#define DEFAULT_TIMEOUT_NANOS  ((int64_t)1000000000)
#define SOLO_DURATION_MSEC    2000
#define DUET_DURATION_MSEC    8000
#define SLEEP_DURATION_MSEC    500

#define MODULE_NAME  "stealAudio"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, MODULE_NAME, __VA_ARGS__)

static const char * s_sharingModeToText(aaudio_sharing_mode_t mode) {
    return (mode == AAUDIO_SHARING_MODE_EXCLUSIVE) ? "EXCLUSIVE"
        : ((mode == AAUDIO_SHARING_MODE_SHARED)  ? "SHARED"
            : AAudio_convertResultToText(mode));
}

static const char * s_performanceModeToText(aaudio_performance_mode_t mode) {
    return (mode == AAUDIO_PERFORMANCE_MODE_LOW_LATENCY) ? "LOWLAT"
        : ((mode == AAUDIO_PERFORMANCE_MODE_NONE)  ? "NONE"
            : AAudio_convertResultToText(mode));
}

static aaudio_data_callback_result_t s_myDataCallbackProc(
        AAudioStream * /* stream */,
        void *userData,
        void *audioData,
        int32_t numFrames);

static void s_myErrorCallbackProc(
        AAudioStream *stream,
        void *userData,
        aaudio_result_t error);

class AudioEngine {
public:

    AudioEngine(const char *name) {
        mName = name;
    }

    // These counters are read and written by the callback and the main thread.
    std::atomic<int32_t> framesCalled{};
    std::atomic<int32_t> callbackCount{};
    std::atomic<aaudio_sharing_mode_t> sharingMode{};
    std::atomic<aaudio_performance_mode_t> performanceMode{};
    std::atomic<bool> isMMap{false};

    void setMaxRetries(int maxRetries) {
        mMaxRetries = maxRetries;
    }

    void setOpenDelayMillis(int openDelayMillis) {
        mOpenDelayMillis = openDelayMillis;
    }

    void restartStream() {
        int retriesLeft = mMaxRetries;
        aaudio_result_t result;
        do {
            closeAudioStream();
            if (mOpenDelayMillis) usleep(mOpenDelayMillis * 1000);
            openAudioStream(mDirection, mRequestedSharingMode);
            // It is possible for the stream to be disconnected, or stolen between the time
            // it is opened and when it is started. If that happens then try again.
            // If it was stolen then it should succeed the second time because there will already be
            // a SHARED stream, which will not get stolen.
            result = AAudioStream_requestStart(mStream);
            printf("%s: AAudioStream_requestStart() returns %s\n",
                    mName.c_str(),
                    AAudio_convertResultToText(result));
        } while (retriesLeft-- > 0 && result != AAUDIO_OK);
    }

    aaudio_data_callback_result_t onAudioReady(
            void * /*audioData */,
            int32_t numFrames) {
        callbackCount++;
        framesCalled += numFrames;
        return AAUDIO_CALLBACK_RESULT_CONTINUE;
    }

    aaudio_result_t openAudioStream(aaudio_direction_t direction,
            aaudio_sharing_mode_t requestedSharingMode) {
        std::lock_guard<std::mutex> lock(mLock);

        AAudioStreamBuilder *builder = nullptr;
        mDirection = direction;
        mRequestedSharingMode = requestedSharingMode;

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
        AAudioStreamBuilder_setSharingMode(builder, mRequestedSharingMode);
        AAudioStreamBuilder_setDirection(builder, direction);
        AAudioStreamBuilder_setDataCallback(builder, s_myDataCallbackProc, this);
        AAudioStreamBuilder_setErrorCallback(builder, s_myErrorCallbackProc, this);

        // Create an AAudioStream using the Builder.
        result = AAudioStreamBuilder_openStream(builder, &mStream);
        AAudioStreamBuilder_delete(builder);
        builder = nullptr;
        if (result != AAUDIO_OK) {
            printf("AAudioStreamBuilder_openStream returned %s",
                   AAudio_convertResultToText(result));
        }

        // See what kind of stream we actually opened.
        int32_t deviceId = AAudioStream_getDeviceId(mStream);
        sharingMode = AAudioStream_getSharingMode(mStream);
        performanceMode = AAudioStream_getPerformanceMode(mStream);
        isMMap = AAudioStream_isMMapUsed(mStream);
        printf("%s: opened: deviceId = %3d, sharingMode = %s, perf = %s, %s --------\n",
               mName.c_str(),
               deviceId,
               s_sharingModeToText(sharingMode),
               s_performanceModeToText(performanceMode),
               (isMMap ? "MMAP" : "Legacy")
               );

        return result;
    }

    aaudio_result_t closeAudioStream() {
        std::lock_guard<std::mutex> lock(mLock);
        aaudio_result_t result = AAUDIO_OK;
        if (mStream != nullptr) {
            result = AAudioStream_close(mStream);
            if (result != AAUDIO_OK) {
                printf("AAudioStream_close returned %s\n",
                       AAudio_convertResultToText(result));
            }
            mStream = nullptr;
        }
        return result;
    }

    /**
     * @return 0 is OK, -1 for error
     */
    int checkEnginePositions() {
        std::lock_guard<std::mutex> lock(mLock);
        if (mStream == nullptr) return 0;

        const int64_t framesRead = AAudioStream_getFramesRead(mStream);
        const int64_t framesWritten = AAudioStream_getFramesWritten(mStream);
        const int32_t delta = (int32_t)(framesWritten - framesRead);
        printf("%s: playing framesRead = %7d, framesWritten = %7d"
               ", delta = %4d, framesCalled = %6d, callbackCount = %4d\n",
               mName.c_str(),
               (int32_t) framesRead,
               (int32_t) framesWritten,
               delta,
               framesCalled.load(),
               callbackCount.load()
        );
        if (delta > AAudioStream_getBufferCapacityInFrames(mStream)) {
            printf("ERROR - delta > capacity\n");
            return -1;
        }
        return 0;
    }

    aaudio_result_t start() {
        std::lock_guard<std::mutex> lock(mLock);
        reset();
        if (mStream == nullptr) return 0;
        return AAudioStream_requestStart(mStream);
    }

    aaudio_result_t stop() {
        std::lock_guard<std::mutex> lock(mLock);
        if (mStream == nullptr) return 0;
        return AAudioStream_requestStop(mStream);
    }

    bool hasAdvanced() {
        std::lock_guard<std::mutex> lock(mLock);
        if (mStream == nullptr) return 0;
        if (mDirection == AAUDIO_DIRECTION_OUTPUT) {
            return AAudioStream_getFramesRead(mStream) > 0;
        } else {
            return AAudioStream_getFramesWritten(mStream) > 0;
        }
    }

    aaudio_result_t verify() {
        int errorCount = 0;
        if (hasAdvanced()) {
            printf("%s: stream is running => PASS\n", mName.c_str());
        } else {
            errorCount++;
            printf("%s: stream should be running => FAIL!!\n", mName.c_str());
        }

        if (isMMap) {
            printf("%s: data path is MMAP => PASS\n", mName.c_str());
        } else {
            errorCount++;
            printf("%s: data path is Legacy! => FAIL\n", mName.c_str());
        }

        // Check for PASS/FAIL
        if (sharingMode == AAUDIO_SHARING_MODE_SHARED) {
            printf("%s: mode is SHARED => PASS\n", mName.c_str());
        } else {
            errorCount++;
            printf("%s: modes is EXCLUSIVE => FAIL!!\n", mName.c_str());
        }
        return errorCount ? AAUDIO_ERROR_INVALID_FORMAT : AAUDIO_OK;
    }

private:
    void reset() {
        framesCalled.store(0);
        callbackCount.store(0);
    }

    AAudioStream       *mStream = nullptr;
    aaudio_direction_t  mDirection = AAUDIO_DIRECTION_OUTPUT;
    aaudio_sharing_mode_t mRequestedSharingMode = AAUDIO_UNSPECIFIED;
    std::mutex          mLock;
    std::string         mName;
    int                 mMaxRetries = 1;
    int                 mOpenDelayMillis = 0;
};

// Callback function that fills the audio output buffer.
static aaudio_data_callback_result_t s_myDataCallbackProc(
        AAudioStream * /* stream */,
        void *userData,
        void *audioData,
        int32_t numFrames
) {
    AudioEngine *engine = (AudioEngine *)userData;
    return engine->onAudioReady(audioData, numFrames);
}

static void s_myRestartStreamProc(void *userData) {
    LOGI("%s() called", __func__);
    printf("%s() - restart in separate thread\n", __func__);
    AudioEngine *engine = (AudioEngine *) userData;
    engine->restartStream();
}

static void s_myErrorCallbackProc(
        AAudioStream * /* stream */,
        void *userData,
        aaudio_result_t error) {
    LOGI("%s() called", __func__);
    printf("%s() - error = %s\n", __func__, AAudio_convertResultToText(error));
    // Handle error on a separate thread.
    std::thread t(s_myRestartStreamProc, userData);
    t.detach();
}

static void s_usage() {
    printf("test_steal_exclusive [-i] [-r{maxRetries}] [-d{delay}] -s\n");
    printf("     -i direction INPUT, otherwise OUTPUT\n");
    printf("     -d delay open by milliseconds, default = 0\n");
    printf("     -r max retries in the error callback, default = 1\n");
    printf("     -s try to open in SHARED mode\n");
}

int main(int argc, char ** argv) {
    AudioEngine victim("victim");
    AudioEngine thief("thief");
    aaudio_direction_t direction = AAUDIO_DIRECTION_OUTPUT;
    aaudio_result_t result = AAUDIO_OK;
    int errorCount = 0;
    int maxRetries = 1;
    int openDelayMillis = 0;
    aaudio_sharing_mode_t requestedSharingMode = AAUDIO_SHARING_MODE_EXCLUSIVE;

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, nullptr, _IONBF, (size_t) 0);

    printf("Test interaction between streams V1.1\n");
    printf("\n");

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (arg[0] == '-') {
            char option = arg[1];
            switch (option) {
                case 'd':
                    openDelayMillis = atoi(&arg[2]);
                    break;
                case 'i':
                    direction = AAUDIO_DIRECTION_INPUT;
                    break;
                case 'r':
                    maxRetries = atoi(&arg[2]);
                    break;
                case 's':
                    requestedSharingMode = AAUDIO_SHARING_MODE_SHARED;
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

    victim.setOpenDelayMillis(openDelayMillis);
    thief.setOpenDelayMillis(openDelayMillis);
    victim.setMaxRetries(maxRetries);
    thief.setMaxRetries(maxRetries);

    result = victim.openAudioStream(direction, requestedSharingMode);
    if (result != AAUDIO_OK) {
        printf("s_OpenAudioStream victim returned %s\n",
               AAudio_convertResultToText(result));
        errorCount++;
    }

    if (victim.sharingMode == requestedSharingMode) {
        printf("Victim modes is %s => OK\n", s_sharingModeToText(requestedSharingMode));
    } else {
        printf("Victim modes should be %s => test not valid!\n",
                s_sharingModeToText(requestedSharingMode));
        goto onerror;
    }

    if (victim.isMMap) {
        printf("Victim data path is MMAP => OK\n");
    } else {
        printf("Victim data path is Legacy! => test not valid\n");
        goto onerror;
    }

    // Start stream.
    result = victim.start();
    printf("AAudioStream_requestStart(VICTIM) returned %d >>>>>>>>>>>>>>>>>>>>>>\n", result);
    if (result != AAUDIO_OK) {
        errorCount++;
    }

    if (result == AAUDIO_OK) {
        const int watchLoops = SOLO_DURATION_MSEC / SLEEP_DURATION_MSEC;
        for (int i = watchLoops; i > 0; i--) {
            errorCount += victim.checkEnginePositions() ? 1 : 0;
            usleep(SLEEP_DURATION_MSEC * 1000);
        }
    }

    printf("Trying to start the THIEF stream, which may steal the VICTIM MMAP resource -----\n");
    result = thief.openAudioStream(direction, requestedSharingMode);
    if (result != AAUDIO_OK) {
        printf("s_OpenAudioStream victim returned %s\n",
               AAudio_convertResultToText(result));
        errorCount++;
    }

    // Start stream.
    result = thief.start();
    printf("AAudioStream_requestStart(THIEF) returned %d >>>>>>>>>>>>>>>>>>>>>>\n", result);
    if (result != AAUDIO_OK) {
        errorCount++;
    }

    // Give stream time to advance.
    usleep(SLEEP_DURATION_MSEC * 1000);

    if (victim.verify()) {
        errorCount++;
        goto onerror;
    }
    if (thief.verify()) {
        errorCount++;
        goto onerror;
    }

    LOGI("Both streams running. Ask user to plug in headset. ====");
    printf("\n====\nPlease PLUG IN A HEADSET now!\n====\n\n");

    if (result == AAUDIO_OK) {
        const int watchLoops = DUET_DURATION_MSEC / SLEEP_DURATION_MSEC;
        for (int i = watchLoops; i > 0; i--) {
            errorCount += victim.checkEnginePositions() ? 1 : 0;
            errorCount += thief.checkEnginePositions() ? 1 : 0;
            usleep(SLEEP_DURATION_MSEC * 1000);
        }
    }

    errorCount += victim.verify() ? 1 : 0;
    errorCount += thief.verify() ? 1 : 0;

    result = victim.stop();
    printf("AAudioStream_requestStop() returned %d <<<<<<<<<<<<<<<<<<<<<\n", result);
    if (result != AAUDIO_OK) {
        printf("stop result = %d = %s\n", result, AAudio_convertResultToText(result));
        errorCount++;
    }
    result = thief.stop();
    printf("AAudioStream_requestStop() returned %d <<<<<<<<<<<<<<<<<<<<<\n", result);
    if (result != AAUDIO_OK) {
        printf("stop result = %d = %s\n", result, AAudio_convertResultToText(result));
        errorCount++;
    }

onerror:
    victim.closeAudioStream();
    thief.closeAudioStream();

    printf("aaudio result = %d = %s\n", result, AAudio_convertResultToText(result));
    printf("test %s\n", errorCount ? "FAILED" : "PASSED");

    return errorCount ? EXIT_FAILURE : EXIT_SUCCESS;
}
