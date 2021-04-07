/*
 * Copyright (C) 2021 The Android Open Source Project
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
 * Test whether an error callback is joined before the close finishes.
 *
 * Start a stream with a callback.
 * The callback just sleeps for a long time.
 * While the callback is sleeping, close() the stream from the main thread.
 * Then check to make sure the callback was joined before the close() returns.
 *
 * This can hang if there are deadlocks. So make sure you get a PASSED result.
 */

#include <atomic>
#include <stdio.h>
#include <unistd.h>

#include <aaudio/AAudio.h>

// Sleep long enough that the foreground has a chance to call close.
static constexpr int kCallbackSleepMillis = 1000;
static constexpr int kPollSleepMillis     =  100;

static int sErrorCount = 0;

#define MY_ASSERT_TRUE(statement) \
    if (!(statement)) { \
        printf("ERROR line:%d - " #statement "\n", __LINE__); \
        sErrorCount++; \
        return false; \
    }

#define MY_ASSERT_EQ(aa,bb) MY_ASSERT_TRUE(((aa) == (bb)))
#define MY_ASSERT_NE(aa,bb) MY_ASSERT_TRUE(((aa) != (bb)))

class AudioEngine {
public:

    // Check for a crash or late callback if we close without stopping.
    bool checkCloseJoins(aaudio_direction_t direction,
                             aaudio_performance_mode_t perfMode,
                             bool callStopFromCallback) {
        mCallStopFromCallback = callStopFromCallback;

        if (!startStreamForStall(direction, perfMode)) return false;

        printf("--------------------------------------------------------\n");
        printf("%s() - direction = %d, perfMode = %d, callStop = %d\n",
            __func__, direction, perfMode, callStopFromCallback);

        // When the callback starts it will go to sleep.
        if (!waitForCallbackToStart()) return false;

        printf("call AAudioStream_close()\n");
        MY_ASSERT_TRUE(!mCallbackFinished); // Still sleeping?
        aaudio_result_t result = AAudioStream_close(mStream); // May hang here!
        if (mCallbackStarted) {
            MY_ASSERT_TRUE(mCallbackFinished);
        }
        MY_ASSERT_EQ(AAUDIO_OK, result);
        printf("AAudioStream_close() returned %d\n", result);

        MY_ASSERT_EQ(AAUDIO_ERROR_DISCONNECTED, mError.load());
        if (mCallStopFromCallback) {
            // Did calling stop() from callback fail? It should have.
            MY_ASSERT_NE(AAUDIO_OK, mStopResult.load());
        }

        return true;
    }

private:
    bool startStreamForStall(aaudio_direction_t direction,
                             aaudio_performance_mode_t perfMode) {
        AAudioStreamBuilder* builder = nullptr;
        aaudio_result_t result = AAUDIO_OK;

        // Use an AAudioStreamBuilder to contain requested parameters.
        result = AAudio_createStreamBuilder(&builder);
        MY_ASSERT_EQ(AAUDIO_OK, result);

        // Request stream properties.
        AAudioStreamBuilder_setDirection(builder, direction);
        AAudioStreamBuilder_setPerformanceMode(builder, perfMode);
        AAudioStreamBuilder_setDataCallback(builder, s_myDataCallbackProc, this);
        AAudioStreamBuilder_setErrorCallback(builder, s_myErrorCallbackProc, this);

        // Create an AAudioStream using the Builder.
        result = AAudioStreamBuilder_openStream(builder, &mStream);
        AAudioStreamBuilder_delete(builder);
        MY_ASSERT_EQ(AAUDIO_OK, result);

        // Check to see what kind of stream we actually got.
        int32_t deviceId = AAudioStream_getDeviceId(mStream);
        aaudio_performance_mode_t
            actualPerfMode = AAudioStream_getPerformanceMode(mStream);
        printf("-------- opened: deviceId = %3d, perfMode = %d\n",
               deviceId,
               actualPerfMode);

        // Start stream.
        result = AAudioStream_requestStart(mStream);
        MY_ASSERT_EQ(AAUDIO_OK, result);

        return true;
    }

    bool waitForCallbackToStart() {
        // Wait for callback to say it has been called.
        int countDown = 10 * 1000 / kPollSleepMillis;
        while (!mCallbackStarted && countDown > 0) {
            if ((countDown % 5) == 0) {
                printf("===== Please PLUG or UNPLUG headphones! ======= %d\n", countDown);
            }
            usleep(kPollSleepMillis * 1000);
            countDown--;
        }
        MY_ASSERT_TRUE(countDown > 0);
        MY_ASSERT_TRUE(mCallbackStarted);
        return true;
    }

// Callback function that fills the audio output buffer.
    static aaudio_data_callback_result_t s_myDataCallbackProc(
            AAudioStream * /* stream */,
            void * /* userData */,
            void * /* audioData */,
            int32_t /* numFrames */
    ) {
        return AAUDIO_CALLBACK_RESULT_CONTINUE;
    }

    static void s_myErrorCallbackProc(
                AAudioStream * stream,
                void *userData,
                aaudio_result_t error) {
        AudioEngine *engine = (AudioEngine *)userData;
        engine->mError = error;
        engine->mCallbackStarted = true;
        usleep(kCallbackSleepMillis * 1000);
        // it is illegal to call stop() from the callback. It should
        // return an error and not hang.
        if (engine->mCallStopFromCallback) {
            engine->mStopResult = AAudioStream_requestStop(stream);
        }
        engine->mCallbackFinished = true;
    }

    AAudioStream* mStream = nullptr;

    std::atomic<aaudio_result_t> mError{AAUDIO_OK}; // written by error callback
    std::atomic<bool> mCallStopFromCallback{false};
    std::atomic<bool> mCallbackStarted{false};   // written by error callback
    std::atomic<bool> mCallbackFinished{false};  // written by error callback
    std::atomic<aaudio_result_t> mStopResult{AAUDIO_OK};
};

int main(int, char **) {
    // Parameters to test.
    static aaudio_direction_t directions[] = {AAUDIO_DIRECTION_OUTPUT,
                                            AAUDIO_DIRECTION_INPUT};
    static aaudio_performance_mode_t perfModes[] =
        {AAUDIO_PERFORMANCE_MODE_LOW_LATENCY, AAUDIO_PERFORMANCE_MODE_NONE};
    static bool callStops[] = { false, true };

    // Make printf print immediately so that debug info is not stuck
    // in a buffer if we hang or crash.
    setvbuf(stdout, nullptr, _IONBF, (size_t) 0);

    printf("Test Disconnect Race V1.0\n");
    printf("\n");

    for (auto callStop : callStops) {
        for (auto direction : directions) {
            for (auto perfMode : perfModes) {
                AudioEngine engine;
                engine.checkCloseJoins(direction, perfMode, callStop);
            }
        }
    }

    printf("Error Count = %d, %s\n", sErrorCount,
           ((sErrorCount == 0) ? "PASS" : "FAIL"));
}
