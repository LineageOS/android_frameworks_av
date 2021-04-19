/*
 * Copyright (C) 2019 The Android Open Source Project
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
 * Test whether the callback is joined before the close finishes.
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

#include <gtest/gtest.h>

#include <aaudio/AAudio.h>

// Sleep long enough that the foreground has a change to call close.
static constexpr int kCallbackSleepMicros = 600 * 1000;

class AudioEngine {
public:

    // Check for a crash or late callback if we close without stopping.
    void checkCloseJoins(aaudio_direction_t direction,
                             aaudio_performance_mode_t perfMode,
                             aaudio_data_callback_result_t callbackResult) {

        // Make printf print immediately so that debug info is not stuck
        // in a buffer if we hang or crash.
        setvbuf(stdout, nullptr, _IONBF, (size_t) 0);

        mCallbackResult = callbackResult;
        startStreamForStall(direction, perfMode);
        // When the callback starts it will go to sleep.
        waitForCallbackToStart();

        printf("call AAudioStream_close()\n");
        ASSERT_FALSE(mCallbackFinished); // Still sleeping?
        aaudio_result_t result = AAudioStream_close(mStream); // May hang here!
        ASSERT_TRUE(mCallbackFinished);
        ASSERT_EQ(AAUDIO_OK, result);
        printf("AAudioStream_close() returned %d\n", result);

        ASSERT_EQ(AAUDIO_OK, mError.load());
        // Did calling stop() from callback fail? It should have.
        ASSERT_NE(AAUDIO_OK, mStopResult.load());
    }

private:
    void startStreamForStall(aaudio_direction_t direction,
                             aaudio_performance_mode_t perfMode) {
        AAudioStreamBuilder* builder = nullptr;
        aaudio_result_t result = AAUDIO_OK;

        // Use an AAudioStreamBuilder to contain requested parameters.
        result = AAudio_createStreamBuilder(&builder);
        ASSERT_EQ(AAUDIO_OK, result);

        // Request stream properties.
        AAudioStreamBuilder_setDirection(builder, direction);
        AAudioStreamBuilder_setPerformanceMode(builder, perfMode);
        AAudioStreamBuilder_setDataCallback(builder, s_myDataCallbackProc, this);
        AAudioStreamBuilder_setErrorCallback(builder, s_myErrorCallbackProc, this);

        // Create an AAudioStream using the Builder.
        result = AAudioStreamBuilder_openStream(builder, &mStream);
        AAudioStreamBuilder_delete(builder);
        ASSERT_EQ(AAUDIO_OK, result);

        // Check to see what kind of stream we actually got.
        int32_t deviceId = AAudioStream_getDeviceId(mStream);
        aaudio_performance_mode_t
            actualPerfMode = AAudioStream_getPerformanceMode(mStream);
        printf("-------- opened: deviceId = %3d, perfMode = %d\n",
               deviceId,
               actualPerfMode);

        // Start stream.
        result = AAudioStream_requestStart(mStream);
        ASSERT_EQ(AAUDIO_OK, result);
    }

    void waitForCallbackToStart() {
        // Wait for callback to say it has been called.
        int countDownMillis = 2000;
        constexpr int countDownPeriodMillis = 50;
        while (!mCallbackStarted && countDownMillis > 0) {
            printf("Waiting for callback to start, %d\n", countDownMillis);
            usleep(countDownPeriodMillis * 1000);
            countDownMillis -= countDownPeriodMillis;
        }
        ASSERT_LT(0, countDownMillis);
        ASSERT_TRUE(mCallbackStarted);
    }

// Callback function that fills the audio output buffer.
    static aaudio_data_callback_result_t s_myDataCallbackProc(
            AAudioStream *stream,
            void *userData,
            void * /*audioData */,
            int32_t /* numFrames */
    ) {
        AudioEngine* engine = (AudioEngine*) userData;
        engine->mCallbackStarted = true;
        usleep(kCallbackSleepMicros);
        // it is illegal to call stop() from the callback. It should
        // return an error and not hang.
        engine->mStopResult = AAudioStream_requestStop(stream);
        engine->mCallbackFinished = true;
        return engine->mCallbackResult;
    }

    static void s_myErrorCallbackProc(
                AAudioStream * /* stream */,
                void *userData,
                aaudio_result_t error) {
        AudioEngine *engine = (AudioEngine *)userData;
        engine->mError = error;
    }

    AAudioStream* mStream = nullptr;

    std::atomic<aaudio_result_t> mError{AAUDIO_OK}; // written by error callback
    std::atomic<bool> mCallbackStarted{false};   // written by data callback
    std::atomic<bool> mCallbackFinished{false};  // written by data callback
    std::atomic<aaudio_data_callback_result_t> mCallbackResult{AAUDIO_CALLBACK_RESULT_CONTINUE};
    std::atomic<aaudio_result_t> mStopResult{AAUDIO_OK};
};

/*********************************************************************/
// Tell the callback to return AAUDIO_CALLBACK_RESULT_CONTINUE.

TEST(test_close_timing, aaudio_close_joins_input_none) {
    AudioEngine engine;
    engine.checkCloseJoins(AAUDIO_DIRECTION_INPUT,
        AAUDIO_PERFORMANCE_MODE_NONE,
        AAUDIO_CALLBACK_RESULT_CONTINUE);
}

TEST(test_close_timing, aaudio_close_joins_output_none) {
    AudioEngine engine;
    engine.checkCloseJoins(AAUDIO_DIRECTION_OUTPUT,
        AAUDIO_PERFORMANCE_MODE_NONE,
        AAUDIO_CALLBACK_RESULT_CONTINUE);
}

TEST(test_close_timing, aaudio_close_joins_input_lowlat) {
    AudioEngine engine;
    engine.checkCloseJoins(AAUDIO_DIRECTION_INPUT,
        AAUDIO_PERFORMANCE_MODE_LOW_LATENCY,
        AAUDIO_CALLBACK_RESULT_CONTINUE);
}

TEST(test_close_timing, aaudio_close_joins_output_lowlat) {
    AudioEngine engine;
    engine.checkCloseJoins(AAUDIO_DIRECTION_OUTPUT,
        AAUDIO_PERFORMANCE_MODE_LOW_LATENCY,
        AAUDIO_CALLBACK_RESULT_CONTINUE);
}

/*********************************************************************/
// Tell the callback to return AAUDIO_CALLBACK_RESULT_STOP.

TEST(test_close_timing, aaudio_close_joins_input_lowlat_stop) {
    AudioEngine engine;
    engine.checkCloseJoins(AAUDIO_DIRECTION_INPUT,
        AAUDIO_PERFORMANCE_MODE_LOW_LATENCY,
        AAUDIO_CALLBACK_RESULT_STOP);
}

TEST(test_close_timing, aaudio_close_joins_output_lowlat_stop) {
    AudioEngine engine;
    engine.checkCloseJoins(AAUDIO_DIRECTION_OUTPUT,
        AAUDIO_PERFORMANCE_MODE_LOW_LATENCY,
        AAUDIO_CALLBACK_RESULT_STOP);
}

TEST(test_close_timing, aaudio_close_joins_output_none_stop) {
    AudioEngine engine;
    engine.checkCloseJoins(AAUDIO_DIRECTION_OUTPUT,
        AAUDIO_PERFORMANCE_MODE_NONE,
        AAUDIO_CALLBACK_RESULT_STOP);
}

TEST(test_close_timing, aaudio_close_joins_input_none_stop) {
    AudioEngine engine;
    engine.checkCloseJoins(AAUDIO_DIRECTION_INPUT,
        AAUDIO_PERFORMANCE_MODE_NONE,
        AAUDIO_CALLBACK_RESULT_STOP);
}
