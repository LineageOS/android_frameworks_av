/*
 * Copyright (C) 2026 The Android Open Source Project
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
package com.android.test.playbackpower;

import android.os.SystemClock;
import android.util.Log;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Logs and saves test results for power tests.
 *
 * <p>All public methods must be called on the main thread.
 */
/* package */ final class TestResultLogger {

    private static final int UNSET = -1;

    private final String mLogTag;
    private final ExecutorService mBackgroundExecutor;
    private final File mResultFile;
    private final JSONObject mResult;

    private long mInitialChargeCounterTimeMs = UNSET;
    private long mInitialChargeCounter = UNSET;
    private long mChargeCounterTimeMs = UNSET;
    private long mChargeCounter = UNSET;
    private int mBatteryScale = UNSET;

    public TestResultLogger(String logTag, File resultFile) {
        mLogTag = logTag;
        mResultFile = resultFile;
        mBackgroundExecutor = Executors.newSingleThreadExecutor();
        mResult = new JSONObject();
    }

    public void logStarted() {
        logEvent("started");
    }

    public void logChargeCounter(long timeMs, long chargeCounter) {
        if (mInitialChargeCounter == UNSET) {
            mInitialChargeCounterTimeMs = timeMs;
            mInitialChargeCounter = chargeCounter;
            logEvent(timeMs, "charge_counter_start", chargeCounter);
        }
        mChargeCounterTimeMs = timeMs;
        mChargeCounter = chargeCounter;
        logEvent(timeMs, "charge_counter", chargeCounter);
    }

    public void logBatteryLevel(long timeMs, int level, int scale) {
        logEvent(timeMs, "battery_level", level);
        if (scale != mBatteryScale) {
            // This shouldn't change during the test, but log at least once at the start.
            mBatteryScale = scale;
            logEvent(timeMs, "battery_scale", scale);
        }
    }

    public void logSuccess(String message) {
        Log.i(mLogTag, "Succeeded " + message);
        if (mInitialChargeCounter != UNSET) {
            logEvent(mChargeCounterTimeMs, "charge_counter_end", mChargeCounter);
            long elapsedTimeSec = (mChargeCounterTimeMs - mInitialChargeCounterTimeMs) / 1000L;
            long chargeCounterDifference = mInitialChargeCounter - mChargeCounter;
            logEvent(
                    mChargeCounterTimeMs,
                    "charge_counter_summary",
                    String.format(
                            "-%d uAh in %dm%ds",
                            chargeCounterDifference,
                            elapsedTimeSec / 60,
                            elapsedTimeSec % 60));
        }
        logEvent("success_summary", message);
        logFinalStatusAndWriteResultAsync("success");
    }

    public void logFailure(String errorMessage) {
        Log.e(mLogTag, "Failed: " + errorMessage);
        logEvent(SystemClock.elapsedRealtime(), "error", errorMessage);
        logFinalStatusAndWriteResultAsync("failure");
    }

    private void logEvent(String name) {
        // SystemClock.elapsedRealtime is guaranteed to be monotonic and ticks during sleep.
        logEvent("event", name);
    }

    private void logEvent(String key, Object value) {
        logEvent(SystemClock.elapsedRealtime(), key, value);
    }

    private void logEvent(long timeMs, String key, Object value) {
        Log.i(mLogTag, String.format("Event at %.2f s: %s = %s", timeMs / 1000.0, key, value));
        try {
            JSONObject event = new JSONObject();
            event.put("timestamp_ms", timeMs);
            event.put(key, value);
            mResult.append("events", event);
        } catch (JSONException e) {
            Log.e(mLogTag, "Failed to log event: " + key, e);
        }
    }

    private void logFinalStatusAndWriteResultAsync(String status) {
        try {
            mResult.put("status", status);
        } catch (JSONException e) {
            Log.e(mLogTag, "Failed to set status to " + status, e);
        }
        String resultString;
        try {
            resultString = mResult.toString(2);
        } catch (JSONException e) {
            Log.e(mLogTag, "Failed to serialize results", e);
            return;
        }

        // Write the result to a file on a background thread to avoid blocking the main thread.
        mBackgroundExecutor.execute(() -> {
            try (FileWriter writer = new FileWriter(mResultFile)) {
                writer.write(resultString);
                Log.i(mLogTag, "Wrote results to " + mResultFile.getAbsolutePath());
            } catch (IOException e) {
                Log.e(mLogTag, "Failed to write result file", e);
            }
        });
    }

}
