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
 * Logs and saves test results for playback power tests.
 *
 * <p>All public methods must be called on the main thread.
 */
/* package */ final class TestResultLogger {

    private static final String TAG = "PlaybackPower";

    private final ExecutorService mBackgroundExecutor;
    private final File mResultFile;
    private final JSONObject mResult;

    private long mInitialChargeCounter;
    private long mChargeCounter;

    public TestResultLogger(File resultFile) {
        mResultFile = resultFile;
        mBackgroundExecutor = Executors.newSingleThreadExecutor();
        mResult = new JSONObject();
        mInitialChargeCounter = -1;
    }

    public void logPlaybackStarted() {
        logEvent("playback_started");
    }

    public void logChargeCounter(long chargeCounter) {
        if (mInitialChargeCounter == -1) {
            mInitialChargeCounter = chargeCounter;
        }
        mChargeCounter = chargeCounter;
        logEvent("charge_counter", chargeCounter);
    }

    public void logSuccess() {
        Log.i(TAG, "Succeeded");
        logEvent("charge_counter_start", mInitialChargeCounter);
        logEvent("charge_counter_end", mChargeCounter);
        logFinalStatusAndWriteResultAsync("success");
    }

    public void logFailure(String errorMessage) {
        Log.e(TAG, "Failed: " + errorMessage);
        logEvent("error", errorMessage);
        logFinalStatusAndWriteResultAsync("failure");
    }

    private void logEvent(String name) {
        logEvent("event", name);
    }

    private void logEvent(String key, Object value) {
        long timeMs = SystemClock.elapsedRealtime();
        Log.i(TAG, String.format("Event at %.2f s: %s = %s", timeMs / 1000.0, key, value));
        try {
            JSONObject event = new JSONObject();
            event.put("timestamp_ms", timeMs);
            event.put(key, value);
            mResult.accumulate("events", event);
        } catch (JSONException e) {
            Log.e(TAG, "Failed to log event: " + key, e);
        }
    }

    private void logFinalStatusAndWriteResultAsync(String status) {
        try {
            mResult.put("status", status);
        } catch (JSONException e) {
            Log.e(TAG, "Failed to set status to " + status, e);
        }
        String resultString;
        try {
            resultString = mResult.toString(2);
        } catch (JSONException e) {
            Log.e(TAG, "Failed to serialize results", e);
            return;
        }

        // Write the result to a file on a background thread to avoid blocking the main thread.
        mBackgroundExecutor.execute(() -> {
            try (FileWriter writer = new FileWriter(mResultFile)) {
                writer.write(resultString);
                Log.i(TAG, "Wrote results to " + mResultFile.getAbsolutePath());
            } catch (IOException e) {
                Log.e(TAG, "Failed to write result file", e);
            }
        });
    }

}
