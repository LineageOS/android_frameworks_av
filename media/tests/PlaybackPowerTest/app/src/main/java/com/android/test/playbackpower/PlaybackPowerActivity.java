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

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.Uri;
import android.os.BatteryManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.os.SystemClock;
import android.widget.Toast;
import androidx.annotation.Nullable;
import androidx.core.view.WindowCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.core.view.WindowInsetsControllerCompat;
import androidx.media3.common.AudioAttributes;
import androidx.media3.common.MediaItem;
import androidx.media3.common.PlaybackException;
import androidx.media3.common.Player;
import androidx.media3.common.TrackSelectionParameters;
import androidx.media3.common.util.Util;
import androidx.media3.exoplayer.analytics.PlaybackStats;
import androidx.media3.exoplayer.analytics.PlaybackStatsListener;
import androidx.media3.exoplayer.ExoPlayer;
import androidx.media3.exoplayer.util.EventLogger;
import androidx.media3.ui.PlayerView;
import java.io.File;
import java.util.UUID;

/** Activity with a video player that can be used to measure playback power. */
public final class PlaybackPowerActivity extends Activity {

    private static final String TAG = "PlaybackPowerApp";

    /** Default duration to play the video for, in seconds. */
    private static final int DEFAULT_DURATION_SEC = 50;
    /** Interval between sampling the coulomb counter, in seconds. */
    private static final int BATTERY_SAMPLE_INTERVAL_SEC = 10;
    /** Default name for the log file in the cache directory. */
    private static final String DEFAULT_LOG_FILE_NAME = "playback_power_log.json";

    private static final String EXTRA_DRM_SCHEME = "drm_scheme";
    private static final String EXTRA_DRM_LICENSE_URI = "drm_license_uri";
    private static final String EXTRA_DURATION_SEC = "duration_sec";
    private static final String EXTRA_LOG_FILE_NAME = "log_file_name";

    private Handler mHandler;

    private ExoPlayer mPlayer;
    private PlayerView mPlayerView;
    private PlaybackStatsListener mPlaybackStatsListener;

    private BatteryManager mBatteryManager;
    private PowerManager mPowerManager;
    private IntentFilter mBatteryChangedIntentFilter;

    private boolean mIsTestPlaybackRunning;
    private boolean mIsFinished;
    private BroadcastReceiver mPowerReceiver;
    private Runnable mSampleBatteryRunnable;
    private TestResultLogger mTestResultLogger;
    private boolean mLoggedBatteryCycleCount;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_playback_power);
        mPlayerView = findViewById(R.id.player_view);
        mHandler = new Handler(Looper.getMainLooper());

        @Nullable String fileName = getIntent().getStringExtra(EXTRA_LOG_FILE_NAME);
        if (fileName == null) {
            fileName = DEFAULT_LOG_FILE_NAME;
        }
        mTestResultLogger = new TestResultLogger(
                /* logTag= */ TAG, new File(getExternalFilesDir(/* type= */ null), fileName));
        mLoggedBatteryCycleCount = false;
        mBatteryManager = getSystemService(BatteryManager.class);
        mPowerManager = getSystemService(PowerManager.class);
        mBatteryChangedIntentFilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);

        // Hide system bars so the playback is full-screen.
        WindowInsetsControllerCompat windowInsetsControllerCompat =
            WindowCompat.getInsetsController(getWindow(), getWindow().getDecorView());
        windowInsetsControllerCompat.setSystemBarsBehavior(
            WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        );
        windowInsetsControllerCompat.hide(WindowInsetsCompat.Type.systemBars());
    }

    @Override
    public void onResume() {
        super.onResume();
        if (mIsFinished) {
            // The app returned to the foreground after previously ending, so do nothing.
            return;
        }
        mPlayerView.onResume();
        preparePlayer();
        startPowerConnectionMonitoring();
    }

    @Override
    public void onPause() {
        super.onPause();
        mPlayerView.onPause();
        if (mIsTestPlaybackRunning) {
            handleFailure("Test playback was interrupted");
        } else if (!mIsFinished) {
            handleFailure("Stopped without running test playback");
        } else {
            releasePlayer();
            stopPowerConnectionMonitoring();
        }
    }

    private void preparePlayer() {
        Intent intent = getIntent();
        Uri uri = intent.getData();
        if (uri == null) {
            handleFailure("No URI provided in intent data");
            return;
        }

        MediaItem.Builder mediaItemBuilder = new MediaItem.Builder().setUri(uri);
        @Nullable String drmSchemeExtra = intent.getStringExtra(EXTRA_DRM_SCHEME);
        if (drmSchemeExtra != null) {
            @Nullable UUID drmUuid = Util.getDrmUuid(drmSchemeExtra);
            mediaItemBuilder.setDrmConfiguration(
                    new MediaItem.DrmConfiguration.Builder(drmUuid)
                            .setLicenseUri(intent.getStringExtra(EXTRA_DRM_LICENSE_URI))
                            .build());
        }
        mPlayer = new ExoPlayer.Builder(/* context= */ this).build();
        mPlayerView.setPlayer(mPlayer);
        mPlayer.addListener(new Player.Listener() {
            @Override
            public void onPlayerError(PlaybackException error) {
                handleFailure("Player error: " + error.toBundle().toString());
            }
        });
        // Keep playback stats for one playback, requested on-demand at the end of the test.
        mPlaybackStatsListener =
                new PlaybackStatsListener(/* keepHistory= */ false, /* callback= */ null);
        mPlayer.addAnalyticsListener(new EventLogger());
        mPlayer.addAnalyticsListener(mPlaybackStatsListener);
        mPlayer.setAudioAttributes(AudioAttributes.DEFAULT, /* handleAudioFocus= */ true);
        mPlayer.setMediaItem(mediaItemBuilder.build());
        mPlayer.setRepeatMode(Player.REPEAT_MODE_ONE);
        // Disable bitrate adaptation and force below 1080p for consistency and to avoid loading a
        // very high bitrate stream.
        mPlayer.setTrackSelectionParameters(
                new TrackSelectionParameters.Builder()
                        .setMaxVideoSize(1919, 1079)
                        .setForceHighestSupportedBitrate(true)
                        .build());
        mPlayer.prepare();
    }

    private void startPowerConnectionMonitoring() {
        // Monitor for connection, disconnection and power saver mode changes.
        mPowerReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (mIsFinished) {
                    return;
                }
                String action = intent.getAction();
                if (PowerManager.ACTION_POWER_SAVE_MODE_CHANGED.equals(action)) {
                    if (mPowerManager.isPowerSaveMode()) {
                        handleInPowerSaverMode();
                    }
                } else if (Intent.ACTION_POWER_CONNECTED.equals(action)) {
                    handlePowerConnected();
                } else if (Intent.ACTION_POWER_DISCONNECTED.equals(action)) {
                    handlePowerDisconnected();
                }
            }
        };

        // Check the current status.
        IntentFilter powerIntentFilter = new IntentFilter();
        powerIntentFilter.addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED);
        powerIntentFilter.addAction(Intent.ACTION_POWER_DISCONNECTED);
        powerIntentFilter.addAction(Intent.ACTION_POWER_CONNECTED);
        registerReceiver(mPowerReceiver, powerIntentFilter);
        @Nullable Intent batteryStatusIntent = getBatteryStatusIntent();
        boolean isPowerConnected = batteryStatusIntent != null
                && batteryStatusIntent.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) != 0;
        if (mPowerManager.isPowerSaveMode()) {
            handleInPowerSaverMode();
        } else if (!isPowerConnected) {
            handlePowerDisconnected();
        }
    }

    private void handleInPowerSaverMode() {
        handleFailure("Device is in power saver mode");
    }

    private void handlePowerDisconnected() {
        if (!mIsTestPlaybackRunning) {
            startTestPlayback();
        }
    }

    private void handlePowerConnected() {
        handleFailure("Power connected");
    }

    // The charge counter, handled elsewhere, is our critical piece of info.
    // However, there are "EXTRA" fields of battery information which help
    // provide context to the charge counter, so we record some of those as well.
    private void logBatteryExtraInfo(long timeMs) {
        @Nullable Intent batteryStatusIntent = getBatteryStatusIntent();
        if (batteryStatusIntent == null) {
            return;
        }
        int level = batteryStatusIntent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
        int scale = batteryStatusIntent.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
        if (level >= 0 && scale > 0) {
            mTestResultLogger.logBatteryLevel(timeMs, level, scale);
        }
        int temperature = batteryStatusIntent.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, -1);
        if (temperature > 0) {
            mTestResultLogger.logBatteryTemperature(timeMs, temperature);
        }
        int health = batteryStatusIntent.getIntExtra(BatteryManager.EXTRA_HEALTH, -1);
        if (health > 0) {
            mTestResultLogger.logBatteryHealth(timeMs, health);
        }
        // This doesn't change during a test run, so only log it once.
        if (!mLoggedBatteryCycleCount) {
            int cycleCount = batteryStatusIntent.getIntExtra(BatteryManager.EXTRA_CYCLE_COUNT, -1);
            // Even if we get -1 here, we'll log it, since we're only logging
            // once per test run, and it's useful to know that the device
            // doesn't report this information.
            mTestResultLogger.logBatteryCycleCount(timeMs, cycleCount);
            mLoggedBatteryCycleCount = true;
        }
    }

    private void startTestPlayback() {
        mIsTestPlaybackRunning = true;

        mPlayer.play();
        mTestResultLogger.logStarted();

        // Repeatedly sample and log the coulomb counter level on the main thread.
        mSampleBatteryRunnable = () -> {
            long timeMs = SystemClock.elapsedRealtime();
            long chargeCounter =
                    mBatteryManager.getLongProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER);
            mTestResultLogger.logChargeCounter(timeMs, chargeCounter);
            logBatteryExtraInfo(timeMs);
            mHandler.postDelayed(mSampleBatteryRunnable, BATTERY_SAMPLE_INTERVAL_SEC * 1000L);
        };
        mHandler.post(mSampleBatteryRunnable);

        // Schedule the end of the test playback.
        long durationMs = getIntent().getIntExtra(EXTRA_DURATION_SEC, DEFAULT_DURATION_SEC) * 1000L;
        mHandler.postDelayed(this::handleSuccess, durationMs);
    }

    private void handleSuccess() {
        // Log a final coulomb counter sample and then stop the playback.
        mSampleBatteryRunnable.run();
        PlaybackStats playbackStats = mPlaybackStatsListener.getCombinedPlaybackStats();
        String summaryMessage = String.format(
            "played=%.2f s, wait=%.2f s, rebuffers=%d (%.2f s), errors=%d",
                playbackStats.getTotalPlayTimeMs() / 1000.0,
                playbackStats.getTotalWaitTimeMs() / 1000.0,
                playbackStats.totalRebufferCount,
                playbackStats.getTotalRebufferTimeMs() / 1000.0,
                playbackStats.nonFatalErrorCount);
        mTestResultLogger.logSuccess(summaryMessage);
        stopTestPlayback();
    }

    private void handleFailure(String errorMessage) {
        // Show a toast with the error for now, to make it easier to debug issues eg. with USB.
        Toast.makeText(this, errorMessage, Toast.LENGTH_LONG).show();
        mTestResultLogger.logFailure(errorMessage);
        stopTestPlayback();
    }

    private void stopTestPlayback() {
        mIsFinished = true;
        mIsTestPlaybackRunning = false;
        mHandler.removeCallbacksAndMessages(/* token= */ null);
        stopPowerConnectionMonitoring();
        releasePlayer();
    }

    private void stopPowerConnectionMonitoring() {
        if (mPowerReceiver != null) {
            unregisterReceiver(mPowerReceiver);
            mPowerReceiver = null;
        }
    }

    private void releasePlayer() {
        mPlayerView.setPlayer(null);
        if (mPlayer != null) {
            mPlayer.release();
            mPlayer = null;
        }
    }

    @Nullable private Intent getBatteryStatusIntent() {
        return registerReceiver(/* receiver= */ null, mBatteryChangedIntentFilter);
    }

}
