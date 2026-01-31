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
import androidx.media3.exoplayer.ExoPlayer;
import androidx.media3.exoplayer.util.EventLogger;
import androidx.media3.ui.PlayerView;
import java.io.File;
import java.util.UUID;

/** Activity with a video player that can be used to measure playback power. */
public final class PlaybackPowerActivity extends Activity {

    private static final String TAG = "PlaybackPower";

    /** Default delay before starting playback, in seconds. */
    private static final int DEFAULT_START_DELAY_SEC = 5;
    /** Default duration to play the video for, in seconds. */
    private static final int DEFAULT_DURATION_SEC = 50;
    /** Interval between sampling the coulomb counter, in seconds. */
    private static final int BATTERY_SAMPLE_INTERVAL_SEC = 10;
    /** Default name for the log file in the cache directory. */
    private static final String DEFAULT_LOG_FILE_NAME = "playback_power_log.json";

    private static final String EXTRA_DRM_SCHEME = "drm_scheme";
    private static final String EXTRA_DRM_LICENSE_URI = "drm_license_uri";
    private static final String EXTRA_START_DELAY_SEC = "start_delay_sec";
    private static final String EXTRA_DURATION_SEC = "duration_sec";
    private static final String EXTRA_LOG_FILE_NAME = "log_file_name";

    private Handler mHandler;

    private ExoPlayer mPlayer;
    private PlayerView mPlayerView;

    private BatteryManager mBatteryManager;
    private PowerManager mPowerManager;
    private BroadcastReceiver mPowerReceiver;
    private Runnable mSampleBatteryRunnable;

    private TestResultLogger mTestResultLogger;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_playback_power);
        mPlayerView = findViewById(R.id.player_view);
        mHandler = new Handler(Looper.getMainLooper());

        String fileName = getIntent().getStringExtra(EXTRA_LOG_FILE_NAME);
        if (fileName == null) {
            fileName = DEFAULT_LOG_FILE_NAME;
        }
        mTestResultLogger = new TestResultLogger(new File(getCacheDir(), fileName));
        mBatteryManager = getSystemService(BatteryManager.class);
        mPowerManager = getSystemService(PowerManager.class);

        // Hide system bars so the playback is full-screen.
        WindowInsetsControllerCompat windowInsetsControllerCompat =
            WindowCompat.getInsetsController(getWindow(), getWindow().getDecorView());
        windowInsetsControllerCompat.setSystemBarsBehavior(
            WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        );
        windowInsetsControllerCompat.hide(WindowInsetsCompat.Type.systemBars());
    }

    @Override
    public void onStart() {
        super.onStart();
        mPlayerView.onResume();

        preparePlayer();
        scheduleTestPlayback();
    }

    @Override
    public void onStop() {
        super.onStop();
        mPlayerView.onPause();
        mPlayerView.setPlayer(null);
        stopTestPlayback();
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
                handleFailure("Player error: " + error);
            }
        });
        mPlayer.addAnalyticsListener(new EventLogger());
        mPlayer.setAudioAttributes(AudioAttributes.DEFAULT, /* handleAudioFocus= */ true);
        mPlayer.setMediaItem(mediaItemBuilder.build());
        mPlayer.setRepeatMode(Player.REPEAT_MODE_ONE);
        // Disable bitrate adaptation to give more repeatable results.
        mPlayer.setTrackSelectionParameters(
                new TrackSelectionParameters.Builder()
                        .setForceHighestSupportedBitrate(true)
                        .build());
        mPlayer.prepare();
    }

    private void scheduleTestPlayback() {
        // Wait for the specified start delay, then play for the specified duration.
        long startDelayMs =
                getIntent().getIntExtra(EXTRA_START_DELAY_SEC, DEFAULT_START_DELAY_SEC) * 1000L;
        long durationMs =
                getIntent().getIntExtra(EXTRA_DURATION_SEC, DEFAULT_DURATION_SEC) * 1000L;
        mHandler.postDelayed(this::startTestPlayback, startDelayMs);
        mHandler.postDelayed(() -> {
            stopTestPlayback();
            handleSuccess();
        }, (startDelayMs + durationMs));
    }

    private void startTestPlayback() {
        mPlayer.play();
        mTestResultLogger.logPlaybackStarted();

        // Repeatedly sample and log the coulomb counter level on the main thread.
        mSampleBatteryRunnable = () -> {
            long chargeCounter =
                    mBatteryManager.getLongProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER);
            mTestResultLogger.logChargeCounter(chargeCounter);
            mHandler.postDelayed(mSampleBatteryRunnable, BATTERY_SAMPLE_INTERVAL_SEC * 1000L);
        };
        mHandler.post(mSampleBatteryRunnable);

        startPowerConnectionMonitoring();
    }

    private void startPowerConnectionMonitoring() {
        // Fail on power connection or power saver mode activation, which would invalidate the test.
        mPowerReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                String action = intent.getAction();
                if (PowerManager.ACTION_POWER_SAVE_MODE_CHANGED.equals(action)) {
                    if (mPowerManager.isPowerSaveMode()) {
                        handleFailure("Entered power saver mode");
                    }
                } else if (Intent.ACTION_POWER_CONNECTED.equals(action)) {
                    handleFailure("Power connected (via power broadcast)");
                }
            }
        };
        IntentFilter powerIntentFilter = new IntentFilter();
        powerIntentFilter.addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED);
        powerIntentFilter.addAction(Intent.ACTION_POWER_CONNECTED);
        registerReceiver(mPowerReceiver, powerIntentFilter);

        // Check the battery intent to see if we already have power connected.
        IntentFilter batteryChangedIntentFilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        Intent batteryStatus = registerReceiver(/* receiver= */ null, batteryChangedIntentFilter);
        int pluggedStatus = batteryStatus.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
        if (pluggedStatus == BatteryManager.BATTERY_PLUGGED_AC
                || pluggedStatus == BatteryManager.BATTERY_PLUGGED_USB) {
            handleFailure("Power connected (via battery intent)");
        }
    }

    private void stopTestPlayback() {
        stopPowerConnectionMonitoring();

        if (mPlayer != null) {
            mPlayer.release();
            mPlayer = null;
        }

        // We don't want any more callbacks on the main thread (including battery sampling).
        mHandler.removeCallbacksAndMessages(/* token= */ null);
    }

    private void stopPowerConnectionMonitoring() {
        if (mPowerReceiver != null) {
            unregisterReceiver(mPowerReceiver);
            mPowerReceiver = null;
        }
    }

    private void handleFailure(String errorMessage) {
        // Show a toast with the error for now, to make it easier to debug issues eg. with USB.
        Toast.makeText(this, errorMessage, Toast.LENGTH_LONG).show();

        stopTestPlayback();
        mTestResultLogger.logFailure(errorMessage);
    }

    private void handleSuccess() {
        mTestResultLogger.logSuccess();
    }

}
