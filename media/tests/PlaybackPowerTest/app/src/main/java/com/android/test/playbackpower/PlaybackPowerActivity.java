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

import androidx.annotation.Nullable;
import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Trace;
import android.util.Log;

import androidx.media3.common.AudioAttributes;
import androidx.media3.common.MediaItem;
import androidx.media3.common.PlaybackException;
import androidx.media3.common.Player;
import androidx.media3.common.util.Util;
import androidx.media3.exoplayer.ExoPlayer;
import androidx.media3.exoplayer.util.EventLogger;
import androidx.media3.exoplayer.analytics.AnalyticsListener;
import androidx.media3.exoplayer.analytics.PlaybackStats;
import androidx.media3.exoplayer.analytics.PlaybackStatsListener;
import androidx.media3.ui.PlayerView;
import java.util.UUID;
import java.util.concurrent.Executors;

/** Activity with a video player that can be used to measure playback power. */
public final class PlaybackPowerActivity extends Activity {

    private static final String TAG = "PlaybackPower";

    private static final String ACTION_VIEW = "com.android.test.playbackpower.VIEW";
    private static final String URI_EXTRA = "uri";
    private static final String DRM_SCHEME_EXTRA = "drm_scheme";
    private static final String DRM_LICENSE_URI_EXTRA = "drm_license_uri";

    private ExoPlayer mPlayer;
    private PlayerView mPlayerView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_playback_power);
        mPlayerView = findViewById(R.id.player_view);
    }

    @Override
    public void onStart() {
        super.onStart();
        initializePlayer();
        mPlayerView.onResume();
    }

    @Override
    public void onStop() {
        super.onStop();
        mPlayerView.onPause();
        releasePlayer();
    }

    private void initializePlayer() {
        mPlayer = new ExoPlayer.Builder(/* context= */ this).build();
        mPlayer.addListener(new PlayerEventListener());
        mPlayer.addAnalyticsListener(new EventLogger());
        mPlayer.addAnalyticsListener(
                new PlaybackStatsListener(
                        /* keepHistory= */ false,
                        new PlaybackStatsListener.Callback() {

                            @Override
                            public void onPlaybackStatsReady(
                                    AnalyticsListener.EventTime eventTime,
                                    PlaybackStats playbackStats) {
                                Log.i(TAG, "onPlaybackStats: " + playbackStats);
                            }
                        }));
        mPlayer.setAudioAttributes(AudioAttributes.DEFAULT, /* handleAudioFocus= */ true);
        mPlayer.setMediaItem(createMediaItem());
        mPlayer.setRepeatMode(Player.REPEAT_MODE_ONE);
        mPlayer.setPlayWhenReady(true);
        mPlayerView.setPlayer(mPlayer);
        mPlayer.prepare();
    }

    private MediaItem createMediaItem() {
        Intent intent = getIntent();
        Uri uri = intent.getData();
        MediaItem.Builder builder = new MediaItem.Builder().setUri(intent.getData());
        @Nullable String drmSchemeExtra = intent.getStringExtra(DRM_SCHEME_EXTRA);
        if (drmSchemeExtra != null) {
            @Nullable UUID drmUuid = Util.getDrmUuid(drmSchemeExtra);
            builder.setDrmConfiguration(
                    new MediaItem.DrmConfiguration.Builder(drmUuid)
                            .setLicenseUri(intent.getStringExtra(DRM_LICENSE_URI_EXTRA))
                            .build());
        }
        return builder.build();
    }

    private void releasePlayer() {
        mPlayer.release();
        mPlayer = null;
        mPlayerView.setPlayer(null);
    }

    private final class PlayerEventListener implements Player.Listener {
        @Override
        public void onPlayerError(PlaybackException error) {
            // TODO: Signal failure to the host side test.
        }
    }
}
