/*
 * Copyright 2018 The Android Open Source Project
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

package com.android.widget;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.media.AudioAttributes;
import android.media.AudioFocusRequest;
import android.media.AudioManager;
import android.media.MediaMetadata;
import android.media.MediaPlayer;
import android.media.MediaPlayerBase;
import android.media.Cea708CaptionRenderer;
import android.media.ClosedCaptionRenderer;
import android.media.Metadata;
import android.media.PlaybackParams;
import android.media.SubtitleController;
import android.media.session.MediaSession;
import android.media.session.PlaybackState;
import android.media.TtmlRenderer;
import android.media.WebVttRenderer;
import android.media.update.VideoView2Provider;
import android.media.update.ViewProvider;
import android.net.Uri;
import android.os.Bundle;
import android.os.ResultReceiver;
import android.support.annotation.Nullable;
import android.util.AttributeSet;
import android.util.Log;
import android.view.Gravity;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout.LayoutParams;
import android.widget.MediaControlView2;
import android.widget.VideoView2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.android.media.update.ApiHelper;
import com.android.media.update.R;

public class VideoView2Impl implements VideoView2Provider, VideoViewInterface.SurfaceListener {
    private static final String TAG = "VideoView2";
    private static final boolean DEBUG = true; // STOPSHIP: Log.isLoggable(TAG, Log.DEBUG);

    private final VideoView2 mInstance;
    private final ViewProvider mSuperProvider;

    private static final int STATE_ERROR = -1;
    private static final int STATE_IDLE = 0;
    private static final int STATE_PREPARING = 1;
    private static final int STATE_PREPARED = 2;
    private static final int STATE_PLAYING = 3;
    private static final int STATE_PAUSED = 4;
    private static final int STATE_PLAYBACK_COMPLETED = 5;

    private final AudioManager mAudioManager;
    private AudioAttributes mAudioAttributes;
    private int mAudioFocusType = AudioManager.AUDIOFOCUS_GAIN; // legacy focus gain
    private int mAudioSession;

    private VideoView2.OnPreparedListener mOnPreparedListener;
    private VideoView2.OnCompletionListener mOnCompletionListener;
    private VideoView2.OnErrorListener mOnErrorListener;
    private VideoView2.OnInfoListener mOnInfoListener;
    private VideoView2.OnViewTypeChangedListener mOnViewTypeChangedListener;

    private VideoViewInterface mCurrentView;
    private VideoTextureView mTextureView;
    private VideoSurfaceView mSurfaceView;

    private MediaPlayer mMediaPlayer;
    private MediaControlView2 mMediaControlView;
    private MediaSession mMediaSession;

    private PlaybackState.Builder mStateBuilder;
    private int mTargetState = STATE_IDLE;
    private int mCurrentState = STATE_IDLE;
    private int mCurrentBufferPercentage;
    private int mSeekWhenPrepared;  // recording the seek position while preparing

    private int mVideoWidth;
    private int mVideoHeight;

    private boolean mCCEnabled;
    private int mSelectedTrackIndex;

    private SubtitleView mSubtitleView;
    private float mSpeed;
    // TODO: Remove mFallbackSpeed when integration with MediaPlayer2's new setPlaybackParams().
    // Refer: https://docs.google.com/document/d/1nzAfns6i2hJ3RkaUre3QMT6wsDedJ5ONLiA_OOBFFX8/edit
    private float mFallbackSpeed;  // keep the original speed before 'pause' is called.

    public VideoView2Impl(
            VideoView2 instance, ViewProvider superProvider,
            @Nullable AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        mInstance = instance;
        mSuperProvider = superProvider;

        mVideoWidth = 0;
        mVideoHeight = 0;
        mSpeed = 1.0f;
        mFallbackSpeed = mSpeed;

        mAudioManager = (AudioManager) mInstance.getContext()
                .getSystemService(Context.AUDIO_SERVICE);
        mAudioAttributes = new AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_MEDIA)
                .setContentType(AudioAttributes.CONTENT_TYPE_MOVIE).build();
        mInstance.setFocusable(true);
        mInstance.setFocusableInTouchMode(true);
        mInstance.requestFocus();

        // TODO: try to keep a single child at a time rather than always having both.
        mTextureView = new VideoTextureView(mInstance.getContext());
        mSurfaceView = new VideoSurfaceView(mInstance.getContext());
        LayoutParams params = new LayoutParams(LayoutParams.MATCH_PARENT,
                LayoutParams.MATCH_PARENT);
        params.gravity = Gravity.CENTER;
        mTextureView.setLayoutParams(params);
        mSurfaceView.setLayoutParams(params);
        mTextureView.setSurfaceListener(this);
        mSurfaceView.setSurfaceListener(this);

        // TODO: Choose TextureView when SurfaceView cannot be created.
        // Choose surface view by default
        mTextureView.setVisibility(View.GONE);
        mSurfaceView.setVisibility(View.VISIBLE);
        mInstance.addView(mTextureView);
        mInstance.addView(mSurfaceView);
        mCurrentView = mSurfaceView;

        LayoutParams subtitleParams = new LayoutParams(LayoutParams.MATCH_PARENT,
                LayoutParams.MATCH_PARENT);
        mSubtitleView = new SubtitleView(mInstance.getContext());
        mSubtitleView.setLayoutParams(subtitleParams);
        mSubtitleView.setBackgroundColor(0);
        mInstance.addView(mSubtitleView);

        // TODO: Need a common namespace for attributes those are defined in updatable library.
        boolean enableControlView = (attrs == null) || attrs.getAttributeBooleanValue(
                "http://schemas.android.com/apk/com.android.media.update",
                "enableControlView", true);
        if (enableControlView) {
            mMediaControlView = new MediaControlView2(mInstance.getContext());
        }
    }

    @Override
    public void setMediaControlView2_impl(MediaControlView2 mediaControlView) {
        mMediaControlView = mediaControlView;

        if (mInstance.isAttachedToWindow()) {
            attachMediaControlView();
        }
    }

    @Override
    public MediaControlView2 getMediaControlView2_impl() {
        return mMediaControlView;
    }

    @Override
    public void start_impl() {
        if (isInPlaybackState() && mCurrentView.hasAvailableSurface()) {
            applySpeed();
            mMediaPlayer.start();
            mCurrentState = STATE_PLAYING;
            updatePlaybackState();
        }
        mTargetState = STATE_PLAYING;
        if (DEBUG) {
            Log.d(TAG, "start(). mCurrentState=" + mCurrentState
                    + ", mTargetState=" + mTargetState);
        }
    }

    @Override
    public void pause_impl() {
        if (isInPlaybackState()) {
            if (mMediaPlayer.isPlaying()) {
                mMediaPlayer.pause();
                mCurrentState = STATE_PAUSED;
                updatePlaybackState();
            }
        }
        mTargetState = STATE_PAUSED;
        if (DEBUG) {
            Log.d(TAG, "pause(). mCurrentState=" + mCurrentState
                    + ", mTargetState=" + mTargetState);
        }
    }

    @Override
    public int getDuration_impl() {
        if (isInPlaybackState()) {
            return mMediaPlayer.getDuration();
        }
        return -1;
    }

    @Override
    public int getCurrentPosition_impl() {
        if (isInPlaybackState()) {
            return mMediaPlayer.getCurrentPosition();
        }
        return 0;
    }

    @Override
    public void seekTo_impl(int msec) {
        if (isInPlaybackState()) {
            mMediaPlayer.seekTo(msec);
            mSeekWhenPrepared = 0;
            updatePlaybackState();
        } else {
            mSeekWhenPrepared = msec;
        }
    }

    @Override
    public boolean isPlaying_impl() {
        return (isInPlaybackState()) && mMediaPlayer.isPlaying();
    }

    @Override
    public int getBufferPercentage_impl() {
        return mCurrentBufferPercentage;
    }

    @Override
    public int getAudioSessionId_impl() {
        if (mAudioSession == 0) {
            MediaPlayer foo = new MediaPlayer();
            mAudioSession = foo.getAudioSessionId();
            foo.release();
        }
        return mAudioSession;
    }

    @Override
    public void showSubtitle_impl() {
        // Retrieve all tracks that belong to the current video.
        MediaPlayer.TrackInfo[] trackInfos = mMediaPlayer.getTrackInfo();

        List<Integer> subtitleTrackIndices = new ArrayList<>();
        for (int i = 0; i < trackInfos.length; ++i) {
            int trackType = trackInfos[i].getTrackType();
            if (trackType == MediaPlayer.TrackInfo.MEDIA_TRACK_TYPE_SUBTITLE) {
                subtitleTrackIndices.add(i);
            }
        }
        if (subtitleTrackIndices.size() > 0) {
            // Select first subtitle track
            mCCEnabled = true;
            mSelectedTrackIndex = subtitleTrackIndices.get(0);
            mMediaPlayer.selectTrack(mSelectedTrackIndex);
        }
    }

    @Override
    public void hideSubtitle_impl() {
        if (mCCEnabled) {
            mMediaPlayer.deselectTrack(mSelectedTrackIndex);
            mCCEnabled = false;
        }
    }

    @Override
    public void setSpeed_impl(float speed) {
        if (speed <= 0.0f) {
            Log.e(TAG, "Unsupported speed (" + speed + ") is ignored.");
            return;
        }
        mSpeed = speed;
        if (mMediaPlayer != null && mMediaPlayer.isPlaying()) {
            applySpeed();
        }
    }

    @Override
    public float getSpeed_impl() {
        if (DEBUG) {
            if (mMediaPlayer != null) {
                float speed = mMediaPlayer.getPlaybackParams().getSpeed();
                if (speed != mSpeed) {
                    Log.w(TAG, "VideoView2's speed : " + mSpeed + " is different from "
                            + "MediaPlayer's speed : " + speed);
                }
            }
        }
        return mSpeed;
    }

    @Override
    public void setAudioFocusRequest_impl(int focusGain) {
        if (focusGain != AudioManager.AUDIOFOCUS_NONE
                && focusGain != AudioManager.AUDIOFOCUS_GAIN
                && focusGain != AudioManager.AUDIOFOCUS_GAIN_TRANSIENT
                && focusGain != AudioManager.AUDIOFOCUS_GAIN_TRANSIENT_MAY_DUCK
                && focusGain != AudioManager.AUDIOFOCUS_GAIN_TRANSIENT_EXCLUSIVE) {
            throw new IllegalArgumentException("Illegal audio focus type " + focusGain);
        }
        mAudioFocusType = focusGain;
    }

    @Override
    public void setAudioAttributes_impl(AudioAttributes attributes) {
        if (attributes == null) {
            throw new IllegalArgumentException("Illegal null AudioAttributes");
        }
        mAudioAttributes = attributes;
    }

    @Override
    public void setRouteAttributes_impl(List<String> routeCategories, MediaPlayerBase player) {
        // TODO: implement this.
    }

    @Override
    public void setVideoPath_impl(String path) {
        mInstance.setVideoURI(Uri.parse(path));
    }

    @Override
    public void setVideoURI_impl(Uri uri) {
        mInstance.setVideoURI(uri, null);
    }

    @Override
    public void setVideoURI_impl(Uri uri, Map<String, String> headers) {
        mSeekWhenPrepared = 0;
        openVideo(uri, headers);
    }

    @Override
    public void setViewType_impl(int viewType) {
        if (viewType == mCurrentView.getViewType()) {
            return;
        }
        VideoViewInterface targetView;
        if (viewType == VideoView2.VIEW_TYPE_TEXTUREVIEW) {
            Log.d(TAG, "switching to TextureView");
            targetView = mTextureView;
        } else if (viewType == VideoView2.VIEW_TYPE_SURFACEVIEW) {
            Log.d(TAG, "switching to SurfaceView");
            targetView = mSurfaceView;
        } else {
            throw new IllegalArgumentException("Unknown view type: " + viewType);
        }
        ((View) targetView).setVisibility(View.VISIBLE);
        targetView.takeOver(mCurrentView);
        mInstance.requestLayout();
    }

    @Override
    public int getViewType_impl() {
        return mCurrentView.getViewType();
    }

    @Override
    public void stopPlayback_impl() {
        resetPlayer();
    }

    @Override
    public void setOnPreparedListener_impl(VideoView2.OnPreparedListener l) {
        mOnPreparedListener = l;
    }

    @Override
    public void setOnCompletionListener_impl(VideoView2.OnCompletionListener l) {
        mOnCompletionListener = l;
    }

    @Override
    public void setOnErrorListener_impl(VideoView2.OnErrorListener l) {
        mOnErrorListener = l;
    }

    @Override
    public void setOnInfoListener_impl(VideoView2.OnInfoListener l) {
        mOnInfoListener = l;
    }

    @Override
    public void setOnViewTypeChangedListener_impl(VideoView2.OnViewTypeChangedListener l) {
        mOnViewTypeChangedListener = l;
    }

    @Override
    public void onAttachedToWindow_impl() {
        mSuperProvider.onAttachedToWindow_impl();

        // Create MediaSession
        mMediaSession = new MediaSession(mInstance.getContext(), "VideoView2MediaSession");
        mMediaSession.setCallback(new MediaSessionCallback());

        attachMediaControlView();
    }

    @Override
    public void onDetachedFromWindow_impl() {
        mSuperProvider.onDetachedFromWindow_impl();
        mMediaSession.release();
        mMediaSession = null;
    }


    @Override
    public CharSequence getAccessibilityClassName_impl() {
        return VideoView2.class.getName();
    }

    @Override
    public boolean onTouchEvent_impl(MotionEvent ev) {
        if (DEBUG) {
            Log.d(TAG, "onTouchEvent(). mCurrentState=" + mCurrentState
                    + ", mTargetState=" + mTargetState);
        }
        if (ev.getAction() == MotionEvent.ACTION_UP
                && isInPlaybackState() && mMediaControlView != null) {
            toggleMediaControlViewVisibility();
        }
        return mSuperProvider.onTouchEvent_impl(ev);
    }

    @Override
    public boolean onTrackballEvent_impl(MotionEvent ev) {
        if (ev.getAction() == MotionEvent.ACTION_UP
                && isInPlaybackState() && mMediaControlView != null) {
            toggleMediaControlViewVisibility();
        }
        return mSuperProvider.onTrackballEvent_impl(ev);
    }

    @Override
    public boolean onKeyDown_impl(int keyCode, KeyEvent event) {
        Log.v(TAG, "onKeyDown_impl: " + keyCode);
        boolean isKeyCodeSupported = keyCode != KeyEvent.KEYCODE_BACK
                && keyCode != KeyEvent.KEYCODE_VOLUME_UP
                && keyCode != KeyEvent.KEYCODE_VOLUME_DOWN
                && keyCode != KeyEvent.KEYCODE_VOLUME_MUTE
                && keyCode != KeyEvent.KEYCODE_MENU
                && keyCode != KeyEvent.KEYCODE_CALL
                && keyCode != KeyEvent.KEYCODE_ENDCALL;
        if (isInPlaybackState() && isKeyCodeSupported && mMediaControlView != null) {
            if (keyCode == KeyEvent.KEYCODE_HEADSETHOOK
                    || keyCode == KeyEvent.KEYCODE_MEDIA_PLAY_PAUSE) {
                if (mMediaPlayer.isPlaying()) {
                    mInstance.pause();
                    mMediaControlView.show();
                } else {
                    mInstance.start();
                    mMediaControlView.hide();
                }
                return true;
            } else if (keyCode == KeyEvent.KEYCODE_MEDIA_PLAY) {
                if (!mMediaPlayer.isPlaying()) {
                    mInstance.start();
                    mMediaControlView.hide();
                }
                return true;
            } else if (keyCode == KeyEvent.KEYCODE_MEDIA_STOP
                    || keyCode == KeyEvent.KEYCODE_MEDIA_PAUSE) {
                if (mMediaPlayer.isPlaying()) {
                    mInstance.pause();
                    mMediaControlView.show();
                }
                return true;
            } else {
                toggleMediaControlViewVisibility();
            }
        }

        return mSuperProvider.onKeyDown_impl(keyCode, event);
    }

    @Override
    public void onFinishInflate_impl() {
        mSuperProvider.onFinishInflate_impl();
    }

    @Override
    public boolean dispatchKeyEvent_impl(KeyEvent event) {
        return mSuperProvider.dispatchKeyEvent_impl(event);
    }

    @Override
    public void setEnabled_impl(boolean enabled) {
        mSuperProvider.setEnabled_impl(enabled);
    }

    ///////////////////////////////////////////////////
    // Implements VideoViewInterface.SurfaceListener
    ///////////////////////////////////////////////////

    @Override
    public void onSurfaceCreated(View view, int width, int height) {
        if (DEBUG) {
            Log.d(TAG, "onSurfaceCreated(). mCurrentState=" + mCurrentState
                    + ", mTargetState=" + mTargetState + ", width/height: " + width + "/" + height
                    + ", " + view.toString());
        }
        if (needToStart()) {
            mInstance.start();
        }
    }

    @Override
    public void onSurfaceDestroyed(View view) {
        if (DEBUG) {
            Log.d(TAG, "onSurfaceDestroyed(). mCurrentState=" + mCurrentState
                    + ", mTargetState=" + mTargetState + ", " + view.toString());
        }
        if (mMediaControlView != null) {
            mMediaControlView.hide();
        }
    }

    @Override
    public void onSurfaceChanged(View view, int width, int height) {
        // TODO: Do we need to call requestLayout here?
        if (DEBUG) {
            Log.d(TAG, "onSurfaceChanged(). width/height: " + width + "/" + height
                    + ", " + view.toString());
        }
    }

    @Override
    public void onSurfaceTakeOverDone(VideoViewInterface view) {
        if (DEBUG) {
            Log.d(TAG, "onSurfaceTakeOverDone(). Now current view is: " + view);
        }
        mCurrentView = view;
        if (mOnViewTypeChangedListener != null) {
            mOnViewTypeChangedListener.onViewTypeChanged(view.getViewType());
        }
        if (needToStart()) {
            mInstance.start();
        }
    }

    ///////////////////////////////////////////////////
    // Protected or private methods
    ///////////////////////////////////////////////////

    private void attachMediaControlView() {
        // TODO: change this so that the CC button appears only where there is a subtitle track.
        // mMediaControlView.showCCButton();

        // Get MediaController from MediaSession and set it inside MediaControlView
        mMediaControlView.setController(mMediaSession.getController());

        LayoutParams params =
                new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT);
        mInstance.addView(mMediaControlView, params);
    }

    private boolean isInPlaybackState() {
        return (mMediaPlayer != null
                && mCurrentState != STATE_ERROR
                && mCurrentState != STATE_IDLE
                && mCurrentState != STATE_PREPARING);
    }

    private boolean needToStart() {
        return (mMediaPlayer != null
                && mCurrentState != STATE_PLAYING
                && mTargetState == STATE_PLAYING);
    }

    // Creates a MediaPlayer instance and prepare playback.
    private void openVideo(Uri uri, Map<String, String> headers) {
        resetPlayer();
        if (mAudioFocusType != AudioManager.AUDIOFOCUS_NONE) {
            // TODO this should have a focus listener
            AudioFocusRequest focusRequest;
            focusRequest = new AudioFocusRequest.Builder(mAudioFocusType)
                    .setAudioAttributes(mAudioAttributes)
                    .build();
            mAudioManager.requestAudioFocus(focusRequest);
        }

        try {
            Log.d(TAG, "openVideo(): creating new MediaPlayer instance.");
            mMediaPlayer = new MediaPlayer();
            mSurfaceView.setMediaPlayer(mMediaPlayer);
            mTextureView.setMediaPlayer(mMediaPlayer);
            mCurrentView.assignSurfaceToMediaPlayer(mMediaPlayer);

            // TODO: create SubtitleController in MediaPlayer, but we need
            // a context for the subtitle renderers
            final Context context = mInstance.getContext();
            final SubtitleController controller = new SubtitleController(
                    context, mMediaPlayer.getMediaTimeProvider(), mMediaPlayer);
            controller.registerRenderer(new WebVttRenderer(context));
            controller.registerRenderer(new TtmlRenderer(context));
            controller.registerRenderer(new Cea708CaptionRenderer(context));
            controller.registerRenderer(new ClosedCaptionRenderer(context));
            mMediaPlayer.setSubtitleAnchor(controller, (SubtitleController.Anchor) mSubtitleView);

            if (mAudioSession != 0) {
                mMediaPlayer.setAudioSessionId(mAudioSession);
            } else {
                mAudioSession = mMediaPlayer.getAudioSessionId();
            }
            mMediaPlayer.setOnPreparedListener(mPreparedListener);
            mMediaPlayer.setOnVideoSizeChangedListener(mSizeChangedListener);
            mMediaPlayer.setOnCompletionListener(mCompletionListener);
            mMediaPlayer.setOnErrorListener(mErrorListener);
            mMediaPlayer.setOnInfoListener(mInfoListener);
            mMediaPlayer.setOnBufferingUpdateListener(mBufferingUpdateListener);
            mCurrentBufferPercentage = 0;
            mMediaPlayer.setDataSource(mInstance.getContext(), uri, headers);
            mMediaPlayer.setAudioAttributes(mAudioAttributes);
            // we don't set the target state here either, but preserve the
            // target state that was there before.
            mCurrentState = STATE_PREPARING;
            mMediaPlayer.prepareAsync();

            if (DEBUG) {
                Log.d(TAG, "openVideo(). mCurrentState=" + mCurrentState
                        + ", mTargetState=" + mTargetState);
            }
            /*
            for (Pair<InputStream, MediaFormat> pending: mPendingSubtitleTracks) {
                try {
                    mMediaPlayer.addSubtitleSource(pending.first, pending.second);
                } catch (IllegalStateException e) {
                    mInfoListener.onInfo(
                            mMediaPlayer, MediaPlayer.MEDIA_INFO_UNSUPPORTED_SUBTITLE, 0);
                }
            }
            */
        } catch (IOException | IllegalArgumentException ex) {
            Log.w(TAG, "Unable to open content: " + uri, ex);
            mCurrentState = STATE_ERROR;
            mTargetState = STATE_ERROR;
            mErrorListener.onError(mMediaPlayer,
                    MediaPlayer.MEDIA_ERROR_UNKNOWN, MediaPlayer.MEDIA_ERROR_IO);
        } finally {
            //mPendingSubtitleTracks.clear();
        }
    }

    /*
     * Reset the media player in any state
     */
    // TODO: Figure out if the legacy code's boolean parameter: cleartargetstate is necessary.
    private void resetPlayer() {
        if (mMediaPlayer != null) {
            mMediaPlayer.reset();
            mMediaPlayer.release();
            mMediaPlayer = null;
            //mPendingSubtitleTracks.clear();
            mCurrentState = STATE_IDLE;
            mTargetState = STATE_IDLE;
            if (mAudioFocusType != AudioManager.AUDIOFOCUS_NONE) {
                mAudioManager.abandonAudioFocus(null);
            }
        }
        mVideoWidth = 0;
        mVideoHeight = 0;
    }

    private void updatePlaybackState() {
        if (mStateBuilder == null) {
            // Get the capabilities of the player for this stream
            Metadata data = mMediaPlayer.getMetadata(MediaPlayer.METADATA_ALL,
                    MediaPlayer.BYPASS_METADATA_FILTER);

            // Add Play action as default
            long playbackActions = PlaybackState.ACTION_PLAY;
            if (data != null) {
                if (!data.has(Metadata.PAUSE_AVAILABLE)
                        || data.getBoolean(Metadata.PAUSE_AVAILABLE)) {
                    playbackActions |= PlaybackState.ACTION_PAUSE;
                }
                if (!data.has(Metadata.SEEK_BACKWARD_AVAILABLE)
                        || data.getBoolean(Metadata.SEEK_BACKWARD_AVAILABLE)) {
                    playbackActions |= PlaybackState.ACTION_REWIND;
                }
                if (!data.has(Metadata.SEEK_FORWARD_AVAILABLE)
                        || data.getBoolean(Metadata.SEEK_FORWARD_AVAILABLE)) {
                    playbackActions |= PlaybackState.ACTION_FAST_FORWARD;
                }
                if (!data.has(Metadata.SEEK_AVAILABLE)
                        || data.getBoolean(Metadata.SEEK_AVAILABLE)) {
                    playbackActions |= PlaybackState.ACTION_SEEK_TO;
                }
            } else {
                playbackActions |= (PlaybackState.ACTION_PAUSE |
                        PlaybackState.ACTION_REWIND | PlaybackState.ACTION_FAST_FORWARD |
                        PlaybackState.ACTION_SEEK_TO);
            }
            mStateBuilder = new PlaybackState.Builder();
            mStateBuilder.setActions(playbackActions);
            mStateBuilder.addCustomAction(MediaControlView2Impl.ACTION_SHOW_SUBTITLE, null, -1);
            mStateBuilder.addCustomAction(MediaControlView2Impl.ACTION_HIDE_SUBTITLE, null, -1);
        }
        mStateBuilder.setState(getCorrespondingPlaybackState(),
                mInstance.getCurrentPosition(), 1.0f);
        mStateBuilder.setBufferedPosition(
                (long) (mCurrentBufferPercentage / 100.0) * mInstance.getDuration());

        // Set PlaybackState for MediaSession
        if (mMediaSession != null) {
            PlaybackState state = mStateBuilder.build();
            mMediaSession.setPlaybackState(state);
        }
    }

    private int getCorrespondingPlaybackState() {
        switch (mCurrentState) {
            case STATE_ERROR:
                return PlaybackState.STATE_ERROR;
            case STATE_IDLE:
                return PlaybackState.STATE_NONE;
            case STATE_PREPARING:
                return PlaybackState.STATE_CONNECTING;
            case STATE_PREPARED:
                return PlaybackState.STATE_STOPPED;
            case STATE_PLAYING:
                return PlaybackState.STATE_PLAYING;
            case STATE_PAUSED:
                return PlaybackState.STATE_PAUSED;
            case STATE_PLAYBACK_COMPLETED:
                return PlaybackState.STATE_STOPPED;
            default:
                return -1;
        }
    }

    private void toggleMediaControlViewVisibility() {
        if (mMediaControlView.isShowing()) {
            mMediaControlView.hide();
        } else {
            mMediaControlView.show();
        }
    }

    private void applySpeed() {
        PlaybackParams params = mMediaPlayer.getPlaybackParams().allowDefaults();
        if (mSpeed != params.getSpeed()) {
            try {
                params.setSpeed(mSpeed);
                mMediaPlayer.setPlaybackParams(params);
                mFallbackSpeed = mSpeed;
            } catch (IllegalArgumentException e) {
                Log.e(TAG, "PlaybackParams has unsupported value: " + e);
                // TODO: should revise this part after integrating with MP2.
                // If mSpeed had an illegal value for speed rate, system will determine best
                // handling (see PlaybackParams.AUDIO_FALLBACK_MODE_DEFAULT).
                // Note: The pre-MP2 returns 0.0f when it is paused. In this case, VideoView2 will
                // use mFallbackSpeed instead.
                float fallbackSpeed = mMediaPlayer.getPlaybackParams().allowDefaults().getSpeed();
                if (fallbackSpeed > 0.0f) {
                    mFallbackSpeed = fallbackSpeed;
                }
                mSpeed = mFallbackSpeed;
            }
        }
    }

    MediaPlayer.OnVideoSizeChangedListener mSizeChangedListener =
            new MediaPlayer.OnVideoSizeChangedListener() {
                public void onVideoSizeChanged(MediaPlayer mp, int width, int height) {
                    if (DEBUG) {
                        Log.d(TAG, "OnVideoSizeChanged(): size: " + width + "/" + height);
                    }
                    mVideoWidth = mp.getVideoWidth();
                    mVideoHeight = mp.getVideoHeight();
                    if (DEBUG) {
                        Log.d(TAG, "OnVideoSizeChanged(): mVideoSize:" + mVideoWidth + "/"
                                + mVideoHeight);
                    }

                    if (mVideoWidth != 0 && mVideoHeight != 0) {
                        mInstance.requestLayout();
                    }
                }
            };

    MediaPlayer.OnPreparedListener mPreparedListener = new MediaPlayer.OnPreparedListener() {
        public void onPrepared(MediaPlayer mp) {
            if (DEBUG) {
                Log.d(TAG, "OnPreparedListener(). mCurrentState=" + mCurrentState
                        + ", mTargetState=" + mTargetState);
            }
            mCurrentState = STATE_PREPARED;
            if (mOnPreparedListener != null) {
                mOnPreparedListener.onPrepared();
            }
            if (mMediaControlView != null) {
                mMediaControlView.setEnabled(true);
            }
            int videoWidth = mp.getVideoWidth();
            int videoHeight = mp.getVideoHeight();

            // mSeekWhenPrepared may be changed after seekTo() call
            int seekToPosition = mSeekWhenPrepared;
            if (seekToPosition != 0) {
                mInstance.seekTo(seekToPosition);
            }

            // Create and set playback state for MediaControlView2
            updatePlaybackState();

            // Get and set duration value as MediaMetadata for MediaControlView2
            MediaMetadata.Builder builder = new MediaMetadata.Builder();
            builder.putLong(MediaMetadata.METADATA_KEY_DURATION, mInstance.getDuration());
            if (mMediaSession != null) {
                mMediaSession.setMetadata(builder.build());
            }

            if (videoWidth != 0 && videoHeight != 0) {
                if (videoWidth != mVideoWidth || videoHeight != mVideoHeight) {
                    if (DEBUG) {
                        Log.i(TAG, "OnPreparedListener() : ");
                        Log.i(TAG, " video size: " + videoWidth + "/" + videoHeight);
                        Log.i(TAG, " measuredSize: " + mInstance.getMeasuredWidth() + "/"
                                + mInstance.getMeasuredHeight());
                        Log.i(TAG, " viewSize: " + mInstance.getWidth() + "/"
                                + mInstance.getHeight());
                    }

                    mVideoWidth = videoWidth;
                    mVideoHeight = videoHeight;
                    mInstance.requestLayout();
                }
                if (needToStart()) {
                    mInstance.start();
                    if (mMediaControlView != null) {
                        mMediaControlView.show();
                    }
                } else if (!mInstance.isPlaying() && (seekToPosition != 0
                        || mInstance.getCurrentPosition() > 0)) {
                    if (mMediaControlView != null) {
                        // Show the media controls when we're paused into a video and
                        // make them stick.
                        mMediaControlView.show(0);
                    }
                }
            } else {
                // We don't know the video size yet, but should start anyway.
                // The video size might be reported to us later.
                if (needToStart()) {
                    mInstance.start();
                }
            }
        }
    };

    private MediaPlayer.OnCompletionListener mCompletionListener =
            new MediaPlayer.OnCompletionListener() {
                public void onCompletion(MediaPlayer mp) {
                    mCurrentState = STATE_PLAYBACK_COMPLETED;
                    mTargetState = STATE_PLAYBACK_COMPLETED;
                    updatePlaybackState();

                    if (mMediaControlView != null) {
                        mMediaControlView.hide();
                    }
                    if (mOnCompletionListener != null) {
                        mOnCompletionListener.onCompletion();
                    }
                    if (mAudioFocusType != AudioManager.AUDIOFOCUS_NONE) {
                        mAudioManager.abandonAudioFocus(null);
                    }
                }
            };

    private MediaPlayer.OnInfoListener mInfoListener =
            new MediaPlayer.OnInfoListener() {
                public boolean onInfo(MediaPlayer mp, int what, int extra) {
                    if (mOnInfoListener != null) {
                        mOnInfoListener.onInfo(what, extra);
                    }
                    return true;
                }
            };

    private MediaPlayer.OnErrorListener mErrorListener =
            new MediaPlayer.OnErrorListener() {
                public boolean onError(MediaPlayer mp, int frameworkErr, int implErr) {
                    if (DEBUG) {
                        Log.d(TAG, "Error: " + frameworkErr + "," + implErr);
                    }
                    mCurrentState = STATE_ERROR;
                    mTargetState = STATE_ERROR;
                    updatePlaybackState();

                    if (mMediaControlView != null) {
                        mMediaControlView.hide();
                    }

                    /* If an error handler has been supplied, use it and finish. */
                    if (mOnErrorListener != null) {
                        if (mOnErrorListener.onError(frameworkErr, implErr)) {
                            return true;
                        }
                    }

                    /* Otherwise, pop up an error dialog so the user knows that
                     * something bad has happened. Only try and pop up the dialog
                     * if we're attached to a window. When we're going away and no
                     * longer have a window, don't bother showing the user an error.
                    */
                    if (mInstance.getWindowToken() != null) {
                        int messageId;

                        if (frameworkErr
                                == MediaPlayer.MEDIA_ERROR_NOT_VALID_FOR_PROGRESSIVE_PLAYBACK) {
                            messageId = R.string.VideoView2_error_text_invalid_progressive_playback;
                        } else {
                            messageId = R.string.VideoView2_error_text_unknown;
                        }

                        Resources res = ApiHelper.getLibResources();
                        new AlertDialog.Builder(mInstance.getContext())
                                .setMessage(res.getString(messageId))
                                .setPositiveButton(res.getString(R.string.VideoView2_error_button),
                                        new DialogInterface.OnClickListener() {
                                            public void onClick(DialogInterface dialog,
                                                                int whichButton) {
                                                /* If we get here, there is no onError listener, so
                                                * at least inform them that the video is over.
                                                */
                                                if (mOnCompletionListener != null) {
                                                    mOnCompletionListener.onCompletion();
                                                }
                                            }
                                        })
                                .setCancelable(false)
                                .show();
                    }
                    return true;
                }
            };

    private MediaPlayer.OnBufferingUpdateListener mBufferingUpdateListener =
            new MediaPlayer.OnBufferingUpdateListener() {
                public void onBufferingUpdate(MediaPlayer mp, int percent) {
                    mCurrentBufferPercentage = percent;
                    updatePlaybackState();
                }
            };

    private class MediaSessionCallback extends MediaSession.Callback {
        @Override
        public void onCommand(String command, Bundle args, ResultReceiver receiver) {
            switch (command) {
                case MediaControlView2Impl.ACTION_SHOW_SUBTITLE:
                    mInstance.showSubtitle();
                    break;
                case MediaControlView2Impl.ACTION_HIDE_SUBTITLE:
                    mInstance.hideSubtitle();
                    break;
            }
        }

        @Override
        public void onPlay() {
            mInstance.start();
        }

        @Override
        public void onPause() {
            mInstance.pause();
        }

        @Override
        public void onSeekTo(long pos) {
            mInstance.seekTo((int) pos);
        }
    }
}
