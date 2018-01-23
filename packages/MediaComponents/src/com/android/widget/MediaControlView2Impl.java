/*
 * Copyright (C) 2017 The Android Open Source Project
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

import android.content.res.Resources;
import android.media.MediaMetadata;
import android.media.session.MediaController;
import android.media.session.PlaybackState;
import android.media.update.MediaControlView2Provider;
import android.media.update.ViewProvider;
import android.util.Log;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.accessibility.AccessibilityManager;
import android.widget.ImageButton;
import android.widget.MediaControlView2;
import android.widget.ProgressBar;
import android.widget.SeekBar;
import android.widget.SeekBar.OnSeekBarChangeListener;
import android.widget.TextView;

import com.android.media.update.ApiHelper;
import com.android.media.update.R;

import java.util.Formatter;
import java.util.Locale;

public class MediaControlView2Impl implements MediaControlView2Provider {
    private static final String TAG = "MediaControlView2";

    private final MediaControlView2 mInstance;
    private final ViewProvider mSuperProvider;

    static final String ACTION_SHOW_SUBTITLE = "showSubtitle";
    static final String ACTION_HIDE_SUBTITLE = "hideSubtitle";

    private static final int MAX_PROGRESS = 1000;
    private static final int DEFAULT_PROGRESS_UPDATE_TIME_MS = 1000;
    private static final int DEFAULT_TIMEOUT_MS = 2000;

    private static final int REWIND_TIME_MS = 10000;
    private static final int FORWARD_TIME_MS = 30000;

    private final boolean mUseClosedCaption;
    private final AccessibilityManager mAccessibilityManager;

    private MediaController mController;
    private MediaController.TransportControls mControls;
    private PlaybackState mPlaybackState;
    private MediaMetadata mMetadata;
    private ProgressBar mProgress;
    private TextView mEndTime, mCurrentTime;
    private int mDuration;
    private int mPrevState;
    private boolean mShowing;
    private boolean mDragging;
    private boolean mListenersSet;
    private boolean mCCIsEnabled;
    private boolean mIsStopped;
    private View.OnClickListener mNextListener, mPrevListener;
    private ImageButton mPlayPauseButton;
    private ImageButton mFfwdButton;
    private ImageButton mRewButton;
    private ImageButton mNextButton;
    private ImageButton mPrevButton;
    private ImageButton mCCButton;
    private CharSequence mPlayDescription;
    private CharSequence mPauseDescription;
    private CharSequence mReplayDescription;

    private StringBuilder mFormatBuilder;
    private Formatter mFormatter;

    public MediaControlView2Impl(MediaControlView2 instance, ViewProvider superProvider) {
        mInstance = instance;
        mSuperProvider = superProvider;
        mUseClosedCaption = true;
        mAccessibilityManager = AccessibilityManager.getInstance(mInstance.getContext());

        // Inflate MediaControlView2 from XML
        View root = makeControllerView();
        mInstance.addView(root);
    }

    @Override
    public void setController_impl(MediaController controller) {
        mController = controller;
        if (controller != null) {
            mControls = controller.getTransportControls();
            // Set mMetadata and mPlaybackState to existing MediaSession variables since they may
            // be called before the callback is called
            mPlaybackState = mController.getPlaybackState();
            mMetadata = mController.getMetadata();
            updateDuration();

            mController.registerCallback(new MediaControllerCallback());
        }
    }

    @Override
    public void show_impl() {
        mInstance.show(DEFAULT_TIMEOUT_MS);
    }

    @Override
    public void show_impl(int timeout) {
        if (!mShowing) {
            setProgress();
            if (mPlayPauseButton != null) {
                mPlayPauseButton.requestFocus();
            }
            disableUnsupportedButtons();
            mInstance.setVisibility(View.VISIBLE);
            mShowing = true;
        }
        // cause the progress bar to be updated even if mShowing
        // was already true.  This happens, for example, if we're
        // paused with the progress bar showing the user hits play.
        mInstance.post(mShowProgress);

        if (timeout != 0 && !mAccessibilityManager.isTouchExplorationEnabled()) {
            mInstance.removeCallbacks(mFadeOut);
            mInstance.postDelayed(mFadeOut, timeout);
        }
    }

    @Override
    public boolean isShowing_impl() {
        return mShowing;
    }

    @Override
    public void hide_impl() {
        if (mShowing) {
            try {
                mInstance.removeCallbacks(mShowProgress);
                // Remove existing call to mFadeOut to avoid from being called later.
                mInstance.removeCallbacks(mFadeOut);
                mInstance.setVisibility(View.GONE);
            } catch (IllegalArgumentException ex) {
                Log.w(TAG, "already removed");
            }
            mShowing = false;
        }
    }

    @Override
    public void showCCButton_impl() {
        if (mCCButton != null) {
            mCCButton.setVisibility(View.VISIBLE);
        }
    }

    @Override
    public boolean isPlaying_impl() {
        if (mPlaybackState != null) {
            return mPlaybackState.getState() == PlaybackState.STATE_PLAYING;
        }
        return false;
    }

    @Override
    public int getCurrentPosition_impl() {
        mPlaybackState = mController.getPlaybackState();
        if (mPlaybackState != null) {
            return (int) mPlaybackState.getPosition();
        }
        return 0;
    }

    @Override
    public int getBufferPercentage_impl() {
        if (mDuration == 0) {
            return 0;
        }
        mPlaybackState = mController.getPlaybackState();
        if (mPlaybackState != null) {
            return (int) (mPlaybackState.getBufferedPosition() * 100) / mDuration;
        }
        return 0;
    }

    @Override
    public boolean canPause_impl() {
        if (mPlaybackState != null) {
            return (mPlaybackState.getActions() & PlaybackState.ACTION_PAUSE) != 0;
        }
        return true;
    }

    @Override
    public boolean canSeekBackward_impl() {
        if (mPlaybackState != null) {
            return (mPlaybackState.getActions() & PlaybackState.ACTION_REWIND) != 0;
        }
        return true;
    }

    @Override
    public boolean canSeekForward_impl() {
        if (mPlaybackState != null) {
            return (mPlaybackState.getActions() & PlaybackState.ACTION_FAST_FORWARD) != 0;
        }
        return true;
    }

    @Override
    public void showSubtitle_impl() {
        mController.sendCommand(ACTION_SHOW_SUBTITLE, null, null);
    }

    @Override
    public void hideSubtitle_impl() {
        mController.sendCommand(ACTION_HIDE_SUBTITLE, null, null);
    }

    @Override
    public void onAttachedToWindow_impl() {
        mSuperProvider.onAttachedToWindow_impl();
    }
    @Override
    public void onDetachedFromWindow_impl() {
        mSuperProvider.onDetachedFromWindow_impl();
    }

    @Override
    public CharSequence getAccessibilityClassName_impl() {
        return MediaControlView2.class.getName();
    }

    @Override
    public boolean onTouchEvent_impl(MotionEvent ev) {
        return false;
    }

    // TODO: Should this function be removed?
    @Override
    public boolean onTrackballEvent_impl(MotionEvent ev) {
        mInstance.show(DEFAULT_TIMEOUT_MS);
        return false;
    }

    @Override
    public boolean onKeyDown_impl(int keyCode, KeyEvent event) {
        return mSuperProvider.onKeyDown_impl(keyCode, event);
    }

    @Override
    public void onFinishInflate_impl() {
        mSuperProvider.onFinishInflate_impl();
    }

    @Override
    public boolean dispatchKeyEvent_impl(KeyEvent event) {
        int keyCode = event.getKeyCode();
        final boolean uniqueDown = event.getRepeatCount() == 0
                && event.getAction() == KeyEvent.ACTION_DOWN;
        if (keyCode == KeyEvent.KEYCODE_HEADSETHOOK
                || keyCode == KeyEvent.KEYCODE_MEDIA_PLAY_PAUSE
                || keyCode == KeyEvent.KEYCODE_SPACE) {
            if (uniqueDown) {
                togglePausePlayState();
                mInstance.show(DEFAULT_TIMEOUT_MS);
                if (mPlayPauseButton != null) {
                    mPlayPauseButton.requestFocus();
                }
            }
            return true;
        } else if (keyCode == KeyEvent.KEYCODE_MEDIA_PLAY) {
            if (uniqueDown && !mInstance.isPlaying()) {
                togglePausePlayState();
                mInstance.show(DEFAULT_TIMEOUT_MS);
            }
            return true;
        } else if (keyCode == KeyEvent.KEYCODE_MEDIA_STOP
                || keyCode == KeyEvent.KEYCODE_MEDIA_PAUSE) {
            if (uniqueDown && mInstance.isPlaying()) {
                togglePausePlayState();
                mInstance.show(DEFAULT_TIMEOUT_MS);
            }
            return true;
        } else if (keyCode == KeyEvent.KEYCODE_VOLUME_DOWN
                || keyCode == KeyEvent.KEYCODE_VOLUME_UP
                || keyCode == KeyEvent.KEYCODE_VOLUME_MUTE
                || keyCode == KeyEvent.KEYCODE_CAMERA) {
            // don't show the controls for volume adjustment
            return mSuperProvider.dispatchKeyEvent_impl(event);
        } else if (keyCode == KeyEvent.KEYCODE_BACK || keyCode == KeyEvent.KEYCODE_MENU) {
            if (uniqueDown) {
                mInstance.hide();
            }
            return true;
        }

        mInstance.show(DEFAULT_TIMEOUT_MS);
        return mSuperProvider.dispatchKeyEvent_impl(event);
    }

    @Override
    public void setEnabled_impl(boolean enabled) {
        if (mPlayPauseButton != null) {
            mPlayPauseButton.setEnabled(enabled);
        }
        if (mFfwdButton != null) {
            mFfwdButton.setEnabled(enabled);
        }
        if (mRewButton != null) {
            mRewButton.setEnabled(enabled);
        }
        if (mNextButton != null) {
            mNextButton.setEnabled(enabled && mNextListener != null);
        }
        if (mPrevButton != null) {
            mPrevButton.setEnabled(enabled && mPrevListener != null);
        }
        if (mProgress != null) {
            mProgress.setEnabled(enabled);
        }
        disableUnsupportedButtons();
        mSuperProvider.setEnabled_impl(enabled);
    }

    ///////////////////////////////////////////////////
    // Protected or private methods
    ///////////////////////////////////////////////////

    /**
     * Create the view that holds the widgets that control playback.
     * Derived classes can override this to create their own.
     *
     * @return The controller view.
     * @hide This doesn't work as advertised
     */
    protected View makeControllerView() {
        View root = LayoutInflater.from(mInstance.getContext()).inflate(
                R.layout.media_controller, null);

        initControllerView(root);

        return root;
    }

    private void initControllerView(View v) {
        Resources res = ApiHelper.getLibResources();
        mPlayDescription = res.getText(R.string.lockscreen_play_button_content_description);
        mPauseDescription = res.getText(R.string.lockscreen_pause_button_content_description);
        mReplayDescription = res.getText(R.string.lockscreen_replay_button_content_description);
        mPlayPauseButton = v.findViewById(R.id.pause);
        if (mPlayPauseButton != null) {
            mPlayPauseButton.requestFocus();
            mPlayPauseButton.setOnClickListener(mPlayPauseListener);
        }

        // TODO: make the following buttons visible based upon whether they are supported for
        // individual media files
        mFfwdButton = v.findViewById(R.id.ffwd);
        if (mFfwdButton != null) {
            mFfwdButton.setOnClickListener(mFfwdListener);
            mFfwdButton.setVisibility(View.GONE);
        }
        mRewButton = v.findViewById(R.id.rew);
        if (mRewButton != null) {
            mRewButton.setOnClickListener(mRewListener);
            mRewButton.setVisibility(View.GONE);
        }
        mNextButton = v.findViewById(R.id.next);
        if (mNextButton != null && !mListenersSet) {
            mNextButton.setVisibility(View.GONE);
        }
        mPrevButton = v.findViewById(R.id.prev);
        if (mPrevButton != null && !mListenersSet) {
            mPrevButton.setVisibility(View.GONE);
        }

        // TODO: make CC button visible if the media file has a subtitle track
        mCCButton = v.findViewById(R.id.cc);
        if (mCCButton != null) {
            mCCButton.setOnClickListener(mCCListener);
            mCCButton.setVisibility(mUseClosedCaption ? View.VISIBLE : View.GONE);
        }

        mProgress =
                v.findViewById(R.id.mediacontroller_progress);
        if (mProgress != null) {
            if (mProgress instanceof SeekBar) {
                SeekBar seeker = (SeekBar) mProgress;
                seeker.setOnSeekBarChangeListener(mSeekListener);
            }
            mProgress.setMax(MAX_PROGRESS);
        }

        mEndTime = v.findViewById(R.id.time);
        mCurrentTime = v.findViewById(R.id.time_current);
        mFormatBuilder = new StringBuilder();
        mFormatter = new Formatter(mFormatBuilder, Locale.getDefault());

        installPrevNextListeners();
    }

    /**
     * Disable pause or seek buttons if the stream cannot be paused or seeked.
     * This requires the control interface to be a MediaPlayerControlExt
     */
    private void disableUnsupportedButtons() {
        try {
            if (mPlayPauseButton != null && !mInstance.canPause()) {
                mPlayPauseButton.setEnabled(false);
            }
            if (mRewButton != null && !mInstance.canSeekBackward()) {
                mRewButton.setEnabled(false);
            }
            if (mFfwdButton != null && !mInstance.canSeekForward()) {
                mFfwdButton.setEnabled(false);
            }
            // TODO What we really should do is add a canSeek to the MediaPlayerControl interface;
            // this scheme can break the case when applications want to allow seek through the
            // progress bar but disable forward/backward buttons.
            //
            // However, currently the flags SEEK_BACKWARD_AVAILABLE, SEEK_FORWARD_AVAILABLE,
            // and SEEK_AVAILABLE are all (un)set together; as such the aforementioned issue
            // shouldn't arise in existing applications.
            if (mProgress != null && !mInstance.canSeekBackward() && !mInstance.canSeekForward()) {
                mProgress.setEnabled(false);
            }
        } catch (IncompatibleClassChangeError ex) {
            // We were given an old version of the interface, that doesn't have
            // the canPause/canSeekXYZ methods. This is OK, it just means we
            // assume the media can be paused and seeked, and so we don't disable
            // the buttons.
        }
    }

    private final Runnable mFadeOut = new Runnable() {
        @Override
        public void run() {
            mInstance.hide();
        }
    };

    private final Runnable mShowProgress = new Runnable() {
        @Override
        public void run() {
            int pos = setProgress();
            if (!mDragging && mShowing && mInstance.isPlaying()) {
                mInstance.postDelayed(mShowProgress,
                        DEFAULT_PROGRESS_UPDATE_TIME_MS - (pos % DEFAULT_PROGRESS_UPDATE_TIME_MS));
            }
        }
    };

    private String stringForTime(int timeMs) {
        int totalSeconds = timeMs / 1000;

        int seconds = totalSeconds % 60;
        int minutes = (totalSeconds / 60) % 60;
        int hours = totalSeconds / 3600;

        mFormatBuilder.setLength(0);
        if (hours > 0) {
            return mFormatter.format("%d:%02d:%02d", hours, minutes, seconds).toString();
        } else {
            return mFormatter.format("%02d:%02d", minutes, seconds).toString();
        }
    }

    private int setProgress() {
        if (mController == null || mDragging) {
            return 0;
        }
        int positionOnProgressBar = 0;
        int currentPosition = mInstance.getCurrentPosition();
        if (mDuration > 0) {
            positionOnProgressBar = (int) (MAX_PROGRESS * (long) currentPosition / mDuration);
        }
        if (mProgress != null && currentPosition != mDuration) {
            mProgress.setProgress(positionOnProgressBar);
            mProgress.setSecondaryProgress(mInstance.getBufferPercentage() * 10);
        }

        if (mEndTime != null) {
            mEndTime.setText(stringForTime(mDuration));

        }
        if (mCurrentTime != null) {
            mCurrentTime.setText(stringForTime(currentPosition));
        }

        return currentPosition;
    }

    private void togglePausePlayState() {
        if (mInstance.isPlaying()) {
            mControls.pause();
            mPlayPauseButton.setImageResource(R.drawable.ic_play_circle_filled);
            mPlayPauseButton.setContentDescription(mPlayDescription);
        } else {
            mControls.play();
            mPlayPauseButton.setImageResource(R.drawable.ic_pause_circle_filled);
            mPlayPauseButton.setContentDescription(mPauseDescription);
        }
    }

    // There are two scenarios that can trigger the seekbar listener to trigger:
    //
    // The first is the user using the touchpad to adjust the posititon of the
    // seekbar's thumb. In this case onStartTrackingTouch is called followed by
    // a number of onProgressChanged notifications, concluded by onStopTrackingTouch.
    // We're setting the field "mDragging" to true for the duration of the dragging
    // session to avoid jumps in the position in case of ongoing playback.
    //
    // The second scenario involves the user operating the scroll ball, in this
    // case there WON'T BE onStartTrackingTouch/onStopTrackingTouch notifications,
    // we will simply apply the updated position without suspending regular updates.
    private final OnSeekBarChangeListener mSeekListener = new OnSeekBarChangeListener() {
        @Override
        public void onStartTrackingTouch(SeekBar bar) {
            mInstance.show(3600000);

            mDragging = true;

            // By removing these pending progress messages we make sure
            // that a) we won't update the progress while the user adjusts
            // the seekbar and b) once the user is done dragging the thumb
            // we will post one of these messages to the queue again and
            // this ensures that there will be exactly one message queued up.
            mInstance.removeCallbacks(mShowProgress);

            // Check if playback is currently stopped. In this case, update the pause button to show
            // the play image instead of the replay image.
            if (mIsStopped) {
                mPlayPauseButton.setImageResource(R.drawable.ic_play_circle_filled);
                mPlayPauseButton.setContentDescription(mPlayDescription);
                mIsStopped = false;
            }
        }

        @Override
        public void onProgressChanged(SeekBar bar, int progress, boolean fromUser) {
            if (!fromUser) {
                // We're not interested in programmatically generated changes to
                // the progress bar's position.
                return;
            }
            if (mDuration > 0) {
                int newPosition = (int) (((long) mDuration * progress) / MAX_PROGRESS);
                mControls.seekTo(newPosition);

                if (mCurrentTime != null) {
                    mCurrentTime.setText(stringForTime(newPosition));
                }
            }
        }

        @Override
        public void onStopTrackingTouch(SeekBar bar) {
            mDragging = false;

            setProgress();
            mInstance.show(DEFAULT_TIMEOUT_MS);

            // Ensure that progress is properly updated in the future,
            // the call to show() does not guarantee this because it is a
            // no-op if we are already showing.
            mInstance.post(mShowProgress);
        }
    };

    private final View.OnClickListener mPlayPauseListener = new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            togglePausePlayState();
            mInstance.show(DEFAULT_TIMEOUT_MS);
        }
    };

    private final View.OnClickListener mRewListener = new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            int pos = mInstance.getCurrentPosition() - REWIND_TIME_MS;
            mControls.seekTo(pos);
            setProgress();

            mInstance.show(DEFAULT_TIMEOUT_MS);
        }
    };

    private final View.OnClickListener mFfwdListener = new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            int pos = mInstance.getCurrentPosition() + FORWARD_TIME_MS;
            mControls.seekTo(pos);
            setProgress();

            mInstance.show(DEFAULT_TIMEOUT_MS);
        }
    };

    private final View.OnClickListener mCCListener = new View.OnClickListener() {
        @Override
        public void onClick(View v) {
            if (!mCCIsEnabled) {
                mCCButton.setImageResource(R.drawable.ic_media_cc_enabled);
                mCCIsEnabled = true;
                mInstance.showSubtitle();
            } else {
                mCCButton.setImageResource(R.drawable.ic_media_cc_disabled);
                mCCIsEnabled = false;
                mInstance.hideSubtitle();
            }
        }
    };

    private void installPrevNextListeners() {
        if (mNextButton != null) {
            mNextButton.setOnClickListener(mNextListener);
            mNextButton.setEnabled(mNextListener != null);
        }

        if (mPrevButton != null) {
            mPrevButton.setOnClickListener(mPrevListener);
            mPrevButton.setEnabled(mPrevListener != null);
        }
    }

    private void updateDuration() {
        if (mMetadata != null) {
            if (mMetadata.containsKey(MediaMetadata.METADATA_KEY_DURATION)) {
                mDuration = (int) mMetadata.getLong(MediaMetadata.METADATA_KEY_DURATION);
                // update progress bar
                setProgress();
            }
        }
    }

    private class MediaControllerCallback extends MediaController.Callback {
        @Override
        public void onPlaybackStateChanged(PlaybackState state) {
            mPlaybackState = state;

            // Update pause button depending on playback state for the following two reasons:
            //   1) Need to handle case where app customizes playback state behavior when app
            //      activity is resumed.
            //   2) Need to handle case where the media file reaches end of duration.
            if (mPlaybackState.getState() != mPrevState) {
                switch (mPlaybackState.getState()) {
                    case PlaybackState.STATE_PLAYING:
                        mPlayPauseButton.setImageResource(R.drawable.ic_pause_circle_filled);
                        mPlayPauseButton.setContentDescription(mPauseDescription);
                        break;
                    case PlaybackState.STATE_PAUSED:
                        mPlayPauseButton.setImageResource(R.drawable.ic_play_circle_filled);
                        mPlayPauseButton.setContentDescription(mPlayDescription);
                        break;
                    case PlaybackState.STATE_STOPPED:
                        mPlayPauseButton.setImageResource(R.drawable.ic_replay);
                        mPlayPauseButton.setContentDescription(mReplayDescription);
                        mIsStopped = true;
                        break;
                    default:
                        break;
                }
                mPrevState = mPlaybackState.getState();
            }
        }

        @Override
        public void onMetadataChanged(MediaMetadata metadata) {
            mMetadata = metadata;
            updateDuration();
        }
    }
}