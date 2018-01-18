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

import android.graphics.Canvas;
import android.media.AudioAttributes;
import android.media.AudioFocusRequest;
import android.media.MediaPlayer;
import android.media.update.VideoView2Provider;
import android.media.update.ViewProvider;
import android.net.Uri;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.widget.MediaController2;
import android.widget.VideoView2;

import java.util.Map;

public class VideoView2Impl implements VideoView2Provider, VideoViewInterface.SurfaceListener {

    private final VideoView2 mInstance;
    private final ViewProvider mSuperProvider;

    public VideoView2Impl(VideoView2 instance, ViewProvider superProvider) {
        mInstance = instance;
        mSuperProvider = superProvider;

        // TODO: Implement
    }

    @Override
    public void start_impl() {
        // TODO: Implement
    }

    @Override
    public void pause_impl() {
        // TODO: Implement
    }

    @Override
    public int getDuration_impl() {
        // TODO: Implement
        return -1;
    }

    @Override
    public int getCurrentPosition_impl() {
        // TODO: Implement
        return 0;
    }

    @Override
    public void seekTo_impl(int msec) {
        // TODO: Implement
    }

    @Override
    public boolean isPlaying_impl() {
        // TODO: Implement
        return false;
    }

    @Override
    public int getBufferPercentage_impl() {
        return -1;
    }

    @Override
    public int getAudioSessionId_impl() {
        // TODO: Implement
        return 0;
    }

    @Override
    public void showSubtitle_impl() {
        // TODO: Implement
    }

    @Override
    public void hideSubtitle_impl() {
        // TODO: Implement
    }

    @Override
    public void setAudioFocusRequest_impl(int focusGain) {
        // TODO: Implement
    }

    @Override
    public void setAudioAttributes_impl(AudioAttributes attributes) {
        // TODO: Implement
    }

    @Override
    public void setVideoPath_impl(String path) {
        // TODO: Implement
    }

    @Override
    public void setVideoURI_impl(Uri uri) {
        // TODO: Implement
    }

    @Override
    public void setVideoURI_impl(Uri uri, Map<String, String> headers) {
        // TODO: Implement
    }

    @Override
    public void setMediaController2_impl(MediaController2 controllerView) {
        // TODO: Implement
    }

    @Override
    public void setViewType_impl(int viewType) {
        // TODO: Implement
    }

    @Override
    public int getViewType_impl() {
        // TODO: Implement
        return -1;
    }

    @Override
    public void stopPlayback_impl() {
        // TODO: Implement
    }

    @Override
    public void setOnPreparedListener_impl(MediaPlayer.OnPreparedListener l) {
        // TODO: Implement
    }

    @Override
    public void setOnCompletionListener_impl(MediaPlayer.OnCompletionListener l) {
        // TODO: Implement
    }

    @Override
    public void setOnErrorListener_impl(MediaPlayer.OnErrorListener l) {
        // TODO: Implement
    }

    @Override
    public void setOnInfoListener_impl(MediaPlayer.OnInfoListener l) {
        // TODO: Implement
    }

    @Override
    public void setOnViewTypeChangedListener_impl(VideoView2.OnViewTypeChangedListener l) {
        // TODO: Implement
    }

    @Override
    public void onAttachedToWindow_impl() {
        mSuperProvider.onAttachedToWindow_impl();
        // TODO: Implement
    }

    @Override
    public void onDetachedFromWindow_impl() {
        mSuperProvider.onDetachedFromWindow_impl();
        // TODO: Implement
    }

    @Override
    public void onLayout_impl(boolean changed, int left, int top, int right, int bottom) {
        mSuperProvider.onLayout_impl(changed, left, top, right, bottom);
        // TODO: Implement
    }

    @Override
    public void draw_impl(Canvas canvas) {
        mSuperProvider.draw_impl(canvas);
        // TODO: Implement
    }

    @Override
    public CharSequence getAccessibilityClassName_impl() {
        // TODO: Implement
        return null;
    }

    @Override
    public boolean onTouchEvent_impl(MotionEvent ev) {
        // TODO: Implement
        return false;
    }

    @Override
    public boolean onTrackballEvent_impl(MotionEvent ev) {
        // TODO: Implement
        return false;
    }

    @Override
    public boolean onKeyDown_impl(int keyCode, KeyEvent event) {
        // TODO: Implement
        return false;
    }

    @Override
    public void onFinishInflate_impl() {
        // TODO: Implement
    }

    @Override
    public boolean dispatchKeyEvent_impl(KeyEvent event) {
        // TODO: Implement
        return false;
    }

    @Override
    public void setEnabled_impl(boolean enabled) {
        // TODO: Implement
    }

    ///////////////////////////////////////////////////
    // Implements VideoViewInterface.SurfaceListener
    ///////////////////////////////////////////////////

    @Override
    public void onSurfaceCreated(View view, int width, int height) {
        // TODO: Implement
    }

    @Override
    public void onSurfaceDestroyed(View view) {
        // TODO: Implement
    }

    @Override
    public void onSurfaceChanged(View view, int width, int height) {
        // TODO: Implement
    }

    @Override
    public void onSurfaceTakeOverDone(VideoViewInterface view) {
        // TODO: Implement
    }
}
