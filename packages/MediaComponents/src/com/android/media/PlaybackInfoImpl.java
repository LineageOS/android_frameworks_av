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

package com.android.media;

import android.content.Context;
import android.media.AudioAttributes;
import android.media.MediaController2.PlaybackInfo;
import android.media.update.PlaybackInfoProvider;
import android.os.Bundle;

public final class PlaybackInfoImpl implements PlaybackInfoProvider {

    private static final String KEY_PLAYBACK_TYPE =
            "android.media.playbackinfo_impl.playback_type";
    private static final String KEY_CONTROL_TYPE =
            "android.media.playbackinfo_impl.control_type";
    private static final String KEY_MAX_VOLUME =
            "android.media.playbackinfo_impl.max_volume";
    private static final String KEY_CURRENT_VOLUME =
            "android.media.playbackinfo_impl.current_volume";
    private static final String KEY_AUDIO_ATTRIBUTES =
            "android.media.playbackinfo_impl.audio_attrs";

    private final Context mContext;
    private final PlaybackInfo mInstance;

    private final int mPlaybackType;
    private final int mControlType;
    private final int mMaxVolume;
    private final int mCurrentVolume;
    private final AudioAttributes mAudioAttrs;

    private PlaybackInfoImpl(Context context, int playbackType, AudioAttributes attrs,
            int controlType, int max, int current) {
        mContext = context;
        mPlaybackType = playbackType;
        mAudioAttrs = attrs;
        mControlType = controlType;
        mMaxVolume = max;
        mCurrentVolume = current;
        mInstance = new PlaybackInfo(this);
    }

    @Override
    public int getPlaybackType_impl() {
        return mPlaybackType;
    }

    @Override
    public AudioAttributes getAudioAttributes_impl() {
        return mAudioAttrs;
    }

    @Override
    public int getControlType_impl() {
        return mControlType;
    }

    @Override
    public int getMaxVolume_impl() {
        return mMaxVolume;
    }

    @Override
    public int getCurrentVolume_impl() {
        return mCurrentVolume;
    }

    public PlaybackInfo getInstance() {
        return mInstance;
    }

    public Bundle toBundle() {
        Bundle bundle = new Bundle();
        bundle.putInt(KEY_PLAYBACK_TYPE, mPlaybackType);
        bundle.putInt(KEY_CONTROL_TYPE, mControlType);
        bundle.putInt(KEY_MAX_VOLUME, mMaxVolume);
        bundle.putInt(KEY_CURRENT_VOLUME, mCurrentVolume);
        bundle.putParcelable(KEY_AUDIO_ATTRIBUTES, mAudioAttrs);
        return bundle;
    }

    public static PlaybackInfo createPlaybackInfo(Context context, int playbackType,
            AudioAttributes attrs, int controlType, int max, int current) {
        return new PlaybackInfoImpl(context, playbackType, attrs, controlType, max, current)
                .getInstance();
    }

    public static PlaybackInfo fromBundle(Context context, Bundle bundle) {
        if (bundle == null) {
            return null;
        }
        final int volumeType = bundle.getInt(KEY_PLAYBACK_TYPE);
        final int volumeControl = bundle.getInt(KEY_CONTROL_TYPE);
        final int maxVolume = bundle.getInt(KEY_MAX_VOLUME);
        final int currentVolume = bundle.getInt(KEY_CURRENT_VOLUME);
        final AudioAttributes attrs = bundle.getParcelable(KEY_AUDIO_ATTRIBUTES);

        return createPlaybackInfo(
                context, volumeType, attrs, volumeControl, maxVolume, currentVolume);
    }
}
