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
import android.media.PlaybackState2;
import android.media.update.PlaybackState2Provider;
import android.os.Bundle;

public final class PlaybackState2Impl implements PlaybackState2Provider {
    /**
     * Keys used for converting a PlaybackState2 to a bundle object and vice versa.
     */
    private static final String KEY_STATE = "android.media.playbackstate2.state";
    private static final String KEY_POSITION = "android.media.playbackstate2.position";
    private static final String KEY_BUFFERED_POSITION =
            "android.media.playbackstate2.buffered_position";
    private static final String KEY_SPEED = "android.media.playbackstate2.speed";
    private static final String KEY_ERROR_MESSAGE = "android.media.playbackstate2.error_message";
    private static final String KEY_UPDATE_TIME = "android.media.playbackstate2.update_time";
    private static final String KEY_ACTIVE_ITEM_ID = "android.media.playbackstate2.active_item_id";

    private final Context mContext;
    private final PlaybackState2 mInstance;
    private final int mState;
    private final long mPosition;
    private final long mUpdateTime;
    private final float mSpeed;
    private final long mBufferedPosition;
    private final long mActiveItemId;
    private final CharSequence mErrorMessage;

    public PlaybackState2Impl(Context context, PlaybackState2 instance, int state, long position,
            long updateTime, float speed, long bufferedPosition, long activeItemId,
            CharSequence error) {
        mContext = context;
        mInstance = instance;
        mState = state;
        mPosition = position;
        mSpeed = speed;
        mUpdateTime = updateTime;
        mBufferedPosition = bufferedPosition;
        mActiveItemId = activeItemId;
        mErrorMessage = error;
    }

    @Override
    public String toString_impl() {
        StringBuilder bob = new StringBuilder("PlaybackState {");
        bob.append("state=").append(mState);
        bob.append(", position=").append(mPosition);
        bob.append(", buffered position=").append(mBufferedPosition);
        bob.append(", speed=").append(mSpeed);
        bob.append(", updated=").append(mUpdateTime);
        bob.append(", active item id=").append(mActiveItemId);
        bob.append(", error=").append(mErrorMessage);
        bob.append("}");
        return bob.toString();
    }

    @Override
    public int getState_impl() {
        return mState;
    }

    @Override
    public long getPosition_impl() {
        return mPosition;
    }

    @Override
    public long getBufferedPosition_impl() {
        return mBufferedPosition;
    }

    @Override
    public float getPlaybackSpeed_impl() {
        return mSpeed;
    }

    @Override
    public CharSequence getErrorMessage_impl() {
        return mErrorMessage;
    }

    @Override
    public long getLastPositionUpdateTime_impl() {
        return mUpdateTime;
    }

    @Override
    public long getCurrentPlaylistItemIndex_impl() {
        return mActiveItemId;
    }

    @Override
    public Bundle toBundle_impl() {
        Bundle bundle = new Bundle();
        bundle.putInt(KEY_STATE, mState);
        bundle.putLong(KEY_POSITION, mPosition);
        bundle.putLong(KEY_UPDATE_TIME, mUpdateTime);
        bundle.putFloat(KEY_SPEED, mSpeed);
        bundle.putLong(KEY_BUFFERED_POSITION, mBufferedPosition);
        bundle.putLong(KEY_ACTIVE_ITEM_ID, mActiveItemId);
        bundle.putCharSequence(KEY_ERROR_MESSAGE, mErrorMessage);
        return bundle;
    }

    public static PlaybackState2 fromBundle(Context context, Bundle bundle) {
        if (bundle == null) {
            return null;
        }
        if (!bundle.containsKey(KEY_STATE)
                || !bundle.containsKey(KEY_POSITION)
                || !bundle.containsKey(KEY_UPDATE_TIME)
                || !bundle.containsKey(KEY_SPEED)
                || !bundle.containsKey(KEY_BUFFERED_POSITION)
                || !bundle.containsKey(KEY_ACTIVE_ITEM_ID)
                || !bundle.containsKey(KEY_ERROR_MESSAGE)) {
            return null;
        }

        return new PlaybackState2(context,
                bundle.getInt(KEY_STATE),
                bundle.getLong(KEY_POSITION),
                bundle.getLong(KEY_UPDATE_TIME),
                bundle.getFloat(KEY_SPEED),
                bundle.getLong(KEY_BUFFERED_POSITION),
                bundle.getLong(KEY_ACTIVE_ITEM_ID),
                bundle.getCharSequence(KEY_ERROR_MESSAGE));
    }
}