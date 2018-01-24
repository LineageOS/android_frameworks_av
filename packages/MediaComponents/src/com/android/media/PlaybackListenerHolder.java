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

import android.media.MediaPlayerBase;
import android.media.MediaPlayerBase.PlaybackListener;
import android.media.session.PlaybackState;
import android.os.Handler;
import android.os.Message;
import android.support.annotation.NonNull;
import java.util.List;

/**
 * Holds {@link android.media.MediaPlayerBase.PlaybackListener} with the {@link Handler}.
 */
public class PlaybackListenerHolder extends Handler {
    private static final int ON_PLAYBACK_CHANGED = 1;

    public final MediaPlayerBase.PlaybackListener listener;

    public PlaybackListenerHolder(
            @NonNull MediaPlayerBase.PlaybackListener listener, @NonNull Handler handler) {
        super(handler.getLooper());
        this.listener = listener;
    }

    @Override
    public void handleMessage(Message msg) {
        switch (msg.what) {
            case ON_PLAYBACK_CHANGED:
                listener.onPlaybackChanged((PlaybackState) msg.obj);
                break;
        }
    }

    public void postPlaybackChange(PlaybackState state) {
        obtainMessage(ON_PLAYBACK_CHANGED, state).sendToTarget();
    }

    /**
     * Returns {@code true} if the given list contains a {@link PlaybackListenerHolder} that holds
     * the given listener.
     *
     * @param list list to check
     * @param listener listener to check
     * @return {@code true} if the given list contains listener. {@code false} otherwise.
     */
    public static <Holder extends PlaybackListenerHolder> boolean contains(
            @NonNull List<Holder> list, PlaybackListener listener) {
        return indexOf(list, listener) >= 0;
    }

    /**
     * Returns the index of the {@link PlaybackListenerHolder} that contains the given listener.
     *
     * @param list list to check
     * @param listener listener to check
     * @return {@code index} of item if the given list contains listener. {@code -1} otherwise.
     */
    public static <Holder extends PlaybackListenerHolder> int indexOf(
            @NonNull List<Holder> list, PlaybackListener listener) {
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).listener == listener) {
                return i;
            }
        }
        return -1;
    }
}
