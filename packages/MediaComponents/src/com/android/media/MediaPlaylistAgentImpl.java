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

import android.annotation.CallbackExecutor;
import android.annotation.NonNull;
import android.annotation.Nullable;
import android.content.Context;
import android.media.MediaItem2;
import android.media.MediaMetadata2;
import android.media.MediaPlaylistAgent;
import android.media.MediaPlaylistAgent.PlaylistEventCallback;
import android.media.update.MediaPlaylistAgentProvider;

import java.util.List;
import java.util.concurrent.Executor;

public class MediaPlaylistAgentImpl implements MediaPlaylistAgentProvider {
    private final Context mContext;
    private final MediaPlaylistAgent mInstance;

    public MediaPlaylistAgentImpl(Context context, MediaPlaylistAgent instance) {
        mContext = context;
        mInstance = instance;
    }

    final public void registerPlaylistEventCallback_impl(
            @NonNull @CallbackExecutor Executor executor, @NonNull PlaylistEventCallback callback) {
        if (executor == null) {
            throw new IllegalArgumentException("executor shouldn't be null");
        }
        if (callback == null) {
            throw new IllegalArgumentException("callback shouldn't be null");
        }
        // TODO(jaewan): implement this (b/74090741)
    }

    final public void unregisterPlaylistEventCallback_impl(
            @NonNull PlaylistEventCallback callback) {
        if (callback == null) {
            throw new IllegalArgumentException("callback shouldn't be null");
        }
        // TODO(jaewan): implement this (b/74090741)
    }

    final public void notifyPlaylistChanged_impl() {
        // TODO(jaewan): implement this (b/74090741)
    }

    final public void notifyPlaylistMetadataChanged_impl() {
        // TODO(jaewan): implement this (b/74090741)
    }

    final public void notifyShuffleModeChanged_impl() {
        // TODO(jaewan): implement this (b/74090741)
    }

    final public void notifyRepeatModeChanged_impl() {
        // TODO(jaewan): implement this (b/74090741)
    }

    public @Nullable List<MediaItem2> getPlaylist_impl() {
        // TODO(jaewan): implement this (b/74090741)
        return null;
    }

    public void setPlaylist_impl(@NonNull List<MediaItem2> list,
            @Nullable MediaMetadata2 metadata) {
        if (list == null) {
            throw new IllegalArgumentException("list shouldn't be null");
        }
        // TODO(jaewan): implement this (b/74090741)
    }

    public @Nullable MediaMetadata2 getPlaylistMetadata_impl() {
        // TODO(jaewan): implement this (b/74090741)
        return null;
    }

    public void updatePlaylistMetadata_impl(@Nullable MediaMetadata2 metadata) {
        // TODO(jaewan): implement this (b/74090741)
    }

    public void addPlaylistItem_impl(int index, @NonNull MediaItem2 item) {
        if (item == null) {
            throw new IllegalArgumentException("item shouldn't be null");
        }
        // TODO(jaewan): implement this (b/74090741)
    }

    public void removePlaylistItem_impl(@NonNull MediaItem2 item) {
        if (item == null) {
            throw new IllegalArgumentException("item shouldn't be null");
        }
        // TODO(jaewan): implement this (b/74090741)
    }

    public void replacePlaylistItem_impl(int index, @NonNull MediaItem2 item) {
        if (index < 0) {
            throw new IllegalArgumentException("index can not have a negative value");
        }
        if (item == null) {
            throw new IllegalArgumentException("item shouldn't be null");
        }
        // TODO(jaewan): implement this (b/74090741)
    }

    public void skipToPlaylistItem_impl(@NonNull MediaItem2 item) {
        if (item == null) {
            throw new IllegalArgumentException("item shouldn't be null");
        }
        // TODO(jaewan): implement this (b/74090741)
    }

    public void skipToPreviousItem_impl() {
        // TODO(jaewan): implement this (b/74090741)
    }

    public void skipToNextItem_impl() {
        // TODO(jaewan): implement this (b/74090741)
    }

    public int getRepeatMode_impl() {
        // TODO(jaewan): implement this (b/74090741)
        return MediaPlaylistAgent.REPEAT_MODE_NONE;
    }

    public void setRepeatMode_impl(int repeatMode) {
        // TODO(jaewan): implement this (b/74090741)
    }

    public int getShuffleMode_impl() {
        // TODO(jaewan): implement this (b/74090741)
        return MediaPlaylistAgent.SHUFFLE_MODE_NONE;
    }

    public void setShuffleMode_impl(int shuffleMode) {
        // TODO(jaewan): implement this (b/74090741)
    }
}
