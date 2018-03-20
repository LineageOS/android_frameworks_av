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

import android.annotation.NonNull;
import android.annotation.Nullable;
import android.content.Context;
import android.media.DataSourceDesc;
import android.media.MediaItem2;
import android.media.MediaMetadata2;
import android.media.MediaPlayerBase;
import android.media.MediaPlaylistAgent;
import android.media.MediaSession2.OnDataSourceMissingHelper;
import android.util.ArrayMap;

import com.android.internal.annotations.GuardedBy;
import com.android.internal.annotations.VisibleForTesting;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

public class SessionPlaylistAgent extends MediaPlaylistAgent {
    private static final String TAG = "SessionPlaylistAgent";
    @VisibleForTesting
    static final int END_OF_PLAYLIST = -1;
    @VisibleForTesting
    static final int NO_VALID_ITEMS = -2;

    private final PlayItem mEopPlayItem = new PlayItem(END_OF_PLAYLIST, null);

    private final Object mLock = new Object();
    private final MediaSession2Impl mSessionImpl;

    // TODO: Set data sources properly into mPlayer (b/74090741)
    @GuardedBy("mLock")
    private MediaPlayerBase mPlayer;
    @GuardedBy("mLock")
    private OnDataSourceMissingHelper mDsmHelper;
    // TODO: Check if having the same item is okay (b/74090741)
    @GuardedBy("mLock")
    private ArrayList<MediaItem2> mPlaylist = new ArrayList<>();
    @GuardedBy("mLock")
    private ArrayList<MediaItem2> mShuffledList = new ArrayList<>();
    @GuardedBy("mLock")
    private Map<MediaItem2, DataSourceDesc> mItemDsdMap = new ArrayMap<>();
    @GuardedBy("mLock")
    private MediaMetadata2 mMetadata;
    @GuardedBy("mLock")
    private int mRepeatMode;
    @GuardedBy("mLock")
    private int mShuffleMode;
    @GuardedBy("mLock")
    private PlayItem mCurrent;

    private class PlayItem {
        int shuffledIdx;
        DataSourceDesc dsd;
        MediaItem2 mediaItem;

        PlayItem(int shuffledIdx) {
            this(shuffledIdx, null);
        }

        PlayItem(int shuffledIdx, DataSourceDesc dsd) {
            this.shuffledIdx = shuffledIdx;
            if (shuffledIdx >= 0) {
                this.mediaItem = mShuffledList.get(shuffledIdx);
                if (dsd == null) {
                    synchronized (mLock) {
                        this.dsd = retrieveDataSourceDescLocked(this.mediaItem);
                    }
                } else {
                    this.dsd = dsd;
                }
            }
        }

        boolean isValid() {
            if (this == mEopPlayItem) {
                return true;
            }
            if (mediaItem == null) {
                return false;
            }
            if (dsd == null) {
                return false;
            }
            if (shuffledIdx >= mShuffledList.size()) {
                return false;
            }
            if (mediaItem != mShuffledList.get(shuffledIdx)) {
                return false;
            }
            if (mediaItem.getDataSourceDesc() != null
                    && !mediaItem.getDataSourceDesc().equals(dsd)) {
                return false;
            }
            return true;
        }
    }

    public SessionPlaylistAgent(@NonNull Context context, @NonNull MediaSession2Impl sessionImpl,
            @NonNull MediaPlayerBase player) {
        super(context);
        if (sessionImpl == null) {
            throw new IllegalArgumentException("sessionImpl shouldn't be null");
        }
        if (player == null) {
            throw new IllegalArgumentException("player shouldn't be null");
        }
        mSessionImpl = sessionImpl;
        mPlayer = player;
    }

    public void setPlayer(MediaPlayerBase player) {
        if (player == null) {
            throw new IllegalArgumentException("player shouldn't be null");
        }
        synchronized (mLock) {
            mPlayer = player;
        }
    }

    public void setOnDataSourceMissingHelper(OnDataSourceMissingHelper helper) {
        synchronized (mLock) {
            mDsmHelper = helper;
        }
    }

    public void clearOnDataSourceMissingHelper() {
        synchronized (mLock) {
            mDsmHelper = null;
        }
    }

    @Override
    public @Nullable List<MediaItem2> getPlaylist() {
        synchronized (mLock) {
            return Collections.unmodifiableList(mPlaylist);
        }
    }

    @Override
    public void setPlaylist(@NonNull List<MediaItem2> list, @Nullable MediaMetadata2 metadata) {
        if (list == null) {
            throw new IllegalArgumentException("list shouldn't be null");
        }

        synchronized (mLock) {
            mItemDsdMap.clear();

            mPlaylist.clear();
            mPlaylist.addAll(list);
            applyShuffleModeLocked();

            mMetadata = metadata;
            mCurrent = getNextValidPlayItemLocked(END_OF_PLAYLIST, 1);
        }
        notifyPlaylistChanged();
    }

    @Override
    public @Nullable MediaMetadata2 getPlaylistMetadata() {
        return mMetadata;
    }

    @Override
    public void updatePlaylistMetadata(@Nullable MediaMetadata2 metadata) {
        synchronized (mLock) {
            if (metadata == mMetadata) {
                return;
            }
            mMetadata = metadata;
        }
        notifyPlaylistMetadataChanged();
    }

    @Override
    public void addPlaylistItem(int index, @NonNull MediaItem2 item) {
        if (item == null) {
            throw new IllegalArgumentException("item shouldn't be null");
        }
        synchronized (mLock) {
            index = clamp(index, mPlaylist.size());
            int shuffledIdx = index;
            mPlaylist.add(index, item);
            if (mShuffleMode == MediaPlaylistAgent.SHUFFLE_MODE_NONE) {
                mShuffledList.add(index, item);
            } else {
                // Add the item in random position of mShuffledList.
                shuffledIdx = ThreadLocalRandom.current().nextInt(mShuffledList.size() + 1);
                mShuffledList.add(shuffledIdx, item);
            }
            if (!hasValidItem()) {
                mCurrent = getNextValidPlayItemLocked(END_OF_PLAYLIST, 1);
            } else {
                updateCurrentIfNeededLocked();
            }
        }
        notifyPlaylistChanged();
    }

    @Override
    public void removePlaylistItem(@NonNull MediaItem2 item) {
        if (item == null) {
            throw new IllegalArgumentException("item shouldn't be null");
        }
        synchronized (mLock) {
            if (!mPlaylist.remove(item)) {
                return;
            }
            mShuffledList.remove(item);
            mItemDsdMap.remove(item);
            updateCurrentIfNeededLocked();
        }
        notifyPlaylistChanged();
    }

    @Override
    public void replacePlaylistItem(int index, @NonNull MediaItem2 item) {
        if (item == null) {
            throw new IllegalArgumentException("item shouldn't be null");
        }
        synchronized (mLock) {
            if (mPlaylist.size() <= 0) {
                return;
            }
            index = clamp(index, mPlaylist.size() - 1);
            int shuffledIdx = mShuffledList.indexOf(mPlaylist.get(index));
            mItemDsdMap.remove(mShuffledList.get(shuffledIdx));
            mShuffledList.set(shuffledIdx, item);
            mPlaylist.set(index, item);
            if (!hasValidItem()) {
                mCurrent = getNextValidPlayItemLocked(END_OF_PLAYLIST, 1);
            } else {
                updateCurrentIfNeededLocked();
            }
        }
        notifyPlaylistChanged();
    }

    @Override
    public void skipToPlaylistItem(@NonNull MediaItem2 item) {
        if (item == null) {
            throw new IllegalArgumentException("item shouldn't be null");
        }
        synchronized (mLock) {
            if (!hasValidItem() || item.equals(mCurrent.mediaItem)) {
                return;
            }
            int shuffledIdx = mShuffledList.indexOf(item);
            if (shuffledIdx < 0) {
                return;
            }
            mCurrent = new PlayItem(shuffledIdx);
            updateCurrentIfNeededLocked();
        }
    }

    @Override
    public void skipToPreviousItem() {
        synchronized (mLock) {
            if (!hasValidItem()) {
                return;
            }
            PlayItem prev = getNextValidPlayItemLocked(mCurrent.shuffledIdx, -1);
            if (prev != mEopPlayItem) {
                mCurrent = prev;
            }
            updateCurrentIfNeededLocked();
       }
    }

    @Override
    public void skipToNextItem() {
        synchronized (mLock) {
            if (!hasValidItem()) {
                return;
            }
            PlayItem next = getNextValidPlayItemLocked(mCurrent.shuffledIdx, 1);
            if (next != mEopPlayItem) {
                mCurrent = next;
            }
            updateCurrentIfNeededLocked();
        }
    }

    @Override
    public int getRepeatMode() {
        return mRepeatMode;
    }

    @Override
    public void setRepeatMode(int repeatMode) {
        if (repeatMode < MediaPlaylistAgent.REPEAT_MODE_NONE
                || repeatMode > MediaPlaylistAgent.REPEAT_MODE_GROUP) {
            return;
        }
        synchronized (mLock) {
            if (mRepeatMode == repeatMode) {
                return;
            }
            mRepeatMode = repeatMode;
        }
        notifyRepeatModeChanged();
    }

    @Override
    public int getShuffleMode() {
        return mShuffleMode;
    }

    @Override
    public void setShuffleMode(int shuffleMode) {
        if (shuffleMode < MediaPlaylistAgent.SHUFFLE_MODE_NONE
                || shuffleMode > MediaPlaylistAgent.SHUFFLE_MODE_GROUP) {
            return;
        }
        synchronized (mLock) {
            if (mShuffleMode == shuffleMode) {
                return;
            }
            mShuffleMode = shuffleMode;
            applyShuffleModeLocked();
        }
        notifyShuffleModeChanged();
    }

    @VisibleForTesting
    int getCurShuffledIndex() {
        return hasValidItem() ? mCurrent.shuffledIdx : NO_VALID_ITEMS;
    }

    private boolean hasValidItem() {
        return mCurrent != null;
    }

    private DataSourceDesc retrieveDataSourceDescLocked(MediaItem2 item) {
        DataSourceDesc dsd = item.getDataSourceDesc();
        if (dsd != null) {
            mItemDsdMap.put(item, dsd);
            return dsd;
        }
        dsd = mItemDsdMap.get(item);
        if (dsd != null) {
            return dsd;
        }
        OnDataSourceMissingHelper helper = mDsmHelper;
        if (helper != null) {
            // TODO: Do not call onDataSourceMissing with the lock (b/74090741).
            dsd = helper.onDataSourceMissing(mSessionImpl.getInstance(), item);
            if (dsd != null) {
                mItemDsdMap.put(item, dsd);
            }
        }
        return dsd;
    }

    private PlayItem getNextValidPlayItemLocked(int curShuffledIdx, int direction) {
        int size = mPlaylist.size();
        if (curShuffledIdx == END_OF_PLAYLIST) {
            curShuffledIdx = (direction > 0) ? -1 : size;
        }
        for (int i = 0; i < size; i++) {
            curShuffledIdx += direction;
            if (curShuffledIdx < 0 || curShuffledIdx >= mPlaylist.size()) {
                if (mRepeatMode == REPEAT_MODE_NONE) {
                    return (i == size - 1) ? null : mEopPlayItem;
                } else {
                    curShuffledIdx = curShuffledIdx < 0 ? mPlaylist.size() - 1 : 0;
                }
            }
            DataSourceDesc dsd = retrieveDataSourceDescLocked(mShuffledList.get(curShuffledIdx));
            if (dsd != null) {
                return new PlayItem(curShuffledIdx, dsd);
            }
        }
        return null;
    }

    private void updateCurrentIfNeededLocked() {
        if (!hasValidItem() || mCurrent.isValid()) {
            return;
        }
        int shuffledIdx = mShuffledList.indexOf(mCurrent.mediaItem);
        if (shuffledIdx >= 0) {
            // Added an item.
            mCurrent.shuffledIdx = shuffledIdx;
            return;
        }

        if (mCurrent.shuffledIdx >= mShuffledList.size()) {
            mCurrent = getNextValidPlayItemLocked(mShuffledList.size() - 1, 1);
        } else {
            mCurrent.mediaItem = mShuffledList.get(mCurrent.shuffledIdx);
            if (retrieveDataSourceDescLocked(mCurrent.mediaItem) == null) {
                mCurrent = getNextValidPlayItemLocked(mCurrent.shuffledIdx, 1);
            }
        }
        return;
    }

    private void applyShuffleModeLocked() {
        mShuffledList.clear();
        mShuffledList.addAll(mPlaylist);
        if (mShuffleMode == MediaPlaylistAgent.SHUFFLE_MODE_ALL
                || mShuffleMode == MediaPlaylistAgent.SHUFFLE_MODE_GROUP) {
            Collections.shuffle(mShuffledList);
        }
    }

    // Clamps value to [0, size]
    private static int clamp(int value, int size) {
        if (value < 0) {
            return 0;
        }
        return (value > size) ? size : value;
    }
}
