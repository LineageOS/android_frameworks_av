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

package android.media;

import android.media.MediaSession2.PlaylistParams;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;

/**
 * A mock implementation of {@link MediaPlayerInterface} for testing.
 */
public class MockPlayer implements MediaPlayerInterface {
    public final CountDownLatch mCountDownLatch;

    public boolean mPlayCalled;
    public boolean mPauseCalled;
    public boolean mStopCalled;
    public boolean mSkipToPreviousCalled;
    public boolean mSkipToNextCalled;
    public boolean mPrepareCalled;
    public boolean mFastForwardCalled;
    public boolean mRewindCalled;
    public boolean mSeekToCalled;
    public long mSeekPosition;
    public boolean mSetCurrentPlaylistItemCalled;
    public int mItemIndex;
    public boolean mSetPlaylistCalled;
    public boolean mSetPlaylistParamsCalled;

    public List<PlaybackListenerHolder> mListeners = new ArrayList<>();
    public List<MediaItem2> mPlaylist;
    public PlaylistParams mPlaylistParams;

    private PlaybackState2 mLastPlaybackState;
    private AudioAttributes mAudioAttributes;

    public MockPlayer(int count) {
        mCountDownLatch = (count > 0) ? new CountDownLatch(count) : null;
    }

    @Override
    public void play() {
        mPlayCalled = true;
        if (mCountDownLatch != null) {
            mCountDownLatch.countDown();
        }
    }

    @Override
    public void pause() {
        mPauseCalled = true;
        if (mCountDownLatch != null) {
            mCountDownLatch.countDown();
        }
    }

    @Override
    public void stop() {
        mStopCalled = true;
        if (mCountDownLatch != null) {
            mCountDownLatch.countDown();
        }
    }

    @Override
    public void skipToPrevious() {
        mSkipToPreviousCalled = true;
        if (mCountDownLatch != null) {
            mCountDownLatch.countDown();
        }
    }

    @Override
    public void skipToNext() {
        mSkipToNextCalled = true;
        if (mCountDownLatch != null) {
            mCountDownLatch.countDown();
        }
    }

    @Override
    public void prepare() {
        mPrepareCalled = true;
        if (mCountDownLatch != null) {
            mCountDownLatch.countDown();
        }
    }

    @Override
    public void fastForward() {
        mFastForwardCalled = true;
        if (mCountDownLatch != null) {
            mCountDownLatch.countDown();
        }
    }

    @Override
    public void rewind() {
        mRewindCalled = true;
        if (mCountDownLatch != null) {
            mCountDownLatch.countDown();
        }
    }

    @Override
    public void seekTo(long pos) {
        mSeekToCalled = true;
        mSeekPosition = pos;
        if (mCountDownLatch != null) {
            mCountDownLatch.countDown();
        }
    }

    @Override
    public void setCurrentPlaylistItem(int index) {
        mSetCurrentPlaylistItemCalled = true;
        mItemIndex = index;
        if (mCountDownLatch != null) {
            mCountDownLatch.countDown();
        }
    }

    @Nullable
    @Override
    public PlaybackState2 getPlaybackState() {
        return mLastPlaybackState;
    }

    @Override
    public void addPlaybackListener(@NonNull Executor executor,
            @NonNull PlaybackListener listener) {
        mListeners.add(new PlaybackListenerHolder(executor, listener));
    }

    @Override
    public void removePlaybackListener(@NonNull PlaybackListener listener) {
        int index = PlaybackListenerHolder.indexOf(mListeners, listener);
        if (index >= 0) {
            mListeners.remove(index);
        }
    }

    public void notifyPlaybackState(final PlaybackState2 state) {
        mLastPlaybackState = state;
        for (int i = 0; i < mListeners.size(); i++) {
            mListeners.get(i).postPlaybackChange(state);
        }
    }

    @Override
    public void setPlaylistParams(PlaylistParams params) {
        mSetPlaylistParamsCalled = true;
        mPlaylistParams = params;
    }

    @Override
    public void addPlaylistItem(int index, MediaItem2 item) {
    }

    @Override
    public void removePlaylistItem(MediaItem2 item) {
    }

    @Override
    public PlaylistParams getPlaylistParams() {
        return mPlaylistParams;
    }

    @Override
    public void setAudioAttributes(AudioAttributes attributes) {
        mAudioAttributes = attributes;
    }

    @Override
    public AudioAttributes getAudioAttributes() {
        return mAudioAttributes;
    }

    @Override
    public void setPlaylist(List<MediaItem2> playlist) {
        mSetPlaylistCalled = true;
        mPlaylist = playlist;
    }

    @Override
    public List<MediaItem2> getPlaylist() {
        return mPlaylist;
    }
}
