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

import android.media.session.PlaybackState;
import android.os.Handler;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/**
 * A mock implementation of {@link MediaPlayerBase} for testing.
 */
public class MockPlayer extends MediaPlayerBase {
    public final CountDownLatch mCountDownLatch;

    public boolean mPlayCalled;
    public boolean mPauseCalled;
    public boolean mStopCalled;
    public boolean mSkipToPreviousCalled;
    public boolean mSkipToNextCalled;
    public List<PlaybackListenerHolder> mListeners = new ArrayList<>();
    private PlaybackState mLastPlaybackState;

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

    @Nullable
    @Override
    public PlaybackState getPlaybackState() {
        return mLastPlaybackState;
    }

    @Override
    public void addPlaybackListener(
            @NonNull PlaybackListener listener, @NonNull Handler handler) {
        mListeners.add(new PlaybackListenerHolder(listener, handler));
    }

    @Override
    public void removePlaybackListener(@NonNull PlaybackListener listener) {
        int index = PlaybackListenerHolder.indexOf(mListeners, listener);
        if (index >= 0) {
            mListeners.remove(index);
        }
    }

    public void notifyPlaybackState(final PlaybackState state) {
        mLastPlaybackState = state;
        for (int i = 0; i < mListeners.size(); i++) {
            mListeners.get(i).postPlaybackChange(state);
        }
    }
}
