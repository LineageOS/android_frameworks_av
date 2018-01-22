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

import android.media.MediaPlayerBase.PlaybackListener;
import android.media.MediaSession2.Builder;
import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.SessionCallback;
import android.media.session.PlaybackState;
import android.os.Process;
import android.os.Looper;
import android.support.annotation.NonNull;
import android.support.test.filters.SmallTest;
import android.support.test.runner.AndroidJUnit4;

import java.util.ArrayList;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static android.media.TestUtils.createPlaybackState;
import static org.junit.Assert.*;

/**
 * Tests {@link MediaSession2}.
 */
@RunWith(AndroidJUnit4.class)
@SmallTest
public class MediaSession2Test extends MediaSession2TestBase {
    private static final String TAG = "MediaSession2Test";

    private MediaSession2 mSession;
    private MockPlayer mPlayer;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        sHandler.postAndSync(() -> {
            mPlayer = new MockPlayer(0);
            mSession = new MediaSession2.Builder(mContext, mPlayer).build();
        });
    }

    @After
    @Override
    public void cleanUp() throws Exception {
        super.cleanUp();
        sHandler.postAndSync(() -> {
            mSession.setPlayer(null);
        });
    }

    @Test
    public void testBuilder() throws Exception {
        try {
            MediaSession2.Builder builder = new Builder(mContext, null);
            fail("null player shouldn't be allowed");
        } catch (IllegalArgumentException e) {
            // expected. pass-through
        }
        MediaSession2.Builder builder = new Builder(mContext, mPlayer);
        try {
            builder.setId(null);
            fail("null id shouldn't be allowed");
        } catch (IllegalArgumentException e) {
            // expected. pass-through
        }
    }

    @Test
    public void testSetPlayer() throws Exception {
        sHandler.postAndSync(() -> {
            MockPlayer player = new MockPlayer(0);
            // Test if setPlayer doesn't crash with various situations.
            mSession.setPlayer(mPlayer);
            mSession.setPlayer(player);
            mSession.setPlayer(null);
        });
    }

    @Test
    public void testPlay() throws Exception {
        sHandler.postAndSync(() -> {
            mSession.play();
            assertTrue(mPlayer.mPlayCalled);
        });
    }

    @Test
    public void testPause() throws Exception {
        sHandler.postAndSync(() -> {
            mSession.pause();
            assertTrue(mPlayer.mPauseCalled);
        });
    }

    @Test
    public void testStop() throws Exception {
        sHandler.postAndSync(() -> {
            mSession.stop();
            assertTrue(mPlayer.mStopCalled);
        });
    }

    @Test
    public void testSkipToNext() throws Exception {
        sHandler.postAndSync(() -> {
            mSession.skipToNext();
            assertTrue(mPlayer.mSkipToNextCalled);
        });
    }

    @Test
    public void testSkipToPrevious() throws Exception {
        sHandler.postAndSync(() -> {
            mSession.skipToPrevious();
            assertTrue(mPlayer.mSkipToPreviousCalled);
        });
    }

    @Test
    public void testPlaybackStateChangedListener() throws InterruptedException {
        final CountDownLatch latch = new CountDownLatch(2);
        final MockPlayer player = new MockPlayer(0);
        final PlaybackListener listener = (state) -> {
            assertEquals(sHandler.getLooper(), Looper.myLooper());
            assertNotNull(state);
            switch ((int) latch.getCount()) {
                case 2:
                    assertEquals(PlaybackState.STATE_PLAYING, state.getState());
                    break;
                case 1:
                    assertEquals(PlaybackState.STATE_PAUSED, state.getState());
                    break;
                case 0:
                    fail();
            }
            latch.countDown();
        };
        player.notifyPlaybackState(createPlaybackState(PlaybackState.STATE_PLAYING));
        sHandler.postAndSync(() -> {
            mSession.addPlaybackListener(listener, sHandler);
            // When the player is set, listeners will be notified about the player's current state.
            mSession.setPlayer(player);
        });
        player.notifyPlaybackState(createPlaybackState(PlaybackState.STATE_PAUSED));
        assertTrue(latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
    }

    @Test
    public void testBadPlayer() throws InterruptedException {
        final CountDownLatch latch = new CountDownLatch(3); // expected call + 1
        final BadPlayer player = new BadPlayer(0);
        sHandler.postAndSync(() -> {
            mSession.addPlaybackListener((state) -> {
                // This will be called for every setPlayer() calls, but no more.
                assertNull(state);
                latch.countDown();
            }, sHandler);
            mSession.setPlayer(player);
            mSession.setPlayer(mPlayer);
        });
        player.notifyPlaybackState(createPlaybackState(PlaybackState.STATE_PAUSED));
        assertFalse(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    private static class BadPlayer extends MockPlayer {
        public BadPlayer(int count) {
            super(count);
        }

        @Override
        public void removePlaybackListener(@NonNull PlaybackListener listener) {
            // No-op. This bad player will keep push notification to the listener that is previously
            // registered by session.setPlayer().
        }
    }

    @Test
    public void testOnCommandCallback() throws InterruptedException {
        final MockOnCommandCallback callback = new MockOnCommandCallback();
        sHandler.postAndSync(() -> {
            mSession.setPlayer(null);
            mPlayer = new MockPlayer(1);
            mSession = new MediaSession2.Builder(mContext, mPlayer)
                    .setSessionCallback(callback).build();
        });
        MediaController2 controller = createController(mSession.getToken());
        controller.pause();
        assertFalse(mPlayer.mCountDownLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        assertFalse(mPlayer.mPauseCalled);
        assertEquals(1, callback.commands.size());
        assertEquals(MediaSession2.COMMAND_CODE_PLAYBACK_PAUSE,
                (long) callback.commands.get(0).getCommandCode());
        controller.skipToNext();
        assertTrue(mPlayer.mCountDownLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        assertTrue(mPlayer.mSkipToNextCalled);
        assertFalse(mPlayer.mPauseCalled);
        assertEquals(2, callback.commands.size());
        assertEquals(MediaSession2.COMMAND_CODE_PLAYBACK_SKIP_NEXT_ITEM,
                (long) callback.commands.get(1).getCommandCode());
    }

    @Test
    public void testOnConnectCallback() throws InterruptedException {
        final MockOnConnectCallback sessionCallback = new MockOnConnectCallback();
        sHandler.postAndSync(() -> {
            mSession.setPlayer(null);
            mSession = new MediaSession2.Builder(mContext, mPlayer)
                    .setSessionCallback(sessionCallback).build();
        });
        MediaController2Wrapper controller = createController(mSession.getToken(), false, null);
        assertNotNull(controller);
        controller.waitForConnect(false);
        controller.waitForDisconnect(true);
    }

    public class MockOnConnectCallback extends SessionCallback {
        @Override
        public MediaSession2.CommandGroup onConnect(ControllerInfo controllerInfo) {
            if (Process.myUid() != controllerInfo.getUid()) {
                return null;
            }
            assertEquals(mContext.getPackageName(), controllerInfo.getPackageName());
            assertEquals(Process.myUid(), controllerInfo.getUid());
            assertFalse(controllerInfo.isTrusted());
            // Reject all
            return null;
        }
    }

    public class MockOnCommandCallback extends SessionCallback {
        public final ArrayList<MediaSession2.Command> commands = new ArrayList<>();

        @Override
        public boolean onCommandRequest(ControllerInfo controllerInfo, MediaSession2.Command command) {
            assertEquals(mContext.getPackageName(), controllerInfo.getPackageName());
            assertEquals(Process.myUid(), controllerInfo.getUid());
            assertFalse(controllerInfo.isTrusted());
            commands.add(command);
            if (command.getCommandCode() == MediaSession2.COMMAND_CODE_PLAYBACK_PAUSE) {
                return false;
            }
            return true;
        }
    }
}
