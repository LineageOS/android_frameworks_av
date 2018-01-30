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

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

import static android.media.TestUtils.createPlaybackState;

import android.media.MediaPlayerInterface.PlaybackListener;
import android.media.MediaSession2.Builder;
import android.media.MediaSession2.Command;
import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.PlaylistParams;
import android.media.MediaSession2.SessionCallback;
import android.os.Bundle;
import android.os.Looper;
import android.os.Process;
import android.os.ResultReceiver;
import android.support.annotation.NonNull;
import android.support.test.filters.SmallTest;
import android.support.test.runner.AndroidJUnit4;
import android.text.TextUtils;

import java.util.ArrayList;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

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
        mPlayer = new MockPlayer(0);
        mSession = new MediaSession2.Builder(mContext, mPlayer)
                .setSessionCallback(sHandlerExecutor, new SessionCallback(mContext)).build();
    }

    @After
    @Override
    public void cleanUp() throws Exception {
        super.cleanUp();
        mSession.close();
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
            mSession.close();
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
    public void testSetPlaylist() throws Exception {
        final List<MediaItem2> playlist = new ArrayList<>();

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestControllerCallbackInterface() {
            @Override
            public void onPlaylistChanged(List<MediaItem2> givenList) {
                assertMediaItemListEquals(playlist, givenList);
                latch.countDown();
            }
        };

        final MediaController2 controller = createController(mSession.getToken(), true, callback);
        mSession.setPlaylist(playlist);

        assertTrue(mPlayer.mSetPlaylistCalled);
        assertMediaItemListEquals(playlist, mPlayer.mPlaylist);
        assertMediaItemListEquals(playlist, mSession.getPlaylist());

        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        assertMediaItemListEquals(playlist, controller.getPlaylist());
    }

    @Test
    public void testSetPlaylistParams() throws Exception {
        final PlaylistParams params = new PlaylistParams(
                PlaylistParams.REPEAT_MODE_ALL,
                PlaylistParams.SHUFFLE_MODE_ALL,
                null /* PlaylistMetadata */);

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestControllerCallbackInterface() {
            @Override
            public void onPlaylistParamsChanged(PlaylistParams givenParams) {
                TestUtils.equals(params.toBundle(), givenParams.toBundle());
                latch.countDown();
            }
        };

        final MediaController2 controller = createController(mSession.getToken(), true, callback);
        mSession.setPlaylistParams(params);
        assertTrue(mPlayer.mSetPlaylistParamsCalled);
        TestUtils.equals(params.toBundle(), mPlayer.mPlaylistParams.toBundle());
        TestUtils.equals(params.toBundle(), mSession.getPlaylistParams().toBundle());
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    // TODO(jaewan): Re-enable test..
    @Ignore
    @Test
    public void testPlaybackStateChangedListener() throws InterruptedException {
        final CountDownLatch latch = new CountDownLatch(2);
        final MockPlayer player = new MockPlayer(0);
        final PlaybackListener listener = (state) -> {
            assertEquals(sHandler.getLooper(), Looper.myLooper());
            assertNotNull(state);
            switch ((int) latch.getCount()) {
                case 2:
                    assertEquals(PlaybackState2.STATE_PLAYING, state.getState());
                    break;
                case 1:
                    assertEquals(PlaybackState2.STATE_PAUSED, state.getState());
                    break;
                case 0:
                    fail();
            }
            latch.countDown();
        };
        player.notifyPlaybackState(createPlaybackState(PlaybackState2.STATE_PLAYING));
        sHandler.postAndSync(() -> {
            mSession.addPlaybackListener(sHandlerExecutor, listener);
            // When the player is set, listeners will be notified about the player's current state.
            mSession.setPlayer(player);
        });
        player.notifyPlaybackState(createPlaybackState(PlaybackState2.STATE_PAUSED));
        assertTrue(latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
    }

    @Test
    public void testBadPlayer() throws InterruptedException {
        // TODO(jaewan): Add equivalent tests again
        final CountDownLatch latch = new CountDownLatch(3); // expected call + 1
        final BadPlayer player = new BadPlayer(0);
        sHandler.postAndSync(() -> {
            mSession.addPlaybackListener(sHandlerExecutor, (state) -> {
                // This will be called for every setPlayer() calls, but no more.
                assertNull(state);
                latch.countDown();
            });
            mSession.setPlayer(player);
            mSession.setPlayer(mPlayer);
        });
        player.notifyPlaybackState(createPlaybackState(PlaybackState2.STATE_PAUSED));
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
            mSession.close();
            mPlayer = new MockPlayer(1);
            mSession = new MediaSession2.Builder(mContext, mPlayer)
                    .setSessionCallback(sHandlerExecutor, callback).build();
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
            mSession.close();
            mSession = new MediaSession2.Builder(mContext, mPlayer)
                    .setSessionCallback(sHandlerExecutor, sessionCallback).build();
        });
        MediaController2 controller =
                createController(mSession.getToken(), false, null);
        assertNotNull(controller);
        waitForConnect(controller, false);
        waitForDisconnect(controller, true);
    }

    @Test
    public void testSendCustomAction() throws InterruptedException {
        final Command testCommand =
                new Command(mContext, MediaSession2.COMMAND_CODE_PLAYBACK_PREPARE);
        final Bundle testArgs = new Bundle();
        testArgs.putString("args", "testSendCustomAction");

        final CountDownLatch latch = new CountDownLatch(2);
        final TestControllerCallbackInterface callback = new TestControllerCallbackInterface() {
            @Override
            public void onCustomCommand(Command command, Bundle args, ResultReceiver receiver) {
                assertEquals(testCommand, command);
                assertTrue(TestUtils.equals(testArgs, args));
                assertNull(receiver);
                latch.countDown();
            }
        };
        final MediaController2 controller =
                createController(mSession.getToken(), true, callback);
        // TODO(jaewan): Test with multiple controllers
        mSession.sendCustomCommand(testCommand, testArgs);

        ControllerInfo controllerInfo = getTestControllerInfo();
        assertNotNull(controllerInfo);
        // TODO(jaewan): Test receivers as well.
        mSession.sendCustomCommand(controllerInfo, testCommand, testArgs, null);
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    private ControllerInfo getTestControllerInfo() {
        List<ControllerInfo> controllers = mSession.getConnectedControllers();
        assertNotNull(controllers);
        final String packageName = mContext.getPackageName();
        for (int i = 0; i < controllers.size(); i++) {
            if (TextUtils.equals(packageName, controllers.get(i).getPackageName())) {
                return controllers.get(i);
            }
        }
        fail("Fails to get custom command");
        return null;
    }

    public class MockOnConnectCallback extends SessionCallback {
        public MockOnConnectCallback() {
            super(mContext);
        }

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

        public MockOnCommandCallback() {
            super(mContext);
        }

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

    private static void assertMediaItemListEquals(List<MediaItem2> a, List<MediaItem2> b) {
        if (a == null || b == null) {
            assertEquals(a, b);
        }
        assertEquals(a.size(), b.size());

        for (int i = 0; i < a.size(); i++) {
            MediaItem2 aItem = a.get(i);
            MediaItem2 bItem = b.get(i);

            if (aItem == null || bItem == null) {
                assertEquals(aItem, bItem);
                continue;
            }

            assertEquals(aItem.getMediaId(), bItem.getMediaId());
            assertEquals(aItem.getFlags(), bItem.getFlags());
            TestUtils.equals(aItem.getMetadata().getBundle(), bItem.getMetadata().getBundle());

            // Note: Here it does not check whether DataSourceDesc are equal,
            // since there DataSourceDec is not comparable.
        }
    }
}
