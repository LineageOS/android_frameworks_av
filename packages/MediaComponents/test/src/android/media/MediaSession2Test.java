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

import static android.media.AudioAttributes.CONTENT_TYPE_MUSIC;
import static android.media.TestUtils.ensurePlaylistParamsModeEquals;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import android.content.Context;
import android.media.MediaController2.PlaybackInfo;
import android.media.MediaSession2.Builder;
import android.media.MediaSession2.Command;
import android.media.MediaSession2.CommandButton;
import android.media.MediaSession2.CommandGroup;
import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.PlaylistParams;
import android.media.MediaSession2.SessionCallback;
import android.os.Bundle;
import android.os.Process;
import android.os.ResultReceiver;
import android.support.annotation.NonNull;
import android.support.test.filters.SmallTest;
import android.support.test.runner.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

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
        mSession = new MediaSession2.Builder(mContext).setPlayer(mPlayer)
                .setSessionCallback(sHandlerExecutor, new SessionCallback(mContext) {}).build();
    }

    @After
    @Override
    public void cleanUp() throws Exception {
        super.cleanUp();
        mSession.close();
    }

    @Ignore
    @Test
    public void testBuilder() throws Exception {
        try {
            MediaSession2.Builder builder = new Builder(mContext);
            fail("null player shouldn't be allowed");
        } catch (IllegalArgumentException e) {
            // expected. pass-through
        }
        MediaSession2.Builder builder = new Builder(mContext).setPlayer(mPlayer);
        try {
            builder.setId(null);
            fail("null id shouldn't be allowed");
        } catch (IllegalArgumentException e) {
            // expected. pass-through
        }
    }

    @Test
    public void testUpdatePlayer() throws Exception {
        MockPlayer player = new MockPlayer(0);
        // Test if setPlayer doesn't crash with various situations.
        mSession.updatePlayer(mPlayer, null, null);
        mSession.updatePlayer(player, null, null);
        mSession.close();
    }

    @Test
    public void testSetPlayer_playbackInfo() throws Exception {
        MockPlayer player = new MockPlayer(0);
        AudioAttributes attrs = new AudioAttributes.Builder()
                .setContentType(CONTENT_TYPE_MUSIC)
                .build();
        player.setAudioAttributes(attrs);

        final int maxVolume = 100;
        final int currentVolume = 23;
        final int volumeControlType = VolumeProvider2.VOLUME_CONTROL_ABSOLUTE;
        VolumeProvider2 volumeProvider =
                new VolumeProvider2(mContext, volumeControlType, maxVolume, currentVolume) { };

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestControllerCallbackInterface() {
            @Override
            public void onPlaybackInfoChanged(PlaybackInfo info) {
                assertEquals(MediaController2.PlaybackInfo.PLAYBACK_TYPE_REMOTE,
                        info.getPlaybackType());
                assertEquals(attrs, info.getAudioAttributes());
                assertEquals(volumeControlType, info.getPlaybackType());
                assertEquals(maxVolume, info.getMaxVolume());
                assertEquals(currentVolume, info.getCurrentVolume());
                latch.countDown();
            }
        };

        mSession.updatePlayer(player, null, null);

        final MediaController2 controller = createController(mSession.getToken(), true, callback);
        PlaybackInfo info = controller.getPlaybackInfo();
        assertNotNull(info);
        assertEquals(PlaybackInfo.PLAYBACK_TYPE_LOCAL, info.getPlaybackType());
        assertEquals(attrs, info.getAudioAttributes());
        AudioManager manager = (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE);
        int localVolumeControlType = manager.isVolumeFixed()
                ? VolumeProvider2.VOLUME_CONTROL_FIXED : VolumeProvider2.VOLUME_CONTROL_ABSOLUTE;
        assertEquals(localVolumeControlType, info.getControlType());
        assertEquals(manager.getStreamMaxVolume(AudioManager.STREAM_MUSIC), info.getMaxVolume());
        assertEquals(manager.getStreamVolume(AudioManager.STREAM_MUSIC), info.getCurrentVolume());

        mSession.updatePlayer(player, null, volumeProvider);
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));

        info = controller.getPlaybackInfo();
        assertNotNull(info);
        assertEquals(PlaybackInfo.PLAYBACK_TYPE_REMOTE, info.getPlaybackType());
        assertEquals(attrs, info.getAudioAttributes());
        assertEquals(volumeControlType, info.getControlType());
        assertEquals(maxVolume, info.getMaxVolume());
        assertEquals(currentVolume, info.getCurrentVolume());
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

    @Ignore
    @Test
    public void testStop() throws Exception {
        sHandler.postAndSync(() -> {
            mSession.stop();
            assertTrue(mPlayer.mStopCalled);
        });
    }

    @Test
    public void testSkipToNextItem() throws Exception {
        sHandler.postAndSync(() -> {
            mSession.skipToNextItem();
            assertTrue(mPlayer.mSkipToNextCalled);
        });
    }

    @Ignore
    @Test
    public void testSkipToPreviousItem() throws Exception {
        sHandler.postAndSync(() -> {
            mSession.skipToPreviousItem();
            assertTrue(mPlayer.mSkipToPreviousCalled);
        });
    }

    @Ignore
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

    @Ignore
    @Test
    public void testSetPlaylistParams() throws Exception {
        final PlaylistParams params = new PlaylistParams(mContext,
                PlaylistParams.REPEAT_MODE_ALL,
                PlaylistParams.SHUFFLE_MODE_ALL,
                null /* PlaylistMetadata */);

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestControllerCallbackInterface() {
            @Override
            public void onPlaylistParamsChanged(PlaylistParams givenParams) {
                ensurePlaylistParamsModeEquals(params, givenParams);
                latch.countDown();
            }
        };

        final MediaController2 controller = createController(mSession.getToken(), true, callback);
        mSession.setPlaylistParams(params);
        assertTrue(mPlayer.mSetPlaylistParamsCalled);
        ensurePlaylistParamsModeEquals(params, mPlayer.mPlaylistParams);
        ensurePlaylistParamsModeEquals(params, mSession.getPlaylistParams());
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    @Ignore
    @Test
    public void testRegisterEventCallback() throws InterruptedException {
        final int testWhat = 1001;
        final MockPlayer player = new MockPlayer(0);
        final CountDownLatch playbackLatch = new CountDownLatch(3);
        final CountDownLatch errorLatch = new CountDownLatch(1);
        // TODO: Uncomment or remove
        /*
        final PlayerEventCallback callback = new PlayerEventCallback() {
            @Override
            public void onPlaybackStateChanged(PlaybackState2 state) {
                assertEquals(sHandler.getLooper(), Looper.myLooper());
                switch ((int) playbackLatch.getCount()) {
                    case 3:
                        assertNull(state);
                        break;
                    case 2:
                        assertNotNull(state);
                        assertEquals(PlaybackState2.STATE_PLAYING, state.getState());
                        break;
                    case 1:
                        assertNotNull(state);
                        assertEquals(PlaybackState2.STATE_PAUSED, state.getState());
                        break;
                    case 0:
                        fail();
                }
                playbackLatch.countDown();
            }

            @Override
            public void onError(String mediaId, int what, int extra) {
                assertEquals(testWhat, what);
                errorLatch.countDown();
            }
        };
        */
        player.notifyPlaybackState(createPlaybackState(PlaybackState2.STATE_PLAYING));
        // EventCallback will be notified with the mPlayer's playback state (null)
        // TODO: Uncomment or remove
        //mSession.registerPlayerEventCallback(sHandlerExecutor, callback);
        // When the player is set, EventCallback will be notified about the new player's state.
        mSession.updatePlayer(player, null, null);
        // When the player is set, EventCallback will be notified about the new player's state.
        player.notifyPlaybackState(createPlaybackState(PlaybackState2.STATE_PAUSED));
        assertTrue(playbackLatch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
        player.notifyError(testWhat);
        assertTrue(errorLatch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
    }

    @Test
    public void testBadPlayer() throws InterruptedException {
        // TODO(jaewan): Add equivalent tests again
        final CountDownLatch latch = new CountDownLatch(4); // expected call + 1
        final BadPlayer player = new BadPlayer(0);
        // TODO: Uncomment or remove
        /*
        mSession.registerPlayerEventCallback(sHandlerExecutor, new PlayerEventCallback() {
            @Override
            public void onPlaybackStateChanged(PlaybackState2 state) {
                // This will be called for every setPlayer() calls, but no more.
                assertNull(state);
                latch.countDown();
            }
        });
        */
        mSession.updatePlayer(player, null, null);
        mSession.updatePlayer(mPlayer, null, null);
        player.notifyPlaybackState(createPlaybackState(PlaybackState2.STATE_PAUSED));
        assertFalse(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    private static class BadPlayer extends MockPlayer {
        public BadPlayer(int count) {
            super(count);
        }

        @Override
        public void unregisterPlayerEventCallback(@NonNull PlayerEventCallback listener) {
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
            mSession = new MediaSession2.Builder(mContext).setPlayer(mPlayer)
                    .setSessionCallback(sHandlerExecutor, callback).build();
        });
        MediaController2 controller = createController(mSession.getToken());
        controller.pause();
        assertFalse(mPlayer.mCountDownLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        assertFalse(mPlayer.mPauseCalled);
        assertEquals(1, callback.commands.size());
        assertEquals(MediaSession2.COMMAND_CODE_PLAYBACK_PAUSE,
                (long) callback.commands.get(0).getCommandCode());
        controller.skipToNextItem();
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
            mSession = new MediaSession2.Builder(mContext).setPlayer(mPlayer)
                    .setSessionCallback(sHandlerExecutor, sessionCallback).build();
        });
        MediaController2 controller =
                createController(mSession.getToken(), false, null);
        assertNotNull(controller);
        waitForConnect(controller, false);
        waitForDisconnect(controller, true);
    }

    @Test
    public void testSetCustomLayout() throws InterruptedException {
        final List<CommandButton> buttons = new ArrayList<>();
        buttons.add(new CommandButton.Builder(mContext)
                .setCommand(new Command(mContext, MediaSession2.COMMAND_CODE_PLAYBACK_PLAY))
                .setDisplayName("button").build());
        final CountDownLatch latch = new CountDownLatch(1);
        final SessionCallback sessionCallback = new SessionCallback(mContext) {
            @Override
            public CommandGroup onConnect(MediaSession2 session,
                    ControllerInfo controller) {
                if (mContext.getPackageName().equals(controller.getPackageName())) {
                    mSession.setCustomLayout(controller, buttons);
                }
                return super.onConnect(session, controller);
            }
        };

        try (final MediaSession2 session = new MediaSession2.Builder(mContext)
                .setPlayer(mPlayer)
                .setId("testSetCustomLayout")
                .setSessionCallback(sHandlerExecutor, sessionCallback)
                .build()) {
            if (mSession != null) {
                mSession.close();
                mSession = session;
            }
            final TestControllerCallbackInterface callback = new TestControllerCallbackInterface() {
                @Override
                public void onCustomLayoutChanged(List<CommandButton> layout) {
                    assertEquals(layout.size(), buttons.size());
                    for (int i = 0; i < layout.size(); i++) {
                        assertEquals(layout.get(i).getCommand(), buttons.get(i).getCommand());
                        assertEquals(layout.get(i).getDisplayName(),
                                buttons.get(i).getDisplayName());
                    }
                    latch.countDown();
                }
            };
            final MediaController2 controller =
                    createController(session.getToken(), true, callback);
            assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        }
    }

    @Test
    public void testSetAllowedCommands() throws InterruptedException {
        final CommandGroup commands = new CommandGroup(mContext);
        commands.addCommand(new Command(mContext, MediaSession2.COMMAND_CODE_PLAYBACK_PLAY));
        commands.addCommand(new Command(mContext, MediaSession2.COMMAND_CODE_PLAYBACK_PAUSE));
        commands.addCommand(new Command(mContext, MediaSession2.COMMAND_CODE_PLAYBACK_STOP));

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestControllerCallbackInterface() {
            @Override
            public void onAllowedCommandsChanged(CommandGroup commandsOut) {
                assertNotNull(commandsOut);
                List<Command> expected = commands.getCommands();
                List<Command> actual = commandsOut.getCommands();

                assertNotNull(actual);
                assertEquals(expected.size(), actual.size());
                for (int i = 0; i < expected.size(); i++) {
                    assertEquals(expected.get(i), actual.get(i));
                }
                latch.countDown();
            }
        };

        final MediaController2 controller = createController(mSession.getToken(), true, callback);
        ControllerInfo controllerInfo = getTestControllerInfo();
        assertNotNull(controllerInfo);

        mSession.setAllowedCommands(controllerInfo, commands);
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
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
        for (int i = 0; i < controllers.size(); i++) {
            if (Process.myUid() == controllers.get(i).getUid()) {
                return controllers.get(i);
            }
        }
        fail("Failed to get test controller info");
        return null;
    }

    public class MockOnConnectCallback extends SessionCallback {
        public MockOnConnectCallback() {
            super(mContext);
        }

        @Override
        public MediaSession2.CommandGroup onConnect(MediaSession2 session,
                ControllerInfo controllerInfo) {
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
        public boolean onCommandRequest(MediaSession2 session, ControllerInfo controllerInfo,
                MediaSession2.Command command) {
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
            TestUtils.equals(aItem.getMetadata().toBundle(), bItem.getMetadata().toBundle());

            // Note: Here it does not check whether DataSourceDesc are equal,
            // since there DataSourceDec is not comparable.
        }
    }
}
