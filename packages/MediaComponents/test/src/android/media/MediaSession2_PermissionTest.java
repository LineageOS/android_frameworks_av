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

import static android.media.MediaSession2.*;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.media.MediaSession2.Command;
import android.media.MediaSession2.CommandGroup;
import android.media.MediaSession2.SessionCallback;
import android.net.Uri;
import android.os.Process;
import android.support.test.filters.MediumTest;
import android.support.test.runner.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Tests whether {@link MediaSession2} receives commands that hasn't allowed.
 */
@RunWith(AndroidJUnit4.class)
@MediumTest
public class MediaSession2_PermissionTest extends MediaSession2TestBase {
    private static final String SESSION_ID = "MediaSession2Test_permission";

    private MockPlayer mPlayer;
    private MediaSession2 mSession;
    private MediaSession2.SessionCallback mCallback;

    private MediaSession2 matchesSession() {
        return argThat((session) -> session == mSession);
    }

    private static ControllerInfo matchesCaller() {
        return argThat((controllerInfo) -> controllerInfo.getUid() == Process.myUid());
    }

    private static Command matches(final int commandCode) {
        return argThat((command) -> command.getCommandCode() == commandCode);
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    @Override
    public void cleanUp() throws Exception {
        super.cleanUp();
        if (mSession != null) {
            mSession.close();
            mSession = null;
        }
        mPlayer = null;
        mCallback = null;
    }

    private MediaSession2 createSessionWithAllowedActions(CommandGroup commands) {
        mPlayer = new MockPlayer(0);
        if (commands == null) {
            commands = new CommandGroup(mContext);
        }
        mCallback = mock(SessionCallback.class);
        when(mCallback.onConnect(any(), any())).thenReturn(commands);
        if (mSession != null) {
            mSession.close();
        }
        mSession = new MediaSession2.Builder(mContext).setPlayer(mPlayer).setId(SESSION_ID)
                .setSessionCallback(sHandlerExecutor, mCallback).build();
        return mSession;
    }

    private CommandGroup createCommandGroupWith(int commandCode) {
        CommandGroup commands = new CommandGroup(mContext);
        commands.addCommand(new Command(mContext, commandCode));
        return commands;
    }

    private CommandGroup createCommandGroupWithout(int commandCode) {
        CommandGroup commands = new CommandGroup(mContext);
        commands.addAllPredefinedCommands();
        commands.removeCommand(new Command(mContext, commandCode));
        return commands;
    }

    @Test
    public void testPlay() throws InterruptedException {
        createSessionWithAllowedActions(createCommandGroupWith(COMMAND_CODE_PLAYBACK_PLAY));
        createController(mSession.getToken()).play();
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onCommandRequest(
                matchesSession(), matchesCaller(), matches(COMMAND_CODE_PLAYBACK_PLAY));

        createSessionWithAllowedActions(createCommandGroupWithout(COMMAND_CODE_PLAYBACK_PLAY));
        createController(mSession.getToken()).play();
        verify(mCallback, after(WAIT_TIME_MS).never()).onCommandRequest(any(), any(), any());
    }

    @Test
    public void testPause() throws InterruptedException {
        createSessionWithAllowedActions(createCommandGroupWith(COMMAND_CODE_PLAYBACK_PAUSE));
        createController(mSession.getToken()).pause();
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onCommandRequest(
                matchesSession(), matchesCaller(), matches(COMMAND_CODE_PLAYBACK_PAUSE));

        createSessionWithAllowedActions(createCommandGroupWithout(COMMAND_CODE_PLAYBACK_PAUSE));
        createController(mSession.getToken()).pause();
        verify(mCallback, after(WAIT_TIME_MS).never()).onCommandRequest(any(), any(), any());
    }

    @Test
    public void testStop() throws InterruptedException {
        createSessionWithAllowedActions(createCommandGroupWith(COMMAND_CODE_PLAYBACK_STOP));
        createController(mSession.getToken()).stop();
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onCommandRequest(
                matchesSession(), matchesCaller(), matches(COMMAND_CODE_PLAYBACK_STOP));

        createSessionWithAllowedActions(createCommandGroupWithout(COMMAND_CODE_PLAYBACK_STOP));
        createController(mSession.getToken()).stop();
        verify(mCallback, after(WAIT_TIME_MS).never()).onCommandRequest(any(), any(), any());
    }

    @Test
    public void testSkipToNext() throws InterruptedException {
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PLAYBACK_SKIP_NEXT_ITEM));
        createController(mSession.getToken()).skipToNextItem();
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onCommandRequest(
                matchesSession(), matchesCaller(), matches(COMMAND_CODE_PLAYBACK_SKIP_NEXT_ITEM));

        createSessionWithAllowedActions(
                createCommandGroupWithout(COMMAND_CODE_PLAYBACK_SKIP_NEXT_ITEM));
        createController(mSession.getToken()).skipToNextItem();
        verify(mCallback, after(WAIT_TIME_MS).never()).onCommandRequest(any(), any(), any());
    }

    @Test
    public void testSkipToPrevious() throws InterruptedException {
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PLAYBACK_SKIP_PREV_ITEM));
        createController(mSession.getToken()).skipToPreviousItem();
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onCommandRequest(
                matchesSession(), matchesCaller(), matches(COMMAND_CODE_PLAYBACK_SKIP_PREV_ITEM));

        createSessionWithAllowedActions(
                createCommandGroupWithout(COMMAND_CODE_PLAYBACK_SKIP_PREV_ITEM));
        createController(mSession.getToken()).skipToPreviousItem();
        verify(mCallback, after(WAIT_TIME_MS).never()).onCommandRequest(any(), any(), any());
    }

    @Test
    public void testFastForward() throws InterruptedException {
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PLAYBACK_FAST_FORWARD));
        createController(mSession.getToken()).fastForward();
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onCommandRequest(
                matchesSession(), matchesCaller(), matches(COMMAND_CODE_PLAYBACK_FAST_FORWARD));

        createSessionWithAllowedActions(
                createCommandGroupWithout(COMMAND_CODE_PLAYBACK_FAST_FORWARD));
        createController(mSession.getToken()).fastForward();
        verify(mCallback, after(WAIT_TIME_MS).never()).onCommandRequest(any(), any(), any());
    }

    @Test
    public void testRewind() throws InterruptedException {
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PLAYBACK_REWIND));
        createController(mSession.getToken()).rewind();
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onCommandRequest(
                matchesSession(), matchesCaller(), matches(COMMAND_CODE_PLAYBACK_REWIND));

        createSessionWithAllowedActions(createCommandGroupWithout(COMMAND_CODE_PLAYBACK_REWIND));
        createController(mSession.getToken()).rewind();
        verify(mCallback, after(WAIT_TIME_MS).never()).onCommandRequest(any(), any(), any());
    }

    @Test
    public void testSeekTo() throws InterruptedException {
        final long position = 10;
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PLAYBACK_SEEK_TO));
        createController(mSession.getToken()).seekTo(position);
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onCommandRequest(
                matchesSession(), matchesCaller(), matches(COMMAND_CODE_PLAYBACK_SEEK_TO));

        createSessionWithAllowedActions(createCommandGroupWithout(COMMAND_CODE_PLAYBACK_SEEK_TO));
        createController(mSession.getToken()).seekTo(position);
        verify(mCallback, after(WAIT_TIME_MS).never()).onCommandRequest(any(), any(), any());
    }

    // TODO(jaewan): Uncomment when we implement skipToPlaylistItem()
    /*
    @Test
    public void testSkipToPlaylistItem() throws InterruptedException {
        final Uri uri = Uri.parse("set://current.playlist.item");
        final DataSourceDesc dsd = new DataSourceDesc.Builder()
                .setDataSource(mContext, uri).build();
        final MediaItem2 item = new MediaItem2.Builder(mContext, MediaItem2.FLAG_PLAYABLE)
                .setDataSourceDesc(dsd).build();
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PLAYBACK_SET_CURRENT_PLAYLIST_ITEM));
        createController(mSession.getToken()).skipToPlaylistItem(item);
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onCommandRequest(matchesCaller(),
                matches(COMMAND_CODE_PLAYBACK_SET_CURRENT_PLAYLIST_ITEM));

        createSessionWithAllowedActions(
                createCommandGroupWithout(COMMAND_CODE_PLAYBACK_SET_CURRENT_PLAYLIST_ITEM));
        createController(mSession.getToken()).skipToPlaylistItem(item);
        verify(mCallback, after(WAIT_TIME_MS).never()).onCommandRequest(any(), any());
    }
    */

    @Test
    public void testSetPlaylistParams() throws InterruptedException {
        final PlaylistParams param = new PlaylistParams(mContext,
                PlaylistParams.REPEAT_MODE_ALL, PlaylistParams.SHUFFLE_MODE_ALL, null);
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PLAYBACK_SET_PLAYLIST_PARAMS));
        createController(mSession.getToken()).setPlaylistParams(param);
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onCommandRequest(
                matchesSession(), matchesCaller(),
                matches(COMMAND_CODE_PLAYBACK_SET_PLAYLIST_PARAMS));

        createSessionWithAllowedActions(
                createCommandGroupWithout(COMMAND_CODE_PLAYBACK_SET_PLAYLIST_PARAMS));
        createController(mSession.getToken()).setPlaylistParams(param);
        verify(mCallback, after(WAIT_TIME_MS).never()).onCommandRequest(any(), any(), any());
    }

    @Test
    public void testSetVolume() throws InterruptedException {
        createSessionWithAllowedActions(createCommandGroupWith(COMMAND_CODE_PLAYBACK_SET_VOLUME));
        createController(mSession.getToken()).setVolumeTo(0, 0);
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onCommandRequest(
                matchesSession(), matchesCaller(), matches(COMMAND_CODE_PLAYBACK_SET_VOLUME));

        createSessionWithAllowedActions(createCommandGroupWithout(COMMAND_CODE_PLAYBACK_SET_VOLUME));
        createController(mSession.getToken()).setVolumeTo(0, 0);
        verify(mCallback, after(WAIT_TIME_MS).never()).onCommandRequest(any(), any(), any());
    }

    @Test
    public void testPlayFromMediaId() throws InterruptedException {
        final String mediaId = "testPlayFromMediaId";
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PLAY_FROM_MEDIA_ID));
        createController(mSession.getToken()).playFromMediaId(mediaId, null);
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onPlayFromMediaId(
                matchesSession(), matchesCaller(), eq(mediaId), isNull());

        createSessionWithAllowedActions(
                createCommandGroupWithout(COMMAND_CODE_PLAY_FROM_MEDIA_ID));
        createController(mSession.getToken()).playFromMediaId(mediaId, null);
        verify(mCallback, after(WAIT_TIME_MS).never()).onPlayFromMediaId(
                any(), any(), any(), any());
    }

    @Test
    public void testPlayFromUri() throws InterruptedException {
        final Uri uri = Uri.parse("play://from.uri");
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PLAY_FROM_URI));
        createController(mSession.getToken()).playFromUri(uri, null);
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onPlayFromUri(
                matchesSession(), matchesCaller(), eq(uri), isNull());

        createSessionWithAllowedActions(
                createCommandGroupWithout(COMMAND_CODE_PLAY_FROM_URI));
        createController(mSession.getToken()).playFromUri(uri, null);
        verify(mCallback, after(WAIT_TIME_MS).never()).onPlayFromUri(any(), any(), any(), any());
    }

    @Test
    public void testPlayFromSearch() throws InterruptedException {
        final String query = "testPlayFromSearch";
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PLAY_FROM_SEARCH));
        createController(mSession.getToken()).playFromSearch(query, null);
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onPlayFromSearch(
                matchesSession(), matchesCaller(), eq(query), isNull());

        createSessionWithAllowedActions(
                createCommandGroupWithout(COMMAND_CODE_PLAY_FROM_SEARCH));
        createController(mSession.getToken()).playFromSearch(query, null);
        verify(mCallback, after(WAIT_TIME_MS).never()).onPlayFromSearch(any(), any(), any(), any());
    }

    @Test
    public void testPrepareFromMediaId() throws InterruptedException {
        final String mediaId = "testPrepareFromMediaId";
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PREPARE_FROM_MEDIA_ID));
        createController(mSession.getToken()).prepareFromMediaId(mediaId, null);
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onPrepareFromMediaId(
                matchesSession(), matchesCaller(), eq(mediaId), isNull());

        createSessionWithAllowedActions(
                createCommandGroupWithout(COMMAND_CODE_PREPARE_FROM_MEDIA_ID));
        createController(mSession.getToken()).prepareFromMediaId(mediaId, null);
        verify(mCallback, after(WAIT_TIME_MS).never()).onPrepareFromMediaId(
                any(), any(), any(), any());
    }

    @Test
    public void testPrepareFromUri() throws InterruptedException {
        final Uri uri = Uri.parse("prepare://from.uri");
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PREPARE_FROM_URI));
        createController(mSession.getToken()).prepareFromUri(uri, null);
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onPrepareFromUri(
                matchesSession(), matchesCaller(), eq(uri), isNull());

        createSessionWithAllowedActions(
                createCommandGroupWithout(COMMAND_CODE_PREPARE_FROM_URI));
        createController(mSession.getToken()).prepareFromUri(uri, null);
        verify(mCallback, after(WAIT_TIME_MS).never()).onPrepareFromUri(any(), any(), any(), any());
    }

    @Test
    public void testPrepareFromSearch() throws InterruptedException {
        final String query = "testPrepareFromSearch";
        createSessionWithAllowedActions(
                createCommandGroupWith(COMMAND_CODE_PREPARE_FROM_SEARCH));
        createController(mSession.getToken()).prepareFromSearch(query, null);
        verify(mCallback, timeout(TIMEOUT_MS).atLeastOnce()).onPrepareFromSearch(
                matchesSession(), matchesCaller(), eq(query), isNull());

        createSessionWithAllowedActions(
                createCommandGroupWithout(COMMAND_CODE_PREPARE_FROM_SEARCH));
        createController(mSession.getToken()).prepareFromSearch(query, null);
        verify(mCallback, after(WAIT_TIME_MS).never()).onPrepareFromSearch(
                any(), any(), any(), any());
    }
}
