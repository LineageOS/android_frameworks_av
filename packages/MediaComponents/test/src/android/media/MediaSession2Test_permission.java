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
import static org.mockito.Mockito.after;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.media.MediaSession2.Command;
import android.media.MediaSession2.CommandGroup;
import android.media.MediaSession2.SessionCallback;

import org.junit.Test;
import org.mockito.Mock;

/**
 * Tests whether {@link MediaSession2} receives commands that hasn't allowed.
 */
@Test
public class MediaSession2Test_permission extends MediaSession2TestBase {
    private static final String SESSION_ID = "MediaSession2Test_permission";

    private MockPlayer mPlayer;
    private MediaSession2 mSession;
    private MediaSession2.SessionCallback mCallback;

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
        when(mCallback.onConnect(any())).thenReturn(commands);
        if (mSession != null) {
            mSession.close();
        }
        mSession = new MediaSession2.Builder(mContext, mPlayer)
                .setId(SESSION_ID).setSessionCallback(sHandlerExecutor, mCallback).build();
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
        createSessionWithAllowedActions(createCommandGroup(COMMAND_CODE_PLAYBACK_PLAY));
        createController(mSession.getToken()).play();
        verify(mCallback, after(WAIT_TIME_MS).never()).onCommandRequest(any(), any());

        createSessionWithoutAllowed
    }
}