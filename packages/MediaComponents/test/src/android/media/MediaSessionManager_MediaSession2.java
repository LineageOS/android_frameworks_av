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

import android.content.Context;
import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.SessionCallback;
import android.media.session.MediaSessionManager;
import android.media.session.PlaybackState;
import android.support.test.filters.SmallTest;
import android.support.test.runner.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

/**
 * Tests {@link MediaSessionManager} with {@link MediaSession2} specific APIs.
 */
@RunWith(AndroidJUnit4.class)
@SmallTest
public class MediaSessionManager_MediaSession2 extends MediaSession2TestBase {
    private static final String TAG = "MediaSessionManager_MediaSession2";

    private MediaSessionManager mManager;
    private MediaSession2 mSession;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        mManager = (MediaSessionManager) mContext.getSystemService(Context.MEDIA_SESSION_SERVICE);

        // Specify TAG here so {@link MediaSession2.getInstance()} doesn't complaint about
        // per test thread differs across the {@link MediaSession2} with the same TAG.
        final MockPlayer player = new MockPlayer(1);
        mSession = new MediaSession2.Builder(mContext, player)
                .setSessionCallback(sHandlerExecutor, new SessionCallback(mContext) { })
                .setId(TAG)
                .build();
        ensureChangeInSession();
    }

    @After
    @Override
    public void cleanUp() throws Exception {
        super.cleanUp();
        sHandler.removeCallbacksAndMessages(null);
        mSession.close();
    }

    // TODO(jaewan): Make this host-side test to see per-user behavior.
    @Ignore
    @Test
    public void testGetMediaSession2Tokens_hasMediaController() throws InterruptedException {
        final MockPlayer player = (MockPlayer) mSession.getPlayer();
        player.notifyPlaybackState(createPlaybackState(PlaybackState.STATE_STOPPED));

        MediaController2 controller = null;
        List<SessionToken2> tokens = mManager.getActiveSessionTokens();
        assertNotNull(tokens);
        for (int i = 0; i < tokens.size(); i++) {
            SessionToken2 token = tokens.get(i);
            if (mContext.getPackageName().equals(token.getPackageName())
                    && TAG.equals(token.getId())) {
                assertNull(controller);
                controller = createController(token);
            }
        }
        assertNotNull(controller);

        // Test if the found controller is correct one.
        assertEquals(PlaybackState.STATE_STOPPED, controller.getPlaybackState().getState());
        controller.play();

        assertTrue(player.mCountDownLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        assertTrue(player.mPlayCalled);
    }

    /**
     * Test if server recognizes a session even if the session refuses the connection from server.
     *
     * @throws InterruptedException
     */
    @Test
    public void testGetSessionTokens_sessionRejected() throws InterruptedException {
        sHandler.postAndSync(() -> {
            mSession.close();
            mSession = new MediaSession2.Builder(mContext, new MockPlayer(0)).setId(TAG)
                    .setSessionCallback(sHandlerExecutor, new SessionCallback(mContext) {
                        @Override
                        public MediaSession2.CommandGroup onConnect(ControllerInfo controller) {
                            // Reject all connection request.
                            return null;
                        }
                    }).build();
        });
        ensureChangeInSession();

        boolean foundSession = false;
        List<SessionToken2> tokens = mManager.getActiveSessionTokens();
        assertNotNull(tokens);
        for (int i = 0; i < tokens.size(); i++) {
            SessionToken2 token = tokens.get(i);
            if (mContext.getPackageName().equals(token.getPackageName())
                    && TAG.equals(token.getId())) {
                assertFalse(foundSession);
                foundSession = true;
            }
        }
        assertTrue(foundSession);
    }

    @Test
    public void testGetMediaSession2Tokens_playerRemoved() throws InterruptedException {
        // Release
        sHandler.postAndSync(() -> {
            mSession.close();
        });
        ensureChangeInSession();

        // When the mSession's player becomes null, it should lose binder connection between server.
        // So server will forget the session.
        List<SessionToken2> tokens = mManager.getActiveSessionTokens();
        for (int i = 0; i < tokens.size(); i++) {
            SessionToken2 token = tokens.get(i);
            assertFalse(mContext.getPackageName().equals(token.getPackageName())
                    && TAG.equals(token.getId()));
        }
    }

    @Test
    public void testGetMediaSessionService2Token() throws InterruptedException {
        boolean foundTestSessionService = false;
        boolean foundTestLibraryService = false;
        List<SessionToken2> tokens = mManager.getSessionServiceTokens();
        for (int i = 0; i < tokens.size(); i++) {
            SessionToken2 token = tokens.get(i);
            if (mContext.getPackageName().equals(token.getPackageName())
                    && MockMediaSessionService2.ID.equals(token.getId())) {
                assertFalse(foundTestSessionService);
                assertEquals(SessionToken2.TYPE_SESSION_SERVICE, token.getType());
                foundTestSessionService = true;
            } else if (mContext.getPackageName().equals(token.getPackageName())
                    && MockMediaLibraryService2.ID.equals(token.getId())) {
                assertFalse(foundTestLibraryService);
                assertEquals(SessionToken2.TYPE_LIBRARY_SERVICE, token.getType());
                foundTestLibraryService = true;
            }
        }
        assertTrue(foundTestSessionService);
        assertTrue(foundTestLibraryService);
    }

    @Test
    public void testGetAllSessionTokens() throws InterruptedException {
        boolean foundTestSession = false;
        boolean foundTestSessionService = false;
        boolean foundTestLibraryService = false;
        List<SessionToken2> tokens = mManager.getAllSessionTokens();
        for (int i = 0; i < tokens.size(); i++) {
            SessionToken2 token = tokens.get(i);
            if (!mContext.getPackageName().equals(token.getPackageName())) {
                continue;
            }
            switch (token.getId()) {
                case TAG:
                    assertFalse(foundTestSession);
                    foundTestSession = true;
                    break;
                case MockMediaSessionService2.ID:
                    assertFalse(foundTestSessionService);
                    foundTestSessionService = true;
                    assertEquals(SessionToken2.TYPE_SESSION_SERVICE, token.getType());
                    break;
                case MockMediaLibraryService2.ID:
                    assertFalse(foundTestLibraryService);
                    assertEquals(SessionToken2.TYPE_LIBRARY_SERVICE, token.getType());
                    foundTestLibraryService = true;
                    break;
                default:
                    fail("Unexpected session " + token + " exists in the package");
            }
        }
        assertTrue(foundTestSession);
        assertTrue(foundTestSessionService);
        assertTrue(foundTestLibraryService);
    }

    // Ensures if the session creation/release is notified to the server.
    private void ensureChangeInSession() throws InterruptedException {
        // TODO(jaewan): Wait by listener.
        Thread.sleep(WAIT_TIME_MS);
    }
}
