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

import android.media.MediaPlayerInterface.PlaybackListener;
import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.SessionCallback;
import android.media.TestUtils.SyncHandler;
import android.media.session.PlaybackState;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Process;
import android.support.test.filters.FlakyTest;
import android.support.test.filters.SmallTest;
import android.support.test.runner.AndroidJUnit4;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static android.media.TestUtils.createPlaybackState;
import static org.junit.Assert.*;

/**
 * Tests {@link MediaController2}.
 */
// TODO(jaewan): Implement host-side test so controller and session can run in different processes.
// TODO(jaewan): Fix flaky failure -- see MediaController2Impl.getController()
// TODO(jaeawn): Revisit create/close session in the sHandler. It's no longer necessary.
@RunWith(AndroidJUnit4.class)
@SmallTest
@FlakyTest
public class MediaController2Test extends MediaSession2TestBase {
    private static final String TAG = "MediaController2Test";

    MediaSession2 mSession;
    MediaController2 mController;
    MockPlayer mPlayer;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        // Create this test specific MediaSession2 to use our own Handler.
        mPlayer = new MockPlayer(1);
        mSession = new MediaSession2.Builder(mContext, mPlayer)
                .setSessionCallback(sHandlerExecutor, new SessionCallback())
                .setId(TAG).build();
        mController = createController(mSession.getToken());
        TestServiceRegistry.getInstance().setHandler(sHandler);
    }

    @After
    @Override
    public void cleanUp() throws Exception {
        super.cleanUp();
        if (mSession != null) {
            mSession.close();
        }
        TestServiceRegistry.getInstance().cleanUp();
    }

    @Test
    public void testPlay() throws InterruptedException {
        mController.play();
        try {
            assertTrue(mPlayer.mCountDownLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        } catch (InterruptedException e) {
            fail(e.getMessage());
        }
        assertTrue(mPlayer.mPlayCalled);
    }

    @Test
    public void testPause() throws InterruptedException {
        mController.pause();
        try {
            assertTrue(mPlayer.mCountDownLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        } catch (InterruptedException e) {
            fail(e.getMessage());
        }
        assertTrue(mPlayer.mPauseCalled);
    }


    @Test
    public void testSkipToPrevious() throws InterruptedException {
        mController.skipToPrevious();
        try {
            assertTrue(mPlayer.mCountDownLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        } catch (InterruptedException e) {
            fail(e.getMessage());
        }
        assertTrue(mPlayer.mSkipToPreviousCalled);
    }

    @Test
    public void testSkipToNext() throws InterruptedException {
        mController.skipToNext();
        try {
            assertTrue(mPlayer.mCountDownLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        } catch (InterruptedException e) {
            fail(e.getMessage());
        }
        assertTrue(mPlayer.mSkipToNextCalled);
    }

    @Test
    public void testStop() throws InterruptedException {
        mController.stop();
        try {
            assertTrue(mPlayer.mCountDownLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        } catch (InterruptedException e) {
            fail(e.getMessage());
        }
        assertTrue(mPlayer.mStopCalled);
    }

    @Test
    public void testGetPackageName() {
        assertEquals(mContext.getPackageName(), mController.getSessionToken().getPackageName());
    }

    @Test
    public void testGetPlaybackState() throws InterruptedException {
        // TODO(jaewan): add equivalent test later
        /*
        final CountDownLatch latch = new CountDownLatch(1);
        final MediaPlayerInterface.PlaybackListener listener = (state) -> {
            assertEquals(PlaybackState.STATE_BUFFERING, state.getState());
            latch.countDown();
        };
        assertNull(mController.getPlaybackState());
        mController.addPlaybackListener(listener, sHandler);

        mPlayer.notifyPlaybackState(createPlaybackState(PlaybackState.STATE_BUFFERING));
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        assertEquals(PlaybackState.STATE_BUFFERING, mController.getPlaybackState().getState());
        */
    }

    // TODO(jaewan): add equivalent test later
    /*
    @Test
    public void testAddPlaybackListener() throws InterruptedException {
        final CountDownLatch latch = new CountDownLatch(2);
        final MediaPlayerInterface.PlaybackListener listener = (state) -> {
            switch ((int) latch.getCount()) {
                case 2:
                    assertEquals(PlaybackState.STATE_PLAYING, state.getState());
                    break;
                case 1:
                    assertEquals(PlaybackState.STATE_PAUSED, state.getState());
                    break;
            }
            latch.countDown();
        };

        mController.addPlaybackListener(listener, sHandler);
        sHandler.postAndSync(()->{
            mPlayer.notifyPlaybackState(createPlaybackState(PlaybackState.STATE_PLAYING));
            mPlayer.notifyPlaybackState(createPlaybackState(PlaybackState.STATE_PAUSED));
        });
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    @Test
    public void testRemovePlaybackListener() throws InterruptedException {
        final CountDownLatch latch = new CountDownLatch(1);
        final MediaPlayerInterface.PlaybackListener listener = (state) -> {
            fail();
            latch.countDown();
        };
        mController.addPlaybackListener(listener, sHandler);
        mController.removePlaybackListener(listener);
        mPlayer.notifyPlaybackState(createPlaybackState(PlaybackState.STATE_PLAYING));
        assertFalse(latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
    }
    */

    @Test
    public void testControllerCallback_onConnected() throws InterruptedException {
        // createController() uses controller callback to wait until the controller becomes
        // available.
        MediaController2 controller = createController(mSession.getToken());
        assertNotNull(controller);
    }

    @Test
    public void testControllerCallback_sessionRejects() throws InterruptedException {
        final MediaSession2.SessionCallback sessionCallback = new SessionCallback() {
            @Override
            public MediaSession2.CommandGroup onConnect(ControllerInfo controller) {
                return null;
            }
        };
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
    public void testControllerCallback_releaseSession() throws InterruptedException {
        sHandler.postAndSync(() -> {
            mSession.close();
        });
        waitForDisconnect(mController, true);
    }

    @Test
    public void testControllerCallback_release() throws InterruptedException {
        mController.close();
        waitForDisconnect(mController, true);
    }

    @Test
    public void testIsConnected() throws InterruptedException {
        assertTrue(mController.isConnected());
        sHandler.postAndSync(()->{
            mSession.close();
        });
        // postAndSync() to wait until the disconnection is propagated.
        sHandler.postAndSync(()->{
            assertFalse(mController.isConnected());
        });
    }

    /**
     * Test potential deadlock for calls between controller and session.
     */
    @Test
    public void testDeadlock() throws InterruptedException {
        sHandler.postAndSync(() -> {
            mSession.close();
            mSession = null;
        });

        // Two more threads are needed not to block test thread nor test wide thread (sHandler).
        final HandlerThread sessionThread = new HandlerThread("testDeadlock_session");
        final HandlerThread testThread = new HandlerThread("testDeadlock_test");
        sessionThread.start();
        testThread.start();
        final SyncHandler sessionHandler = new SyncHandler(sessionThread.getLooper());
        final Handler testHandler = new Handler(testThread.getLooper());
        final CountDownLatch latch = new CountDownLatch(1);
        try {
            final MockPlayer player = new MockPlayer(0);
            sessionHandler.postAndSync(() -> {
                mSession = new MediaSession2.Builder(mContext, mPlayer)
                        .setSessionCallback(sHandlerExecutor, new SessionCallback())
                        .setId("testDeadlock").build();
            });
            final MediaController2 controller = createController(mSession.getToken());
            testHandler.post(() -> {
                final PlaybackState2 state = createPlaybackState(PlaybackState.STATE_ERROR);
                for (int i = 0; i < 100; i++) {
                    // triggers call from session to controller.
                    player.notifyPlaybackState(state);
                    // triggers call from controller to session.
                    controller.play();

                    // Repeat above
                    player.notifyPlaybackState(state);
                    controller.pause();
                    player.notifyPlaybackState(state);
                    controller.stop();
                    player.notifyPlaybackState(state);
                    controller.skipToNext();
                    player.notifyPlaybackState(state);
                    controller.skipToPrevious();
                }
                // This may hang if deadlock happens.
                latch.countDown();
            });
            assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        } finally {
            if (mSession != null) {
                sessionHandler.postAndSync(() -> {
                    // Clean up here because sessionHandler will be removed afterwards.
                    mSession.close();
                    mSession = null;
                });
            }
            if (sessionThread != null) {
                sessionThread.quitSafely();
            }
            if (testThread != null) {
                testThread.quitSafely();
            }
        }
    }

    @Ignore
    @Test
    public void testGetServiceToken() {
        SessionToken2 token = TestUtils.getServiceToken(mContext, MockMediaSessionService2.ID);
        assertNotNull(token);
        assertEquals(mContext.getPackageName(), token.getPackageName());
        assertEquals(MockMediaSessionService2.ID, token.getId());
        assertNull(token.getSessionBinder());
        assertEquals(SessionToken2.TYPE_SESSION_SERVICE, token.getType());
    }

    private void connectToService(SessionToken2 token) throws InterruptedException {
        mController = createController(token);
        mSession = TestServiceRegistry.getInstance().getServiceInstance().getSession();
        mPlayer = (MockPlayer) mSession.getPlayer();
    }

    // TODO(jaewan): Reenable when session manager detects app installs
    @Ignore
    @Test
    public void testConnectToService_sessionService() throws InterruptedException {
        connectToService(TestUtils.getServiceToken(mContext, MockMediaSessionService2.ID));
        testConnectToService();
    }

    // TODO(jaewan): Reenable when session manager detects app installs
    @Ignore
    @Test
    public void testConnectToService_libraryService() throws InterruptedException {
        connectToService(TestUtils.getServiceToken(mContext, MockMediaLibraryService2.ID));
        testConnectToService();
    }

    public void testConnectToService() throws InterruptedException {
        TestServiceRegistry serviceInfo = TestServiceRegistry.getInstance();
        ControllerInfo info = serviceInfo.getOnConnectControllerInfo();
        assertEquals(mContext.getPackageName(), info.getPackageName());
        assertEquals(Process.myUid(), info.getUid());
        assertFalse(info.isTrusted());

        // Test command from controller to session service
        mController.play();
        assertTrue(mPlayer.mCountDownLatch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
        assertTrue(mPlayer.mPlayCalled);

        // Test command from session service to controller
        // TODO(jaewan): Add equivalent tests again
        /*
        final CountDownLatch latch = new CountDownLatch(1);
        mController.addPlaybackListener((state) -> {
            assertNotNull(state);
            assertEquals(PlaybackState.STATE_REWINDING, state.getState());
            latch.countDown();
        }, sHandler);
        mPlayer.notifyPlaybackState(
                TestUtils.createPlaybackState(PlaybackState.STATE_REWINDING));
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        */
    }

    @Test
    public void testControllerAfterSessionIsGone_session() throws InterruptedException {
        testControllerAfterSessionIsGone(mSession.getToken().getId());
    }

    @Ignore
    @Test
    public void testControllerAfterSessionIsGone_sessionService() throws InterruptedException {
        connectToService(TestUtils.getServiceToken(mContext, MockMediaSessionService2.ID));
        testControllerAfterSessionIsGone(MockMediaSessionService2.ID);
    }

    @Test
    public void testClose_beforeConnected() throws InterruptedException {
        MediaController2 controller =
                createController(mSession.getToken(), false, null);
        controller.close();
    }

    @Test
    public void testClose_twice() throws InterruptedException {
        mController.close();
        mController.close();
    }

    @Test
    public void testClose_session() throws InterruptedException {
        final String id = mSession.getToken().getId();
        mController.close();
        // close is done immediately for session.
        testNoInteraction();

        // Test whether the controller is notified about later close of the session or
        // re-creation.
        testControllerAfterSessionIsGone(id);
    }

    // TODO(jaewan): Reenable when session manager detects app installs
    @Ignore
    @Test
    public void testClose_sessionService() throws InterruptedException {
        connectToService(TestUtils.getServiceToken(mContext, MockMediaSessionService2.ID));
        testCloseFromService();
    }

    // TODO(jaewan): Reenable when session manager detects app installs
    @Ignore
    @Test
    public void testClose_libraryService() throws InterruptedException {
        connectToService(TestUtils.getServiceToken(mContext, MockMediaSessionService2.ID));
        testCloseFromService();
    }

    private void testCloseFromService() throws InterruptedException {
        final String id = mController.getSessionToken().getId();
        final CountDownLatch latch = new CountDownLatch(1);
        TestServiceRegistry.getInstance().setServiceInstanceChangedCallback((service) -> {
            if (service == null) {
                // Destroying..
                latch.countDown();
            }
        });
        mController.close();
        // Wait until close triggers onDestroy() of the session service.
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
        assertNull(TestServiceRegistry.getInstance().getServiceInstance());
        testNoInteraction();

        // Test whether the controller is notified about later close of the session or
        // re-creation.
        testControllerAfterSessionIsGone(id);
    }

    private void testControllerAfterSessionIsGone(final String id) throws InterruptedException {
        sHandler.postAndSync(() -> {
            // TODO(jaewan): Use Session.close later when we add the API.
            mSession.close();
        });
        waitForDisconnect(mController, true);
        testNoInteraction();

        // Test with the newly created session.
        sHandler.postAndSync(() -> {
            // Recreated session has different session stub, so previously created controller
            // shouldn't be available.
            mSession = new MediaSession2.Builder(mContext, mPlayer)
                    .setSessionCallback(sHandlerExecutor, new SessionCallback())
                    .setId(id).build();
        });
        testNoInteraction();
    }

    private void testNoInteraction() throws InterruptedException {
        final CountDownLatch latch = new CountDownLatch(1);
        final PlaybackListener playbackListener = (state) -> {
            fail("Controller shouldn't be notified about change in session after the close.");
            latch.countDown();
        };
        // TODO(jaewan): Add equivalent tests again
        /*
        mController.addPlaybackListener(playbackListener, sHandler);
        mPlayer.notifyPlaybackState(TestUtils.createPlaybackState(PlaybackState.STATE_BUFFERING));
        assertFalse(latch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
        mController.removePlaybackListener(playbackListener);
        */
    }

    // TODO(jaewan): Add  test for service connect rejection, when we differentiate session
    //               active/inactive and connection accept/refuse
}
