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

import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;

import android.content.Context;
import android.media.MediaController2.ControllerCallback;
import android.media.MediaSession2.CommandGroup;
import android.os.Bundle;
import android.os.HandlerThread;
import android.support.annotation.CallSuper;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.test.InstrumentationRegistry;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import org.junit.AfterClass;
import org.junit.BeforeClass;

/**
 * Base class for session test.
 */
abstract class MediaSession2TestBase {
    // Expected success
    static final int WAIT_TIME_MS = 1000;

    // Expected timeout
    static final int TIMEOUT_MS = 500;

    static TestUtils.SyncHandler sHandler;
    static Executor sHandlerExecutor;

    Context mContext;
    private List<MediaController2> mControllers = new ArrayList<>();

    interface TestControllerInterface {
        ControllerCallback getCallback();
    }

    interface TestControllerCallbackInterface {
        // Add methods in ControllerCallback/BrowserCallback that you want to test.
        default void onPlaylistParamsChanged(MediaSession2.PlaylistParams params) {}

        // Currently empty. Add methods in ControllerCallback/BrowserCallback that you want to test.
        default void onPlaybackStateChanged(PlaybackState2 state) { }

        // Browser specific callbacks
        default void onGetRootResult(Bundle rootHints, String rootMediaId, Bundle rootExtra) {}
    }

    interface WaitForConnectionInterface {
        void waitForConnect(boolean expect) throws InterruptedException;
        void waitForDisconnect(boolean expect) throws InterruptedException;
    }

    @BeforeClass
    public static void setUpThread() {
        if (sHandler == null) {
            HandlerThread handlerThread = new HandlerThread("MediaSession2TestBase");
            handlerThread.start();
            sHandler = new TestUtils.SyncHandler(handlerThread.getLooper());
            sHandlerExecutor = (runnable) -> {
                sHandler.post(runnable);
            };
        }
    }

    @AfterClass
    public static void cleanUpThread() {
        if (sHandler != null) {
            sHandler.getLooper().quitSafely();
            sHandler = null;
            sHandlerExecutor = null;
        }
    }

    @CallSuper
    public void setUp() throws Exception {
        mContext = InstrumentationRegistry.getTargetContext();
    }

    @CallSuper
    public void cleanUp() throws Exception {
        for (int i = 0; i < mControllers.size(); i++) {
            mControllers.get(i).close();
        }
    }

    final MediaController2 createController(SessionToken2 token) throws InterruptedException {
        return createController(token, true, null);
    }

    final MediaController2 createController(@NonNull SessionToken2 token,
            boolean waitForConnect, @Nullable TestControllerCallbackInterface callback)
            throws InterruptedException {
        TestControllerInterface instance = onCreateController(token, callback);
        if (!(instance instanceof MediaController2)) {
            throw new RuntimeException("Test has a bug. Expected MediaController2 but returned "
                    + instance);
        }
        MediaController2 controller = (MediaController2) instance;
        mControllers.add(controller);
        if (waitForConnect) {
            waitForConnect(controller, true);
        }
        return controller;
    }

    private static WaitForConnectionInterface getWaitForConnectionInterface(
            MediaController2 controller) {
        if (!(controller instanceof TestControllerInterface)) {
            throw new RuntimeException("Test has a bug. Expected controller implemented"
                    + " TestControllerInterface but got " + controller);
        }
        ControllerCallback callback = ((TestControllerInterface) controller).getCallback();
        if (!(callback instanceof WaitForConnectionInterface)) {
            throw new RuntimeException("Test has a bug. Expected controller with callback "
                    + " implemented WaitForConnectionInterface but got " + controller);
        }
        return (WaitForConnectionInterface) callback;
    }

    public static void waitForConnect(MediaController2 controller, boolean expected)
            throws InterruptedException {
        getWaitForConnectionInterface(controller).waitForConnect(expected);
    }

    public static void waitForDisconnect(MediaController2 controller, boolean expected)
            throws InterruptedException {
        getWaitForConnectionInterface(controller).waitForDisconnect(expected);
    }

    TestControllerInterface onCreateController(@NonNull SessionToken2 token,
            @NonNull TestControllerCallbackInterface callback) {
        return new TestMediaController(mContext, token, new TestControllerCallback(callback));
    }

    public static class TestControllerCallback extends MediaController2.ControllerCallback
            implements WaitForConnectionInterface {
        public final TestControllerCallbackInterface mCallbackProxy;
        public final CountDownLatch connectLatch = new CountDownLatch(1);
        public final CountDownLatch disconnectLatch = new CountDownLatch(1);

        TestControllerCallback(TestControllerCallbackInterface callbackProxy) {
            mCallbackProxy = callbackProxy;
        }

        @CallSuper
        @Override
        public void onConnected(CommandGroup commands) {
            super.onConnected(commands);
            connectLatch.countDown();
        }

        @CallSuper
        @Override
        public void onDisconnected() {
            super.onDisconnected();
            disconnectLatch.countDown();
        }

        @Override
        public void onPlaybackStateChanged(PlaybackState2 state) {
            super.onPlaybackStateChanged(state);
            if (mCallbackProxy != null) {
                mCallbackProxy.onPlaybackStateChanged(state);
            }
        }

        @Override
        public void waitForConnect(boolean expect) throws InterruptedException {
            if (expect) {
                assertTrue(connectLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
            } else {
                assertFalse(connectLatch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
            }
        }

        @Override
        public void waitForDisconnect(boolean expect) throws InterruptedException {
            if (expect) {
                assertTrue(disconnectLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
            } else {
                assertFalse(disconnectLatch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
            }
        }

        @Override
        public void onPlaylistParamsChanged(MediaSession2.PlaylistParams params) {
            mCallbackProxy.onPlaylistParamsChanged(params);
        }
    }

    public class TestMediaController extends MediaController2 implements TestControllerInterface {
        private final ControllerCallback mCallback;

        public TestMediaController(@NonNull Context context, @NonNull SessionToken2 token,
                @NonNull ControllerCallback callback) {
            super(context, token, sHandlerExecutor, callback);
            mCallback = callback;
        }

        @Override
        public ControllerCallback getCallback() {
            return mCallback;
        }
    }
}
