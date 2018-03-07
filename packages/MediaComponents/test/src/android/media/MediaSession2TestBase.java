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
import android.media.MediaSession2.Command;
import android.media.MediaSession2.CommandButton;
import android.media.MediaSession2.CommandGroup;
import android.os.Bundle;
import android.os.HandlerThread;
import android.os.ResultReceiver;
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

    // Any change here should be also reflected to the TestControllerCallback and
    // TestBrowserCallback
    interface TestControllerCallbackInterface {
        // Add methods in ControllerCallback that you want to test.
        default void onPlaylistChanged(List<MediaItem2> playlist) {}
        default void onPlaylistParamsChanged(MediaSession2.PlaylistParams params) {}
        default void onPlaybackInfoChanged(MediaController2.PlaybackInfo info) {}
        default void onPlaybackStateChanged(PlaybackState2 state) {}
        default void onCustomLayoutChanged(List<CommandButton> layout) {}
        default void onAllowedCommandsChanged(CommandGroup commands) {}
        default void onCustomCommand(Command command, Bundle args, ResultReceiver receiver) {}
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

    /**
     * Creates a {@link android.media.session.PlaybackState} with the given state.
     *
     * @param state one of the PlaybackState.STATE_xxx.
     * @return a PlaybackState
     */
    public PlaybackState2 createPlaybackState(int state) {
        return new PlaybackState2(mContext, state, 0, 0, 1.0f, 0, 0);
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
            @Nullable TestControllerCallbackInterface callback) {
        if (callback == null) {
            callback = new TestControllerCallbackInterface() {};
        }
        return new TestMediaController(mContext, token, new TestControllerCallback(callback));
    }

    public static class TestControllerCallback extends MediaController2.ControllerCallback
            implements WaitForConnectionInterface {
        public final TestControllerCallbackInterface mCallbackProxy;
        public final CountDownLatch connectLatch = new CountDownLatch(1);
        public final CountDownLatch disconnectLatch = new CountDownLatch(1);

        TestControllerCallback(@NonNull TestControllerCallbackInterface callbackProxy) {
            if (callbackProxy == null) {
                throw new IllegalArgumentException("Callback proxy shouldn't be null. Test bug");
            }
            mCallbackProxy = callbackProxy;
        }

        @CallSuper
        @Override
        public void onConnected(MediaController2 controller, CommandGroup commands) {
            connectLatch.countDown();
        }

        @CallSuper
        @Override
        public void onDisconnected(MediaController2 controller) {
            disconnectLatch.countDown();
        }

        @Override
        public void onPlaybackStateChanged(MediaController2 controller, PlaybackState2 state) {
            mCallbackProxy.onPlaybackStateChanged(state);
        }

        @Override
        public void onCustomCommand(MediaController2 controller, Command command, Bundle args,
                ResultReceiver receiver) {
            mCallbackProxy.onCustomCommand(command, args, receiver);
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
        public void onPlaylistChanged(MediaController2 controller, List<MediaItem2> params) {
            mCallbackProxy.onPlaylistChanged(params);
        }

        @Override
        public void onPlaylistParamsChanged(MediaController2 controller,
                MediaSession2.PlaylistParams params) {
            mCallbackProxy.onPlaylistParamsChanged(params);
        }

        @Override
        public void onPlaybackInfoChanged(MediaController2 controller,
                MediaController2.PlaybackInfo info) {
            mCallbackProxy.onPlaybackInfoChanged(info);
        }

        @Override
        public void onCustomLayoutChanged(MediaController2 controller, List<CommandButton> layout) {
            mCallbackProxy.onCustomLayoutChanged(layout);
        }

        @Override
        public void onAllowedCommandsChanged(MediaController2 controller, CommandGroup commands) {
            mCallbackProxy.onAllowedCommandsChanged(commands);
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
