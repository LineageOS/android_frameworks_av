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
import android.media.MediaSession2.CommandGroup;
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
            mControllers.get(i).release();
        }
    }

    MediaController2Wrapper createController(SessionToken token) throws InterruptedException {
        return createController(token, true, null);
    }

    MediaController2Wrapper createController(@NonNull SessionToken token, boolean waitForConnect,
            @Nullable TestControllerCallback callback)
            throws InterruptedException {
        if (callback == null) {
            callback = new TestControllerCallback();
        }
        MediaController2Wrapper controller = new MediaController2Wrapper(mContext, token, callback);
        mControllers.add(controller);
        if (waitForConnect) {
            controller.waitForConnect(true);
        }
        return controller;
    }

    public static class TestControllerCallback extends MediaController2.ControllerCallback {
        public final CountDownLatch connectLatch = new CountDownLatch(1);
        public final CountDownLatch disconnectLatch = new CountDownLatch(1);

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
    }

    public class MediaController2Wrapper extends MediaController2 {
        private final TestControllerCallback mCallback;

        public MediaController2Wrapper(@NonNull Context context, @NonNull SessionToken token,
                @NonNull TestControllerCallback callback) {
            super(context, token, callback, sHandlerExecutor);
            mCallback = callback;
        }

        public void waitForConnect(boolean expect) throws InterruptedException {
            if (expect) {
                assertTrue(mCallback.connectLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
            } else {
                assertFalse(mCallback.connectLatch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
            }
        }

        public void waitForDisconnect(boolean expect) throws InterruptedException {
            if (expect) {
                assertTrue(mCallback.disconnectLatch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
            } else {
                assertFalse(mCallback.disconnectLatch.await(TIMEOUT_MS, TimeUnit.MILLISECONDS));
            }
        }
    }
}
