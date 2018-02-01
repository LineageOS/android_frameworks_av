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
import static junit.framework.Assert.assertFalse;
import static junit.framework.Assert.assertTrue;

import android.annotation.Nullable;
import android.content.Context;
import android.media.MediaBrowser2.BrowserCallback;
import android.media.MediaSession2.Command;
import android.media.MediaSession2.CommandGroup;
import android.media.MediaSession2.PlaylistParams;
import android.os.Bundle;
import android.os.ResultReceiver;
import android.support.annotation.CallSuper;
import android.support.annotation.NonNull;
import android.support.test.filters.SmallTest;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Tests {@link MediaBrowser2}.
 * <p>
 * This test inherits {@link MediaController2Test} to ensure that inherited APIs from
 * {@link MediaController2} works cleanly.
 */
// TODO(jaewan): Implement host-side test so browser and service can run in different processes.
@RunWith(AndroidJUnit4.class)
@SmallTest
public class MediaBrowser2Test extends MediaController2Test {
    private static final String TAG = "MediaBrowser2Test";

    @Override
    TestControllerInterface onCreateController(@NonNull SessionToken2 token,
            @Nullable TestControllerCallbackInterface callback) {
        if (callback == null) {
            callback = new TestBrowserCallbackInterface() {};
        }
        return new TestMediaBrowser(mContext, token, new TestBrowserCallback(callback));
    }

    interface TestBrowserCallbackInterface extends TestControllerCallbackInterface {
        // Browser specific callbacks
        default void onGetRootResult(Bundle rootHints, String rootMediaId, Bundle rootExtra) {}
    }

    @Test
    public void testGetLibraryRoot() throws InterruptedException {
        final Bundle param = new Bundle();
        param.putString(TAG, TAG);

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestBrowserCallbackInterface() {
            @Override
            public void onGetRootResult(Bundle rootHints, String rootMediaId, Bundle rootExtra) {
                assertTrue(TestUtils.equals(param, rootHints));
                assertEquals(MockMediaLibraryService2.ROOT_ID, rootMediaId);
                assertTrue(TestUtils.equals(MockMediaLibraryService2.EXTRA, rootExtra));
                latch.countDown();
            }
        };

        final SessionToken2 token = MockMediaLibraryService2.getToken(mContext);
        MediaBrowser2 browser =
                (MediaBrowser2) createController(token,true, callback);
        browser.getLibraryRoot(param);
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    public static class TestBrowserCallback extends BrowserCallback
            implements WaitForConnectionInterface {
        private final TestControllerCallbackInterface mCallbackProxy;
        public final CountDownLatch connectLatch = new CountDownLatch(1);
        public final CountDownLatch disconnectLatch = new CountDownLatch(1);

        TestBrowserCallback(TestControllerCallbackInterface callbackProxy) {
            if (callbackProxy == null) {
                throw new IllegalArgumentException("Callback proxy shouldn't be null. Test bug");
            }
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
            mCallbackProxy.onPlaybackStateChanged(state);
        }

        @Override
        public void onPlaylistParamsChanged(PlaylistParams params) {
            super.onPlaylistParamsChanged(params);
            mCallbackProxy.onPlaylistParamsChanged(params);
        }

        @Override
        public void onCustomCommand(Command command, Bundle args, ResultReceiver receiver) {
            super.onCustomCommand(command, args, receiver);
            mCallbackProxy.onCustomCommand(command, args, receiver);
        }

        @Override
        public void onGetRootResult(Bundle rootHints, String rootMediaId, Bundle rootExtra) {
            super.onGetRootResult(rootHints, rootMediaId, rootExtra);
            if (mCallbackProxy instanceof TestBrowserCallbackInterface) {
                ((TestBrowserCallbackInterface) mCallbackProxy)
                        .onGetRootResult(rootHints, rootMediaId, rootExtra);
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
    }

    public class TestMediaBrowser extends MediaBrowser2 implements TestControllerInterface {
        private final BrowserCallback mCallback;

        public TestMediaBrowser(@NonNull Context context, @NonNull SessionToken2 token,
                @NonNull ControllerCallback callback) {
            super(context, token, sHandlerExecutor, (BrowserCallback) callback);
            mCallback = (BrowserCallback) callback;
        }

        @Override
        public BrowserCallback getCallback() {
            return mCallback;
        }
    }
}