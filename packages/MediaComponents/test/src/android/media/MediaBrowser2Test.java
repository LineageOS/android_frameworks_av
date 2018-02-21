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
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;
import static junit.framework.Assert.assertNull;

import android.annotation.Nullable;
import android.content.Context;
import android.media.MediaBrowser2.BrowserCallback;
import android.media.MediaSession2.Command;
import android.media.MediaSession2.CommandButton;
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

import java.util.List;
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
        default void onItemLoaded(String mediaId, MediaItem2 result) {}
        default void onChildrenLoaded(String parentId, int page, int pageSize, Bundle extras,
                List<MediaItem2> result) {}
        default void onSearchResultChanged(String query, Bundle extras, int itemCount) {}
        default void onSearchResultLoaded(String query, int page, int pageSize, Bundle extras,
                List<MediaItem2> result) {}
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

    @Test
    public void testGetItem() throws InterruptedException {
        final String mediaId = MockMediaLibraryService2.MEDIA_ID_GET_ITEM;

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestBrowserCallbackInterface() {
            @Override
            public void onItemLoaded(String mediaIdOut, MediaItem2 result) {
                assertEquals(mediaId, mediaIdOut);
                assertNotNull(result);
                assertEquals(mediaId, result.getMediaId());
                latch.countDown();
            }
        };

        final SessionToken2 token = MockMediaLibraryService2.getToken(mContext);
        MediaBrowser2 browser = (MediaBrowser2) createController(token, true, callback);
        browser.getItem(mediaId);
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    @Test
    public void testGetItemNullResult() throws InterruptedException {
        final String mediaId = "random_media_id";

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestBrowserCallbackInterface() {
            @Override
            public void onItemLoaded(String mediaIdOut, MediaItem2 result) {
                assertEquals(mediaId, mediaIdOut);
                assertNull(result);
                latch.countDown();
            }
        };

        final SessionToken2 token = MockMediaLibraryService2.getToken(mContext);
        MediaBrowser2 browser = (MediaBrowser2) createController(token, true, callback);
        browser.getItem(mediaId);
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    @Test
    public void testGetChildren() throws InterruptedException {
        final String parentId = MockMediaLibraryService2.PARENT_ID;
        final int page = 4;
        final int pageSize = 10;
        final Bundle extras = new Bundle();
        extras.putString(TAG, TAG);

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestBrowserCallbackInterface() {
            @Override
            public void onChildrenLoaded(String parentIdOut, int pageOut, int pageSizeOut,
                    Bundle extrasOut, List<MediaItem2> result) {
                assertEquals(parentId, parentIdOut);
                assertEquals(page, pageOut);
                assertEquals(pageSize, pageSizeOut);
                assertTrue(TestUtils.equals(extras, extrasOut));
                assertNotNull(result);

                int fromIndex = (page - 1) * pageSize;
                int toIndex = Math.min(page * pageSize, MockMediaLibraryService2.CHILDREN_COUNT);

                // Compare the given results with originals.
                for (int originalIndex = fromIndex; originalIndex < toIndex; originalIndex++) {
                    int relativeIndex = originalIndex - fromIndex;
                    assertEquals(
                            MockMediaLibraryService2.GET_CHILDREN_RESULT.get(originalIndex)
                                    .getMediaId(),
                            result.get(relativeIndex).getMediaId());
                }
                latch.countDown();
            }
        };

        final SessionToken2 token = MockMediaLibraryService2.getToken(mContext);
        MediaBrowser2 browser = (MediaBrowser2) createController(token, true, callback);
        browser.getChildren(parentId, page, pageSize, extras);
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    @Test
    public void testGetChildrenEmptyResult() throws InterruptedException {
        final String parentId = MockMediaLibraryService2.PARENT_ID_NO_CHILDREN;

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestBrowserCallbackInterface() {
            @Override
            public void onChildrenLoaded(String parentIdOut, int pageOut, int pageSizeOut,
                    Bundle extrasOut, List<MediaItem2> result) {
                assertNotNull(result);
                assertEquals(0, result.size());
                latch.countDown();
            }
        };

        final SessionToken2 token = MockMediaLibraryService2.getToken(mContext);
        MediaBrowser2 browser = (MediaBrowser2) createController(token, true, callback);
        browser.getChildren(parentId, 1, 1, null);
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    @Test
    public void testGetChildrenNullResult() throws InterruptedException {
        final String parentId = MockMediaLibraryService2.PARENT_ID_ERROR;

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestBrowserCallbackInterface() {
            @Override
            public void onChildrenLoaded(String parentIdOut, int pageOut, int pageSizeOut,
                    Bundle extrasOut, List<MediaItem2> result) {
                assertNull(result);
                latch.countDown();
            }
        };

        final SessionToken2 token = MockMediaLibraryService2.getToken(mContext);
        MediaBrowser2 browser = (MediaBrowser2) createController(token, true, callback);
        browser.getChildren(parentId, 1, 1, null);
        assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    @Test
    public void testSearch() throws InterruptedException {
        final String query = MockMediaLibraryService2.SEARCH_QUERY;
        final int page = 4;
        final int pageSize = 10;
        final Bundle extras = new Bundle();
        extras.putString(TAG, TAG);

        final CountDownLatch latchForSearch = new CountDownLatch(1);
        final CountDownLatch latchForGetSearchResult = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestBrowserCallbackInterface() {
            @Override
            public void onSearchResultChanged(String queryOut, Bundle extrasOut, int itemCount) {
                assertEquals(query, queryOut);
                assertTrue(TestUtils.equals(extras, extrasOut));
                assertEquals(MockMediaLibraryService2.SEARCH_RESULT_COUNT, itemCount);
                latchForSearch.countDown();
            }

            @Override
            public void onSearchResultLoaded(String queryOut, int pageOut, int pageSizeOut,
                    Bundle extrasOut, List<MediaItem2> result) {
                assertEquals(query, queryOut);
                assertEquals(page, pageOut);
                assertEquals(pageSize, pageSizeOut);
                assertTrue(TestUtils.equals(extras, extrasOut));
                assertNotNull(result);

                int fromIndex = (page - 1) * pageSize;
                int toIndex = Math.min(
                        page * pageSize, MockMediaLibraryService2.SEARCH_RESULT_COUNT);

                // Compare the given results with originals.
                for (int originalIndex = fromIndex; originalIndex < toIndex; originalIndex++) {
                    int relativeIndex = originalIndex - fromIndex;
                    assertEquals(
                            MockMediaLibraryService2.SEARCH_RESULT.get(originalIndex).getMediaId(),
                            result.get(relativeIndex).getMediaId());
                }
                latchForGetSearchResult.countDown();
            }
        };

        // Request the search.
        final SessionToken2 token = MockMediaLibraryService2.getToken(mContext);
        MediaBrowser2 browser = (MediaBrowser2) createController(token, true, callback);
        browser.search(query, extras);
        assertTrue(latchForSearch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));

        // Get the search result.
        browser.getSearchResult(query, page, pageSize, extras);
        assertTrue(latchForGetSearchResult.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    @Test
    public void testSearchTakesTime() throws InterruptedException {
        final String query = MockMediaLibraryService2.SEARCH_QUERY_TAKES_TIME;
        final Bundle extras = new Bundle();
        extras.putString(TAG, TAG);

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestBrowserCallbackInterface() {
            @Override
            public void onSearchResultChanged(String queryOut, Bundle extrasOut, int itemCount) {
                assertEquals(query, queryOut);
                assertTrue(TestUtils.equals(extras, extrasOut));
                assertEquals(MockMediaLibraryService2.SEARCH_RESULT_COUNT, itemCount);
                latch.countDown();
            }
        };

        final SessionToken2 token = MockMediaLibraryService2.getToken(mContext);
        MediaBrowser2 browser = (MediaBrowser2) createController(token, true, callback);
        browser.search(query, extras);
        assertTrue(latch.await(
                MockMediaLibraryService2.SEARCH_TIME_IN_MS + WAIT_TIME_MS, TimeUnit.MILLISECONDS));
    }

    @Test
    public void testSearchEmptyResult() throws InterruptedException {
        final String query = MockMediaLibraryService2.SEARCH_QUERY_EMPTY_RESULT;
        final Bundle extras = new Bundle();
        extras.putString(TAG, TAG);

        final CountDownLatch latch = new CountDownLatch(1);
        final TestControllerCallbackInterface callback = new TestBrowserCallbackInterface() {
            @Override
            public void onSearchResultChanged(String queryOut, Bundle extrasOut, int itemCount) {
                assertEquals(query, queryOut);
                assertTrue(TestUtils.equals(extras, extrasOut));
                assertEquals(0, itemCount);
                latch.countDown();
            }
        };

        final SessionToken2 token = MockMediaLibraryService2.getToken(mContext);
        MediaBrowser2 browser = (MediaBrowser2) createController(token, true, callback);
        browser.search(query, extras);
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
            connectLatch.countDown();
        }

        @CallSuper
        @Override
        public void onDisconnected() {
            disconnectLatch.countDown();
        }

        @Override
        public void onPlaybackStateChanged(PlaybackState2 state) {
            mCallbackProxy.onPlaybackStateChanged(state);
        }

        @Override
        public void onPlaylistParamsChanged(PlaylistParams params) {
            mCallbackProxy.onPlaylistParamsChanged(params);
        }

        @Override
        public void onPlaybackInfoChanged(MediaController2.PlaybackInfo info) {
            mCallbackProxy.onPlaybackInfoChanged(info);
        }

        @Override
        public void onCustomCommand(Command command, Bundle args, ResultReceiver receiver) {
            mCallbackProxy.onCustomCommand(command, args, receiver);
        }


        @Override
        public void onCustomLayoutChanged(List<CommandButton> layout) {
            mCallbackProxy.onCustomLayoutChanged(layout);
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
        public void onItemLoaded(String mediaId, MediaItem2 result) {
            super.onItemLoaded(mediaId, result);
            if (mCallbackProxy instanceof TestBrowserCallbackInterface) {
                ((TestBrowserCallbackInterface) mCallbackProxy).onItemLoaded(mediaId, result);
            }
        }

        @Override
        public void onChildrenLoaded(String parentId, int page, int pageSize, Bundle extras,
                List<MediaItem2> result) {
            super.onChildrenLoaded(parentId, page, pageSize, extras, result);
            if (mCallbackProxy instanceof TestBrowserCallbackInterface) {
                ((TestBrowserCallbackInterface) mCallbackProxy)
                        .onChildrenLoaded(parentId, page, pageSize, extras, result);
            }
        }

        @Override
        public void onSearchResultChanged(String query, Bundle extras, int itemCount) {
            super.onSearchResultChanged(query, extras, itemCount);
            if (mCallbackProxy instanceof TestBrowserCallbackInterface) {
                ((TestBrowserCallbackInterface) mCallbackProxy)
                        .onSearchResultChanged(query, extras, itemCount);
            }
        }

        @Override
        public void onSearchResultLoaded(String query, int page, int pageSize, Bundle extras,
                List<MediaItem2> result) {
            super.onSearchResultLoaded(query, page, pageSize, extras, result);
            if (mCallbackProxy instanceof TestBrowserCallbackInterface) {
                ((TestBrowserCallbackInterface) mCallbackProxy)
                        .onSearchResultLoaded(query, page, pageSize, extras, result);
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