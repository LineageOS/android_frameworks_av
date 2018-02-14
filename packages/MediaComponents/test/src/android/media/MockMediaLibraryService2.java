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

import static junit.framework.Assert.fail;

import static org.junit.Assert.assertEquals;

import android.content.Context;
import android.media.MediaSession2.CommandGroup;
import android.media.MediaSession2.ControllerInfo;
import android.media.TestServiceRegistry.SessionCallbackProxy;
import android.media.TestUtils.SyncHandler;
import android.os.Bundle;
import android.util.Log;

import java.io.FileDescriptor;
import java.util.ArrayList;
import java.util.List;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import javax.annotation.concurrent.GuardedBy;

/**
 * Mock implementation of {@link MediaLibraryService2} for testing.
 */
public class MockMediaLibraryService2 extends MediaLibraryService2 {
    // Keep in sync with the AndroidManifest.xml
    public static final String ID = "TestLibrary";

    public static final String ROOT_ID = "rootId";
    public static final Bundle EXTRA = new Bundle();

    public static final String MEDIA_ID_GET_ITEM = "media_id_get_item";

    public static final String PARENT_ID = "parent_id";
    public static final String PARENT_ID_NO_CHILDREN = "parent_id_no_children";
    public static final String PARENT_ID_ERROR = "parent_id_error";

    public static final List<MediaItem2> GET_CHILDREN_RESULT = new ArrayList<>();
    public static final int CHILDREN_COUNT = 100;

    public static final String SEARCH_QUERY = "search_query";
    public static final String SEARCH_QUERY_TAKES_TIME = "search_query_takes_time";
    public static final int SEARCH_TIME_IN_MS = 5000;
    public static final String SEARCH_QUERY_EMPTY_RESULT = "search_query_empty_result";

    public static final List<MediaItem2> SEARCH_RESULT = new ArrayList<>();
    public static final int SEARCH_RESULT_COUNT = 50;

    private static final DataSourceDesc DATA_SOURCE_DESC =
            new DataSourceDesc.Builder().setDataSource(new FileDescriptor()).build();

    private static final String TAG = "MockMediaLibrarySvc2";

    static {
        EXTRA.putString(ROOT_ID, ROOT_ID);
    }
    @GuardedBy("MockMediaLibraryService2.class")
    private static SessionToken2 sToken;

    private MediaLibrarySession mSession;

    public MockMediaLibraryService2() {
        super();
        GET_CHILDREN_RESULT.clear();
        String getChildrenMediaIdPrefix = "get_children_media_id_";
        for (int i = 0; i < CHILDREN_COUNT; i++) {
            GET_CHILDREN_RESULT.add(createMediaItem(getChildrenMediaIdPrefix + i));
        }

        SEARCH_RESULT.clear();
        String getSearchResultMediaIdPrefix = "get_search_result_media_id_";
        for (int i = 0; i < SEARCH_RESULT_COUNT; i++) {
            SEARCH_RESULT.add(createMediaItem(getSearchResultMediaIdPrefix + i));
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        TestServiceRegistry.getInstance().setServiceInstance(this);
    }

    @Override
    public MediaLibrarySession onCreateSession(String sessionId) {
        final MockPlayer player = new MockPlayer(1);
        final SyncHandler handler = (SyncHandler) TestServiceRegistry.getInstance().getHandler();
        final Executor executor = (runnable) -> handler.post(runnable);
        SessionCallbackProxy sessionCallbackProxy = TestServiceRegistry.getInstance()
                .getSessionCallbackProxy();
        if (sessionCallbackProxy == null) {
            // Ensures non-null
            sessionCallbackProxy = new SessionCallbackProxy(this) {};
        }
        TestLibrarySessionCallback callback =
                new TestLibrarySessionCallback(sessionCallbackProxy);
        mSession = new MediaLibrarySessionBuilder(MockMediaLibraryService2.this, player,
                executor, callback).setId(sessionId).build();
        return mSession;
    }

    @Override
    public void onDestroy() {
        TestServiceRegistry.getInstance().cleanUp();
        super.onDestroy();
    }

    public static SessionToken2 getToken(Context context) {
        synchronized (MockMediaLibraryService2.class) {
            if (sToken == null) {
                sToken = new SessionToken2(context, context.getPackageName(),
                        MockMediaLibraryService2.class.getName());
                assertEquals(SessionToken2.TYPE_LIBRARY_SERVICE, sToken.getType());
            }
            return sToken;
        }
    }

    private class TestLibrarySessionCallback extends MediaLibrarySessionCallback {
        private final SessionCallbackProxy mCallbackProxy;

        public TestLibrarySessionCallback(SessionCallbackProxy callbackProxy) {
            super(MockMediaLibraryService2.this);
            mCallbackProxy = callbackProxy;
        }

        @Override
        public CommandGroup onConnect(ControllerInfo controller) {
            return mCallbackProxy.onConnect(controller);
        }

        @Override
        public LibraryRoot onGetRoot(ControllerInfo controller, Bundle rootHints) {
            return new LibraryRoot(MockMediaLibraryService2.this, ROOT_ID, EXTRA);
        }

        @Override
        public MediaItem2 onLoadItem(ControllerInfo controller, String mediaId) {
            if (MEDIA_ID_GET_ITEM.equals(mediaId)) {
                return createMediaItem(mediaId);
            } else {
                return null;
            }
        }

        @Override
        public List<MediaItem2> onLoadChildren(ControllerInfo controller, String parentId, int page,
                int pageSize, Bundle extras) {
            if (PARENT_ID.equals(parentId)) {
                return getPaginatedResult(GET_CHILDREN_RESULT, page, pageSize);
            } else if (PARENT_ID_ERROR.equals(parentId)) {
                return null;
            }
            // Includes the case of PARENT_ID_NO_CHILDREN.
            return new ArrayList<>();
        }

        @Override
        public void onSearch(ControllerInfo controllerInfo, String query, Bundle extras) {
            if (SEARCH_QUERY.equals(query)) {
                mSession.notifySearchResultChanged(controllerInfo, query, extras,
                        SEARCH_RESULT_COUNT);
            } else if (SEARCH_QUERY_TAKES_TIME.equals(query)) {
                // Searching takes some time. Notify after 5 seconds.
                Executors.newSingleThreadScheduledExecutor().schedule(new Runnable() {
                    @Override
                    public void run() {
                        mSession.notifySearchResultChanged(
                                controllerInfo, query, extras, SEARCH_RESULT_COUNT);
                    }
                }, SEARCH_TIME_IN_MS, TimeUnit.MILLISECONDS);
            } else if (SEARCH_QUERY_EMPTY_RESULT.equals(query)) {
                mSession.notifySearchResultChanged(controllerInfo, query, extras, 0);
            } else {
                // TODO: For the error case, how should we notify the browser?
            }
        }

        @Override
        public List<MediaItem2> onLoadSearchResult(ControllerInfo controllerInfo,
                String query, int page, int pageSize, Bundle extras) {
            if (SEARCH_QUERY.equals(query)) {
                return getPaginatedResult(SEARCH_RESULT, page, pageSize);
            } else {
                return null;
            }
        }
    }

    private List<MediaItem2> getPaginatedResult(List<MediaItem2> items, int page, int pageSize) {
        if (items == null) {
            return null;
        } else if (items.size() == 0) {
            return new ArrayList<>();
        }

        final int totalItemCount = items.size();
        int fromIndex = (page - 1) * pageSize;
        int toIndex = Math.min(page * pageSize, totalItemCount);

        List<MediaItem2> paginatedResult = new ArrayList<>();
        try {
            // The case of (fromIndex >= totalItemCount) will throw exception below.
            paginatedResult = items.subList(fromIndex, toIndex);
        } catch (IndexOutOfBoundsException | IllegalArgumentException ex) {
            Log.d(TAG, "Result is empty for given pagination arguments: totalItemCount="
                    + totalItemCount + ", page=" + page + ", pageSize=" + pageSize, ex);
        }
        return paginatedResult;
    }

    private MediaItem2 createMediaItem(String mediaId) {
        Context context = MockMediaLibraryService2.this;
        return new MediaItem2(
                context,
                mediaId,
                DATA_SOURCE_DESC,
                new MediaMetadata2.Builder(context)
                        .putString(MediaMetadata2.METADATA_KEY_MEDIA_ID, mediaId)
                        .build(),
                0 /* Flags */);
    }
}