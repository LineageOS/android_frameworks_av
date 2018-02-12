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
import android.os.Process;

import java.util.concurrent.Executor;

import javax.annotation.concurrent.GuardedBy;

/**
 * Mock implementation of {@link MediaLibraryService2} for testing.
 */
public class MockMediaLibraryService2 extends MediaLibraryService2 {
    // Keep in sync with the AndroidManifest.xml
    public static final String ID = "TestLibrary";

    public static final String ROOT_ID = "rootId";
    public static final Bundle EXTRA = new Bundle();
    static {
        EXTRA.putString(ROOT_ID, ROOT_ID);
    }
    @GuardedBy("MockMediaLibraryService2.class")
    private static SessionToken2 sToken;

    private MediaLibrarySession mSession;

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
    }
}