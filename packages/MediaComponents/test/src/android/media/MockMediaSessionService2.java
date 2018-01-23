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

import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.SessionCallback;
import android.media.TestUtils.SyncHandler;
import android.os.Process;

/**
 * Mock implementation of {@link android.media.MediaSessionService2} for testing.
 */
public class MockMediaSessionService2 extends MediaSessionService2 {
    // Keep in sync with the AndroidManifest.xml
    public static final String ID = "TestSession";
    public MediaSession2 mSession;

    @Override
    public MediaSession2 onCreateSession(String sessionId) {
        final MockPlayer player = new MockPlayer(1);
        SyncHandler handler = (SyncHandler) TestServiceRegistry.getInstance().getHandler();
        try {
            handler.postAndSync(() -> {
                mSession = new MediaSession2.Builder(MockMediaSessionService2.this, player)
                        .setId(sessionId).setSessionCallback(new MySessionCallback()).build();
            });
        } catch (InterruptedException e) {
            fail(e.toString());
        }
        return mSession;
    }

    @Override
    public void onCreate() {
        super.onCreate();
    }

    @Override
    public void onDestroy() {
        TestServiceRegistry.getInstance().cleanUp();
        super.onDestroy();
    }

    private class MySessionCallback extends SessionCallback {
        @Override
        public MediaSession2.CommandGroup onConnect(ControllerInfo controller) {
            if (Process.myUid() != controller.getUid()) {
                // It's system app wants to listen changes. Ignore.
                return super.onConnect(controller);
            }
            TestServiceRegistry.getInstance().setServiceInstance(
                    MockMediaSessionService2.this, controller);
            return super.onConnect(controller);
        }
    }
}
