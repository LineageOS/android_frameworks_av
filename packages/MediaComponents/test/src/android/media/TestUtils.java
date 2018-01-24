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
import android.media.session.MediaSessionManager;
import android.media.session.PlaybackState;
import android.os.Bundle;
import android.os.Handler;

import android.os.Looper;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Utilities for tests.
 */
public final class TestUtils {
    private static final int WAIT_TIME_MS = 1000;
    private static final int WAIT_SERVICE_TIME_MS = 5000;

    /**
     * Creates a {@link android.media.session.PlaybackState} with the given state.
     *
     * @param state one of the PlaybackState.STATE_xxx.
     * @return a PlaybackState
     */
    public static PlaybackState createPlaybackState(int state) {
        return new PlaybackState.Builder().setState(state, 0, 1.0f).build();
    }

    /**
     * Finds the session with id in this test package.
     *
     * @param context
     * @param id
     * @return
     */
    // TODO(jaewan): Currently not working.
    public static SessionToken getServiceToken(Context context, String id) {
        MediaSessionManager manager =
                (MediaSessionManager) context.getSystemService(Context.MEDIA_SESSION_SERVICE);
        List<SessionToken> tokens = manager.getSessionServiceTokens();
        for (int i = 0; i < tokens.size(); i++) {
            SessionToken token = tokens.get(i);
            if (context.getPackageName().equals(token.getPackageName())
                    && id.equals(token.getId())) {
                return token;
            }
        }
        fail("Failed to find service");
        return null;
    }

    /**
     * Compares contents of two bundles.
     *
     * @param a a bundle
     * @param b another bundle
     * @return {@code true} if two bundles are the same. {@code false} otherwise. This may be
     *     incorrect if any bundle contains a bundle.
     */
    public static boolean equals(Bundle a, Bundle b) {
        if (a == b) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        if (!a.keySet().containsAll(b.keySet())
                || !b.keySet().containsAll(a.keySet())) {
            return false;
        }
        for (String key : a.keySet()) {
            if (!Objects.equals(a.get(key), b.get(key))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Handler that always waits until the Runnable finishes.
     */
    public static class SyncHandler extends Handler {
        public SyncHandler(Looper looper) {
            super(looper);
        }

        public void postAndSync(Runnable runnable) throws InterruptedException {
            final CountDownLatch latch = new CountDownLatch(1);
            if (getLooper() == Looper.myLooper()) {
                runnable.run();
            } else {
                post(()->{
                    runnable.run();
                    latch.countDown();
                });
                assertTrue(latch.await(WAIT_TIME_MS, TimeUnit.MILLISECONDS));
            }
        }
    }
}
