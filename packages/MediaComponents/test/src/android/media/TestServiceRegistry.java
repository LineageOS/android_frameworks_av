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

import static org.junit.Assert.fail;

import android.content.Context;
import android.media.MediaLibraryService2.MediaLibrarySession;
import android.media.MediaSession2.CommandGroup;
import android.media.MediaSession2.ControllerInfo;
import android.media.TestUtils.SyncHandler;
import android.os.Bundle;
import android.os.Handler;
import android.os.Process;
import android.support.annotation.GuardedBy;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

/**
 * Keeps the instance of currently running {@link MockMediaSessionService2}. And also provides
 * a way to control them in one place.
 * <p>
 * It only support only one service at a time.
 */
public class TestServiceRegistry {
    /**
     * Proxy for both {@link MediaSession2.SessionCallback} and
     * {@link MediaLibraryService2.MediaLibrarySession.MediaLibrarySessionCallback}.
     */
    public static abstract class SessionCallbackProxy {
        private final Context mContext;

        /**
         * Constructor
         */
        public SessionCallbackProxy(Context context) {
            mContext = context;
        }

        public final Context getContext() {
            return mContext;
        }

        /**
         * @param controller
         * @return
         */
        public CommandGroup onConnect(@NonNull MediaSession2 session,
                @NonNull ControllerInfo controller) {
            if (Process.myUid() == controller.getUid()) {
                CommandGroup commands = new CommandGroup(mContext);
                commands.addAllPredefinedCommands();
                return commands;
            }
            return null;
        }

        /**
         * Called when enclosing service is created.
         */
        public void onServiceCreated(MediaSessionService2 service) { }

        /**
         * Called when enclosing service is destroyed.
         */
        public void onServiceDestroyed() { }

        public void onSubscribe(@NonNull MediaLibrarySession session, @NonNull ControllerInfo info,
                @NonNull String parentId, @Nullable Bundle extra) { }
        public void onUnsubscribe(@NonNull MediaLibrarySession session,
                @NonNull ControllerInfo info, @NonNull String parentId) { }
    }

    @GuardedBy("TestServiceRegistry.class")
    private static TestServiceRegistry sInstance;
    @GuardedBy("TestServiceRegistry.class")
    private MediaSessionService2 mService;
    @GuardedBy("TestServiceRegistry.class")
    private SyncHandler mHandler;
    @GuardedBy("TestServiceRegistry.class")
    private SessionCallbackProxy mCallbackProxy;

    public static TestServiceRegistry getInstance() {
        synchronized (TestServiceRegistry.class) {
            if (sInstance == null) {
                sInstance = new TestServiceRegistry();
            }
            return sInstance;
        }
    }

    public void setHandler(Handler handler) {
        synchronized (TestServiceRegistry.class) {
            mHandler = new SyncHandler(handler.getLooper());
        }
    }

    public Handler getHandler() {
        synchronized (TestServiceRegistry.class) {
            return mHandler;
        }
    }

    public void setSessionCallbackProxy(SessionCallbackProxy callbackProxy) {
        synchronized (TestServiceRegistry.class) {
            mCallbackProxy = callbackProxy;
        }
    }

    public SessionCallbackProxy getSessionCallbackProxy() {
        synchronized (TestServiceRegistry.class) {
            return mCallbackProxy;
        }
    }

    public void setServiceInstance(MediaSessionService2 service) {
        synchronized (TestServiceRegistry.class) {
            if (mService != null) {
                fail("Previous service instance is still running. Clean up manually to ensure"
                        + " previoulsy running service doesn't break current test");
            }
            mService = service;
            if (mCallbackProxy != null) {
                mCallbackProxy.onServiceCreated(service);
            }
        }
    }

    public MediaSessionService2 getServiceInstance() {
        synchronized (TestServiceRegistry.class) {
            return mService;
        }
    }

    public void cleanUp() {
        synchronized (TestServiceRegistry.class) {
            final SessionCallbackProxy callbackProxy = mCallbackProxy;
            if (mService != null) {
                mService.getSession().close();
                // stopSelf() would not kill service while the binder connection established by
                // bindService() exists, and close() above will do the job instead.
                // So stopSelf() isn't really needed, but just for sure.
                mService.stopSelf();
                mService = null;
            }
            if (mHandler != null) {
                mHandler.removeCallbacksAndMessages(null);
            }
            mCallbackProxy = null;

            if (callbackProxy != null) {
                callbackProxy.onServiceDestroyed();
            }
        }
    }
}
