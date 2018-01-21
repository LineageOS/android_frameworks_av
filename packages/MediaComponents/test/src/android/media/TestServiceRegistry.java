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

import android.media.MediaSession2.ControllerInfo;
import android.media.TestUtils.SyncHandler;
import android.os.Handler;
import android.os.Looper;
import android.support.annotation.GuardedBy;

/**
 * Keeps the instance of currently running {@link MockMediaSessionService2}. And also provides
 * a way to control them in one place.
 * <p>
 * It only support only one service at a time.
 */
public class TestServiceRegistry {
    public interface ServiceInstanceChangedCallback {
        void OnServiceInstanceChanged(MediaSessionService2 service);
    }

    @GuardedBy("TestServiceRegistry.class")
    private static TestServiceRegistry sInstance;
    @GuardedBy("TestServiceRegistry.class")
    private MediaSessionService2 mService;
    @GuardedBy("TestServiceRegistry.class")
    private SyncHandler mHandler;
    @GuardedBy("TestServiceRegistry.class")
    private ControllerInfo mOnConnectControllerInfo;
    @GuardedBy("TestServiceRegistry.class")
    private ServiceInstanceChangedCallback mCallback;

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

    public void setServiceInstanceChangedCallback(ServiceInstanceChangedCallback callback) {
        synchronized (TestServiceRegistry.class) {
            mCallback = callback;
        }
    }

    public Handler getHandler() {
        synchronized (TestServiceRegistry.class) {
            return mHandler;
        }
    }

    public void setServiceInstance(MediaSessionService2 service, ControllerInfo controller) {
        synchronized (TestServiceRegistry.class) {
            if (mService != null) {
                fail("Previous service instance is still running. Clean up manually to ensure"
                        + " previoulsy running service doesn't break current test");
            }
            mService = service;
            mOnConnectControllerInfo = controller;
            if (mCallback != null) {
                mCallback.OnServiceInstanceChanged(service);
            }
        }
    }

    public MediaSessionService2 getServiceInstance() {
        synchronized (TestServiceRegistry.class) {
            return mService;
        }
    }

    public ControllerInfo getOnConnectControllerInfo() {
        synchronized (TestServiceRegistry.class) {
            return mOnConnectControllerInfo;
        }
    }


    public void cleanUp() {
        synchronized (TestServiceRegistry.class) {
            final ServiceInstanceChangedCallback callback = mCallback;
            if (mService != null) {
                try {
                    if (mHandler.getLooper() == Looper.myLooper()) {
                        mService.getSession().setPlayer(null);
                    } else {
                        mHandler.postAndSync(() -> {
                            mService.getSession().setPlayer(null);
                        });
                    }
                } catch (InterruptedException e) {
                    // No-op. Service containing session will die, but shouldn't be a huge issue.
                }
                // stopSelf() would not kill service while the binder connection established by
                // bindService() exists, and setPlayer(null) above will do the job instead.
                // So stopSelf() isn't really needed, but just for sure.
                mService.stopSelf();
                mService = null;
            }
            if (mHandler != null) {
                mHandler.removeCallbacksAndMessages(null);
            }
            mCallback = null;
            mOnConnectControllerInfo = null;

            if (callback != null) {
                callback.OnServiceInstanceChanged(null);
            }
        }
    }
}
