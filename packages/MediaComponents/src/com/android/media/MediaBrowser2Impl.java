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

package com.android.media;

import android.content.Context;
import android.media.IMediaSession2;
import android.media.MediaBrowser2;
import android.media.MediaBrowser2.BrowserCallback;
import android.media.MediaSession2.CommandButton;
import android.media.SessionToken2;
import android.media.update.MediaBrowser2Provider;
import android.os.Bundle;
import android.os.RemoteException;
import android.util.Log;

import java.util.List;
import java.util.concurrent.Executor;

public class MediaBrowser2Impl extends MediaController2Impl implements MediaBrowser2Provider {
    private final String TAG = "MediaBrowser2";
    private final boolean DEBUG = true; // TODO(jaewan): change.

    private final MediaBrowser2 mInstance;
    private final MediaBrowser2.BrowserCallback mCallback;

    public MediaBrowser2Impl(MediaBrowser2 instance, Context context, SessionToken2 token,
            BrowserCallback callback, Executor executor) {
        super(instance, context, token, callback, executor);
        mInstance = instance;
        mCallback = callback;
    }

    @Override
    public void getBrowserRoot_impl(Bundle rootHints) {
        final IMediaSession2 binder = getSessionBinder();
        if (binder != null) {
            try {
                binder.getBrowserRoot(getControllerStub(), rootHints);
            } catch (RemoteException e) {
                // TODO(jaewan): Handle disconnect.
                if (DEBUG) {
                    Log.w(TAG, "Cannot connect to the service or the session is gone", e);
                }
            }
        } else {
            Log.w(TAG, "Session isn't active", new IllegalStateException());
        }
    }

    @Override
    public void subscribe_impl(String parentId, Bundle options) {
        // TODO(jaewan): Implement
    }

    @Override
    public void unsubscribe_impl(String parentId, Bundle options) {
        // TODO(jaewan): Implement
    }

    @Override
    public void getItem_impl(String mediaId) {
        // TODO(jaewan): Implement
    }

    @Override
    public void getChildren_impl(String parentId, int page, int pageSize, Bundle options) {
        // TODO(jaewan): Implement
    }

    @Override
    public void search_impl(String query, int page, int pageSize, Bundle extras) {
        // TODO(jaewan): Implement
    }

    public void onGetRootResult(
            final Bundle rootHints, final String rootMediaId, final Bundle rootExtra) {
        getCallbackExecutor().execute(() -> {
            mCallback.onGetRootResult(rootHints, rootMediaId, rootExtra);
        });
    }

    public void onCustomLayoutChanged(final List<CommandButton> layout) {
        getCallbackExecutor().execute(() -> {
            mCallback.onCustomLayoutChanged(layout);
        });
    }
}
