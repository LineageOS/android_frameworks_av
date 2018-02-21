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
import android.media.MediaBrowser2;
import android.media.MediaBrowser2.BrowserCallback;
import android.media.MediaItem2;
import android.media.SessionToken2;
import android.media.update.MediaBrowser2Provider;
import android.os.Bundle;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;

import java.util.List;
import java.util.concurrent.Executor;

public class MediaBrowser2Impl extends MediaController2Impl implements MediaBrowser2Provider {
    private final String TAG = "MediaBrowser2";
    private final boolean DEBUG = true; // TODO(jaewan): change.

    private final MediaBrowser2 mInstance;
    private final MediaBrowser2.BrowserCallback mCallback;

    public MediaBrowser2Impl(Context context, MediaBrowser2 instance, SessionToken2 token,
            Executor executor, BrowserCallback callback) {
        super(context, instance, token, executor, callback);
        mInstance = instance;
        mCallback = callback;
    }

    @Override
    public void getLibraryRoot_impl(Bundle rootHints) {
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
    public void subscribe_impl(String parentId, Bundle extras) {
        // TODO(jaewan): Implement
    }

    @Override
    public void unsubscribe_impl(String parentId, Bundle extras) {
        // TODO(jaewan): Implement
    }

    @Override
    public void getItem_impl(String mediaId) {
        if (mediaId == null) {
            throw new IllegalArgumentException("mediaId shouldn't be null");
        }

        final IMediaSession2 binder = getSessionBinder();
        if (binder != null) {
            try {
                binder.getItem(getControllerStub(), mediaId);
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
    public void getChildren_impl(String parentId, int page, int pageSize, Bundle extras) {
        if (parentId == null) {
            throw new IllegalArgumentException("parentId shouldn't be null");
        }
        if (page < 1 || pageSize < 1) {
            throw new IllegalArgumentException("Neither page nor pageSize should be less than 1");
        }

        final IMediaSession2 binder = getSessionBinder();
        if (binder != null) {
            try {
                binder.getChildren(getControllerStub(), parentId, page, pageSize, extras);
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
    public void search_impl(String query, Bundle extras) {
        if (TextUtils.isEmpty(query)) {
            throw new IllegalArgumentException("query shouldn't be empty");
        }
        final IMediaSession2 binder = getSessionBinder();
        if (binder != null) {
            try {
                binder.search(getControllerStub(), query, extras);
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
    public void getSearchResult_impl(String query, int page, int pageSize, Bundle extras) {
        if (TextUtils.isEmpty(query)) {
            throw new IllegalArgumentException("query shouldn't be empty");
        }
        final IMediaSession2 binder = getSessionBinder();
        if (binder != null) {
            try {
                binder.getSearchResult(getControllerStub(), query, page, pageSize, extras);
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

    public void onGetRootResult(
            final Bundle rootHints, final String rootMediaId, final Bundle rootExtra) {
        getCallbackExecutor().execute(() -> {
            mCallback.onGetRootResult(rootHints, rootMediaId, rootExtra);
        });
    }

    public void onItemLoaded(String mediaId, MediaItem2 item) {
        getCallbackExecutor().execute(() -> {
            mCallback.onItemLoaded(mediaId, item);
        });
    }

    public void onChildrenLoaded(String parentId, int page, int pageSize, Bundle extras,
            List<MediaItem2> result) {
        getCallbackExecutor().execute(() -> {
            mCallback.onChildrenLoaded(parentId, page, pageSize, extras, result);
        });
    }

    public void onSearchResultChanged(String query, Bundle extras, int itemCount) {
        getCallbackExecutor().execute(() -> {
            mCallback.onSearchResultChanged(query, extras, itemCount);
        });
    }

    public void onSearchResultLoaded(String query, int page, int pageSize, Bundle extras,
            List<MediaItem2> result) {
        getCallbackExecutor().execute(() -> {
            mCallback.onSearchResultLoaded(query, page, pageSize, extras, result);
        });
    }
}
