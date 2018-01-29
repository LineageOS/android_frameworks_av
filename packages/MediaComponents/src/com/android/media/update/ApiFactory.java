/*
 * Copyright (C) 2017 The Android Open Source Project
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

package com.android.media.update;

import android.app.PendingIntent;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.media.DataSourceDesc;
import android.media.MediaBrowser2;
import android.media.MediaBrowser2.BrowserCallback;
import android.media.MediaController2;
import android.media.MediaController2.ControllerCallback;
import android.media.MediaItem2;
import android.media.MediaLibraryService2;
import android.media.MediaLibraryService2.MediaLibrarySession;
import android.media.MediaLibraryService2.MediaLibrarySessionCallback;
import android.media.MediaMetadata2;
import android.media.MediaPlayerInterface;
import android.media.MediaSession2;
import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.SessionCallback;
import android.media.MediaSessionService2;
import android.media.SessionPlayer2;
import android.media.SessionToken2;
import android.media.VolumeProvider;
import android.media.update.MediaBrowser2Provider;
import android.media.update.MediaControlView2Provider;
import android.media.update.MediaController2Provider;
import android.media.update.MediaItem2Provider;
import android.media.update.MediaLibraryService2Provider.MediaLibrarySessionProvider;
import android.media.update.MediaSession2Provider;
import android.media.update.MediaSessionService2Provider;
import android.media.update.SessionPlayer2Provider;
import android.media.update.SessionToken2Provider;
import android.media.update.VideoView2Provider;
import android.media.update.StaticProvider;
import android.media.update.ViewProvider;
import android.os.Bundle;
import android.os.IInterface;
import android.support.annotation.Nullable;
import android.util.AttributeSet;
import android.widget.MediaControlView2;
import android.widget.VideoView2;

import com.android.media.IMediaSession2;
import com.android.media.IMediaSession2Callback;
import com.android.media.MediaBrowser2Impl;
import com.android.media.MediaController2Impl;
import com.android.media.MediaItem2Impl;
import com.android.media.MediaLibraryService2Impl;
import com.android.media.MediaLibraryService2Impl.MediaLibrarySessionImpl;
import com.android.media.MediaSession2Impl;
import com.android.media.MediaSessionService2Impl;
import com.android.media.SessionToken2Impl;
import com.android.widget.MediaControlView2Impl;
import com.android.widget.VideoView2Impl;

import java.util.concurrent.Executor;

public class ApiFactory implements StaticProvider {
    public static Object initialize(Resources libResources, Theme libTheme)
            throws ReflectiveOperationException {
        ApiHelper.initialize(libResources, libTheme);
        return new ApiFactory();
    }

    @Override
    public MediaController2Provider createMediaController2(
            Context context, MediaController2 instance, SessionToken2 token,
            Executor executor, ControllerCallback callback) {
        return new MediaController2Impl(context, instance, token, executor, callback);
    }

    @Override
    public MediaBrowser2Provider createMediaBrowser2(Context context, MediaBrowser2 instance,
            SessionToken2 token, Executor executor, BrowserCallback callback) {
        return new MediaBrowser2Impl(context, instance, token, executor, callback);
    }

    @Override
    public MediaSession2Provider createMediaSession2(Context context, MediaSession2 instance,
            MediaPlayerInterface player, String id, VolumeProvider volumeProvider,
            int ratingType, PendingIntent sessionActivity, Executor callbackExecutor,
            SessionCallback callback) {
        return new MediaSession2Impl(context, instance, player, id, volumeProvider, ratingType,
                sessionActivity, callbackExecutor, callback);
    }

    @Override
    public MediaSession2Provider.ControllerInfoProvider createMediaSession2ControllerInfoProvider(
            Context context, ControllerInfo instance, int uid, int pid, String packageName,
            IInterface callback) {
        return new MediaSession2Impl.ControllerInfoImpl(context,
                instance, uid, pid, packageName, (IMediaSession2Callback) callback);
    }

    @Override
    public MediaSessionService2Provider createMediaSessionService2(
            MediaSessionService2 instance) {
        return new MediaSessionService2Impl(instance);
    }

    @Override
    public MediaSessionService2Provider createMediaLibraryService2(
            MediaLibraryService2 instance) {
        return new MediaLibraryService2Impl(instance);
    }

    @Override
    public MediaLibrarySessionProvider createMediaLibraryService2MediaLibrarySession(
            Context context, MediaLibrarySession instance, MediaPlayerInterface player,
            String id, VolumeProvider volumeProvider, int ratingType, PendingIntent sessionActivity,
            Executor callbackExecutor, MediaLibrarySessionCallback callback) {
        return new MediaLibrarySessionImpl(context, instance, player, id, volumeProvider,
                ratingType, sessionActivity, callbackExecutor, callback);
    }

    @Override
    public MediaControlView2Provider createMediaControlView2(
            MediaControlView2 instance, ViewProvider superProvider) {
        return new MediaControlView2Impl(instance, superProvider);
    }

    @Override
    public VideoView2Provider createVideoView2(
            VideoView2 instance, ViewProvider superProvider,
            @Nullable AttributeSet attrs, int defStyleAttr, int defStyleRes) {
        return new VideoView2Impl(instance, superProvider, attrs, defStyleAttr, defStyleRes);
    }

    @Override
    public SessionToken2Provider createSessionToken2(Context context, SessionToken2 instance,
            int uid, int type, String packageName, String serviceName, String id,
            IInterface sessionBinderInterface) {
        return new SessionToken2Impl(context, instance, uid, type, packageName,
                serviceName, id, (IMediaSession2) sessionBinderInterface);
    }

    @Override
    public SessionToken2 SessionToken2_fromBundle(Context context, Bundle bundle) {
        return SessionToken2Impl.fromBundle(context, bundle);
    }

    @Override
    public SessionPlayer2Provider createSessionPlayer2(Context context, SessionPlayer2 instance) {
        // TODO(jaewan): Implement this
        return null;
    }

    @Override
    public MediaItem2Provider createMediaItem2Provider(Context context, MediaItem2 instance,
            String mediaId, DataSourceDesc dsd, MediaMetadata2 metadata, int flags) {
        return new MediaItem2Impl(context, instance, mediaId, dsd, metadata, flags);
    }

    @Override
    public MediaItem2 fromBundle_MediaItem2(Context context, Bundle bundle) {
        return MediaItem2Impl.fromBundle(context, bundle);
    }
}
