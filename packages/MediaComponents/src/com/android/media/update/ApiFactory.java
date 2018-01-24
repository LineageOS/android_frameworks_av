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
import android.media.MediaBrowser2;
import android.media.MediaBrowser2.BrowserCallback;
import android.media.MediaController2;
import android.media.MediaLibraryService2;
import android.media.MediaLibraryService2.MediaLibrarySession;
import android.media.MediaLibraryService2.MediaLibrarySessionCallback;
import android.media.MediaPlayerBase;
import android.media.MediaSession2;
import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.SessionCallback;
import android.media.MediaSessionService2;
import android.media.IMediaSession2Callback;
import android.media.SessionToken;
import android.media.VolumeProvider;
import android.media.update.MediaBrowser2Provider;
import android.media.update.MediaControlView2Provider;
import android.media.update.MediaController2Provider;
import android.media.update.MediaLibraryService2Provider.MediaLibrarySessionProvider;
import android.media.update.MediaSession2Provider;
import android.media.update.MediaSessionService2Provider;
import android.media.update.VideoView2Provider;
import android.media.update.StaticProvider;
import android.media.update.ViewProvider;
import android.support.annotation.Nullable;
import android.util.AttributeSet;
import android.widget.MediaControlView2;
import android.widget.VideoView2;

import com.android.media.MediaBrowser2Impl;
import com.android.media.MediaController2Impl;
import com.android.media.MediaLibraryService2Impl;
import com.android.media.MediaLibraryService2Impl.MediaLibrarySessionImpl;
import com.android.media.MediaSession2Impl;
import com.android.media.MediaSessionService2Impl;
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
            MediaController2 instance, Context context, SessionToken token,
            MediaController2.ControllerCallback callback, Executor executor) {
        return new MediaController2Impl(instance, context, token, callback, executor);
    }

    @Override
    public MediaBrowser2Provider createMediaBrowser2(MediaBrowser2 instance, Context context,
            SessionToken token, BrowserCallback callback, Executor executor) {
        return new MediaBrowser2Impl(instance, context, token, callback, executor);
    }

    @Override
    public MediaSession2Provider createMediaSession2(MediaSession2 instance, Context context,
            MediaPlayerBase player, String id, SessionCallback callback,
            VolumeProvider volumeProvider, int ratingType,
            PendingIntent sessionActivity) {
        return new MediaSession2Impl(instance, context, player, id, callback,
                volumeProvider, ratingType, sessionActivity);
    }

    @Override
    public MediaSession2Provider.ControllerInfoProvider createMediaSession2ControllerInfoProvider(
            ControllerInfo instance, Context context, int uid, int pid, String packageName,
            IMediaSession2Callback callback) {
        return new MediaSession2Impl.ControllerInfoImpl(
                instance, context, uid, pid, packageName, callback);
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
            MediaLibrarySession instance, Context context, MediaPlayerBase player, String id,
            MediaLibrarySessionCallback callback, VolumeProvider volumeProvider, int ratingType,
            PendingIntent sessionActivity) {
        return new MediaLibrarySessionImpl(instance, context, player, id, callback, volumeProvider,
                ratingType, sessionActivity);
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
}
