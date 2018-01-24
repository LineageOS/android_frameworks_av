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

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.media.MediaLibraryService2;
import android.media.MediaLibraryService2.MediaLibrarySession;
import android.media.MediaLibraryService2.MediaLibrarySessionCallback;
import android.media.MediaPlayerBase;
import android.media.MediaSession2;
import android.media.MediaSession2.ControllerInfo;
import android.media.MediaSession2.SessionCallback;
import android.media.MediaSessionService2;
import android.media.VolumeProvider;
import android.media.update.MediaLibraryService2Provider;
import android.os.Bundle;

public class MediaLibraryService2Impl extends MediaSessionService2Impl implements
        MediaLibraryService2Provider {
    private final MediaSessionService2 mInstance;
    private MediaLibrarySession mLibrarySession;

    public MediaLibraryService2Impl(MediaLibraryService2 instance) {
        super(instance);
        mInstance = instance;
    }

    @Override
    public void onCreate_impl() {
        super.onCreate_impl();

        // Effectively final
        MediaSession2 session = getSession();
        if (!(session instanceof MediaLibrarySession)) {
            throw new RuntimeException("Expected MediaLibrarySession, but returned MediaSession2");
        }
        mLibrarySession = (MediaLibrarySession) getSession();
    }

    @Override
    Intent createServiceIntent() {
        Intent serviceIntent = new Intent(mInstance, mInstance.getClass());
        serviceIntent.setAction(MediaLibraryService2.SERVICE_INTERFACE);
        return serviceIntent;
    }

    public static class MediaLibrarySessionImpl extends MediaSession2Impl
            implements MediaLibrarySessionProvider {
        private final MediaLibrarySession mInstance;
        private final MediaLibrarySessionCallback mCallback;

        public MediaLibrarySessionImpl(MediaLibrarySession instance, Context context,
                MediaPlayerBase player, String id,
                MediaLibrarySessionCallback callback, VolumeProvider volumeProvider, int ratingType,
                PendingIntent sessionActivity) {
            super(instance, context, player, id, callback, volumeProvider, ratingType,
                    sessionActivity);
            mInstance = instance;
            mCallback = callback;
        }

        @Override
        public void notifyChildrenChanged_impl(ControllerInfo controller, String parentId,
                Bundle options) {
            // TODO(jaewan): Implements
        }

        @Override
        public void notifyChildrenChanged_impl(String parentId, Bundle options) {
            // TODO(jaewan): Implements
        }
    }
}
