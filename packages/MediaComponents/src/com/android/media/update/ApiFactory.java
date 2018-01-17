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

import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.media.update.MediaControlView2Provider;
import android.media.update.VideoView2Provider;
import android.media.update.StaticProvider;
import android.media.update.ViewProvider;
import android.support.annotation.Nullable;
import android.util.AttributeSet;
import android.widget.MediaControlView2;
import android.widget.VideoView2;

import com.android.widget.MediaControlView2Impl;
import com.android.widget.VideoView2Impl;

public class ApiFactory implements StaticProvider {
    public static Object initialize(Resources libResources, Theme libTheme)
            throws ReflectiveOperationException {
        ApiHelper.initialize(libResources, libTheme);
        return new ApiFactory();
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
