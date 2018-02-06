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

package com.android.media.update;

import android.annotation.Nullable;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.content.res.XmlResourceParser;
import android.support.v4.widget.Space;
import android.support.v7.widget.ButtonBarLayout;
import android.util.AttributeSet;
import android.view.ContextThemeWrapper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import com.android.support.mediarouter.app.MediaRouteButton;
import com.android.support.mediarouter.app.MediaRouteExpandCollapseButton;
import com.android.support.mediarouter.app.MediaRouteVolumeSlider;
import com.android.support.mediarouter.app.OverlayListView;

public class ApiHelper {
    private static ApiHelper sInstance;
    private final Resources mLibResources;
    private final Theme mLibTheme;

    public static ApiHelper getInstance() {
        return sInstance;
    }

    static void initialize(Resources libResources, Theme libTheme) {
        if (sInstance == null) {
            sInstance = new ApiHelper(libResources, libTheme);
        }
    }

    private ApiHelper(Resources libResources, Theme libTheme) {
        mLibResources = libResources;
        mLibTheme = libTheme;
    }

    public static Resources getLibResources() {
        return sInstance.mLibResources;
    }

    public static Theme getLibTheme() {
        return sInstance.mLibTheme;
    }

    public static Theme getLibTheme(int themeId) {
        Theme theme = sInstance.mLibResources.newTheme();
        theme.applyStyle(themeId, true);
        return theme;
    }

    public static LayoutInflater getLayoutInflater(Context context) {
        return getLayoutInflater(context, getLibTheme());
    }

    public static LayoutInflater getLayoutInflater(Context context, Theme theme) {
        // TODO (b/72975976): Avoid to use ContextThemeWrapper with app context and lib theme.
        LayoutInflater layoutInflater = LayoutInflater.from(context).cloneInContext(
                new ContextThemeWrapper(context, theme));
        layoutInflater.setFactory2(new LayoutInflater.Factory2() {
            @Override
            public View onCreateView(
                    View parent, String name, Context context, AttributeSet attrs) {
                if (MediaRouteButton.class.getCanonicalName().equals(name)) {
                    return new MediaRouteButton(context, attrs);
                } else if (MediaRouteVolumeSlider.class.getCanonicalName().equals(name)) {
                    return new MediaRouteVolumeSlider(context, attrs);
                } else if (MediaRouteExpandCollapseButton.class.getCanonicalName().equals(name)) {
                    return new MediaRouteExpandCollapseButton(context, attrs);
                } else if (OverlayListView.class.getCanonicalName().equals(name)) {
                    return new OverlayListView(context, attrs);
                } else if (ButtonBarLayout.class.getCanonicalName().equals(name)) {
                    return new ButtonBarLayout(context, attrs);
                } else if (Space.class.getCanonicalName().equals(name)) {
                    return new Space(context, attrs);
                }
                return null;
            }

            @Override
            public View onCreateView(String name, Context context, AttributeSet attrs) {
                return onCreateView(null, name, context, attrs);
            }
        });
        return layoutInflater;
    }

    public static View inflateLibLayout(Context context, int libResId) {
        return inflateLibLayout(context, getLibTheme(), libResId, null, false);
    }

    public static View inflateLibLayout(Context context, Theme theme, int libResId) {
        return inflateLibLayout(context, theme, libResId, null, false);
    }

    public static View inflateLibLayout(Context context, Theme theme, int libResId,
            @Nullable ViewGroup root, boolean attachToRoot) {
        try (XmlResourceParser parser = getLibResources().getLayout(libResId)) {
            return getLayoutInflater(context, theme).inflate(parser, root, attachToRoot);
        }
    }
}
