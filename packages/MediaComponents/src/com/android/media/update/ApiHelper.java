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

import android.content.Context;
import android.content.res.Resources;
import android.content.res.Resources.Theme;
import android.content.res.XmlResourceParser;
import android.util.AttributeSet;
import android.view.ContextThemeWrapper;
import android.view.LayoutInflater;
import android.view.View;

import com.android.support.mediarouter.app.MediaRouteButton;

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

    public static Resources.Theme getLibTheme() {
        return sInstance.mLibTheme;
    }

    public static LayoutInflater getLayoutInflater(Context context) {
        LayoutInflater layoutInflater = LayoutInflater.from(context).cloneInContext(
                new ContextThemeWrapper(context, getLibTheme()));
        layoutInflater.setFactory2(new LayoutInflater.Factory2() {
            @Override
            public View onCreateView(
                    View parent, String name, Context context, AttributeSet attrs) {
                if (MediaRouteButton.class.getCanonicalName().equals(name)) {
                    return new MediaRouteButton(context, attrs);
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
        try (XmlResourceParser parser = getLibResources().getLayout(libResId)) {
            return getLayoutInflater(context).inflate(parser, null);
        }
    }
}
