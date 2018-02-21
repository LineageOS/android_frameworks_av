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
import android.os.Bundle;
import android.os.ResultReceiver;

import com.android.media.IMediaSession2;

/**
 * Interface from MediaSession2 to MediaSession2Record.
 * <p>
 * Keep this interface oneway. Otherwise a malicious app may implement fake version of this,
 * and holds calls from session to make session owner(s) frozen.
 */
oneway interface IMediaSession2Callback {
    void onPlaybackStateChanged(in Bundle state);
    void onPlaylistChanged(in List<Bundle> playlist);
    void onPlaylistParamsChanged(in Bundle params);
    void onPlaybackInfoChanged(in Bundle playbackInfo);

    // TODO(jaewan): Handle when the playlist becomes too huge.
    void onConnected(IMediaSession2 sessionBinder, in Bundle commandGroup, in Bundle playbackState,
            in Bundle playbackInfo, in Bundle params, in List<Bundle> playlist, int ratingType,
            in PendingIntent sessionActivity);
    void onDisconnected();

    void onCustomLayoutChanged(in List<Bundle> commandButtonlist);

    void sendCustomCommand(in Bundle command, in Bundle args, in ResultReceiver receiver);

    //////////////////////////////////////////////////////////////////////////////////////////////
    // Browser sepcific
    //////////////////////////////////////////////////////////////////////////////////////////////
    void onGetRootResult(in Bundle rootHints, String rootMediaId, in Bundle rootExtra);
    void onItemLoaded(String mediaId, in Bundle result);
    void onChildrenLoaded(String parentId, int page, int pageSize, in Bundle extras,
            in List<Bundle> result);
    void onSearchResultChanged(String query, in Bundle extras, int itemCount);
    void onSearchResultLoaded(String query, int page, int pageSize, in Bundle extras,
            in List<Bundle> result);
}
