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

import android.os.Bundle;
import android.os.ResultReceiver;
import android.net.Uri;

import com.android.media.IMediaSession2Callback;

/**
 * Interface to MediaSession2.
 * <p>
 * Keep this interface oneway. Otherwise a malicious app may implement fake version of this,
 * and holds calls from session to make session owner(s) frozen.
 */
oneway interface IMediaSession2 {
    // TODO(jaewan): add onCommand() to send private command
    // TODO(jaewan): Due to the nature of oneway calls, APIs can be called in out of order
    //               Add id for individual calls to address this.

    // TODO(jaewan): We may consider to add another binder just for the connection
    //               not to expose other methods to the controller whose connection wasn't accepted.
    //               But this would be enough for now because it's the same as existing
    //               MediaBrowser and MediaBrowserService.
    void connect(IMediaSession2Callback caller, String callingPackage);
    void release(IMediaSession2Callback caller);

    void setVolumeTo(IMediaSession2Callback caller, int value, int flags);
    void adjustVolume(IMediaSession2Callback caller, int direction, int flags);

    //////////////////////////////////////////////////////////////////////////////////////////////
    // send command
    //////////////////////////////////////////////////////////////////////////////////////////////
    void sendTransportControlCommand(IMediaSession2Callback caller,
            int commandCode, in Bundle args);
    void sendCustomCommand(IMediaSession2Callback caller, in Bundle command, in Bundle args,
            in ResultReceiver receiver);

    void prepareFromUri(IMediaSession2Callback caller, in Uri uri, in Bundle extras);
    void prepareFromSearch(IMediaSession2Callback caller, String query, in Bundle extras);
    void prepareFromMediaId(IMediaSession2Callback caller, String mediaId, in Bundle extras);
    void playFromUri(IMediaSession2Callback caller, in Uri uri, in Bundle extras);
    void playFromSearch(IMediaSession2Callback caller, String query, in Bundle extras);
    void playFromMediaId(IMediaSession2Callback caller, String mediaId, in Bundle extras);
    void setRating(IMediaSession2Callback caller, String mediaId, in Bundle rating);

    //////////////////////////////////////////////////////////////////////////////////////////////
    // library service specific
    //////////////////////////////////////////////////////////////////////////////////////////////
    void getLibraryRoot(IMediaSession2Callback caller, in Bundle rootHints);
    void getItem(IMediaSession2Callback caller, String mediaId);
    void getChildren(IMediaSession2Callback caller, String parentId, int page, int pageSize,
            in Bundle extras);
    void search(IMediaSession2Callback caller, String query, in Bundle extras);
    void getSearchResult(IMediaSession2Callback caller, String query, int page, int pageSize,
            in Bundle extras);
    void subscribe(IMediaSession2Callback caller, String parentId, in Bundle extras);
    void unsubscribe(IMediaSession2Callback caller, String parentId);
}
