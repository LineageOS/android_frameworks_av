/*
 * Copyright 2023 The Android Open Source Project
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

package android.companion.virtualcamera;

import android.companion.virtualcamera.Format;
import android.view.Surface;

/**
 * AIDL Interface to receive callbacks from virtual camera instance.
 * @hide
 */
oneway interface IVirtualCameraCallback {

    /**
     * Called when there's new video stream. This callback is send after clients opens and
     * configures camera. Implementation should hold onto the surface until corresponding
     * terminateStream call is received.
     *
     * @param streamId - id of the video stream.
     * @param surface - Surface representing the virtual camera sensor.
     * @param width - width of the surface.
     * @param height - height of the surface.
     * @param pixelFormat - pixel format of the surface.
     */
    void onStreamConfigured(int streamId, in Surface surface, int width, int height,
            in Format pixelFormat);

    /**
     * Called when framework requests capture. This can be used by the client as a hint
     * to render another frame into input surface.
     *
     * @param streamId - id of the stream corresponding to the Surface for which next
     *     frame is requested.
     * @param frameId - id of the requested frame.
     */
    void onProcessCaptureRequest(int streamId, int frameId);

    /**
     * Called when the corresponding stream is no longer in use. Implementation should dispose of
     * corresponding Surface upon receiving this call and no longer interact with it.
     *
     * @param streamId - id of the video stream to terminate.
     */
    void onStreamClosed(int streamId);
}
