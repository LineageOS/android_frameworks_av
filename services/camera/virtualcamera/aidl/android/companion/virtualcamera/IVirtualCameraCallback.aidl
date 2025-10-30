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
import android.companion.virtualcamera.ICaptureResultConsumer;
import android.companion.virtualcamera.VirtualCameraMetadata;
import android.view.Surface;

/**
 * AIDL Interface to receive callbacks from virtual camera instance.
 * @hide
 */
oneway interface IVirtualCameraCallback {

    /**
     * Called when the client application calls
     * {@link android.hardware.camera2.CameraManager#openCamera}. This is the earliest signal that
     * this camera will be used. At this point, no stream is opened yet, nor any configuration took
     * place. The owner of the virtual camera can use this as signal to prepare the camera and
     * reduce latency for when
     * {@link android.hardware.camera2.CameraDevice#createCaptureSession(SessionConfiguration)} is
     * called and before
     * {@link
     * android.hardware.camera2.CameraCaptureSession.StateCallback#onConfigured(CameraCaptureSession)}
     * is called.
     */
    void onOpenCamera();

    /**
     * Called when there's a new camera session. This callback is sent when clients open and
     * configure the video session for the virtual camera.
     *
     * @param sessionParameters - native CameraMetadata of the session parameters packed
     *      as VirtualCameraMetadata.
     * @param captureResultConsumer - consumer interface to inject the metadata of capture results
     *      to the virtual camera service. It is null if per frame camera metadata is not enabled.
     */
    void onConfigureSession(in VirtualCameraMetadata sessionParameters,
        in @nullable ICaptureResultConsumer captureResultConsumer);

    /**
     * Called when there's new video stream. This callback is sent after the client opens and
     * configures the camera. Implementation should hold onto the surface until corresponding
     * terminateStream call is received.
     *
     * @param streamId - id of the video stream.
     * @param surface - Surface representing the virtual camera sensor.
     * @param width - width of the surface.
     * @param height - height of the surface.
     * @param imageFormat - image format of the surface.
     */
    void onStreamConfigured(int streamId, in Surface surface, int width, int height,
        in Format imageFormat);

    /**
     * Called when framework requests capture. This can be used by the client as a hint
     * to render another frame into input surface.
     *
     * @param streamId - id of the stream corresponding to the Surface for which next
     *      frame is requested.
     * @param frameId - id of the requested frame.
     * @param captureRequestSettings - The capture request settings metadata provided by the app
     *      in association with the requested {@code frameId}.
     */
    void onProcessCaptureRequest(int streamId, int frameId,
        in @nullable VirtualCameraMetadata captureRequestSettings);

    /**
     * Called when the corresponding stream is no longer in use. Implementation should dispose of
     * corresponding Surface upon receiving this call and no longer interact with it.
     *
     * @param streamId - id of the video stream to terminate.
     */
    void onStreamClosed(int streamId);
}
