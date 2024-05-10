/*
 * Copyright (C) 2023 The Android Open Source Project
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

package android.hardware;

/**
 * Metrics specific to Extension Sessions (see CameraExtensionSession) for logging.
 *
 * Each Extension Session is mapped to one camera session internally, and will be sent to
 * CameraServiceProxy with IDLE/CLOSE calls.
 * @hide
 */
parcelable CameraExtensionSessionStats {
    /**
     * Value should match {@code CameraExtensionCharacteristics#EXTENSION_*}
     */
    @Backing(type="int")
    enum Type {
        EXTENSION_NONE = -1,
        EXTENSION_AUTOMATIC = 0,
        EXTENSION_FACE_RETOUCH = 1,
        EXTENSION_BOKEH = 2,
        EXTENSION_HDR = 3,
        EXTENSION_NIGHT = 4
    }

    /**
     * Key to uniquely identify the session this stat is associated with. The first call to
     * 'ICameraService.reportExtensionSessionStats' should set this to an empty string.
     * 'ICameraService.reportExtensionSessionStats' will return the key which should be used with
     * the next calls.
     */
    String key;

    /**
     * Camera ID for which the stats is being reported.
     */
    String cameraId;

    /**
     * Package name of the client using the camera
     */
    String clientName;


    /**
     * Type of extension session requested by the app. Note that EXTENSION_AUTOMATIC is reported
     * as such.
     */
    Type type = Type.EXTENSION_NONE;

    /**
     * true if advanced extensions are being used, false otherwise
     */
    boolean isAdvanced = false;

    /**
     * Format of image capture request
     */
    int captureFormat;
}