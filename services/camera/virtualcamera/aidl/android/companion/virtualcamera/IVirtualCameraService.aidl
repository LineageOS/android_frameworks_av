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

package android.companion.virtualcamera;

import android.companion.virtualcamera.VirtualCameraConfiguration;

/**
 * AIDL Interface to communicate with the VirtualCamera HAL
 * @hide
 */
interface IVirtualCameraService {

    /**
     * Registers a new camera with the virtual camera hal.
     * @return true if the camera was successfully registered
     */
    boolean registerCamera(in IBinder token, in VirtualCameraConfiguration configuration,
            int deviceId);

    /**
     * Unregisters the camera from the virtual camera hal. After this call the virtual camera won't
     * be visible to the camera framework anymore.
     */
    void unregisterCamera(in IBinder token);

    /**
     * Returns the camera id for a given binder token. Note that this id corresponds to the id of
     * the camera device in the camera framework.
     */
    int getCameraId(in IBinder token);
}
