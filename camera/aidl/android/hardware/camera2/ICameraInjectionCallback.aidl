/*
 * Copyright (C) 2021 The Android Open Source Project
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

package android.hardware.camera2;

import android.hardware.camera2.ICameraInjectionSession;

/**
 * Binder interface used to call back the error state injected by the external camera,
 * and camera service can be switched back to internal camera when binder signals process death.
 *
 * @hide
 */
interface ICameraInjectionCallback
{
    // Error codes for onInjectionError
    // To indicate all invalid error codes
    const int ERROR_INJECTION_INVALID_ERROR = -1;
    // To indicate the camera injection session has encountered a fatal error, such as injection
    // init failure, configure failure or injecting failure etc.
    const int ERROR_INJECTION_SESSION = 0;
    // To indicate the camera service has encountered a fatal error.
    const int ERROR_INJECTION_SERVICE = 1;
    // To indicate the injection camera does not support certain camera functions, such as
    // unsupport stream format, no capture/record function or no multi-camera function etc.
    // When this error occurs, the default processing is still in the inject state, and the app is
    // notified to display an error message and a black screen.
    const int ERROR_INJECTION_UNSUPPORTED = 2;

    oneway void onInjectionError(int errorCode);
}
