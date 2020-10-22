/*
 * Copyright (C) 2020 The Android Open Source Project
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

package android.media;

/**
 * {@hide}
 */
parcelable AudioPortConfigDeviceExt {
    /**
     * Module the device is attached to.
     * Interpreted as audio_module_handle_t.
     */
    int hwModule;
    /**
     * Device type (e.g AUDIO_DEVICE_OUT_SPEAKER).
     * Interpreted as audio_devices_t.
     * TODO: Convert to a standalone AIDL representation.
     */
    int type;
    /** Device address. "" if N/A. */
    @utf8InCpp String address;
}
