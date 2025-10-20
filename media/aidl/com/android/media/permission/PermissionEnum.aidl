/*
 * Copyright (C) 2024 The Android Open Source Project
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

package com.android.media.permission;

/**
 * Enumerates permissions which are tracked/pushed by NativePermissionController
 * @hide
 */
enum PermissionEnum {
    // This is a runtime + WIU permission, which means data delivery should be protected by AppOps
    // We query the controller only for early fails/hard errors
    RECORD_AUDIO = 0,
    MODIFY_AUDIO_ROUTING = 1,
    MODIFY_AUDIO_SETTINGS = 2,
    MODIFY_PHONE_STATE = 3,
    MODIFY_DEFAULT_AUDIO_EFFECTS = 4,
    WRITE_SECURE_SETTINGS = 5,
    CALL_AUDIO_INTERCEPTION = 6,
    ACCESS_ULTRASOUND = 7,
    CAPTURE_AUDIO_OUTPUT = 8,
    CAPTURE_MEDIA_OUTPUT = 9,
    CAPTURE_AUDIO_HOTWORD = 10,
    CAPTURE_TUNER_AUDIO_INPUT = 11,
    CAPTURE_VOICE_COMMUNICATION_OUTPUT = 12,
    BLUETOOTH_CONNECT = 13,
    BYPASS_CONCURRENT_RECORD_AUDIO_RESTRICTION = 14,
    MODIFY_AUDIO_SETTINGS_PRIVILEGED = 15,
    ENUM_SIZE = 16, // Not for actual usage, used by Java
}
