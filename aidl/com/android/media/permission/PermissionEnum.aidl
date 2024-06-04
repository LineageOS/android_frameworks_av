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
 * {@hide}
 */
enum PermissionEnum {
    MODIFY_AUDIO_ROUTING = 0,
    MODIFY_PHONE_STATE = 1,
    CALL_AUDIO_INTERCEPTION = 2,
    // This is a runtime + WIU permission, which means data delivery should be protected by AppOps
    // We query the controller only for early fails/hard errors
    RECORD_AUDIO = 3,
    ENUM_SIZE = 4, // Not for actual usage
}
