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
@Backing(type="int")
enum AudioFlag {
    AUDIBILITY_ENFORCED = 0,
    SECURE = 1,
    SCO = 2,
    BEACON = 3,
    HW_AV_SYNC = 4,
    HW_HOTWORD = 5,
    BYPASS_INTERRUPTION_POLICY = 6,
    BYPASS_MUTE = 7,
    LOW_LATENCY = 8,
    DEEP_BUFFER = 9,
    NO_MEDIA_PROJECTION = 10,
    MUTE_HAPTIC = 11,
    NO_SYSTEM_CAPTURE = 12,
    CAPTURE_PRIVATE = 13,
    CONTENT_SPATIALIZED = 14,
    NEVER_SPATIALIZE = 15,
}
