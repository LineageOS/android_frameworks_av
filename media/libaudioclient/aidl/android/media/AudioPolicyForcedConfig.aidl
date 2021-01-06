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
package android.media;

/**
 * {@hide}
 */
@Backing(type="int")
enum AudioPolicyForcedConfig {
    NONE = 0,
    SPEAKER = 1,
    HEADPHONES = 2,
    BT_SCO = 3,
    BT_A2DP = 4,
    WIRED_ACCESSORY = 5,
    BT_CAR_DOCK = 6,
    BT_DESK_DOCK = 7,
    ANALOG_DOCK = 8,
    DIGITAL_DOCK = 9,
    NO_BT_A2DP = 10, /* A2DP sink is not preferred to speaker or wired HS */
    SYSTEM_ENFORCED = 11,
    HDMI_SYSTEM_AUDIO_ENFORCED = 12,
    ENCODED_SURROUND_NEVER = 13,
    ENCODED_SURROUND_ALWAYS = 14,
    ENCODED_SURROUND_MANUAL = 15,
}
