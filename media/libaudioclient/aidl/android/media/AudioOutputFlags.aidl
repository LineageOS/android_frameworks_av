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
enum AudioOutputFlags {
    DIRECT           = 0,
    PRIMARY          = 1,
    FAST             = 2,
    DEEP_BUFFER      = 3,
    COMPRESS_OFFLOAD = 4,
    NON_BLOCKING     = 5,
    HW_AV_SYNC       = 6,
    TTS              = 7,
    RAW              = 8,
    SYNC             = 9,
    IEC958_NONAUDIO  = 10,
    DIRECT_PCM       = 11,
    MMAP_NOIRQ       = 12,
    VOIP_RX          = 13,
    INCALL_MUSIC     = 14,
    GAPLESS_OFFLOAD  = 15,
}
