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

package aaudio;

import android.media.audio.common.AudioFormat;

parcelable StreamParameters {
    int                                       samplesPerFrame;  //      = AAUDIO_UNSPECIFIED;
    int                                       sampleRate;  //           = AAUDIO_UNSPECIFIED;
    int                                       deviceId;  //             = AAUDIO_UNSPECIFIED;
    int /* aaudio_sharing_mode_t */           sharingMode;  //          = AAUDIO_SHARING_MODE_SHARED;
    AudioFormat                               audioFormat;  //          = AUDIO_FORMAT_DEFAULT;
    int /* aaudio_direction_t */              direction;  //            = AAUDIO_DIRECTION_OUTPUT;
    int /* aaudio_usage_t */                  usage;  //                = AAUDIO_UNSPECIFIED;
    int /* aaudio_content_type_t */           contentType;  //          = AAUDIO_UNSPECIFIED;
    int /* aaudio_input_preset_t */           inputPreset;  //          = AAUDIO_UNSPECIFIED;
    int                                       bufferCapacity;  //       = AAUDIO_UNSPECIFIED;
    int /* aaudio_allowed_capture_policy_t */ allowedCapturePolicy;  // = AAUDIO_UNSPECIFIED;
    int /* aaudio_session_id_t */             sessionId;  //            = AAUDIO_SESSION_ID_NONE;
    boolean                                   isPrivacySensitive;  //   = false;
}
