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

import android.media.AudioSourceType;

/**
 * {@hide}
 */
parcelable RecordClientInfo {
    /** Interpreted as audio_unique_id_t. */
    int riid;
    /** Interpreted as uid_t. */
    int uid;
    /** Interpreted as audio_session_t. */
    int session;
    AudioSourceType source;
    /** Interpreted as audio_port_handle_t. */
    int portId;
    boolean silenced;
}
