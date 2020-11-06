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
enum AudioUniqueIdUse {
    UNSPECIFIED = 0,
    SESSION = 1, // audio_session_t
                 // for allocated sessions, not special AUDIO_SESSION_*
    MODULE = 2,  // audio_module_handle_t
    EFFECT = 3,  // audio_effect_handle_t
    PATCH = 4,   // audio_patch_handle_t
    OUTPUT = 5,  // audio_io_handle_t
    INPUT = 6,   // audio_io_handle_t
    CLIENT = 7,  // client-side players and recorders
                 // FIXME should move to a separate namespace;
                 // these IDs are allocated by AudioFlinger on client request,
                 // but are never used by AudioFlinger
}
