/*
 * Copyright (C) 2022 The Android Open Source Project
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
 * Defines the mixer behavior that can be used when setting mixer attributes.
 */
@Backing(type="int")
enum AudioMixerBehavior {
    /**
     * The mixer behavior is invalid.
     */
    INVALID = -1,
    /**
     * The mixer behavior that follows platform default behavior, which is mixing audio from
     * different sources.
     */
    DEFAULT = 0,
    /**
     * The audio data in the mixer will be bit-perfect as long as possible.
     */
    BIT_PERFECT = 1,
}
