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
 * The audio HAL version definition.
 *
 * {@hide}
 */
parcelable AudioHalVersion {

    @Backing(type="int")
    enum Type {
        /**
         * Indicate the audio HAL is implemented with HIDL (HAL interface definition language).
         * @see <a href="https://source.android.com/docs/core/architecture/hidl/">HIDL</a>
         */
        HIDL = 0,

        /**
         * Indicate the audio HAL is implemented with AIDL (Android Interface Definition Language).
         * @see <a href="https://source.android.com/docs/core/architecture/aidl/">AIDL</a>
         */
        AIDL
    }

    Type type = Type.HIDL;

    /**
     * Major version number.
     */
    int major;

    /**
     * Minor version number.
     */
    int minor;
}
