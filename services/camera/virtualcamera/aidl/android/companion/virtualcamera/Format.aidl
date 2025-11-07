/*
 * Copyright (C) 2023 The Android Open Source Project
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

package android.companion.virtualcamera;

/**
 * Image format supported by a virtual camera stream.
 *
 * Must be in sync with the values in AIMAGE_FORMATS, see {@link AImage}.
 *
 * @hide
 */
@Backing(type="int")
enum Format {
    UNKNOWN = 0,
    RGBA_8888 = 1,
    YUV_420_888 = 0x23,
    JPEG = 0x100,
    HEIC = 0x48454946,
}
