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
 * AudioChannelMask is an opaque type and its internal layout should not be
 * assumed as it may change in the future.
 *
 * This is a temporary implementation to provide a distinct type (instead of
 * 'int') in all the places that need a channel mask. Later the enum will be
 * replaced with a type which is more extensible by vendors.
 *
 * The actual value range of this enum is the same as of
 * the 'audio_channel_mask_t' enum.
 *
 * {@hide}
 */
@Backing(type="int")
enum AudioChannelMask {
   /**
    * Framework use only, do not constitute a valid channel mask.
    */
   INVALID = 0xC0000000,

   NONE = 0,
   /**
    * Since the current code never uses the values of the SAIDL enum
    * directly--it uses the values of the C enum and coerces the type--
    * we don't specify any other values here.
    */
}
