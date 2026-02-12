/*
 * Copyright (C) 2026 The Android Open Source Project
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
///////////////////////////////////////////////////////////////////////////////
// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
///////////////////////////////////////////////////////////////////////////////

// This file is a snapshot of an AIDL file. Do not edit it manually. There are
// two cases:
// 1). this is a frozen version file - do not edit this in any case.
// 2). this is a 'current' file. If you make a backwards compatible change to
//     the interface (from the latest frozen version), the build system will
//     prompt you to update this file with `m <name>-update-api`.
//
// You must not make a backward incompatible change to any AIDL file built
// with the aidl_interface module type with versions property set. The module
// type is used to build AIDL files in a way that they can be used across
// independently updatable components of the system. If a device is shipped
// with such a backward incompatible change, it has a high risk of breaking
// later when a module using the interface is updated, e.g., Mainline modules.

package android.media.metrics;
parcelable StructuredItem {
  @utf8InCpp String key;
  int debugPid;
  int uid;
  long timestampNs;
  android.media.metrics.StructuredItem.Property[] properties;
  const @utf8InCpp String KEY_AUDIOPOLICY = "audiopolicy";
  const @utf8InCpp String KEY_AUDIORECORD = "audiorecord";
  const @utf8InCpp String KEY_AUDIOTHREAD = "audiothread";
  const @utf8InCpp String KEY_AUDIOTRACK = "audiotrack";
  const @utf8InCpp String KEY_CODEC = "codec";
  const @utf8InCpp String KEY_DRMMANAGER = "drmmanager";
  const @utf8InCpp String KEY_EXTRACTOR = "extractor";
  const @utf8InCpp String KEY_MEDIADRM = "mediadrm";
  const @utf8InCpp String KEY_MEDIADRM_CREATED = "mediadrm.created";
  const @utf8InCpp String KEY_MEDIADRM_ERRORED = "mediadrm.errored";
  const @utf8InCpp String KEY_MEDIADRM_SESSION = "mediadrm.session_opened";
  const @utf8InCpp String KEY_MEDIAPARSER = "mediaparser";
  const @utf8InCpp String KEY_NUPLAYER = "nuplayer";
  const @utf8InCpp String KEY_NUPLAYER2 = "nuplayer2";
  const @utf8InCpp String KEY_RECORDER = "recorder";
  const @utf8InCpp String KEY_VIDEO_FREEZE_EVENT = "videofreeze";
  const @utf8InCpp String KEY_VIDEO_JUDDER_EVENT = "videojudder";
  const @utf8InCpp String KEY_AUDIO_PREFIX = "audio.";
  const @utf8InCpp String KEY_MEDIADRM_VENDOR_PREFIX = "drm.vendor.";
  parcelable Rate {
    long numerator;
    long denominator;
  }
  union Value {
    int mInt32;
    long mInt64;
    double mDouble;
    @utf8InCpp String mString;
    android.media.metrics.StructuredItem.Rate mRate;
  }
  parcelable Property {
    @utf8InCpp String mName;
    android.media.metrics.StructuredItem.Value mValue;
  }
}
