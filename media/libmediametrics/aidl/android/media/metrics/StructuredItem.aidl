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

package android.media.metrics;

parcelable StructuredItem {

    /*
     * The bytestring version looks like this, we need to get that data across
     *
     * -- begin of item
     * -- begin of header
     * (uint32) item size: including the item size field
     * (uint32) header size, including the item size and header size fields.
     * (uint16) version: exactly 0
     * (uint16) key size, that is key strlen + 1 for zero termination.
     * (int8)+ key, a string which is 0 terminated (UTF-8).
     * (int32) pid
     * (int32) uid
     * (int64) timestamp
     * -- end of header
     * -- begin body
     * (uint32) number of properties
     * -- repeat for number of properties
     *     (uint16) property size, including property size field itself
     *     (uint8) type of property
     *     (int8)+ key string, including 0 termination
     *      based on type of property (given above), one of:
     *       (int32)
     *       (int64)
     *       (double)
     *       (int8)+ for TYPE_CSTRING, including 0 termination
     *       (int64, int64) for rate
     */

    parcelable Rate {
        long numerator;
        long denominator;
    }

    union Value {
        int mInt32;
        long mInt64;
        double mDouble;
        @utf8InCpp String mString;
        Rate mRate;
    }

    // holds the name/value pair
    parcelable Property {
        @utf8InCpp String mName;
        Value mValue;
    }

    @utf8InCpp String key;
        /**
         * List of keys for these records.
         */
        @utf8InCpp const String KEY_AUDIOPOLICY = "audiopolicy";
        @utf8InCpp const String KEY_AUDIORECORD = "audiorecord";
        @utf8InCpp const String KEY_AUDIOTHREAD = "audiothread";
        @utf8InCpp const String KEY_AUDIOTRACK = "audiotrack";
        @utf8InCpp const String KEY_CODEC = "codec";
        @utf8InCpp const String KEY_DRMMANAGER = "drmmanager";
        @utf8InCpp const String KEY_EXTRACTOR = "extractor";
        @utf8InCpp const String KEY_MEDIADRM = "mediadrm";
        @utf8InCpp const String KEY_MEDIADRM_CREATED = "mediadrm.created";
        @utf8InCpp const String KEY_MEDIADRM_ERRORED = "mediadrm.errored";
        @utf8InCpp const String KEY_MEDIADRM_SESSION = "mediadrm.session_opened";
        @utf8InCpp const String KEY_MEDIAPARSER = "mediaparser";
        @utf8InCpp const String KEY_NUPLAYER = "nuplayer";
        @utf8InCpp const String KEY_NUPLAYER2 = "nuplayer2";
        @utf8InCpp const String KEY_RECORDER = "recorder";
        @utf8InCpp const String KEY_VIDEO_FREEZE_EVENT = "videofreeze";
        @utf8InCpp const String KEY_VIDEO_JUDDER_EVENT = "videojudder";

        /**
         * List of key prefixes for these records.
         */
        @utf8InCpp const String KEY_AUDIO_PREFIX = "audio.";
        @utf8InCpp const String KEY_MEDIADRM_VENDOR_PREFIX = "drm.vendor.";

    int debugPid;
    int uid;
    long timestampNs;

    Property[] properties;
}
