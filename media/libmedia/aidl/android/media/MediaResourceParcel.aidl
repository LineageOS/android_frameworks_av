/**
 * Copyright (c) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.media;

import android.media.MediaResourceType;
import android.media.MediaResourceSubType;

/**
 * Description of a media resource to be tracked by MediaResourceManager.
 *
 * {@hide}
 */
parcelable MediaResourceParcel {
    // TODO: default enum value is not supported yet.
    // Set default enum value when b/142739329 is fixed.

    /**
     * Type of the media resource.
     */
    MediaResourceType type;// = MediaResourceTypeEnum::kUnspecified;

    /**
     * Sub-type of the media resource.
     */
    MediaResourceSubType subType;// = MediaResourceSubTypeEnum::kUnspecifiedSubType;

    /**
     * Identifier of the media resource (eg. Drm session id).
     */
    byte[] id;

    /**
     * Number of units of the media resource (bytes of graphic memory, number of codecs, etc.).
     */
    long value = 0;
}
