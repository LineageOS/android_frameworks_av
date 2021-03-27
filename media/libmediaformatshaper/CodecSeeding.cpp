/*
 * Copyright 2021, The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "CodecSeeding"
#include <utils/Log.h>

#include <string>

#include <media/formatshaper/CodecProperties.h>

namespace android {
namespace mediaformatshaper {

/*
 * a block of pre-loads; things the library seeds into the codecproperties based
 * on the mediaType.
 * XXX: parsing from a file is likely better than embedding in code.
 */
typedef struct {
    const char *key;
    int32_t value;
} preloadFeature_t;

typedef struct {
    const char *mediaType;
    preloadFeature_t *features;
} preloadProperties_t;

/*
 * 240 = 2.4 bits per pixel-per-second == 5mbps@1080, 2.3mbps@720p, which is about where
 * we want our initial floor for now.
 */

static preloadFeature_t featuresAvc[] = {
      {"vq-target-bppx100", 240},
      {nullptr, 0}
};

static preloadFeature_t featuresHevc[] = {
      {"vq-target-bppx100", 240},
      {nullptr, 0}
};

static preloadFeature_t featuresGenericVideo[] = {
      {"vq-target-bppx100", 240},
      {nullptr, 0}
};

static preloadProperties_t preloadProperties[] = {
    { "video/avc", featuresAvc},
    { "video/hevc", &featuresHevc[0]},

    // wildcard for any video format not already captured
    { "video/*", &featuresGenericVideo[0]},
    { nullptr, nullptr}
};

void CodecProperties::Seed() {
    ALOGV("Seed: for codec %s, mediatype %s", mName.c_str(), mMediaType.c_str());

    // load me up with initial configuration data
    int count = 0;
    for (int i=0;; i++) {
        preloadProperties_t *p = &preloadProperties[i];
        if (p->mediaType == nullptr) {
            break;
        }
        bool found = false;
        if (strcmp(p->mediaType, mMediaType.c_str()) == 0) {
            found = true;
        }
        const char *r;
        if (!found && (r = strchr(p->mediaType, '*')) != NULL) {
            // wildcard; check the prefix
            size_t len = r - p->mediaType;
            if (strncmp(p->mediaType, mMediaType.c_str(), len) == 0) {
                found = true;
            }
        }

        if (!found) {
            continue;
        }
        ALOGV("seeding from mediaType '%s'", p->mediaType);

        // walk through, filling things
        if (p->features != nullptr) {
            for (int j=0;; j++) {
                preloadFeature_t *q = &p->features[j];
                if (q->key == nullptr) {
                    break;
                }
                setFeatureValue(q->key, q->value);
                count++;
            }
            break;
        }
    }
    ALOGV("loaded %d preset values", count);
}

// a chance, as we register the codec and accept no further updates, to
// override any poor configuration that arrived from the device's XML files.
//
void CodecProperties::Finish() {
    ALOGV("Finish: for codec %s, mediatype %s", mName.c_str(), mMediaType.c_str());

    // currently a no-op
}

} // namespace mediaformatshaper
} // namespace android

