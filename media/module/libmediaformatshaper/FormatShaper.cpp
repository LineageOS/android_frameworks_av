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

//#define LOG_NDEBUG 0
#define LOG_TAG "FormatShaper"
#include <utils/Log.h>

#include <string>
#include <inttypes.h>

#include <media/NdkMediaFormat.h>

#include "CodecProperties.h"
#include "VideoShaper.h"
#include "VQops.h"

#include <media/formatshaper/FormatShaper.h>

namespace android {
namespace mediaformatshaper {

//
// Caller retains ownership of and responsibility for inFormat
//

//
// the interface to the outside
//

int shapeFormat(shaperHandle_t shaper, AMediaFormat* inFormat, int flags) {
    CodecProperties *codec = (CodecProperties*) shaper;
    if (codec == nullptr) {
        return -1;
    }
    if (!codec->isRegistered()) {
        return -1;
    }

    // run through the list of possible transformations
    //

    std::string mediaType = codec->getMediaType();
    if (strncmp(mediaType.c_str(), "video/", 6) == 0) {
        // video specific shaping
        (void) videoShaper(codec, inFormat, flags);

    } else if (strncmp(mediaType.c_str(), "audio/", 6) == 0) {
        // audio specific shaping

    } else {
        ALOGV("unknown mediatype '%s', left untouched", mediaType.c_str());

    }

    return 0;
}

int setMap(shaperHandle_t shaper,  const char *kind, const char *key, const char *value) {
    ALOGV("setMap: kind %s key %s -> value %s", kind, key, value);
    CodecProperties *codec = (CodecProperties*) shaper;
    if (codec == nullptr) {
        return -1;
    }
    // must not yet be registered
    if (codec->isRegistered()) {
        return -1;
    }

    codec->setMapping(kind, key, value);
    return 0;
}

int setFeature(shaperHandle_t shaper, const char *feature, int value) {
    ALOGV("set_feature: feature %s value %d", feature, value);
    CodecProperties *codec = (CodecProperties*) shaper;
    if (codec == nullptr) {
        return -1;
    }
    // must not yet be registered
    if (codec->isRegistered()) {
        return -1;
    }

    // save a map of all features
    codec->setFeatureValue(feature, value);

    return 0;
}

int setTuning(shaperHandle_t shaper, const char *tuning, const char *value) {
    ALOGV("setTuning: tuning %s value %s", tuning, value);
    CodecProperties *codec = (CodecProperties*) shaper;
    if (codec == nullptr) {
        return -1;
    }
    // must not yet be registered
    if (codec->isRegistered()) {
        return -1;
    }

    // save a map of all features
    codec->setTuningValue(tuning, value);

    return 0;
}

/*
 * The routines that manage finding, creating, and registering the shapers.
 */

shaperHandle_t findShaper(const char *codecName, const char *mediaType) {
    CodecProperties *codec = findCodec(codecName, mediaType);
    return (shaperHandle_t) codec;
}

shaperHandle_t createShaper(const char *codecName, const char *mediaType) {
    CodecProperties *codec = new CodecProperties(codecName, mediaType);
    if (codec != nullptr) {
        codec->Seed();
    }
    return (shaperHandle_t) codec;
}

shaperHandle_t registerShaper(shaperHandle_t shaper, const char *codecName, const char *mediaType) {
    ALOGV("registerShaper(handle, codecName %s, mediaType %s", codecName, mediaType);
    CodecProperties *codec = (CodecProperties*) shaper;
    if (codec == nullptr) {
        return nullptr;
    }
    // must not yet be registered
    if (codec->isRegistered()) {
        return nullptr;
    }

    // any final cleanup for the parameters. This allows us to override
    // bad parameters from a devices XML file.
    codec->Finish();

    // may return a different codec, if we lost a race.
    // if so, registerCodec() reclaims the one we tried to register for us.
    codec = registerCodec(codec, codecName, mediaType);
    return (shaperHandle_t) codec;
}

// mapping & unmapping
// give me the mappings for 'kind'.
// kind==null (or empty string), means *all* mappings

const char **getMappings(shaperHandle_t shaper, const char *kind) {
    CodecProperties *codec = (CodecProperties*) shaper;
    if (codec == nullptr)
        return nullptr;
    if (kind == nullptr)
        kind = "";

    return codec->getMappings(kind, /* reverse */ false);
}

const char **getReverseMappings(shaperHandle_t shaper, const char *kind) {
    CodecProperties *codec = (CodecProperties*) shaper;
    if (codec == nullptr)
        return nullptr;
    if (kind == nullptr)
        kind = "";

    return codec->getMappings(kind, /* reverse */ true);
}


// the system grabs this structure
__attribute__ ((visibility ("default")))
extern "C" FormatShaperOps_t shaper_ops = {
    .version = SHAPER_VERSION_V1,

    .findShaper = findShaper,
    .createShaper = createShaper,
    .setMap = setMap,
    .setFeature = setFeature,
    .registerShaper = registerShaper,

    .shapeFormat = shapeFormat,
    .getMappings = getMappings,
    .getReverseMappings = getReverseMappings,

    .setTuning = setTuning,
};

}  // namespace mediaformatshaper
}  // namespace android

