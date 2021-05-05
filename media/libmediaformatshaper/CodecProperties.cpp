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
#define LOG_TAG "CodecProperties"
#include <utils/Log.h>

#include <string>
#include <stdlib.h>

#include "CodecProperties.h"

#include <media/stagefright/MediaCodecConstants.h>


// we aren't going to mess with shaping points dimensions beyond this
static const int32_t DIMENSION_LIMIT = 16384;

namespace android {
namespace mediaformatshaper {

CodecProperties::CodecProperties(std::string name, std::string mediaType) {
    ALOGV("CodecProperties(%s, %s)", name.c_str(), mediaType.c_str());
    mName = name;
    mMediaType = mediaType;
}

std::string CodecProperties::getName(){
    return mName;
}

std::string CodecProperties::getMediaType(){
    return mMediaType;
}

int CodecProperties::supportedMinimumQuality() {
    return mMinimumQuality;
}
void CodecProperties::setSupportedMinimumQuality(int vmaf) {
    mMinimumQuality = vmaf;
}

void CodecProperties::setMissingQpBoost(double boost) {
    mMissingQpBoost = boost;
}
void CodecProperties::setPhaseOut(double phaseout) {
    mPhaseOut = phaseout;
}

// what API is this codec set up for (e.g. API of the associated partition)
// vendor-side (OEM) codecs may be older, due to 'vendor freeze' and treble
int CodecProperties::supportedApi() {
    return mApi;
}

void CodecProperties::setFeatureValue(std::string key, int32_t value) {
    ALOGD("setFeatureValue(%s,%d)", key.c_str(), value);
    mFeatures.insert({key, value});

    if (!strcmp(key.c_str(), FEATURE_QpBounds)) {
        setSupportsQp(1);
    } else if (!strcmp(key.c_str(), "video-minimum-quality")) {
        setSupportedMinimumQuality(1);
    } else if (!strcmp(key.c_str(), "vq-minimum-quality")) { // from prototyping
        setSupportedMinimumQuality(1);
    }
}

bool CodecProperties::getFeatureValue(std::string key, int32_t *valuep) {
    ALOGV("getFeatureValue(%s)", key.c_str());
    if (valuep == nullptr) {
        return false;
    }
    auto mapped = mFeatures.find(key);
    if (mapped != mFeatures.end()) {
        *valuep = mapped->second;
        return true;
    }
    return false;
}

// Tuning values (which differ from Features)
// this is where we set up things like target bitrates and QP ranges
// NB the tuning values arrive as a string, allowing us to convert it into an appropriate
// format (int, float, ranges, other combinations)
//
void CodecProperties::setTuningValue(std::string key, std::string value) {
    ALOGD("setTuningValue(%s,%s)", key.c_str(), value.c_str());
    mTunings.insert({key, value});

    bool legal = false;
    // NB: old school strtol() because std::stoi() throws exceptions
    if (!strcmp(key.c_str(), "vq-target-qpmax")) {
        const char *p = value.c_str();
        char *q;
        int32_t iValue =  strtol(p, &q, 0);
        if (q != p) {
            setTargetQpMax(iValue);
            legal = true;
        }
    } else if (!strncmp(key.c_str(), "vq-target-qpmax-", strlen("vq-target-qpmax-"))) {
            std::string resolution = key.substr(strlen("vq-target-qpmax-"));
            if (qpMaxPoint(resolution, value)) {
                legal = true;
            }
    } else if (!strcmp(key.c_str(), "vq-target-bpp")) {
        const char *p = value.c_str();
        char *q;
        double bpp = strtod(p, &q);
        if (q != p) {
            setBpp(bpp);
            legal = true;
        }
    } else if (!strncmp(key.c_str(), "vq-target-bpp-", strlen("vq-target-bpp-"))) {
            std::string resolution = key.substr(strlen("vq-target-bpp-"));
            if (bppPoint(resolution, value)) {
                legal = true;
            }
    } else if (!strcmp(key.c_str(), "vq-target-bppx100")) {
        // legacy, prototyping
        const char *p = value.c_str();
        char *q;
        int32_t iValue =  strtol(p, &q, 0);
        if (q != p) {
            double bpp = iValue / 100.0;
            setBpp(bpp);
            legal = true;
        }
    } else if (!strcmp(key.c_str(), "vq-bitrate-phaseout")) {
        const char *p = value.c_str();
        char *q;
        double phaseout = strtod(p, &q);
        if (q != p) {
            setPhaseOut(phaseout);
            legal = true;
        }
    } else if (!strcmp(key.c_str(), "vq-boost-missing-qp")) {
        const char *p = value.c_str();
        char *q;
        double boost = strtod(p, &q);
        if (q != p) {
            setMissingQpBoost(boost);
            legal = true;
        }
    } else {
        legal = true;
    }

    if (!legal) {
        ALOGW("setTuningValue() unable to apply tuning '%s' with value '%s'",
              key.c_str(), value.c_str());
    }
    return;
}

bool CodecProperties::getTuningValue(std::string key, std::string &value) {
    ALOGV("getTuningValue(%s)", key.c_str());
    auto mapped = mFeatures.find(key);
    if (mapped != mFeatures.end()) {
        value = mapped->second;
        return true;
    }
    return false;
}

bool CodecProperties::bppPoint(std::string resolution, std::string value) {

    int32_t width = 0;
    int32_t height = 0;
    double bpp = -1;

    // resolution is "WxH", "W*H" or a standard name like "720p"
    if (resolution == "1080p") {
        width = 1080; height = 1920;
    } else if (resolution == "720p") {
        width = 720; height = 1280;
    } else if (resolution == "540p") {
        width = 540; height = 960;
    } else if (resolution == "480p") {
        width = 480; height = 854;
    } else {
        size_t sep = resolution.find('x');
        if (sep == std::string::npos) {
            sep = resolution.find('*');
        }
        if (sep == std::string::npos) {
            ALOGW("unable to parse resolution: '%s'", resolution.c_str());
            return false;
        }
        std::string w = resolution.substr(0, sep);
        std::string h = resolution.substr(sep+1);

        char *q;
        const char *p = w.c_str();
        width = strtol(p, &q, 0);
        if (q == p) {
                width = -1;
        }
        p = h.c_str();
        height = strtol(p, &q, 0);
        if (q == p) {
                height = -1;
        }
        if (width <= 0 || height <= 0 || width > DIMENSION_LIMIT || height > DIMENSION_LIMIT) {
            ALOGW("unparseable: width, height '%s'", resolution.c_str());
            return false;
        }
    }

    const char *p = value.c_str();
    char *q;
    bpp = strtod(p, &q);
    if (q == p) {
        ALOGW("unparseable bpp '%s'", value.c_str());
        return false;
    }

    struct bpp_point *point = (struct bpp_point*) malloc(sizeof(*point));
    if (point == nullptr) {
        ALOGW("unable to allocate memory for bpp point");
        return false;
    }

    point->pixels = width * height;
    point->width = width;
    point->height = height;
    point->bpp = bpp;

    if (mBppPoints == nullptr) {
        point->next = nullptr;
        mBppPoints = point;
    } else if (point->pixels < mBppPoints->pixels) {
        // at the front
        point->next = mBppPoints;
        mBppPoints = point;
    } else {
        struct bpp_point *after = mBppPoints;
        while (after->next) {
            if (point->pixels > after->next->pixels) {
                after = after->next;
                continue;
            }

            // insert before after->next
            point->next = after->next;
            after->next = point;
            break;
        }
        if (after->next == nullptr) {
            // hasn't gone in yet
            point->next = nullptr;
            after->next = point;
        }
    }

    return true;
}

double CodecProperties::getBpp(int32_t width, int32_t height) {
    // look in the per-resolution list

    int32_t pixels = width * height;

    if (mBppPoints) {
        struct bpp_point *point = mBppPoints;
        while (point && point->pixels < pixels) {
            point = point->next;
        }
        if (point) {
            ALOGV("getBpp(w=%d,h=%d) returns %f from bpppoint w=%d h=%d",
                width, height, point->bpp, point->width, point->height);
            return point->bpp;
        }
    }

    ALOGV("defaulting to %f bpp", mBpp);
    return mBpp;
}

bool CodecProperties::qpMaxPoint(std::string resolution, std::string value) {

    int32_t width = 0;
    int32_t height = 0;
    int qpMax = INT32_MAX;

    // resolution is "WxH", "W*H" or a standard name like "720p"
    if (resolution == "1080p") {
        width = 1080; height = 1920;
    } else if (resolution == "720p") {
        width = 720; height = 1280;
    } else if (resolution == "540p") {
        width = 540; height = 960;
    } else if (resolution == "480p") {
        width = 480; height = 854;
    } else {
        size_t sep = resolution.find('x');
        if (sep == std::string::npos) {
            sep = resolution.find('*');
        }
        if (sep == std::string::npos) {
            ALOGW("unable to parse resolution: '%s'", resolution.c_str());
            return false;
        }
        std::string w = resolution.substr(0, sep);
        std::string h = resolution.substr(sep+1);

        char *q;
        const char *p = w.c_str();
        width = strtol(p, &q, 0);
        if (q == p) {
                width = -1;
        }
        p = h.c_str();
        height = strtol(p, &q, 0);
        if (q == p) {
                height = -1;
        }
        if (width <= 0 || height <= 0 || width > DIMENSION_LIMIT || height > DIMENSION_LIMIT) {
            ALOGW("unparseable: width, height '%s'", resolution.c_str());
            return false;
        }
    }

    const char *p = value.c_str();
    char *q;
    qpMax = strtol(p, &q, 0);
    if (q == p) {
        ALOGW("unparseable qpmax '%s'", value.c_str());
        return false;
    }

    // convert to our internal 'unspecified' notation
    if (qpMax == -1)
        qpMax = INT32_MAX;

    struct qpmax_point *point = (struct qpmax_point*) malloc(sizeof(*point));
    if (point == nullptr) {
        ALOGW("unable to allocate memory for qpmax point");
        return false;
    }

    point->pixels = width * height;
    point->width = width;
    point->height = height;
    point->qpMax = qpMax;

    if (mQpMaxPoints == nullptr) {
        point->next = nullptr;
        mQpMaxPoints = point;
    } else if (point->pixels < mQpMaxPoints->pixels) {
        // at the front
        point->next = mQpMaxPoints;
        mQpMaxPoints = point;
    } else {
        struct qpmax_point *after = mQpMaxPoints;
        while (after->next) {
            if (point->pixels > after->next->pixels) {
                after = after->next;
                continue;
            }

            // insert before after->next
            point->next = after->next;
            after->next = point;
            break;
        }
        if (after->next == nullptr) {
            // hasn't gone in yet
            point->next = nullptr;
            after->next = point;
        }
    }

    return true;
}

int CodecProperties::targetQpMax(int32_t width, int32_t height) {
    // look in the per-resolution list

    int32_t pixels = width * height;

    if (mQpMaxPoints) {
        struct qpmax_point *point = mQpMaxPoints;
        while (point && point->pixels < pixels) {
            point = point->next;
        }
        if (point) {
            ALOGV("targetQpMax(w=%d,h=%d) returns %d from qpmax_point w=%d h=%d",
                width, height, point->qpMax, point->width, point->height);
            return point->qpMax;
        }
    }

    ALOGV("defaulting to %d qpmax", mTargetQpMax);
    return mTargetQpMax;
}

void CodecProperties::setTargetQpMax(int qpMax) {
    // convert to our internal 'unspecified' notation
    if (qpMax == -1)
        qpMax = INT32_MAX;
    mTargetQpMax = qpMax;
}

std::string CodecProperties::getMapping(std::string key, std::string kind) {
    ALOGV("getMapping(key %s, kind %s )", key.c_str(), kind.c_str());
    //play with mMappings
    auto mapped = mMappings.find(kind + "-" + key);
    if (mapped != mMappings.end()) {
        std::string result = mapped->second;
        ALOGV("getMapping(%s, %s) -> %s", key.c_str(), kind.c_str(), result.c_str());
        return result;
    }
    ALOGV("nope, return unchanged key");
    return key;
}


// really a bit of debugging code here.
void CodecProperties::showMappings() {
    ALOGD("Mappings:");
    int count = 0;
    for (const auto& [key, value] : mMappings) {
         count++;
         ALOGD("'%s' -> '%s'", key.c_str(), value.c_str());
    }
    ALOGD("total %d mappings", count);
}

void CodecProperties::setMapping(std::string kind, std::string key, std::string value) {
    ALOGV("setMapping(%s,%s,%s)", kind.c_str(), key.c_str(), value.c_str());
    std::string metaKey = kind + "-" + key;
    mMappings.insert({metaKey, value});
}

const char **CodecProperties::getMappings(std::string kind, bool reverse) {
    ALOGV("getMappings(kind %s, reverse %d", kind.c_str(), reverse);
    // how many do we need?
    int count = mMappings.size();
    if (count == 0) {
        ALOGV("empty mappings");
        return nullptr;
    }
    size_t size = sizeof(char *) * (2 * count + 2);
    const char **result = (const char **)malloc(size);
    if (result == nullptr) {
        ALOGW("no memory to return mappings");
        return nullptr;
    }
    memset(result, '\0', size);

    const char **pp = result;
    for (const auto& [key, value] : mMappings) {
        // split out the kind/key
        size_t pos = key.find('-');
        if (pos == std::string::npos) {
            ALOGD("ignoring malformed key: %s", key.c_str());
            continue;
        }
        std::string actualKind = key.substr(0,pos);
        if (kind.length() != 0 && kind != actualKind) {
            ALOGD("kinds don't match: want '%s' got '%s'", kind.c_str(), actualKind.c_str());
            continue;
        }
        if (reverse) {
            // codec specific -> std aka 'unmapping'
            pp[0] = strdup( value.c_str());
            pp[1] = strdup( key.substr(pos+1).c_str());
        } else {
            // std -> codec specific
            pp[0] = strdup( key.substr(pos+1).c_str());
            pp[1] = strdup( value.c_str());
        }
        ALOGV(" %s -> %s", pp[0], pp[1]);
        pp += 2;
    }

    pp[0] = nullptr;
    pp[1] = nullptr;

    return result;
}


} // namespace mediaformatshaper
} // namespace android

