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

#include <media/formatshaper/CodecProperties.h>

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

int CodecProperties::targetQpMax() {
    return mTargetQpMax;
}
void CodecProperties::setTargetQpMax(int qpMax) {
    mTargetQpMax = qpMax;
}

// what API is this codec set up for (e.g. API of the associated partition)
// vendor-side (OEM) codecs may be older, due to 'vendor freeze' and treble
int CodecProperties::supportedApi() {
    return mApi;
}

void CodecProperties::setFeatureValue(std::string key, int32_t value) {
    ALOGD("setFeatureValue(%s,%d)", key.c_str(), value);
    mFeatures.insert({key, value});

    if (!strcmp(key.c_str(), "qp-bounds")) {               // official key
        setSupportsQp(1);
    } else if (!strcmp(key.c_str(), "vq-supports-qp")) {   // key from prototyping
        setSupportsQp(1);
    } else if (!strcmp(key.c_str(), "vq-minimum-quality")) {
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
    } else if (!strcmp(key.c_str(), "vq-target-bpp")) {
        const char *p = value.c_str();
        char *q;
        double bpp = strtod(p, &q);
        if (q != p) {
            setBpp(bpp);
            legal = true;
        }
    } else if (!strcmp(key.c_str(), "vq-target-bppx100")) {
        const char *p = value.c_str();
        char *q;
        int32_t iValue =  strtol(p, &q, 0);
        if (q != p) {
            double bpp = iValue / 100.0;
            setBpp(bpp);
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

