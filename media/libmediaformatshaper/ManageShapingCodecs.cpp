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
#define LOG_TAG "ManageShapingCodecs"
#include <utils/Log.h>

#include <mutex>
#include <string>
#include <inttypes.h>

#include <media/NdkMediaFormat.h>

#include "CodecProperties.h"

namespace android {
namespace mediaformatshaper {

// manage the list of codec information.
//
// XXX: the mutex here is too heavy; rework that.
//

static std::mutex sCodecMutex;
static std::map<std::string, CodecProperties*> sCodecTraits;

CodecProperties *findCodec(const char *codecName, const char *mediaType) {
    CodecProperties *codec = nullptr;

    // synthesize a name from both codecName + mediaType
    // some codecs support multiple media types and may have different capabilities
    // for each media type
    //
    std::string codecKey = codecName;
    codecKey += "-";
    codecKey += mediaType;

    std::lock_guard  _l(sCodecMutex);

    auto it = sCodecTraits.find(codecKey);
    if (it != sCodecTraits.end()) {
        codec = it->second;
    }

    return codec;
}

CodecProperties *registerCodec(CodecProperties *codec, const char *codecName,
                               const char *mediaType) {

    CodecProperties *registeredCodec = nullptr;

    if (codec->isRegistered()) {
        return nullptr;
    }

    // synthesize a name from both codecName + mediaType
    // some codecs support multiple media types and may have different capabilities
    // for each media type
    //
    std::string codecKey = codecName;
    codecKey += "-";
    codecKey += mediaType;

    std::lock_guard  _l(sCodecMutex);

    auto it = sCodecTraits.find(codecKey);
    if (it != sCodecTraits.end()) {
        registeredCodec = it->second;
    }

    if (registeredCodec == nullptr) {
        // register the one that was passed to us
        ALOGV("Creating entry for codec %s, mediaType %s, key %s", codecName, mediaType,
              codecKey.c_str());
        sCodecTraits.insert({codecKey, codec});
        registeredCodec = codec;
        codec->setRegistered(true);
    } else {
        // one has already been registered, use that
        // and discard the candidate
        delete codec;
        codec = nullptr;
    }

    return registeredCodec;
}

}  // namespace mediaformatshaper
}  // namespace android

