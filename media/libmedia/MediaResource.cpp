/*
 * Copyright 2015 The Android Open Source Project
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
#define LOG_TAG "MediaResource"
#include <utils/Log.h>
#include <media/MediaResource.h>

#include <vector>

namespace android {

MediaResource::MediaResource(Type type, int64_t value) {
    this->type = type;
    this->subType = SubType::kUnspecifiedSubType;
    this->value = value;
}

MediaResource::MediaResource(Type type, SubType subType, int64_t value) {
    this->type = type;
    this->subType = subType;
    this->value = value;
}

MediaResource::MediaResource(Type type, const std::vector<int8_t> &id, int64_t value) {
    this->type = type;
    this->subType = SubType::kUnspecifiedSubType;
    this->id = id;
    this->value = value;
}

//static
MediaResource MediaResource::CodecResource(bool secure, bool video) {
    return MediaResource(
            secure ? Type::kSecureCodec : Type::kNonSecureCodec,
            video ? SubType::kVideoCodec : SubType::kAudioCodec,
            1);
}

//static
MediaResource MediaResource::GraphicMemoryResource(int64_t value) {
    return MediaResource(Type::kGraphicMemory, value);
}

//static
MediaResource MediaResource::CpuBoostResource() {
    return MediaResource(Type::kCpuBoost, 1);
}

//static
MediaResource MediaResource::VideoBatteryResource() {
    return MediaResource(Type::kBattery, SubType::kVideoCodec, 1);
}

//static
MediaResource MediaResource::DrmSessionResource(const std::vector<int8_t> &id, int64_t value) {
    return MediaResource(Type::kDrmSession, id, value);
}

static String8 bytesToHexString(const std::vector<int8_t> &bytes) {
    String8 str;
    for (auto &b : bytes) {
        str.appendFormat("%02x", b);
    }
    return str;
}

String8 toString(const MediaResourceParcel& resource) {
    String8 str;

    str.appendFormat("%s/%s:[%s]:%lld",
            asString(resource.type), asString(resource.subType),
            bytesToHexString(resource.id).c_str(),
            (long long)resource.value);
    return str;
}

}; // namespace android
