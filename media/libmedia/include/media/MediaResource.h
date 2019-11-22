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


#ifndef ANDROID_MEDIA_RESOURCE_H
#define ANDROID_MEDIA_RESOURCE_H

#include <aidl/android/media/MediaResourceParcel.h>
#include <utils/String8.h>

namespace android {

using aidl::android::media::MediaResourceParcel;
using aidl::android::media::MediaResourceSubType;
using aidl::android::media::MediaResourceType;

class MediaResource : public MediaResourceParcel {
public:
    using Type = MediaResourceType;
    using SubType = MediaResourceSubType;

    MediaResource() = delete;
    MediaResource(Type type, int64_t value);
    MediaResource(Type type, SubType subType, int64_t value);
    MediaResource(Type type, const std::vector<int8_t> &id, int64_t value);

    static MediaResource CodecResource(bool secure, bool video);
    static MediaResource GraphicMemoryResource(int64_t value);
    static MediaResource CpuBoostResource();
    static MediaResource VideoBatteryResource();
    static MediaResource DrmSessionResource(const std::vector<int8_t> &id, int64_t value);
};

inline static const char *asString(MediaResource::Type i, const char *def = "??") {
    switch (i) {
        case MediaResource::Type::kUnspecified:    return "unspecified";
        case MediaResource::Type::kSecureCodec:    return "secure-codec";
        case MediaResource::Type::kNonSecureCodec: return "non-secure-codec";
        case MediaResource::Type::kGraphicMemory:  return "graphic-memory";
        case MediaResource::Type::kCpuBoost:       return "cpu-boost";
        case MediaResource::Type::kBattery:        return "battery";
        case MediaResource::Type::kDrmSession:     return "drm-session";
        default:                                   return def;
    }
}

inline static const char *asString(MediaResource::SubType i, const char *def = "??") {
    switch (i) {
        case MediaResource::SubType::kUnspecifiedSubType: return "unspecified";
        case MediaResource::SubType::kAudioCodec:         return "audio-codec";
        case MediaResource::SubType::kVideoCodec:         return "video-codec";
        default:                                 return def;
    }
}

String8 toString(const MediaResourceParcel& resource);

}; // namespace android

#endif  // ANDROID_MEDIA_RESOURCE_H
