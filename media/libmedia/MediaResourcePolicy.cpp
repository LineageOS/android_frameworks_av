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
#define LOG_TAG "MediaResourcePolicy"

#include <aidl/android/media/IResourceManagerService.h>
#include <media/MediaResourcePolicy.h>
#include <utils/Log.h>

namespace android {

using aidl::android::media::IResourceManagerService;
//static
const char* MediaResourcePolicy::kPolicySupportsMultipleSecureCodecs() {
    return IResourceManagerService::kPolicySupportsMultipleSecureCodecs;
}
//static
const char* MediaResourcePolicy::kPolicySupportsSecureWithNonSecureCodec() {
    return IResourceManagerService::kPolicySupportsSecureWithNonSecureCodec;
}

MediaResourcePolicy::MediaResourcePolicy(
        const std::string& type, const std::string& value) {
    this->type = type;
    this->value = value;
}

String8 toString(const MediaResourcePolicyParcel &policy) {
    String8 str;
    str.appendFormat("%s:%s", policy.type.c_str(), policy.value.c_str());
    return str;
}

}; // namespace android
