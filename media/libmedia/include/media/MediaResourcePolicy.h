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


#ifndef ANDROID_MEDIA_RESOURCE_POLICY_H
#define ANDROID_MEDIA_RESOURCE_POLICY_H

#include <aidl/android/media/MediaResourcePolicyParcel.h>
#include <utils/String8.h>

namespace android {

using aidl::android::media::MediaResourcePolicyParcel;

class MediaResourcePolicy : public MediaResourcePolicyParcel {
public:
    MediaResourcePolicy() = delete;
    MediaResourcePolicy(const std::string& type, const std::string& value);

    static const char* kPolicySupportsMultipleSecureCodecs();
    static const char* kPolicySupportsSecureWithNonSecureCodec();
};

String8 toString(const MediaResourcePolicyParcel &policy);

}; // namespace android

#endif  // ANDROID_MEDIA_RESOURCE_POLICY_H
