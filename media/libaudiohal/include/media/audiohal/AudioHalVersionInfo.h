/*
 * Copyright (C) 2022 The Android Open Source Project
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

#pragma once

#include <string>
#include <utility>
#include <android/media/AudioHalVersion.h>

namespace android::detail {

class AudioHalVersionInfo : public android::media::AudioHalVersion {
  public:
    AudioHalVersionInfo(Type halType, int halMajor, int halMinor = 0) {
        type = halType;
        major = halMajor;
        minor = halMinor;
    }

    Type getType() const { return type; }

    int getMajorVersion() const { return major; }

    int getMinorVersion() const { return minor; }

    /** Keep HIDL version format as is for backward compatibility, only add prefix for AIDL. */
    std::string toVersionString() const {
        std::string versionStr =
                android::internal::ToString(major) + "." + android::internal::ToString(minor);
        if (type == Type::AIDL) {
            return "aidl";
        } else {
            return versionStr;
        }
    }
};

} // namespace android
