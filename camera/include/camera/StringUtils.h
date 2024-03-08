/*
 * Copyright (C) 2023 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA_STRINGUTILS_H
#define ANDROID_SERVERS_CAMERA_STRINGUTILS_H

#include <memory>
#include <optional>
#include <string>

#include <fmt/printf.h>
#include <utils/String8.h>
#include <utils/String16.h>

namespace android {
    inline String8 toString8(const std::string &str) {
        return String8(str.c_str());
    }

    inline String8 toString8(const String16 &str) {
        return String8(str);
    }

    inline String8 toString8(const char *str) {
        return String8(str);
    }

    inline String16 toString16(const std::string &str) {
        return String16(str.c_str());
    }

    inline String16 toString16(const String8 &str) {
        return String16(str);
    }

    inline String16 toString16(const char *str) {
        return String16(str);
    }

    inline std::optional<String16> toString16(std::optional<std::string> str) {
        if (str.has_value()) {
            return std::optional<String16>(toString16(str.value()));
        }

        return std::nullopt;
    }

    inline std::string toStdString(const String8 &str) {
        return std::string(str.c_str());
    }

    inline std::string toStdString(const String16 &str) {
        String8 str8(str);
        return std::string(str8.c_str());
    }

    /**
     * Convert a non-null-terminated UTF16 string to a UTF8 string (i.e. in jni functions)
     * len is the number of characters.
     */
    inline std::string toStdString(const char16_t *str, size_t len) {
        String16 str16(str, len);
        String8 str8(str16);
        return std::string(str8.c_str());
    }
} // namespace android

#endif // ANDROID_SERVERS_CAMERA_STRINGUTILS_H
