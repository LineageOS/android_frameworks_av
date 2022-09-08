/*
 * Copyright (C) 2009 The Android Open Source Project
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
#define LOG_TAG "FoundationUtils"
#include <utils/Log.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cutils/properties.h>
#include <media/stagefright/foundation/AString.h>

namespace android {

AString uriDebugString(const AString &uri, bool incognito) {
    if (incognito) {
        return AString("<URI suppressed>");
    }

    if (property_get_bool("media.stagefright.log-uri", false)) {
        return uri;
    }

    // find scheme
    AString scheme;
    const char *chars = uri.c_str();
    for (size_t i = 0; i < uri.size(); i++) {
        const char c = chars[i];
        if (!isascii(c)) {
            break;
        } else if (isalpha(c)) {
            continue;
        } else if (i == 0) {
            // first character must be a letter
            break;
        } else if (isdigit(c) || c == '+' || c == '.' || c =='-') {
            continue;
        } else if (c != ':') {
            break;
        }
        scheme = AString(uri, 0, i);
        scheme.append("://<suppressed>");
        return scheme;
    }
    return AString("<no-scheme URI suppressed>");
}

AString MakeUserAgent() {
    AString ua;
    ua.append("stagefright/1.2 (Linux;Android ");

#if (PROPERTY_VALUE_MAX < 8)
#error "PROPERTY_VALUE_MAX must be at least 8"
#endif

    char value[PROPERTY_VALUE_MAX];
    property_get("ro.build.version.release", value, "Unknown");
    ua.append(value);
    ua.append(")");

    return ua;
}

AString nameForFd(int fd) {
    const size_t SIZE = 256;
    char buffer[SIZE];
    AString result;
    snprintf(buffer, SIZE, "/proc/%d/fd/%d", getpid(), fd);
    struct stat s;
    if (lstat(buffer, &s) == 0) {
        if ((s.st_mode & S_IFMT) == S_IFLNK) {
            char linkto[256];
            int len = readlink(buffer, linkto, sizeof(linkto));
            if(len > 0) {
                if(len > 255) {
                    linkto[252] = '.';
                    linkto[253] = '.';
                    linkto[254] = '.';
                    linkto[255] = 0;
                } else {
                    linkto[len] = 0;
                }
                result.append(linkto);
            }
        } else {
            result.append("unexpected type for ");
            result.append(buffer);
        }
    } else {
        result.append("couldn't open ");
        result.append(buffer);
    }
    return result;
}

}  // namespace android
