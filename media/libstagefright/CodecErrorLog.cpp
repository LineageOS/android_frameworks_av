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

//#define LOG_NDEBUG 0
#define LOG_TAG "CodecErrorLog"

#include <log/log.h>
#include <media/stagefright/CodecErrorLog.h>

namespace android {

void CodecErrorLog::log(const char *tag, const char *message) {
    std::unique_lock lock(mLock);
    ALOG(LOG_ERROR, tag, "%s", message);
    mStream << message << std::endl;
}

void CodecErrorLog::log(const char *tag, const std::string &message) {
    log(tag, message.c_str());
}

std::string CodecErrorLog::extract() {
    std::unique_lock lock(mLock);
    std::string msg = mStream.str();
    mStream.str("");
    return msg;
}

void CodecErrorLog::clear() {
    std::unique_lock lock(mLock);
    mStream.str("");
}

}  // namespace android
