/*
 * Copyright 2023, The Android Open Source Project
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

#ifndef CODEC_ERROR_LOG_H_

#define CODEC_ERROR_LOG_H_

#include <sstream>
#include <string>

#include <android-base/thread_annotations.h>

#include <media/stagefright/foundation/AString.h>

namespace android {

/**
 * CodecErrorLog gathers what happened during codec failures, and make them
 * available to clients for debugging purpose.
 */
class CodecErrorLog {
public:
    CodecErrorLog() = default;

    /**
     * Log a line of message.
     *
     * \note the message should be readable to developers who may not be
     *       familiar with MediaCodec internals
     */
    void log(const char *tag, const char *message);
    void log(const char *tag, const std::string &message);

    /**
     * Extract the accumulated log as string. This operation clears the log.
     */
    std::string extract();

    /**
     * Clears the previous log.
     */
    void clear();

private:
    mutable std::mutex mLock;
    std::stringstream mStream GUARDED_BY(mLock);
};

}  // namespace android

#endif  // CODEC_ERROR_LOG_H_
