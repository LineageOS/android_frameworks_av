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

// #define LOG_NDEBUG 0
#define LOG_TAG "TranscodingLogger"

#include <media/NdkCommon.h>
#include <media/TranscodingLogger.h>
#include <statslog_media.h>
#include <utils/Log.h>

#include <cmath>
#include <string>

namespace android {

static_assert(TranscodingLogger::UNKNOWN ==
                      android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__UNKNOWN,
              "Session event mismatch");
static_assert(TranscodingLogger::FINISHED ==
                      android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__FINISHED,
              "Session event mismatch");
static_assert(TranscodingLogger::ERROR ==
                      android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__ERROR,
              "Session event mismatch");
static_assert(TranscodingLogger::PAUSED ==
                      android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__PAUSED,
              "Session event mismatch");
static_assert(TranscodingLogger::CANCELLED ==
                      android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__CANCELLED,
              "Session event mismatch");
static_assert(TranscodingLogger::START_FAILED ==
                      android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__START_FAILED,
              "Session event mismatch");
static_assert(TranscodingLogger::RESUME_FAILED ==
                      android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__RESUME_FAILED,
              "Session event mismatch");
static_assert(TranscodingLogger::CREATE_FAILED ==
                      android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__CREATE_FAILED,
              "Session event mismatch");
static_assert(
        TranscodingLogger::CONFIG_SRC_FAILED ==
                android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__CONFIG_SRC_FAILED,
        "Session event mismatch");
static_assert(
        TranscodingLogger::CONFIG_DST_FAILED ==
                android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__CONFIG_DST_FAILED,
        "Session event mismatch");
static_assert(
        TranscodingLogger::CONFIG_TRACK_FAILED ==
                android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__CONFIG_TRACK_FAILED,
        "Session event mismatch");
static_assert(
        TranscodingLogger::OPEN_SRC_FD_FAILED ==
                android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__OPEN_SRC_FD_FAILED,
        "Session event mismatch");
static_assert(
        TranscodingLogger::OPEN_DST_FD_FAILED ==
                android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__OPEN_DST_FD_FAILED,
        "Session event mismatch");
static_assert(TranscodingLogger::NO_TRACKS ==
                      android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED__REASON__NO_TRACKS,
              "Session event mismatch");

static inline int32_t getInt32(AMediaFormat* fmt, const char* key, int32_t defaultValue = -1) {
    int32_t value;
    if (fmt == nullptr || !AMediaFormat_getInt32(fmt, key, &value)) {
        ALOGW("Unable to get %s", key);
        value = defaultValue;
    }
    return value;
}

// Note: returned string is owned by format and only valid until the next getString.
static inline const char* getString(AMediaFormat* fmt, const char* key,
                                    const char* defaultValue = "(null)") {
    const char* value;
    if (fmt == nullptr || !AMediaFormat_getString(fmt, key, &value)) {
        ALOGW("Unable to get %s", key);
        value = defaultValue;
    }
    return value;
}

TranscodingLogger::TranscodingLogger()
      : mSessionEndedAtomWriter(&android::media::stats::stats_write) {}

void TranscodingLogger::logSessionEnded(enum SessionEndedReason reason, uid_t callingUid,
                                        int status, std::chrono::microseconds duration,
                                        AMediaFormat* srcFormat, AMediaFormat* dstFormat) {
    logSessionEnded(std::chrono::steady_clock::now(), reason, callingUid, status, duration,
                    srcFormat, dstFormat);
}

void TranscodingLogger::logSessionEnded(const std::chrono::steady_clock::time_point& now,
                                        enum SessionEndedReason reason, uid_t callingUid,
                                        int status, std::chrono::microseconds duration,
                                        AMediaFormat* srcFormat, AMediaFormat* dstFormat) {
    if (srcFormat == nullptr) {
        ALOGE("Source format is null. Dropping event.");
        return;
    }

    if (!shouldLogAtom(now, status)) {
        ALOGD("Maximum logged event count reached. Dropping event.");
        return;
    }

    // Extract the pieces of information to log.
    const int32_t srcWidth = getInt32(srcFormat, AMEDIAFORMAT_KEY_WIDTH);
    const int32_t srcHeight = getInt32(srcFormat, AMEDIAFORMAT_KEY_HEIGHT);
    const char* srcMime = getString(srcFormat, AMEDIAFORMAT_KEY_MIME);
    const int32_t srcProfile = getInt32(srcFormat, AMEDIAFORMAT_KEY_PROFILE);
    const int32_t srcLevel = getInt32(srcFormat, AMEDIAFORMAT_KEY_LEVEL);
    const int32_t srcFrameRate = getInt32(srcFormat, AMEDIAFORMAT_KEY_FRAME_RATE);
    const int32_t srcFrameCount = getInt32(srcFormat, AMEDIAFORMAT_KEY_FRAME_COUNT);
    const bool srcIsHdr = AMediaFormatUtils::VideoIsHdr(srcFormat);

    int32_t dstWidth = getInt32(dstFormat, AMEDIAFORMAT_KEY_WIDTH, srcWidth);
    int32_t dstHeight = getInt32(dstFormat, AMEDIAFORMAT_KEY_HEIGHT, srcHeight);
    const char* dstMime = dstFormat == nullptr
                                  ? "passthrough"
                                  : getString(dstFormat, AMEDIAFORMAT_KEY_MIME, srcMime);
    const bool dstIsHdr = false;  // Transcoder always request SDR output.

    int64_t tmpDurationUs;
    const int32_t srcDurationMs =
            AMediaFormat_getInt64(srcFormat, AMEDIAFORMAT_KEY_DURATION, &tmpDurationUs)
                    ? static_cast<int32_t>(tmpDurationUs / 1000)
                    : -1;

    int32_t transcodeFrameRate = -1;
    if (status == 0 && srcFrameCount > 0 && duration.count() > 0) {
        std::chrono::duration<double> seconds{duration};
        transcodeFrameRate = static_cast<int32_t>(
                std::round(static_cast<double>(srcFrameCount) / seconds.count()));
    }

    // Write the atom.
    mSessionEndedAtomWriter(android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED,
                            static_cast<int>(reason), callingUid, status, transcodeFrameRate,
                            srcWidth, srcHeight, srcMime, srcProfile, srcLevel, srcFrameRate,
                            srcDurationMs, srcIsHdr, dstWidth, dstHeight, dstMime, dstIsHdr);
}

bool TranscodingLogger::shouldLogAtom(const std::chrono::steady_clock::time_point& now,
                                      int status) {
    std::scoped_lock lock{mLock};
    static const std::chrono::hours oneDay(24);

    // Remove events older than one day.
    while (mLastLoggedAtoms.size() > 0 && (now - mLastLoggedAtoms.front().first) >= oneDay) {
        if (mLastLoggedAtoms.front().second == AMEDIA_OK) {
            --mSuccessfulCount;
        }
        mLastLoggedAtoms.pop();
    }

    // Don't log if maximum number of events is reached.
    if (mLastLoggedAtoms.size() >= kMaxAtomsPerDay) {
        return false;
    }

    // Don't log if the event is successful and the maximum number of successful events is reached.
    if (status == AMEDIA_OK && mSuccessfulCount >= kMaxSuccessfulAtomsPerDay) {
        return false;
    }

    // Record the event.
    if (status == AMEDIA_OK) {
        ++mSuccessfulCount;
    }
    mLastLoggedAtoms.emplace(now, status);
    return true;
}

void TranscodingLogger::setSessionEndedAtomWriter(const SessionEndedAtomWriter& writer) {
    mSessionEndedAtomWriter = writer;
}

}  // namespace android
