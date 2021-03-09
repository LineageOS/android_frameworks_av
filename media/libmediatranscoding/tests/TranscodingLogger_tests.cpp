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

// Unit Test for TranscodingLogger

// #define LOG_NDEBUG 0
#define LOG_TAG "TranscodingLoggerTest"

#include <android-base/logging.h>
#include <gtest/gtest.h>
#include <media/NdkCommon.h>
#include <media/TranscodingLogger.h>
#include <statslog_media.h>
#include <utils/Log.h>

#include <chrono>

namespace android {

using Reason = TranscodingLogger::SessionEndedReason;

// Data structure corresponding to MediaTranscodingEnded atom.
struct SessionEndedAtom {
    SessionEndedAtom(int32_t atomCode, int32_t reason, int32_t callingUid, int32_t status,
                     int32_t transcoderFps, int32_t srcWidth, int32_t srcHeight,
                     char const* srcMime, int32_t srcProfile, int32_t srcLevel, int32_t srcFps,
                     int32_t srcDurationMs, bool srcIsHdr, int32_t dstWidth, int32_t dstHeight,
                     char const* dstMime, bool dstIsHdr)
          : atomCode(atomCode),
            reason(reason),
            callingUid(callingUid),
            status(status),
            transcoderFps(transcoderFps),
            srcWidth(srcWidth),
            srcHeight(srcHeight),
            srcMime(srcMime),
            srcProfile(srcProfile),
            srcLevel(srcLevel),
            srcFps(srcFps),
            srcDurationMs(srcDurationMs),
            srcIsHdr(srcIsHdr),
            dstWidth(dstWidth),
            dstHeight(dstHeight),
            dstMime(dstMime),
            dstIsHdr(dstIsHdr) {}

    int32_t atomCode;
    int32_t reason;
    int32_t callingUid;
    int32_t status;
    int32_t transcoderFps;
    int32_t srcWidth;
    int32_t srcHeight;
    std::string srcMime;
    int32_t srcProfile;
    int32_t srcLevel;
    int32_t srcFps;
    int32_t srcDurationMs;
    bool srcIsHdr;
    int32_t dstWidth;
    int32_t dstHeight;
    std::string dstMime;
    bool dstIsHdr;
};

// Default configuration values.
static constexpr int32_t kDefaultCallingUid = 1;
static constexpr std::chrono::microseconds kDefaultTranscodeDuration = std::chrono::seconds{2};

static constexpr int32_t kDefaultSrcWidth = 1920;
static constexpr int32_t kDefaultSrcHeight = 1080;
static const std::string kDefaultSrcMime{AMEDIA_MIMETYPE_VIDEO_HEVC};
static constexpr int32_t kDefaultSrcProfile = 1;    // HEVC Main
static constexpr int32_t kDefaultSrcLevel = 65536;  // HEVCMainTierLevel51
static constexpr int32_t kDefaultSrcFps = 30;
static constexpr int32_t kDefaultSrcFrameCount = 120;
static constexpr int64_t kDefaultSrcDurationUs = 1000000 * kDefaultSrcFrameCount / kDefaultSrcFps;

static constexpr int32_t kDefaultDstWidth = 1280;
static constexpr int32_t kDefaultDstHeight = 720;
static const std::string kDefaultDstMime{AMEDIA_MIMETYPE_VIDEO_AVC};

// Util for creating a default source video format.
static AMediaFormat* CreateSrcFormat() {
    AMediaFormat* fmt = AMediaFormat_new();
    AMediaFormat_setInt32(fmt, AMEDIAFORMAT_KEY_WIDTH, kDefaultSrcWidth);
    AMediaFormat_setInt32(fmt, AMEDIAFORMAT_KEY_HEIGHT, kDefaultSrcHeight);
    AMediaFormat_setString(fmt, AMEDIAFORMAT_KEY_MIME, kDefaultSrcMime.c_str());
    AMediaFormat_setInt32(fmt, AMEDIAFORMAT_KEY_PROFILE, kDefaultSrcProfile);
    AMediaFormat_setInt32(fmt, AMEDIAFORMAT_KEY_LEVEL, kDefaultSrcLevel);
    AMediaFormat_setInt32(fmt, AMEDIAFORMAT_KEY_FRAME_RATE, kDefaultSrcFps);
    AMediaFormat_setInt32(fmt, AMEDIAFORMAT_KEY_FRAME_COUNT, kDefaultSrcFrameCount);
    AMediaFormat_setInt64(fmt, AMEDIAFORMAT_KEY_DURATION, kDefaultSrcDurationUs);
    return fmt;
}

// Util for creating a default destination video format.
static AMediaFormat* CreateDstFormat() {
    AMediaFormat* fmt = AMediaFormat_new();
    AMediaFormat_setInt32(fmt, AMEDIAFORMAT_KEY_WIDTH, kDefaultDstWidth);
    AMediaFormat_setInt32(fmt, AMEDIAFORMAT_KEY_HEIGHT, kDefaultDstHeight);
    AMediaFormat_setString(fmt, AMEDIAFORMAT_KEY_MIME, kDefaultDstMime.c_str());
    return fmt;
}

class TranscodingLoggerTest : public ::testing::Test {
public:
    TranscodingLoggerTest() { ALOGI("TranscodingLoggerTest created"); }

    void SetUp() override {
        ALOGI("TranscodingLoggerTest set up");
        mLogger.reset(new TranscodingLogger());
        mLoggedAtoms.clear();
        mSrcFormat.reset();
        mDstFormat.reset();

        // Set a custom atom writer that saves all data, so the test can validate it afterwards.
        mLogger->setSessionEndedAtomWriter(
                [=](int32_t atomCode, int32_t reason, int32_t callingUid, int32_t status,
                    int32_t transcoderFps, int32_t srcWidth, int32_t srcHeight, char const* srcMime,
                    int32_t srcProfile, int32_t srcLevel, int32_t srcFps, int32_t srcDurationMs,
                    bool srcIsHdr, int32_t dstWidth, int32_t dstHeight, char const* dstMime,
                    bool dstIsHdr) -> int {
                    mLoggedAtoms.emplace_back(atomCode, reason, callingUid, status, transcoderFps,
                                              srcWidth, srcHeight, srcMime, srcProfile, srcLevel,
                                              srcFps, srcDurationMs, srcIsHdr, dstWidth, dstHeight,
                                              dstMime, dstIsHdr);
                    return 0;
                });
    }

    void logSession(const std::chrono::steady_clock::time_point& time, Reason reason, int status,
                    AMediaFormat* srcFormat, AMediaFormat* dstFormat) {
        mLogger->logSessionEnded(time, reason, kDefaultCallingUid, status,
                                 kDefaultTranscodeDuration, srcFormat, dstFormat);
    }

    void logSession(const std::chrono::steady_clock::time_point& time, Reason reason, int status) {
        if (!mSrcFormat) {
            mSrcFormat = std::shared_ptr<AMediaFormat>(CreateSrcFormat(), &AMediaFormat_delete);
        }
        if (!mDstFormat) {
            mDstFormat = std::shared_ptr<AMediaFormat>(CreateDstFormat(), &AMediaFormat_delete);
        }
        logSession(time, reason, status, mSrcFormat.get(), mDstFormat.get());
    }

    void logSessionFinished(const std::chrono::steady_clock::time_point& time) {
        logSession(time, Reason::FINISHED, 0);
    }

    void logSessionFailed(const std::chrono::steady_clock::time_point& time) {
        logSession(time, Reason::ERROR, AMEDIA_ERROR_UNKNOWN);
    }

    int logCount() const { return mLoggedAtoms.size(); }

    void validateLatestAtom(Reason reason, int status, bool passthrough = false) {
        const SessionEndedAtom& atom = mLoggedAtoms.back();

        EXPECT_EQ(atom.atomCode, android::media::stats::MEDIA_TRANSCODING_SESSION_ENDED);
        EXPECT_EQ(atom.reason, static_cast<int>(reason));
        EXPECT_EQ(atom.callingUid, kDefaultCallingUid);
        EXPECT_EQ(atom.status, status);
        EXPECT_EQ(atom.srcWidth, kDefaultSrcWidth);
        EXPECT_EQ(atom.srcHeight, kDefaultSrcHeight);
        EXPECT_EQ(atom.srcMime, kDefaultSrcMime);
        EXPECT_EQ(atom.srcProfile, kDefaultSrcProfile);
        EXPECT_EQ(atom.srcLevel, kDefaultSrcLevel);
        EXPECT_EQ(atom.srcFps, kDefaultSrcFps);
        EXPECT_EQ(atom.srcDurationMs, kDefaultSrcDurationUs / 1000);
        EXPECT_FALSE(atom.srcIsHdr);
        EXPECT_EQ(atom.dstWidth, passthrough ? kDefaultSrcWidth : kDefaultDstWidth);
        EXPECT_EQ(atom.dstHeight, passthrough ? kDefaultSrcHeight : kDefaultDstHeight);
        EXPECT_EQ(atom.dstMime, passthrough ? "passthrough" : kDefaultDstMime);
        EXPECT_FALSE(atom.dstIsHdr);

        // Transcoder frame rate is only present on successful sessions.
        if (status == AMEDIA_OK) {
            std::chrono::duration<double> seconds{kDefaultTranscodeDuration};
            const int32_t transcoderFps =
                    static_cast<int32_t>(kDefaultSrcFrameCount / seconds.count());
            EXPECT_EQ(atom.transcoderFps, transcoderFps);
        } else {
            EXPECT_EQ(atom.transcoderFps, -1);
        }
    }

    void TearDown() override { ALOGI("TranscodingLoggerTest tear down"); }
    ~TranscodingLoggerTest() { ALOGD("TranscodingLoggerTest destroyed"); }

    std::shared_ptr<TranscodingLogger> mLogger;
    std::vector<SessionEndedAtom> mLoggedAtoms;

    std::shared_ptr<AMediaFormat> mSrcFormat;
    std::shared_ptr<AMediaFormat> mDstFormat;
};

TEST_F(TranscodingLoggerTest, TestDailyLogQuota) {
    ALOGD("TestDailyLogQuota");
    auto start = std::chrono::steady_clock::now();

    EXPECT_LT(TranscodingLogger::kMaxSuccessfulAtomsPerDay, TranscodingLogger::kMaxAtomsPerDay);

    // 1. Check that the first kMaxSuccessfulAtomsPerDay successful atoms are logged.
    for (int i = 0; i < TranscodingLogger::kMaxSuccessfulAtomsPerDay; ++i) {
        logSessionFinished(start + std::chrono::seconds{i});
        EXPECT_EQ(logCount(), i + 1);
    }

    // 2. Check that subsequent successful atoms within the same 24h interval are not logged.
    for (int i = 1; i < 24; ++i) {
        logSessionFinished(start + std::chrono::hours{i});
        EXPECT_EQ(logCount(), TranscodingLogger::kMaxSuccessfulAtomsPerDay);
    }

    // 3. Check that failed atoms are logged up to kMaxAtomsPerDay.
    for (int i = TranscodingLogger::kMaxSuccessfulAtomsPerDay;
         i < TranscodingLogger::kMaxAtomsPerDay; ++i) {
        logSessionFailed(start + std::chrono::seconds{i});
        EXPECT_EQ(logCount(), i + 1);
    }

    // 4. Check that subsequent failed atoms within the same 24h interval are not logged.
    for (int i = 1; i < 24; ++i) {
        logSessionFailed(start + std::chrono::hours{i});
        EXPECT_EQ(logCount(), TranscodingLogger::kMaxAtomsPerDay);
    }

    // 5. Check that failed and successful atoms are logged again after 24h.
    logSessionFinished(start + std::chrono::hours{24});
    EXPECT_EQ(logCount(), TranscodingLogger::kMaxAtomsPerDay + 1);

    logSessionFailed(start + std::chrono::hours{24} + std::chrono::seconds{1});
    EXPECT_EQ(logCount(), TranscodingLogger::kMaxAtomsPerDay + 2);
}

TEST_F(TranscodingLoggerTest, TestNullFormats) {
    ALOGD("TestNullFormats");
    auto srcFormat = std::shared_ptr<AMediaFormat>(CreateSrcFormat(), &AMediaFormat_delete);
    auto dstFormat = std::shared_ptr<AMediaFormat>(CreateDstFormat(), &AMediaFormat_delete);
    auto now = std::chrono::steady_clock::now();

    // Source format null, should not log.
    logSession(now, Reason::FINISHED, AMEDIA_OK, nullptr /*srcFormat*/, dstFormat.get());
    EXPECT_EQ(logCount(), 0);

    // Both formats null, should not log.
    logSession(now, Reason::FINISHED, AMEDIA_OK, nullptr /*srcFormat*/, nullptr /*dstFormat*/);
    EXPECT_EQ(logCount(), 0);

    // Destination format null (passthrough mode), should log.
    logSession(now, Reason::FINISHED, AMEDIA_OK, srcFormat.get(), nullptr /*dstFormat*/);
    EXPECT_EQ(logCount(), 1);
    validateLatestAtom(Reason::FINISHED, AMEDIA_OK, true /*passthrough*/);
}

TEST_F(TranscodingLoggerTest, TestAtomContentCorrectness) {
    ALOGD("TestAtomContentCorrectness");
    auto now = std::chrono::steady_clock::now();

    // Log and validate a failure.
    logSession(now, Reason::ERROR, AMEDIA_ERROR_MALFORMED);
    EXPECT_EQ(logCount(), 1);
    validateLatestAtom(Reason::ERROR, AMEDIA_ERROR_MALFORMED);

    // Log and validate a success.
    logSession(now, Reason::FINISHED, AMEDIA_OK);
    EXPECT_EQ(logCount(), 2);
    validateLatestAtom(Reason::FINISHED, AMEDIA_OK);
}

}  // namespace android
