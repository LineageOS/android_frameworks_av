/******************************************************************************
 *
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *****************************************************************************
 * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */
#include <C2Config.h>
#include <android/binder_process.h>
#include <fcntl.h>
#include <media/MediaTranscoder.h>
#include <media/NdkCommon.h>
#include <stdio.h>

#define UNUSED_PARAM __attribute__((unused))
#define SRC_FILE "sourceTranscodingFile"
#define DEST_FILE "destTranscodingFile"

using namespace std;
using namespace android;

const char* kMimeType[] = {AMEDIA_MIMETYPE_VIDEO_AVC, AMEDIA_MIMETYPE_VIDEO_HEVC};
const C2Config::profile_t kAvcProfile[] = {C2Config::PROFILE_AVC_BASELINE,
                                           C2Config::PROFILE_AVC_CONSTRAINED_BASELINE,
                                           C2Config::PROFILE_AVC_MAIN};
const C2Config::level_t kAvcLevel[] = {
        C2Config::LEVEL_AVC_1,   C2Config::LEVEL_AVC_1B,  C2Config::LEVEL_AVC_1_1,
        C2Config::LEVEL_AVC_1_2, C2Config::LEVEL_AVC_1_3, C2Config::LEVEL_AVC_2,
        C2Config::LEVEL_AVC_2_1, C2Config::LEVEL_AVC_2_2, C2Config::LEVEL_AVC_3,
        C2Config::LEVEL_AVC_3_1, C2Config::LEVEL_AVC_3_2, C2Config::LEVEL_AVC_4,
        C2Config::LEVEL_AVC_4_1, C2Config::LEVEL_AVC_4_2, C2Config::LEVEL_AVC_5,
};
const C2Config::profile_t kHevcProfile[] = {C2Config::PROFILE_HEVC_MAIN,
                                            C2Config::PROFILE_HEVC_MAIN_STILL};
const C2Config::level_t kHevcLevel[] = {
        C2Config::LEVEL_HEVC_MAIN_1,   C2Config::LEVEL_HEVC_MAIN_2,   C2Config::LEVEL_HEVC_MAIN_2_1,
        C2Config::LEVEL_HEVC_MAIN_3,   C2Config::LEVEL_HEVC_MAIN_3_1, C2Config::LEVEL_HEVC_MAIN_4,
        C2Config::LEVEL_HEVC_MAIN_4_1, C2Config::LEVEL_HEVC_MAIN_5,   C2Config::LEVEL_HEVC_MAIN_5_1,
        C2Config::LEVEL_HEVC_MAIN_5_2};
const size_t kNumAvcProfile = size(kAvcProfile);
const size_t kNumAvcLevel = size(kAvcLevel);
const size_t kNumHevcProfile = size(kHevcProfile);
const size_t kNumHevcLevel = size(kHevcLevel);
const size_t kMaxBitrate = 500000000;

enum {
    IDX_MIME_TYPE = 0,
    IDX_PROFILE,
    IDX_LEVEL,
    IDX_BITRATE_BYTE_1,
    IDX_BITRATE_BYTE_2,
    IDX_LAST
};

class TestCallbacks : public MediaTranscoder::CallbackInterface {
public:
    virtual void onFinished(const MediaTranscoder* transcoder UNUSED_PARAM) override {
        unique_lock<mutex> lock(mMutex);
        mFinished = true;
        mCondition.notify_all();
    }

    virtual void onError(const MediaTranscoder* transcoder UNUSED_PARAM,
                         media_status_t error UNUSED_PARAM) override {
        unique_lock<mutex> lock(mMutex);
        mFinished = true;
        mCondition.notify_all();
    }

    virtual void onProgressUpdate(const MediaTranscoder* transcoder UNUSED_PARAM,
                                  int32_t progress) override {
        unique_lock<mutex> lock(mMutex);
        if (progress > 0 && !mProgressMade) {
            mProgressMade = true;
            mCondition.notify_all();
        }
    }

    virtual void onHeartBeat(const MediaTranscoder* transcoder UNUSED_PARAM) override {}

    virtual void onCodecResourceLost(const MediaTranscoder* transcoder UNUSED_PARAM,
                                     const shared_ptr<ndk::ScopedAParcel>& pausedState
                                             UNUSED_PARAM) override {}

    void waitForTranscodingFinished() {
        unique_lock<mutex> lock(mMutex);
        while (!mFinished) {
            mCondition.wait(lock);
        }
    }

private:
    mutex mMutex;
    condition_variable mCondition;
    bool mFinished = false;
    bool mProgressMade = false;
};

class MediaTranscoderFuzzer {
public:
    void init();
    void invokeTranscoder(const uint8_t* data, size_t size);
    void deInit();

private:
    AMediaFormat* getFormat(AMediaFormat* sourceFormat) {
        AMediaFormat* format = nullptr;
        const char* mime = nullptr;
        AMediaFormat_getString(sourceFormat, AMEDIAFORMAT_KEY_MIME, &mime);
        if (mime != nullptr) {
            if (strncmp(mime, "video/", 6) == 0 && (mDestMime != nullptr)) {
                format = AMediaFormat_new();
                AMediaFormat_setString(format, AMEDIAFORMAT_KEY_MIME, mDestMime);
                AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_PROFILE, mProfile);
                AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_LEVEL, mLevel);
                AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_BIT_RATE, mBitrate);
                AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_OPERATING_RATE, INT32_MAX);
                AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_PRIORITY, 1);
            }
        }
        return format;
    }

    shared_ptr<TestCallbacks> mCallbacks;
    int mSrcFd = 0;
    int mDestFd = 0;
    const char* mDestMime;
    C2Config::profile_t mProfile;
    C2Config::level_t mLevel;
    uint64_t mBitrate = 0;
};

void MediaTranscoderFuzzer::init() {
    mCallbacks = make_shared<TestCallbacks>();
    ABinderProcess_startThreadPool();
}

void MediaTranscoderFuzzer::deInit() {
    mCallbacks.reset();
    if (mSrcFd) {
        close(mSrcFd);
    }
    if (mDestFd) {
        close(mDestFd);
    }
}

void MediaTranscoderFuzzer::invokeTranscoder(const uint8_t* data, size_t size) {
    auto transcoder = MediaTranscoder::create(mCallbacks);
    if (transcoder == nullptr) {
        return;
    }

    mDestMime = kMimeType[data[IDX_MIME_TYPE] & 0x01];
    mBitrate = (((data[IDX_BITRATE_BYTE_1] << 8) | data[IDX_BITRATE_BYTE_2]) * 1000) % kMaxBitrate;
    if (mDestMime == AMEDIA_MIMETYPE_VIDEO_AVC) {
        mProfile = kAvcProfile[data[IDX_PROFILE] % kNumAvcProfile];
        mLevel = kAvcLevel[data[IDX_LEVEL] % kNumAvcLevel];
    } else {
        mProfile = kHevcProfile[data[IDX_PROFILE] % kNumHevcProfile];
        mLevel = kHevcLevel[data[IDX_LEVEL] % kNumHevcLevel];
    }

    data += IDX_LAST;
    size -= IDX_LAST;

    mSrcFd = memfd_create(SRC_FILE, MFD_ALLOW_SEALING);
    write(mSrcFd, data, size);

    transcoder->configureSource(mSrcFd);
    vector<shared_ptr<AMediaFormat>> trackFormats = transcoder->getTrackFormats();
    for (int i = 0; i < trackFormats.size(); ++i) {
        AMediaFormat* format = getFormat(trackFormats[i].get());
        transcoder->configureTrackFormat(i, format);

        if (format != nullptr) {
            AMediaFormat_delete(format);
        }
    }
    mDestFd = memfd_create(DEST_FILE, MFD_ALLOW_SEALING);
    transcoder->configureDestination(mDestFd);
    if (transcoder->start() == AMEDIA_OK) {
        mCallbacks->waitForTranscodingFinished();
        transcoder->cancel();
    }
    close(mSrcFd);
    close(mDestFd);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < IDX_LAST + 1) {
        return 0;
    }
    MediaTranscoderFuzzer transcoderFuzzer;
    transcoderFuzzer.init();
    transcoderFuzzer.invokeTranscoder(data, size);
    transcoderFuzzer.deInit();
    return 0;
}
