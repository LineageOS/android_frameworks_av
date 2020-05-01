/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <media/MediaTrackTranscoder.h>

#include <condition_variable>
#include <memory>
#include <mutex>

namespace android {

//
// This file contains test utilities used by more than one track transcoder test.
//

class TrackTranscoderTestUtils {
public:
    static std::shared_ptr<AMediaFormat> getDefaultVideoDestinationFormat(
            AMediaFormat* sourceFormat) {
        // Default video destination format setup.
        static constexpr float kFrameRate = 30.0f;
        static constexpr float kIFrameInterval = 30.0f;
        static constexpr int32_t kBitRate = 2 * 1000 * 1000;
        static constexpr int32_t kColorFormatSurface = 0x7f000789;

        AMediaFormat* destinationFormat = AMediaFormat_new();
        AMediaFormat_copy(destinationFormat, sourceFormat);
        AMediaFormat_setFloat(destinationFormat, AMEDIAFORMAT_KEY_FRAME_RATE, kFrameRate);
        AMediaFormat_setFloat(destinationFormat, AMEDIAFORMAT_KEY_I_FRAME_INTERVAL,
                              kIFrameInterval);
        AMediaFormat_setInt32(destinationFormat, AMEDIAFORMAT_KEY_BIT_RATE, kBitRate);
        AMediaFormat_setInt32(destinationFormat, AMEDIAFORMAT_KEY_COLOR_FORMAT,
                              kColorFormatSurface);

        return std::shared_ptr<AMediaFormat>(destinationFormat,
                                             std::bind(AMediaFormat_delete, std::placeholders::_1));
    }
};

class TestCallback : public MediaTrackTranscoderCallback {
public:
    TestCallback() = default;
    ~TestCallback() = default;

    // MediaTrackTranscoderCallback
    void onTrackFinished(MediaTrackTranscoder* transcoder __unused) {
        std::unique_lock<std::mutex> lock(mMutex);
        mTranscodingFinished = true;
        mCv.notify_all();
    }

    void onTrackError(MediaTrackTranscoder* transcoder __unused, media_status_t status) {
        std::unique_lock<std::mutex> lock(mMutex);
        mTranscodingFinished = true;
        mStatus = status;
        mCv.notify_all();
    }
    // ~MediaTrackTranscoderCallback

    media_status_t waitUntilFinished() {
        std::unique_lock<std::mutex> lock(mMutex);
        while (!mTranscodingFinished) {
            mCv.wait(lock);
        }
        return mStatus;
    }

private:
    media_status_t mStatus = AMEDIA_OK;
    std::mutex mMutex;
    std::condition_variable mCv;
    bool mTranscodingFinished = false;
};

};  // namespace android
