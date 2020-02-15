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

//#define LOG_NDEBUG 0
#define LOG_TAG "WebmFrameThreadUnitTest"
#include <utils/Log.h>

#include <gtest/gtest.h>

#include <media/stagefright/MediaAdapter.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/Utils.h>

#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/AMessage.h>
#include <media/stagefright/foundation/OpusHeader.h>

#include "webm/EbmlUtil.h"
#include "webm/WebmConstants.h"
#include "webm/WebmFrameThread.h"

using namespace android;
using namespace webm;

static constexpr int32_t kVideoIdx = 0;
static constexpr int32_t kAudioIdx = 1;
static constexpr int32_t kMaxStreamCount = 2;

static constexpr int32_t kCsdSize = 32;
static constexpr int32_t kFrameSize = 128;

static constexpr int32_t kMaxLoopCount = 20;
static constexpr int32_t kNumFramesToWrite = 32;
static constexpr int32_t kSyncFrameInterval = 10;
static constexpr uint64_t kDefaultTimeCodeScaleUs = 1000000; /* 1sec */

#define OUTPUT_FILE_NAME "/data/local/tmp/webmFrameThreadOutput.webm"

// LookUpTable of clips and metadata for component testing
static const struct InputData {
    const char *mime;
    int32_t firstParam;
    int32_t secondParam;
    bool isAudio;
} kInputData[] = {
        {MEDIA_MIMETYPE_AUDIO_OPUS, 48000, 6, true},
        {MEDIA_MIMETYPE_AUDIO_VORBIS, 44100, 1, true},
        {MEDIA_MIMETYPE_VIDEO_VP9, 176, 144, false},
        {MEDIA_MIMETYPE_VIDEO_VP8, 1920, 1080, false},
};

class WebmFrameThreadUnitTest : public ::testing::TestWithParam<std::pair<int32_t, int32_t>> {
  public:
    WebmFrameThreadUnitTest()
        : mSinkThread(nullptr), mAudioThread(nullptr), mVideoThread(nullptr), mSource{} {}

    ~WebmFrameThreadUnitTest() {
        if (mSinkThread) mSinkThread.clear();
        if (mAudioThread) mAudioThread.clear();
        if (mVideoThread) mVideoThread.clear();
    }

    virtual void SetUp() override {
        mSegmentDataStart = 0;
        mFd = open(OUTPUT_FILE_NAME, O_CREAT | O_LARGEFILE | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
        ASSERT_GE(mFd, 0) << "Failed to open output file " << OUTPUT_FILE_NAME;
    }

    virtual void TearDown() override {
        if (mFd >= 0) close(mFd);
        for (int32_t idx = 0; idx < kMaxStreamCount; idx++) {
            if (mSource[idx] != nullptr) {
                mSource[idx].clear();
            }
        }
        mVSink.clear();
        mASink.clear();
        mCuePoints.clear();
    }

    void addTrack(bool isAudio, int32_t index);
    void writeFileData(int32_t inputFrameId, int32_t range);

    void createWebmThreads(std::initializer_list<int32_t> indexList);
    void startWebmFrameThreads();
    void stopWebmFrameThreads();

    int32_t mFd;
    uint64_t mSegmentDataStart;

    sp<WebmFrameSinkThread> mSinkThread;
    sp<WebmFrameSourceThread> mAudioThread;
    sp<WebmFrameSourceThread> mVideoThread;

    List<sp<WebmElement>> mCuePoints;
    sp<MediaAdapter> mSource[kMaxStreamCount];
    LinkedBlockingQueue<const sp<WebmFrame>> mVSink;
    LinkedBlockingQueue<const sp<WebmFrame>> mASink;
};

void writeAudioHeaderData(const sp<AMessage> &format, const char *mimeType) {
    if (strncasecmp(mimeType, MEDIA_MIMETYPE_AUDIO_OPUS, strlen(MEDIA_MIMETYPE_AUDIO_OPUS) + 1) &&
        strncasecmp(mimeType, MEDIA_MIMETYPE_AUDIO_VORBIS,
                    strlen(MEDIA_MIMETYPE_AUDIO_VORBIS) + 1)) {
        ASSERT_TRUE(false) << "Unsupported mime type";
    }

    // Dummy CSD buffers for Opus and Vorbis
    char csdBuffer[kCsdSize];
    memset(csdBuffer, 0xFF, sizeof(csdBuffer));

    sp<ABuffer> csdBuffer0 = ABuffer::CreateAsCopy((void *)csdBuffer, kCsdSize);
    ASSERT_NE(csdBuffer0.get(), nullptr) << "Unable to allocate buffer for CSD0 data";
    ASSERT_NE(csdBuffer0->base(), nullptr) << "ABuffer base is null for CSD0";

    sp<ABuffer> csdBuffer1 = ABuffer::CreateAsCopy((void *)csdBuffer, kCsdSize);
    ASSERT_NE(csdBuffer1.get(), nullptr) << "Unable to allocate buffer for CSD1 data";
    ASSERT_NE(csdBuffer1->base(), nullptr) << "ABuffer base is null for CSD1";

    sp<ABuffer> csdBuffer2 = ABuffer::CreateAsCopy((void *)csdBuffer, kCsdSize);
    ASSERT_NE(csdBuffer2.get(), nullptr) << "Unable to allocate buffer for CSD2 data";
    ASSERT_NE(csdBuffer2->base(), nullptr) << "ABuffer base is null for CSD2";

    format->setBuffer("csd-0", csdBuffer0);
    format->setBuffer("csd-1", csdBuffer1);
    format->setBuffer("csd-2", csdBuffer2);
}

void WebmFrameThreadUnitTest::addTrack(bool isAudio, int32_t index) {
    ASSERT_LT(index, sizeof(kInputData) / sizeof(kInputData[0]))
            << "Invalid index for loopup table";

    sp<AMessage> format = new AMessage;
    format->setString("mime", kInputData[index].mime);
    if (!isAudio) {
        format->setInt32("width", kInputData[index].firstParam);
        format->setInt32("height", kInputData[index].secondParam);
    } else {
        format->setInt32("sample-rate", kInputData[index].firstParam);
        format->setInt32("channel-count", kInputData[index].secondParam);
        ASSERT_NO_FATAL_FAILURE(writeAudioHeaderData(format, kInputData[index].mime));
    }

    sp<MetaData> trackMeta = new MetaData;
    convertMessageToMetaData(format, trackMeta);

    if (!isAudio) {
        mSource[kVideoIdx] = new MediaAdapter(trackMeta);
        ASSERT_NE(mSource[kVideoIdx], nullptr) << "Unable to create source";
    } else {
        mSource[kAudioIdx] = new MediaAdapter(trackMeta);
        ASSERT_NE(mSource[kAudioIdx], nullptr) << "Unable to create source";
    }
}

void WebmFrameThreadUnitTest::createWebmThreads(std::initializer_list<int32_t> indexList) {
    mSinkThread = new WebmFrameSinkThread(mFd, mSegmentDataStart, mVSink, mASink, mCuePoints);
    ASSERT_NE(mSinkThread, nullptr) << "Failed to create Sink Thread";

    bool isAudio;
    // MultiTrack input
    for (int32_t index : indexList) {
        isAudio = kInputData[index].isAudio;
        ASSERT_NO_FATAL_FAILURE(addTrack(isAudio, index));
        if (!isAudio) {
            mVideoThread = new WebmFrameMediaSourceThread(mSource[kVideoIdx], kVideoType, mVSink,
                                                          kDefaultTimeCodeScaleUs, 0, 0, 1, 0);
        } else {
            mAudioThread = new WebmFrameMediaSourceThread(mSource[kAudioIdx], kAudioType, mASink,
                                                          kDefaultTimeCodeScaleUs, 0, 0, 1, 0);
        }
    }
    // To handle single track file
    if (!mVideoThread) {
        mVideoThread = new WebmFrameEmptySourceThread(kVideoType, mVSink);
    } else if (!mAudioThread) {
        mAudioThread = new WebmFrameEmptySourceThread(kAudioType, mASink);
    }
    ASSERT_NE(mVideoThread, nullptr) << "Failed to create Video Thread";
    ASSERT_NE(mAudioThread, nullptr) << "Failed to create Audio Thread";
}

void WebmFrameThreadUnitTest::startWebmFrameThreads() {
    status_t status = mAudioThread->start();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to start Audio Thread";
    status = mVideoThread->start();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to start Video Thread";
    status = mSinkThread->start();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to start Sink Thread";
}

void WebmFrameThreadUnitTest::stopWebmFrameThreads() {
    status_t status = mAudioThread->stop();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to stop Audio Thread";
    status = mVideoThread->stop();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to stop Video Thread";
    status = mSinkThread->stop();
    ASSERT_EQ(status, AMEDIA_OK) << "Failed to stop Sink Thread";
}

// Write dummy data to a file
void WebmFrameThreadUnitTest::writeFileData(int32_t inputFrameId, int32_t range) {
    char data[kFrameSize];
    memset(data, 0xFF, sizeof(data));
    int32_t status = OK;
    do {
        // Queue frames for both A/V tracks
        for (int32_t idx = kVideoIdx; idx < kMaxStreamCount; idx++) {
            sp<ABuffer> buffer = new ABuffer((void *)data, kFrameSize);
            ASSERT_NE(buffer.get(), nullptr) << "ABuffer returned nullptr";

            // Released in MediaAdapter::signalBufferReturned().
            MediaBuffer *mediaBuffer = new MediaBuffer(buffer);
            ASSERT_NE(mediaBuffer, nullptr) << "MediaBuffer returned nullptr";

            mediaBuffer->add_ref();
            mediaBuffer->set_range(buffer->offset(), buffer->size());

            MetaDataBase &sampleMetaData = mediaBuffer->meta_data();
            sampleMetaData.setInt64(kKeyTime, inputFrameId * kDefaultTimeCodeScaleUs);

            // For audio codecs, treat all frame as sync frame
            if ((idx == kAudioIdx) || (inputFrameId % kSyncFrameInterval == 0)) {
                sampleMetaData.setInt32(kKeyIsSyncFrame, true);
            }

            // This pushBuffer will wait until the mediaBuffer is consumed.
            if (mSource[idx] != nullptr) {
                status = mSource[idx]->pushBuffer(mediaBuffer);
            }
            ASSERT_EQ(status, OK);
        }
        inputFrameId++;
    } while (inputFrameId < range);
}

TEST_P(WebmFrameThreadUnitTest, WriteTest) {
    int32_t index1 = GetParam().first;
    int32_t index2 = GetParam().second;
    ASSERT_NO_FATAL_FAILURE(createWebmThreads({index1, index2}));

    ASSERT_NO_FATAL_FAILURE(startWebmFrameThreads());

    ASSERT_NO_FATAL_FAILURE(writeFileData(0, kNumFramesToWrite));

    if (mSource[kAudioIdx]) mSource[kAudioIdx]->stop();
    if (mSource[kVideoIdx]) mSource[kVideoIdx]->stop();

    ASSERT_NO_FATAL_FAILURE(stopWebmFrameThreads());
}

TEST_P(WebmFrameThreadUnitTest, PauseTest) {
    int32_t index1 = GetParam().first;
    int32_t index2 = GetParam().second;
    ASSERT_NO_FATAL_FAILURE(createWebmThreads({index1, index2}));

    ASSERT_NO_FATAL_FAILURE(startWebmFrameThreads());

    int32_t offset = 0;
    ASSERT_NO_FATAL_FAILURE(writeFileData(offset, kNumFramesToWrite));
    offset += kNumFramesToWrite;

    for (int idx = 0; idx < kMaxLoopCount; idx++) {
        // pause the threads
        status_t status = mAudioThread->pause();
        ASSERT_EQ(status, AMEDIA_OK) << "Failed to pause Audio Thread";
        status = mVideoThread->pause();
        ASSERT_EQ(status, AMEDIA_OK) << "Failed to pause Video Thread";

        // Under pause state, no write should happen
        ASSERT_NO_FATAL_FAILURE(writeFileData(offset, kNumFramesToWrite));
        offset += kNumFramesToWrite;

        status = mAudioThread->resume();
        ASSERT_EQ(status, AMEDIA_OK) << "Failed to resume Audio Thread";
        status = mVideoThread->resume();
        ASSERT_EQ(status, AMEDIA_OK) << "Failed to resume Video Thread";

        ASSERT_NO_FATAL_FAILURE(writeFileData(offset, kNumFramesToWrite));
        offset += kNumFramesToWrite;
    }

    if (mSource[kAudioIdx]) mSource[kAudioIdx]->stop();
    if (mSource[kVideoIdx]) mSource[kVideoIdx]->stop();
    ASSERT_NO_FATAL_FAILURE(stopWebmFrameThreads());
}

INSTANTIATE_TEST_SUITE_P(WebmFrameThreadUnitTestAll, WebmFrameThreadUnitTest,
                         ::testing::Values(std::make_pair(0, 1), std::make_pair(0, 2),
                                           std::make_pair(0, 3), std::make_pair(1, 0),
                                           std::make_pair(1, 2), std::make_pair(1, 3),
                                           std::make_pair(2, 3)));

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    int status = RUN_ALL_TESTS();
    ALOGV("Test result = %d\n", status);
    return status;
}
