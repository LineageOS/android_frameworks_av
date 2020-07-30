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

// Unit Test for MediaSampleWriter

// #define LOG_NDEBUG 0
#define LOG_TAG "MediaSampleWriterTests"

#include <android-base/logging.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <media/MediaSampleQueue.h>
#include <media/MediaSampleWriter.h>
#include <media/NdkMediaExtractor.h>

#include <condition_variable>
#include <list>
#include <mutex>

namespace android {

/** Muxer interface to enable MediaSampleWriter testing. */
class TestMuxer : public MediaSampleWriterMuxerInterface {
public:
    // MuxerInterface
    ssize_t addTrack(AMediaFormat* trackFormat) override {
        mEventQueue.push_back(AddTrack(trackFormat));
        return mTrackCount++;
    }
    media_status_t start() override {
        mEventQueue.push_back(Start());
        return AMEDIA_OK;
    }

    media_status_t writeSampleData(size_t trackIndex, const uint8_t* data,
                                   const AMediaCodecBufferInfo* info) override {
        mEventQueue.push_back(WriteSample(trackIndex, data, info));
        return AMEDIA_OK;
    }
    media_status_t stop() override {
        mEventQueue.push_back(Stop());
        return AMEDIA_OK;
    }
    // ~MuxerInterface

    struct Event {
        enum { NoEvent, AddTrack, Start, WriteSample, Stop } type = NoEvent;
        const AMediaFormat* format = nullptr;
        size_t trackIndex = 0;
        const uint8_t* data = nullptr;
        AMediaCodecBufferInfo info{};
    };

    static constexpr Event NoEvent = {Event::NoEvent, nullptr, 0, nullptr, {}};

    static Event AddTrack(const AMediaFormat* format) {
        return {.type = Event::AddTrack, .format = format};
    }

    static Event Start() { return {.type = Event::Start}; }
    static Event Stop() { return {.type = Event::Stop}; }

    static Event WriteSample(size_t trackIndex, const uint8_t* data,
                             const AMediaCodecBufferInfo* info) {
        return {.type = Event::WriteSample, .trackIndex = trackIndex, .data = data, .info = *info};
    }

    const Event& popEvent() {
        if (mEventQueue.empty()) {
            mPoppedEvent = NoEvent;
        } else {
            mPoppedEvent = *mEventQueue.begin();
            mEventQueue.pop_front();
        }
        return mPoppedEvent;
    }

private:
    Event mPoppedEvent;
    std::list<Event> mEventQueue;
    ssize_t mTrackCount = 0;
};

bool operator==(const AMediaCodecBufferInfo& lhs, const AMediaCodecBufferInfo& rhs) {
    return lhs.offset == rhs.offset && lhs.size == rhs.size &&
           lhs.presentationTimeUs == rhs.presentationTimeUs && lhs.flags == rhs.flags;
}

bool operator==(const TestMuxer::Event& lhs, const TestMuxer::Event& rhs) {
    return lhs.type == rhs.type && lhs.format == rhs.format && lhs.trackIndex == rhs.trackIndex &&
           lhs.data == rhs.data && lhs.info == rhs.info;
}

/** Represents a media source file. */
class TestMediaSource {
public:
    void init() {
        static const char* sourcePath =
                "/data/local/tmp/TranscodingTestAssets/cubicle_avc_480x240_aac_24KHz.mp4";

        mExtractor = AMediaExtractor_new();
        ASSERT_NE(mExtractor, nullptr);

        int sourceFd = open(sourcePath, O_RDONLY);
        ASSERT_GT(sourceFd, 0);

        off_t fileSize = lseek(sourceFd, 0, SEEK_END);
        lseek(sourceFd, 0, SEEK_SET);

        media_status_t status = AMediaExtractor_setDataSourceFd(mExtractor, sourceFd, 0, fileSize);
        ASSERT_EQ(status, AMEDIA_OK);
        close(sourceFd);

        mTrackCount = AMediaExtractor_getTrackCount(mExtractor);
        ASSERT_GT(mTrackCount, 1);
        for (size_t trackIndex = 0; trackIndex < mTrackCount; trackIndex++) {
            AMediaFormat* trackFormat = AMediaExtractor_getTrackFormat(mExtractor, trackIndex);
            ASSERT_NE(trackFormat, nullptr);

            const char* mime = nullptr;
            AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &mime);
            if (strncmp(mime, "video/", 6) == 0) {
                mVideoTrackIndex = trackIndex;
            } else if (strncmp(mime, "audio/", 6) == 0) {
                mAudioTrackIndex = trackIndex;
            }

            mTrackFormats.push_back(
                    std::shared_ptr<AMediaFormat>(trackFormat, &AMediaFormat_delete));

            AMediaExtractor_selectTrack(mExtractor, trackIndex);
        }
        EXPECT_GE(mVideoTrackIndex, 0);
        EXPECT_GE(mAudioTrackIndex, 0);
    }

    void reset() const {
        media_status_t status = AMediaExtractor_seekTo(mExtractor, 0 /* seekPosUs */,
                                                       AMEDIAEXTRACTOR_SEEK_PREVIOUS_SYNC);
        ASSERT_EQ(status, AMEDIA_OK);
    }

    AMediaExtractor* mExtractor = nullptr;
    size_t mTrackCount = 0;
    std::vector<std::shared_ptr<AMediaFormat>> mTrackFormats;
    int mVideoTrackIndex = -1;
    int mAudioTrackIndex = -1;
};

class TestCallbacks : public MediaSampleWriter::CallbackInterface {
public:
    TestCallbacks(bool expectSuccess = true) : mExpectSuccess(expectSuccess) {}

    bool hasFinished() {
        std::unique_lock<std::mutex> lock(mMutex);
        return mFinished;
    }

    // MediaSampleWriter::CallbackInterface
    virtual void onFinished(const MediaSampleWriter* writer __unused,
                            media_status_t status) override {
        std::unique_lock<std::mutex> lock(mMutex);
        EXPECT_FALSE(mFinished);
        if (mExpectSuccess) {
            EXPECT_EQ(status, AMEDIA_OK);
        } else {
            EXPECT_NE(status, AMEDIA_OK);
        }
        mFinished = true;
        mCondition.notify_all();
    }

    virtual void onProgressUpdate(const MediaSampleWriter* writer __unused,
                                  int32_t progress) override {
        EXPECT_GT(progress, mLastProgress);
        EXPECT_GE(progress, 0);
        EXPECT_LE(progress, 100);

        mLastProgress = progress;
        mProgressUpdateCount++;
    }
    // ~MediaSampleWriter::CallbackInterface

    void waitForWritingFinished() {
        std::unique_lock<std::mutex> lock(mMutex);
        while (!mFinished) {
            mCondition.wait(lock);
        }
    }

    uint32_t getProgressUpdateCount() const { return mProgressUpdateCount; }

private:
    std::mutex mMutex;
    std::condition_variable mCondition;
    bool mFinished = false;
    bool mExpectSuccess;
    int32_t mLastProgress = -1;
    uint32_t mProgressUpdateCount = 0;
};

class MediaSampleWriterTests : public ::testing::Test {
public:
    MediaSampleWriterTests() { LOG(DEBUG) << "MediaSampleWriterTests created"; }
    ~MediaSampleWriterTests() { LOG(DEBUG) << "MediaSampleWriterTests destroyed"; }

    static const TestMediaSource& getMediaSource() {
        static TestMediaSource sMediaSource;
        static std::once_flag sOnceToken;

        std::call_once(sOnceToken, [] { sMediaSource.init(); });

        sMediaSource.reset();
        return sMediaSource;
    }

    static std::shared_ptr<MediaSample> newSample(int64_t ptsUs, uint32_t flags, size_t size,
                                                  size_t offset, const uint8_t* buffer) {
        auto sample = std::make_shared<MediaSample>();
        sample->info.presentationTimeUs = ptsUs;
        sample->info.flags = flags;
        sample->info.size = size;
        sample->dataOffset = offset;
        sample->buffer = buffer;
        return sample;
    }

    static std::shared_ptr<MediaSample> newSampleEos() {
        return newSample(0, SAMPLE_FLAG_END_OF_STREAM, 0, 0, nullptr);
    }

    static std::shared_ptr<MediaSample> newSampleWithPts(int64_t ptsUs) {
        static uint32_t sampleCount = 0;

        // Use sampleCount to get a unique mock sample.
        uint32_t sampleId = ++sampleCount;
        return newSample(ptsUs, 0, sampleId, sampleId, reinterpret_cast<const uint8_t*>(sampleId));
    }

    void SetUp() override {
        LOG(DEBUG) << "MediaSampleWriterTests set up";
        mTestMuxer = std::make_shared<TestMuxer>();
        mSampleQueue = std::make_shared<MediaSampleQueue>();
    }

    void TearDown() override {
        LOG(DEBUG) << "MediaSampleWriterTests tear down";
        mTestMuxer.reset();
        mSampleQueue.reset();
    }

protected:
    std::shared_ptr<TestMuxer> mTestMuxer;
    std::shared_ptr<MediaSampleQueue> mSampleQueue;
    std::shared_ptr<TestCallbacks> mTestCallbacks = std::make_shared<TestCallbacks>();
};

TEST_F(MediaSampleWriterTests, TestAddTrackWithoutInit) {
    const TestMediaSource& mediaSource = getMediaSource();

    MediaSampleWriter writer{};
    EXPECT_FALSE(writer.addTrack(mSampleQueue, mediaSource.mTrackFormats[0]));
}

TEST_F(MediaSampleWriterTests, TestStartWithoutInit) {
    MediaSampleWriter writer{};
    EXPECT_FALSE(writer.start());
}

TEST_F(MediaSampleWriterTests, TestStartWithoutTracks) {
    MediaSampleWriter writer{};
    EXPECT_TRUE(writer.init(mTestMuxer, mTestCallbacks));
    EXPECT_FALSE(writer.start());
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::NoEvent);
}

TEST_F(MediaSampleWriterTests, TestAddInvalidTrack) {
    MediaSampleWriter writer{};
    EXPECT_TRUE(writer.init(mTestMuxer, mTestCallbacks));

    EXPECT_FALSE(writer.addTrack(mSampleQueue, nullptr));
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::NoEvent);

    const TestMediaSource& mediaSource = getMediaSource();
    EXPECT_FALSE(writer.addTrack(nullptr, mediaSource.mTrackFormats[0]));
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::NoEvent);
}

TEST_F(MediaSampleWriterTests, TestDoubleStartStop) {
    MediaSampleWriter writer{};

    std::shared_ptr<TestCallbacks> callbacks =
            std::make_shared<TestCallbacks>(false /* expectSuccess */);
    EXPECT_TRUE(writer.init(mTestMuxer, callbacks));

    const TestMediaSource& mediaSource = getMediaSource();
    EXPECT_TRUE(writer.addTrack(mSampleQueue, mediaSource.mTrackFormats[0]));
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::AddTrack(mediaSource.mTrackFormats[0].get()));

    ASSERT_TRUE(writer.start());
    EXPECT_FALSE(writer.start());

    EXPECT_TRUE(writer.stop());
    EXPECT_TRUE(callbacks->hasFinished());
    EXPECT_FALSE(writer.stop());
}

TEST_F(MediaSampleWriterTests, TestStopWithoutStart) {
    MediaSampleWriter writer{};
    EXPECT_TRUE(writer.init(mTestMuxer, mTestCallbacks));

    const TestMediaSource& mediaSource = getMediaSource();
    EXPECT_TRUE(writer.addTrack(mSampleQueue, mediaSource.mTrackFormats[0]));
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::AddTrack(mediaSource.mTrackFormats[0].get()));

    EXPECT_FALSE(writer.stop());
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::NoEvent);
}

TEST_F(MediaSampleWriterTests, TestStartWithoutCallback) {
    MediaSampleWriter writer{};

    std::weak_ptr<MediaSampleWriter::CallbackInterface> unassignedWp;
    EXPECT_FALSE(writer.init(mTestMuxer, unassignedWp));

    std::shared_ptr<MediaSampleWriter::CallbackInterface> unassignedSp;
    EXPECT_FALSE(writer.init(mTestMuxer, unassignedSp));

    const TestMediaSource& mediaSource = getMediaSource();
    EXPECT_FALSE(writer.addTrack(mSampleQueue, mediaSource.mTrackFormats[0]));
    ASSERT_FALSE(writer.start());
}

TEST_F(MediaSampleWriterTests, TestProgressUpdate) {
    static constexpr uint32_t kSegmentLengthUs = 1;
    const TestMediaSource& mediaSource = getMediaSource();

    MediaSampleWriter writer{kSegmentLengthUs};
    EXPECT_TRUE(writer.init(mTestMuxer, mTestCallbacks));

    std::shared_ptr<AMediaFormat> videoFormat =
            std::shared_ptr<AMediaFormat>(AMediaFormat_new(), &AMediaFormat_delete);
    AMediaFormat_copy(videoFormat.get(),
                      mediaSource.mTrackFormats[mediaSource.mVideoTrackIndex].get());

    AMediaFormat_setInt64(videoFormat.get(), AMEDIAFORMAT_KEY_DURATION, 100);
    EXPECT_TRUE(writer.addTrack(mSampleQueue, videoFormat));
    ASSERT_TRUE(writer.start());

    for (int64_t pts = 0; pts < 100; ++pts) {
        mSampleQueue->enqueue(newSampleWithPts(pts));
    }
    mSampleQueue->enqueue(newSampleEos());
    mTestCallbacks->waitForWritingFinished();

    EXPECT_EQ(mTestCallbacks->getProgressUpdateCount(), 100);
}

TEST_F(MediaSampleWriterTests, TestInterleaving) {
    static constexpr uint32_t kSegmentLength = MediaSampleWriter::kDefaultTrackSegmentLengthUs;

    MediaSampleWriter writer{kSegmentLength};
    EXPECT_TRUE(writer.init(mTestMuxer, mTestCallbacks));

    // Use two tracks for this test.
    static constexpr int kNumTracks = 2;
    std::shared_ptr<MediaSampleQueue> sampleQueues[kNumTracks];
    std::vector<std::pair<std::shared_ptr<MediaSample>, size_t>> interleavedSamples;
    const TestMediaSource& mediaSource = getMediaSource();

    for (int trackIdx = 0; trackIdx < kNumTracks; ++trackIdx) {
        sampleQueues[trackIdx] = std::make_shared<MediaSampleQueue>();

        auto trackFormat = mediaSource.mTrackFormats[trackIdx % mediaSource.mTrackCount];
        EXPECT_TRUE(writer.addTrack(sampleQueues[trackIdx], trackFormat));
        EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::AddTrack(trackFormat.get()));
    }

    // Create samples in the expected interleaved order for easy verification.
    auto addSampleToTrackWithPts = [&interleavedSamples, &sampleQueues](int trackIndex,
                                                                        int64_t pts) {
        auto sample = newSampleWithPts(pts);
        sampleQueues[trackIndex]->enqueue(sample);
        interleavedSamples.emplace_back(sample, trackIndex);
    };

    addSampleToTrackWithPts(0, 0);
    addSampleToTrackWithPts(0, kSegmentLength / 2);
    addSampleToTrackWithPts(0, kSegmentLength);  // Track 0 reached 1st segment end

    addSampleToTrackWithPts(1, 0);
    addSampleToTrackWithPts(1, kSegmentLength);  // Track 1 reached 1st segment end

    addSampleToTrackWithPts(0, kSegmentLength * 2);  // Track 0 reached 2nd segment end

    addSampleToTrackWithPts(1, kSegmentLength + 1);
    addSampleToTrackWithPts(1, kSegmentLength * 2);  // Track 1 reached 2nd segment end

    addSampleToTrackWithPts(0, kSegmentLength * 2 + 1);

    for (int trackIndex = 0; trackIndex < kNumTracks; ++trackIndex) {
        sampleQueues[trackIndex]->enqueue(newSampleEos());
    }

    // Start the writer.
    ASSERT_TRUE(writer.start());

    // Wait for writer to complete.
    mTestCallbacks->waitForWritingFinished();
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::Start());

    // Verify sample order.
    for (auto entry : interleavedSamples) {
        auto sample = entry.first;
        auto trackIndex = entry.second;

        const TestMuxer::Event& event = mTestMuxer->popEvent();
        EXPECT_EQ(event.type, TestMuxer::Event::WriteSample);
        EXPECT_EQ(event.trackIndex, trackIndex);
        EXPECT_EQ(event.data, sample->buffer);
        EXPECT_EQ(event.info.offset, sample->dataOffset);
        EXPECT_EQ(event.info.size, sample->info.size);
        EXPECT_EQ(event.info.presentationTimeUs, sample->info.presentationTimeUs);
        EXPECT_EQ(event.info.flags, sample->info.flags);
    }

    // Verify EOS samples.
    for (int trackIndex = 0; trackIndex < kNumTracks; ++trackIndex) {
        auto trackFormat = mediaSource.mTrackFormats[trackIndex % mediaSource.mTrackCount];
        int64_t duration = 0;
        AMediaFormat_getInt64(trackFormat.get(), AMEDIAFORMAT_KEY_DURATION, &duration);

        const AMediaCodecBufferInfo info = {0, 0, duration, AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM};
        EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::WriteSample(trackIndex, nullptr, &info));
    }

    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::Stop());
    EXPECT_TRUE(writer.stop());
    EXPECT_TRUE(mTestCallbacks->hasFinished());
}

TEST_F(MediaSampleWriterTests, TestAbortInputQueue) {
    MediaSampleWriter writer{};
    std::shared_ptr<TestCallbacks> callbacks =
            std::make_shared<TestCallbacks>(false /* expectSuccess */);
    EXPECT_TRUE(writer.init(mTestMuxer, callbacks));

    // Use two tracks for this test.
    static constexpr int kNumTracks = 2;
    std::shared_ptr<MediaSampleQueue> sampleQueues[kNumTracks];
    const TestMediaSource& mediaSource = getMediaSource();

    for (int trackIdx = 0; trackIdx < kNumTracks; ++trackIdx) {
        sampleQueues[trackIdx] = std::make_shared<MediaSampleQueue>();

        auto trackFormat = mediaSource.mTrackFormats[trackIdx % mediaSource.mTrackCount];
        EXPECT_TRUE(writer.addTrack(sampleQueues[trackIdx], trackFormat));
        EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::AddTrack(trackFormat.get()));
    }

    // Start the writer.
    ASSERT_TRUE(writer.start());

    // Abort the input queues and wait for the writer to complete.
    for (int trackIdx = 0; trackIdx < kNumTracks; ++trackIdx) {
        sampleQueues[trackIdx]->abort();
    }

    callbacks->waitForWritingFinished();

    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::Start());
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::Stop());
    EXPECT_TRUE(writer.stop());
}

// Convenience function for reading a sample from an AMediaExtractor represented as a MediaSample.
static std::shared_ptr<MediaSample> readSampleAndAdvance(AMediaExtractor* extractor,
                                                         size_t* trackIndexOut) {
    int trackIndex = AMediaExtractor_getSampleTrackIndex(extractor);
    if (trackIndex < 0) {
        return nullptr;
    }

    if (trackIndexOut != nullptr) {
        *trackIndexOut = trackIndex;
    }

    ssize_t sampleSize = AMediaExtractor_getSampleSize(extractor);
    int64_t sampleTimeUs = AMediaExtractor_getSampleTime(extractor);
    uint32_t flags = AMediaExtractor_getSampleFlags(extractor);

    size_t bufferSize = static_cast<size_t>(sampleSize);
    uint8_t* buffer = new uint8_t[bufferSize];

    ssize_t dataRead = AMediaExtractor_readSampleData(extractor, buffer, bufferSize);
    EXPECT_EQ(dataRead, sampleSize);

    auto sample = MediaSample::createWithReleaseCallback(
            buffer, 0 /* offset */, 0 /* id */, [buffer](MediaSample*) { delete[] buffer; });
    sample->info.size = bufferSize;
    sample->info.presentationTimeUs = sampleTimeUs;
    sample->info.flags = flags;

    (void)AMediaExtractor_advance(extractor);
    return sample;
}

TEST_F(MediaSampleWriterTests, TestDefaultMuxer) {
    // Write samples straight from an extractor and validate output file.
    static const char* destinationPath =
            "/data/local/tmp/MediaSampleWriterTests_TestDefaultMuxer_output.MP4";
    const int destinationFd =
            open(destinationPath, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IROTH);
    ASSERT_GT(destinationFd, 0);

    // Initialize writer.
    MediaSampleWriter writer{};
    EXPECT_TRUE(writer.init(destinationFd, mTestCallbacks));
    close(destinationFd);

    // Add tracks.
    const TestMediaSource& mediaSource = getMediaSource();
    std::vector<std::shared_ptr<MediaSampleQueue>> inputQueues;

    for (size_t trackIndex = 0; trackIndex < mediaSource.mTrackCount; trackIndex++) {
        inputQueues.push_back(std::make_shared<MediaSampleQueue>());
        EXPECT_TRUE(
                writer.addTrack(inputQueues[trackIndex], mediaSource.mTrackFormats[trackIndex]));
    }

    // Start the writer.
    ASSERT_TRUE(writer.start());

    // Enqueue samples and finally End Of Stream.
    std::shared_ptr<MediaSample> sample;
    size_t trackIndex;
    while ((sample = readSampleAndAdvance(mediaSource.mExtractor, &trackIndex)) != nullptr) {
        inputQueues[trackIndex]->enqueue(sample);
    }
    for (trackIndex = 0; trackIndex < mediaSource.mTrackCount; trackIndex++) {
        inputQueues[trackIndex]->enqueue(newSampleEos());
    }

    // Wait for writer.
    mTestCallbacks->waitForWritingFinished();
    EXPECT_TRUE(writer.stop());

    // Compare output file with source.
    mediaSource.reset();

    AMediaExtractor* extractor = AMediaExtractor_new();
    ASSERT_NE(extractor, nullptr);

    int sourceFd = open(destinationPath, O_RDONLY);
    ASSERT_GT(sourceFd, 0);

    off_t fileSize = lseek(sourceFd, 0, SEEK_END);
    lseek(sourceFd, 0, SEEK_SET);

    media_status_t status = AMediaExtractor_setDataSourceFd(extractor, sourceFd, 0, fileSize);
    ASSERT_EQ(status, AMEDIA_OK);
    close(sourceFd);

    size_t trackCount = AMediaExtractor_getTrackCount(extractor);
    EXPECT_EQ(trackCount, mediaSource.mTrackCount);

    for (size_t trackIndex = 0; trackIndex < trackCount; trackIndex++) {
        AMediaFormat* trackFormat = AMediaExtractor_getTrackFormat(extractor, trackIndex);
        ASSERT_NE(trackFormat, nullptr);

        AMediaExtractor_selectTrack(extractor, trackIndex);
    }

    // Compare samples.
    std::shared_ptr<MediaSample> sample1 = readSampleAndAdvance(mediaSource.mExtractor, nullptr);
    std::shared_ptr<MediaSample> sample2 = readSampleAndAdvance(extractor, nullptr);

    while (sample1 != nullptr && sample2 != nullptr) {
        EXPECT_EQ(sample1->info.presentationTimeUs, sample2->info.presentationTimeUs);
        EXPECT_EQ(sample1->info.size, sample2->info.size);
        EXPECT_EQ(sample1->info.flags, sample2->info.flags);

        EXPECT_EQ(memcmp(sample1->buffer, sample2->buffer, sample1->info.size), 0);

        sample1 = readSampleAndAdvance(mediaSource.mExtractor, nullptr);
        sample2 = readSampleAndAdvance(extractor, nullptr);
    }
    EXPECT_EQ(sample1, nullptr);
    EXPECT_EQ(sample2, nullptr);

    AMediaExtractor_delete(extractor);
}

}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
