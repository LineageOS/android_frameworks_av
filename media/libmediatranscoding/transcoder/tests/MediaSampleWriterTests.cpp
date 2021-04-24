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

    static Event WriteSampleWithPts(size_t trackIndex, int64_t pts) {
        return {.type = Event::WriteSample, .trackIndex = trackIndex, .info = {0, 0, pts, 0}};
    }

    void pushEvent(const Event& e) {
        std::unique_lock<std::mutex> lock(mMutex);
        mEventQueue.push_back(e);
        mCondition.notify_one();
    }

    const Event& popEvent(bool wait = false) {
        std::unique_lock<std::mutex> lock(mMutex);
        while (wait && mEventQueue.empty()) {
            mCondition.wait_for(lock, std::chrono::milliseconds(200));
        }

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
    std::mutex mMutex;
    std::condition_variable mCondition;
};

bool operator==(const AMediaCodecBufferInfo& lhs, const AMediaCodecBufferInfo& rhs) {
    return lhs.offset == rhs.offset && lhs.size == rhs.size &&
           lhs.presentationTimeUs == rhs.presentationTimeUs && lhs.flags == rhs.flags;
}

bool operator==(const TestMuxer::Event& lhs, const TestMuxer::Event& rhs) {
    // Don't test format pointer equality since the writer can make a copy.
    return lhs.type == rhs.type /*&& lhs.format == rhs.format*/ &&
           lhs.trackIndex == rhs.trackIndex && lhs.data == rhs.data && lhs.info == rhs.info;
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
    bool hasFinished() {
        std::unique_lock<std::mutex> lock(mMutex);
        return mFinished;
    }

    // MediaSampleWriter::CallbackInterface
    virtual void onFinished(const MediaSampleWriter* writer __unused,
                            media_status_t status) override {
        std::unique_lock<std::mutex> lock(mMutex);
        EXPECT_FALSE(mFinished);
        mFinished = true;
        mStatus = status;
        mCondition.notify_all();
    }

    virtual void onStopped(const MediaSampleWriter* writer __unused) {
        std::unique_lock<std::mutex> lock(mMutex);
        EXPECT_FALSE(mFinished);
        mStopped = true;
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

    virtual void onHeartBeat(const MediaSampleWriter* writer __unused) override {}
    // ~MediaSampleWriter::CallbackInterface

    void waitForWritingFinished() {
        std::unique_lock<std::mutex> lock(mMutex);
        while (!mFinished && !mStopped) {
            mCondition.wait(lock);
        }
    }

    uint32_t getProgressUpdateCount() const { return mProgressUpdateCount; }
    bool wasStopped() const { return mStopped; }

private:
    std::mutex mMutex;
    std::condition_variable mCondition;
    bool mFinished = false;
    bool mStopped = false;
    media_status_t mStatus = AMEDIA_OK;
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

    static std::shared_ptr<MediaSample> newSampleWithPtsOnly(int64_t ptsUs) {
        return newSample(ptsUs, 0, 0, 0, nullptr);
    }

    void SetUp() override {
        LOG(DEBUG) << "MediaSampleWriterTests set up";
        mTestMuxer = std::make_shared<TestMuxer>();
    }

    void TearDown() override {
        LOG(DEBUG) << "MediaSampleWriterTests tear down";
        mTestMuxer.reset();
    }

protected:
    std::shared_ptr<TestMuxer> mTestMuxer;
    std::shared_ptr<TestCallbacks> mTestCallbacks = std::make_shared<TestCallbacks>();
};

TEST_F(MediaSampleWriterTests, TestAddTrackWithoutInit) {
    const TestMediaSource& mediaSource = getMediaSource();

    std::shared_ptr<MediaSampleWriter> writer = MediaSampleWriter::Create();
    EXPECT_EQ(writer->addTrack(mediaSource.mTrackFormats[0]), nullptr);
}

TEST_F(MediaSampleWriterTests, TestStartWithoutInit) {
    std::shared_ptr<MediaSampleWriter> writer = MediaSampleWriter::Create();
    EXPECT_FALSE(writer->start());
}

TEST_F(MediaSampleWriterTests, TestStartWithoutTracks) {
    std::shared_ptr<MediaSampleWriter> writer = MediaSampleWriter::Create();
    EXPECT_TRUE(writer->init(mTestMuxer, mTestCallbacks));
    EXPECT_FALSE(writer->start());
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::NoEvent);
}

TEST_F(MediaSampleWriterTests, TestAddInvalidTrack) {
    std::shared_ptr<MediaSampleWriter> writer = MediaSampleWriter::Create();
    EXPECT_TRUE(writer->init(mTestMuxer, mTestCallbacks));

    EXPECT_EQ(writer->addTrack(nullptr), nullptr);
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::NoEvent);
}

TEST_F(MediaSampleWriterTests, TestDoubleStartStop) {
    std::shared_ptr<MediaSampleWriter> writer = MediaSampleWriter::Create();

    std::shared_ptr<TestCallbacks> callbacks = std::make_shared<TestCallbacks>();
    EXPECT_TRUE(writer->init(mTestMuxer, callbacks));

    const TestMediaSource& mediaSource = getMediaSource();
    EXPECT_NE(writer->addTrack(mediaSource.mTrackFormats[0]), nullptr);
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::AddTrack(mediaSource.mTrackFormats[0].get()));

    ASSERT_TRUE(writer->start());
    EXPECT_FALSE(writer->start());

    writer->stop();
    writer->stop();
    callbacks->waitForWritingFinished();
    EXPECT_TRUE(callbacks->wasStopped());
}

TEST_F(MediaSampleWriterTests, TestStopWithoutStart) {
    std::shared_ptr<MediaSampleWriter> writer = MediaSampleWriter::Create();
    EXPECT_TRUE(writer->init(mTestMuxer, mTestCallbacks));

    const TestMediaSource& mediaSource = getMediaSource();
    EXPECT_NE(writer->addTrack(mediaSource.mTrackFormats[0]), nullptr);
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::AddTrack(mediaSource.mTrackFormats[0].get()));

    writer->stop();
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::NoEvent);
}

TEST_F(MediaSampleWriterTests, TestStartWithoutCallback) {
    std::shared_ptr<MediaSampleWriter> writer = MediaSampleWriter::Create();

    std::weak_ptr<MediaSampleWriter::CallbackInterface> unassignedWp;
    EXPECT_FALSE(writer->init(mTestMuxer, unassignedWp));

    std::shared_ptr<MediaSampleWriter::CallbackInterface> unassignedSp;
    EXPECT_FALSE(writer->init(mTestMuxer, unassignedSp));

    const TestMediaSource& mediaSource = getMediaSource();
    EXPECT_EQ(writer->addTrack(mediaSource.mTrackFormats[0]), nullptr);
    ASSERT_FALSE(writer->start());
}

TEST_F(MediaSampleWriterTests, TestProgressUpdate) {
    const TestMediaSource& mediaSource = getMediaSource();

    std::shared_ptr<MediaSampleWriter> writer = MediaSampleWriter::Create();
    EXPECT_TRUE(writer->init(mTestMuxer, mTestCallbacks));

    std::shared_ptr<AMediaFormat> videoFormat =
            std::shared_ptr<AMediaFormat>(AMediaFormat_new(), &AMediaFormat_delete);
    AMediaFormat_copy(videoFormat.get(),
                      mediaSource.mTrackFormats[mediaSource.mVideoTrackIndex].get());

    AMediaFormat_setInt64(videoFormat.get(), AMEDIAFORMAT_KEY_DURATION, 100);
    auto sampleConsumer = writer->addTrack(videoFormat);
    EXPECT_NE(sampleConsumer, nullptr);
    ASSERT_TRUE(writer->start());

    for (int64_t pts = 0; pts < 100; ++pts) {
        sampleConsumer(newSampleWithPts(pts));
    }
    sampleConsumer(newSampleEos());
    mTestCallbacks->waitForWritingFinished();

    EXPECT_EQ(mTestCallbacks->getProgressUpdateCount(), 100);
}

TEST_F(MediaSampleWriterTests, TestInterleaving) {
    std::shared_ptr<MediaSampleWriter> writer = MediaSampleWriter::Create();
    EXPECT_TRUE(writer->init(mTestMuxer, mTestCallbacks));

    // Use two tracks for this test.
    static constexpr int kNumTracks = 2;
    MediaSampleWriter::MediaSampleConsumerFunction sampleConsumers[kNumTracks];
    std::vector<std::pair<std::shared_ptr<MediaSample>, size_t>> addedSamples;
    const TestMediaSource& mediaSource = getMediaSource();

    for (int trackIdx = 0; trackIdx < kNumTracks; ++trackIdx) {
        auto trackFormat = mediaSource.mTrackFormats[trackIdx % mediaSource.mTrackCount];
        sampleConsumers[trackIdx] = writer->addTrack(trackFormat);
        EXPECT_NE(sampleConsumers[trackIdx], nullptr);
        EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::AddTrack(trackFormat.get()));
    }

    // Create samples in the expected interleaved order for easy verification.
    auto addSampleToTrackWithPts = [&addedSamples, &sampleConsumers](int trackIndex, int64_t pts) {
        auto sample = newSampleWithPts(pts);
        sampleConsumers[trackIndex](sample);
        addedSamples.emplace_back(sample, trackIndex);
    };

    addSampleToTrackWithPts(0, 0);
    addSampleToTrackWithPts(1, 4);

    addSampleToTrackWithPts(0, 1);
    addSampleToTrackWithPts(0, 2);
    addSampleToTrackWithPts(0, 3);
    addSampleToTrackWithPts(0, 10);

    addSampleToTrackWithPts(1, 5);
    addSampleToTrackWithPts(1, 6);
    addSampleToTrackWithPts(1, 11);

    addSampleToTrackWithPts(0, 12);
    addSampleToTrackWithPts(1, 13);

    for (int trackIndex = 0; trackIndex < kNumTracks; ++trackIndex) {
        sampleConsumers[trackIndex](newSampleEos());
    }

    // Start the writer.
    ASSERT_TRUE(writer->start());

    // Wait for writer to complete.
    mTestCallbacks->waitForWritingFinished();
    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::Start());

    std::sort(addedSamples.begin(), addedSamples.end(),
              [](const std::pair<std::shared_ptr<MediaSample>, size_t>& left,
                 const std::pair<std::shared_ptr<MediaSample>, size_t>& right) {
                  return left.first->info.presentationTimeUs < right.first->info.presentationTimeUs;
              });

    // Verify sample order.
    for (auto entry : addedSamples) {
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

        // EOS timestamp = first sample timestamp + duration.
        const int64_t endTime = duration + (trackIndex == 1 ? 4 : 0);
        const AMediaCodecBufferInfo info = {0, 0, endTime, AMEDIACODEC_BUFFER_FLAG_END_OF_STREAM};

        EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::WriteSample(trackIndex, nullptr, &info));
    }

    EXPECT_EQ(mTestMuxer->popEvent(), TestMuxer::Stop());
    EXPECT_TRUE(mTestCallbacks->hasFinished());
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
    std::shared_ptr<MediaSampleWriter> writer = MediaSampleWriter::Create();
    EXPECT_TRUE(writer->init(destinationFd, mTestCallbacks));
    close(destinationFd);

    // Add tracks.
    const TestMediaSource& mediaSource = getMediaSource();
    std::vector<MediaSampleWriter::MediaSampleConsumerFunction> sampleConsumers;

    for (size_t trackIndex = 0; trackIndex < mediaSource.mTrackCount; trackIndex++) {
        auto consumer = writer->addTrack(mediaSource.mTrackFormats[trackIndex]);
        sampleConsumers.push_back(consumer);
    }

    // Start the writer.
    ASSERT_TRUE(writer->start());

    // Enqueue samples and finally End Of Stream.
    std::shared_ptr<MediaSample> sample;
    size_t trackIndex;
    while ((sample = readSampleAndAdvance(mediaSource.mExtractor, &trackIndex)) != nullptr) {
        sampleConsumers[trackIndex](sample);
    }
    for (trackIndex = 0; trackIndex < mediaSource.mTrackCount; trackIndex++) {
        sampleConsumers[trackIndex](newSampleEos());
    }

    // Wait for writer.
    mTestCallbacks->waitForWritingFinished();

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
