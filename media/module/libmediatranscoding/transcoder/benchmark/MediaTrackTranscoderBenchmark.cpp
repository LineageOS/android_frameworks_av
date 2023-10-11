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

/**
 * Native media track transcoder benchmark tests.
 *
 * How to run the benchmark:
 *
 * 1. Download the media assets from http://go/transcodingbenchmark and push the directory
 *    ("TranscodingBenchmark") to /data/local/tmp.
 *
 * 2. Compile the benchmark and sync to device:
 *      $ mm -j72 && adb sync
 *
 * 3. Run:
 *      $ adb shell /data/nativetest64/MediaTrackTranscoderBenchmark/MediaTrackTranscoderBenchmark
 */

// #define LOG_NDEBUG 0
#define LOG_TAG "MediaTrackTranscoderBenchmark"

#include <android-base/logging.h>
#include <android/binder_process.h>
#include <benchmark/benchmark.h>
#include <fcntl.h>
#include <media/MediaSampleReader.h>
#include <media/MediaSampleReaderNDK.h>
#include <media/MediaTrackTranscoder.h>
#include <media/MediaTrackTranscoderCallback.h>
#include <media/NdkCommon.h>
#include <media/PassthroughTrackTranscoder.h>
#include <media/VideoTrackTranscoder.h>

#include "BenchmarkCommon.h"

using namespace android;

typedef enum {
    kVideo,
    kAudio,
} MediaType;

class TrackTranscoderCallbacks : public MediaTrackTranscoderCallback {
public:
    virtual void onTrackFormatAvailable(const MediaTrackTranscoder* transcoder __unused) override {}

    virtual void onTrackFinished(const MediaTrackTranscoder* transcoder __unused) override {
        std::unique_lock lock(mMutex);
        mFinished = true;
        mCondition.notify_all();
    }

    virtual void onTrackStopped(const MediaTrackTranscoder* transcoder __unused) override {
        std::unique_lock lock(mMutex);
        mFinished = true;
        mCondition.notify_all();
    }

    virtual void onTrackError(const MediaTrackTranscoder* transcoder __unused,
                              media_status_t status) override {
        std::unique_lock lock(mMutex);
        mFinished = true;
        mStatus = status;
        mCondition.notify_all();
    }

    void waitForTranscodingFinished() {
        std::unique_lock lock(mMutex);
        while (!mFinished) {
            mCondition.wait(lock);
        }
    }

    media_status_t mStatus = AMEDIA_OK;

private:
    std::mutex mMutex;
    std::condition_variable mCondition;
    bool mFinished = false;
};

/**
 * MockSampleReader holds a ringbuffer of the first samples in the provided source track. Samples
 * are returned to the caller from the ringbuffer in a round-robin fashion with increasing
 * timestamps. The number of samples returned before EOS matches the number of frames in the source
 * track.
 */
class MockSampleReader : public MediaSampleReader {
public:
    static std::shared_ptr<MediaSampleReader> createFromFd(int fd, size_t offset, size_t size) {
        AMediaExtractor* extractor = AMediaExtractor_new();
        media_status_t status = AMediaExtractor_setDataSourceFd(extractor, fd, offset, size);
        if (status != AMEDIA_OK) return nullptr;

        auto sampleReader = std::shared_ptr<MockSampleReader>(new MockSampleReader(extractor));
        return sampleReader;
    }

    AMediaFormat* getFileFormat() override { return AMediaExtractor_getFileFormat(mExtractor); }

    size_t getTrackCount() const override { return AMediaExtractor_getTrackCount(mExtractor); }

    AMediaFormat* getTrackFormat(int trackIndex) override {
        return AMediaExtractor_getTrackFormat(mExtractor, trackIndex);
    }

    media_status_t selectTrack(int trackIndex) override {
        if (mSelectedTrack >= 0) return AMEDIA_ERROR_UNSUPPORTED;
        mSelectedTrack = trackIndex;

        media_status_t status = AMediaExtractor_selectTrack(mExtractor, trackIndex);
        if (status != AMEDIA_OK) return status;

        // Get the sample count.
        AMediaFormat* format = getTrackFormat(trackIndex);
        const bool haveSampleCount =
                AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_FRAME_COUNT, &mSampleCount);
        AMediaFormat_delete(format);

        if (!haveSampleCount) {
            LOG(ERROR) << "No sample count in track format.";
            return AMEDIA_ERROR_UNSUPPORTED;
        }

        // Buffer samples.
        const int32_t targetBufferCount = 60;
        std::unique_ptr<uint8_t[]> buffer;
        MediaSampleInfo info;
        while (true) {
            info.presentationTimeUs = AMediaExtractor_getSampleTime(mExtractor);
            info.flags = AMediaExtractor_getSampleFlags(mExtractor);
            info.size = AMediaExtractor_getSampleSize(mExtractor);

            // Finish buffering after either reading all the samples in the track or after
            // completing the GOP satisfying the target count.
            if (mSamples.size() == mSampleCount ||
                (mSamples.size() >= targetBufferCount && info.flags & SAMPLE_FLAG_SYNC_SAMPLE)) {
                break;
            }

            buffer.reset(new uint8_t[info.size]);

            ssize_t bytesRead = AMediaExtractor_readSampleData(mExtractor, buffer.get(), info.size);
            if (bytesRead != info.size) {
                return AMEDIA_ERROR_UNKNOWN;
            }

            mSamples.emplace_back(std::move(buffer), info);

            AMediaExtractor_advance(mExtractor);
        }

        mFirstPtsUs = mSamples[0].second.presentationTimeUs;
        mPtsDiff = mSamples[1].second.presentationTimeUs - mSamples[0].second.presentationTimeUs;

        return AMEDIA_OK;
    }

    media_status_t unselectTrack(int trackIndex __unused) override {
        return AMEDIA_ERROR_UNSUPPORTED;
    }

    media_status_t setEnforceSequentialAccess(bool enforce __unused) override { return AMEDIA_OK; }

    media_status_t getEstimatedBitrateForTrack(int trackIndex __unused,
                                               int32_t* bitrate __unused) override {
        return AMEDIA_ERROR_UNSUPPORTED;
    }

    media_status_t getSampleInfoForTrack(int trackIndex, MediaSampleInfo* info) override {
        if (trackIndex != mSelectedTrack) return AMEDIA_ERROR_INVALID_PARAMETER;

        if (mCurrentSampleIndex >= mSampleCount) {
            info->presentationTimeUs = 0;
            info->size = 0;
            info->flags = SAMPLE_FLAG_END_OF_STREAM;
            return AMEDIA_ERROR_END_OF_STREAM;
        }

        *info = mSamples[mCurrentSampleIndex % mSamples.size()].second;
        info->presentationTimeUs = mFirstPtsUs + mCurrentSampleIndex * mPtsDiff;
        return AMEDIA_OK;
    }

    media_status_t readSampleDataForTrack(int trackIndex, uint8_t* buffer,
                                          size_t bufferSize) override {
        if (trackIndex != mSelectedTrack) return AMEDIA_ERROR_INVALID_PARAMETER;

        if (mCurrentSampleIndex >= mSampleCount) return AMEDIA_ERROR_END_OF_STREAM;

        auto& p = mSamples[mCurrentSampleIndex % mSamples.size()];

        if (bufferSize < p.second.size) return AMEDIA_ERROR_INVALID_PARAMETER;
        memcpy(buffer, p.first.get(), p.second.size);

        advanceTrack(trackIndex);
        return AMEDIA_OK;
    }

    void advanceTrack(int trackIndex) {
        if (trackIndex != mSelectedTrack) return;
        ++mCurrentSampleIndex;
    }

    virtual ~MockSampleReader() override { AMediaExtractor_delete(mExtractor); }

private:
    MockSampleReader(AMediaExtractor* extractor) : mExtractor(extractor) {}
    AMediaExtractor* mExtractor = nullptr;
    int32_t mSampleCount = 0;
    std::vector<std::pair<std::unique_ptr<uint8_t[]>, MediaSampleInfo>> mSamples;
    int mSelectedTrack = -1;
    int32_t mCurrentSampleIndex = 0;
    int64_t mFirstPtsUs = 0;
    int64_t mPtsDiff = 0;
};

static std::shared_ptr<AMediaFormat> GetDefaultTrackFormat(MediaType mediaType,
                                                           AMediaFormat* sourceFormat) {
    // Default video config.
    static constexpr int32_t kVideoBitRate = 20 * 1000 * 1000;  // 20 mbps
    static constexpr float kVideoFrameRate = 30.0f;             // 30 fps

    AMediaFormat* format = nullptr;

    if (mediaType == kVideo) {
        format = AMediaFormat_new();
        AMediaFormat_copy(format, sourceFormat);
        AMediaFormat_setString(format, AMEDIAFORMAT_KEY_MIME, AMEDIA_MIMETYPE_VIDEO_AVC);
        AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_BIT_RATE, kVideoBitRate);
        AMediaFormat_setFloat(format, AMEDIAFORMAT_KEY_FRAME_RATE, kVideoFrameRate);
    }
    // nothing for audio.

    return std::shared_ptr<AMediaFormat>(format, &AMediaFormat_delete);
}

/** Gets a MediaSampleReader for the source file */
static std::shared_ptr<MediaSampleReader> GetSampleReader(const std::string& srcFileName,
                                                          bool mock) {
    int srcFd = 0;
    std::string srcPath = kAssetDirectory + srcFileName;

    if ((srcFd = open(srcPath.c_str(), O_RDONLY)) < 0) {
        return nullptr;
    }

    const size_t fileSize = lseek(srcFd, 0, SEEK_END);
    lseek(srcFd, 0, SEEK_SET);

    std::shared_ptr<MediaSampleReader> sampleReader;

    if (mock) {
        sampleReader = MockSampleReader::createFromFd(srcFd, 0 /* offset */, fileSize);
    } else {
        sampleReader = MediaSampleReaderNDK::createFromFd(srcFd, 0 /* offset */, fileSize);
    }

    if (srcFd > 0) close(srcFd);
    return sampleReader;
}

/**
 * Configures a MediaTrackTranscoder with an empty sample consumer so that the samples are returned
 * to the transcoder immediately.
 */
static void ConfigureEmptySampleConsumer(const std::shared_ptr<MediaTrackTranscoder>& transcoder,
                                         uint32_t& sampleCount) {
    transcoder->setSampleConsumer([&sampleCount](const std::shared_ptr<MediaSample>& sample) {
        if (!(sample->info.flags & SAMPLE_FLAG_CODEC_CONFIG) && sample->info.size > 0) {
            ++sampleCount;
        }
    });
}

/**
 * Callback to edit track format for transcoding.
 * @param dstFormat The default track format for the track type.
 */
using TrackFormatEditCallback = std::function<void(AMediaFormat* dstFormat)>;

/**
 * Configures a MediaTrackTranscoder with the provided MediaSampleReader, reading from the first
 * track that matches the specified media type.
 */
static bool ConfigureSampleReader(const std::shared_ptr<MediaTrackTranscoder>& transcoder,
                                  const std::shared_ptr<MediaSampleReader>& sampleReader,
                                  MediaType mediaType,
                                  const TrackFormatEditCallback& formatEditor) {
    int srcTrackIndex = -1;
    std::shared_ptr<AMediaFormat> srcTrackFormat = nullptr;

    for (int trackIndex = 0; trackIndex < sampleReader->getTrackCount(); ++trackIndex) {
        AMediaFormat* trackFormat = sampleReader->getTrackFormat(trackIndex);

        const char* mime = nullptr;
        AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &mime);

        if ((mediaType == kVideo && strncmp(mime, "video/", 6) == 0) ||
            (mediaType == kAudio && strncmp(mime, "audio/", 6) == 0)) {
            srcTrackIndex = trackIndex;
            srcTrackFormat = std::shared_ptr<AMediaFormat>(trackFormat, &AMediaFormat_delete);
            break;
        }
        AMediaFormat_delete(trackFormat);
    }

    if (srcTrackIndex == -1) {
        LOG(ERROR) << "No matching source track found";
        return false;
    }

    media_status_t status = sampleReader->selectTrack(srcTrackIndex);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "Unable to select track";
        return false;
    }

    auto destinationFormat = GetDefaultTrackFormat(mediaType, srcTrackFormat.get());
    if (formatEditor != nullptr) {
        formatEditor(destinationFormat.get());
    }
    status = transcoder->configure(sampleReader, srcTrackIndex, destinationFormat);
    if (status != AMEDIA_OK) {
        LOG(ERROR) << "transcoder configure returned " << status;
        return false;
    }

    return true;
}

static void BenchmarkTranscoder(benchmark::State& state, const std::string& srcFileName,
                                bool mockReader, MediaType mediaType,
                                const TrackFormatEditCallback& formatEditor = nullptr) {
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    pthread_once(&once, ABinderProcess_startThreadPool);

    for (auto _ : state) {
        std::shared_ptr<TrackTranscoderCallbacks> callbacks =
                std::make_shared<TrackTranscoderCallbacks>();
        std::shared_ptr<MediaTrackTranscoder> transcoder;

        if (mediaType == kVideo) {
            transcoder = VideoTrackTranscoder::create(callbacks);
        } else {
            transcoder = std::make_shared<PassthroughTrackTranscoder>(callbacks);
        }

        std::shared_ptr<MediaSampleReader> sampleReader = GetSampleReader(srcFileName, mockReader);
        if (sampleReader == nullptr) {
            state.SkipWithError("Unable to create sample reader: " + srcFileName);
            return;
        }

        if (!ConfigureSampleReader(transcoder, sampleReader, mediaType, formatEditor)) {
            state.SkipWithError("Unable to configure the transcoder");
            return;
        }

        uint32_t sampleCount = 0;
        ConfigureEmptySampleConsumer(transcoder, sampleCount);

        if (!transcoder->start()) {
            state.SkipWithError("Unable to start the transcoder");
            return;
        }

        callbacks->waitForTranscodingFinished();
        transcoder->stop();

        if (callbacks->mStatus != AMEDIA_OK) {
            state.SkipWithError("Transcoder failed with error");
            return;
        }

        LOG(DEBUG) << "Number of samples received: " << sampleCount;
        state.counters["FrameRate"] = benchmark::Counter(sampleCount, benchmark::Counter::kIsRate);
    }
}

static void BenchmarkTranscoderWithOperatingRate(benchmark::State& state,
                                                 const std::string& srcFile, bool mockReader,
                                                 MediaType mediaType) {
    TrackFormatEditCallback editor;
    const int32_t operatingRate = state.range(0);
    const int32_t priority = state.range(1);

    if (operatingRate >= 0 && priority >= 0) {
        editor = [operatingRate, priority](AMediaFormat* format) {
            AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_OPERATING_RATE, operatingRate);
            AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_PRIORITY, priority);
        };
    }
    BenchmarkTranscoder(state, srcFile, mockReader, mediaType, editor);
}

//-------------------------------- AVC to AVC Benchmarks -------------------------------------------

static void BM_VideoTranscode_AVC2AVC(benchmark::State& state) {
    const char* srcFile = "video_1920x1080_3648frame_h264_22Mbps_30fps_aac.mp4";
    BenchmarkTranscoderWithOperatingRate(state, srcFile, false /* mockReader */, kVideo);
}

static void BM_VideoTranscode_AVC2AVC_NoExtractor(benchmark::State& state) {
    const char* srcFile = "video_1920x1080_3648frame_h264_22Mbps_30fps_aac.mp4";
    BenchmarkTranscoderWithOperatingRate(state, srcFile, true /* mockReader */, kVideo);
}

//-------------------------------- HEVC to AVC Benchmarks ------------------------------------------

static void BM_VideoTranscode_HEVC2AVC(benchmark::State& state) {
    const char* srcFile = "video_1920x1080_3863frame_hevc_4Mbps_30fps_aac.mp4";
    BenchmarkTranscoderWithOperatingRate(state, srcFile, false /* mockReader */, kVideo);
}

static void BM_VideoTranscode_HEVC2AVC_NoExtractor(benchmark::State& state) {
    const char* srcFile = "video_1920x1080_3863frame_hevc_4Mbps_30fps_aac.mp4";
    BenchmarkTranscoderWithOperatingRate(state, srcFile, true /* mockReader */, kVideo);
}

//-------------------------------- Benchmark Registration ------------------------------------------

// Benchmark registration wrapper for transcoding.
#define TRANSCODER_BENCHMARK(func) \
    BENCHMARK(func)->UseRealTime()->MeasureProcessCPUTime()->Unit(benchmark::kMillisecond)

// Benchmark registration for testing different operating rate and priority combinations.
#define TRANSCODER_OPERATING_RATE_BENCHMARK(func)  \
    TRANSCODER_BENCHMARK(func)                     \
            ->Args({-1, -1}) /* <-- Use default */ \
            ->Args({240, 0})                       \
            ->Args({INT32_MAX, 0})                 \
            ->Args({240, 1})                       \
            ->Args({INT32_MAX, 1})

TRANSCODER_OPERATING_RATE_BENCHMARK(BM_VideoTranscode_AVC2AVC);
TRANSCODER_OPERATING_RATE_BENCHMARK(BM_VideoTranscode_AVC2AVC_NoExtractor);

TRANSCODER_OPERATING_RATE_BENCHMARK(BM_VideoTranscode_HEVC2AVC);
TRANSCODER_OPERATING_RATE_BENCHMARK(BM_VideoTranscode_HEVC2AVC_NoExtractor);

BENCHMARK_MAIN();
