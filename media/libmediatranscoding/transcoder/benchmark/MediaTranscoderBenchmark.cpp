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
 * Native media transcoder library benchmark tests.
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
 *      $ adb shell /data/nativetest64/MediaTranscoderBenchmark/MediaTranscoderBenchmark
 */

#include <benchmark/benchmark.h>
#include <fcntl.h>
#include <media/MediaTranscoder.h>

using namespace android;

class TranscoderCallbacks : public MediaTranscoder::CallbackInterface {
public:
    virtual void onFinished(const MediaTranscoder* transcoder __unused) override {
        std::unique_lock<std::mutex> lock(mMutex);
        mFinished = true;
        mCondition.notify_all();
    }

    virtual void onError(const MediaTranscoder* transcoder __unused,
                         media_status_t error) override {
        std::unique_lock<std::mutex> lock(mMutex);
        mFinished = true;
        mStatus = error;
        mCondition.notify_all();
    }

    virtual void onProgressUpdate(const MediaTranscoder* transcoder __unused,
                                  int32_t progress __unused) override {}

    virtual void onCodecResourceLost(const MediaTranscoder* transcoder __unused,
                                     const std::shared_ptr<const Parcel>& pausedState
                                             __unused) override {}

    bool waitForTranscodingFinished() {
        std::unique_lock<std::mutex> lock(mMutex);
        while (!mFinished) {
            if (mCondition.wait_for(lock, std::chrono::minutes(5)) == std::cv_status::timeout) {
                return false;
            }
        }
        return true;
    }

    media_status_t mStatus = AMEDIA_OK;

private:
    std::mutex mMutex;
    std::condition_variable mCondition;
    bool mFinished = false;
};

static void TranscodeMediaFile(benchmark::State& state, const std::string& srcFileName,
                               const std::string& dstFileName, bool includeAudio) {
    // Default bitrate
    static constexpr int32_t kVideoBitRate = 20 * 1000 * 1000;  // 20Mbs
    // Write-only, create file if non-existent.
    static constexpr int kDstOpenFlags = O_WRONLY | O_CREAT;
    // User R+W permission.
    static constexpr int kDstFileMode = S_IRUSR | S_IWUSR;
    // Asset directory
    static const std::string kAssetDirectory = "/data/local/tmp/TranscodingBenchmark/";

    int srcFd = 0;
    int dstFd = 0;

    std::string srcPath = kAssetDirectory + srcFileName;
    std::string dstPath = kAssetDirectory + dstFileName;

    auto callbacks = std::make_shared<TranscoderCallbacks>();
    media_status_t status = AMEDIA_OK;

    if ((srcFd = open(srcPath.c_str(), O_RDONLY)) < 0) {
        state.SkipWithError("Unable to open source file");
        goto exit;
    }
    if ((dstFd = open(dstPath.c_str(), kDstOpenFlags, kDstFileMode)) < 0) {
        state.SkipWithError("Unable to open destination file");
        goto exit;
    }

    for (auto _ : state) {
        auto transcoder = MediaTranscoder::create(callbacks, nullptr);

        status = transcoder->configureSource(srcFd);
        if (status != AMEDIA_OK) {
            state.SkipWithError("Unable to configure transcoder source");
            goto exit;
        }

        status = transcoder->configureDestination(dstFd);
        if (status != AMEDIA_OK) {
            state.SkipWithError("Unable to configure transcoder destination");
            goto exit;
        }

        std::vector<std::shared_ptr<AMediaFormat>> trackFormats = transcoder->getTrackFormats();
        for (int i = 0; i < trackFormats.size(); ++i) {
            AMediaFormat* srcFormat = trackFormats[i].get();
            AMediaFormat* dstFormat = nullptr;

            const char* mime = nullptr;
            if (!AMediaFormat_getString(srcFormat, AMEDIAFORMAT_KEY_MIME, &mime)) {
                state.SkipWithError("Source track format does not have MIME type");
                goto exit;
            }

            if (strncmp(mime, "video/", 6) == 0) {
                dstFormat = AMediaFormat_new();
                AMediaFormat_setInt32(dstFormat, AMEDIAFORMAT_KEY_BIT_RATE, kVideoBitRate);

                int32_t frameCount;
                if (AMediaFormat_getInt32(srcFormat, AMEDIAFORMAT_KEY_FRAME_COUNT, &frameCount)) {
                    state.counters["VideoFrameRate"] =
                            benchmark::Counter(frameCount, benchmark::Counter::kIsRate);
                }
            } else if (!includeAudio && strncmp(mime, "audio/", 6) == 0) {
                continue;
            }

            status = transcoder->configureTrackFormat(i, dstFormat);
            if (dstFormat != nullptr) {
                AMediaFormat_delete(dstFormat);
            }
            if (status != AMEDIA_OK) {
                state.SkipWithError("Unable to configure track");
                goto exit;
            }
        }

        status = transcoder->start();
        if (status != AMEDIA_OK) {
            state.SkipWithError("Unable to start transcoder");
            goto exit;
        }

        if (!callbacks->waitForTranscodingFinished()) {
            state.SkipWithError("Transcoder timed out");
            goto exit;
        }
        if (callbacks->mStatus != AMEDIA_OK) {
            state.SkipWithError("Transcoder error when running");
            goto exit;
        }
    }

exit:
    if (srcFd > 0) close(srcFd);
    if (dstFd > 0) close(dstFd);
}

// Benchmark registration wrapper for transcoding.
#define TRANSCODER_BENCHMARK(func) \
    BENCHMARK(func)->UseRealTime()->MeasureProcessCPUTime()->Unit(benchmark::kMillisecond)

static void BM_TranscodeAvc2AvcAudioVideo2AudioVideo(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3648frame_h264_22Mbps_30fps_aac.mp4",
                       "video_1920x1080_3648frame_h264_22Mbps_30fps_aac_transcoded_AV.mp4",
                       true /* includeAudio */);
}

static void BM_TranscodeAvc2AvcAudioVideo2Video(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3648frame_h264_22Mbps_30fps_aac.mp4",
                       "video_1920x1080_3648frame_h264_22Mbps_30fps_aac_transcoded_V.mp4",
                       false /* includeAudio */);
}

static void BM_TranscodeAvc2AvcVideo2Video(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3648frame_h264_22Mbps_30fps.mp4",
                       "video_1920x1080_3648frame_h264_22Mbps_30fps_transcoded_V.mp4",
                       false /* includeAudio */);
}

TRANSCODER_BENCHMARK(BM_TranscodeAvc2AvcAudioVideo2AudioVideo);
TRANSCODER_BENCHMARK(BM_TranscodeAvc2AvcAudioVideo2Video);
TRANSCODER_BENCHMARK(BM_TranscodeAvc2AvcVideo2Video);

BENCHMARK_MAIN();
