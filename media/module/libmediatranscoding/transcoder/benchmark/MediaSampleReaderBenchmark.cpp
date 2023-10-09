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
 * MediaSampleReader benchmark tests.
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
 *      $ adb shell /data/nativetest64/MediaSampleReaderBenchmark/MediaSampleReaderBenchmark
 */

#define LOG_TAG "MediaSampleReaderBenchmark"

#include <android-base/logging.h>
#include <benchmark/benchmark.h>
#include <fcntl.h>
#include <media/MediaSampleReaderNDK.h>
#include <unistd.h>

#include <thread>

#include "BenchmarkCommon.h"
using namespace android;

static void ReadMediaSamples(benchmark::State& state, const std::string& srcFileName,
                             bool readAudio, bool sequentialAccess = false) {
    int srcFd = 0;
    std::string srcPath = kAssetDirectory + srcFileName;

    if ((srcFd = open(srcPath.c_str(), O_RDONLY)) < 0) {
        state.SkipWithError("Unable to open source file: " + srcPath);
        return;
    }

    const size_t fileSize = lseek(srcFd, 0, SEEK_END);
    lseek(srcFd, 0, SEEK_SET);

    for (auto _ : state) {
        auto sampleReader = MediaSampleReaderNDK::createFromFd(srcFd, 0, fileSize);
        if (sampleReader->setEnforceSequentialAccess(sequentialAccess) != AMEDIA_OK) {
            state.SkipWithError("setEnforceSequentialAccess failed");
            return;
        }

        // Select tracks.
        std::vector<int> trackIndices;
        for (int trackIndex = 0; trackIndex < sampleReader->getTrackCount(); ++trackIndex) {
            const char* mime = nullptr;

            AMediaFormat* trackFormat = sampleReader->getTrackFormat(trackIndex);
            AMediaFormat_getString(trackFormat, AMEDIAFORMAT_KEY_MIME, &mime);

            if (strncmp(mime, "video/", 6) == 0) {
                int32_t frameCount;
                if (AMediaFormat_getInt32(trackFormat, AMEDIAFORMAT_KEY_FRAME_COUNT, &frameCount)) {
                    state.counters["VideoFrameRate"] =
                            benchmark::Counter(frameCount, benchmark::Counter::kIsRate);
                }
            } else if (!readAudio && strncmp(mime, "audio/", 6) == 0) {
                continue;
            }

            trackIndices.push_back(trackIndex);
            sampleReader->selectTrack(trackIndex);
        }

        // Start threads.
        std::vector<std::thread> trackThreads;
        for (auto trackIndex : trackIndices) {
            trackThreads.emplace_back([trackIndex, sampleReader, &state] {
                LOG(INFO) << "Track " << trackIndex << " started";
                MediaSampleInfo info;

                size_t bufferSize = 0;
                std::unique_ptr<uint8_t[]> buffer;

                while (true) {
                    media_status_t status = sampleReader->getSampleInfoForTrack(trackIndex, &info);
                    if (status == AMEDIA_ERROR_END_OF_STREAM) {
                        break;
                    }

                    if (info.size > bufferSize) {
                        bufferSize = info.size;
                        buffer.reset(new uint8_t[bufferSize]);
                    }

                    status = sampleReader->readSampleDataForTrack(trackIndex, buffer.get(),
                                                                  bufferSize);
                    if (status != AMEDIA_OK) {
                        state.SkipWithError("Error reading sample data");
                        break;
                    }
                }

                LOG(INFO) << "Track " << trackIndex << " finished";
            });
        }

        // Join threads.
        for (auto& thread : trackThreads) {
            thread.join();
        }
    }

    close(srcFd);
}

// Benchmark registration wrapper for transcoding.
#define TRANSCODER_BENCHMARK(func) \
    BENCHMARK(func)->UseRealTime()->MeasureProcessCPUTime()->Unit(benchmark::kMillisecond)

static void BM_MediaSampleReader_AudioVideo_Parallel(benchmark::State& state) {
    ReadMediaSamples(state, "video_1920x1080_3648frame_h264_22Mbps_30fps_aac.mp4",
                     true /* readAudio */);
}

static void BM_MediaSampleReader_AudioVideo_Sequential(benchmark::State& state) {
    ReadMediaSamples(state, "video_1920x1080_3648frame_h264_22Mbps_30fps_aac.mp4",
                     true /* readAudio */, true /* sequentialAccess */);
}

static void BM_MediaSampleReader_Video(benchmark::State& state) {
    ReadMediaSamples(state, "video_1920x1080_3648frame_h264_22Mbps_30fps_aac.mp4",
                     false /* readAudio */);
}

TRANSCODER_BENCHMARK(BM_MediaSampleReader_AudioVideo_Parallel);
TRANSCODER_BENCHMARK(BM_MediaSampleReader_AudioVideo_Sequential);
TRANSCODER_BENCHMARK(BM_MediaSampleReader_Video);

BENCHMARK_MAIN();
