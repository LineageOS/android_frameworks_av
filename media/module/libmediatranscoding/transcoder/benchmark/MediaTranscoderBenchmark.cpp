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
#include <binder/ProcessState.h>
#include <fcntl.h>
#include <media/MediaTranscoder.h>
#include <media/NdkCommon.h>

#include <iostream>

using namespace android;

const std::string PARAM_VIDEO_FRAME_RATE = "VideoFrameRate";

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

    virtual void onHeartBeat(const MediaTranscoder* transcoder __unused) override {}

    virtual void onCodecResourceLost(const MediaTranscoder* transcoder __unused,
                                     const std::shared_ptr<ndk::ScopedAParcel>& pausedState
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

static AMediaFormat* CreateDefaultVideoFormat() {
    // Default bitrate
    static constexpr int32_t kVideoBitRate = 20 * 1000 * 1000;  // 20Mbs

    AMediaFormat* videoFormat = AMediaFormat_new();
    AMediaFormat_setInt32(videoFormat, AMEDIAFORMAT_KEY_BIT_RATE, kVideoBitRate);
    AMediaFormat_setString(videoFormat, AMEDIAFORMAT_KEY_MIME, AMEDIA_MIMETYPE_VIDEO_AVC);
    return videoFormat;
}

/**
 * Callback to configure tracks for transcoding.
 * @param mime The source track mime type.
 * @param dstFormat The destination format if the track should be transcoded or nullptr if the track
 * should be passed through.
 * @return True if the track should be included in the output file.
 */
using TrackSelectionCallback = std::function<bool(const char* mime, AMediaFormat** dstFormat)>;

static void TranscodeMediaFile(benchmark::State& state, const std::string& srcFileName,
                               const std::string& dstFileName,
                               TrackSelectionCallback trackSelectionCallback) {
    // Write-only, create file if non-existent.
    static constexpr int kDstOpenFlags = O_WRONLY | O_CREAT;
    // User R+W permission.
    static constexpr int kDstFileMode = S_IRUSR | S_IWUSR;
    // Asset directory
    static const std::string kAssetDirectory = "/data/local/tmp/TranscodingBenchmark/";

    // Transcoding configuration params to be logged
    int64_t trackDurationUs = 0;
    int32_t width = 0;
    int32_t height = 0;
    std::string sourceMime = "NA";
    std::string targetMime = "NA";
    bool includeAudio = false;
    bool transcodeVideo = false;
    int32_t targetBitrate = 0;

    int srcFd = 0;
    int dstFd = 0;

    std::string srcPath = kAssetDirectory + srcFileName;
    std::string dstPath = kAssetDirectory + dstFileName;

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
        auto callbacks = std::make_shared<TranscoderCallbacks>();
        auto transcoder = MediaTranscoder::create(callbacks);

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
                int32_t frameCount;
                if (AMediaFormat_getInt32(srcFormat, AMEDIAFORMAT_KEY_FRAME_COUNT, &frameCount)) {
                    state.counters[PARAM_VIDEO_FRAME_RATE] = benchmark::Counter(
                            frameCount, benchmark::Counter::kIsIterationInvariantRate);
                }
                if (!AMediaFormat_getInt32(srcFormat, AMEDIAFORMAT_KEY_WIDTH, &width)) {
                    state.SkipWithError("Video source track format does not have width");
                    goto exit;
                }
                if (!AMediaFormat_getInt32(srcFormat, AMEDIAFORMAT_KEY_HEIGHT, &height)) {
                    state.SkipWithError("Video source track format does not have height");
                    goto exit;
                }
                AMediaFormat_getInt64(srcFormat, AMEDIAFORMAT_KEY_DURATION, &trackDurationUs);
                sourceMime = mime;
            }

            if (trackSelectionCallback(mime, &dstFormat)) {
                status = transcoder->configureTrackFormat(i, dstFormat);
                if (strncmp(mime, "video/", 6) == 0 && dstFormat != nullptr) {
                    const char* mime = nullptr;
                    if (AMediaFormat_getString(dstFormat, AMEDIAFORMAT_KEY_MIME, &mime)) {
                        targetMime = mime;
                    }
                    AMediaFormat_getInt32(dstFormat, AMEDIAFORMAT_KEY_BIT_RATE, &targetBitrate);
                    transcodeVideo = true;
                } else if (strncmp(mime, "audio/", 6) == 0) {
                    includeAudio = true;
                }
            }

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
            transcoder->cancel();
            state.SkipWithError("Transcoder timed out");
            goto exit;
        }
        if (callbacks->mStatus != AMEDIA_OK) {
            state.SkipWithError("Transcoder error when running");
            goto exit;
        }
    }

    // Set transcoding configuration params in benchmark label
    state.SetLabel(srcFileName + "," +
                   std::to_string(width) + "x" + std::to_string(height) + "," +
                   sourceMime + "," +
                   std::to_string(trackDurationUs/1000) + "," +
                   (includeAudio ? "Yes" : "No") + "," +
                   (transcodeVideo ? "Yes" : "No") + "," +
                   targetMime + "," +
                   std::to_string(targetBitrate)
                   );

exit:
    if (srcFd > 0) close(srcFd);
    if (dstFd > 0) close(dstFd);
}

/**
 * Callback to edit track format for transcoding.
 * @param dstFormat The default track format for the track type.
 */
using TrackFormatEditCallback = std::function<void(AMediaFormat* dstFormat)>;

static void TranscodeMediaFile(benchmark::State& state, const std::string& srcFileName,
                               const std::string& dstFileName, bool includeAudio,
                               bool transcodeVideo,
                               const TrackFormatEditCallback& videoFormatEditor = nullptr) {
    TranscodeMediaFile(state, srcFileName, dstFileName,
                       [=](const char* mime, AMediaFormat** dstFormatOut) -> bool {
                           *dstFormatOut = nullptr;
                           if (strncmp(mime, "video/", 6) == 0 && transcodeVideo) {
                               *dstFormatOut = CreateDefaultVideoFormat();
                               if (videoFormatEditor != nullptr) {
                                   videoFormatEditor(*dstFormatOut);
                               }
                           } else if (strncmp(mime, "audio/", 6) == 0 && !includeAudio) {
                               return false;
                           }
                           return true;
                       });
}

static void SetMaxOperatingRate(AMediaFormat* format) {
    AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_OPERATING_RATE, INT32_MAX);
    AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_PRIORITY, 1);
}

//-------------------------------- AVC to AVC Benchmarks -------------------------------------------

static void BM_TranscodeAvc2AvcAudioVideo2AudioVideo(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3648frame_h264_22Mbps_30fps_aac.mp4",
                       "video_1920x1080_3648frame_h264_22Mbps_30fps_aac_transcoded_AV.mp4",
                       true /* includeAudio */, true /* transcodeVideo */);
}

static void BM_TranscodeAvc2AvcVideo2Video(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3648frame_h264_22Mbps_30fps.mp4",
                       "video_1920x1080_3648frame_h264_22Mbps_30fps_transcoded_V.mp4",
                       false /* includeAudio */, true /* transcodeVideo */);
}

static void BM_TranscodeAvc2AvcAV2AVMaxOperatingRate(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3648frame_h264_22Mbps_30fps_aac.mp4",
                       "video_1920x1080_3648frame_h264_22Mbps_30fps_aac_transcoded_AV.mp4",
                       true /* includeAudio */, true /* transcodeVideo */, SetMaxOperatingRate);
}

static void BM_TranscodeAvc2AvcV2VMaxOperatingRate(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3648frame_h264_22Mbps_30fps.mp4",
                       "video_1920x1080_3648frame_h264_22Mbps_30fps_transcoded_V.mp4",
                       false /* includeAudio */, true /* transcodeVideo */, SetMaxOperatingRate);
}

static void BM_TranscodeAvc2AvcAV2AV720P(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1280x720_3648frame_h264_16Mbps_30fps_aac.mp4",
                       "video_1280x720_3648frame_h264_16Mbps_30fps_aac_transcoded_AV.mp4",
                       true /* includeAudio */, true /* transcodeVideo */);
}

static void BM_TranscodeAvc2AvcAV2AV720PMaxOperatingRate(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1280x720_3648frame_h264_16Mbps_30fps_aac.mp4",
                       "video_1280x720_3648frame_h264_16Mbps_30fps_aac_transcoded_AV.mp4",
                       true /* includeAudio */, true /* transcodeVideo */, SetMaxOperatingRate);
}
//-------------------------------- HEVC to AVC Benchmarks ------------------------------------------

static void BM_TranscodeHevc2AvcAudioVideo2AudioVideo(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3863frame_hevc_4Mbps_30fps_aac.mp4",
                       "video_1920x1080_3863frame_hevc_4Mbps_30fps_aac_transcoded_AV.mp4",
                       true /* includeAudio */, true /* transcodeVideo */);
}

static void BM_TranscodeHevc2AvcVideo2Video(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3863frame_hevc_4Mbps_30fps.mp4",
                       "video_1920x1080_3863frame_hevc_4Mbps_30fps_transcoded_V.mp4",
                       false /* includeAudio */, true /* transcodeVideo */);
}

static void BM_TranscodeHevc2AvcAV2AVMaxOperatingRate(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3863frame_hevc_4Mbps_30fps_aac.mp4",
                       "video_1920x1080_3863frame_hevc_4Mbps_30fps_aac_transcoded_AV.mp4",
                       true /* includeAudio */, true /* transcodeVideo */, SetMaxOperatingRate);
}

static void BM_TranscodeHevc2AvcV2VMaxOperatingRate(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3863frame_hevc_4Mbps_30fps.mp4",
                       "video_1920x1080_3863frame_hevc_4Mbps_30fps_transcoded_V.mp4",
                       false /* includeAudio */, true /* transcodeVideo */, SetMaxOperatingRate);
}

static void BM_TranscodeHevc2AvcAV2AV720P(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1280x720_3863frame_hevc_16Mbps_30fps_aac.mp4",
                       "video_1280x720_3863frame_hevc_16Mbps_30fps_aac_transcoded_AV.mp4",
                       true /* includeAudio */, true /* transcodeVideo */);
}

static void BM_TranscodeHevc2AvcAV2AV720PMaxOperatingRate(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1280x720_3863frame_hevc_16Mbps_30fps_aac.mp4",
                       "video_1280x720_3863frame_hevc_16Mbps_30fps_aac_transcoded_AV.mp4",
                       true /* includeAudio */, true /* transcodeVideo */, SetMaxOperatingRate);
}

//-------------------------------- Passthrough Benchmarks ------------------------------------------

static void BM_TranscodeAudioVideoPassthrough(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3648frame_h264_22Mbps_30fps_aac.mp4",
                       "video_1920x1080_3648frame_h264_22Mbps_30fps_aac_passthrough_AV.mp4",
                       true /* includeAudio */, false /* transcodeVideo */);
}
static void BM_TranscodeVideoPassthrough(benchmark::State& state) {
    TranscodeMediaFile(state, "video_1920x1080_3648frame_h264_22Mbps_30fps.mp4",
                       "video_1920x1080_3648frame_h264_22Mbps_30fps_passthrough_AV.mp4",
                       false /* includeAudio */, false /* transcodeVideo */);
}

//---------------------------- Codecs, Resolutions, Bitrate  ---------------------------------------
static void SetMimeBitrate(AMediaFormat* format, std::string mime, int32_t bitrate) {
    AMediaFormat_setString(format, AMEDIAFORMAT_KEY_MIME, mime.c_str());
    AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_BIT_RATE, bitrate);
}

static void BM_1920x1080_Avc22Mbps2Avc12Mbps(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1920_1080_30fps_h264_22Mbps.mp4",
                       "tx_bm_1920_1080_30fps_h264_22Mbps_transcoded_h264_12Mbps.mp4",
                       false /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 12000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_1920x1080_Avc15Mbps2Avc8Mbps(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1920_1080_30fps_h264_15Mbps.mp4",
                       "tx_bm_1920_1080_30fps_h264_15Mbps_transcoded_h264_8Mbps.mp4",
                       false /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 8000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_1920x1080_Avc15Mbps2AvcPassthrough(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1920_1080_30fps_h264_15Mbps.mp4",
                       "tx_bm_1920_1080_30fps_h264_15Mbps_passthrough_V.mp4",
                       false /* includeAudio */, false /* transcodeVideo */);
}

static void BM_1920x1080_Avc15MbpsAac2Avc8Mbps(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1920_1080_30fps_h264_15Mbps_aac.mp4",
                       "tx_bm_1920_1080_30fps_h264_15Mbps_aac_transcoded_h264_8Mbps.mp4",
                       false /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 8000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_1920x1080_Avc15MbpsAac2Avc8MbpsAac(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1920_1080_30fps_h264_15Mbps_aac.mp4",
                       "tx_bm_1920_1080_30fps_h264_15Mbps_aac_transcoded_h264_8Mbps_aac.mp4",
                       true /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 8000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_1920x1080_Avc15MbpsAac2AvcPassthrough(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1920_1080_30fps_h264_15Mbps_aac.mp4",
                       "tx_bm_1920_1080_30fps_h264_15Mbps_aac_passthrough_V.mp4",
                       false /* includeAudio */, false /* transcodeVideo */);
}

static void BM_1920x1080_Avc15MbpsAac2AvcAacPassthrough(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1920_1080_30fps_h264_15Mbps_aac.mp4",
                       "tx_bm_1920_1080_30fps_h264_15Mbps_aac_passthrough_AV.mp4",
                       true /* includeAudio */, false /* transcodeVideo */);
}

static void BM_1920x1080_Hevc17Mbps2Hevc8Mbps(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1920_1080_30fps_hevc_17Mbps.mp4",
                       "tx_bm_1920_1080_30fps_hevc_17Mbps_transcoded_hevc_8Mbps.mp4",
                       false /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/hevc", bitrate = 8000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_1920x1080_Hevc17Mbps2Avc12Mbps(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1920_1080_30fps_hevc_17Mbps.mp4",
                       "tx_bm_1920_1080_30fps_hevc_17Mbps_transcoded_h264_12Mbps.mp4",
                       false /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 12000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_1920x1080_60fps_Hevc28Mbps2Avc15Mbps(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1920_1080_60fps_hevc_28Mbps.mp4",
                       "tx_bm_1920_1080_60fps_hevc_28Mbps_transcoded_h264_15Mbps.mp4",
                       false /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 15000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_1280x720_Avc10Mbps2Avc4Mbps(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1280_720_30fps_h264_10Mbps.mp4",
                       "tx_bm_1280_720_30fps_h264_10Mbps_transcoded_h264_4Mbps.mp4",
                       false /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 4000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_1280x720_Avc10Mbps2AvcPassthrough(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1280_720_30fps_h264_10Mbps.mp4",
                       "tx_bm_1280_720_30fps_h264_10Mbps_passthrough_V.mp4",
                       false /* includeAudio */, false /* transcodeVideo */);
}

static void BM_1280x720_Avc10MbpsAac2Avc4Mbps(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1280_720_30fps_h264_10Mbps_aac.mp4",
                       "tx_bm_1280_720_30fps_h264_10Mbps_aac_transcoded_h264_4Mbps.mp4",
                       false /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 4000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_1280x720_Avc10MbpsAac2Avc4MbpsAac(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1280_720_30fps_h264_10Mbps_aac.mp4",
                       "tx_bm_1280_720_30fps_h264_10Mbps_aac_transcoded_h264_4Mbps_aac.mp4",
                       true /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 4000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_1280x720_Avc10MbpsAac2AvcPassthrough(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1280_720_30fps_h264_10Mbps_aac.mp4",
                       "tx_bm_1280_720_30fps_h264_10Mbps_aac_passthrough_V.mp4",
                       false /* includeAudio */, false /* transcodeVideo */);
}

static void BM_1280x720_Avc10MbpsAac2AvcAacPassthrough(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1280_720_30fps_h264_10Mbps_aac.mp4",
                       "tx_bm_1280_720_30fps_h264_10Mbps_aac_passthrough_AV.mp4",
                       true /* includeAudio */, false /* transcodeVideo */);
}

static void BM_1280x720_Hevc8Mbps2Avc4Mbps(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1280_720_30fps_hevc_8Mbps.mp4",
                       "tx_bm_1280_720_30fps_hevc_8Mbps_transcoded_h264_4Mbps.mp4",
                       false /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 4000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_1080x1920_Avc15Mbps2Avc8Mbps(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_1080_1920_30fps_h264_15Mbps.mp4",
                       "tx_bm_1080_1920_30fps_h264_15Mbps_transcoded_h264_8Mbps.mp4",
                       false /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 8000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_720x1280_Avc10Mbps2Avc4Mbps(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_720_1280_30fps_h264_10Mbps.mp4",
                       "tx_bm_720_1280_30fps_h264_10Mbps_transcoded_h264_4Mbps.mp4",
                       false /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 4000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

static void BM_3840x2160_Hevc42Mbps2Avc20Mbps(benchmark::State& state) {
    TranscodeMediaFile(state, "tx_bm_3840_2160_30fps_hevc_42Mbps.mp4",
                       "tx_bm_3840_2160_30fps_hevc_42Mbps_transcoded_h264_4Mbps.mp4",
                       false /* includeAudio */, true /* transcodeVideo */,
                       [mime = "video/avc", bitrate = 20000000](AMediaFormat* dstFormat) {
                           SetMimeBitrate(dstFormat, mime, bitrate);
                       });
}

//-------------------------------- Benchmark Registration ------------------------------------------

// Benchmark registration wrapper for transcoding.
#define TRANSCODER_BENCHMARK(func) \
    BENCHMARK(func)->UseRealTime()->MeasureProcessCPUTime()->Unit(benchmark::kMillisecond)

TRANSCODER_BENCHMARK(BM_TranscodeAvc2AvcAudioVideo2AudioVideo);
TRANSCODER_BENCHMARK(BM_TranscodeAvc2AvcVideo2Video);
TRANSCODER_BENCHMARK(BM_TranscodeAvc2AvcAV2AVMaxOperatingRate);
TRANSCODER_BENCHMARK(BM_TranscodeAvc2AvcV2VMaxOperatingRate);
TRANSCODER_BENCHMARK(BM_TranscodeAvc2AvcAV2AV720P);
TRANSCODER_BENCHMARK(BM_TranscodeAvc2AvcAV2AV720PMaxOperatingRate);

TRANSCODER_BENCHMARK(BM_TranscodeHevc2AvcAudioVideo2AudioVideo);
TRANSCODER_BENCHMARK(BM_TranscodeHevc2AvcVideo2Video);
TRANSCODER_BENCHMARK(BM_TranscodeHevc2AvcAV2AVMaxOperatingRate);
TRANSCODER_BENCHMARK(BM_TranscodeHevc2AvcV2VMaxOperatingRate);
TRANSCODER_BENCHMARK(BM_TranscodeHevc2AvcAV2AV720P);
TRANSCODER_BENCHMARK(BM_TranscodeHevc2AvcAV2AV720PMaxOperatingRate);

TRANSCODER_BENCHMARK(BM_TranscodeAudioVideoPassthrough);
TRANSCODER_BENCHMARK(BM_TranscodeVideoPassthrough);

TRANSCODER_BENCHMARK(BM_1920x1080_Avc22Mbps2Avc12Mbps);
TRANSCODER_BENCHMARK(BM_1920x1080_Avc15Mbps2Avc8Mbps);
TRANSCODER_BENCHMARK(BM_1920x1080_Avc15Mbps2AvcPassthrough);
TRANSCODER_BENCHMARK(BM_1920x1080_Avc15MbpsAac2Avc8Mbps);
TRANSCODER_BENCHMARK(BM_1920x1080_Avc15MbpsAac2Avc8MbpsAac);
TRANSCODER_BENCHMARK(BM_1920x1080_Avc15MbpsAac2AvcPassthrough);
TRANSCODER_BENCHMARK(BM_1920x1080_Avc15MbpsAac2AvcAacPassthrough);
TRANSCODER_BENCHMARK(BM_1920x1080_Hevc17Mbps2Hevc8Mbps);
TRANSCODER_BENCHMARK(BM_1920x1080_Hevc17Mbps2Avc12Mbps);
TRANSCODER_BENCHMARK(BM_1920x1080_60fps_Hevc28Mbps2Avc15Mbps);

TRANSCODER_BENCHMARK(BM_1280x720_Avc10Mbps2Avc4Mbps);
TRANSCODER_BENCHMARK(BM_1280x720_Avc10Mbps2AvcPassthrough);
TRANSCODER_BENCHMARK(BM_1280x720_Avc10MbpsAac2Avc4Mbps);
TRANSCODER_BENCHMARK(BM_1280x720_Avc10MbpsAac2Avc4MbpsAac);
TRANSCODER_BENCHMARK(BM_1280x720_Avc10MbpsAac2AvcPassthrough);
TRANSCODER_BENCHMARK(BM_1280x720_Avc10MbpsAac2AvcAacPassthrough);
TRANSCODER_BENCHMARK(BM_1280x720_Hevc8Mbps2Avc4Mbps);

TRANSCODER_BENCHMARK(BM_1080x1920_Avc15Mbps2Avc8Mbps);
TRANSCODER_BENCHMARK(BM_720x1280_Avc10Mbps2Avc4Mbps);

TRANSCODER_BENCHMARK(BM_3840x2160_Hevc42Mbps2Avc20Mbps);

class CustomCsvReporter : public benchmark::BenchmarkReporter {
public:
    CustomCsvReporter() : mPrintedHeader(false) {}
    virtual bool ReportContext(const Context& context);
    virtual void ReportRuns(const std::vector<Run>& reports);

private:
    void PrintRunData(const Run& report);

    bool mPrintedHeader;
    std::vector<std::string> mHeaders = {
        "File",          "Resolution",     "SourceMime", "VideoTrackDuration(ms)",
        "IncludeAudio",  "TranscodeVideo", "TargetMime", "TargetBirate(bps)",
        "real_time(ms)", "cpu_time(ms)",   PARAM_VIDEO_FRAME_RATE
    };
};

bool CustomCsvReporter::ReportContext(const Context& context __unused) {
    return true;
}

void CustomCsvReporter::ReportRuns(const std::vector<Run>& reports) {
    std::ostream& Out = GetOutputStream();

    if (!mPrintedHeader) {
        // print the header
        for (auto header = mHeaders.begin(); header != mHeaders.end();) {
            Out << *header++;
            if (header != mHeaders.end()) Out << ",";
        }
        Out << "\n";
        mPrintedHeader = true;
    }

    // print results for each run
    for (const auto& run : reports) {
        PrintRunData(run);
    }
}

void CustomCsvReporter::PrintRunData(const Run& run) {
    if (run.skipped) {
        return;
    }
    std::ostream& Out = GetOutputStream();
    // Log the transcoding params reported through label
    Out << run.report_label << ",";
    Out << run.GetAdjustedRealTime() << ",";
    Out << run.GetAdjustedCPUTime() << ",";
    auto frameRate = run.counters.find(PARAM_VIDEO_FRAME_RATE);
    if (frameRate == run.counters.end()) {
        Out << "NA"
            << ",";
    } else {
        Out << frameRate->second << ",";
    }
    Out << '\n';
}

int main(int argc, char** argv) {
    android::ProcessState::self()->startThreadPool();
    std::unique_ptr<benchmark::BenchmarkReporter> fileReporter;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]).find("--benchmark_out") != std::string::npos) {
            fileReporter.reset(new CustomCsvReporter);
            break;
        }
    }
    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
    ::benchmark::RunSpecifiedBenchmarks(nullptr, fileReporter.get());
}
