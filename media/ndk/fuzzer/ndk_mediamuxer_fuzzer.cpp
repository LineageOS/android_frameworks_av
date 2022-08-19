/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <android/binder_process.h>
#include <fcntl.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <media/NdkMediaMuxer.h>
#include <sys/mman.h>
#include <unistd.h>

const std::string kMuxerFile = "mediaMuxer";
const std::string kAppendFile = "mediaAppend";
constexpr size_t kMinBytes = 0;
constexpr size_t kMaxBytes = 1000;
constexpr size_t kMinChoice = 0;
constexpr size_t kMaxChoice = 7;
constexpr size_t kMaxStringLength = 20;
constexpr size_t kOffset = 0;

constexpr OutputFormat kOutputFormat[] = {AMEDIAMUXER_OUTPUT_FORMAT_MPEG_4,
                                          AMEDIAMUXER_OUTPUT_FORMAT_WEBM,
                                          AMEDIAMUXER_OUTPUT_FORMAT_THREE_GPP};
constexpr AppendMode kAppendMode[] = {AMEDIAMUXER_APPEND_IGNORE_LAST_VIDEO_GOP,
                                      AMEDIAMUXER_APPEND_TO_EXISTING_DATA};

const std::string kAudioMimeType[] = {"audio/3gpp", "audio/amr-wb", "audio/mp4a-latm",
                                      "audio/flac", "audio/vorbis", "audio/opus"};

const std::string kVideoMimeType[] = {"video/x-vnd.on2.vp8", "video/x-vnd.on2.vp9", "video/av01",
                                      "video/avc",           "video/hevc",          "video/mp4v-es",
                                      "video/3gpp"};

void getSampleAudioFormat(FuzzedDataProvider& fdp, AMediaFormat* format) {
    std::string mimeType = fdp.ConsumeBool() ? fdp.ConsumeRandomLengthString(kMaxStringLength)
                                             : fdp.PickValueInArray(kAudioMimeType);
    AMediaFormat_setString(format, AMEDIAFORMAT_KEY_MIME, mimeType.c_str());
    AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_BIT_RATE, fdp.ConsumeIntegral<int32_t>());
    AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_SAMPLE_RATE, fdp.ConsumeIntegral<int32_t>());
    AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_CHANNEL_COUNT, fdp.ConsumeIntegral<int32_t>());
    AMediaFormat_setInt64(format, AMEDIAFORMAT_KEY_DURATION, fdp.ConsumeIntegral<int64_t>());
}

void getSampleVideoFormat(FuzzedDataProvider& fdp, AMediaFormat* format) {
    std::string mimeType = fdp.ConsumeBool() ? fdp.ConsumeRandomLengthString(kMaxStringLength)
                                             : fdp.PickValueInArray(kAudioMimeType);
    AMediaFormat_setString(format, AMEDIAFORMAT_KEY_MIME, mimeType.c_str());
    AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_BIT_RATE, fdp.ConsumeIntegral<int32_t>());
    AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_WIDTH, fdp.ConsumeIntegral<int32_t>());
    AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_HEIGHT, fdp.ConsumeIntegral<int32_t>());
    AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_FRAME_RATE, fdp.ConsumeIntegral<int32_t>());
    AMediaFormat_setFloat(format, AMEDIAFORMAT_KEY_I_FRAME_INTERVAL,
                          fdp.ConsumeFloatingPoint<float>());
    AMediaFormat_setFloat(format, AMEDIAFORMAT_KEY_CAPTURE_RATE, fdp.ConsumeFloatingPoint<float>());
    AMediaFormat_setInt32(format, AMEDIAFORMAT_KEY_COLOR_FORMAT, fdp.ConsumeIntegral<int32_t>());
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    /**
     * Create a threadpool for incoming binder transactions,
     * without this muxer results in a DoS after few instances.
     */
    ABinderProcess_startThreadPool();
    FuzzedDataProvider fdp(data, size);
    /**
     * memfd_create() creates an anonymous file and returns a file
     * descriptor that refers to it. MFD_ALLOW_SEALING allow sealing
     * operations on this file.
     */
    int32_t fd = -1;
    AMediaMuxer* muxer = nullptr;
    if (fdp.ConsumeBool()) {
        fd = memfd_create(kMuxerFile.c_str(), MFD_ALLOW_SEALING);
        muxer = AMediaMuxer_new(fd, fdp.ConsumeBool()
                                            ? fdp.PickValueInArray(kOutputFormat)
                                            : (OutputFormat)fdp.ConsumeIntegral<int32_t>());
    } else {
        fd = memfd_create(kAppendFile.c_str(), MFD_ALLOW_SEALING);
        std::vector<uint8_t> appendData =
                fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
        write(fd, appendData.data(), appendData.size());
        muxer = AMediaMuxer_append(fd, fdp.PickValueInArray(kAppendMode) /* mode */);
    }
    if (!muxer) {
        close(fd);
        return 0;
    }
    AMediaFormat* mediaFormat = nullptr;
    ssize_t trackIdx = 0;
    while (fdp.remaining_bytes()) {
        int32_t kSwitchChoice = fdp.ConsumeIntegralInRange<int32_t>(kMinChoice, kMaxChoice);
        switch (kSwitchChoice) {
            case 0: {
                AMediaMuxer_setLocation(muxer, fdp.ConsumeFloatingPoint<float>() /* latitude */,
                                        fdp.ConsumeFloatingPoint<float>() /* longitude */);
                break;
            }
            case 1: {
                AMediaMuxer_setOrientationHint(muxer, fdp.ConsumeIntegral<int32_t>() /* degrees */);
                break;
            }
            case 2: {
                AMediaMuxer_start(muxer);
                break;
            }
            case 3: {
                AMediaMuxer_stop(muxer);
                break;
            }
            case 4: {
                AMediaMuxer_getTrackCount(muxer);
                break;
            }
            case 5: {
                AMediaFormat* getFormat =
                        AMediaMuxer_getTrackFormat(muxer, fdp.ConsumeIntegral<size_t>() /* idx */);
                AMediaFormat_delete(getFormat);
                break;
            }
            case 6: {
                mediaFormat = AMediaFormat_new();
                fdp.ConsumeBool() ? getSampleAudioFormat(fdp, mediaFormat)
                                  : getSampleVideoFormat(fdp, mediaFormat);
                trackIdx = AMediaMuxer_addTrack(muxer, mediaFormat);
                AMediaFormat_delete(mediaFormat);
                break;
            }
            default: {
                std::vector<uint8_t> sampleData = fdp.ConsumeBytes<uint8_t>(
                        fdp.ConsumeIntegralInRange<size_t>(kMinBytes, kMaxBytes));
                AMediaCodecBufferInfo codecBuffer;
                codecBuffer.size = sampleData.size();
                codecBuffer.offset = kOffset;
                codecBuffer.presentationTimeUs = fdp.ConsumeIntegral<int64_t>();
                codecBuffer.flags = fdp.ConsumeIntegral<uint32_t>();
                AMediaMuxer_writeSampleData(
                        muxer,
                        fdp.ConsumeBool() ? trackIdx : fdp.ConsumeIntegral<size_t>() /* trackIdx */,
                        sampleData.data(), &codecBuffer);
                break;
            }
        }
    }
    AMediaMuxer_delete(muxer);
    close(fd);
    return 0;
}
