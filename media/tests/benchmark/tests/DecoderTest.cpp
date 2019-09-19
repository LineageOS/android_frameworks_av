/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define LOG_TAG "decoderTest"

#include <fstream>
#include <iostream>
#include <limits>

#include "Decoder.h"
#include "BenchmarkTestEnvironment.h"

static BenchmarkTestEnvironment *gEnv = nullptr;

class DecoderTest : public ::testing::TestWithParam<tuple<string, string, bool>> {};

TEST_P(DecoderTest, Decode) {
    ALOGV("Decode the samples given by extractor");
    tuple<string /* InputFile */, string /* CodecName */, bool /* asyncMode */> params = GetParam();

    string inputFile = gEnv->getRes() + get<0>(params);
    FILE *inputFp = fopen(inputFile.c_str(), "rb");
    if (!inputFp) {
        cout << "[   WARN   ] Test Skipped. Unable to open input file for reading \n";
        return;
    }

    Decoder *decoder = new Decoder();
    Extractor *extractor = decoder->getExtractor();
    if (!extractor) {
        cout << "[   WARN   ] Test Skipped. Extractor creation failed \n";
        return;
    }

    // Read file properties
    fseek(inputFp, 0, SEEK_END);
    size_t fileSize = ftell(inputFp);
    fseek(inputFp, 0, SEEK_SET);
    int32_t fd = fileno(inputFp);

    int32_t trackCount = extractor->initExtractor(fd, fileSize);
    if (trackCount <= 0) {
        cout << "[   WARN   ] Test Skipped. initExtractor failed\n";
        return;
    }
    for (int curTrack = 0; curTrack < trackCount; curTrack++) {
        int32_t status = extractor->setupTrackFormat(curTrack);
        if (status != 0) {
            cout << "[   WARN   ] Test Skipped. Track Format invalid \n";
            return;
        }

        uint8_t *inputBuffer = (uint8_t *)malloc(kMaxBufferSize);
        if (!inputBuffer) {
            cout << "[   WARN   ] Test Skipped. Insufficient memory \n";
            return;
        }
        vector<AMediaCodecBufferInfo> frameInfo;
        AMediaCodecBufferInfo info;
        uint32_t inputBufferOffset = 0;

        // Get frame data
        while (1) {
            status = extractor->getFrameSample(info);
            if (status || !info.size) break;
            // copy the meta data and buffer to be passed to decoder
            if (inputBufferOffset + info.size > kMaxBufferSize) {
                cout << "[   WARN   ] Test Skipped. Memory allocated not sufficient\n";
                free(inputBuffer);
                return;
            }
            memcpy(inputBuffer + inputBufferOffset, extractor->getFrameBuf(), info.size);
            frameInfo.push_back(info);
            inputBufferOffset += info.size;
        }

        string codecName = get<1>(params);
        bool asyncMode = get<2>(params);
        decoder->setupDecoder();
        status = decoder->decode(inputBuffer, frameInfo, codecName, asyncMode);
        if (status != AMEDIA_OK) {
            cout << "[   WARN   ] Test Failed. Decode returned error " << status << endl;
            free(inputBuffer);
            return;
        }
        decoder->deInitCodec();
        cout << "codec : " << codecName << endl;
        string inputReference = get<0>(params);
        decoder->dumpStatistics(inputReference);
        free(inputBuffer);
        decoder->resetDecoder();
    }
    fclose(inputFp);
    extractor->deInitExtractor();
    delete decoder;
}

// TODO: (b/140549596)
// Add wav files
INSTANTIATE_TEST_SUITE_P(
        AudioDecoderSyncTest, DecoderTest,
        ::testing::Values(make_tuple("bbb_44100hz_2ch_128kbps_aac_30sec.mp4", "", false),
                          make_tuple("bbb_44100hz_2ch_128kbps_mp3_30sec.mp3", "", false),
                          make_tuple("bbb_8000hz_1ch_8kbps_amrnb_30sec.3gp", "", false),
                          make_tuple("bbb_16000hz_1ch_9kbps_amrwb_30sec.3gp", "", false),
                          make_tuple("bbb_44100hz_2ch_80kbps_vorbis_30sec.mp4", "", false),
                          make_tuple("bbb_44100hz_2ch_600kbps_flac_30sec.mp4", "", false),
                          make_tuple("bbb_48000hz_2ch_100kbps_opus_30sec.webm", "", false)));

INSTANTIATE_TEST_SUITE_P(
        AudioDecoderAsyncTest, DecoderTest,
        ::testing::Values(make_tuple("bbb_44100hz_2ch_128kbps_aac_30sec.mp4", "", true),
                          make_tuple("bbb_44100hz_2ch_128kbps_mp3_30sec.mp3", "", true),
                          make_tuple("bbb_8000hz_1ch_8kbps_amrnb_30sec.3gp", "", true),
                          make_tuple("bbb_16000hz_1ch_9kbps_amrwb_30sec.3gp", "", true),
                          make_tuple("bbb_44100hz_2ch_80kbps_vorbis_30sec.mp4", "", true),
                          make_tuple("bbb_44100hz_2ch_600kbps_flac_30sec.mp4", "", true),
                          make_tuple("bbb_48000hz_2ch_100kbps_opus_30sec.webm", "", true)));

INSTANTIATE_TEST_SUITE_P(VideDecoderSyncTest, DecoderTest,
                         ::testing::Values(
                                 // Hardware codecs
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp9.webm", "", false),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp8.webm", "", false),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_av1.webm", "", false),
                                 make_tuple("crowd_1920x1080_25fps_7300kbps_mpeg2.mp4", "", false),
                                 make_tuple("crowd_1920x1080_25fps_6000kbps_mpeg4.mp4", "", false),
                                 make_tuple("crowd_352x288_25fps_6000kbps_h263.3gp", "", false),
                                 make_tuple("crowd_1920x1080_25fps_6700kbps_h264.ts", "", false),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_h265.mkv", "", false),
                                 // Software codecs
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp9.webm",
                                            "c2.android.vp9.decoder", false),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp8.webm",
                                            "c2.android.vp8.decoder", false),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_av1.webm",
                                            "c2.android.av1.decoder", false),
                                 make_tuple("crowd_1920x1080_25fps_7300kbps_mpeg2.mp4",
                                            "c2.android.mpeg2.decoder", false),
                                 make_tuple("crowd_1920x1080_25fps_6000kbps_mpeg4.mp4",
                                            "c2.android.mpeg4.decoder", false),
                                 make_tuple("crowd_352x288_25fps_6000kbps_h263.3gp",
                                            "c2.android.h263.decoder", false),
                                 make_tuple("crowd_1920x1080_25fps_6700kbps_h264.ts",
                                            "c2.android.avc.decoder", false),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_h265.mkv",
                                            "c2.android.hevc.decoder", false)));

INSTANTIATE_TEST_SUITE_P(VideoDecoderAsyncTest, DecoderTest,
                         ::testing::Values(
                                 // Hardware codecs
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp9.webm", "", true),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp8.webm", "", true),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_av1.webm", "", true),
                                 make_tuple("crowd_1920x1080_25fps_7300kbps_mpeg2.mp4", "", true),
                                 make_tuple("crowd_1920x1080_25fps_6000kbps_mpeg4.mp4", "", true),
                                 make_tuple("crowd_352x288_25fps_6000kbps_h263.3gp", "", true),
                                 make_tuple("crowd_1920x1080_25fps_6700kbps_h264.ts", "", true),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_h265.mkv", "", true),
                                 // Software codecs
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp9.webm",
                                            "c2.android.vp9.decoder", true),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp8.webm",
                                            "c2.android.vp8.decoder", true),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_av1.webm",
                                            "c2.android.av1.decoder", true),
                                 make_tuple("crowd_1920x1080_25fps_7300kbps_mpeg2.mp4",
                                            "c2.android.mpeg2.decoder", true),
                                 make_tuple("crowd_1920x1080_25fps_6000kbps_mpeg4.mp4",
                                            "c2.android.mpeg4.decoder", true),
                                 make_tuple("crowd_352x288_25fps_6000kbps_h263.3gp",
                                            "c2.android.h263.decoder", true),
                                 make_tuple("crowd_1920x1080_25fps_6700kbps_h264.ts",
                                            "c2.android.avc.decoder", true),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_h265.mkv",
                                            "c2.android.hevc.decoder", true)));

int main(int argc, char **argv) {
    gEnv = new BenchmarkTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGD("Decoder Test result = %d\n", status);
    }
    return status;
}