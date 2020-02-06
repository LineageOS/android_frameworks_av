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

#include "BenchmarkTestEnvironment.h"
#include "Decoder.h"

static BenchmarkTestEnvironment *gEnv = nullptr;

class DecoderTest : public ::testing::TestWithParam<tuple<string, string, bool>> {};

TEST_P(DecoderTest, Decode) {
    ALOGV("Decode the samples given by extractor");
    tuple<string /* InputFile */, string /* CodecName */, bool /* asyncMode */> params = GetParam();

    string inputFile = gEnv->getRes() + get<0>(params);
    FILE *inputFp = fopen(inputFile.c_str(), "rb");
    ASSERT_NE(inputFp, nullptr) << "Unable to open " << inputFile << " file for reading";

    Decoder *decoder = new Decoder();
    ASSERT_NE(decoder, nullptr) << "Decoder creation failed";

    Extractor *extractor = decoder->getExtractor();
    ASSERT_NE(extractor, nullptr) << "Extractor creation failed";

    // Read file properties
    struct stat buf;
    stat(inputFile.c_str(), &buf);
    size_t fileSize = buf.st_size;
    int32_t fd = fileno(inputFp);

    int32_t trackCount = extractor->initExtractor(fd, fileSize);
    ASSERT_GT(trackCount, 0) << "initExtractor failed";

    for (int curTrack = 0; curTrack < trackCount; curTrack++) {
        int32_t status = extractor->setupTrackFormat(curTrack);
        ASSERT_EQ(status, 0) << "Track Format invalid";

        uint8_t *inputBuffer = (uint8_t *)malloc(kMaxBufferSize);
        ASSERT_NE(inputBuffer, nullptr) << "Insufficient memory";

        vector<AMediaCodecBufferInfo> frameInfo;
        AMediaCodecBufferInfo info;
        uint32_t inputBufferOffset = 0;

        // Get frame data
        while (1) {
            status = extractor->getFrameSample(info);
            if (status || !info.size) break;
            // copy the meta data and buffer to be passed to decoder
            ASSERT_LE(inputBufferOffset + info.size, kMaxBufferSize)
                    << "Memory allocated not sufficient";

            memcpy(inputBuffer + inputBufferOffset, extractor->getFrameBuf(), info.size);
            frameInfo.push_back(info);
            inputBufferOffset += info.size;
        }

        string codecName = get<1>(params);
        bool asyncMode = get<2>(params);
        decoder->setupDecoder();
        status = decoder->decode(inputBuffer, frameInfo, codecName, asyncMode);
        ASSERT_EQ(status, AMEDIA_OK) << "Decoder failed for " << codecName;

        decoder->deInitCodec();
        ALOGV("codec : %s", codecName.c_str());
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
                          make_tuple("bbb_44100hz_2ch_80kbps_vorbis_30sec.webm", "", false),
                          make_tuple("bbb_44100hz_2ch_600kbps_flac_30sec.mp4", "", false),
                          make_tuple("bbb_48000hz_2ch_100kbps_opus_30sec.webm", "", false)));

INSTANTIATE_TEST_SUITE_P(
        AudioDecoderAsyncTest, DecoderTest,
        ::testing::Values(make_tuple("bbb_44100hz_2ch_128kbps_aac_30sec.mp4", "", true),
                          make_tuple("bbb_44100hz_2ch_128kbps_mp3_30sec.mp3", "", true),
                          make_tuple("bbb_8000hz_1ch_8kbps_amrnb_30sec.3gp", "", true),
                          make_tuple("bbb_16000hz_1ch_9kbps_amrwb_30sec.3gp", "", true),
                          make_tuple("bbb_44100hz_2ch_80kbps_vorbis_30sec.webm", "", true),
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