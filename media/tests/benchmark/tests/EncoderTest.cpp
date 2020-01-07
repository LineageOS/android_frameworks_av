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
#define LOG_TAG "encoderTest"

#include <fstream>

#include "BenchmarkTestEnvironment.h"
#include "Decoder.h"
#include "Encoder.h"

static BenchmarkTestEnvironment *gEnv = nullptr;

class EncoderTest : public ::testing::TestWithParam<tuple<string, string, bool>> {};

TEST_P(EncoderTest, Encode) {
    ALOGD("Encode test for all codecs");
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

    Encoder *encoder = new Encoder();
    ASSERT_NE(encoder, nullptr) << "Decoder creation failed";

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

        string decName = "";
        string outputFileName = "decode.out";
        FILE *outFp = fopen(outputFileName.c_str(), "wb");
        ASSERT_NE(outFp, nullptr) << "Unable to open output file" << outputFileName
                                  << " for dumping decoder's output";

        decoder->setupDecoder();
        status = decoder->decode(inputBuffer, frameInfo, decName, false /*asyncMode */, outFp);
        ASSERT_EQ(status, AMEDIA_OK) << "Decode returned error : " << status;

        ifstream eleStream;
        eleStream.open(outputFileName.c_str(), ifstream::binary | ifstream::ate);
        ASSERT_EQ(eleStream.is_open(), true) << outputFileName.c_str() << " - file not found";
        size_t eleSize = eleStream.tellg();
        eleStream.seekg(0, ifstream::beg);

        AMediaFormat *format = extractor->getFormat();
        const char *mime = nullptr;
        AMediaFormat_getString(format, AMEDIAFORMAT_KEY_MIME, &mime);
        ASSERT_NE(mime, nullptr) << "Invalid mime type";

        // Get encoder params
        encParameter encParams;
        if (!strncmp(mime, "video/", 6)) {
            ASSERT_TRUE(AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_WIDTH, &encParams.width));
            ASSERT_TRUE(AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_HEIGHT, &encParams.height));
            AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_FRAME_RATE, &encParams.frameRate);
            AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_BIT_RATE, &encParams.bitrate);
            if (encParams.bitrate <= 0 || encParams.frameRate <= 0) {
                encParams.frameRate = 25;
                if (!strcmp(mime, "video/3gpp") || !strcmp(mime, "video/mp4v-es")) {
                    encParams.bitrate = 600000 /* 600 Kbps */;
                } else {
                    encParams.bitrate = 8000000 /* 8 Mbps */;
                }
            }
            AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_PROFILE, &encParams.profile);
            AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_LEVEL, &encParams.level);
        } else {
            ASSERT_TRUE(AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_SAMPLE_RATE,
                                              &encParams.sampleRate));
            ASSERT_TRUE(AMediaFormat_getInt32(format, AMEDIAFORMAT_KEY_CHANNEL_COUNT,
                                              &encParams.numChannels));
            encParams.bitrate =
                    encParams.sampleRate * encParams.numChannels * 16 /* bitsPerSample */;
        }

        encoder->setupEncoder();
        string codecName = get<1>(params);
        bool asyncMode = get<2>(params);
        status = encoder->encode(codecName, eleStream, eleSize, asyncMode, encParams, (char *)mime);
        ASSERT_EQ(status, 0) << "Encoder failed for " << codecName;

        encoder->deInitCodec();
        ALOGV("codec : %s", codecName.c_str());
        string inputReference = get<0>(params);
        encoder->dumpStatistics(inputReference, extractor->getClipDuration());
        eleStream.close();
        if (outFp) fclose(outFp);

        if (format) {
            AMediaFormat_delete(format);
            format = nullptr;
        }
        encoder->resetEncoder();
        decoder->deInitCodec();
        free(inputBuffer);
        decoder->resetDecoder();
    }
    delete encoder;
    fclose(inputFp);
    extractor->deInitExtractor();
    delete decoder;
}

INSTANTIATE_TEST_SUITE_P(
        AudioEncoderSyncTest, EncoderTest,
        ::testing::Values(make_tuple("bbb_44100hz_2ch_128kbps_aac_30sec.mp4", "", false),
                          make_tuple("bbb_8000hz_1ch_8kbps_amrnb_30sec.3gp", "", false),
                          make_tuple("bbb_16000hz_1ch_9kbps_amrwb_30sec.3gp", "", false),
                          make_tuple("bbb_44100hz_2ch_600kbps_flac_30sec.mp4", "", false),
                          make_tuple("bbb_48000hz_2ch_100kbps_opus_30sec.webm", "", false)));

INSTANTIATE_TEST_SUITE_P(
        AudioEncoderAsyncTest, EncoderTest,
        ::testing::Values(make_tuple("bbb_44100hz_2ch_128kbps_aac_30sec.mp4", "", true),
                          make_tuple("bbb_8000hz_1ch_8kbps_amrnb_30sec.3gp", "", true),
                          make_tuple("bbb_16000hz_1ch_9kbps_amrwb_30sec.3gp", "", true),
                          make_tuple("bbb_44100hz_2ch_600kbps_flac_30sec.mp4", "", true),
                          make_tuple("bbb_48000hz_2ch_100kbps_opus_30sec.webm", "", true)));

INSTANTIATE_TEST_SUITE_P(VideEncoderSyncTest, EncoderTest,
                         ::testing::Values(
                                 // Hardware codecs
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp8.webm", "", false),
                                 make_tuple("crowd_1920x1080_25fps_6700kbps_h264.ts", "", false),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_h265.mkv", "", false),
                                 // Software codecs
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp9.webm",
                                            "c2.android.vp9.encoder", false),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp8.webm",
                                            "c2.android.vp8.encoder", false),
                                 make_tuple("crowd_176x144_25fps_6000kbps_mpeg4.mp4",
                                            "c2.android.mpeg4.encoder", false),
                                 make_tuple("crowd_176x144_25fps_6000kbps_h263.3gp",
                                            "c2.android.h263.encoder", false),
                                 make_tuple("crowd_1920x1080_25fps_6700kbps_h264.ts",
                                            "c2.android.avc.encoder", false),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_h265.mkv",
                                            "c2.android.hevc.encoder", false)));

INSTANTIATE_TEST_SUITE_P(VideoEncoderAsyncTest, EncoderTest,
                         ::testing::Values(
                                 // Hardware codecs
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp8.webm", "", true),
                                 make_tuple("crowd_1920x1080_25fps_6700kbps_h264.ts", "", true),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_h265.mkv", "", true),
                                 // Software codecs
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp9.webm",
                                            "c2.android.vp9.encoder", true),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_vp8.webm",
                                            "c2.android.vp8.encoder", true),
                                 make_tuple("crowd_176x144_25fps_6000kbps_mpeg4.mp4",
                                            "c2.android.mpeg4.encoder", true),
                                 make_tuple("crowd_176x144_25fps_6000kbps_h263.3gp",
                                            "c2.android.h263.encoder", true),
                                 make_tuple("crowd_1920x1080_25fps_6700kbps_h264.ts",
                                            "c2.android.avc.encoder", true),
                                 make_tuple("crowd_1920x1080_25fps_4000kbps_h265.mkv",
                                            "c2.android.hevc.encoder", true)));

int main(int argc, char **argv) {
    gEnv = new BenchmarkTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGD("Encoder Test result = %d\n", status);
    }
    return status;
}
