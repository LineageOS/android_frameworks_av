
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
#define LOG_TAG "muxerTest"

#include <fstream>
#include <iostream>

#include "BenchmarkTestEnvironment.h"
#include "Muxer.h"

#define OUTPUT_FILE_NAME "/data/local/tmp/mux.out"

static BenchmarkTestEnvironment *gEnv = nullptr;

class MuxerTest : public ::testing::TestWithParam<pair<string, string>> {};

static MUXER_OUTPUT_T getMuxerOutFormat(string fmt) {
    static const struct {
        string name;
        MUXER_OUTPUT_T value;
    } kFormatMaps[] = {{"mp4", MUXER_OUTPUT_FORMAT_MPEG_4},
                       {"webm", MUXER_OUTPUT_FORMAT_WEBM},
                       {"3gpp", MUXER_OUTPUT_FORMAT_3GPP},
                       {"ogg", MUXER_OUTPUT_FORMAT_OGG}};

    MUXER_OUTPUT_T format = MUXER_OUTPUT_FORMAT_INVALID;
    for (size_t i = 0; i < sizeof(kFormatMaps) / sizeof(kFormatMaps[0]); ++i) {
        if (!fmt.compare(kFormatMaps[i].name)) {
            format = kFormatMaps[i].value;
            break;
        }
    }
    return format;
}

TEST_P(MuxerTest, Mux) {
    ALOGV("Mux the samples given by extractor");
    string inputFile = gEnv->getRes() + GetParam().first;
    FILE *inputFp = fopen(inputFile.c_str(), "rb");
    ASSERT_NE(inputFp, nullptr) << "Unable to open " << inputFile << " file for reading";

    string fmt = GetParam().second;
    MUXER_OUTPUT_T outputFormat = getMuxerOutFormat(fmt);
    ASSERT_NE(outputFormat, MUXER_OUTPUT_FORMAT_INVALID) << "Invalid muxer output format";

    Muxer *muxerObj = new Muxer();
    ASSERT_NE(muxerObj, nullptr) << "Muxer creation failed";

    Extractor *extractor = muxerObj->getExtractor();
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

        // AMediaCodecBufferInfo : <size of frame> <flags> <presentationTimeUs> <offset>
        vector<AMediaCodecBufferInfo> frameInfos;
        AMediaCodecBufferInfo info;
        uint32_t inputBufferOffset = 0;

        // Get Frame Data
        while (1) {
            status = extractor->getFrameSample(info);
            if (status || !info.size) break;
            // copy the meta data and buffer to be passed to muxer
            ASSERT_LE(inputBufferOffset + info.size, kMaxBufferSize)
                    << "Memory allocated not sufficient";

            memcpy(inputBuffer + inputBufferOffset, extractor->getFrameBuf(), info.size);
            info.offset = inputBufferOffset;
            frameInfos.push_back(info);
            inputBufferOffset += info.size;
        }

        string outputFileName = OUTPUT_FILE_NAME;
        FILE *outputFp = fopen(outputFileName.c_str(), "w+b");
        ASSERT_NE(outputFp, nullptr)
                << "Unable to open output file" << outputFileName << " for writing";

        int32_t fd = fileno(outputFp);
        status = muxerObj->initMuxer(fd, outputFormat);
        ASSERT_EQ(status, 0) << "initMuxer failed";

        status = muxerObj->mux(inputBuffer, frameInfos);
        ASSERT_EQ(status, 0) << "Mux failed";

        muxerObj->deInitMuxer();
        muxerObj->dumpStatistics(GetParam().first + "." + fmt.c_str());
        free(inputBuffer);
        fclose(outputFp);
        muxerObj->resetMuxer();
    }
    fclose(inputFp);
    extractor->deInitExtractor();
    delete muxerObj;
}

INSTANTIATE_TEST_SUITE_P(
        MuxerTestAll, MuxerTest,
        ::testing::Values(make_pair("crowd_1920x1080_25fps_4000kbps_vp8.webm", "webm"),
                          make_pair("crowd_1920x1080_25fps_4000kbps_vp9.webm", "webm"),
                          make_pair("crowd_1920x1080_25fps_6000kbps_mpeg4.mp4", "mp4"),
                          make_pair("crowd_352x288_25fps_6000kbps_h263.3gp", "mp4"),
                          make_pair("crowd_1920x1080_25fps_6700kbps_h264.ts", "mp4"),
                          make_pair("crowd_1920x1080_25fps_4000kbps_h265.mkv", "mp4"),
                          make_pair("crowd_1920x1080_25fps_6000kbps_mpeg4.mp4", "3gpp"),
                          make_pair("crowd_352x288_25fps_6000kbps_h263.3gp", "3gpp"),
                          make_pair("crowd_1920x1080_25fps_6700kbps_h264.ts", "3gpp"),
                          make_pair("crowd_1920x1080_25fps_4000kbps_h265.mkv", "3gpp"),
                          make_pair("bbb_48000hz_2ch_100kbps_opus_5mins.webm", "ogg"),
                          make_pair("bbb_44100hz_2ch_80kbps_vorbis_5mins.webm", "webm"),
                          make_pair("bbb_48000hz_2ch_100kbps_opus_5mins.webm", "webm"),
                          make_pair("bbb_44100hz_2ch_128kbps_aac_5mins.mp4", "mp4"),
                          make_pair("bbb_8000hz_1ch_8kbps_amrnb_5mins.3gp", "mp4"),
                          make_pair("bbb_16000hz_1ch_9kbps_amrwb_5mins.3gp", "mp4"),
                          make_pair("bbb_44100hz_2ch_128kbps_aac_5mins.mp4", "3gpp"),
                          make_pair("bbb_8000hz_1ch_8kbps_amrnb_5mins.3gp", "3gpp"),
                          make_pair("bbb_16000hz_1ch_9kbps_amrwb_5mins.3gp", "3gpp")));

int main(int argc, char **argv) {
    gEnv = new BenchmarkTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
