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
#define LOG_TAG "extractorTest"

#include <gtest/gtest.h>

#include "Extractor.h"
#include "BenchmarkTestEnvironment.h"

static BenchmarkTestEnvironment *gEnv = nullptr;

class ExtractorTest : public ::testing::TestWithParam<pair<string, int32_t>> {};

TEST_P(ExtractorTest, Extract) {
    Extractor *extractObj = new Extractor();

    string inputFile = gEnv->getRes() + GetParam().first;
    FILE *inputFp = fopen(inputFile.c_str(), "rb");
    if (!inputFp) {
        cout << "[   WARN   ] Test Skipped. Unable to open input file for reading \n";
        return;
    }

    // Read file properties
    size_t fileSize = 0;
    fseek(inputFp, 0, SEEK_END);
    fileSize = ftell(inputFp);
    fseek(inputFp, 0, SEEK_SET);
    int32_t fd = fileno(inputFp);

    int32_t trackCount = extractObj->initExtractor(fd, fileSize);
    if (trackCount <= 0) {
        cout << "[   WARN   ] Test Skipped. initExtractor failed\n";
        return;
    }

    int32_t trackID = GetParam().second;
    int32_t status = extractObj->extract(trackID);
    if (status != AMEDIA_OK) {
        cout << "[   WARN   ] Test Skipped. Extraction failed \n";
        return;
    }

    extractObj->deInitExtractor();

    extractObj->dumpStatistics(GetParam().first);

    fclose(inputFp);
    delete extractObj;
}

INSTANTIATE_TEST_SUITE_P(ExtractorTestAll, ExtractorTest,
                         ::testing::Values(make_pair("crowd_1920x1080_25fps_4000kbps_vp9.webm", 0),
                                           make_pair("crowd_1920x1080_25fps_6000kbps_h263.3gp", 0),
                                           make_pair("crowd_1920x1080_25fps_6000kbps_mpeg4.mp4", 0),
                                           make_pair("crowd_1920x1080_25fps_6700kbps_h264.ts", 0),
                                           make_pair("crowd_1920x1080_25fps_7300kbps_mpeg2.mp4", 0),
                                           make_pair("crowd_1920x1080_25fps_4000kbps_av1.webm", 0),
                                           make_pair("crowd_1920x1080_25fps_4000kbps_h265.mkv", 0),
                                           make_pair("crowd_1920x1080_25fps_4000kbps_vp8.webm", 0),
                                           make_pair("bbb_44100hz_2ch_128kbps_aac_5mins.mp4", 0),
                                           make_pair("bbb_44100hz_2ch_128kbps_mp3_5mins.mp3", 0),
                                           make_pair("bbb_44100hz_2ch_600kbps_flac_5mins.flac", 0),
                                           make_pair("bbb_8000hz_1ch_8kbps_amrnb_5mins.3gp", 0),
                                           make_pair("bbb_16000hz_1ch_9kbps_amrwb_5mins.3gp", 0),
                                           make_pair("bbb_44100hz_2ch_80kbps_vorbis_5mins.mp4", 0),
                                           make_pair("bbb_48000hz_2ch_100kbps_opus_5mins.webm", 0)));

int main(int argc, char **argv) {
    gEnv = new BenchmarkTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGD(" Extractor Test result = %d\n", status);
    }
    return status;
}
