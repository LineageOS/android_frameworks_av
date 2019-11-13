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
#define LOG_TAG "C2DecoderTest"

#include <fstream>
#include <iostream>
#include <limits>

#include "BenchmarkTestEnvironment.h"
#include "C2Decoder.h"
#include "Extractor.h"

static BenchmarkTestEnvironment *gEnv = nullptr;

class C2DecoderTest : public ::testing::TestWithParam<pair<string, string>> {
  public:
    C2DecoderTest() : mDecoder(nullptr), disableTest(false) { setupC2DecoderTest(); }

    void setupC2DecoderTest();

    vector<string> mCodecList;
    C2Decoder *mDecoder;
    bool disableTest;
};

void C2DecoderTest::setupC2DecoderTest() {
    mDecoder = new C2Decoder();
    if (!mDecoder) {
        cout << "[   WARN   ] Test Skipped. C2Decoder creation failed\n";
        disableTest = true;
        return;
    }
    int32_t status = mDecoder->setupCodec2();
    if (status != 0) {
        cout << "[   WARN   ] Test Skipped. Codec2 setup failed \n";
        disableTest = true;
        return;
    }
    mCodecList = mDecoder->getSupportedComponentList(false /* isEncoder*/);
    if (!mCodecList.size()) {
        cout << "[   WARN   ] Test Skipped. Codec2 client didn't recognise any component \n";
        disableTest = true;
        return;
    }
}

TEST_P(C2DecoderTest, Codec2Decode) {
    if (disableTest) return;

    ALOGV("Decode the samples given by extractor using codec2");
    string inputFile = gEnv->getRes() + GetParam().first;
    FILE *inputFp = fopen(inputFile.c_str(), "rb");
    if (!inputFp) {
        cout << "[   WARN   ] Test Skipped. Unable to open input file" << inputFile
             << " for reading \n";
        return;
    }

    Extractor *extractor = new Extractor();
    if (!extractor) {
        cout << "[   WARN   ] Test Skipped. Extractor creation failed \n";
        return;
    }

    // Read file properties
    fseek(inputFp, 0, SEEK_END);
    size_t fileSize = ftell(inputFp);
    fseek(inputFp, 0, SEEK_SET);
    int32_t fd = fileno(inputFp);

    if (fileSize > kMaxBufferSize) {
        cout << "[   WARN   ] Test Skipped. Input file size is greater than the threshold memory "
                "dedicated to the test \n";
    }

    int32_t trackCount = extractor->initExtractor(fd, fileSize);
    if (trackCount <= 0) {
        cout << "[   WARN   ] Test Skipped. initExtractor failed\n";
        return;
    }
    for (int32_t curTrack = 0; curTrack < trackCount; curTrack++) {
        int32_t status = extractor->setupTrackFormat(curTrack);
        if (status != 0) {
            cout << "[   WARN   ] Test Skipped. Track Format invalid \n";
            return;
        }

        uint8_t *inputBuffer = (uint8_t *)malloc(fileSize);
        if (!inputBuffer) {
            cout << "[   WARN   ] Test Skipped. Insufficient memory \n";
            return;
        }

        vector<AMediaCodecBufferInfo> frameInfo;
        AMediaCodecBufferInfo info;
        uint32_t inputBufferOffset = 0;
        int32_t idx = 0;

        // Get CSD data
        while (1) {
            void *csdBuffer = extractor->getCSDSample(info, idx);
            if (!csdBuffer || !info.size) break;
            // copy the meta data and buffer to be passed to decoder
            if (inputBufferOffset + info.size > fileSize) {
                cout << "[   WARN   ] Test Skipped. Memory allocated not sufficient\n";
                free(inputBuffer);
                return;
            }
            memcpy(inputBuffer + inputBufferOffset, csdBuffer, info.size);
            frameInfo.push_back(info);
            inputBufferOffset += info.size;
            idx++;
        }

        // Get frame data
        while (1) {
            status = extractor->getFrameSample(info);
            if (status || !info.size) break;
            // copy the meta data and buffer to be passed to decoder
            if (inputBufferOffset + info.size > fileSize) {
                cout << "[   WARN   ] Test Skipped. Memory allocated not sufficient\n";
                free(inputBuffer);
                return;
            }
            memcpy(inputBuffer + inputBufferOffset, extractor->getFrameBuf(), info.size);
            frameInfo.push_back(info);
            inputBufferOffset += info.size;
        }

        AMediaFormat *format = extractor->getFormat();
        // Decode the given input stream for all C2 codecs supported by device
        for (string codecName : mCodecList) {
            if (codecName.find(GetParam().second) != string::npos &&
                codecName.find("secure") == string::npos) {
                status = mDecoder->createCodec2Component(codecName, format);
                if (status != 0) {
                    cout << "[   WARN   ] Test Skipped. Create component failed for " << codecName
                         << "\n";
                    continue;
                }

                // Send the inputs to C2 Decoder and wait till all buffers are returned.
                mDecoder->decodeFrames(inputBuffer, frameInfo);
                mDecoder->waitOnInputConsumption();
                if (!mDecoder->mEos) {
                    cout << "[   WARN   ] Test Failed. Didn't receive EOS \n";
                }
                mDecoder->deInitCodec();
                int64_t durationUs = extractor->getClipDuration();
                cout << "codec: " << codecName << endl;
                mDecoder->dumpStatistics(GetParam().first, durationUs);
                mDecoder->resetDecoder();
            }
        }
        free(inputBuffer);
        fclose(inputFp);
        extractor->deInitExtractor();
        delete extractor;
        delete mDecoder;
    }
}

// TODO: (b/140549596)
// Add wav files
INSTANTIATE_TEST_SUITE_P(
        AudioDecoderTest, C2DecoderTest,
        ::testing::Values(
                make_pair("bbb_44100hz_2ch_128kbps_aac_30sec.mp4", "aac"),
                make_pair("bbb_44100hz_2ch_128kbps_mp3_30sec.mp3", "mp3"),
                make_pair("bbb_8000hz_1ch_8kbps_amrnb_30sec.3gp", "amrnb"),
                make_pair("bbb_16000hz_1ch_9kbps_amrwb_30sec.3gp", "amrnb"),
                make_pair("bbb_44100hz_2ch_80kbps_vorbis_30sec.mp4", "vorbis"),
                make_pair("bbb_44100hz_2ch_600kbps_flac_30sec.mp4", "flac"),
                make_pair("bbb_48000hz_2ch_100kbps_opus_30sec.webm", "opus")));

INSTANTIATE_TEST_SUITE_P(
        VideoDecoderTest, C2DecoderTest,
        ::testing::Values(
                make_pair("crowd_1920x1080_25fps_4000kbps_vp9.webm", "vp9"),
                make_pair("crowd_1920x1080_25fps_4000kbps_vp8.webm", "vp8"),
                make_pair("crowd_1920x1080_25fps_4000kbps_av1.webm", "av1"),
                make_pair("crowd_1920x1080_25fps_7300kbps_mpeg2.mp4", "mpeg2"),
                make_pair("crowd_1920x1080_25fps_6000kbps_mpeg4.mp4", "mpeg4"),
                make_pair("crowd_352x288_25fps_6000kbps_h263.3gp", "h263"),
                make_pair("crowd_1920x1080_25fps_6700kbps_h264.ts", "avc"),
                make_pair("crowd_1920x1080_25fps_4000kbps_h265.mkv", "hevc")));

int main(int argc, char **argv) {
    gEnv = new BenchmarkTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("C2 Decoder Test result = %d\n", status);
    }
    return status;
}
