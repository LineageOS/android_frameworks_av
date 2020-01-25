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
#define LOG_TAG "Mp3DecoderTest"

#include <utils/Log.h>

#include <audio_utils/sndfile.h>
#include <stdio.h>

#include "mp3reader.h"
#include "pvmp3decoder_api.h"

#include "Mp3DecoderTestEnvironment.h"

#define OUTPUT_FILE "/data/local/tmp/mp3Decode.out"

constexpr int32_t kInputBufferSize = 1024 * 10;
constexpr int32_t kOutputBufferSize = 4608 * 2;
constexpr int32_t kMaxCount = 10;
constexpr int32_t kNumFrameReset = 150;

static Mp3DecoderTestEnvironment *gEnv = nullptr;

class Mp3DecoderTest : public ::testing::TestWithParam<string> {
  public:
    Mp3DecoderTest() : mConfig(nullptr) {}

    ~Mp3DecoderTest() {
        if (mConfig) {
            delete mConfig;
            mConfig = nullptr;
        }
    }

    virtual void SetUp() override {
        mConfig = new tPVMP3DecoderExternal{};
        ASSERT_NE(mConfig, nullptr) << "Failed to initialize config. No Memory available";
        mConfig->equalizerType = flat;
        mConfig->crcEnabled = false;
    }

    tPVMP3DecoderExternal *mConfig;
    Mp3Reader mMp3Reader;

    ERROR_CODE DecodeFrames(void *decoderbuf, SNDFILE *outFileHandle, SF_INFO sfInfo,
                            int32_t frameCount = INT32_MAX);
    SNDFILE *openOutputFile(SF_INFO *sfInfo);
};

ERROR_CODE Mp3DecoderTest::DecodeFrames(void *decoderBuf, SNDFILE *outFileHandle, SF_INFO sfInfo,
                                        int32_t frameCount) {
    uint8_t inputBuf[kInputBufferSize];
    int16_t outputBuf[kOutputBufferSize];
    uint32_t bytesRead;
    ERROR_CODE decoderErr;
    while (frameCount > 0) {
        bool success = mMp3Reader.getFrame(inputBuf, &bytesRead);
        if (!success) {
            break;
        }
        mConfig->inputBufferCurrentLength = bytesRead;
        mConfig->inputBufferMaxLength = 0;
        mConfig->inputBufferUsedLength = 0;
        mConfig->pInputBuffer = inputBuf;
        mConfig->pOutputBuffer = outputBuf;
        mConfig->outputFrameSize = kOutputBufferSize / sizeof(int16_t);
        decoderErr = pvmp3_framedecoder(mConfig, decoderBuf);
        if (decoderErr != NO_DECODING_ERROR) break;
        sf_writef_short(outFileHandle, outputBuf, mConfig->outputFrameSize / sfInfo.channels);
        frameCount--;
    }
    return decoderErr;
}

SNDFILE *Mp3DecoderTest::openOutputFile(SF_INFO *sfInfo) {
    memset(sfInfo, 0, sizeof(SF_INFO));
    sfInfo->channels = mMp3Reader.getNumChannels();
    sfInfo->format = SF_FORMAT_WAV | SF_FORMAT_PCM_16;
    sfInfo->samplerate = mMp3Reader.getSampleRate();
    SNDFILE *outFileHandle = sf_open(OUTPUT_FILE, SFM_WRITE, sfInfo);
    return outFileHandle;
}

TEST_F(Mp3DecoderTest, MultiCreateMp3DecoderTest) {
    size_t memRequirements = pvmp3_decoderMemRequirements();
    ASSERT_NE(memRequirements, 0) << "Failed to get the memory requirement size";
    void *decoderBuf = malloc(memRequirements);
    ASSERT_NE(decoderBuf, nullptr)
            << "Failed to allocate decoder memory of size " << memRequirements;
    for (int count = 0; count < kMaxCount; count++) {
        pvmp3_InitDecoder(mConfig, decoderBuf);
        ALOGV("Decoder created successfully");
    }
    if (decoderBuf) {
        free(decoderBuf);
        decoderBuf = nullptr;
    }
}

TEST_P(Mp3DecoderTest, DecodeTest) {
    size_t memRequirements = pvmp3_decoderMemRequirements();
    ASSERT_NE(memRequirements, 0) << "Failed to get the memory requirement size";
    void *decoderBuf = malloc(memRequirements);
    ASSERT_NE(decoderBuf, nullptr)
            << "Failed to allocate decoder memory of size " << memRequirements;

    pvmp3_InitDecoder(mConfig, decoderBuf);
    ALOGV("Decoder created successfully");
    string inputFile = gEnv->getRes() + GetParam();
    bool status = mMp3Reader.init(inputFile.c_str());
    ASSERT_TRUE(status) << "Unable to initialize the mp3Reader";

    // Open the output file.
    SF_INFO sfInfo;
    SNDFILE *outFileHandle = openOutputFile(&sfInfo);
    ASSERT_NE(outFileHandle, nullptr) << "Error opening output file for writing decoded output";

    ERROR_CODE decoderErr = DecodeFrames(decoderBuf, outFileHandle, sfInfo);
    ASSERT_EQ(decoderErr, NO_DECODING_ERROR) << "Failed to decode the frames";
    ASSERT_EQ(sfInfo.channels, mConfig->num_channels) << "Number of channels does not match";
    ASSERT_EQ(sfInfo.samplerate, mConfig->samplingRate) << "Sample rate does not match";

    mMp3Reader.close();
    sf_close(outFileHandle);
    if (decoderBuf) {
        free(decoderBuf);
        decoderBuf = nullptr;
    }
}

TEST_P(Mp3DecoderTest, ResetDecoderTest) {
    size_t memRequirements = pvmp3_decoderMemRequirements();
    ASSERT_NE(memRequirements, 0) << "Failed to get the memory requirement size";
    void *decoderBuf = malloc(memRequirements);
    ASSERT_NE(decoderBuf, nullptr)
            << "Failed to allocate decoder memory of size " << memRequirements;

    pvmp3_InitDecoder(mConfig, decoderBuf);
    ALOGV("Decoder created successfully.");
    string inputFile = gEnv->getRes() + GetParam();
    bool status = mMp3Reader.init(inputFile.c_str());
    ASSERT_TRUE(status) << "Unable to initialize the mp3Reader";

    // Open the output file.
    SF_INFO sfInfo;
    SNDFILE *outFileHandle = openOutputFile(&sfInfo);
    ASSERT_NE(outFileHandle, nullptr) << "Error opening output file for writing decoded output";

    ERROR_CODE decoderErr;
    decoderErr = DecodeFrames(decoderBuf, outFileHandle, sfInfo, kNumFrameReset);
    ASSERT_EQ(decoderErr, NO_DECODING_ERROR) << "Failed to decode the frames";
    ASSERT_EQ(sfInfo.channels, mConfig->num_channels) << "Number of channels does not match";
    ASSERT_EQ(sfInfo.samplerate, mConfig->samplingRate) << "Sample rate does not match";

    pvmp3_resetDecoder(decoderBuf);
    // Decode the same file.
    decoderErr = DecodeFrames(decoderBuf, outFileHandle, sfInfo);
    ASSERT_EQ(decoderErr, NO_DECODING_ERROR) << "Failed to decode the frames";
    ASSERT_EQ(sfInfo.channels, mConfig->num_channels) << "Number of channels does not match";
    ASSERT_EQ(sfInfo.samplerate, mConfig->samplingRate) << "Sample rate does not match";

    mMp3Reader.close();
    sf_close(outFileHandle);
    if (decoderBuf) {
        free(decoderBuf);
        decoderBuf = nullptr;
    }
}

INSTANTIATE_TEST_SUITE_P(Mp3DecoderTestAll, Mp3DecoderTest,
                         ::testing::Values(("bbb_44100hz_2ch_128kbps_mp3_30sec.mp3"),
                                           ("bbb_44100hz_2ch_128kbps_mp3_5mins.mp3"),
                                           ("bbb_mp3_stereo_192kbps_48000hz.mp3")));

int main(int argc, char **argv) {
    gEnv = new Mp3DecoderTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
