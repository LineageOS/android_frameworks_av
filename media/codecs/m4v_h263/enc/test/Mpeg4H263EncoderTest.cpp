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

//#define LOG_NDEBUG 0
#define LOG_TAG "Mpeg4H263EncoderTest"
#include <utils/Log.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "mp4enc_api.h"

#include "Mpeg4H263EncoderTestEnvironment.h"

#define ENCODED_FILE "/data/local/tmp/Mpeg4H263Output"

// assuming a worst case compression of 2X
constexpr int16_t kCompressionRatio = 2;
constexpr int8_t kIDRFrameRefreshIntervalInSec = 1;

static Mpeg4H263EncoderTestEnvironment *gEnv = nullptr;

class Mpeg4H263EncoderTest
    : public ::testing::TestWithParam<tuple<string, bool, int32_t, int32_t, float, int32_t>> {
  private:
    void initEncoderParams();

  public:
    Mpeg4H263EncoderTest()
        : mInputBuffer(nullptr),
          mOutputBuffer(nullptr),
          mFpInput(nullptr),
          mFpOutput(nullptr),
          mEncodeHandle(nullptr),
          mEncodeControl(nullptr) {}

    ~Mpeg4H263EncoderTest() {
        if(mFpInput) {
            fclose(mFpInput);
        }
        if(mFpOutput) {
            fclose(mFpOutput);
        }
        if(mInputBuffer) free(mInputBuffer);
        if(mOutputBuffer) free(mOutputBuffer);
        if(mEncodeHandle) free(mEncodeHandle);
        if(mEncodeControl) free(mEncodeControl);
    }

    void SetUp() override {
        tuple<string /* fileName */, bool /* isMpeg4 */, int32_t /* frameWidth */,
          int32_t /* frameHeight */, float /* frameRate */, int32_t /* bitRate */>
            params = GetParam();
        mFileName = gEnv->getRes() + get<0>(params);
        mIsMpeg4 = get<1>(params);
        mFrameWidth = get<2>(params);
        mFrameHeight = get<3>(params);
        mFrameRate = get<4>(params);
        mBitRate = get<5>(params);

        ASSERT_TRUE(mFrameWidth % 16 == 0) << "Frame Width should be multiple of 16";
        ASSERT_TRUE(mFrameHeight % 16 == 0) << "Frame Height should be multiple of 16";
        ASSERT_LE(mFrameWidth, (mIsMpeg4 ? 720 : 352))
                << "Frame Width <= 720 for Mpeg4 and <= 352 for H263";
        ASSERT_LE(mFrameHeight, (mIsMpeg4 ? 480 : 288))
                << "Frame Height <= 480 for Mpeg4 and <= 288 for H263";
        ASSERT_LE(mFrameRate, 30) << "Frame rate less than or equal to 30";
        ASSERT_LE(mBitRate, 2048) << "Bit rate less than or equal to 2048 kbps";

        mOutputBufferSize = ( mFrameWidth * mFrameHeight * 3/2 ) / kCompressionRatio;
        mEncodeHandle = new VideoEncOptions;
        ASSERT_NE(mEncodeHandle, nullptr) << "Failed to get Video Encoding options object";
        memset(mEncodeHandle, 0, sizeof(VideoEncOptions));
        mEncodeControl = new VideoEncControls;
        ASSERT_NE(mEncodeControl, nullptr) << "Failed to get Video Encoding control object";
        memset(mEncodeControl, 0, sizeof(VideoEncControls));
        ASSERT_NO_FATAL_FAILURE(initEncoderParams())
                << "Failed to get the default Encoding parameters!";
    }

    int64_t getTotalFrames();
    void processEncoder(int32_t);
    bool mIsMpeg4;
    int32_t mFrameWidth, mFrameHeight, mBitRate;
    int64_t mOutputBufferSize;
    float mFrameRate;
    string mFileName;
    uint8_t *mInputBuffer, *mOutputBuffer;
    FILE *mFpInput, *mFpOutput;
    VideoEncOptions *mEncodeHandle;
    VideoEncControls *mEncodeControl;
};

void Mpeg4H263EncoderTest::initEncoderParams() {
    bool status = PVGetDefaultEncOption(mEncodeHandle, 0);
    ASSERT_TRUE(status);

    mEncodeHandle->rcType = VBR_1;
    mEncodeHandle->vbvDelay = 5.0f;
    mEncodeHandle->profile_level = CORE_PROFILE_LEVEL2;
    mEncodeHandle->packetSize = 32;
    mEncodeHandle->rvlcEnable = PV_OFF;
    mEncodeHandle->numLayers = 1;
    mEncodeHandle->timeIncRes = 1000;
    mEncodeHandle->iQuant[0] = 15;
    mEncodeHandle->pQuant[0] = 12;
    mEncodeHandle->quantType[0] = 0;
    mEncodeHandle->noFrameSkipped = PV_OFF;
    mEncodeHandle->numIntraMB = 0;
    mEncodeHandle->sceneDetect = PV_ON;
    mEncodeHandle->searchRange = 16;
    mEncodeHandle->mv8x8Enable = PV_OFF;
    mEncodeHandle->gobHeaderInterval = 0;
    mEncodeHandle->useACPred = PV_ON;
    mEncodeHandle->intraDCVlcTh = 0;
    if(!mIsMpeg4) {
        mEncodeHandle->encMode = H263_MODE;
    } else {
        mEncodeHandle->encMode = COMBINE_MODE_WITH_ERR_RES;
    }
    mEncodeHandle->encWidth[0] = mFrameWidth;
    mEncodeHandle->encHeight[0] = mFrameHeight;
    mEncodeHandle->encFrameRate[0] = mFrameRate;
    mEncodeHandle->bitRate[0] = mBitRate * 1024;
    mEncodeHandle->tickPerSrc = mEncodeHandle->timeIncRes / mFrameRate;
    if (kIDRFrameRefreshIntervalInSec == 0) {
        // All I frames.
        mEncodeHandle->intraPeriod = 1;
    } else {
        mEncodeHandle->intraPeriod = (kIDRFrameRefreshIntervalInSec * mFrameRate);
    }
}

int64_t Mpeg4H263EncoderTest::getTotalFrames() {
    int32_t frameSize = (mFrameWidth * mFrameHeight * 3) / 2;
    struct stat buf;
    stat(mFileName.c_str(), &buf);
    size_t fileSize = buf.st_size;
    int64_t totalFrames = (int64_t)(fileSize/frameSize);
    return totalFrames;
}

void Mpeg4H263EncoderTest::processEncoder(int32_t numFramesToEncode) {
    bool status;
    int64_t numEncodedFrames = 0;
    int32_t bytesRead;
    int32_t frameSize = (mFrameWidth * mFrameHeight * 3) / 2;
    while(numFramesToEncode != 0) {
        bytesRead = fread(mInputBuffer, 1, frameSize, mFpInput);
        // End of file.
        if (bytesRead != frameSize) {
            break;
        }

        VideoEncFrameIO videoIn, videoOut;
        videoIn.height = mFrameHeight;
        videoIn.pitch = mFrameWidth;
        videoIn.timestamp = (numEncodedFrames * 1000) / mFrameRate;  // in ms.
        videoIn.yChan = mInputBuffer;
        videoIn.uChan = videoIn.yChan + videoIn.height * videoIn.pitch;
        videoIn.vChan = videoIn.uChan + ((videoIn.height * videoIn.pitch) >> 2);
        uint32_t modTimeMs = 0;
        int32_t dataLength = mOutputBufferSize;
        int32_t nLayer = 0;
        status = PVEncodeVideoFrame(mEncodeControl, &videoIn, &videoOut, &modTimeMs, mOutputBuffer,
                                    &dataLength, &nLayer);
        ASSERT_TRUE(status) << "Failed to Encode: " << mFileName;

        MP4HintTrack hintTrack;
        status = PVGetHintTrack(mEncodeControl, &hintTrack);
        ASSERT_TRUE(status) << "Failed to get hint track!";
        UChar *overrunBuffer = PVGetOverrunBuffer(mEncodeControl);
        ASSERT_EQ(overrunBuffer, nullptr) << "Overrun of buffer!";

        int64_t numBytes = fwrite(mOutputBuffer, 1, dataLength, mFpOutput);
        ASSERT_EQ(numBytes, dataLength) << "Failed to write to the output file!";
        numEncodedFrames++;
        numFramesToEncode--;
    }
}

TEST_P(Mpeg4H263EncoderTest, EncodeTest) {
    mInputBuffer = (uint8_t *)malloc((mFrameWidth * mFrameWidth * 3) / 2);
    ASSERT_NE(mInputBuffer, nullptr) << "Failed to allocate the input buffer!";

    mOutputBuffer = (uint8_t *)malloc(mOutputBufferSize);
    ASSERT_NE(mOutputBuffer, nullptr) << "Failed to allocate the output buffer!";

    mFpInput = fopen(mFileName.c_str(), "rb");
    ASSERT_NE(mFpInput, nullptr) << "Failed to open the input file: " << mFileName;

    mFpOutput = fopen(ENCODED_FILE, "wb");
    ASSERT_NE(mFpOutput, nullptr) << "Failed to open the output file:" << ENCODED_FILE;

    bool status = PVInitVideoEncoder(mEncodeControl, mEncodeHandle);
    ASSERT_TRUE(status) << "Failed to initialize the encoder!";

    // Get VOL header.
    int32_t size = mOutputBufferSize;
    status = PVGetVolHeader(mEncodeControl, mOutputBuffer, &size, 0);
    ASSERT_TRUE(status) << "Failed to get the VOL header!";

    // Write the VOL header on the first frame.
    int32_t numBytes = fwrite(mOutputBuffer, 1, size, mFpOutput);
    ASSERT_EQ(numBytes, size) << "Failed to write the VOL header!";

    int64_t totalFrames = getTotalFrames();
    ASSERT_NO_FATAL_FAILURE(processEncoder(totalFrames)) << "Failed to Encode: " << mFileName;
    status = PVCleanUpVideoEncoder(mEncodeControl);
    ASSERT_TRUE(status) << "Failed to clean up the encoder resources!";
}

INSTANTIATE_TEST_SUITE_P(
        EncodeTest, Mpeg4H263EncoderTest,
        ::testing::Values(
                make_tuple("bbb_352x288_420p_30fps_32frames.yuv", false, 352, 288, 25, 1024),
                make_tuple("bbb_352x288_420p_30fps_32frames.yuv", true, 352, 288, 25, 1024),
                make_tuple("bbb_352x288_420p_30fps_32frames.yuv", false, 176, 144, 25, 1024),
                make_tuple("bbb_352x288_420p_30fps_32frames.yuv", true, 176, 144, 25, 1024),
                make_tuple("football_qvga.yuv", false, 352, 288, 25, 1024),
                make_tuple("football_qvga.yuv", true, 352, 288, 25, 1024),
                make_tuple("football_qvga.yuv", false, 176, 144, 30, 1024),
                make_tuple("football_qvga.yuv", true, 176, 144, 30, 1024)));

int32_t main(int argc, char **argv) {
    gEnv = new Mpeg4H263EncoderTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    uint8_t status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGI("Encoder Test Result = %d\n", status);
    }
    return status;
}
