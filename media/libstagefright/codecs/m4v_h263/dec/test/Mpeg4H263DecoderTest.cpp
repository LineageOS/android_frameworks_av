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
#define LOG_TAG "Mpeg4H263DecoderTest"
#include <utils/Log.h>

#include <stdio.h>
#include <string.h>
#include <utils/String8.h>
#include <fstream>

#include <media/stagefright/foundation/AUtils.h>
#include "mp4dec_api.h"

#include "Mpeg4H263DecoderTestEnvironment.h"

using namespace android;

#define OUTPUT_FILE_NAME "/data/local/tmp/Output.yuv"
#define CODEC_CONFIG_FLAG 32
#define SYNC_FRAME 1
#define MPEG4_MAX_WIDTH 1920
#define MPEG4_MAX_HEIGHT 1080
#define H263_MAX_WIDTH 352
#define H263_MAX_HEIGHT 288

constexpr uint32_t kNumOutputBuffers = 2;

struct FrameInfo {
    int32_t bytesCount;
    uint32_t flags;
    int64_t timestamp;
};

struct tagvideoDecControls;

static Mpeg4H263DecoderTestEnvironment *gEnv = nullptr;

class Mpeg4H263DecoderTest : public ::testing::TestWithParam<tuple<string, string, bool>> {
  public:
    Mpeg4H263DecoderTest()
        : mDecHandle(nullptr),
          mInputBuffer(nullptr),
          mInitialized(false),
          mFramesConfigured(false),
          mNumSamplesOutput(0),
          mWidth(352),
          mHeight(288) {
        memset(mOutputBuffer, 0x0, sizeof(mOutputBuffer));
    }

    ~Mpeg4H263DecoderTest() {
        if (mEleStream.is_open()) mEleStream.close();
        if (mDecHandle) {
            delete mDecHandle;
            mDecHandle = nullptr;
        }
        if (mInputBuffer) {
            free(mInputBuffer);
            mInputBuffer = nullptr;
        }
        freeOutputBuffer();
    }

    status_t initDecoder();
    void allocOutputBuffer(size_t outputBufferSize);
    void dumpOutput(ofstream &ostrm);
    void freeOutputBuffer();
    void processMpeg4H263Decoder(vector<FrameInfo> Info, int32_t offset, int32_t range,
                                 ifstream &mEleStream, ofstream &ostrm, MP4DecodingMode inputMode);
    void deInitDecoder();

    ifstream mEleStream;
    tagvideoDecControls *mDecHandle;
    char *mInputBuffer;
    uint8_t *mOutputBuffer[kNumOutputBuffers];
    bool mInitialized;
    bool mFramesConfigured;
    uint32_t mNumSamplesOutput;
    uint32_t mWidth;
    uint32_t mHeight;
};

status_t Mpeg4H263DecoderTest::initDecoder() {
    if (!mDecHandle) {
        mDecHandle = new tagvideoDecControls;
    }
    if (!mDecHandle) {
        return NO_MEMORY;
    }
    memset(mDecHandle, 0, sizeof(tagvideoDecControls));

    return OK;
}

void Mpeg4H263DecoderTest::allocOutputBuffer(size_t outputBufferSize) {
    for (int32_t i = 0; i < kNumOutputBuffers; ++i) {
        if (!mOutputBuffer[i]) {
            mOutputBuffer[i] = (uint8_t *)malloc(outputBufferSize);
            ASSERT_NE(mOutputBuffer[i], nullptr) << "Output buffer allocation failed";
        }
    }
}

void Mpeg4H263DecoderTest::dumpOutput(ofstream &ostrm) {
    uint8_t *src = mOutputBuffer[mNumSamplesOutput & 1];
    size_t vStride = align(mHeight, 16);
    size_t srcYStride = align(mWidth, 16);
    size_t srcUVStride = srcYStride / 2;
    uint8_t *srcStart = src;

    /* Y buffer */
    for (size_t i = 0; i < mHeight; ++i) {
        ostrm.write(reinterpret_cast<char *>(src), mWidth);
        src += srcYStride;
    }
    /* U buffer */
    src = srcStart + vStride * srcYStride;
    for (size_t i = 0; i < mHeight / 2; ++i) {
        ostrm.write(reinterpret_cast<char *>(src), mWidth / 2);
        src += srcUVStride;
    }
    /* V buffer */
    src = srcStart + vStride * srcYStride * 5 / 4;
    for (size_t i = 0; i < mHeight / 2; ++i) {
        ostrm.write(reinterpret_cast<char *>(src), mWidth / 2);
        src += srcUVStride;
    }
}

void Mpeg4H263DecoderTest::freeOutputBuffer() {
    for (int32_t i = 0; i < kNumOutputBuffers; ++i) {
        if (mOutputBuffer[i]) {
            free(mOutputBuffer[i]);
            mOutputBuffer[i] = nullptr;
        }
    }
}

void Mpeg4H263DecoderTest::processMpeg4H263Decoder(vector<FrameInfo> Info, int32_t offset,
                                                   int32_t range, ifstream &mEleStream,
                                                   ofstream &ostrm, MP4DecodingMode inputMode) {
    size_t maxWidth = (inputMode == MPEG4_MODE) ? MPEG4_MAX_WIDTH : H263_MAX_WIDTH;
    size_t maxHeight = (inputMode == MPEG4_MODE) ? MPEG4_MAX_HEIGHT : H263_MAX_HEIGHT;
    size_t outputBufferSize = align(maxWidth, 16) * align(maxHeight, 16) * 3 / 2;
    uint32_t frameIndex = offset;
    bool status = true;
    ASSERT_GE(range, 0) << "Invalid range";
    ASSERT_TRUE(offset >= 0 && offset <= Info.size() - 1) << "Invalid offset";
    ASSERT_LE(range + offset, Info.size()) << "range+offset can't be greater than the no of frames";

    while (1) {
        if (frameIndex == Info.size() || frameIndex == (offset + range)) break;

        int32_t bytesCount = Info[frameIndex].bytesCount;
        ASSERT_GT(bytesCount, 0) << "Size for the memory allocation is negative";
        mInputBuffer = (char *)malloc(bytesCount);
        ASSERT_NE(mInputBuffer, nullptr) << "Insufficient memory to read frame";
        mEleStream.read(mInputBuffer, bytesCount);
        ASSERT_EQ(mEleStream.gcount(), bytesCount) << "mEleStream.gcount() != bytesCount";
        static const uint8_t volInfo[] = {0x00, 0x00, 0x01, 0xB0};
        bool volHeader = memcmp(mInputBuffer, volInfo, 4) == 0;
        if (volHeader) {
            PVCleanUpVideoDecoder(mDecHandle);
            mInitialized = false;
        }

        if (!mInitialized) {
            uint8_t *volData[1]{};
            int32_t volSize = 0;

            uint32_t flags = Info[frameIndex].flags;
            bool codecConfig = flags == CODEC_CONFIG_FLAG;
            if (codecConfig || volHeader) {
                volData[0] = reinterpret_cast<uint8_t *>(mInputBuffer);
                volSize = bytesCount;
            }

            status = PVInitVideoDecoder(mDecHandle, volData, &volSize, 1, maxWidth, maxHeight,
                                        inputMode);
            ASSERT_TRUE(status) << "PVInitVideoDecoder failed. Unsupported content";

            mInitialized = true;
            MP4DecodingMode actualMode = PVGetDecBitstreamMode(mDecHandle);
            ASSERT_EQ(inputMode, actualMode)
                    << "Decoded mode not same as actual mode of the decoder";

            PVSetPostProcType(mDecHandle, 0);

            int32_t dispWidth, dispHeight;
            PVGetVideoDimensions(mDecHandle, &dispWidth, &dispHeight);

            int32_t bufWidth, bufHeight;
            PVGetBufferDimensions(mDecHandle, &bufWidth, &bufHeight);

            ASSERT_LE(dispWidth, bufWidth) << "Display width is greater than buffer width";
            ASSERT_LE(dispHeight, bufHeight) << "Display height is greater than buffer height";

            if (dispWidth != mWidth || dispHeight != mHeight) {
                mWidth = dispWidth;
                mHeight = dispHeight;
                freeOutputBuffer();
                if (inputMode == H263_MODE) {
                    PVCleanUpVideoDecoder(mDecHandle);

                    uint8_t *volData[1]{};
                    int32_t volSize = 0;

                    status = PVInitVideoDecoder(mDecHandle, volData, &volSize, 1, maxWidth,
                                                maxHeight, H263_MODE);
                    ASSERT_TRUE(status) << "PVInitVideoDecoder failed for H263";
                }
                mFramesConfigured = false;
            }

            if (codecConfig) {
                frameIndex++;
                continue;
            }
        }

        uint32_t yFrameSize = sizeof(uint8) * mDecHandle->size;
        ASSERT_GE(outputBufferSize, yFrameSize * 3 / 2)
                << "Too small output buffer: " << outputBufferSize << " bytes";
        ASSERT_NO_FATAL_FAILURE(allocOutputBuffer(outputBufferSize));

        if (!mFramesConfigured) {
            PVSetReferenceYUV(mDecHandle, mOutputBuffer[1]);
            mFramesConfigured = true;
        }

        // Need to check if header contains new info, e.g., width/height, etc.
        VopHeaderInfo headerInfo;
        uint32_t useExtTimestamp = 1;
        int32_t inputSize = (Info)[frameIndex].bytesCount;
        uint32_t timestamp = frameIndex;

        uint8_t *bitstreamTmp = reinterpret_cast<uint8_t *>(mInputBuffer);

        status = PVDecodeVopHeader(mDecHandle, &bitstreamTmp, &timestamp, &inputSize, &headerInfo,
                                   &useExtTimestamp, mOutputBuffer[mNumSamplesOutput & 1]);
        ASSERT_EQ(status, PV_TRUE) << "failed to decode vop header";

        // H263 doesn't have VOL header, the frame size information is in short header, i.e. the
        // decoder may detect size change after PVDecodeVopHeader.
        int32_t dispWidth, dispHeight;
        PVGetVideoDimensions(mDecHandle, &dispWidth, &dispHeight);

        int32_t bufWidth, bufHeight;
        PVGetBufferDimensions(mDecHandle, &bufWidth, &bufHeight);

        ASSERT_LE(dispWidth, bufWidth) << "Display width is greater than buffer width";
        ASSERT_LE(dispHeight, bufHeight) << "Display height is greater than buffer height";
        if (dispWidth != mWidth || dispHeight != mHeight) {
            mWidth = dispWidth;
            mHeight = dispHeight;
        }

        status = PVDecodeVopBody(mDecHandle, &inputSize);
        ASSERT_EQ(status, PV_TRUE) << "failed to decode video frame No = %d" << frameIndex;

        dumpOutput(ostrm);

        ++mNumSamplesOutput;
        ++frameIndex;
    }
    freeOutputBuffer();
}

void Mpeg4H263DecoderTest::deInitDecoder() {
    if (mInitialized) {
        if (mDecHandle) {
            PVCleanUpVideoDecoder(mDecHandle);
            delete mDecHandle;
            mDecHandle = nullptr;
        }
        mInitialized = false;
    }
    freeOutputBuffer();
}

void getInfo(string infoFileName, vector<FrameInfo> &Info) {
    ifstream eleInfo;
    eleInfo.open(infoFileName);
    ASSERT_EQ(eleInfo.is_open(), true) << "Failed to open " << infoFileName;
    int32_t bytesCount = 0;
    uint32_t flags = 0;
    uint32_t timestamp = 0;
    while (1) {
        if (!(eleInfo >> bytesCount)) {
            break;
        }
        eleInfo >> flags;
        eleInfo >> timestamp;
        Info.push_back({bytesCount, flags, timestamp});
    }
    if (eleInfo.is_open()) eleInfo.close();
}

TEST_P(Mpeg4H263DecoderTest, DecodeTest) {
    tuple<string /* InputFileName */, string /* InfoFileName */, bool /* mode */> params =
            GetParam();

    string inputFileName = gEnv->getRes() + get<0>(params);
    mEleStream.open(inputFileName, ifstream::binary);
    ASSERT_EQ(mEleStream.is_open(), true) << "Failed to open " << get<0>(params);

    string infoFileName = gEnv->getRes() + get<1>(params);
    vector<FrameInfo> Info;
    ASSERT_NO_FATAL_FAILURE(getInfo(infoFileName, Info));
    ASSERT_NE(Info.empty(), true) << "Invalid Info file";

    ofstream ostrm;
    ostrm.open(OUTPUT_FILE_NAME, std::ofstream::binary);
    ASSERT_EQ(ostrm.is_open(), true) << "Failed to open output stream for " << get<0>(params);

    status_t err = initDecoder();
    ASSERT_EQ(err, OK) << "initDecoder: failed to create decoder " << err;

    bool isMpeg4 = get<2>(params);
    MP4DecodingMode inputMode = isMpeg4 ? MPEG4_MODE : H263_MODE;
    ASSERT_NO_FATAL_FAILURE(
            processMpeg4H263Decoder(Info, 0, Info.size(), mEleStream, ostrm, inputMode));
    deInitDecoder();
    ostrm.close();
    Info.clear();
}

TEST_P(Mpeg4H263DecoderTest, FlushTest) {
    tuple<string /* InputFileName */, string /* InfoFileName */, bool /* mode */> params =
            GetParam();

    string inputFileName = gEnv->getRes() + get<0>(params);
    mEleStream.open(inputFileName, ifstream::binary);
    ASSERT_EQ(mEleStream.is_open(), true) << "Failed to open " << get<0>(params);

    string infoFileName = gEnv->getRes() + get<1>(params);
    vector<FrameInfo> Info;
    ASSERT_NO_FATAL_FAILURE(getInfo(infoFileName, Info));
    ASSERT_NE(Info.empty(), true) << "Invalid Info file";

    ofstream ostrm;
    ostrm.open(OUTPUT_FILE_NAME, std::ofstream::binary);
    ASSERT_EQ(ostrm.is_open(), true) << "Failed to open output stream for " << get<0>(params);

    status_t err = initDecoder();
    ASSERT_EQ(err, OK) << "initDecoder: failed to create decoder " << err;

    bool isMpeg4 = get<2>(params);
    MP4DecodingMode inputMode = isMpeg4 ? MPEG4_MODE : H263_MODE;
    // Number of frames to be decoded before flush
    int32_t numFrames = Info.size() / 3;
    ASSERT_NO_FATAL_FAILURE(
            processMpeg4H263Decoder(Info, 0, numFrames, mEleStream, ostrm, inputMode));

    if (mInitialized) {
        int32_t status = PVResetVideoDecoder(mDecHandle);
        ASSERT_EQ(status, PV_TRUE);
    }

    // Seek to next key frame and start decoding till the end
    int32_t index = numFrames;
    bool keyFrame = false;
    uint32_t flags = 0;
    while (index < (int32_t)Info.size()) {
        if (Info[index].flags) flags = 1u << (Info[index].flags - 1);
        if ((flags & SYNC_FRAME) == SYNC_FRAME) {
            keyFrame = true;
            break;
        }
        flags = 0;
        mEleStream.ignore(Info[index].bytesCount);
        index++;
    }
    ALOGV("Index= %d", index);
    if (keyFrame) {
        mNumSamplesOutput = 0;
        ASSERT_NO_FATAL_FAILURE(processMpeg4H263Decoder(Info, index, (int32_t)Info.size() - index,
                                                        mEleStream, ostrm, inputMode));
    }
    deInitDecoder();
    ostrm.close();
    Info.clear();
}

INSTANTIATE_TEST_SUITE_P(
        Mpeg4H263DecoderTestAll, Mpeg4H263DecoderTest,
        ::testing::Values(make_tuple("swirl_128x96_h263.h263", "swirl_128x96_h263.info", false),
                          make_tuple("swirl_176x144_h263.h263", "swirl_176x144_h263.info", false),
                          make_tuple("swirl_352x288_h263.h263", "swirl_352x288_h263.info", false),
                          make_tuple("bbb_352x288_h263.h263", "bbb_352x288_h263.info", false),
                          make_tuple("bbb_352x288_mpeg4.m4v", "bbb_352x288_mpeg4.info", true),
                          make_tuple("swirl_128x128_mpeg4.m4v", "swirl_128x128_mpeg4.info", true),
                          make_tuple("swirl_130x132_mpeg4.m4v", "swirl_130x132_mpeg4.info", true),
                          make_tuple("swirl_132x130_mpeg4.m4v", "swirl_132x130_mpeg4.info", true),
                          make_tuple("swirl_136x144_mpeg4.m4v", "swirl_136x144_mpeg4.info", true),
                          make_tuple("swirl_144x136_mpeg4.m4v", "swirl_144x136_mpeg4.info", true)));

int main(int argc, char **argv) {
    gEnv = new Mpeg4H263DecoderTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGD("Decoder Test Result = %d\n", status);
    }
    return status;
}
