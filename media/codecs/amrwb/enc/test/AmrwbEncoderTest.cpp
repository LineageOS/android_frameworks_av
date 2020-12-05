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
#define LOG_TAG "AmrwbEncoderTest"

#include <utils/Log.h>

#include <stdio.h>

#include "cmnMemory.h"
#include "voAMRWB.h"

#include "AmrwbEncTestEnvironment.h"

#define OUTPUT_FILE "/data/local/tmp/amrwbEncode.out"
#define VOAMRWB_RFC3267_HEADER_INFO "#!AMR-WB\n"

constexpr int32_t kInputBufferSize = 640;
constexpr int32_t kOutputBufferSize = 1024;

static AmrwbEncTestEnvironment *gEnv = nullptr;

class AmrwbEncoderTest : public ::testing::TestWithParam<tuple<string, int32_t, VOAMRWBFRAMETYPE>> {
  public:
    AmrwbEncoderTest() : mEncoderHandle(nullptr) {
        tuple<string, int32_t, VOAMRWBFRAMETYPE> params = GetParam();
        mInputFile = gEnv->getRes() + get<0>(params);
        mMode = get<1>(params);
        mFrameType = get<2>(params);
        mMemOperator.Alloc = cmnMemAlloc;
        mMemOperator.Copy = cmnMemCopy;
        mMemOperator.Free = cmnMemFree;
        mMemOperator.Set = cmnMemSet;
        mMemOperator.Check = cmnMemCheck;

        mUserData.memflag = VO_IMF_USERMEMOPERATOR;
        mUserData.memData = (VO_PTR)(&mMemOperator);
    }

    ~AmrwbEncoderTest() {
        if (mEncoderHandle) {
            mEncoderHandle = nullptr;
        }
    }

    string mInputFile;
    unsigned char mOutputBuf[kOutputBufferSize];
    unsigned char mInputBuf[kInputBufferSize];
    VOAMRWBFRAMETYPE mFrameType;
    VO_AUDIO_CODECAPI mApiHandle;
    VO_MEM_OPERATOR mMemOperator;
    VO_CODEC_INIT_USERDATA mUserData;
    VO_HANDLE mEncoderHandle;
    int32_t mMode;
};

TEST_P(AmrwbEncoderTest, CreateAmrwbEncoderTest) {
    int32_t status = voGetAMRWBEncAPI(&mApiHandle);
    ASSERT_EQ(status, VO_ERR_NONE) << "Failed to get api handle";

    status = mApiHandle.Init(&mEncoderHandle, VO_AUDIO_CodingAMRWB, &mUserData);
    ASSERT_EQ(status, VO_ERR_NONE) << "Failed to init AMRWB encoder";

    status = mApiHandle.SetParam(mEncoderHandle, VO_PID_AMRWB_FRAMETYPE, &mFrameType);
    ASSERT_EQ(status, VO_ERR_NONE) << "Failed to set AMRWB encoder frame type to " << mFrameType;

    status = mApiHandle.SetParam(mEncoderHandle, VO_PID_AMRWB_MODE, &mMode);
    ASSERT_EQ(status, VO_ERR_NONE) << "Failed to set AMRWB encoder mode to %d" << mMode;
    ALOGV("AMR-WB encoder created successfully");

    status = mApiHandle.Uninit(mEncoderHandle);
    ASSERT_EQ(status, VO_ERR_NONE) << "Failed to delete AMRWB encoder";
    ALOGV("AMR-WB encoder deleted successfully");
}

TEST_P(AmrwbEncoderTest, AmrwbEncodeTest) {
    VO_CODECBUFFER inData;
    VO_CODECBUFFER outData;
    VO_AUDIO_OUTPUTINFO outFormat;

    FILE *fpInput = fopen(mInputFile.c_str(), "rb");
    ASSERT_NE(fpInput, nullptr) << "Error opening input file " << mInputFile;

    FILE *fpOutput = fopen(OUTPUT_FILE, "wb");
    ASSERT_NE(fpOutput, nullptr) << "Error opening output file " << OUTPUT_FILE;

    uint32_t status = voGetAMRWBEncAPI(&mApiHandle);
    ASSERT_EQ(status, VO_ERR_NONE) << "Failed to get api handle";

    status = mApiHandle.Init(&mEncoderHandle, VO_AUDIO_CodingAMRWB, &mUserData);
    ASSERT_EQ(status, VO_ERR_NONE) << "Failed to init AMRWB encoder";

    status = mApiHandle.SetParam(mEncoderHandle, VO_PID_AMRWB_FRAMETYPE, &mFrameType);
    ASSERT_EQ(status, VO_ERR_NONE) << "Failed to set AMRWB encoder frame type to " << mFrameType;

    status = mApiHandle.SetParam(mEncoderHandle, VO_PID_AMRWB_MODE, &mMode);
    ASSERT_EQ(status, VO_ERR_NONE) << "Failed to set AMRWB encoder mode to " << mMode;

    if (mFrameType == VOAMRWB_RFC3267) {
        /* write RFC3267 Header info to indicate single channel AMR file storage format */
        int32_t size = strlen(VOAMRWB_RFC3267_HEADER_INFO);
        memcpy(mOutputBuf, VOAMRWB_RFC3267_HEADER_INFO, size);
        fwrite(mOutputBuf, 1, size, fpOutput);
    }

    int32_t frameNum = 0;
    while (1) {
        int32_t buffLength =
                (int32_t)fread(mInputBuf, sizeof(signed char), kInputBufferSize, fpInput);

        if (buffLength == 0 || feof(fpInput)) break;
        ASSERT_EQ(buffLength, kInputBufferSize) << "Error in reading input file";

        inData.Buffer = (unsigned char *)mInputBuf;
        inData.Length = buffLength;
        outData.Buffer = mOutputBuf;
        status = mApiHandle.SetInputData(mEncoderHandle, &inData);
        ASSERT_EQ(status, VO_ERR_NONE) << "Failed to setup Input data";

        do {
            status = mApiHandle.GetOutputData(mEncoderHandle, &outData, &outFormat);
            ASSERT_NE(status, VO_ERR_LICENSE_ERROR) << "Failed to encode the file";
            if (status == 0) {
                frameNum++;
                fwrite(outData.Buffer, 1, outData.Length, fpOutput);
                fflush(fpOutput);
            }
        } while (status != VO_ERR_INPUT_BUFFER_SMALL);
    }

    ALOGV("Number of frames processed: %d", frameNum);
    status = mApiHandle.Uninit(mEncoderHandle);
    ASSERT_EQ(status, VO_ERR_NONE) << "Failed to delete AMRWB encoder";

    if (fpInput) {
        fclose(fpInput);
    }
    if (fpOutput) {
        fclose(fpOutput);
    }
}

INSTANTIATE_TEST_SUITE_P(
        AmrwbEncoderTestAll, AmrwbEncoderTest,
        ::testing::Values(
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD66, VOAMRWB_DEFAULT),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD885, VOAMRWB_DEFAULT),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1265, VOAMRWB_DEFAULT),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1425, VOAMRWB_DEFAULT),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1585, VOAMRWB_DEFAULT),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1825, VOAMRWB_DEFAULT),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1985, VOAMRWB_DEFAULT),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD2305, VOAMRWB_DEFAULT),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD2385, VOAMRWB_DEFAULT),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD66, VOAMRWB_ITU),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD885, VOAMRWB_ITU),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1265, VOAMRWB_ITU),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1425, VOAMRWB_ITU),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1585, VOAMRWB_ITU),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1825, VOAMRWB_ITU),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1985, VOAMRWB_ITU),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD2305, VOAMRWB_ITU),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD2385, VOAMRWB_ITU),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD66, VOAMRWB_RFC3267),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD885, VOAMRWB_RFC3267),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1265, VOAMRWB_RFC3267),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1425, VOAMRWB_RFC3267),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1585, VOAMRWB_RFC3267),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1825, VOAMRWB_RFC3267),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD1985, VOAMRWB_RFC3267),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD2305, VOAMRWB_RFC3267),
                make_tuple("bbb_raw_1ch_16khz_s16le.raw", VOAMRWB_MD2385, VOAMRWB_RFC3267)));

int main(int argc, char **argv) {
    gEnv = new AmrwbEncTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
