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
#define LOG_TAG "MetaDataUtilsTest"
#include <utils/Log.h>

#include <fstream>
#include <string>

#include <ESDS.h>
#include <media/NdkMediaFormat.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaDataBase.h>
#include <media/stagefright/MetaDataUtils.h>
#include <media/stagefright/foundation/ABitReader.h>

#include "MetaDataUtilsTestEnvironment.h"

constexpr uint8_t kAdtsCsdSize = 7;
// from AAC specs: https://www.iso.org/standard/43345.html
constexpr int32_t kSamplingFreq[] = {96000, 88200, 64000, 48000, 44100, 32000,
                                     24000, 22050, 16000, 12000, 11025, 8000};
constexpr uint8_t kMaxSamplingFreqIndex = sizeof(kSamplingFreq) / sizeof(kSamplingFreq[0]);

static MetaDataUtilsTestEnvironment *gEnv = nullptr;

using namespace android;

class MetaDataValidate {
  public:
    MetaDataValidate() : mInputBuffer(nullptr) {}

    ~MetaDataValidate() {
        if (mInputBuffer) {
            delete[] mInputBuffer;
            mInputBuffer = nullptr;
        }
    }

    void SetUpMetaDataValidate(string fileName) {
        struct stat buf;
        int8_t err = stat(fileName.c_str(), &buf);
        ASSERT_EQ(err, 0) << "Failed to get file information for file: " << fileName;

        mInputBufferSize = buf.st_size;
        FILE *inputFilePtr = fopen(fileName.c_str(), "rb+");
        ASSERT_NE(inputFilePtr, nullptr) << "Failed to open file: " << fileName;

        mInputBuffer = new uint8_t[mInputBufferSize];
        ASSERT_NE(mInputBuffer, nullptr)
                << "Failed to allocate memory of size: " << mInputBufferSize;

        int32_t numBytes =
                fread((char *)mInputBuffer, sizeof(uint8_t), mInputBufferSize, inputFilePtr);
        ASSERT_EQ(numBytes, mInputBufferSize) << numBytes << " of " << mInputBufferSize << " read";

        fclose(inputFilePtr);
    }

    size_t mInputBufferSize;
    const uint8_t *mInputBuffer;
};

class AvcCSDTest : public ::testing::TestWithParam<
                           tuple<string /*inputFile*/, size_t /*avcWidth*/, size_t /*avcHeight*/>> {
  public:
    AvcCSDTest() : mInputBuffer(nullptr) {}

    ~AvcCSDTest() {
        if (mInputBuffer) {
            delete[] mInputBuffer;
            mInputBuffer = nullptr;
        }
    }
    virtual void SetUp() override {
        tuple<string, size_t, size_t> params = GetParam();
        string inputFile = gEnv->getRes() + get<0>(params);
        mFrameWidth = get<1>(params);
        mFrameHeight = get<2>(params);

        struct stat buf;
        int8_t err = stat(inputFile.c_str(), &buf);
        ASSERT_EQ(err, 0) << "Failed to get information for file: " << inputFile;

        mInputBufferSize = buf.st_size;
        FILE *inputFilePtr = fopen(inputFile.c_str(), "rb+");
        ASSERT_NE(inputFilePtr, nullptr) << "Failed to open file: " << inputFile;

        mInputBuffer = new uint8_t[mInputBufferSize];
        ASSERT_NE(mInputBuffer, nullptr)
                << "Failed to create a buffer of size: " << mInputBufferSize;

        int32_t numBytes =
                fread((char *)mInputBuffer, sizeof(uint8_t), mInputBufferSize, inputFilePtr);
        ASSERT_EQ(numBytes, mInputBufferSize) << numBytes << " of " << mInputBufferSize << " read";

        fclose(inputFilePtr);
    }

    size_t mFrameWidth;
    size_t mFrameHeight;
    size_t mInputBufferSize;
    const uint8_t *mInputBuffer;
};

class AvcCSDValidateTest : public MetaDataValidate,
                           public ::testing::TestWithParam<string /*inputFile*/> {
  public:
    virtual void SetUp() override {
        string inputFile = gEnv->getRes() + GetParam();

        ASSERT_NO_FATAL_FAILURE(SetUpMetaDataValidate(inputFile));
    }
};

class AacCSDTest
    : public ::testing::TestWithParam<tuple<uint32_t /*profile*/, uint32_t /*samplingFreqIndex*/,
                                            uint32_t /*channelConfig*/>> {
  public:
    virtual void SetUp() override {
        tuple<uint32_t, uint32_t, uint32_t> params = GetParam();
        mAacProfile = get<0>(params);
        mAacSamplingFreqIndex = get<1>(params);
        mAacChannelConfig = get<2>(params);
    }

    uint32_t mAacProfile;
    uint32_t mAacSamplingFreqIndex;
    uint32_t mAacChannelConfig;
};

class AacADTSTest
    : public ::testing::TestWithParam<
              tuple<string /*adtsFile*/, uint32_t /*channelCount*/, uint32_t /*sampleRate*/>> {
  public:
    AacADTSTest() : mInputBuffer(nullptr) {}

    virtual void SetUp() override {
        tuple<string, uint32_t, uint32_t> params = GetParam();
        string fileName = gEnv->getRes() + get<0>(params);
        mAacChannelCount = get<1>(params);
        mAacSampleRate = get<2>(params);

        FILE *filePtr = fopen(fileName.c_str(), "r");
        ASSERT_NE(filePtr, nullptr) << "Failed to open file: " << fileName;

        mInputBuffer = new uint8_t[kAdtsCsdSize];
        ASSERT_NE(mInputBuffer, nullptr) << "Failed to allocate a memory of size: " << kAdtsCsdSize;

        int32_t numBytes = fread((void *)mInputBuffer, sizeof(uint8_t), kAdtsCsdSize, filePtr);
        ASSERT_EQ(numBytes, kAdtsCsdSize)
                << "Failed to read complete file, bytes read: " << numBytes;

        fclose(filePtr);
    }
    int32_t mAacChannelCount;
    int32_t mAacSampleRate;
    const uint8_t *mInputBuffer;
};

class AacCSDValidateTest : public MetaDataValidate,
                           public ::testing::TestWithParam<string /*inputFile*/> {
  public:
    virtual void SetUp() override {
        string inputFile = gEnv->getRes() + GetParam();

        ASSERT_NO_FATAL_FAILURE(SetUpMetaDataValidate(inputFile));
    }
};

class VorbisTest : public ::testing::TestWithParam<pair<string /*fileName*/, string /*infoFile*/>> {
  public:
    virtual void SetUp() override {
        pair<string, string> params = GetParam();
        string inputMediaFile = gEnv->getRes() + params.first;
        mInputFileStream.open(inputMediaFile, ifstream::in);
        ASSERT_TRUE(mInputFileStream.is_open()) << "Failed to open data file: " << inputMediaFile;

        string inputInfoFile = gEnv->getRes() + params.second;
        mInfoFileStream.open(inputInfoFile, ifstream::in);
        ASSERT_TRUE(mInputFileStream.is_open()) << "Failed to open data file: " << inputInfoFile;
        ASSERT_FALSE(inputInfoFile.empty()) << "Empty info file: " << inputInfoFile;
    }

    ~VorbisTest() {
        if (mInputFileStream.is_open()) mInputFileStream.close();
        if (mInfoFileStream.is_open()) mInfoFileStream.close();
    }

    ifstream mInputFileStream;
    ifstream mInfoFileStream;
};

TEST_P(AvcCSDTest, AvcCSDValidationTest) {
    AMediaFormat *csdData = AMediaFormat_new();
    ASSERT_NE(csdData, nullptr) << "Failed to create AMedia format";

    bool status = MakeAVCCodecSpecificData(csdData, mInputBuffer, mInputBufferSize);
    ASSERT_TRUE(status) << "Failed to make AVC CSD from AMediaFormat";

    int32_t avcWidth = -1;
    status = AMediaFormat_getInt32(csdData, AMEDIAFORMAT_KEY_WIDTH, &avcWidth);
    ASSERT_TRUE(status) << "Failed to get avc width";
    ASSERT_EQ(avcWidth, mFrameWidth);

    int32_t avcHeight = -1;
    status = AMediaFormat_getInt32(csdData, AMEDIAFORMAT_KEY_HEIGHT, &avcHeight);
    ASSERT_TRUE(status) << "Failed to get avc height";
    ASSERT_EQ(avcHeight, mFrameHeight);

    const char *mimeType = "";
    status = AMediaFormat_getString(csdData, AMEDIAFORMAT_KEY_MIME, &mimeType);
    ASSERT_TRUE(status) << "Failed to get the mime type";
    ASSERT_STREQ(mimeType, MEDIA_MIMETYPE_VIDEO_AVC);

    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create MetaData Base";

    status = MakeAVCCodecSpecificData(*metaData, mInputBuffer, mInputBufferSize);
    ASSERT_TRUE(status) << "Failed to make AVC CSD from MetaDataBase";

    avcWidth = -1;
    status = metaData->findInt32(kKeyWidth, &avcWidth);
    ASSERT_TRUE(status) << "Failed to find the width";
    ASSERT_EQ(avcWidth, mFrameWidth);

    avcHeight = -1;
    status = metaData->findInt32(kKeyHeight, &avcHeight);
    ASSERT_TRUE(status) << "Failed to find the height";
    ASSERT_EQ(avcHeight, mFrameHeight);

    void *csdAMediaFormatBuffer = nullptr;
    size_t csdAMediaFormatSize;
    status = AMediaFormat_getBuffer(csdData, AMEDIAFORMAT_KEY_CSD_AVC, &csdAMediaFormatBuffer,
                                    &csdAMediaFormatSize);
    ASSERT_TRUE(status) << "Failed to get the CSD from AMediaFormat";
    ASSERT_NE(csdAMediaFormatBuffer, nullptr) << "Invalid CSD from AMediaFormat";

    const void *csdMetaDataBaseBuffer = nullptr;
    size_t csdMetaDataBaseSize = 0;
    uint32_t mediaType;
    status = metaData->findData(kKeyAVCC, &mediaType, &csdMetaDataBaseBuffer, &csdMetaDataBaseSize);
    ASSERT_TRUE(status) << "Failed to get the CSD from MetaDataBase";
    ASSERT_NE(csdMetaDataBaseBuffer, nullptr) << "Invalid CSD from MetaDataBase";
    ASSERT_GT(csdMetaDataBaseSize, 0) << "CSD size must be greater than 0";
    ASSERT_EQ(csdMetaDataBaseSize, csdAMediaFormatSize)
            << "CSD size of MetaData type and AMediaFormat type must be same";

    int32_t result = memcmp(csdAMediaFormatBuffer, csdMetaDataBaseBuffer, csdAMediaFormatSize);
    ASSERT_EQ(result, 0) << "CSD from AMediaFormat and MetaDataBase do not match";

    delete metaData;
    AMediaFormat_delete(csdData);
}

TEST_P(AvcCSDValidateTest, AvcValidateTest) {
    AMediaFormat *csdData = AMediaFormat_new();
    ASSERT_NE(csdData, nullptr) << "Failed to create AMedia format";

    bool status = MakeAVCCodecSpecificData(csdData, mInputBuffer, mInputBufferSize);
    ASSERT_FALSE(status) << "MakeAVCCodecSpecificData with AMediaFormat succeeds with invalid data";

    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create MetaData Base";

    status = MakeAVCCodecSpecificData(*metaData, mInputBuffer, mInputBufferSize);
    ASSERT_FALSE(status) << "MakeAVCCodecSpecificData with MetaDataBase succeeds with invalid data";
}

TEST_P(AacCSDTest, AacCSDValidationTest) {
    AMediaFormat *csdData = AMediaFormat_new();
    ASSERT_NE(csdData, nullptr) << "Failed to create AMedia format";

    ASSERT_GE(mAacSamplingFreqIndex, 0);
    ASSERT_LT(mAacSamplingFreqIndex, kMaxSamplingFreqIndex);
    bool status = MakeAACCodecSpecificData(csdData, mAacProfile, mAacSamplingFreqIndex,
                                           mAacChannelConfig);
    ASSERT_TRUE(status) << "Failed to make AAC CSD from AMediaFormat";

    int32_t sampleRate = -1;
    status = AMediaFormat_getInt32(csdData, AMEDIAFORMAT_KEY_SAMPLE_RATE, &sampleRate);
    ASSERT_TRUE(status) << "Failed to get sample rate";
    ASSERT_EQ(kSamplingFreq[mAacSamplingFreqIndex], sampleRate);

    int32_t channelCount = -1;
    status = AMediaFormat_getInt32(csdData, AMEDIAFORMAT_KEY_CHANNEL_COUNT, &channelCount);
    ASSERT_TRUE(status) << "Failed to get channel count";
    ASSERT_EQ(channelCount, mAacChannelConfig);

    const char *mimeType = "";
    status = AMediaFormat_getString(csdData, AMEDIAFORMAT_KEY_MIME, &mimeType);
    ASSERT_TRUE(status) << "Failed to get the mime type";
    ASSERT_STREQ(mimeType, MEDIA_MIMETYPE_AUDIO_AAC);

    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create MetaData Base";

    status = MakeAACCodecSpecificData(*metaData, mAacProfile, mAacSamplingFreqIndex,
                                      mAacChannelConfig);
    ASSERT_TRUE(status) << "Failed to make AAC CSD from MetaDataBase";

    sampleRate = -1;
    status = metaData->findInt32(kKeySampleRate, &sampleRate);
    ASSERT_TRUE(status) << "Failed to get sampling rate";
    ASSERT_EQ(kSamplingFreq[mAacSamplingFreqIndex], sampleRate);

    channelCount = -1;
    status = metaData->findInt32(kKeyChannelCount, &channelCount);
    ASSERT_TRUE(status) << "Failed to get channel count";
    ASSERT_EQ(channelCount, mAacChannelConfig);

    mimeType = "";
    status = metaData->findCString(kKeyMIMEType, &mimeType);
    ASSERT_TRUE(status) << "Failed to get mime type";
    ASSERT_STREQ(mimeType, MEDIA_MIMETYPE_AUDIO_AAC);

    void *csdAMediaFormatBuffer = nullptr;
    size_t csdAMediaFormatSize = 0;
    status = AMediaFormat_getBuffer(csdData, AMEDIAFORMAT_KEY_CSD_0, &csdAMediaFormatBuffer,
                                    &csdAMediaFormatSize);
    ASSERT_TRUE(status) << "Failed to get the AMediaFormat CSD";
    ASSERT_GT(csdAMediaFormatSize, 0) << "CSD size must be greater than 0";
    ASSERT_NE(csdAMediaFormatBuffer, nullptr) << "Invalid CSD found";

    const void *csdMetaDataBaseBuffer;
    size_t csdMetaDataBaseSize = 0;
    uint32_t mediaType;
    status = metaData->findData(kKeyESDS, &mediaType, &csdMetaDataBaseBuffer, &csdMetaDataBaseSize);
    ASSERT_TRUE(status) << "Failed to get the ESDS data from MetaDataBase";
    ASSERT_GT(csdMetaDataBaseSize, 0) << "CSD size must be greater than 0";

    ESDS esds(csdMetaDataBaseBuffer, csdMetaDataBaseSize);
    status_t result = esds.getCodecSpecificInfo(&csdMetaDataBaseBuffer, &csdMetaDataBaseSize);
    ASSERT_EQ(result, (status_t)OK) << "Failed to get CSD from ESDS data";
    ASSERT_NE(csdMetaDataBaseBuffer, nullptr) << "Invalid CSD found";
    ASSERT_EQ(csdAMediaFormatSize, csdMetaDataBaseSize)
            << "CSD size do not match between AMediaFormat type and MetaDataBase type";

    int32_t memcmpResult =
            memcmp(csdAMediaFormatBuffer, csdMetaDataBaseBuffer, csdAMediaFormatSize);
    ASSERT_EQ(memcmpResult, 0) << "AMediaFormat and MetaDataBase CSDs do not match";

    AMediaFormat_delete(csdData);
    delete metaData;
}

TEST_P(AacADTSTest, AacADTSValidationTest) {
    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create meta data";

    bool status = MakeAACCodecSpecificData(*metaData, mInputBuffer, kAdtsCsdSize);
    ASSERT_TRUE(status) << "Failed to make AAC CSD from MetaDataBase";

    int32_t sampleRate = -1;
    status = metaData->findInt32(kKeySampleRate, &sampleRate);
    ASSERT_TRUE(status) << "Failed to get sampling rate";
    ASSERT_EQ(sampleRate, mAacSampleRate);

    int32_t channelCount = -1;
    status = metaData->findInt32(kKeyChannelCount, &channelCount);
    ASSERT_TRUE(status) << "Failed to get channel count";
    ASSERT_EQ(channelCount, mAacChannelCount);

    const char *mimeType = "";
    status = metaData->findCString(kKeyMIMEType, &mimeType);
    ASSERT_TRUE(status) << "Failed to get mime type";
    ASSERT_STREQ(mimeType, MEDIA_MIMETYPE_AUDIO_AAC);

    delete metaData;
}

TEST_P(AacCSDValidateTest, AacInvalidInputTest) {
    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create meta data";

    bool status = MakeAACCodecSpecificData(*metaData, mInputBuffer, kAdtsCsdSize);
    ASSERT_FALSE(status) << "MakeAACCodecSpecificData succeeds with invalid data";
}

TEST_P(VorbisTest, VorbisCommentTest) {
    string line;
    string tag;
    string key;
    string value;
    size_t commentLength;
    bool status;

    while (getline(mInfoFileStream, line)) {
        istringstream stringLine(line);
        stringLine >> tag >> key >> value >> commentLength;
        ASSERT_GT(commentLength, 0) << "Vorbis comment size must be greater than 0";

        string comment;
        string dataLine;

        getline(mInputFileStream, dataLine);
        istringstream dataStringLine(dataLine);
        dataStringLine >> comment;

        char *buffer = strndup(comment.c_str(), commentLength);
        ASSERT_NE(buffer, nullptr) << "Failed to allocate buffer of size: " << commentLength;

        AMediaFormat *fileMeta = AMediaFormat_new();
        ASSERT_NE(fileMeta, nullptr) << "Failed to create AMedia format";

        parseVorbisComment(fileMeta, buffer, commentLength);
        free(buffer);

        if (!strncasecmp(tag.c_str(), "ANDROID_HAPTIC", sizeof(tag))) {
            int32_t numChannelExpected = stoi(value);
            int32_t numChannelFound = -1;
            status = AMediaFormat_getInt32(fileMeta, key.c_str(), &numChannelFound);
            ASSERT_TRUE(status) << "Failed to get the channel count";
            ASSERT_EQ(numChannelExpected, numChannelFound);
        } else if (!strncasecmp(tag.c_str(), "ANDROID_LOOP", sizeof(tag))) {
            int32_t loopExpected = !value.compare("true");
            int32_t loopFound = -1;

            status = AMediaFormat_getInt32(fileMeta, "loop", &loopFound);
            ASSERT_TRUE(status) << "Failed to get the loop count";
            ASSERT_EQ(loopExpected, loopFound);
        } else {
            const char *tagValue = "";
            status = AMediaFormat_getString(fileMeta, key.c_str(), &tagValue);
            ASSERT_TRUE(status) << "Failed to get the tag value";
            ASSERT_STREQ(value.c_str(), tagValue);
        }
        AMediaFormat_delete(fileMeta);
    }
}

INSTANTIATE_TEST_SUITE_P(MetaDataUtilsTestAll, AvcCSDTest,
                         ::testing::Values(make_tuple("sps_pps_userdata.h264", 8, 8),
                                           make_tuple("sps_userdata_pps.h264", 8, 8),
                                           make_tuple("sps_pps_sps_pps.h264", 8, 8)));

// TODO(b/158067691): Add invalid test vectors with incomplete PPS or no PPS
INSTANTIATE_TEST_SUITE_P(MetaDataUtilsTestAll, AvcCSDValidateTest,
                         ::testing::Values("sps_pps_only_startcode.h264",
                                           "sps_incomplete_pps.h264",
                                           // TODO(b/158067691) "sps_pps_incomplete.h264",
                                           "randomdata.h264",
                                           // TODO(b/158067691) "sps.h264",
                                           "pps.h264"));

INSTANTIATE_TEST_SUITE_P(MetaDataUtilsTestAll, AacCSDTest,
                         ::testing::Values(make_tuple(AACObjectMain, 1, 1)));

INSTANTIATE_TEST_SUITE_P(MetaDataUtilsTestAll, AacADTSTest,
                         ::testing::Values(make_tuple("loudsoftaacadts", 1, 44100)));

INSTANTIATE_TEST_SUITE_P(MetaDataUtilsTestAll, AacCSDValidateTest,
                         ::testing::Values("loudsoftaacadts_invalidheader",
                                           "loudsoftaacadts_invalidprofile",
                                           "loudsoftaacadts_invalidchannelconfig"));

// TODO(b/157974508) Add test vector for vorbis thumbnail tag
// Info file contains TAG, Key, Value and size of the vorbis comment
INSTANTIATE_TEST_SUITE_P(
        MetaDataUtilsTestAll, VorbisTest,
        ::testing::Values(make_pair("vorbiscomment_sintel.dat", "vorbiscomment_sintel.info"),
                          make_pair("vorbiscomment_album.dat", "vorbiscomment_album.info"),
                          make_pair("vorbiscomment_loop.dat", "vorbiscomment_loop.info")));

int main(int argc, char **argv) {
    gEnv = new MetaDataUtilsTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
