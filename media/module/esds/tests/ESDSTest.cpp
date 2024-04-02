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
#define LOG_TAG "ESDSTest"
#include <utils/Log.h>

#include <stdio.h>
#include <string.h>
#include <fstream>
#include <memory>

#include <media/esds/ESDS.h>
#include <binder/ProcessState.h>
#include <datasource/FileSource.h>
#include <media/stagefright/MediaExtractorFactory.h>
#include <media/stagefright/MetaData.h>

#include "ESDSTestEnvironment.h"

using namespace android;

static ESDSTestEnvironment *gEnv = nullptr;

struct ESDSParams {
    const char *inputFile;
    int32_t objectTypeIndication;
    const char *codecSpecificInfoData;
    int32_t codecSpecificInfoDataSize;
    int32_t bitrateMax;
    int32_t bitrateAvg;
};

class ESDSUnitTest : public ::testing::TestWithParam<tuple<
                             /* InputFile */ const char *,
                             /* ObjectTypeIndication */ int32_t,
                             /* CodecSpecificInfoData */ const char *,
                             /* CodecSpecificInfoDataSize */ int32_t,
                             /* BitrateMax */ int32_t,
                             /* BitrateAvg */ int32_t>> {
  public:
    ESDSUnitTest() {
        mESDSParams.inputFile = get<0>(GetParam());
        mESDSParams.objectTypeIndication = get<1>(GetParam());
        mESDSParams.codecSpecificInfoData = get<2>(GetParam());
        mESDSParams.codecSpecificInfoDataSize = get<3>(GetParam());
        mESDSParams.bitrateMax = get<4>(GetParam());
        mESDSParams.bitrateAvg = get<5>(GetParam());
    };

    ~ESDSUnitTest() {
        if (mESDSData != nullptr) {
            free(mESDSData);
            mESDSData = nullptr;
        }
    }

    virtual void TearDown() override {
        if (mDataSource) mDataSource.clear();
        if (mInputFp) {
            fclose(mInputFp);
            mInputFp = nullptr;
        }
    }

    virtual void SetUp() override { ASSERT_NO_FATAL_FAILURE(readESDSData()); }
    void *mESDSData = nullptr;
    size_t mESDSSize = 0;
    ESDSParams mESDSParams;

  private:
    void readESDSData() {
        string inputFile = gEnv->getRes() + mESDSParams.inputFile;
        mInputFp = fopen(inputFile.c_str(), "rb");
        ASSERT_NE(mInputFp, nullptr) << "File open failed for file: " << inputFile;
        int32_t fd = fileno(mInputFp);
        ASSERT_GE(fd, 0) << "File descriptor invalid for file: " << inputFile;

        struct stat buf;
        status_t status = stat(inputFile.c_str(), &buf);
        ASSERT_EQ(status, 0) << "Failed to get properties of input file: " << mESDSParams.inputFile;
        size_t fileSize = buf.st_size;

        mDataSource = new FileSource(dup(fd), 0, fileSize);
        ASSERT_NE(mDataSource, nullptr) << "Unable to create data source for file: " << inputFile;

        sp<IMediaExtractor> extractor = MediaExtractorFactory::Create(mDataSource);
        if (extractor == nullptr) {
            mDataSource.clear();
            ASSERT_TRUE(false) << "Unable to create extractor for file: " << inputFile;
        }

        size_t numTracks = extractor->countTracks();
        ASSERT_GT(numTracks, 0) << "No tracks in file: " << inputFile;
        ASSERT_TRUE(esdsDataPresent(numTracks, extractor))
                << "Unable to find esds in any track in file: " << inputFile;
    }

    bool esdsDataPresent(size_t numTracks, sp<IMediaExtractor> extractor) {
        bool foundESDS = false;
        uint32_t type;
        if (mESDSData != nullptr) {
            free(mESDSData);
            mESDSData = nullptr;
        }
        for (size_t i = 0; i < numTracks; ++i) {
            sp<MetaData> trackMeta = extractor->getTrackMetaData(i);
            const void *esdsData = nullptr;
            size_t esdsSize = 0;
            if (trackMeta != nullptr &&
                trackMeta->findData(kKeyESDS, &type, &esdsData, &esdsSize)) {
                mESDSData = malloc(esdsSize);
                mESDSSize = esdsSize;
                memcpy(mESDSData, esdsData, esdsSize);
                trackMeta->clear();
                foundESDS = true;
                break;
            }
        }
        return foundESDS;
    }

    FILE *mInputFp;
    sp<DataSource> mDataSource;
};

TEST_P(ESDSUnitTest, InvalidDataTest) {
    std::unique_ptr<char[]> invalidData(new char[mESDSSize]());
    ASSERT_NE(invalidData, nullptr) << "Unable to allocate memory";
    ESDS esds((void*)invalidData.get(), mESDSSize);
    ASSERT_NE(esds.InitCheck(), OK) << "invalid ESDS data accepted";
}

TEST(ESDSSanityUnitTest, ConstructorSanityTest) {
    std::unique_ptr<char[]> invalidData(new char[1]());
    ASSERT_NE(invalidData, nullptr) << "Unable to allocate memory";
    ESDS esds_zero((void*)invalidData.get(), 0);
    ASSERT_NE(esds_zero.InitCheck(), OK) << "invalid ESDS data accepted";

    ESDS esds_null(NULL, 0);
    ASSERT_NE(esds_null.InitCheck(), OK) << "invalid ESDS data accepted";
}

TEST_P(ESDSUnitTest, CreateAndDestroyTest) {
    ESDS esds(mESDSData, mESDSSize);
    ASSERT_EQ(esds.InitCheck(), OK) << "ESDS data invalid";
}

TEST_P(ESDSUnitTest, ObjectTypeIndicationTest) {
    ESDS esds(mESDSData, mESDSSize);
    ASSERT_EQ(esds.InitCheck(), OK) << "ESDS data invalid";
    uint8_t objectTypeIndication;
    status_t status = esds.getObjectTypeIndication(&objectTypeIndication);
    ASSERT_EQ(status, OK) << "ESDS objectTypeIndication data invalid";
    ASSERT_EQ(objectTypeIndication, mESDSParams.objectTypeIndication)
            << "ESDS objectTypeIndication data doesn't match";
}

TEST_P(ESDSUnitTest, CodecSpecificInfoTest) {
    ESDS esds(mESDSData, mESDSSize);
    ASSERT_EQ(esds.InitCheck(), OK) << "ESDS data invalid";
    status_t status;
    const void *codecSpecificInfo;
    size_t codecSpecificInfoSize;
    status = esds.getCodecSpecificInfo(&codecSpecificInfo, &codecSpecificInfoSize);
    ASSERT_EQ(status, OK) << "ESDS getCodecSpecificInfo data invalid";
    ASSERT_EQ(mESDSParams.codecSpecificInfoDataSize, codecSpecificInfoSize)
            << "CodecSpecificInfo data doesn't match";
    status = memcmp(codecSpecificInfo, mESDSParams.codecSpecificInfoData, codecSpecificInfoSize);
    ASSERT_EQ(status, 0) << "CodecSpecificInfo data doesn't match";
}

TEST_P(ESDSUnitTest, GetBitrateTest) {
    ESDS esds(mESDSData, mESDSSize);
    ASSERT_EQ(esds.InitCheck(), OK) << "ESDS data invalid";
    uint32_t bitrateMax;
    uint32_t bitrateAvg;
    status_t status = esds.getBitRate(&bitrateMax, &bitrateAvg);
    ASSERT_EQ(status, OK) << "ESDS bitRate data invalid";
    ASSERT_EQ(bitrateMax, mESDSParams.bitrateMax) << "ESDS bitrateMax doesn't match";
    ASSERT_EQ(bitrateAvg, mESDSParams.bitrateAvg) << "ESDS bitrateAvg doesn't match";
    ASSERT_LE(bitrateAvg, bitrateMax) << "ESDS bitrateMax is less than bitrateAvg";
}

INSTANTIATE_TEST_SUITE_P(
        ESDSUnitTestAll, ESDSUnitTest,
        ::testing::Values(
                // InputFile, ObjectTypeIndication, CodecSpecificInfoData,
                // CodecSpecificInfoDataSize, BitrateMax, BitrateAvg
                make_tuple("video_176x144_3gp_h263_56kbps_12fps_aac_stereo_128kbps_22050hz.3gp", 64,
                           "\x13\x90", 2, 131072, 0),
                make_tuple("video_1280x720_mp4_mpeg2_3000kbps_30fps_aac_stereo_128kbps_48000hz.mp4",
                           97,
                           "\x00\x00\x01\xB3\x50\x02\xD0\x35\xFF\xFF\xE1\xA0\x00\x00\x01\xB5\x15"
                           "\x6A\x00\x01\x00\x00",
                           22, 3415452, 3415452),
                make_tuple("video_176x144_3gp_h263_56kbps_25fps_aac_mono_24kbps_11025hz.3gp", 64,
                           "\x15\x08", 2, 24576, 0)));

int main(int argc, char **argv) {
    // MediaExtractor needs binder thread pool
    ProcessState::self()->startThreadPool();
    gEnv = new ESDSTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
