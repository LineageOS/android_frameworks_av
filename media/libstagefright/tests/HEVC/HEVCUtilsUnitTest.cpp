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
#define LOG_TAG "HevcUtilityTest"
#include <utils/Log.h>

#include <fstream>

#include <media/stagefright/foundation/ABitReader.h>
#include "include/HevcUtils.h"

#include "HEVCUtilsTestEnvironment.h"

using namespace android;

// max size of hvcc box is 2 KB
constexpr uint32_t kHvccBoxMaxSize = 2048;
constexpr uint32_t kHvccBoxMinSize = 20;
constexpr uint32_t kVPSCode = 32;
constexpr uint32_t kSPSCode = 33;
constexpr uint32_t kPPSCode = 34;
constexpr uint32_t kNALSizeLength = 2;

static HEVCUtilsTestEnvironment *gEnv = nullptr;

class HEVCUtilsUnitTest
    : public ::testing::TestWithParam<
              tuple</*fileName*/ string, /*infoFileName*/ string, /*numVPSNals*/ size_t,
                    /*numSPSNals*/ size_t, /*numPPSNals*/ size_t, /*frameRate*/ int16_t,
                    /*isHdr*/ bool>> {
  public:
    ~HEVCUtilsUnitTest() {
        if (mMediaFileStream.is_open()) mMediaFileStream.close();
        if (mInfoFileStream.is_open()) mInfoFileStream.close();
    }

    virtual void SetUp() override {
        tuple<string, string, size_t, size_t, size_t, int16_t, bool> params = GetParam();
        string inputMediaFile = gEnv->getRes() + get<0>(params);
        mMediaFileStream.open(inputMediaFile, ifstream::in);
        ASSERT_TRUE(mMediaFileStream.is_open()) << "Failed to open media file: " << inputMediaFile;

        string inputInfoFile = gEnv->getRes() + get<1>(params);
        mInfoFileStream.open(inputInfoFile, ifstream::in);
        ASSERT_TRUE(mInfoFileStream.is_open()) << "Failed to open info file: " << inputInfoFile;

        mNumVPSNals = get<2>(params);
        mNumSPSNals = get<3>(params);
        mNumPPSNals = get<4>(params);
        mFrameRate = get<5>(params);
        mIsHDR = get<6>(params);
    }

    size_t mNumVPSNals;
    size_t mNumSPSNals;
    size_t mNumPPSNals;
    int16_t mFrameRate;
    bool mIsHDR;
    ifstream mMediaFileStream;
    ifstream mInfoFileStream;
};

TEST_P(HEVCUtilsUnitTest, NALUnitTest) {
    HevcParameterSets hevcParams;

    string line;
    int32_t index = 0;
    status_t err;
    while (getline(mInfoFileStream, line)) {
        string type;
        int32_t chunkLength;

        istringstream stringLine(line);
        stringLine >> type >> chunkLength;
        ASSERT_GT(chunkLength, 0) << "Length of data chunk must be greater than 0";

        char *data = (char *)malloc(chunkLength);
        ASSERT_NE(data, nullptr) << "Failed to allocate data buffer of size: " << chunkLength;

        mMediaFileStream.read(data, chunkLength);
        ASSERT_EQ(mMediaFileStream.gcount(), chunkLength)
                << "Failed to read complete file, bytes read: " << mMediaFileStream.gcount();

        // A valid startcode consists of at least two 0x00 bytes followed by 0x01.
        int32_t offset = 0;
        for (; offset + 2 < chunkLength; ++offset) {
            if (data[offset + 2] == 0x01 && data[offset + 1] == 0x00 && data[offset] == 0x00) {
                break;
            }
        }
        offset += 3;
        ASSERT_LE(offset, chunkLength) << "NAL unit offset must not exceed the chunk length";

        uint8_t *nalUnit = (uint8_t *)(data + offset);
        size_t nalUnitLength = chunkLength - offset;

        // Add NAL units only if they're of type: VPS/SPS/PPS/SEI
        if (!((type.compare("VPS") && type.compare("SPS") && type.compare("PPS") &&
               type.compare("SEI")))) {
            err = hevcParams.addNalUnit(nalUnit, nalUnitLength);
            ASSERT_EQ(err, (status_t)OK)
                    << "Failed to add NAL Unit type: " << type << " Size: " << nalUnitLength;

            size_t sizeNalUnit = hevcParams.getSize(index);
            ASSERT_EQ(sizeNalUnit, nalUnitLength) << "Invalid size returned for NAL: " << type;

            uint8_t *destination = (uint8_t *)malloc(nalUnitLength);
            ASSERT_NE(destination, nullptr)
                    << "Failed to allocate buffer of size: " << nalUnitLength;

            bool status = hevcParams.write(index, destination, nalUnitLength);
            ASSERT_TRUE(status) << "Unable to write NAL Unit data";

            free(destination);
            index++;
        } else {
            err = hevcParams.addNalUnit(nalUnit, nalUnitLength);
            ASSERT_NE(err, (status_t)OK) << "Invalid NAL Unit added, type: " << type;
        }
        free(data);
    }

    size_t numNalUnits = hevcParams.getNumNalUnitsOfType(kVPSCode);
    ASSERT_EQ(numNalUnits, mNumVPSNals) << "Wrong number of VPS NAL Units";

    numNalUnits = hevcParams.getNumNalUnitsOfType(kSPSCode);
    ASSERT_EQ(numNalUnits, mNumSPSNals) << "Wrong number of SPS NAL Units";

    numNalUnits = hevcParams.getNumNalUnitsOfType(kPPSCode);
    ASSERT_EQ(numNalUnits, mNumPPSNals) << "Wrong number of PPS NAL Units";

    HevcParameterSets::Info info = hevcParams.getInfo();
    ASSERT_EQ(info & HevcParameterSets::kInfoIsHdr,
              (mIsHDR ? HevcParameterSets::kInfoIsHdr : HevcParameterSets::kInfoNone))
            << "Wrong info about HDR";

    ASSERT_EQ(info & HevcParameterSets::kInfoHasColorDescription,
              (mIsHDR ? HevcParameterSets::kInfoHasColorDescription : HevcParameterSets::kInfoNone))
            << "Wrong info about color description";

    // an HEVC file starts with VPS, SPS and PPS NAL units in sequence.
    uint8_t typeNalUnit = hevcParams.getType(0);
    ASSERT_EQ(typeNalUnit, kHevcNalUnitTypeVps)
            << "Expected NAL type: 32(VPS), found: " << typeNalUnit;

    typeNalUnit = hevcParams.getType(1);
    ASSERT_EQ(typeNalUnit, kHevcNalUnitTypeSps)
            << "Expected NAL type: 33(SPS), found: " << typeNalUnit;

    typeNalUnit = hevcParams.getType(2);
    ASSERT_EQ(typeNalUnit, kHevcNalUnitTypePps)
            << "Expected NAL type: 34(PPS), found: " << typeNalUnit;

    size_t hvccBoxSize = kHvccBoxMaxSize;
    uint8_t *hvcc = (uint8_t *)malloc(kHvccBoxMaxSize);
    ASSERT_NE(hvcc, nullptr) << "Failed to allocate a hvcc buffer of size: " << kHvccBoxMaxSize;

    err = hevcParams.makeHvcc(hvcc, &hvccBoxSize, kNALSizeLength);
    ASSERT_EQ(err, (status_t)OK) << "Unable to create hvcc box";

    ASSERT_GT(hvccBoxSize, kHvccBoxMinSize)
            << "Hvcc box size must be greater than " << kHvccBoxMinSize;

    int16_t frameRate = hvcc[kHvccBoxMinSize - 1] | (hvcc[kHvccBoxMinSize] << 8);
    if (frameRate != mFrameRate)
        cout << "[   WARN   ] Expected frame rate: " << mFrameRate << " Found: " << frameRate
             << endl;

    free(hvcc);
}

// Info File contains the type and length for each chunk/frame
INSTANTIATE_TEST_SUITE_P(
        HEVCUtilsUnitTestAll, HEVCUtilsUnitTest,
        ::testing::Values(make_tuple("crowd_3840x2160p50f300_32500kbps.hevc",
                                     "crowd_3840x2160p50f300_32500kbps.info", 1, 1, 1, 50, false),
                          make_tuple("crowd_1920x1080p24f300_4500kbps.hevc",
                                     "crowd_1920x1080p24f300_4500kbps.info", 1, 1, 1, 24, false),
                          make_tuple("crowd_1280x720p24f300_3000kbps.hevc",
                                     "crowd_1280x720p24f300_3000kbps.info", 1, 1, 1, 24, false),
                          make_tuple("crowd_640x360p24f300_500kbps.hevc",
                                     "crowd_640x360p24f300_500kbps.info", 1, 1, 1, 24, false)));

int main(int argc, char **argv) {
    gEnv = new HEVCUtilsTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
