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
#define LOG_TAG "ColorUtilsTest"
#include <utils/Log.h>

#include <gtest/gtest.h>

#include <stdio.h>

#include <media/NdkMediaFormat.h>
#include <media/NdkMediaFormatPriv.h>
#include <media/stagefright/MediaCodecConstants.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ColorUtils.h>

const size_t kHDRBufferSize = 25;
const uint16_t kHDRInfoTestValue1 = 420;
const uint16_t kHDRInfoTestValue2 = 42069;

using namespace android;

typedef ColorAspects CA;

class ColorRangeTest : public ::testing::TestWithParam</* ColorRange */ CA::Range> {
  public:
    ColorRangeTest() { mRange = GetParam(); };

    CA::Range mRange;
};

class ColorTransferTest : public ::testing::TestWithParam</* ColorTransfer */ CA::Transfer> {
  public:
    ColorTransferTest() { mTransfer = GetParam(); };

    CA::Transfer mTransfer;
};

class ColorStandardTest : public ::testing::TestWithParam<std::pair<
                                  /* Primaries */ CA::Primaries,
                                  /* MatrixCoeffs */ CA::MatrixCoeffs>> {
  public:
    ColorStandardTest() {
        mPrimaries = GetParam().first;
        mMatrixCoeffs = GetParam().second;
    };

    CA::Primaries mPrimaries;
    CA::MatrixCoeffs mMatrixCoeffs;
};

class IsoToPlatformAspectsTest : public ::testing::TestWithParam<std::tuple<
                                         /* Primaries */ CA::Primaries,
                                         /* Transfer */ CA::Transfer,
                                         /* MatrixCoeffs */ CA::MatrixCoeffs,
                                         /* Standard */ int32_t,
                                         /* Transfer */ int32_t>> {
  public:
    IsoToPlatformAspectsTest() {
        mPrimaries = std::get<0>(GetParam());
        mTransfer = std::get<1>(GetParam());
        mMatrixCoeffs = std::get<2>(GetParam());
        mPlatformStandard = std::get<3>(GetParam());
        mPlatformTransfer = std::get<4>(GetParam());
    };

    CA::Primaries mPrimaries;
    CA::Transfer mTransfer;
    CA::MatrixCoeffs mMatrixCoeffs;
    int32_t mPlatformStandard;
    int32_t mPlatformTransfer;
};

class ColorAspectsTest : public ::testing::TestWithParam<std::tuple<
                                 /* Primaries */ CA::Primaries,
                                 /* ColorTransfer */ CA::Transfer,
                                 /* MatrixCoeffs */ CA::MatrixCoeffs,
                                 /* ColorRange */ CA::Range,
                                 /* ColorStandard */ CA::Standard>> {
  public:
    ColorAspectsTest() {
        mPrimaries = std::get<0>(GetParam());
        mTransfer = std::get<1>(GetParam());
        mMatrixCoeffs = std::get<2>(GetParam());
        mRange = std::get<3>(GetParam());
        mStandard = std::get<4>(GetParam());
    };

    CA::Primaries mPrimaries;
    CA::Transfer mTransfer;
    CA::MatrixCoeffs mMatrixCoeffs;
    CA::Range mRange;
    CA::Standard mStandard;
};

class DefaultColorAspectsTest : public ::testing::TestWithParam<std::tuple<
                                        /* Width */ int32_t,
                                        /* Height */ int32_t,
                                        /* Primaries */ CA::Primaries,
                                        /* MatrixCoeffs */ CA::MatrixCoeffs>> {
  public:
    DefaultColorAspectsTest() {
        mWidth = std::get<0>(GetParam());
        mHeight = std::get<1>(GetParam());
        mPrimaries = std::get<2>(GetParam());
        mMatrixCoeffs = std::get<3>(GetParam());
    };

    int32_t mWidth;
    int32_t mHeight;
    CA::Primaries mPrimaries;
    CA::MatrixCoeffs mMatrixCoeffs;
};

class DataSpaceTest : public ::testing::TestWithParam<std::tuple<
                              /* ColorRange */ CA::Range,
                              /* Primaries */ CA::Primaries,
                              /* ColorTransfer */ CA::Transfer,
                              /* MatrixCoeffs */ CA::MatrixCoeffs,
                              /* v0_android_dataspace */ android_dataspace,
                              /* android_dataspace */ android_dataspace>> {
  public:
    DataSpaceTest() {
        mRange = std::get<0>(GetParam());
        mPrimaries = std::get<1>(GetParam());
        mTransfer = std::get<2>(GetParam());
        mMatrixCoeffs = std::get<3>(GetParam());
        mDataSpaceV0 = std::get<4>(GetParam());
        mDataSpace = std::get<5>(GetParam());
    };

    CA::Range mRange;
    CA::Primaries mPrimaries;
    CA::Transfer mTransfer;
    CA::MatrixCoeffs mMatrixCoeffs;
    android_dataspace mDataSpaceV0;
    android_dataspace mDataSpace;
};

TEST_P(ColorRangeTest, WrapColorRangeTest) {
    int32_t range = ColorUtils::wrapColorAspectsIntoColorRange(mRange);
    CA::Range unwrappedRange;
    status_t status = ColorUtils::unwrapColorAspectsFromColorRange(range, &unwrappedRange);
    ASSERT_EQ(status, OK) << "unwrapping ColorAspects from ColorRange failed";
    EXPECT_EQ(unwrappedRange, mRange) << "Returned ColorRange doesn't match";
    ALOGV("toString test: Range: %s", asString(mRange, "default"));
}

TEST_P(ColorTransferTest, WrapColorTransferTest) {
    int32_t transfer = ColorUtils::wrapColorAspectsIntoColorTransfer(mTransfer);
    CA::Transfer unwrappedTransfer;
    status_t status = ColorUtils::unwrapColorAspectsFromColorTransfer(transfer, &unwrappedTransfer);
    ASSERT_EQ(status, OK) << "unwrapping ColorAspects from ColorTransfer failed";
    EXPECT_EQ(unwrappedTransfer, mTransfer) << "Returned ColorTransfer doesn't match";
    ALOGV("toString test: Transfer: %s", asString(mTransfer, "default"));
}

TEST_P(ColorStandardTest, WrapColorStandardTest) {
    int32_t standard = ColorUtils::wrapColorAspectsIntoColorStandard(mPrimaries, mMatrixCoeffs);
    CA::Primaries unwrappedPrimaries;
    CA::MatrixCoeffs unwrappedMatrixCoeffs;
    status_t status = ColorUtils::unwrapColorAspectsFromColorStandard(standard, &unwrappedPrimaries,
                                                                      &unwrappedMatrixCoeffs);
    ASSERT_EQ(status, OK) << "unwrapping ColorAspects from ColorStandard failed";
    EXPECT_EQ(unwrappedPrimaries, mPrimaries) << "Returned primaries doesn't match";
    EXPECT_EQ(unwrappedMatrixCoeffs, mMatrixCoeffs) << "Returned  matrixCoeffs doesn't match";
}

TEST_P(ColorAspectsTest, PlatformAspectsTest) {
    CA aspects;
    aspects.mRange = mRange;
    aspects.mPrimaries = mPrimaries;
    aspects.mTransfer = mTransfer;
    aspects.mMatrixCoeffs = mMatrixCoeffs;

    int32_t range = -1;
    int32_t standard = -1;
    int32_t transfer = -1;
    status_t status = ColorUtils::convertCodecColorAspectsToPlatformAspects(aspects, &range,
                                                                            &standard, &transfer);
    ASSERT_EQ(status, OK) << "Conversion of ColorAspects to PlatformAspects failed";

    CA returnedAspects;
    status = ColorUtils::convertPlatformColorAspectsToCodecAspects(range, standard, transfer,
                                                                   returnedAspects);
    ASSERT_EQ(status, OK) << "Conversion of PlatformAspects to ColorAspects failed";
    EXPECT_EQ(returnedAspects.mRange, aspects.mRange)
            << "range mismatch for conversion between PlatformAspects";
    EXPECT_EQ(returnedAspects.mPrimaries, aspects.mPrimaries)
            << "primaries mismatch for conversion between PlatformAspects";
    EXPECT_EQ(returnedAspects.mTransfer, aspects.mTransfer)
            << "transfer mismatch for conversion between PlatformAspects";
    EXPECT_EQ(returnedAspects.mMatrixCoeffs, aspects.mMatrixCoeffs)
            << "matrixCoeffs mismatch for conversion between PlatformAspects";
}

TEST_P(ColorAspectsTest, IsoAspectsTest) {
    CA aspects;
    aspects.mRange = mRange;
    aspects.mPrimaries = mPrimaries;
    aspects.mTransfer = mTransfer;
    aspects.mMatrixCoeffs = mMatrixCoeffs;

    int32_t primaries = -1;
    int32_t colorTransfer = -1;
    int32_t matrixCoeffs = -1;
    bool fullRange = false;
    ColorUtils::convertCodecColorAspectsToIsoAspects(aspects, &primaries, &colorTransfer,
                                                     &matrixCoeffs, &fullRange);

    CA returnedAspects;
    ColorUtils::convertIsoColorAspectsToCodecAspects(primaries, colorTransfer, matrixCoeffs,
                                                     fullRange, returnedAspects);
    EXPECT_EQ(returnedAspects.mRange, aspects.mRange)
            << "range mismatch for conversion between IsoAspects";
    EXPECT_EQ(returnedAspects.mPrimaries, aspects.mPrimaries)
            << "primaries mismatch for conversion between IsoAspects";
    EXPECT_EQ(returnedAspects.mTransfer, aspects.mTransfer)
            << "transfer mismatch for conversion between IsoAspects";
    EXPECT_EQ(returnedAspects.mMatrixCoeffs, aspects.mMatrixCoeffs)
            << "matrixCoeffs mismatch for conversion between IsoAspects";
}

TEST_P(IsoToPlatformAspectsTest, IsoAspectsToPlatformAspectsTest) {
    CA aspects;
    aspects.mPrimaries = mPrimaries;
    aspects.mTransfer = mTransfer;
    aspects.mMatrixCoeffs = mMatrixCoeffs;

    int32_t isoPrimaries = -1;
    int32_t isoTransfer = -1;
    int32_t isoMatrixCoeffs = -1;
    bool fullrange = false;
    ColorUtils::convertCodecColorAspectsToIsoAspects(aspects, &isoPrimaries, &isoTransfer,
                                                     &isoMatrixCoeffs, &fullrange);

    int32_t range = -1;
    int32_t standard = -1;
    int32_t transfer = -1;
    ColorUtils::convertIsoColorAspectsToPlatformAspects(isoPrimaries, isoTransfer, isoMatrixCoeffs,
                                                        fullrange, &range, &standard, &transfer);
    if (fullrange) {
        EXPECT_EQ(range, ColorUtils::kColorRangeFull)
                << "range incorrect converting to PlatformAspects";
    }
    EXPECT_EQ(standard, mPlatformStandard) << "standard incorrect converting to PlatformAspects";
    EXPECT_EQ(transfer, mPlatformTransfer) << "transfer incorrect converting to PlatformAspects";
}

TEST_P(ColorAspectsTest, PackColorAspectsTest) {
    CA aspects;
    aspects.mRange = mRange;
    aspects.mPrimaries = mPrimaries;
    aspects.mTransfer = mTransfer;
    aspects.mMatrixCoeffs = mMatrixCoeffs;
    uint32_t packedColorAspects = ColorUtils::packToU32(aspects);

    CA unpackedAspects = ColorUtils::unpackToColorAspects(packedColorAspects);
    EXPECT_EQ(unpackedAspects.mRange, mRange) << "range mismatch after unpacking";
    EXPECT_EQ(unpackedAspects.mPrimaries, mPrimaries) << "primaries mismatch after unpacking";
    EXPECT_EQ(unpackedAspects.mTransfer, mTransfer) << "transfer mismatch after unpacking";
    EXPECT_EQ(unpackedAspects.mMatrixCoeffs, mMatrixCoeffs)
            << "matrixCoeffs mismatch after unpacking";
    ALOGV("toString test: Standard: %s", asString(mStandard, "default"));
}

TEST_P(DefaultColorAspectsTest, DefaultColorAspectsTest) {
    CA aspects;
    aspects.mRange = CA::RangeUnspecified;
    aspects.mPrimaries = CA::PrimariesUnspecified;
    aspects.mMatrixCoeffs = CA::MatrixUnspecified;
    aspects.mTransfer = CA::TransferUnspecified;

    ColorUtils::setDefaultCodecColorAspectsIfNeeded(aspects, mWidth, mHeight);
    EXPECT_EQ(aspects.mRange, CA::RangeLimited) << "range not set to default";
    EXPECT_EQ(aspects.mPrimaries, mPrimaries) << "primaries not set to default";
    EXPECT_EQ(aspects.mMatrixCoeffs, mMatrixCoeffs) << "matrixCoeffs not set to default";
    EXPECT_EQ(aspects.mTransfer, CA::TransferSMPTE170M) << "transfer not set to default";
}

TEST_P(DataSpaceTest, DataSpaceTest) {
    CA aspects;
    aspects.mRange = mRange;
    aspects.mPrimaries = mPrimaries;
    aspects.mTransfer = mTransfer;
    aspects.mMatrixCoeffs = mMatrixCoeffs;

    android_dataspace dataSpace = ColorUtils::getDataSpaceForColorAspects(aspects, false);
    EXPECT_EQ(dataSpace, mDataSpace) << "Returned incorrect dataspace";

    bool status = ColorUtils::convertDataSpaceToV0(dataSpace);
    ASSERT_TRUE(status) << "Returned v0 dataspace is not aspect-only";
    EXPECT_EQ(dataSpace, mDataSpaceV0) << "Returned incorrect v0 dataspace";
}

TEST(ColorUtilsUnitTest, AspectsChangedTest) {
    CA origAspects;
    origAspects.mRange = CA::Range::RangeFull;
    origAspects.mPrimaries = CA::Primaries::PrimariesBT709_5;
    origAspects.mTransfer = CA::Transfer::TransferLinear;
    origAspects.mMatrixCoeffs = CA::MatrixCoeffs::MatrixBT709_5;

    CA aspects;
    aspects.mRange = CA::Range::RangeFull;
    aspects.mPrimaries = CA::Primaries::PrimariesBT709_5;
    aspects.mTransfer = CA::Transfer::TransferLinear;
    aspects.mMatrixCoeffs = CA::MatrixCoeffs::MatrixBT709_5;

    bool status = ColorUtils::checkIfAspectsChangedAndUnspecifyThem(aspects, origAspects);
    ASSERT_FALSE(status) << "ColorAspects comparison check failed";

    aspects.mRange = CA::Range::RangeLimited;
    status = ColorUtils::checkIfAspectsChangedAndUnspecifyThem(aspects, origAspects);
    ASSERT_TRUE(status) << "ColorAspects comparison check failed";
    EXPECT_EQ(aspects.mRange, CA::Range::RangeUnspecified) << "range should have been unspecified";
    aspects.mRange = CA::Range::RangeFull;

    aspects.mTransfer = CA::Transfer::TransferSRGB;
    status = ColorUtils::checkIfAspectsChangedAndUnspecifyThem(aspects, origAspects);
    ASSERT_TRUE(status) << "ColorAspects comparison check failed";
    EXPECT_EQ(aspects.mTransfer, CA::Transfer::TransferUnspecified)
            << "transfer should have been unspecified";
    aspects.mTransfer = CA::Transfer::TransferLinear;

    aspects.mPrimaries = CA::Primaries::PrimariesBT2020;
    status = ColorUtils::checkIfAspectsChangedAndUnspecifyThem(aspects, origAspects, true);
    ASSERT_TRUE(status) << "ColorAspects comparison check failed";
    EXPECT_EQ(aspects.mPrimaries, CA::Primaries::PrimariesUnspecified)
            << "primaries should have been unspecified";
    EXPECT_EQ(aspects.mMatrixCoeffs, CA::MatrixCoeffs::MatrixUnspecified)
            << "matrixCoeffs should have been unspecified";

    aspects.mMatrixCoeffs = CA::MatrixCoeffs::MatrixSMPTE240M;
    status = ColorUtils::checkIfAspectsChangedAndUnspecifyThem(aspects, origAspects, true);
    ASSERT_TRUE(status) << "ColorAspects comparison check failed";
    EXPECT_EQ(aspects.mPrimaries, CA::Primaries::PrimariesUnspecified)
            << "primaries should have been unspecified";
    EXPECT_EQ(aspects.mMatrixCoeffs, CA::MatrixCoeffs::MatrixUnspecified)
            << "matrixCoeffs should have been unspecified";
}

TEST(ColorUtilsUnitTest, ColorConfigFromFormatTest) {
    int range = -1;
    int standard = -1;
    int transfer = -1;
    sp<AMessage> format = new AMessage();
    ASSERT_NE(format, nullptr) << "failed to create AMessage";
    ColorUtils::getColorConfigFromFormat(format, &range, &standard, &transfer);
    EXPECT_EQ(range | standard | transfer, 0) << "color config didn't default to 0";

    format->setInt32(KEY_COLOR_RANGE, CA::Range::RangeFull);
    format->setInt32(KEY_COLOR_STANDARD, CA::Standard::StandardBT709);
    format->setInt32(KEY_COLOR_TRANSFER, CA::Transfer::TransferLinear);
    ColorUtils::getColorConfigFromFormat(format, &range, &standard, &transfer);
    EXPECT_EQ(range, CA::Range::RangeFull) << "range mismatch";
    EXPECT_EQ(standard, CA::Standard::StandardBT709) << "standard mismatch";
    EXPECT_EQ(transfer, CA::Transfer::TransferLinear) << "transfer mismatch";

    range = standard = transfer = -1;
    sp<AMessage> copyFormat = new AMessage();
    ASSERT_NE(copyFormat, nullptr) << "failed to create AMessage";
    ColorUtils::copyColorConfig(format, copyFormat);
    bool status = copyFormat->findInt32(KEY_COLOR_RANGE, &range);
    ASSERT_TRUE(status) << "ColorConfig range entry missing";
    status = copyFormat->findInt32(KEY_COLOR_STANDARD, &standard);
    ASSERT_TRUE(status) << "ColorConfig standard entry missing";
    status = copyFormat->findInt32(KEY_COLOR_TRANSFER, &transfer);
    ASSERT_TRUE(status) << "ColorConfig transfer entry missing";
    EXPECT_EQ(range, CA::Range::RangeFull) << "range mismatch";
    EXPECT_EQ(standard, CA::Standard::StandardBT709) << "standard mismatch";
    EXPECT_EQ(transfer, CA::Transfer::TransferLinear) << "transfer mismatchd";

    range = standard = transfer = -1;
    ColorUtils::getColorConfigFromFormat(copyFormat, &range, &standard, &transfer);
    EXPECT_EQ(range, CA::Range::RangeFull) << "range mismatch";
    EXPECT_EQ(standard, CA::Standard::StandardBT709) << "standard mismatch";
    EXPECT_EQ(transfer, CA::Transfer::TransferLinear) << "transfer mismatch";
}

TEST_P(ColorAspectsTest, FormatTest) {
    CA aspects;
    sp<AMessage> format = new AMessage();
    ASSERT_NE(format, nullptr) << "failed to create AMessage";
    ColorUtils::setColorAspectsIntoFormat(aspects, format, true);

    CA returnedAspects;
    ColorUtils::getColorAspectsFromFormat(format, returnedAspects);
    EXPECT_EQ(returnedAspects.mRange, aspects.mRange) << "range mismatch";
    EXPECT_EQ(returnedAspects.mPrimaries, aspects.mPrimaries) << "primaries mismatch";
    EXPECT_EQ(returnedAspects.mTransfer, aspects.mTransfer) << "transfer mismatch";
    EXPECT_EQ(returnedAspects.mMatrixCoeffs, aspects.mMatrixCoeffs) << "matrixCoeffs mismatch";

    aspects.mRange = mRange;
    aspects.mPrimaries = mPrimaries;
    aspects.mTransfer = mTransfer;
    aspects.mMatrixCoeffs = mMatrixCoeffs;
    ColorUtils::setColorAspectsIntoFormat(aspects, format);

    memset(&returnedAspects, 0, sizeof(returnedAspects));
    ColorUtils::getColorAspectsFromFormat(format, returnedAspects);
    EXPECT_EQ(returnedAspects.mRange, aspects.mRange) << "range mismatch";
    EXPECT_EQ(returnedAspects.mPrimaries, aspects.mPrimaries) << "primaries mismatch";
    EXPECT_EQ(returnedAspects.mTransfer, aspects.mTransfer) << "transfer mismatch";
    EXPECT_EQ(returnedAspects.mMatrixCoeffs, aspects.mMatrixCoeffs) << "matrixCoeffs mismatch";
}

TEST(ColorUtilsUnitTest, HDRStaticInfoTest) {
    sp<AMessage> format = new AMessage();
    ASSERT_NE(format, nullptr) << "failed to create AMessage";

    HDRStaticInfo returnedInfoHDR;
    bool status = ColorUtils::getHDRStaticInfoFromFormat(format, &returnedInfoHDR);
    ASSERT_FALSE(status) << "HDR info should be absent in empty format";

    HDRStaticInfo infoHDR;
    infoHDR.sType1.mMaxDisplayLuminance = kHDRInfoTestValue2;
    infoHDR.sType1.mMinDisplayLuminance = kHDRInfoTestValue1;
    infoHDR.sType1.mMaxContentLightLevel = kHDRInfoTestValue2;
    infoHDR.sType1.mMaxFrameAverageLightLevel = kHDRInfoTestValue1;
    infoHDR.sType1.mR.x = kHDRInfoTestValue1;
    infoHDR.sType1.mR.y = kHDRInfoTestValue2;
    infoHDR.sType1.mG.x = kHDRInfoTestValue1;
    infoHDR.sType1.mG.y = kHDRInfoTestValue2;
    infoHDR.sType1.mB.x = kHDRInfoTestValue1;
    infoHDR.sType1.mB.y = kHDRInfoTestValue2;
    infoHDR.sType1.mW.x = kHDRInfoTestValue1;
    infoHDR.sType1.mW.y = kHDRInfoTestValue2;
    ColorUtils::setHDRStaticInfoIntoFormat(infoHDR, format);

    status = ColorUtils::getHDRStaticInfoFromFormat(format, &returnedInfoHDR);
    ASSERT_TRUE(status) << "Failed to get HDR info from format";
    ASSERT_EQ(0, memcmp(&returnedInfoHDR, &infoHDR, sizeof(infoHDR))) << " HDRStaticInfo mismatch";

    AMediaFormat *mediaFormat = AMediaFormat_new();
    ASSERT_NE(mediaFormat, nullptr) << "Unable to create AMediaFormat";
    ColorUtils::setHDRStaticInfoIntoAMediaFormat(infoHDR, mediaFormat);
    memset(&returnedInfoHDR, 0, sizeof(returnedInfoHDR));
    status = ColorUtils::getHDRStaticInfoFromFormat(mediaFormat->mFormat, &returnedInfoHDR);
    AMediaFormat_delete(mediaFormat);
    ASSERT_TRUE(status) << "Failed to get HDR info from media format";
    ASSERT_EQ(0, memcmp(&returnedInfoHDR, &infoHDR, sizeof(infoHDR))) << " HDRStaticInfo mismatch";
}

TEST(ColorUtilsUnitTest, SanityTest) {
    CA::Primaries unmappedPrimaries = (CA::Primaries)(CA::Primaries::PrimariesOther + 1);
    CA::MatrixCoeffs unmappedMatrixCoeffs = (CA::MatrixCoeffs)(CA::MatrixOther + 1);
    int32_t colorStandard =
            ColorUtils::wrapColorAspectsIntoColorStandard(unmappedPrimaries, CA::MatrixUnspecified);
    EXPECT_EQ(colorStandard, ColorUtils::kColorStandardUnspecified)
            << "Standard unspecified expected";
    colorStandard =
            ColorUtils::wrapColorAspectsIntoColorStandard(CA::PrimariesOther, unmappedMatrixCoeffs);
    EXPECT_EQ(colorStandard, ColorUtils::kColorStandardUnspecified)
            << "Standard unspecified expected";
    colorStandard = ColorUtils::wrapColorAspectsIntoColorStandard(CA::PrimariesBT601_6_525,
                                                                  CA::MatrixBT2020);
    EXPECT_GE(colorStandard, ColorUtils::kColorStandardExtendedStart)
            << "Standard greater than extended start expected";
    unmappedPrimaries = (CA::Primaries)(CA::Primaries::PrimariesBT2020 + 1);
    unmappedMatrixCoeffs = (CA::MatrixCoeffs)(CA::MatrixBT2020Constant + 1);
    colorStandard =
            ColorUtils::wrapColorAspectsIntoColorStandard(unmappedPrimaries, unmappedMatrixCoeffs);
    EXPECT_GE(colorStandard, ColorUtils::kColorStandardExtendedStart)
            << "Standard greater than extended start expected";

    CA aspects;
    int32_t colorRange = -1;
    colorStandard = -1;
    int32_t colorTransfer = -1;
    aspects.mPrimaries = (CA::Primaries)(CA::Primaries::PrimariesOther + 1);
    status_t status = ColorUtils::convertCodecColorAspectsToPlatformAspects(
            aspects, &colorRange, &colorStandard, &colorTransfer);
    EXPECT_NE(status, OK) << "invalid colorAspects value accepted";

    int32_t colorPrimaries = -1;
    colorTransfer = -1;
    int32_t colorMatrixCoeffs = -1;
    bool fullRange = false;
    aspects.mPrimaries = CA::PrimariesOther;
    aspects.mTransfer = CA::TransferOther;
    aspects.mMatrixCoeffs = CA::MatrixOther;
    ColorUtils::convertCodecColorAspectsToIsoAspects(aspects, &colorPrimaries, &colorTransfer,
                                                     &colorMatrixCoeffs, &fullRange);
    CA returnedAspects;
    ColorUtils::convertIsoColorAspectsToCodecAspects(colorPrimaries, colorTransfer,
                                                     colorMatrixCoeffs, fullRange, returnedAspects);
    EXPECT_EQ(returnedAspects.mPrimaries, CA::PrimariesUnspecified)
            << "expected unspecified Primaries";
    EXPECT_EQ(returnedAspects.mTransfer, CA::TransferUnspecified)
            << "expected unspecified Transfer";
    EXPECT_EQ(returnedAspects.mMatrixCoeffs, CA::MatrixUnspecified)
            << "expected unspecified MatrixCoeffs";

    // invalid values, other value equals 0xFF
    colorPrimaries = CA::PrimariesOther;
    colorTransfer = CA::TransferOther;
    colorMatrixCoeffs = CA::MatrixOther;
    fullRange = false;
    memset(&returnedAspects, 0, sizeof(returnedAspects));
    ColorUtils::convertIsoColorAspectsToCodecAspects(colorPrimaries, colorTransfer,
                                                     colorMatrixCoeffs, fullRange, returnedAspects);
    EXPECT_EQ(returnedAspects.mPrimaries, CA::PrimariesUnspecified)
            << "expected unspecified Primaries";
    EXPECT_EQ(returnedAspects.mTransfer, CA::TransferUnspecified)
            << "expected unspecified Transfer";
    EXPECT_EQ(returnedAspects.mMatrixCoeffs, CA::MatrixUnspecified)
            << "expected unspecified MatrixCoeffs";

    CA::Primaries primaries = CA::PrimariesUnspecified;
    CA::MatrixCoeffs matrixCoeffs = CA::MatrixUnspecified;
    status = ColorUtils::unwrapColorAspectsFromColorStandard(ColorUtils::kColorStandardVendorStart,
                                                             &primaries, &matrixCoeffs);
    EXPECT_EQ(status, OK) << "unwrapping aspects from color standard failed";

    primaries = CA::PrimariesUnspecified;
    matrixCoeffs = CA::MatrixUnspecified;
    status = ColorUtils::unwrapColorAspectsFromColorStandard(
            ColorUtils::kColorStandardVendorStart * 4, &primaries, &matrixCoeffs);
    EXPECT_NE(status, OK) << "unwrapping aspects from color standard failed";

    colorRange = ColorUtils::wrapColorAspectsIntoColorRange((CA::Range)(CA::RangeOther + 1));
    EXPECT_EQ(colorRange, ColorUtils::kColorRangeUnspecified) << "expected unspecified color range";

    CA::Range range;
    status = ColorUtils::unwrapColorAspectsFromColorRange(
            ColorUtils::kColorRangeVendorStart + CA::RangeOther + 1, &range);
    EXPECT_NE(status, OK) << "invalid range value accepted";
    EXPECT_EQ(range, CA::RangeOther) << "returned unexpected range value";

    colorTransfer =
            ColorUtils::wrapColorAspectsIntoColorTransfer((CA::Transfer)(CA::TransferOther + 1));
    EXPECT_EQ(colorTransfer, ColorUtils::kColorTransferUnspecified)
            << "expected unspecified color transfer";

    CA::Transfer transfer;
    status = ColorUtils::unwrapColorAspectsFromColorTransfer(
            ColorUtils::kColorTransferVendorStart + CA::TransferOther + 1, &transfer);
    EXPECT_NE(status, OK) << "invalid transfer value accepted";
    EXPECT_EQ(transfer, CA::TransferOther) << "expected other color transfer";
}

TEST(ColorUtilsUnitTest, HDRInfoSanityTest) {
    HDRStaticInfo hdrInfo;
    sp<AMessage> format = new AMessage();
    ASSERT_NE(format, nullptr) << "failed to create AMessage";

    bool boolStatus = ColorUtils::getHDRStaticInfoFromFormat(format, &hdrInfo);
    EXPECT_FALSE(boolStatus) << "HDRStaticInfo should not be present";

    sp<ABuffer> invalidSizeHDRInfoBuffer = new ABuffer(kHDRBufferSize - 1);
    ASSERT_NE(invalidSizeHDRInfoBuffer, nullptr) << "failed to create ABuffer";
    format->setBuffer(KEY_HDR_STATIC_INFO, invalidSizeHDRInfoBuffer);
    memset(&hdrInfo, 0, sizeof(hdrInfo));
    boolStatus = ColorUtils::getHDRStaticInfoFromFormat(format, &hdrInfo);
    EXPECT_FALSE(boolStatus) << "incorrect HDRStaticInfo buffer accepted";

    sp<ABuffer> invalidHDRInfoBuffer = new ABuffer(kHDRBufferSize);
    ASSERT_NE(invalidHDRInfoBuffer, nullptr) << "failed to create ABuffer";
    uint8_t *data = invalidHDRInfoBuffer->data();
    *data = HDRStaticInfo::kType1 + 1;
    format->setBuffer(KEY_HDR_STATIC_INFO, invalidHDRInfoBuffer);
    memset(&hdrInfo, 0, sizeof(hdrInfo));
    boolStatus = ColorUtils::getHDRStaticInfoFromFormat(format, &hdrInfo);
    EXPECT_FALSE(boolStatus) << "incorrect HDRStaticInfo buffer accepted";

    CA aspects;
    format->setInt32(KEY_COLOR_RANGE, ColorUtils::kColorRangeVendorStart + CA::RangeOther + 1);
    format->setInt32(KEY_COLOR_STANDARD, CA::Standard::StandardBT709);
    format->setInt32(KEY_COLOR_TRANSFER, CA::Transfer::TransferLinear);
    ColorUtils::getColorAspectsFromFormat(format, aspects);
    EXPECT_EQ(aspects.mRange, CA::RangeOther) << "unexpected range";
}

TEST(ColorUtilsUnitTest, DataSpaceSanityTest) {
    CA aspects;
    aspects.mRange = CA::RangeUnspecified;
    aspects.mPrimaries = CA::PrimariesUnspecified;
    aspects.mMatrixCoeffs = CA::MatrixUnspecified;
    aspects.mTransfer = CA::TransferUnspecified;
    android_dataspace dataSpace = ColorUtils::getDataSpaceForColorAspects(aspects, true);
    EXPECT_EQ(dataSpace, 0) << "expected invalid dataspace";
    aspects.mPrimaries = CA::PrimariesUnspecified;
    aspects.mMatrixCoeffs = CA::MatrixBT2020Constant;
    dataSpace = ColorUtils::getDataSpaceForColorAspects(aspects, true);
    EXPECT_NE(dataSpace, 0) << "unexpected value";
}

INSTANTIATE_TEST_SUITE_P(ColorUtilsUnitTest, ColorRangeTest,
                         ::testing::Values(
                                 // ColorRange
                                 CA::Range::RangeLimited, CA::Range::RangeFull,
                                 CA::Range::RangeUnspecified, CA::Range::RangeOther));

INSTANTIATE_TEST_SUITE_P(ColorUtilsUnitTest, ColorTransferTest,
                         ::testing::Values(
                                 // ColorTransfer
                                 CA::Transfer::TransferUnspecified, CA::Transfer::TransferLinear,
                                 CA::Transfer::TransferSRGB, CA::Transfer::TransferSMPTE170M,
                                 CA::Transfer::TransferGamma22, CA::Transfer::TransferGamma28,
                                 CA::Transfer::TransferST2084, CA::Transfer::TransferHLG,
                                 CA::Transfer::TransferSMPTE240M, CA::Transfer::TransferXvYCC,
                                 CA::Transfer::TransferBT1361, CA::Transfer::TransferST428,
                                 CA::Transfer::TransferOther));

INSTANTIATE_TEST_SUITE_P(
        ColorUtilsUnitTest, ColorStandardTest,
        ::testing::Values(
                // Primaries, MatrixCoeffs
                std::make_pair(CA::Primaries::PrimariesUnspecified,
                               CA::MatrixCoeffs::MatrixUnspecified),
                std::make_pair(CA::Primaries::PrimariesBT709_5,
                               CA::MatrixCoeffs::MatrixBT709_5),
                std::make_pair(CA::Primaries::PrimariesBT601_6_625,
                               CA::MatrixCoeffs::MatrixBT601_6),
                std::make_pair(CA::Primaries::PrimariesBT601_6_625,
                               CA::MatrixCoeffs::MatrixBT709_5),
                std::make_pair(CA::Primaries::PrimariesBT601_6_525,
                               CA::MatrixCoeffs::MatrixBT601_6),
                std::make_pair(CA::Primaries::PrimariesBT601_6_525,
                               CA::MatrixCoeffs::MatrixSMPTE240M),
                std::make_pair(CA::Primaries::PrimariesBT2020,
                               CA::MatrixCoeffs::MatrixBT2020),
                std::make_pair(CA::Primaries::PrimariesBT2020,
                               CA::MatrixCoeffs::MatrixBT2020Constant),
                std::make_pair(CA::Primaries::PrimariesBT470_6M,
                               CA::MatrixCoeffs::MatrixBT470_6M),
                std::make_pair(CA::Primaries::PrimariesGenericFilm,
                               CA::MatrixCoeffs::MatrixBT2020)));

INSTANTIATE_TEST_SUITE_P(
        ColorUtilsUnitTest, ColorAspectsTest,
        ::testing::Values(
                // Primaries, ColorTransfer, MatrixCoeffs, ColorRange, ColorStandard
                std::make_tuple(CA::Primaries::PrimariesUnspecified,
                                CA::Transfer::TransferUnspecified,
                                CA::MatrixCoeffs::MatrixUnspecified, CA::Range::RangeFull,
                                CA::Standard::StandardUnspecified),
                std::make_tuple(CA::Primaries::PrimariesBT709_5, CA::Transfer::TransferLinear,
                                CA::MatrixCoeffs::MatrixBT709_5, CA::Range::RangeFull,
                                CA::Standard::StandardBT709),
                std::make_tuple(CA::Primaries::PrimariesBT601_6_625, CA::Transfer::TransferSRGB,
                                CA::MatrixCoeffs::MatrixBT601_6, CA::Range::RangeFull,
                                CA::Standard::StandardUnspecified),
                std::make_tuple(CA::Primaries::PrimariesBT601_6_625,
                                CA::Transfer::TransferSMPTE170M, CA::MatrixCoeffs::MatrixBT709_5,
                                CA::Range::RangeFull, CA::Standard::StandardUnspecified),
                std::make_tuple(CA::Primaries::PrimariesBT601_6_525, CA::Transfer::TransferGamma22,
                                CA::MatrixCoeffs::MatrixBT601_6, CA::Range::RangeFull,
                                CA::Standard::StandardUnspecified),
                std::make_tuple(CA::Primaries::PrimariesBT601_6_525, CA::Transfer::TransferGamma28,
                                CA::MatrixCoeffs::MatrixSMPTE240M, CA::Range::RangeFull,
                                CA::Standard::StandardBT470M),
                std::make_tuple(CA::Primaries::PrimariesBT2020, CA::Transfer::TransferST2084,
                                CA::MatrixCoeffs::MatrixBT2020, CA::Range::RangeFull,
                                CA::Standard::StandardBT601_525),
                std::make_tuple(CA::Primaries::PrimariesBT2020, CA::Transfer::TransferHLG,
                                CA::MatrixCoeffs::MatrixBT2020Constant, CA::Range::RangeFull,
                                CA::Standard::StandardBT601_525),
                std::make_tuple(CA::Primaries::PrimariesBT470_6M, CA::Transfer::TransferLinear,
                                CA::MatrixCoeffs::MatrixBT470_6M, CA::Range::RangeFull,
                                CA::Standard::StandardUnspecified),
                std::make_tuple(CA::Primaries::PrimariesGenericFilm, CA::Transfer::TransferLinear,
                                CA::MatrixCoeffs::MatrixBT2020, CA::Range::RangeFull,
                                CA::Standard::StandardBT601_625)));

INSTANTIATE_TEST_SUITE_P(
        ColorUtilsUnitTest, IsoToPlatformAspectsTest,
        ::testing::Values(
                // Primaries, Transfer, MatrixCoeffs, Standard, Transfer
                std::make_tuple(CA::PrimariesUnspecified, CA::TransferUnspecified,
                                CA::MatrixUnspecified, ColorUtils::kColorStandardUnspecified,
                                ColorUtils::kColorTransferUnspecified),
                std::make_tuple(CA::PrimariesBT709_5, CA::TransferLinear, CA::MatrixBT709_5,
                                ColorUtils::kColorStandardBT709, ColorUtils::kColorTransferLinear),
                std::make_tuple(CA::PrimariesBT601_6_625, CA::TransferSRGB, CA::MatrixBT601_6,
                                ColorUtils::kColorStandardBT601_625,
                                ColorUtils::kColorTransferSRGB),
                std::make_tuple(CA::PrimariesBT601_6_625, CA::TransferSMPTE170M, CA::MatrixBT709_5,
                                ColorUtils::kColorStandardBT601_625_Unadjusted,
                                ColorUtils::kColorTransferSMPTE_170M),
                std::make_tuple(CA::PrimariesBT601_6_525, CA::TransferGamma22, CA::MatrixBT601_6,
                                ColorUtils::kColorStandardBT601_525,
                                ColorUtils::kColorTransferGamma22),
                std::make_tuple(CA::PrimariesBT601_6_525, CA::TransferGamma28, CA::MatrixSMPTE240M,
                                ColorUtils::kColorStandardBT601_525_Unadjusted,
                                ColorUtils::kColorTransferGamma28),
                std::make_tuple(CA::PrimariesBT2020, CA::TransferST2084, CA::MatrixBT2020,
                                ColorUtils::kColorStandardBT2020, ColorUtils::kColorTransferST2084),
                std::make_tuple(CA::PrimariesBT2020, CA::TransferHLG, CA::MatrixBT2020Constant,
                                ColorUtils::kColorStandardBT2020Constant,
                                ColorUtils::kColorTransferHLG),
                std::make_tuple(CA::PrimariesBT470_6M, CA::TransferUnspecified, CA::MatrixBT470_6M,
                                ColorUtils::kColorStandardBT470M,
                                ColorUtils::kColorTransferUnspecified),
                std::make_tuple(CA::PrimariesGenericFilm, CA::TransferLinear, CA::MatrixBT2020,
                                ColorUtils::kColorStandardFilm, ColorUtils::kColorTransferLinear)));

INSTANTIATE_TEST_SUITE_P(
        ColorUtilsUnitTest, DefaultColorAspectsTest,
        ::testing::Values(
                // Width, Height, Primaries, MatrixCoeffs
                std::make_tuple(3840, 3840, CA::PrimariesBT2020, CA::MatrixBT2020),
                std::make_tuple(720, 576, CA::PrimariesBT601_6_625, CA::MatrixBT601_6),
                std::make_tuple(480, 360, CA::PrimariesBT601_6_525, CA::MatrixBT601_6),
                std::make_tuple(480, 1920, CA::PrimariesBT709_5, CA::MatrixBT709_5)));

INSTANTIATE_TEST_SUITE_P(
        ColorUtilsUnitTest, DataSpaceTest,
        ::testing::Values(
                // ColorRange, Primaries, ColorTransfer, MatrixCoeffs, v0_android_dataspace,
                // android_dataspace
                std::make_tuple(CA::Range::RangeFull, CA::Primaries::PrimariesBT709_5,
                                CA::Transfer::TransferSRGB, CA::MatrixCoeffs::MatrixBT709_5,
                                HAL_DATASPACE_V0_SRGB, HAL_DATASPACE_SRGB),
                std::make_tuple(CA::Range::RangeLimited, CA::Primaries::PrimariesBT709_5,
                                CA::Transfer::TransferSMPTE170M, CA::MatrixCoeffs::MatrixBT709_5,
                                HAL_DATASPACE_V0_BT709, HAL_DATASPACE_BT709),
                std::make_tuple(CA::Range::RangeFull, CA::Primaries::PrimariesBT709_5,
                                CA::Transfer::TransferLinear, CA::MatrixCoeffs::MatrixBT709_5,
                                HAL_DATASPACE_V0_SRGB_LINEAR, HAL_DATASPACE_SRGB_LINEAR),
                std::make_tuple(CA::Range::RangeLimited, CA::Primaries::PrimariesBT601_6_525,
                                CA::Transfer::TransferSMPTE170M, CA::MatrixCoeffs::MatrixBT601_6,
                                HAL_DATASPACE_V0_BT601_525, HAL_DATASPACE_BT601_525),
                std::make_tuple(CA::Range::RangeLimited, CA::Primaries::PrimariesBT601_6_625,
                                CA::Transfer::TransferSMPTE170M, CA::MatrixCoeffs::MatrixBT601_6,
                                HAL_DATASPACE_V0_BT601_625, HAL_DATASPACE_BT601_625),
                std::make_tuple(CA::Range::RangeFull, CA::Primaries::PrimariesBT601_6_625,
                                CA::Transfer::TransferSMPTE170M, CA::MatrixCoeffs::MatrixBT601_6,
                                HAL_DATASPACE_V0_JFIF, HAL_DATASPACE_JFIF),
                std::make_tuple(CA::Range::RangeLimited, CA::Primaries::PrimariesBT709_5,
                                CA::Transfer::TransferSMPTE170M, CA::MatrixCoeffs::MatrixBT470_6M,
                                HAL_DATASPACE_V0_BT601_625, HAL_DATASPACE_BT601_625),
                std::make_tuple(CA::Range::RangeLimited, CA::Primaries::PrimariesBT709_5,
                                CA::Transfer::TransferSMPTE170M, CA::MatrixCoeffs::MatrixBT601_6,
                                HAL_DATASPACE_V0_BT601_625, HAL_DATASPACE_BT601_625),
                std::make_tuple(CA::Range::RangeLimited, CA::Primaries::PrimariesBT709_5,
                                CA::Transfer::TransferSMPTE170M, CA::MatrixCoeffs::MatrixSMPTE240M,
                                HAL_DATASPACE_V0_BT709, HAL_DATASPACE_BT709),
                std::make_tuple(CA::Range::RangeLimited, CA::Primaries::PrimariesBT709_5,
                                CA::Transfer::TransferSMPTE170M, CA::MatrixCoeffs::MatrixBT2020,
                                HAL_DATASPACE_V0_BT709, HAL_DATASPACE_BT709),
                std::make_tuple(CA::Range::RangeLimited, CA::Primaries::PrimariesBT709_5,
                                CA::Transfer::TransferSMPTE170M,
                                CA::MatrixCoeffs::MatrixBT2020Constant, HAL_DATASPACE_V0_BT601_525,
                                HAL_DATASPACE_BT601_525),
                std::make_tuple(CA::Range::RangeLimited, CA::Primaries::PrimariesBT601_6_625,
                                CA::Transfer::TransferSMPTE170M, CA::MatrixCoeffs::MatrixBT470_6M,
                                HAL_DATASPACE_V0_BT601_625, HAL_DATASPACE_BT601_625),
                std::make_tuple(CA::Range::RangeLimited, CA::Primaries::PrimariesBT601_6_625,
                                CA::Transfer::TransferSMPTE170M,
                                CA::MatrixCoeffs::MatrixBT2020Constant, HAL_DATASPACE_V0_BT601_525,
                                HAL_DATASPACE_BT601_525),
                std::make_tuple(CA::Range::RangeLimited, CA::Primaries::PrimariesBT601_6_525,
                                CA::Transfer::TransferSMPTE170M, CA::MatrixCoeffs::MatrixBT470_6M,
                                HAL_DATASPACE_V0_BT601_525, HAL_DATASPACE_BT601_525),
                std::make_tuple(CA::Range::RangeLimited, CA::Primaries::PrimariesBT601_6_525,
                                CA::Transfer::TransferSMPTE170M,
                                CA::MatrixCoeffs::MatrixBT2020Constant, HAL_DATASPACE_V0_BT601_525,
                                HAL_DATASPACE_BT601_525)));
