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
#define LOG_TAG "TimedTextUnitTest"
#include <utils/Log.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fstream>

#include <binder/Parcel.h>
#include <media/stagefright/foundation/AString.h>
#include <media/stagefright/foundation/ByteUtils.h>

#include "timedtext/TextDescriptions.h"

#include "TimedTextTestEnvironment.h"

constexpr int32_t kStartTimeMs = 10000;

enum {
    // These keys must be in sync with the keys in
    // frameworks/av/media/libstagefright/timedtext/TextDescriptions.h
    KEY_DISPLAY_FLAGS = 1,
    KEY_STYLE_FLAGS = 2,
    KEY_BACKGROUND_COLOR_RGBA = 3,
    KEY_HIGHLIGHT_COLOR_RGBA = 4,
    KEY_SCROLL_DELAY = 5,
    KEY_WRAP_TEXT = 6,
    KEY_START_TIME = 7,
    KEY_STRUCT_BLINKING_TEXT_LIST = 8,
    KEY_STRUCT_FONT_LIST = 9,
    KEY_STRUCT_HIGHLIGHT_LIST = 10,
    KEY_STRUCT_HYPER_TEXT_LIST = 11,
    KEY_STRUCT_KARAOKE_LIST = 12,
    KEY_STRUCT_STYLE_LIST = 13,
    KEY_STRUCT_TEXT_POS = 14,
    KEY_STRUCT_JUSTIFICATION = 15,
    KEY_STRUCT_TEXT = 16,

    KEY_GLOBAL_SETTING = 101,
    KEY_LOCAL_SETTING = 102,
    KEY_START_CHAR = 103,
    KEY_END_CHAR = 104,
    KEY_FONT_ID = 105,
    KEY_FONT_SIZE = 106,
    KEY_TEXT_COLOR_RGBA = 107,
};

struct FontInfo {
    int32_t displayFlag = -1;
    int32_t horizontalJustification = -1;
    int32_t verticalJustification = -1;
    int32_t rgbaBackground = -1;
    int32_t leftPos = -1;
    int32_t topPos = -1;
    int32_t bottomPos = -1;
    int32_t rightPos = -1;
    int32_t startchar = -1;
    int32_t endChar = -1;
    int32_t fontId = -1;
    int32_t faceStyle = -1;
    int32_t fontSize = -1;
    int32_t rgbaText = -1;
    int32_t entryCount = -1;
};

struct FontRecord {
    int32_t fontID = -1;
    int32_t fontNameLength = -1;
    const uint8_t *font = nullptr;
};

using namespace android;

static TimedTextTestEnvironment *gEnv = nullptr;

class TimedTextUnitTest : public ::testing::TestWithParam</*filename*/ string> {
  public:
    TimedTextUnitTest(){};

    ~TimedTextUnitTest() {
        if (mEleStream) mEleStream.close();
    }

    virtual void SetUp() override {
        mInputFileName = gEnv->getRes() + GetParam();
        mEleStream.open(mInputFileName, ifstream::binary);
        ASSERT_EQ(mEleStream.is_open(), true) << "Failed to open " << GetParam();

        struct stat buf;
        status_t status = stat(mInputFileName.c_str(), &buf);
        ASSERT_EQ(status, 0) << "Failed to get properties of input file: " << GetParam();
        mFileSize = buf.st_size;
        ALOGI("Size of the input file %s = %zu", GetParam().c_str(), mFileSize);
    }

    string mInputFileName;
    size_t mFileSize;
    ifstream mEleStream;
};

class SRTDescriptionTest : public TimedTextUnitTest {
  public:
    virtual void SetUp() override { TimedTextUnitTest::SetUp(); }
};

class Text3GPPDescriptionTest : public TimedTextUnitTest {
  public:
    virtual void SetUp() override { TimedTextUnitTest::SetUp(); }
};

TEST_P(SRTDescriptionTest, extractSRTDescriptionTest) {
    char data[mFileSize];
    mEleStream.read(data, sizeof(data));
    ASSERT_EQ(mEleStream.gcount(), mFileSize);

    Parcel parcel;
    int32_t flag = TextDescriptions::OUT_OF_BAND_TEXT_SRT | TextDescriptions::LOCAL_DESCRIPTIONS;
    status_t status = TextDescriptions::getParcelOfDescriptions((const uint8_t *)data, mFileSize,
                                                                flag, kStartTimeMs, &parcel);
    ASSERT_EQ(status, 0) << "getParcelOfDescriptions returned error";
    ALOGI("Size of the Parcel: %zu", parcel.dataSize());
    ASSERT_GT(parcel.dataSize(), 0) << "Parcel is empty";

    parcel.setDataPosition(0);
    int32_t key = parcel.readInt32();
    ASSERT_EQ(key, KEY_LOCAL_SETTING) << "Parcel has invalid key";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_START_TIME) << "Parcel has invalid start time key";
    ASSERT_EQ(parcel.readInt32(), kStartTimeMs) << "Parcel has invalid timings";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_STRUCT_TEXT) << "Parcel has invalid struct text key";
    ASSERT_EQ(parcel.readInt32(), mFileSize) << "Parcel has invalid text data";
    int32_t fileSize = parcel.readInt32();
    ASSERT_EQ(fileSize, mFileSize) << "Parcel has invalid file size value";
    uint8_t tmpData[fileSize];
    status = parcel.read((void *)tmpData, fileSize);
    ASSERT_EQ(status, 0) << "Failed to read the data from parcel";
    // To make sure end of parcel is reached
    ASSERT_EQ(parcel.dataAvail(), 0) << "Parcel has some data left to read";
}

// This test uses the properties of tx3g box mentioned in 3GPP Timed Text Format
// Specification#: 26.245 / Section: 5.16(Sample Description Format)
// https://www.3gpp.org/ftp/Specs/archive/26_series/26.245/

TEST_P(Text3GPPDescriptionTest, Text3GPPGlobalDescriptionTest) {
    char data[mFileSize];
    mEleStream.read(data, sizeof(data));
    ASSERT_EQ(mEleStream.gcount(), mFileSize);

    const uint8_t *tmpData = (const uint8_t *)data;
    int32_t remaining = mFileSize;
    FontInfo fontInfo;
    vector<FontRecord> fontRecordEntries;

    // Skipping the bytes containing information about the type of subbox(tx3g)
    tmpData += 16;
    remaining -= 16;

    fontInfo.displayFlag = U32_AT(tmpData);
    ALOGI("Display flag: %d", fontInfo.displayFlag);
    fontInfo.horizontalJustification = tmpData[4];
    ALOGI("Horizontal Justification: %d", fontInfo.horizontalJustification);
    fontInfo.verticalJustification = tmpData[5];
    ALOGI("Vertical Justification: %d", fontInfo.verticalJustification);
    fontInfo.rgbaBackground =
            *(tmpData + 6) << 24 | *(tmpData + 7) << 16 | *(tmpData + 8) << 8 | *(tmpData + 9);
    ALOGI("rgba value of background: %d", fontInfo.rgbaBackground);

    tmpData += 10;
    remaining -= 10;

    if (remaining >= 8) {
        fontInfo.leftPos = U16_AT(tmpData);
        ALOGI("Left: %d", fontInfo.leftPos);
        fontInfo.topPos = U16_AT(tmpData + 2);
        ALOGI("Top: %d", fontInfo.topPos);
        fontInfo.bottomPos = U16_AT(tmpData + 4);
        ALOGI("Bottom: %d", fontInfo.bottomPos);
        fontInfo.rightPos = U16_AT(tmpData + 6);
        ALOGI("Right: %d", fontInfo.rightPos);

        tmpData += 8;
        remaining -= 8;

        if (remaining >= 12) {
            fontInfo.startchar = U16_AT(tmpData);
            ALOGI("Start character: %d", fontInfo.startchar);
            fontInfo.endChar = U16_AT(tmpData + 2);
            ALOGI("End character: %d", fontInfo.endChar);
            fontInfo.fontId = U16_AT(tmpData + 4);
            ALOGI("Value of font Identifier: %d", fontInfo.fontId);
            fontInfo.faceStyle = *(tmpData + 6);
            ALOGI("Face style flag : %d", fontInfo.faceStyle);
            fontInfo.fontSize = *(tmpData + 7);
            ALOGI("Size of the font: %d", fontInfo.fontSize);
            fontInfo.rgbaText = *(tmpData + 8) << 24 | *(tmpData + 9) << 16 | *(tmpData + 10) << 8 |
                                *(tmpData + 11);
            ALOGI("rgba value of the text: %d", fontInfo.rgbaText);

            tmpData += 12;
            remaining -= 12;

            if (remaining >= 10) {
                // Skipping the bytes containing information about the type of subbox(ftab)
                fontInfo.entryCount = U16_AT(tmpData + 8);
                ALOGI("Value of entry count: %d", fontInfo.entryCount);

                tmpData += 10;
                remaining -= 10;

                for (int32_t i = 0; i < fontInfo.entryCount; i++) {
                    if (remaining < 3) break;
                    int32_t tempFontID = U16_AT(tmpData);
                    ALOGI("Font Id: %d", tempFontID);
                    int32_t tempFontNameLength = *(tmpData + 2);
                    ALOGI("Length of font name: %d", tempFontNameLength);

                    tmpData += 3;
                    remaining -= 3;

                    if (remaining < tempFontNameLength) break;
                    const uint8_t *tmpFont = tmpData;
                    char *tmpFontName = strndup((const char *)tmpFont, tempFontNameLength);
                    ASSERT_NE(tmpFontName, nullptr) << "Font Name is null";
                    ALOGI("FontName = %s", tmpFontName);
                    free(tmpFontName);
                    tmpData += tempFontNameLength;
                    remaining -= tempFontNameLength;
                    fontRecordEntries.push_back({tempFontID, tempFontNameLength, tmpFont});
                }
            }
        }
    }

    Parcel parcel;
    int32_t flag = TextDescriptions::IN_BAND_TEXT_3GPP | TextDescriptions::GLOBAL_DESCRIPTIONS;
    status_t status = TextDescriptions::getParcelOfDescriptions((const uint8_t *)data, mFileSize,
                                                                flag, kStartTimeMs, &parcel);
    ASSERT_EQ(status, 0) << "getParcelOfDescriptions returned error";
    ALOGI("Size of the Parcel: %zu", parcel.dataSize());
    ASSERT_GT(parcel.dataSize(), 0) << "Parcel is empty";

    parcel.setDataPosition(0);
    int32_t key = parcel.readInt32();
    ASSERT_EQ(key, KEY_GLOBAL_SETTING) << "Parcel has invalid key";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_DISPLAY_FLAGS) << "Parcel has invalid DISPLAY FLAGS Key";
    ASSERT_EQ(parcel.readInt32(), fontInfo.displayFlag)
            << "Parcel has invalid value of display flag";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_STRUCT_JUSTIFICATION) << "Parcel has invalid STRUCT JUSTIFICATION key";
    ASSERT_EQ(parcel.readInt32(), fontInfo.horizontalJustification)
            << "Parcel has invalid value of Horizontal justification";
    ASSERT_EQ(parcel.readInt32(), fontInfo.verticalJustification)
            << "Parcel has invalid value of Vertical justification";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_BACKGROUND_COLOR_RGBA) << "Parcel has invalid BACKGROUND COLOR key";
    ASSERT_EQ(parcel.readInt32(), fontInfo.rgbaBackground)
            << "Parcel has invalid rgba background color value";

    if (parcel.dataAvail() == 0) {
        ALOGV("Completed reading the parcel");
        return;
    }

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_STRUCT_TEXT_POS) << "Parcel has invalid STRUCT TEXT POSITION key";
    ASSERT_EQ(parcel.readInt32(), fontInfo.leftPos)
            << "Parcel has invalid rgba background color value";
    ASSERT_EQ(parcel.readInt32(), fontInfo.topPos)
            << "Parcel has invalid rgba background color value";
    ASSERT_EQ(parcel.readInt32(), fontInfo.bottomPos)
            << "Parcel has invalid rgba background color value";
    ASSERT_EQ(parcel.readInt32(), fontInfo.rightPos)
            << "Parcel has invalid rgba background color value";

    if (parcel.dataAvail() == 0) {
        ALOGV("Completed reading the parcel");
        return;
    }

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_STRUCT_STYLE_LIST) << "Parcel has invalid STRUCT STYLE LIST key";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_START_CHAR) << "Parcel has invalid START CHAR key";
    ASSERT_EQ(parcel.readInt32(), fontInfo.startchar)
            << "Parcel has invalid value of start character";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_END_CHAR) << "Parcel has invalid END CHAR key";
    ASSERT_EQ(parcel.readInt32(), fontInfo.endChar) << "Parcel has invalid value of end character";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_FONT_ID) << "Parcel has invalid FONT ID key";
    ASSERT_EQ(parcel.readInt32(), fontInfo.fontId) << "Parcel has invalid value of font Id";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_STYLE_FLAGS) << "Parcel has invalid STYLE FLAGS key";
    ASSERT_EQ(parcel.readInt32(), fontInfo.faceStyle) << "Parcel has invalid value of style flags";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_FONT_SIZE) << "Parcel has invalid FONT SIZE key";
    ASSERT_EQ(parcel.readInt32(), fontInfo.fontSize) << "Parcel has invalid value of font size";

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_TEXT_COLOR_RGBA) << "Parcel has invalid TEXT COLOR RGBA key";
    ASSERT_EQ(parcel.readInt32(), fontInfo.rgbaText) << "Parcel has invalid rgba text color value";

    if (parcel.dataAvail() == 0) {
        ALOGV("Completed reading the parcel");
        return;
    }

    key = parcel.readInt32();
    ASSERT_EQ(key, KEY_STRUCT_FONT_LIST) << "Parcel has invalid STRUCT FONT LIST key";
    ASSERT_EQ(parcel.readInt32(), fontInfo.entryCount) << "Parcel has invalid value of entry count";
    ASSERT_EQ(fontInfo.entryCount, fontRecordEntries.size())
            << "Array size does not match expected number of entries";
    for (int32_t i = 0; i < fontInfo.entryCount; i++) {
        ASSERT_EQ(parcel.readInt32(), fontRecordEntries[i].fontID)
                << "Parcel has invalid value of font Id";
        ASSERT_EQ(parcel.readInt32(), fontRecordEntries[i].fontNameLength)
                << "Parcel has invalid value of font name length";
        uint8_t fontName[fontRecordEntries[i].fontNameLength];
        // written with writeByteArray() writes count, then the actual data
        ASSERT_EQ(parcel.readInt32(), fontRecordEntries[i].fontNameLength);
        status = parcel.read((void *)fontName, fontRecordEntries[i].fontNameLength);
        ASSERT_EQ(status, 0) << "Failed to read the font name from parcel";
        ASSERT_EQ(memcmp(fontName, fontRecordEntries[i].font, fontRecordEntries[i].fontNameLength),
                  0)
                << "Parcel has invalid font";
    }
    // To make sure end of parcel is reached
    ASSERT_EQ(parcel.dataAvail(), 0) << "Parcel has some data left to read";
}

INSTANTIATE_TEST_SUITE_P(TimedTextUnitTestAll, SRTDescriptionTest,
                         ::testing::Values(("sampleTest1.srt"),
                                           ("sampleTest2.srt")));

INSTANTIATE_TEST_SUITE_P(TimedTextUnitTestAll, Text3GPPDescriptionTest,
                         ::testing::Values(("tx3gBox1"),
                                           ("tx3gBox2")));

int main(int argc, char **argv) {
    gEnv = new TimedTextTestEnvironment();
    ::testing::AddGlobalTestEnvironment(gEnv);
    ::testing::InitGoogleTest(&argc, argv);
    int status = gEnv->initFromOptions(argc, argv);
    if (status == 0) {
        status = RUN_ALL_TESTS();
        ALOGV("Test result = %d\n", status);
    }
    return status;
}
