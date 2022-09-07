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
#include <gtest/gtest.h>

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fstream>

#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MetaDataBase.h>

constexpr int32_t kWidth1 = 1920;
constexpr int32_t kHeight1 = 1080;
constexpr int32_t kWidth2 = 1280;
constexpr int32_t kHeight2 = 920;
constexpr int32_t kWidth3 = 720;
constexpr int32_t kHeight3 = 480;
constexpr int32_t kProfile = 1;
constexpr int32_t kLevel = 1;
constexpr int32_t kPlatformValue = 1;

// Rectangle margins
constexpr int32_t kLeft = 100;
constexpr int32_t kTop = 100;
constexpr int32_t kRight = 100;
constexpr int32_t kBottom = 100;

constexpr int64_t kDurationUs = 60000000;

constexpr float kCaptureRate = 30.0;

namespace android {

class MetaDataBaseUnitTest : public ::testing::Test {};

TEST_F(MetaDataBaseUnitTest, CreateMetaDataBaseTest) {
    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create meta data";

    // Testing copy constructor
    MetaDataBase *metaDataCopy = metaData;
    ASSERT_NE(metaDataCopy, nullptr) << "Failed to create meta data copy";

    delete metaData;
}

TEST_F(MetaDataBaseUnitTest, SetAndFindDataTest) {
    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create meta data";

    // Setting the different key-value pair type for first time, overwrite
    // expected to be false
    bool status = metaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_AVC);
    ASSERT_FALSE(status) << "Initializing kKeyMIMEType, overwrite is expected to be false";

    status = metaData->setInt32(kKeyWidth, kWidth1);
    ASSERT_FALSE(status) << "Initializing kKeyWidth, overwrite is expected to be false";
    status = metaData->setInt32(kKeyHeight, kHeight1);
    ASSERT_FALSE(status) << "Initializing kKeyHeight, overwrite is expected to be false";
    status = metaData->setInt32(kKeyVideoProfile, kProfile);
    ASSERT_FALSE(status) << "Initializing kKeyVideoProfile, overwrite is expected to be false";
    status = metaData->setInt32(kKeyVideoLevel, kLevel);
    ASSERT_FALSE(status) << "Initializing kKeyVideoLevel, overwrite is expected to be false";

    status = metaData->setInt64(kKeyDuration, kDurationUs);
    ASSERT_FALSE(status) << "Initializing kKeyDuration, overwrite is expected to be false";

    status = metaData->setFloat(kKeyCaptureFramerate, kCaptureRate);
    ASSERT_FALSE(status) << "Initializing kKeyCaptureFramerate, overwrite is expected to be false";

    const int32_t *platform = &kPlatformValue;
    status = metaData->setPointer(kKeyPlatformPrivate, (void *)platform);
    ASSERT_FALSE(status) << "Initializing kKeyPlatformPrivate, overwrite is expected to be false";

    status = metaData->setRect(kKeyCropRect, kLeft, kTop, kRight, kBottom);
    ASSERT_FALSE(status) << "Initializing kKeyCropRect, overwrite is expected to be false";

    // Dump to log for reference
    metaData->dumpToLog();

    // Find the data which was set
    const char *mime;
    status = metaData->findCString(kKeyMIMEType, &mime);
    ASSERT_TRUE(status) << "kKeyMIMEType key does not exists in metadata";
    ASSERT_STREQ(mime, MEDIA_MIMETYPE_VIDEO_AVC) << "Incorrect mime type returned";

    int32_t width, height, profile, level;
    status = metaData->findInt32(kKeyWidth, &width);
    ASSERT_TRUE(status) << "kKeyWidth key does not exists in metadata";
    ASSERT_EQ(width, kWidth1) << "Incorrect value of width returned";

    status = metaData->findInt32(kKeyHeight, &height);
    ASSERT_TRUE(status) << "kKeyHeight key does not exists in metadata";
    ASSERT_EQ(height, kHeight1) << "Incorrect value of height returned";

    status = metaData->findInt32(kKeyVideoProfile, &profile);
    ASSERT_TRUE(status) << "kKeyVideoProfile key does not exists in metadata";
    ASSERT_EQ(profile, kProfile) << "Incorrect value of profile returned";

    status = metaData->findInt32(kKeyVideoLevel, &level);
    ASSERT_TRUE(status) << "kKeyVideoLevel key does not exists in metadata";
    ASSERT_EQ(level, kLevel) << "Incorrect value of level returned";

    int64_t duration;
    status = metaData->findInt64(kKeyDuration, &duration);
    ASSERT_TRUE(status) << "kKeyDuration key does not exists in metadata";
    ASSERT_EQ(duration, kDurationUs) << "Incorrect value of duration returned";

    float frameRate;
    status = metaData->findFloat(kKeyCaptureFramerate, &frameRate);
    ASSERT_TRUE(status) << "kKeyCaptureFramerate key does not exists in metadata";
    ASSERT_EQ(frameRate, kCaptureRate) << "Incorrect value of captureFrameRate returned";

    int32_t top, bottom, left, right;
    status = metaData->findRect(kKeyCropRect, &left, &top, &right, &bottom);
    ASSERT_TRUE(status) << "kKeyCropRect key does not exists in metadata";
    ASSERT_EQ(left, kLeft) << "Incorrect value of left margin returned";
    ASSERT_EQ(top, kTop) << "Incorrect value of top margin returned";
    ASSERT_EQ(right, kRight) << "Incorrect value of right margin returned";
    ASSERT_EQ(bottom, kBottom) << "Incorrect value of bottom margin returned";

    void *platformValue;
    status = metaData->findPointer(kKeyPlatformPrivate, &platformValue);
    ASSERT_TRUE(status) << "kKeyPlatformPrivate key does not exists in metadata";
    ASSERT_EQ(platformValue, &kPlatformValue) << "Incorrect value of pointer returned";

    // Check for the key which is not added to metadata
    int32_t angle;
    status = metaData->findInt32(kKeyRotation, &angle);
    ASSERT_FALSE(status) << "Value for an invalid key is returned when the key is not set";

    delete (metaData);
}

TEST_F(MetaDataBaseUnitTest, OverWriteFunctionalityTest) {
    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create meta data";

    // set/set/read to check first overwrite operation
    bool status = metaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_AVC);
    ASSERT_FALSE(status) << "Initializing kKeyMIMEType, overwrite is expected to be false";
    // Overwrite the value
    status = metaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_HEVC);
    ASSERT_TRUE(status) << "Setting kKeyMIMEType again, overwrite is expected to be true";
    // Check the value
    const char *mime;
    status = metaData->findCString(kKeyMIMEType, &mime);
    ASSERT_TRUE(status) << "kKeyMIMEType key does not exists in metadata";
    ASSERT_STREQ(mime, MEDIA_MIMETYPE_VIDEO_HEVC) << "Mime value is not overwritten";

    // set/set/set/read to check second overwrite operation
    status = metaData->setInt32(kKeyWidth, kWidth1);
    ASSERT_FALSE(status) << "Initializing kKeyWidth, overwrite is expected to be false";
    status = metaData->setInt32(kKeyHeight, kHeight1);
    ASSERT_FALSE(status) << "Initializing kKeyHeight, overwrite is expected to be false";
    // Overwrite the value
    status = metaData->setInt32(kKeyWidth, kWidth2);
    ASSERT_TRUE(status) << "Setting kKeyWidth again, overwrite is expected to be true";
    status = metaData->setInt32(kKeyHeight, kHeight2);
    ASSERT_TRUE(status) << "Setting kKeyHeight again, overwrite is expected to be true";
    // Overwrite the value again
    status = metaData->setInt32(kKeyWidth, kWidth3);
    ASSERT_TRUE(status) << "Setting kKeyWidth again, overwrite is expected to be true";
    status = metaData->setInt32(kKeyHeight, kHeight3);
    ASSERT_TRUE(status) << "Setting kKeyHeight again, overwrite is expected to be true";
    // Check the value
    int32_t width, height;
    status = metaData->findInt32(kKeyWidth, &width);
    ASSERT_TRUE(status) << "kKeyWidth key does not exists in metadata";
    ASSERT_EQ(width, kWidth3) << "Value of width is not overwritten";

    status = metaData->findInt32(kKeyHeight, &height);
    ASSERT_TRUE(status) << "kKeyHeight key does not exists in metadata";
    ASSERT_EQ(height, kHeight3) << "Value of height is not overwritten";

    delete (metaData);
}

TEST_F(MetaDataBaseUnitTest, RemoveKeyTest) {
    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create meta data";

    bool status = metaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_AVC);
    ASSERT_FALSE(status) << "Initializing kKeyMIMEType, overwrite is expected to be false";
    // Query the key
    status = metaData->hasData(kKeyMIMEType);
    ASSERT_TRUE(status) << "MetaData does not have the mime key";

    status = metaData->remove(kKeyMIMEType);
    ASSERT_TRUE(status) << "Failed to remove the kKeyMIMEType key";

    // Query the key
    status = metaData->hasData(kKeyMIMEType);
    ASSERT_FALSE(status) << "MetaData has mime key after removing it, expected to be false";

    // Remove the non existing key
    status = metaData->remove(kKeyMIMEType);
    ASSERT_FALSE(status) << "Removed the non existing key";

    // Check overwriting the removed key
    metaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_HEVC);
    ASSERT_FALSE(status) << "Overwrite should be false since the key was removed";

    status = metaData->setInt32(kKeyWidth, kWidth1);
    ASSERT_FALSE(status) << "Initializing kKeyWidth, overwrite is expected to be false";

    // Clear whole metadata
    metaData->clear();

    // Check finding key after clearing the metadata
    int32_t width;
    status = metaData->findInt32(kKeyWidth, &width);
    ASSERT_FALSE(status) << "MetaData found kKeyWidth key after clearing all the items in it, "
                            "expected to be false";

    // Query the key
    status = metaData->hasData(kKeyWidth);
    ASSERT_FALSE(status)
            << "MetaData has width key after clearing all the items in it, expected to be false";

    status = metaData->hasData(kKeyMIMEType);
    ASSERT_FALSE(status)
            << "MetaData has mime key after clearing all the items in it, expected to be false";

    // Check removing key after clearing the metadata
    status = metaData->remove(kKeyMIMEType);
    ASSERT_FALSE(status) << "Removed the key, after clearing the metadata";

    // Checking set after clearing the metadata
    status = metaData->setInt32(kKeyWidth, kWidth1);
    ASSERT_FALSE(status) << "Overwrite should be false since the metadata was cleared";

    metaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_HEVC);
    ASSERT_FALSE(status) << "Overwrite should be false since the metadata was cleared";

    delete (metaData);
}

TEST_F(MetaDataBaseUnitTest, ConvertToStringTest) {
    MetaDataBase *metaData = new MetaDataBase();
    ASSERT_NE(metaData, nullptr) << "Failed to create meta data";

    String8 info = metaData->toString();
    ASSERT_EQ(info.length(), 0) << "Empty MetaData length is non-zero: " << info.length();

    bool status = metaData->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_AVC);
    ASSERT_FALSE(status) << "Initializing kKeyMIMEType, overwrite is expected to be false";

    status = metaData->setInt32(kKeyWidth, kWidth1);
    ASSERT_FALSE(status) << "Initializing kKeyWidth, overwrite is expected to be false";
    status = metaData->setInt32(kKeyHeight, kHeight1);
    ASSERT_FALSE(status) << "Initializing kKeyHeight, overwrite is expected to be false";
    status = metaData->setInt32(kKeyVideoProfile, kProfile);
    ASSERT_FALSE(status) << "Initializing kKeyVideoProfile, overwrite is expected to be false";
    status = metaData->setInt32(kKeyVideoLevel, kLevel);
    ASSERT_FALSE(status) << "Initializing kKeyVideoLevel, overwrite is expected to be false";

    info = metaData->toString();
    ASSERT_GT(info.length(), 0) << "MetaData contains no information";

    // Dump to log for reference
    metaData->dumpToLog();

    // Clear whole metadata
    metaData->clear();

    info = metaData->toString();
    ASSERT_EQ(info.length(), 0) << "MetaData length is non-zero after clearing it: "
                                << info.length();

    delete (metaData);
}

}  // namespace android
