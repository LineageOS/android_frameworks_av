/*
 * Copyright 2021 The Android Open Source Project
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
#define LOG_TAG "NdkMediaFormat_test"

#include <gtest/gtest.h>
#include <utils/RefBase.h>

#include <media/NdkMediaFormat.h>

namespace android {

class NdkMediaFormatTest : public ::testing::Test {
};


TEST(NdkMediaFormat_tests, test_create) {

   AMediaFormat *fmt1 = AMediaFormat_new();
   AMediaFormat *fmt2 = AMediaFormat_new();

   EXPECT_NE(fmt1, fmt2);
   EXPECT_NE(fmt1, nullptr);
   EXPECT_NE(fmt2, nullptr);

   AMediaFormat_delete(fmt1);
   AMediaFormat_delete(fmt2);
}

TEST(NdkMediaFormat_tests, test_int32) {
   AMediaFormat *fmt1 = AMediaFormat_new();
   int32_t i32;
   int64_t i64;
   AMediaFormat_setInt32(fmt1, "five", 5);

   EXPECT_TRUE(AMediaFormat_getInt32(fmt1, "five", &i32));
   EXPECT_FALSE(AMediaFormat_getInt64(fmt1, "five", &i64));
   EXPECT_EQ(i32, 5);

   // verify detecting some bad parameters.
   AMediaFormat_setInt32(nullptr, "whatever", 6);
   AMediaFormat_setInt32(fmt1, nullptr, 6);

   EXPECT_FALSE(AMediaFormat_getInt32(nullptr, "whatever", &i32));
   EXPECT_FALSE(AMediaFormat_getInt32(fmt1, nullptr, &i32));

   AMediaFormat_delete(fmt1);
}

TEST(NdkMediaFormat_tests, test_int64) {
   AMediaFormat *fmt1 = AMediaFormat_new();
   int64_t i64;
   AMediaFormat_setInt64(fmt1, "verylarge", INT64_MAX);

   EXPECT_TRUE(AMediaFormat_getInt64(fmt1, "verylarge", &i64));
   EXPECT_EQ(i64, INT64_MAX);

   // return unchanged if not found
   i64 = -1;
   EXPECT_FALSE(AMediaFormat_getInt64(fmt1, "five", &i64));
   EXPECT_EQ(i64, -1);

   // verify detecting some bad parameters.
   AMediaFormat_setInt64(nullptr, "whatever", 6);
   AMediaFormat_setInt64(fmt1, nullptr, 6);

   EXPECT_FALSE(AMediaFormat_getInt64(nullptr, "whatever", &i64));
   EXPECT_FALSE(AMediaFormat_getInt64(fmt1, nullptr, &i64));

   AMediaFormat_delete(fmt1);
}

TEST(NdkMediaFormat_tests, test_size) {
   AMediaFormat *fmt1 = AMediaFormat_new();

   size_t size = -15;
   AMediaFormat_setSize(fmt1, "small", 1);
   AMediaFormat_setSize(fmt1, "medium", 10);
   AMediaFormat_setSize(fmt1, "large", 100);
   EXPECT_TRUE(AMediaFormat_getSize(fmt1, "medium", &size));
   EXPECT_EQ(size, 10);

   // verify detecting some bad parameters.
   AMediaFormat_setSize(nullptr, "whatever", 6);
   AMediaFormat_setSize(fmt1, nullptr, 6);

   EXPECT_FALSE(AMediaFormat_getSize(nullptr, "whatever", &size));
   EXPECT_FALSE(AMediaFormat_getSize(fmt1, nullptr, &size));

   AMediaFormat_delete(fmt1);
}

TEST(NdkMediaFormat_tests, test_float) {
   AMediaFormat *fmt1 = AMediaFormat_new();
   float f;
   AMediaFormat_setFloat(fmt1, "boat", 1.5);
   AMediaFormat_setFloat(fmt1, "ship", 0.5);
   EXPECT_TRUE(AMediaFormat_getFloat(fmt1, "boat", &f));
   EXPECT_EQ(f, 1.5);

   // verify detecting some bad parameters.
   AMediaFormat_setFloat(nullptr, "whatever", 1.5);
   AMediaFormat_setFloat(fmt1, nullptr, 1.5);

   EXPECT_FALSE(AMediaFormat_getFloat(nullptr, "whatever", &f));
   EXPECT_FALSE(AMediaFormat_getFloat(fmt1, nullptr, &f));

   AMediaFormat_delete(fmt1);
}

TEST(NdkMediaFormat_tests, test_double) {
   AMediaFormat *fmt1 = AMediaFormat_new();
   double d;
   AMediaFormat_setDouble(fmt1, "trouble", 100.5);
   AMediaFormat_setDouble(fmt1, "dip", 0.5);
   EXPECT_TRUE(AMediaFormat_getDouble(fmt1, "trouble", &d));
   EXPECT_EQ(d, 100.5);

   // verify detecting some bad parameters.
   AMediaFormat_setDouble(nullptr, "whatever", 1.5);
   AMediaFormat_setDouble(fmt1, nullptr, 1.5);

   EXPECT_FALSE(AMediaFormat_getDouble(nullptr, "whatever", &d));
   EXPECT_FALSE(AMediaFormat_getDouble(fmt1, nullptr, &d));

   AMediaFormat_delete(fmt1);
}

TEST(NdkMediaFormat_tests, test_string) {
   AMediaFormat *fmt1 = AMediaFormat_new();

   const char *content = "This is my test string";
   const char *out = nullptr;
   AMediaFormat_setString(fmt1, "stringtheory", content);
   EXPECT_TRUE(AMediaFormat_getString(fmt1, "stringtheory", &out));
   EXPECT_NE(out, nullptr);
   EXPECT_NE(out, content);     // should not be the original
   EXPECT_EQ(strcmp(out,content), 0);

   // verify detecting some bad parameters.
   AMediaFormat_setString(nullptr, "whatever", content);
   AMediaFormat_setString(fmt1, nullptr, content);

   EXPECT_FALSE(AMediaFormat_getString(nullptr, "whatever", &out));
   EXPECT_FALSE(AMediaFormat_getString(fmt1, nullptr, &out));

   AMediaFormat_delete(fmt1);
}


TEST(NdkMediaFormat_tests, test_clear) {
   AMediaFormat *fmt1 = AMediaFormat_new();

   int32_t i32;
   AMediaFormat_setInt32(fmt1, "five", 5);
   size_t size = -15;
   AMediaFormat_setSize(fmt1, "medium", 10);
   float f;
   AMediaFormat_setFloat(fmt1, "boat", 1.5);

   AMediaFormat_clear(fmt1);
   EXPECT_FALSE(AMediaFormat_getInt32(fmt1, "five", &i32));
   EXPECT_FALSE(AMediaFormat_getSize(fmt1, "medium", &size));
   EXPECT_FALSE(AMediaFormat_getFloat(fmt1, "boat", &f));

   AMediaFormat_delete(fmt1);
}

TEST(NdkMediaFormat_tests, test_copy) {
   AMediaFormat *fmt1 = AMediaFormat_new();
   AMediaFormat *fmt2 = AMediaFormat_new();

   double d;
   int32_t i32;

   // test copy functionality (NB: we cleared everything just above here)
   AMediaFormat_setDouble(fmt1, "trouble", 100.5);
   EXPECT_TRUE(AMediaFormat_getDouble(fmt1, "trouble", &d));
   EXPECT_FALSE(AMediaFormat_getDouble(fmt2, "trouble", &d));

   EXPECT_EQ(AMEDIA_OK, AMediaFormat_copy(fmt2, fmt1));

   EXPECT_TRUE(AMediaFormat_getDouble(fmt2, "trouble", &d));
   EXPECT_EQ(d, 100.5);

   AMediaFormat *fmt3 = nullptr;
   EXPECT_NE(AMEDIA_OK, AMediaFormat_copy(fmt3, fmt1));
   EXPECT_NE(AMEDIA_OK, AMediaFormat_copy(fmt1, fmt3));

   // we should lose an entry when we copy over it
   AMediaFormat_setInt32(fmt2, "vanishing", 50);
   EXPECT_FALSE(AMediaFormat_getInt32(fmt1, "vanishing", &i32));
   EXPECT_TRUE(AMediaFormat_getInt32(fmt2, "vanishing", &i32));
   EXPECT_EQ(AMEDIA_OK, AMediaFormat_copy(fmt2, fmt1));
   EXPECT_FALSE(AMediaFormat_getInt32(fmt2, "vanishing", &i32));

   AMediaFormat_delete(fmt1);
   AMediaFormat_delete(fmt2);
}

TEST(NdkMediaFormat_tests, test_buffer) {
   AMediaFormat *fmt1 = AMediaFormat_new();

   typedef struct blockomem {
        int leading;
        int filled[100];
        int trailing;
   } block_t;
   block_t buf = {};
   buf.leading = 1;
   buf.trailing = 2;
   void *data;
   size_t bsize;

   AMediaFormat_setBuffer(fmt1, "mybuffer", &buf, sizeof(buf));
   EXPECT_TRUE(AMediaFormat_getBuffer(fmt1, "mybuffer", &data, &bsize));
   EXPECT_NE(&buf, data);
   EXPECT_EQ(sizeof(buf), bsize);
   block_t *bufp = (block_t*) data;
   EXPECT_EQ(bufp->leading, buf.leading);
   EXPECT_EQ(bufp->trailing, buf.trailing);
   EXPECT_EQ(0, memcmp(&buf, data, bsize));

   AMediaFormat_delete(fmt1);
}

} // namespace android
