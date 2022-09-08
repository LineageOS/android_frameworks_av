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
#define LOG_TAG "AData_test"

#include <gtest/gtest.h>
#include <utils/RefBase.h>

#include <media/stagefright/foundation/AMessage.h>

using namespace android;

class AMessageTest : public ::testing::Test {
};


TEST(AMessage_tests, item_manipulation) {
  sp<AMessage> m1 = new AMessage();

  m1->setInt32("value", 2);
  m1->setInt32("bar", 3);

  int32_t i32;
  EXPECT_TRUE(m1->findInt32("value", &i32));
  EXPECT_EQ(2, i32);

  EXPECT_TRUE(m1->findInt32("bar", &i32));
  EXPECT_EQ(3, i32);


  m1->setInt64("big", INT64_MAX);
  m1->setInt64("smaller", INT64_MAX - 2);
  m1->setInt64("smallest", 257);

  int64_t i64;
  EXPECT_TRUE(m1->findInt64("big", &i64));
  EXPECT_EQ(INT64_MAX, i64);

  EXPECT_TRUE(m1->findInt64("smaller", &i64));
  EXPECT_EQ(INT64_MAX - 2, i64);

  m1->setSize("size1", 257);
  m1->setSize("size2", 1023);

  size_t sizing;
  EXPECT_TRUE(m1->findSize("size2", &sizing));
  EXPECT_EQ(1023, sizing);
  EXPECT_TRUE(m1->findSize("size1", &sizing));
  EXPECT_EQ(257, sizing);

  m1->setDouble("precise", 10.5);
  m1->setDouble("small", 0.125);

  double d;
  EXPECT_TRUE(m1->findDouble("precise", &d));
  EXPECT_EQ(10.5, d);

  EXPECT_TRUE(m1->findDouble("small", &d));
  EXPECT_EQ(0.125, d);

  // should be unchanged from the top of the test
  EXPECT_TRUE(m1->findInt32("bar", &i32));
  EXPECT_EQ(3, i32);

  EXPECT_FALSE(m1->findInt32("nonesuch", &i32));
  EXPECT_FALSE(m1->findInt64("nonesuch2", &i64));
  // types disagree, not found
  EXPECT_FALSE(m1->findInt32("big", &i32));
  EXPECT_FALSE(m1->findInt32("precise", &i32));

  // integral types should come back true
  EXPECT_TRUE(m1->findAsInt64("big", &i64));
  EXPECT_EQ(INT64_MAX, i64);
  EXPECT_TRUE(m1->findAsInt64("bar", &i64));
  EXPECT_EQ(3, i64);
  EXPECT_FALSE(m1->findAsInt64("precise", &i64));

  // recovers ints, size, and floating point values
  float value;
  EXPECT_TRUE(m1->findAsFloat("value", &value));
  EXPECT_EQ(2, value);
  EXPECT_TRUE(m1->findAsFloat("smallest", &value));
  EXPECT_EQ(257, value);
  EXPECT_TRUE(m1->findAsFloat("size2", &value));
  EXPECT_EQ(1023, value);
  EXPECT_TRUE(m1->findAsFloat("precise", &value));
  EXPECT_EQ(10.5, value);
  EXPECT_TRUE(m1->findAsFloat("small", &value));
  EXPECT_EQ(0.125, value);


  // need to handle still:
  // strings
  // Object
  // Buffer
  // Message (nested)
  //

  // removal
  m1->setInt32("shortlived", 2);
  m1->setInt32("alittlelonger", 2);
  EXPECT_EQ(OK, m1->removeEntryByName("shortlived"));
  EXPECT_EQ(BAD_VALUE, m1->removeEntryByName(nullptr));
  EXPECT_EQ(BAD_INDEX, m1->removeEntryByName("themythicalnonesuch"));
  EXPECT_FALSE(m1->findInt32("shortlived", &i32));
  EXPECT_TRUE(m1->findInt32("alittlelonger", &i32));

  EXPECT_NE(OK, m1->removeEntryByName("notpresent"));

}

