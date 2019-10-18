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

#define LOG_TAG "mediametrics_tests"
#include <utils/Log.h>

#include "MediaAnalyticsService.h"

#include <stdio.h>

#include <gtest/gtest.h>
#include <media/MediaAnalyticsItem.h>

using namespace android;

TEST(mediametrics_tests, instantiate) {
  sp mediaMetrics = new MediaAnalyticsService();
  status_t status;

  // random keys ignored when empty
  std::unique_ptr<MediaAnalyticsItem> random_key(MediaAnalyticsItem::create("random_key"));
  status = mediaMetrics->submit(random_key.get());
  ASSERT_EQ(PERMISSION_DENIED, status);

  // random keys ignored with data
  random_key->setInt32("foo", 10);
  status = mediaMetrics->submit(random_key.get());
  ASSERT_EQ(PERMISSION_DENIED, status);

  // known keys ignored if empty
  std::unique_ptr<MediaAnalyticsItem> audiotrack_key(MediaAnalyticsItem::create("audiotrack"));
  status = mediaMetrics->submit(audiotrack_key.get());
  ASSERT_EQ(BAD_VALUE, status);

  // known keys not ignored if not empty
  audiotrack_key->addInt32("foo", 10);
  status = mediaMetrics->submit(audiotrack_key.get());
  ASSERT_EQ(NO_ERROR, status);


  /*
  // fluent style that goes directly to mediametrics
  ASSERT_EQ(true, MediaAnalyticsItem("audiorecord")
                     .setInt32("value", 2)
                     .addInt32("bar", 1)
                     .addInt32("value", 3)
                     .selfrecord());
  */

  mediaMetrics->dump(fileno(stdout), {} /* args */);
}

TEST(mediametrics_tests, item_manipulation) {
  MediaAnalyticsItem item("audiorecord");

  item.setInt32("value", 2).addInt32("bar", 3).addInt32("value", 4);

  int32_t i32;
  ASSERT_TRUE(item.getInt32("value", &i32));
  ASSERT_EQ(6, i32);

  ASSERT_TRUE(item.getInt32("bar", &i32));
  ASSERT_EQ(3, i32);

  item.setInt64("big", INT64_MAX).setInt64("smaller", INT64_MAX - 1).addInt64("smaller", -2);

  int64_t i64;
  ASSERT_TRUE(item.getInt64("big", &i64));
  ASSERT_EQ(INT64_MAX, i64);

  ASSERT_TRUE(item.getInt64("smaller", &i64));
  ASSERT_EQ(INT64_MAX - 3, i64);

  item.setDouble("precise", 10.5).setDouble("small", 0.125).addDouble("precise", 0.25);

  double d;
  ASSERT_TRUE(item.getDouble("precise", &d));
  ASSERT_EQ(10.75, d);

  ASSERT_TRUE(item.getDouble("small", &d));
  ASSERT_EQ(0.125, d);

  char *s;
  item.setCString("name", "Frank").setCString("mother", "June").setCString("mother", "July");
  ASSERT_TRUE(item.getCString("name", &s));
  ASSERT_EQ(0, strcmp(s, "Frank"));
  free(s);

  ASSERT_TRUE(item.getCString("mother", &s));
  ASSERT_EQ(0, strcmp(s, "July"));  // "July" overwrites "June"
  free(s);

  item.setRate("burgersPerHour", 5, 2);
  int64_t b, h;
  ASSERT_TRUE(item.getRate("burgersPerHour", &b, &h, &d));
  ASSERT_EQ(5, b);
  ASSERT_EQ(2, h);
  ASSERT_EQ(2.5, d);

  item.addRate("burgersPerHour", 4, 2);
  ASSERT_TRUE(item.getRate("burgersPerHour", &b, &h, &d));
  ASSERT_EQ(9, b);
  ASSERT_EQ(4, h);
  ASSERT_EQ(2.25, d);

  printf("item: %s\n", item.toString().c_str());
  fflush(stdout);

  sp mediaMetrics = new MediaAnalyticsService();
  status_t status = mediaMetrics->submit(&item);
  ASSERT_EQ(NO_ERROR, status);
  mediaMetrics->dump(fileno(stdout), {} /* args */);
}

TEST(mediametrics_tests, superbig_item) {
  MediaAnalyticsItem item("TheBigOne");
  constexpr size_t count = 10000;

  for (size_t i = 0; i < count; ++i) {
    item.setInt32(std::to_string(i).c_str(), i);
  }
  for (size_t i = 0; i < count; ++i) {
    int32_t i32;
    ASSERT_TRUE(item.getInt32(std::to_string(i).c_str(), &i32));
    ASSERT_EQ((int32_t)i, i32);
  }
}

TEST(mediametrics_tests, superbig_item_removal) {
  MediaAnalyticsItem item("TheOddBigOne");
  constexpr size_t count = 10000;

  for (size_t i = 0; i < count; ++i) {
    item.setInt32(std::to_string(i).c_str(), i);
  }
  for (size_t i = 0; i < count; i += 2) {
    item.filter(std::to_string(i).c_str()); // filter out all the evens.
  }
  for (size_t i = 0; i < count; ++i) {
    int32_t i32;
    if (i & 1) { // check to see that only the odds are left.
        ASSERT_TRUE(item.getInt32(std::to_string(i).c_str(), &i32));
        ASSERT_EQ((int32_t)i, i32);
    } else {
        ASSERT_FALSE(item.getInt32(std::to_string(i).c_str(), &i32));
    }
  }
}

TEST(mediametrics_tests, item_transmutation) {
  MediaAnalyticsItem item("Alchemist's Stone");

  item.setInt64("convert", 123);
  int64_t i64;
  ASSERT_TRUE(item.getInt64("convert", &i64));
  ASSERT_EQ(123, i64);

  item.addInt32("convert", 2);     // changes type of 'convert' from i64 to i32 (and re-init).
  ASSERT_FALSE(item.getInt64("convert", &i64));  // should be false, no value in i64.

  int32_t i32;
  ASSERT_TRUE(item.getInt32("convert", &i32));   // check it is i32 and 2 (123 is discarded).
  ASSERT_EQ(2, i32);
}
