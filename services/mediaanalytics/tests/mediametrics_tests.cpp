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

  // NOTE: submission of items to MediaMetrics releases ownership, even on error.

  // random keys ignored when empty
  status = mediaMetrics->submit(MediaAnalyticsItem::create("random_key"), false);
  ASSERT_EQ(MediaAnalyticsItem::SessionIDInvalid, status);

  // random keys ignored with data
  auto random_key = MediaAnalyticsItem::create("random_key");
  random_key->setInt32("foo", 10);
  status = mediaMetrics->submit(random_key, false);
  ASSERT_EQ(MediaAnalyticsItem::SessionIDInvalid, status);

  // known keys ignored if empty
  status = mediaMetrics->submit(MediaAnalyticsItem::create("audiotrack"), false);
  ASSERT_EQ(MediaAnalyticsItem::SessionIDInvalid, status);

  auto audiotrack = MediaAnalyticsItem::create("audiotrack");
  audiotrack->addInt32("foo", 10);
  status = mediaMetrics->submit(audiotrack, false);
  ASSERT_GT(status, MediaAnalyticsItem::SessionIDNone);

  mediaMetrics->dump(fileno(stdout), {} /* args */);
}
