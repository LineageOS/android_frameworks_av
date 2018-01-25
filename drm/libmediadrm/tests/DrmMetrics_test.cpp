/*
 * Copyright 2018 The Android Open Source Project
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

#include "DrmMetrics.h"

using ::android::hardware::drm::V1_0::EventType;
using ::android::hardware::drm::V1_0::KeyStatusType;

namespace android {

/**
 * Unit tests for the MediaDrmMetrics class.
 */
class MediaDrmMetricsTest : public ::testing::Test {
};

TEST_F(MediaDrmMetricsTest, EmptySuccess) {
  MediaDrmMetrics metrics;
  MediaAnalyticsItem item;

  metrics.Export(&item);
  EXPECT_EQ(0, item.count());
}

TEST_F(MediaDrmMetricsTest, AllValuesSuccessCounts) {
  MediaDrmMetrics metrics;

  metrics.mOpenSessionCounter.Increment(OK);
  metrics.mCloseSessionCounter.Increment(OK);

  {
    EventTimer<status_t> get_key_request_timer(&metrics.mGetKeyRequestTiming);
    EventTimer<status_t> provide_key_response_timer(
        &metrics.mProvideKeyResponseTiming);
    get_key_request_timer.SetAttribute(OK);
    provide_key_response_timer.SetAttribute(OK);
  }

  metrics.mGetProvisionRequestCounter.Increment(OK);
  metrics.mProvideProvisionResponseCounter.Increment(OK);
  metrics.mGetDeviceUniqueIdCounter.Increment(OK);

  metrics.mKeyStatusChangeCounter.Increment(KeyStatusType::USABLE);
  metrics.mEventCounter.Increment(EventType::PROVISION_REQUIRED);

  MediaAnalyticsItem item;

  metrics.Export(&item);
  EXPECT_EQ(11, item.count());

  // Verify the list of pairs of int64 metrics.
  std::vector<std::pair<std::string, int64_t>> expected_values = {
      { "/drm/mediadrm/open_session/ok/count", 1 },
      { "/drm/mediadrm/close_session/ok/count", 1 },
      { "/drm/mediadrm/get_key_request/ok/count", 1 },
      { "/drm/mediadrm/provide_key_response/ok/count", 1 },
      { "/drm/mediadrm/get_provision_request/ok/count", 1 },
      { "/drm/mediadrm/provide_provision_response/ok/count", 1 },
      { "/drm/mediadrm/key_status_change/USABLE/count", 1 },
      { "/drm/mediadrm/event/PROVISION_REQUIRED/count", 1 },
      { "/drm/mediadrm/get_device_unique_id/ok/count", 1 }};
  for (const auto& expected_pair : expected_values) {
    int64_t value = -1;
    EXPECT_TRUE(item.getInt64(expected_pair.first.c_str(), &value))
        << "Failed to get " << expected_pair.first;
    EXPECT_EQ(expected_pair.second, value)
        << "Unexpected value for " << expected_pair.first;
  }

  // Validate timing values exist.
  int64_t value = -1;
  EXPECT_TRUE(
      item.getInt64("/drm/mediadrm/get_key_request/ok/average_time_micros",
                    &value));
  EXPECT_GE(value, 0);

  value = -1;
  EXPECT_TRUE(
      item.getInt64("/drm/mediadrm/provide_key_response/ok/average_time_micros",
                    &value));
  EXPECT_GE(value, 0);
}

TEST_F(MediaDrmMetricsTest, AllValuesFull) {
  MediaDrmMetrics metrics;

  metrics.mOpenSessionCounter.Increment(OK);
  metrics.mOpenSessionCounter.Increment(UNEXPECTED_NULL);

  metrics.mCloseSessionCounter.Increment(OK);
  metrics.mCloseSessionCounter.Increment(UNEXPECTED_NULL);

  for (status_t s : {OK, UNEXPECTED_NULL}) {
    {
      EventTimer<status_t> get_key_request_timer(&metrics.mGetKeyRequestTiming);
      EventTimer<status_t> provide_key_response_timer(
          &metrics.mProvideKeyResponseTiming);
      get_key_request_timer.SetAttribute(s);
      provide_key_response_timer.SetAttribute(s);
    }
  }

  metrics.mGetProvisionRequestCounter.Increment(OK);
  metrics.mGetProvisionRequestCounter.Increment(UNEXPECTED_NULL);
  metrics.mProvideProvisionResponseCounter.Increment(OK);
  metrics.mProvideProvisionResponseCounter.Increment(UNEXPECTED_NULL);
  metrics.mGetDeviceUniqueIdCounter.Increment(OK);
  metrics.mGetDeviceUniqueIdCounter.Increment(UNEXPECTED_NULL);

  metrics.mKeyStatusChangeCounter.Increment(KeyStatusType::USABLE);
  metrics.mKeyStatusChangeCounter.Increment(KeyStatusType::EXPIRED);
  metrics.mKeyStatusChangeCounter.Increment(KeyStatusType::OUTPUTNOTALLOWED);
  metrics.mKeyStatusChangeCounter.Increment(KeyStatusType::STATUSPENDING);
  metrics.mKeyStatusChangeCounter.Increment(KeyStatusType::INTERNALERROR);
  metrics.mEventCounter.Increment(EventType::PROVISION_REQUIRED);
  metrics.mEventCounter.Increment(EventType::KEY_NEEDED);
  metrics.mEventCounter.Increment(EventType::KEY_EXPIRED);
  metrics.mEventCounter.Increment(EventType::VENDOR_DEFINED);
  metrics.mEventCounter.Increment(EventType::SESSION_RECLAIMED);

  MediaAnalyticsItem item;

  metrics.Export(&item);
  EXPECT_EQ(26, item.count());

  // Verify the list of pairs of int64 metrics.
  std::vector<std::pair<std::string, int64_t>> expected_values = {
      { "/drm/mediadrm/open_session/ok/count", 1 },
      { "/drm/mediadrm/close_session/ok/count", 1 },
      { "/drm/mediadrm/get_key_request/ok/count", 1 },
      { "/drm/mediadrm/provide_key_response/ok/count", 1 },
      { "/drm/mediadrm/get_provision_request/ok/count", 1 },
      { "/drm/mediadrm/provide_provision_response/ok/count", 1 },
      { "/drm/mediadrm/get_device_unique_id/ok/count", 1 },
      { "/drm/mediadrm/open_session/error/count", 1 },
      { "/drm/mediadrm/close_session/error/count", 1 },
      { "/drm/mediadrm/get_key_request/error/count", 1 },
      { "/drm/mediadrm/provide_key_response/error/count", 1 },
      { "/drm/mediadrm/get_provision_request/error/count", 1 },
      { "/drm/mediadrm/provide_provision_response/error/count", 1 },
      { "/drm/mediadrm/get_device_unique_id/error/count", 1 },
      { "/drm/mediadrm/key_status_change/USABLE/count", 1 },
      { "/drm/mediadrm/key_status_change/EXPIRED/count", 1 },
      { "/drm/mediadrm/key_status_change/OUTPUT_NOT_ALLOWED/count", 1 },
      { "/drm/mediadrm/key_status_change/STATUS_PENDING/count", 1 },
      { "/drm/mediadrm/key_status_change/INTERNAL_ERROR/count", 1 },
      { "/drm/mediadrm/event/PROVISION_REQUIRED/count", 1 },
      { "/drm/mediadrm/event/KEY_NEEDED/count", 1 },
      { "/drm/mediadrm/event/KEY_EXPIRED/count", 1 },
      { "/drm/mediadrm/event/VENDOR_DEFINED/count", 1 },
      { "/drm/mediadrm/event/SESSION_RECLAIMED/count", 1 }};
  for (const auto& expected_pair : expected_values) {
    int64_t value = -1;
    EXPECT_TRUE(item.getInt64(expected_pair.first.c_str(), &value))
        << "Failed to get " << expected_pair.first;
    EXPECT_EQ(expected_pair.second, value)
        << "Unexpected value for " << expected_pair.first;
  }

  // Validate timing values exist.
  int64_t value = -1;
  std::string name = metrics.mGetKeyRequestTiming.metric_name()
      + "/ok/average_time_micros";
  EXPECT_TRUE(item.getInt64(name.c_str(), &value));
  EXPECT_GE(value, 0);

  value = -1;
  name = metrics.mProvideKeyResponseTiming.metric_name()
      + "/ok/average_time_micros";
  EXPECT_TRUE(item.getInt64(name.c_str(), &value));
  EXPECT_GE(value, 0);
}



}  // namespace android
