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

#include <binder/PersistableBundle.h>
#include <gtest/gtest.h>

#include "DrmMetrics.h"

using ::android::hardware::drm::V1_0::EventType;
using ::android::hardware::drm::V1_0::KeyStatusType;
using ::android::os::PersistableBundle;

namespace android {

/**
 * Unit tests for the MediaDrmMetrics class.
 */
class MediaDrmMetricsTest : public ::testing::Test {
};

TEST_F(MediaDrmMetricsTest, EmptySuccess) {
  MediaDrmMetrics metrics;
  PersistableBundle bundle;

  metrics.Export(&bundle);
  EXPECT_TRUE(bundle.empty());
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

  PersistableBundle bundle;

  metrics.Export(&bundle);
  EXPECT_EQ(11U, bundle.size());

  // Verify the list of pairs of int64 metrics.
  std::vector<std::pair<std::string, int64_t>> expected_values = {
      { "drm.mediadrm.open_session.ok.count", 1 },
      { "drm.mediadrm.close_session.ok.count", 1 },
      { "drm.mediadrm.get_key_request.ok.count", 1 },
      { "drm.mediadrm.provide_key_response.ok.count", 1 },
      { "drm.mediadrm.get_provision_request.ok.count", 1 },
      { "drm.mediadrm.provide_provision_response.ok.count", 1 },
      { "drm.mediadrm.key_status_change.USABLE.count", 1 },
      { "drm.mediadrm.event.PROVISION_REQUIRED.count", 1 },
      { "drm.mediadrm.get_device_unique_id.ok.count", 1 }};
  for (const auto& expected_pair : expected_values) {
    String16 key(expected_pair.first.c_str());
    int64_t value = -1;
    EXPECT_TRUE(bundle.getLong(key, &value))
        << "Unexpected error retrieviing key: " << key;
    EXPECT_EQ(expected_pair.second, value)
        << "Unexpected value for " << expected_pair.first << ". " << value;
  }

  // Validate timing values exist.
  String16 get_key_request_key(
      "drm.mediadrm.get_key_request.ok.average_time_micros");
  String16 provide_key_response_key(
      "drm.mediadrm.provide_key_response.ok.average_time_micros");
  int64_t value = -1;
  EXPECT_TRUE(bundle.getLong(get_key_request_key, &value));
  EXPECT_GE(value, 0);
  value = -1;
  EXPECT_TRUE(bundle.getLong(provide_key_response_key, &value));
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

  PersistableBundle bundle;
  metrics.Export(&bundle);
  EXPECT_EQ(33U, bundle.size());

  // Verify the list of pairs of int64 metrics.
  std::vector<std::pair<std::string, int64_t>> expected_values = {
      { "drm.mediadrm.open_session.ok.count", 1 },
      { "drm.mediadrm.close_session.ok.count", 1 },
      { "drm.mediadrm.get_key_request.ok.count", 1 },
      { "drm.mediadrm.provide_key_response.ok.count", 1 },
      { "drm.mediadrm.get_provision_request.ok.count", 1 },
      { "drm.mediadrm.provide_provision_response.ok.count", 1 },
      { "drm.mediadrm.get_device_unique_id.ok.count", 1 },
      { "drm.mediadrm.open_session.error.count", 1 },
      { "drm.mediadrm.close_session.error.count", 1 },
      { "drm.mediadrm.get_key_request.error.count", 1 },
      { "drm.mediadrm.provide_key_response.error.count", 1 },
      { "drm.mediadrm.get_provision_request.error.count", 1 },
      { "drm.mediadrm.provide_provision_response.error.count", 1 },
      { "drm.mediadrm.get_device_unique_id.error.count", 1 },
      { "drm.mediadrm.key_status_change.USABLE.count", 1 },
      { "drm.mediadrm.key_status_change.EXPIRED.count", 1 },
      { "drm.mediadrm.key_status_change.OUTPUT_NOT_ALLOWED.count", 1 },
      { "drm.mediadrm.key_status_change.STATUS_PENDING.count", 1 },
      { "drm.mediadrm.key_status_change.INTERNAL_ERROR.count", 1 },
      { "drm.mediadrm.event.PROVISION_REQUIRED.count", 1 },
      { "drm.mediadrm.event.KEY_NEEDED.count", 1 },
      { "drm.mediadrm.event.KEY_EXPIRED.count", 1 },
      { "drm.mediadrm.event.VENDOR_DEFINED.count", 1 },
      { "drm.mediadrm.event.SESSION_RECLAIMED.count", 1 }};
  for (const auto& expected_pair : expected_values) {
    String16 key(expected_pair.first.c_str());
    int64_t value = -1;
    EXPECT_TRUE(bundle.getLong(key, &value))
        << "Unexpected error retrieviing key: " << key;
    EXPECT_EQ(expected_pair.second, value)
        << "Unexpected value for " << expected_pair.first << ". " << value;
  }

  // Verify the error lists
  std::vector<std::pair<std::string, std::vector<int64_t>>> expected_vector_values = {
      { "drm.mediadrm.close_session.error.list", { UNEXPECTED_NULL } },
      { "drm.mediadrm.get_device_unique_id.error.list", { UNEXPECTED_NULL } },
      { "drm.mediadrm.get_key_request.error.list", { UNEXPECTED_NULL } },
      { "drm.mediadrm.get_provision_request.error.list", { UNEXPECTED_NULL } },
      { "drm.mediadrm.open_session.error.list", { UNEXPECTED_NULL } },
      { "drm.mediadrm.provide_key_response.error.list", { UNEXPECTED_NULL } },
      { "drm.mediadrm.provide_provision_response.error.list", { UNEXPECTED_NULL } }};
  for (const auto& expected_pair : expected_vector_values) {
    String16 key(expected_pair.first.c_str());
    std::vector<int64_t> values;
    EXPECT_TRUE(bundle.getLongVector(key, &values))
        << "Unexpected error retrieviing key: " << key;
    for (auto expected : expected_pair.second) {
      EXPECT_TRUE(std::find(values.begin(), values.end(), expected) != values.end())
          << "Could not find " << expected << " for key " << expected_pair.first;
    }
  }

  // Validate timing values exist.
  String16 get_key_request_key(
      "drm.mediadrm.get_key_request.ok.average_time_micros");
  String16 provide_key_response_key(
      "drm.mediadrm.provide_key_response.ok.average_time_micros");
  int64_t value = -1;
  EXPECT_TRUE(bundle.getLong(get_key_request_key, &value));
  EXPECT_GE(value, 0);
  value = -1;
  EXPECT_TRUE(bundle.getLong(provide_key_response_key, &value));
  EXPECT_GE(value, 0);
}

}  // namespace android
