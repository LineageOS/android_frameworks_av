/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <android-base/macros.h>
#include <media/DrmMetrics.h>

using ::android::hardware::drm::V1_0::EventType;
using ::android::hardware::drm::V1_0::KeyStatusType;

namespace {

template<typename T>
std::string GetAttributeName(T type);

template<>
std::string GetAttributeName<KeyStatusType>(KeyStatusType type) {
  static const char* type_names[] = {
      "USABLE", "EXPIRED", "OUTPUT_NOT_ALLOWED",
      "STATUS_PENDING", "INTERNAL_ERROR" };
  if (((size_t) type) > arraysize(type_names)) {
    return "UNKNOWN_TYPE";
  }
  return type_names[(size_t) type];
}

template<>
std::string GetAttributeName<EventType>(EventType type) {
  static const char* type_names[] = {
      "PROVISION_REQUIRED", "KEY_NEEDED", "KEY_EXPIRED",
      "VENDOR_DEFINED", "SESSION_RECLAIMED" };
  if (((size_t) type) > arraysize(type_names)) {
    return "UNKNOWN_TYPE";
  }
  return type_names[(size_t) type];
}

template<typename T>
void ExportCounterMetric(const android::CounterMetric<T>& counter,
                         android::MediaAnalyticsItem* item) {
  if (!item) {
    ALOGE("item was unexpectedly null.");
    return;
  }
  std::string success_count_name = counter.metric_name() + "/ok/count";
  std::string error_count_name = counter.metric_name() + "/error/count";
  counter.ExportValues(
      [&] (const android::status_t status, const int64_t value) {
          if (status == android::OK) {
              item->setInt64(success_count_name.c_str(), value);
          } else {
              int64_t total_errors(0);
              item->getInt64(error_count_name.c_str(), &total_errors);
              item->setInt64(error_count_name.c_str(), total_errors + value);
              // TODO: Add support for exporting the list of error values.
              // This probably needs to be added to MediaAnalyticsItem.
          }
      });
}

template<typename T>
void ExportCounterMetricWithAttributeNames(
    const android::CounterMetric<T>& counter,
    android::MediaAnalyticsItem* item) {
  if (!item) {
    ALOGE("item was unexpectedly null.");
    return;
  }
  counter.ExportValues(
      [&] (const T& attribute, const int64_t value) {
          std::string name = counter.metric_name()
              + "/" + GetAttributeName(attribute) + "/count";
          item->setInt64(name.c_str(), value);
      });
}

template<typename T>
void ExportEventMetric(const android::EventMetric<T>& event,
                       android::MediaAnalyticsItem* item) {
  if (!item) {
    ALOGE("item was unexpectedly null.");
    return;
  }
  std::string success_count_name = event.metric_name() + "/ok/count";
  std::string error_count_name = event.metric_name() + "/error/count";
  std::string timing_name = event.metric_name() + "/ok/average_time_micros";
  event.ExportValues(
      [&] (const android::status_t& status,
           const android::EventStatistics& value) {
          if (status == android::OK) {
              item->setInt64(success_count_name.c_str(), value.count);
              item->setInt64(timing_name.c_str(), value.mean);
          } else {
              int64_t total_errors(0);
              item->getInt64(error_count_name.c_str(), &total_errors);
              item->setInt64(error_count_name.c_str(),
                             total_errors + value.count);
              // TODO: Add support for exporting the list of error values.
              // This probably needs to be added to MediaAnalyticsItem.
          }
      });
}

}  // namespace anonymous

namespace android {

MediaDrmMetrics::MediaDrmMetrics()
    : mOpenSessionCounter("/drm/mediadrm/open_session", "status"),
      mCloseSessionCounter("/drm/mediadrm/close_session", "status"),
      mGetKeyRequestTiming("/drm/mediadrm/get_key_request", "status"),
      mProvideKeyResponseTiming("/drm/mediadrm/provide_key_response", "status"),
      mGetProvisionRequestCounter(
          "/drm/mediadrm/get_provision_request", "status"),
      mProvideProvisionResponseCounter(
          "/drm/mediadrm/provide_provision_response", "status"),
      mKeyStatusChangeCounter(
          "/drm/mediadrm/key_status_change", "key_status_type"),
      mEventCounter("/drm/mediadrm/event", "event_type"),
      mGetDeviceUniqueIdCounter(
          "/drm/mediadrm/get_device_unique_id", "status") {
}

void MediaDrmMetrics::Export(MediaAnalyticsItem* item) {
  if (!item) {
    ALOGE("item was unexpectedly null.");
    return;
  }
  ExportCounterMetric(mOpenSessionCounter, item);
  ExportCounterMetric(mCloseSessionCounter, item);
  ExportEventMetric(mGetKeyRequestTiming, item);
  ExportEventMetric(mProvideKeyResponseTiming, item);
  ExportCounterMetric(mGetProvisionRequestCounter, item);
  ExportCounterMetric(mProvideProvisionResponseCounter, item);
  ExportCounterMetricWithAttributeNames(mKeyStatusChangeCounter, item);
  ExportCounterMetricWithAttributeNames(mEventCounter, item);
  ExportCounterMetric(mGetDeviceUniqueIdCounter, item);
}

}  // namespace android
