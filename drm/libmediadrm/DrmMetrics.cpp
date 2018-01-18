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

#include <media/DrmMetrics.h>

namespace {

template<typename T>
void ExportCounterMetric(const android::CounterMetric<T>& counter,
                         android::MediaAnalyticsItem* item) {
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
void ExportEventMetric(const android::EventMetric<T>& event,
                       android::MediaAnalyticsItem* item) {
  std::string success_count_name = event.metric_name() + "/ok/count";
  std::string error_count_name = event.metric_name() + "/error/count";
  std::string timing_name = event.metric_name() + "/average_time_micros";
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
      mGetKeyRequestTiming("/drm/mediadrm/get_key_request", "status") {
}

void MediaDrmMetrics::Export(MediaAnalyticsItem* item) {
  ExportCounterMetric(mOpenSessionCounter, item);
  ExportEventMetric(mGetKeyRequestTiming, item);
}

}  // namespace android
