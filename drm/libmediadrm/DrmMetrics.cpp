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
#define LOG_TAG "DrmMetrics"
#include <iomanip>
#include <utility>

#include <android-base/macros.h>
#include <media/stagefright/foundation/base64.h>
#include <mediadrm/DrmMetrics.h>
#include <sys/time.h>
#include <utils/Log.h>
#include <utils/Timers.h>

#include "protos/metrics.pb.h"

using ::android::String16;
using ::android::String8;
using ::android::drm_metrics::DrmFrameworkMetrics;
using ::android::hardware::drm::V1_0::EventType;
using ::android::hardware::drm::V1_2::KeyStatusType;
using ::android::hardware::drm::V1_1::DrmMetricGroup;

namespace {

std::string ToHexString(const android::Vector<uint8_t> &sessionId) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < sessionId.size(); i++) {
        out << std::setw(2) << (int)(sessionId[i]);
    }
    return out.str();
}

} // namespace

namespace android {

MediaDrmMetrics::MediaDrmMetrics()
    : mOpenSessionCounter("drm.mediadrm.open_session", "status"),
      mCloseSessionCounter("drm.mediadrm.close_session", "status"),
      mGetKeyRequestTimeUs("drm.mediadrm.get_key_request", "status"),
      mProvideKeyResponseTimeUs("drm.mediadrm.provide_key_response", "status"),
      mGetProvisionRequestCounter("drm.mediadrm.get_provision_request",
                                  "status"),
      mProvideProvisionResponseCounter(
          "drm.mediadrm.provide_provision_response", "status"),
      mKeyStatusChangeCounter("drm.mediadrm.key_status_change",
                              "key_status_type"),
      mEventCounter("drm.mediadrm.event", "event_type"),
      mGetDeviceUniqueIdCounter("drm.mediadrm.get_device_unique_id", "status") {
}

void MediaDrmMetrics::SetSessionStart(
    const android::Vector<uint8_t> &sessionId) {
    std::string sessionIdHex = ToHexString(sessionId);
    mSessionLifespans[sessionIdHex] =
        std::make_pair(GetCurrentTimeMs(), (int64_t)0);
}

void MediaDrmMetrics::SetSessionEnd(const android::Vector<uint8_t> &sessionId) {
    std::string sessionIdHex = ToHexString(sessionId);
    int64_t endTimeMs = GetCurrentTimeMs();
    if (mSessionLifespans.find(sessionIdHex) != mSessionLifespans.end()) {
        mSessionLifespans[sessionIdHex] =
            std::make_pair(mSessionLifespans[sessionIdHex].first, endTimeMs);
    } else {
        mSessionLifespans[sessionIdHex] = std::make_pair((int64_t)0, endTimeMs);
    }
}

status_t MediaDrmMetrics::GetSerializedMetrics(std::string *serializedMetrics) {

    if (!serializedMetrics) {
        ALOGE("serializedMetrics was unexpectedly null.");
        return UNEXPECTED_NULL;
    }

    DrmFrameworkMetrics metrics;

    mOpenSessionCounter.ExportValues(
        [&](const android::status_t status, const int64_t value) {
            DrmFrameworkMetrics::Counter *counter =
                metrics.add_open_session_counter();
            counter->set_count(value);
            counter->mutable_attributes()->set_error_code(status);
        });

    mCloseSessionCounter.ExportValues(
        [&](const android::status_t status, const int64_t value) {
            DrmFrameworkMetrics::Counter *counter =
                metrics.add_close_session_counter();
            counter->set_count(value);
            counter->mutable_attributes()->set_error_code(status);
        });

    mGetProvisionRequestCounter.ExportValues(
        [&](const android::status_t status, const int64_t value) {
            DrmFrameworkMetrics::Counter *counter =
                metrics.add_get_provisioning_request_counter();
            counter->set_count(value);
            counter->mutable_attributes()->set_error_code(status);
        });

    mProvideProvisionResponseCounter.ExportValues(
        [&](const android::status_t status, const int64_t value) {
            DrmFrameworkMetrics::Counter *counter =
                metrics.add_provide_provisioning_response_counter();
            counter->set_count(value);
            counter->mutable_attributes()->set_error_code(status);
        });

    mKeyStatusChangeCounter.ExportValues(
        [&](const KeyStatusType key_status_type, const int64_t value) {
            DrmFrameworkMetrics::Counter *counter =
                metrics.add_key_status_change_counter();
            counter->set_count(value);
            counter->mutable_attributes()->set_key_status_type(
                (uint32_t)key_status_type);
        });

    mEventCounter.ExportValues(
        [&](const EventType event_type, const int64_t value) {
            DrmFrameworkMetrics::Counter *counter =
                metrics.add_event_callback_counter();
            counter->set_count(value);
            counter->mutable_attributes()->set_event_type((uint32_t)event_type);
        });

    mGetDeviceUniqueIdCounter.ExportValues(
        [&](const status_t status, const int64_t value) {
            DrmFrameworkMetrics::Counter *counter =
                metrics.add_get_device_unique_id_counter();
            counter->set_count(value);
            counter->mutable_attributes()->set_error_code(status);
        });

    mGetKeyRequestTimeUs.ExportValues(
        [&](const status_t status, const EventStatistics &stats) {
            DrmFrameworkMetrics::DistributionMetric *metric =
                metrics.add_get_key_request_time_us();
            metric->set_min(stats.min);
            metric->set_max(stats.max);
            metric->set_mean(stats.mean);
            metric->set_operation_count(stats.count);
            metric->set_variance(stats.sum_squared_deviation / stats.count);
            metric->mutable_attributes()->set_error_code(status);
        });

    mProvideKeyResponseTimeUs.ExportValues(
        [&](const status_t status, const EventStatistics &stats) {
            DrmFrameworkMetrics::DistributionMetric *metric =
                metrics.add_provide_key_response_time_us();
            metric->set_min(stats.min);
            metric->set_max(stats.max);
            metric->set_mean(stats.mean);
            metric->set_operation_count(stats.count);
            metric->set_variance(stats.sum_squared_deviation / stats.count);
            metric->mutable_attributes()->set_error_code(status);
        });

    for (const auto &sessionLifespan : mSessionLifespans) {
        auto *map = metrics.mutable_session_lifetimes();

        (*map)[sessionLifespan.first].set_start_time_ms(
            sessionLifespan.second.first);
        (*map)[sessionLifespan.first].set_end_time_ms(
            sessionLifespan.second.second);
    }

    if (!metrics.SerializeToString(serializedMetrics)) {
        ALOGE("Failed to serialize metrics.");
        return UNKNOWN_ERROR;
    }

    return OK;
}

std::map<std::string, std::pair<int64_t, int64_t>> MediaDrmMetrics::GetSessionLifespans() const {
  return mSessionLifespans;
}

int64_t MediaDrmMetrics::GetCurrentTimeMs() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((int64_t)tv.tv_sec * 1000) + ((int64_t)tv.tv_usec / 1000);
}

} // namespace android
