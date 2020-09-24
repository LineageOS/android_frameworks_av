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
#define LOG_TAG "DrmMetricsConsumer"

#include <android-base/macros.h>
#include <mediadrm/DrmMetricsConsumer.h>
#include <mediadrm/DrmMetrics.h>
#include <utils/String8.h>
#include <utils/String16.h>

using ::android::String16;
using ::android::String8;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::drm::V1_0::EventType;
using ::android::hardware::drm::V1_2::KeyStatusType;
using ::android::hardware::drm::V1_1::DrmMetricGroup;
using ::android::os::PersistableBundle;

namespace {

template <typename T> std::string GetAttributeName(T type);

template <> std::string GetAttributeName<KeyStatusType>(KeyStatusType type) {
    static const char *type_names[] = {"USABLE", "EXPIRED",
                                       "OUTPUT_NOT_ALLOWED", "STATUS_PENDING",
                                       "INTERNAL_ERROR", "USABLE_IN_FUTURE"};
    if (((size_t)type) >= arraysize(type_names)) {
        return "UNKNOWN_TYPE";
    }
    return type_names[(size_t)type];
}

template <> std::string GetAttributeName<EventType>(EventType type) {
    static const char *type_names[] = {"PROVISION_REQUIRED", "KEY_NEEDED",
                                       "KEY_EXPIRED", "VENDOR_DEFINED",
                                       "SESSION_RECLAIMED"};
    if (((size_t)type) >= arraysize(type_names)) {
        return "UNKNOWN_TYPE";
    }
    return type_names[(size_t)type];
}

template <typename T>
void ExportCounterMetric(const android::CounterMetric<T> &counter,
                         PersistableBundle *metrics) {
    if (!metrics) {
        ALOGE("metrics was unexpectedly null.");
        return;
    }
    std::string success_count_name = counter.metric_name() + ".ok.count";
    std::string error_count_name = counter.metric_name() + ".error.count";
    std::vector<int64_t> status_values;
    counter.ExportValues(
        [&](const android::status_t status, const int64_t value) {
            if (status == android::OK) {
                metrics->putLong(android::String16(success_count_name.c_str()),
                                 value);
            } else {
                int64_t total_errors(0);
                metrics->getLong(android::String16(error_count_name.c_str()),
                                 &total_errors);
                metrics->putLong(android::String16(error_count_name.c_str()),
                                 total_errors + value);
                status_values.push_back(status);
            }
        });
    if (!status_values.empty()) {
        std::string error_list_name = counter.metric_name() + ".error.list";
        metrics->putLongVector(android::String16(error_list_name.c_str()),
                               status_values);
    }
}

template <typename T>
void ExportCounterMetricWithAttributeNames(
    const android::CounterMetric<T> &counter, PersistableBundle *metrics) {
    if (!metrics) {
        ALOGE("metrics was unexpectedly null.");
        return;
    }
    counter.ExportValues([&](const T &attribute, const int64_t value) {
        std::string name = counter.metric_name() + "." +
                           GetAttributeName(attribute) + ".count";
        metrics->putLong(android::String16(name.c_str()), value);
    });
}

template <typename T>
void ExportEventMetric(const android::EventMetric<T> &event,
                       PersistableBundle *metrics) {
    if (!metrics) {
        ALOGE("metrics was unexpectedly null.");
        return;
    }
    std::string success_count_name = event.metric_name() + ".ok.count";
    std::string error_count_name = event.metric_name() + ".error.count";
    std::string timing_name = event.metric_name() + ".ok.average_time_micros";
    std::vector<int64_t> status_values;
    event.ExportValues([&](const android::status_t &status,
                           const android::EventStatistics &value) {
        if (status == android::OK) {
            metrics->putLong(android::String16(success_count_name.c_str()),
                             value.count);
            metrics->putLong(android::String16(timing_name.c_str()),
                             value.mean);
        } else {
            int64_t total_errors(0);
            metrics->getLong(android::String16(error_count_name.c_str()),
                             &total_errors);
            metrics->putLong(android::String16(error_count_name.c_str()),
                             total_errors + value.count);
            status_values.push_back(status);
        }
    });
    if (!status_values.empty()) {
        std::string error_list_name = event.metric_name() + ".error.list";
        metrics->putLongVector(android::String16(error_list_name.c_str()),
                               status_values);
    }
}

void ExportSessionLifespans(
    const std::map<std::string, std::pair<int64_t, int64_t>> &sessionLifespans,
    PersistableBundle *metrics) {
    if (!metrics) {
        ALOGE("metrics was unexpectedly null.");
        return;
    }

    if (sessionLifespans.empty()) {
        return;
    }

    PersistableBundle startTimesBundle;
    PersistableBundle endTimesBundle;
    for (auto it = sessionLifespans.begin(); it != sessionLifespans.end();
         it++) {
        String16 key(it->first.c_str(), it->first.size());
        startTimesBundle.putLong(key, it->second.first);
        endTimesBundle.putLong(key, it->second.second);
    }
    metrics->putPersistableBundle(
        android::String16("drm.mediadrm.session_start_times_ms"),
        startTimesBundle);
    metrics->putPersistableBundle(
        android::String16("drm.mediadrm.session_end_times_ms"), endTimesBundle);
}

template <typename CT>
void SetValue(const String16 &name, DrmMetricGroup::ValueType type,
              const CT &value, PersistableBundle *bundle) {
    switch (type) {
    case DrmMetricGroup::ValueType::INT64_TYPE:
        bundle->putLong(name, value.int64Value);
        break;
    case DrmMetricGroup::ValueType::DOUBLE_TYPE:
        bundle->putDouble(name, value.doubleValue);
        break;
    case DrmMetricGroup::ValueType::STRING_TYPE:
        bundle->putString(name, String16(value.stringValue.c_str()));
        break;
    default:
        ALOGE("Unexpected value type: %hhu", type);
    }
}

inline String16 MakeIndexString(unsigned int index) {
  std::string str("[");
  str.append(std::to_string(index));
  str.append("]");
  return String16(str.c_str());
}

} // namespace

namespace android {

status_t DrmMetricsConsumer::consumeFrameworkMetrics(const MediaDrmMetrics &metrics) {
    ExportCounterMetric(metrics.mOpenSessionCounter, mBundle);
    ExportCounterMetric(metrics.mCloseSessionCounter, mBundle);
    ExportEventMetric(metrics.mGetKeyRequestTimeUs, mBundle);
    ExportEventMetric(metrics.mProvideKeyResponseTimeUs, mBundle);
    ExportCounterMetric(metrics.mGetProvisionRequestCounter, mBundle);
    ExportCounterMetric(metrics.mProvideProvisionResponseCounter, mBundle);
    ExportCounterMetricWithAttributeNames(metrics.mKeyStatusChangeCounter, mBundle);
    ExportCounterMetricWithAttributeNames(metrics.mEventCounter, mBundle);
    ExportCounterMetric(metrics.mGetDeviceUniqueIdCounter, mBundle);
    ExportSessionLifespans(metrics.GetSessionLifespans(), mBundle);
    return android::OK;
}

status_t DrmMetricsConsumer::consumeHidlMetrics(
        const String8 &vendor,
        const hidl_vec<DrmMetricGroup> &pluginMetrics) {
    PersistableBundle pluginBundle;
    if (DrmMetricsConsumer::HidlMetricsToBundle(
            pluginMetrics, &pluginBundle) == OK) {
        mBundle->putPersistableBundle(String16(vendor), pluginBundle);
    }
    return android::OK;
}

status_t DrmMetricsConsumer::HidlMetricsToBundle(
    const hidl_vec<DrmMetricGroup> &hidlMetricGroups,
    PersistableBundle *bundleMetricGroups) {
    if (bundleMetricGroups == nullptr) {
        return UNEXPECTED_NULL;
    }
    if (hidlMetricGroups.size() == 0) {
        return OK;
    }

    int groupIndex = 0;
    std::map<String16, int> indexMap;
    for (const auto &hidlMetricGroup : hidlMetricGroups) {
        PersistableBundle bundleMetricGroup;
        for (const auto &hidlMetric : hidlMetricGroup.metrics) {
            String16 metricName(hidlMetric.name.c_str());
            PersistableBundle bundleMetric;
            // Add metric component values.
            for (const auto &value : hidlMetric.values) {
                SetValue(String16(value.componentName.c_str()), value.type,
                         value, &bundleMetric);
            }
            // Set metric attributes.
            PersistableBundle bundleMetricAttributes;
            for (const auto &attribute : hidlMetric.attributes) {
                SetValue(String16(attribute.name.c_str()), attribute.type,
                         attribute, &bundleMetricAttributes);
            }
            // Add attributes to the bundle metric.
            bundleMetric.putPersistableBundle(String16("attributes"),
                                              bundleMetricAttributes);
            // Add one layer of indirection, allowing for repeated metric names.
            PersistableBundle repeatedMetrics;
            bundleMetricGroup.getPersistableBundle(metricName,
                                                   &repeatedMetrics);
            int index = indexMap[metricName];
            repeatedMetrics.putPersistableBundle(MakeIndexString(index),
                                                 bundleMetric);
            indexMap[metricName] = ++index;

            // Add the bundle metric to the group of metrics.
            bundleMetricGroup.putPersistableBundle(metricName,
                                                   repeatedMetrics);
        }
        // Add the bundle metric group to the collection of groups.
        bundleMetricGroups->putPersistableBundle(MakeIndexString(groupIndex++),
                                                 bundleMetricGroup);
    }

    return OK;
}

} // namespace android

