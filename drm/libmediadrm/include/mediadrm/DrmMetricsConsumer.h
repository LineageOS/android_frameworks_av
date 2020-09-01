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

#include <binder/PersistableBundle.h>
#include <mediadrm/IDrmMetricsConsumer.h>
#include <utils/Errors.h>

#ifndef ANDROID_METRICSCONSUMER_H_

#define ANDROID_METRICSCONSUMER_H_

namespace android {

/**
 * IDrmMetricsConsumer which saves IDrm/ICrypto metrics into a PersistableBundle.
 *
 * Example usage:
 *
 *   PersistableBundle bundle;
 *   DrmMetricsConsumer consumer(&bundle);
 *   drm->exportMetrics(&consumer);
 *   crypto->exportMetrics(&consumer);
 *   // bundle now contains metrics from drm/crypto.
 *
 */
struct DrmMetricsConsumer : public IDrmMetricsConsumer {
    DrmMetricsConsumer(os::PersistableBundle *bundle) : mBundle(bundle) {}

    status_t consumeFrameworkMetrics(const MediaDrmMetrics &) override;

    status_t consumeHidlMetrics(
            const String8 &/*vendor*/,
            const hidl_vec<DrmMetricGroup> &/*pluginMetrics*/) override;

    // Converts the DRM plugin metrics to a PersistableBundle. All of the metrics
    // found in |pluginMetrics| are added to the |metricsBundle| parameter.
    // |pluginBundle| is owned by the caller and must not be null.
    //
    // Each item in the pluginMetrics vector is added as a new PersistableBundle. E.g.
    // DrmMetricGroup {
    //   metrics[0] {
    //     name: "buf_copy"
    //     attributes[0] {
    //       name: "size"
    //       type: INT64_TYPE
    //       int64Value: 1024
    //     }
    //     values[0] {
    //       componentName: "operation_count"
    //       type: INT64_TYPE
    //       int64Value: 75
    //     }
    //     values[1] {
    //       component_name: "average_time_seconds"
    //       type: DOUBLE_TYPE
    //       doubleValue: 0.00000042
    //     }
    //   }
    // }
    //
    // becomes
    //
    // metricsBundle {
    //   "0": (PersistableBundle) {
    //     "attributes" : (PersistableBundle) {
    //       "size" : (int64) 1024
    //     }
    //     "operation_count" : (int64) 75
    //     "average_time_seconds" : (double) 0.00000042
    //   }
    //
    static status_t HidlMetricsToBundle(
            const hardware::hidl_vec<hardware::drm::V1_1::DrmMetricGroup>& pluginMetrics,
            os::PersistableBundle* metricsBundle);

private:
    os::PersistableBundle *mBundle;
    DISALLOW_EVIL_CONSTRUCTORS(DrmMetricsConsumer);
};

}  // namespace android

#endif // ANDROID_METRICSCONSUMER_H_
