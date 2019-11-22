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

#ifndef ANDROID_BUNDLEMETRICSCONSUMER_H_

#define ANDROID_BUNDLEMETRICSCONSUMER_H_

namespace android {

/**
 * IDrmMetricsConsumer which saves IDrm/ICrypto metrics into a PersistableBundle.
 *
 * Example usage:
 *
 *   PersistableBundle bundle;
 *   BundleDrmMetricsConsumer consumer(&bundle);
 *   drm->exportMetrics(&consumer);
 *   crypto->exportMetrics(&consumer);
 *   // bundle now contains metrics from drm/crypto.
 *
 */
struct BundleDrmMetricsConsumer : public IDrmMetricsConsumer {
    BundleDrmMetricsConsumer(os::PersistableBundle*) {}

    status_t consumeFrameworkMetrics(const MediaDrmMetrics &) override {
        return OK;
    }

    status_t consumeHidlMetrics(
            const String8 &/*vendor*/,
            const hidl_vec<DrmMetricGroup> &/*pluginMetrics*/) override {
        return OK;
    }

private:
    DISALLOW_EVIL_CONSTRUCTORS(BundleDrmMetricsConsumer);
};

}  // namespace android

#endif // ANDROID_BUNDLEMETRICSCONSUMER_H_
