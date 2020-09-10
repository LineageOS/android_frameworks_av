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

#include <android/hardware/drm/1.1/types.h>
#include <hidl/HidlSupport.h>
#include <media/stagefright/foundation/ABase.h>

#ifndef ANDROID_IDRMMETRICSCONSUMER_H_

#define ANDROID_IDRMMETRICSCONSUMER_H_

using ::android::hardware::hidl_vec;
using ::android::hardware::drm::V1_1::DrmMetricGroup;

namespace android {

class MediaDrmMetrics;
class String8;

/**
 * Interface to consume metrics produced by the IDrm/ICrypto
 *
 * To use with IDrm:
 *   drm->exportMetrics(&consumer);
 *
 * IDrmMetricsConsumer::consumeFrameworkMetrics &
 * IDrmMetricsConsumer::consumeHidlMetrics implementations
 * would each be invoked once per call to IDrm::exportMetrics.
 * |consumeFrameworkMetrics| would be called for plugin-agnostic
 * framework metrics; |consumeHidlMetrics| would be called for
 * plugin specific metrics.
 *
 * ----------------------------------------
 *
 * To use with ICrypto:
 *   crypto->exportMetrics(&consumer);
 *
 * IDrmMetricsConsumer::consumeHidlMetrics implementation
 * would each be invoked once per call to ICrypto::exportMetrics.
 * ICrypto metrics are plugin agnostic.
 *
 * ----------------------------------------
 *
 * For an example implementation of IDrmMetricsConsumer, please
 * see DrmMetricsConsumer. DrmMetricsConsumer consumes IDrm/ICrypto
 * metrics and saves the metrics to a PersistableBundle.
 *
 */
struct IDrmMetricsConsumer : public RefBase {

    virtual ~IDrmMetricsConsumer() {}

    /**
     * Consume framework (plugin agnostic) MediaDrmMetrics
     */
    virtual status_t consumeFrameworkMetrics(const MediaDrmMetrics &) = 0;

    /**
     * Consume list of DrmMetricGroup with optional Drm vendor name
     */
    virtual status_t consumeHidlMetrics(
            const String8 &vendor,
            const hidl_vec<DrmMetricGroup> &pluginMetrics) = 0;

protected:
    IDrmMetricsConsumer() {}

private:
    DISALLOW_EVIL_CONSTRUCTORS(IDrmMetricsConsumer);
};

}  // namespace android

#endif // ANDROID_IDRMMETRICSCONSUMER_H_
