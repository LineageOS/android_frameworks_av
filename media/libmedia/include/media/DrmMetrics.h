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

#ifndef DRM_METRICS_H_
#define DRM_METRICS_H_

#include <map>

#include <android/hardware/drm/1.0/types.h>
#include <media/CounterMetric.h>
#include <media/EventMetric.h>

namespace android {

/**
 * This class contains the definition of metrics captured within MediaDrm.
 * It also contains a method for exporting all of the metrics to a
 * MediaAnalyticsItem instance.
 */
class MediaDrmMetrics {
 public:
  explicit MediaDrmMetrics();
  // Count of openSession calls.
  CounterMetric<status_t> mOpenSessionCounter;
  // Count of closeSession calls.
  CounterMetric<status_t> mCloseSessionCounter;
  // Count and timing of getKeyRequest calls.
  EventMetric<status_t> mGetKeyRequestTiming;
  // Count and timing of provideKeyResponse calls.
  EventMetric<status_t> mProvideKeyResponseTiming;
  // Count of getProvisionRequest calls.
  CounterMetric<status_t> mGetProvisionRequestCounter;
  // Count of provideProvisionResponse calls.
  CounterMetric<status_t> mProvideProvisionResponseCounter;

  // Count of key status events broken out by status type.
  CounterMetric<::android::hardware::drm::V1_0::KeyStatusType>
      mKeyStatusChangeCounter;
  // Count of events broken out by event type
  CounterMetric<::android::hardware::drm::V1_0::EventType> mEventCounter;

  // Count getPropertyByteArray calls to retrieve the device unique id.
  CounterMetric<status_t> mGetDeviceUniqueIdCounter;

  // TODO: Add session start and end time support. These are a special case.

  // Export the metrics to a MediaAnalyticsItem.
  void Export(MediaAnalyticsItem* item);
};

}  // namespace android

#endif  // DRM_METRICS_H_
