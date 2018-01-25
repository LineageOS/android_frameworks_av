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
  // Counter of times openSession was called.
  CounterMetric<status_t> mOpenSessionCounter;
  // Counter and timing of the getKeyRequest call.
  EventMetric<status_t> mGetKeyRequestTiming;

  // TODO: Add the full set of metrics to be captured.

  // Export the metrics to a MediaAnalyticsItem.
  void Export(MediaAnalyticsItem* item);
};

}  // namespace android

#endif  // DRM_METRICS_H_
