/*
 * Copyright (C) 2026 The Android Open Source Project
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

#pragma once

#include <media/MediaMetrics.h>
#include <media/MediaMetricsItem.h>

#ifdef  METRICS_IN_MODULE
#include <aidl/android/media/IMediaMetricsService.h>
#include <aidl/android/media/metrics/StructuredItem.h>

using aidl::android::media::IMediaMetricsService;
using aidl::android::media::metrics::StructuredItem;

#else
#include <android/media/IMediaMetricsService.h>
#include <android/media/metrics/StructuredItem.h>

using android::media::IMediaMetricsService;
using android::media::metrics::StructuredItem;
#endif

namespace android::mediametrics {

// translation between Item and the stable-aidl constructs
std::shared_ptr<StructuredItem> writeItemToStructured(android::mediametrics::Item&);
std::shared_ptr<android::mediametrics::Item> readFromStructuredItem(const StructuredItem*);

// manages finding, keeping access to the service
sp<IMediaMetricsService> getService();

} // namespace android::mediametrics
