/*
 * Copyright (C) 2017 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "PluginMetricsReporting"

#include <media/PluginMetricsReporting.h>

#include <inttypes.h>

#include <media/MediaMetrics.h>
#include <utils/Log.h>


namespace android {

namespace {

constexpr char kSerializedMetricsField[] = "serialized_metrics";

status_t reportVendorMetrics(const std::string& metrics,
                             const String8& name,
                             uid_t appUid) {
    mediametrics_handle_t analyticsItem(mediametrics_create(name.c_str()));
    mediametrics_setUid(analyticsItem, appUid);
    if (metrics.size() > 0) {
        mediametrics_setCString(analyticsItem, kSerializedMetricsField, metrics.c_str());
    }

    if (!mediametrics_selfRecord(analyticsItem)) {
      ALOGE("%s: selfrecord() returned false", __func__);
    }

    mediametrics_delete(analyticsItem);
    return OK;
}

String8 sanitize(const String8& input) {
    // Filters the input string down to just alphanumeric characters.
    String8 output;
    for (size_t i = 0; i < input.size(); ++i) {
        char candidate = input[i];
        if ((candidate >= 'a' && candidate <= 'z') ||
                (candidate >= 'A' && candidate <= 'Z') ||
                (candidate >= '0' && candidate <= '9')) {
            output.append(&candidate, 1);
        }
    }
    return output;
}

}  // namespace

status_t reportDrmPluginMetrics(const std::string& b64EncodedMetrics,
                                const String8& vendor,
                                const String8& description,
                                uid_t appUid) {

    String8 name = String8::format("drm.vendor.%s.%s",
                                   sanitize(vendor).c_str(),
                                   sanitize(description).c_str());

    return reportVendorMetrics(b64EncodedMetrics, name, appUid);
}

}  // namespace android
