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

//#define LOG_NDEBUG 0
#define LOG_TAG "statsd_drm"
#include <utils/Log.h>

#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <pthread.h>
#include <unistd.h>

#include <string.h>
#include <pwd.h>

#include "MediaMetricsService.h"
#include "iface_statsd.h"

#include <statslog.h>

#include <array>
#include <string>

namespace android {

// mediadrm
bool statsd_mediadrm(const mediametrics::Item *item)
{
    if (item == nullptr) return false;

    const nsecs_t timestamp = MediaMetricsService::roundTime(item->getTimestamp());
    std::string pkgName = item->getPkgName();
    int64_t pkgVersionCode = item->getPkgVersionCode();
    int64_t mediaApexVersion = 0;

    std::string vendor;
    (void) item->getString("vendor", &vendor);
    std::string description;
    (void) item->getString("description", &description);
    std::string serialized_metrics;
    (void) item->getString("serialized_metrics", &serialized_metrics);

    if (enabled_statsd) {
        android::util::BytesField bf_serialized(serialized_metrics.c_str(),
                                                serialized_metrics.size());
        android::util::stats_write(android::util::MEDIAMETRICS_MEDIADRM_REPORTED,
                                   timestamp, pkgName.c_str(), pkgVersionCode,
                                   mediaApexVersion,
                                   vendor.c_str(),
                                   description.c_str(),
                                   bf_serialized);
    } else {
        ALOGV("NOT sending: mediadrm private data (len=%zu)", serialized_metrics.size());
    }

    return true;
}

// widevineCDM
bool statsd_widevineCDM(const mediametrics::Item *item)
{
    if (item == nullptr) return false;

    const nsecs_t timestamp = MediaMetricsService::roundTime(item->getTimestamp());
    std::string pkgName = item->getPkgName();
    int64_t pkgVersionCode = item->getPkgVersionCode();
    int64_t mediaApexVersion = 0;

    std::string serialized_metrics;
    (void) item->getString("serialized_metrics", &serialized_metrics);

    if (enabled_statsd) {
        android::util::BytesField bf_serialized(serialized_metrics.c_str(),
                                                serialized_metrics.size());
        android::util::stats_write(android::util::MEDIAMETRICS_DRM_WIDEVINE_REPORTED,
                                   timestamp, pkgName.c_str(), pkgVersionCode,
                                   mediaApexVersion,
                                   bf_serialized);
    } else {
        ALOGV("NOT sending: widevine private data (len=%zu)", serialized_metrics.size());
    }

    return true;
}

// drmmanager
bool statsd_drmmanager(const mediametrics::Item *item)
{
    using namespace std::string_literals;
    if (item == nullptr) return false;

    if (!enabled_statsd) {
        ALOGV("NOT sending: drmmanager data");
        return true;
    }

    const nsecs_t timestamp = MediaMetricsService::roundTime(item->getTimestamp());
    std::string pkgName = item->getPkgName();
    int64_t pkgVersionCode = item->getPkgVersionCode();
    int64_t mediaApexVersion = 0;

    std::string plugin_id;
    (void) item->getString("plugin_id", &plugin_id);
    std::string description;
    (void) item->getString("description", &description);
    int32_t method_id = -1;
    (void) item->getInt32("method_id", &method_id);
    std::string mime_types;
    (void) item->getString("mime_types", &mime_types);

    // Corresponds to the 13 APIs tracked in the MediametricsDrmManagerReported statsd proto
    // Please see also DrmManager::kMethodIdMap
    std::array<int64_t, 13> methodCounts{};
    for (size_t i = 0; i < methodCounts.size() ; i++) {
        item->getInt64(("method"s + std::to_string(i)).c_str(), &methodCounts[i]);
    }

    android::util::stats_write(android::util::MEDIAMETRICS_DRMMANAGER_REPORTED,
                               timestamp, pkgName.c_str(), pkgVersionCode, mediaApexVersion,
                               plugin_id.c_str(), description.c_str(),
                               method_id, mime_types.c_str(),
                               methodCounts[0], methodCounts[1], methodCounts[2],
                               methodCounts[3], methodCounts[4], methodCounts[5],
                               methodCounts[6], methodCounts[7], methodCounts[8],
                               methodCounts[9], methodCounts[10], methodCounts[11],
                               methodCounts[12]);

    return true;
}

} // namespace android
