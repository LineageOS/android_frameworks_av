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
#include <media/stagefright/foundation/base64.h>

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
#include "StringUtils.h"
#include "iface_statsd.h"

#include <statslog.h>

#include <array>
#include <string>
#include <vector>

namespace android {

// mediadrm
bool statsd_mediadrm(const std::shared_ptr<const mediametrics::Item>& item,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog)
{
    if (item == nullptr) return false;

    const nsecs_t timestamp_nanos = MediaMetricsService::roundTime(item->getTimestamp());
    const std::string package_name = item->getPkgName();
    const int64_t package_version_code = item->getPkgVersionCode();
    const int64_t media_apex_version = 0;

    std::string vendor;
    (void) item->getString("vendor", &vendor);
    std::string description;
    (void) item->getString("description", &description);

    std::string serialized_metrics;
    (void) item->getString("serialized_metrics", &serialized_metrics);
    if (serialized_metrics.empty()) {
        ALOGD("statsd_mediadrm skipping empty entry");
        return false;
    }

    // This field is left here for backward compatibility.
    // This field is not used anymore.
    const std::string  kUnusedField("");
    android::util::BytesField bf_serialized(kUnusedField.c_str(), kUnusedField.size());
    int result = android::util::stats_write(android::util::MEDIAMETRICS_MEDIADRM_REPORTED,
        timestamp_nanos, package_name.c_str(), package_version_code,
        media_apex_version,
        vendor.c_str(),
        description.c_str(),
        bf_serialized);

    std::stringstream log;
    log << "result:" << result << " {"
            << " mediametrics_mediadrm_reported:"
            << android::util::MEDIAMETRICS_MEDIADRM_REPORTED
            << " timestamp_nanos:" << timestamp_nanos
            << " package_name:" << package_name
            << " package_version_code:" << package_version_code
            << " media_apex_version:" << media_apex_version

            << " vendor:" << vendor
            << " description:" << description
            // omitting serialized
            << " }";
    statsdLog->log(android::util::MEDIAMETRICS_MEDIADRM_REPORTED, log.str());
    return true;
}

// drmmanager
bool statsd_drmmanager(const std::shared_ptr<const mediametrics::Item>& item,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog)
{
    using namespace std::string_literals;
    if (item == nullptr) return false;

    const nsecs_t timestamp_nanos = MediaMetricsService::roundTime(item->getTimestamp());
    const std::string package_name = item->getPkgName();
    const int64_t package_version_code = item->getPkgVersionCode();
    const int64_t media_apex_version = 0;

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

    const int result = android::util::stats_write(android::util::MEDIAMETRICS_DRMMANAGER_REPORTED,
                               timestamp_nanos, package_name.c_str(), package_version_code,
                               media_apex_version,
                               plugin_id.c_str(), description.c_str(),
                               method_id, mime_types.c_str(),
                               methodCounts[0], methodCounts[1], methodCounts[2],
                               methodCounts[3], methodCounts[4], methodCounts[5],
                               methodCounts[6], methodCounts[7], methodCounts[8],
                               methodCounts[9], methodCounts[10], methodCounts[11],
                               methodCounts[12]);

    std::stringstream log;
    log << "result:" << result << " {"
            << " mediametrics_drmmanager_reported:"
            << android::util::MEDIAMETRICS_DRMMANAGER_REPORTED
            << " timestamp_nanos:" << timestamp_nanos
            << " package_name:" << package_name
            << " package_version_code:" << package_version_code
            << " media_apex_version:" << media_apex_version

            << " plugin_id:" << plugin_id
            << " description:" << description
            << " method_id:" << method_id
            << " mime_types:" << mime_types;

    for (size_t i = 0; i < methodCounts.size(); ++i) {
        log << " method_" << i << ":" << methodCounts[i];
    }
    log << " }";
    statsdLog->log(android::util::MEDIAMETRICS_DRMMANAGER_REPORTED, log.str());
    return true;
}

namespace {
std::vector<uint8_t> base64DecodeNoPad(std::string& str) {
    if (str.empty()) {
        return {};
    }

    switch (str.length() % 4) {
    case 3: str += "="; break;
    case 2: str += "=="; break;
    case 1: str += "==="; break;
    case 0: /* unchanged */ break;
    }

    std::vector<uint8_t> buf(str.length() / 4 * 3, 0);
    size_t size = buf.size();
    if (decodeBase64(buf.data(), &size, str.c_str()) && size <= buf.size()) {
        buf.erase(buf.begin() + (ptrdiff_t)size, buf.end());
        return buf;
    }
    return {};
}
} // namespace

// |out| and its contents are memory-managed by statsd.
bool statsd_mediadrm_puller(
        const std::shared_ptr<const mediametrics::Item>& item, AStatsEventList* out,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog)
{
    if (item == nullptr) {
        return false;
    }

    std::string serialized_metrics;
    (void) item->getString("serialized_metrics", &serialized_metrics);
    const auto framework_raw(base64DecodeNoPad(serialized_metrics));

    std::string plugin_metrics;
    (void) item->getString("plugin_metrics", &plugin_metrics);
    const auto plugin_raw(base64DecodeNoPad(plugin_metrics));

    if (serialized_metrics.size() == 0 && plugin_metrics.size() == 0) {
        ALOGD("statsd_mediadrm_puller skipping empty entry");
        return false;
    }

    std::string vendor;
    (void) item->getString("vendor", &vendor);
    std::string description;
    (void) item->getString("description", &description);

    // Memory for |event| is internally managed by statsd.
    AStatsEvent* event = AStatsEventList_addStatsEvent(out);
    AStatsEvent_setAtomId(event, android::util::MEDIA_DRM_ACTIVITY_INFO);
    AStatsEvent_writeString(event, item->getPkgName().c_str());
    AStatsEvent_writeInt64(event, item->getPkgVersionCode());
    AStatsEvent_writeString(event, vendor.c_str());
    AStatsEvent_writeString(event, description.c_str());
    AStatsEvent_writeByteArray(event, framework_raw.data(), framework_raw.size());
    AStatsEvent_writeByteArray(event, plugin_raw.data(), plugin_raw.size());
    AStatsEvent_build(event);

    std::stringstream log;
    log << "pulled:" << " {"
            << " media_drm_activity_info:"
            << android::util::MEDIA_DRM_ACTIVITY_INFO
            << " package_name:" << item->getPkgName()
            << " package_version_code:" << item->getPkgVersionCode()
            << " vendor:" << vendor
            << " description:" << description
            << " framework_metrics:" << mediametrics::stringutils::bytesToString(framework_raw, 8)
            << " vendor_metrics:" <<  mediametrics::stringutils::bytesToString(plugin_raw, 8)
            << " }";
    statsdLog->log(android::util::MEDIA_DRM_ACTIVITY_INFO, log.str());
    return true;
}

} // namespace android
