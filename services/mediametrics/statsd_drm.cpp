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
#include <binder/IPCThreadState.h>

#include <cstdint>
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
#include "MediaDrmStatsdHelper.h"
#include "StringUtils.h"
#include "iface_statsd.h"

#include <stats_media_metrics.h>

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
    const stats::media_metrics::BytesField bf_serialized(kUnusedField.c_str(), kUnusedField.size());
    const int result = stats::media_metrics::stats_write(
        stats::media_metrics::MEDIAMETRICS_MEDIADRM_REPORTED,
        timestamp_nanos, package_name.c_str(), package_version_code,
        media_apex_version,
        vendor.c_str(),
        description.c_str(),
        bf_serialized);

    std::stringstream log;
    log << "result:" << result << " {"
            << " mediametrics_mediadrm_reported:"
            << stats::media_metrics::MEDIAMETRICS_MEDIADRM_REPORTED
            << " timestamp_nanos:" << timestamp_nanos
            << " package_name:" << package_name
            << " package_version_code:" << package_version_code
            << " media_apex_version:" << media_apex_version

            << " vendor:" << vendor
            << " description:" << description
            // omitting serialized
            << " }";
    statsdLog->log(stats::media_metrics::MEDIAMETRICS_MEDIADRM_REPORTED, log.str());
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

    const int result = stats::media_metrics::stats_write(
                               stats::media_metrics::MEDIAMETRICS_DRMMANAGER_REPORTED,
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
            << stats::media_metrics::MEDIAMETRICS_DRMMANAGER_REPORTED
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
    statsdLog->log(stats::media_metrics::MEDIAMETRICS_DRMMANAGER_REPORTED, log.str());
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
    AStatsEvent_setAtomId(event, stats::media_metrics::MEDIA_DRM_ACTIVITY_INFO);
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
            << stats::media_metrics::MEDIA_DRM_ACTIVITY_INFO
            << " package_name:" << item->getPkgName()
            << " package_version_code:" << item->getPkgVersionCode()
            << " vendor:" << vendor
            << " description:" << description
            << " framework_metrics:" << mediametrics::stringutils::bytesToString(framework_raw, 8)
            << " vendor_metrics:" <<  mediametrics::stringutils::bytesToString(plugin_raw, 8)
            << " }";
    statsdLog->log(stats::media_metrics::MEDIA_DRM_ACTIVITY_INFO, log.str());
    return true;
}

bool statsd_mediadrm_created(const std::shared_ptr<const mediametrics::Item>& item,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog)
{
    int64_t uuid_lsb = -1;
    if (!item->getInt64("uuid_lsb", &uuid_lsb)) return false;
    int64_t uuid_msb = -1;
    if (!item->getInt64("uuid_msb", &uuid_msb)) return false;
    const int32_t scheme = MediaDrmStatsdHelper::findDrmScheme(uuid_msb, uuid_lsb);
    const int32_t uid = IPCThreadState::self()->getCallingUid();
    int32_t frontend = 0;
    if (!item->getInt32("frontend", &frontend)) return false;

    // Optional to be included
    std::string version = "";
    item->getString("version", &version);
    const int result = stats_write(stats::media_metrics::MEDIA_DRM_CREATED,
                    scheme, uuid_lsb, uuid_msb, uid, frontend, version.c_str());

    std::stringstream log;
    log << "result:" << result << " {"
            << " media_drm_created:"
            << stats::media_metrics::MEDIA_DRM_CREATED
            << " scheme:" << scheme
            << " uuid_lsb:" << uuid_lsb
            << " uuid_msb:" << uuid_msb
            << " uid:" << uid
            << " frontend:" << frontend
            << " version:" << version
            << " }";
    statsdLog->log(stats::media_metrics::MEDIA_DRM_CREATED, log.str());
    return true;
}

bool statsd_mediadrm_session_opened(const std::shared_ptr<const mediametrics::Item>& item,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog)
{
    int64_t uuid_lsb = -1;
    if (!item->getInt64("uuid_lsb", &uuid_lsb)) return false;
    int64_t uuid_msb = -1;
    if (!item->getInt64("uuid_msb", &uuid_msb)) return false;
    const int32_t scheme = MediaDrmStatsdHelper::findDrmScheme(uuid_msb, uuid_lsb);
    std::string object_nonce = "";
    if (!item->getString("object_nonce", &object_nonce)) return false;
    const int32_t uid = IPCThreadState::self()->getCallingUid();
    int32_t frontend = 0;
    if (!item->getInt32("frontend", &frontend)) return false;
    int32_t requested_security_level = 0;
    if (!item->getInt32("requested_security_level", &requested_security_level)) return false;
    int32_t opened_security_level = 0;
    if (!item->getInt32("opened_security_level", &opened_security_level)) return false;

    // Optional to be included
    std::string version = "";
    item->getString("version", &version);
    const int result = stats_write(stats::media_metrics::MEDIA_DRM_SESSION_OPENED,
                        scheme, uuid_lsb, uuid_msb, uid, frontend, version.c_str(),
                        object_nonce.c_str(), requested_security_level,
                        opened_security_level);

    std::stringstream log;
    log << "result:" << result << " {"
            << " media_drm_session_opened:"
            << stats::media_metrics::MEDIA_DRM_SESSION_OPENED
            << " scheme:" << scheme
            << " uuid_lsb:" << uuid_lsb
            << " uuid_msb:" << uuid_msb
            << " uid:" << uid
            << " frontend:" << frontend
            << " version:" << version
            << " object_nonce:" << object_nonce
            << " requested_security_level:" << requested_security_level
            << " opened_security_level:" << opened_security_level
            << " }";
    statsdLog->log(stats::media_metrics::MEDIA_DRM_SESSION_OPENED, log.str());
    return true;
}

bool statsd_mediadrm_errored(const std::shared_ptr<const mediametrics::Item>& item,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog)
{
    int64_t uuid_lsb = -1;
    if (!item->getInt64("uuid_lsb", &uuid_lsb)) return false;
    int64_t uuid_msb = -1;
    if (!item->getInt64("uuid_msb", &uuid_msb)) return false;
    const int32_t scheme = MediaDrmStatsdHelper::findDrmScheme(uuid_msb, uuid_lsb);
    const int32_t uid = IPCThreadState::self()->getCallingUid();
    int32_t frontend = 0;
    if (!item->getInt32("frontend", &frontend)) return false;
    std::string object_nonce = "";
    if (!item->getString("object_nonce", &object_nonce)) return false;
    std::string api_str = "";
    if (!item->getString("api", &api_str)) return false;
    const int32_t api = MediaDrmStatsdHelper::findDrmApi(api_str);
    int32_t error_code = 0;
    if (!item->getInt32("error_code", &error_code)) return false;

    // Optional to be included
    std::string version = "";
    item->getString("version", &version);
    std::string session_nonce = "";
    item->getString("session_nonce", &session_nonce);
    int32_t security_level = 0;
    item->getInt32("security_level", &security_level);

    int32_t cdm_err = 0;
    item->getInt32("cdm_err", &cdm_err);
    int32_t oem_err = 0;
    item->getInt32("oem_err", &oem_err);
    int32_t error_context = 0;
    item->getInt32("error_context", &error_context);

    const int result = stats_write(stats::media_metrics::MEDIA_DRM_ERRORED, scheme, uuid_lsb,
                        uuid_msb, uid, frontend, version.c_str(), object_nonce.c_str(),
                        session_nonce.c_str(), security_level, api, error_code, cdm_err,
                        oem_err, error_context);

    std::stringstream log;
    log << "result:" << result << " {"
            << " media_drm_errored:"
            << stats::media_metrics::MEDIA_DRM_ERRORED
            << " scheme:" << scheme
            << " uuid_lsb:" << uuid_lsb
            << " uuid_msb:" << uuid_msb
            << " uid:" << uid
            << " frontend:" << frontend
            << " version:" << version
            << " object_nonce:" << object_nonce
            << " session_nonce:" << session_nonce
            << " security_level:" << security_level
            << " api:" << api
            << " error_code:" << error_code
            << " cdm_err:" << cdm_err
            << " oem_err:" << oem_err
            << " error_context:" << error_context
            << " }";
    statsdLog->log(stats::media_metrics::MEDIA_DRM_ERRORED, log.str());
    return true;
}

} // namespace android
