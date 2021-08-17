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
#define LOG_TAG "statsd_extractor"
#include <utils/Log.h>

#include <dirent.h>
#include <inttypes.h>
#include <pthread.h>
#include <pwd.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <statslog.h>

#include "MediaMetricsService.h"
#include "StringUtils.h"
#include "frameworks/proto_logging/stats/message/mediametrics_message.pb.h"
#include "iface_statsd.h"

namespace android {

bool statsd_extractor(const std::shared_ptr<const mediametrics::Item>& item,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog)
{
    if (item == nullptr) return false;

    // these go into the statsd wrapper
    const nsecs_t timestamp_nanos = MediaMetricsService::roundTime(item->getTimestamp());
    const std::string package_name = item->getPkgName();
    const int64_t package_version_code = item->getPkgVersionCode();
    const int64_t media_apex_version = 0;

    // the rest into our own proto
    //
    ::android::stats::mediametrics_message::ExtractorData metrics_proto;

    std::string format;
    if (item->getString("android.media.mediaextractor.fmt", &format)) {
        metrics_proto.set_format(format);
    }

    std::string mime;
    if (item->getString("android.media.mediaextractor.mime", &mime)) {
        metrics_proto.set_mime(mime);
    }

    int32_t tracks = -1;
    if (item->getInt32("android.media.mediaextractor.ntrk", &tracks)) {
        metrics_proto.set_tracks(tracks);
    }

    std::string entry_point_string;
    stats::mediametrics_message::ExtractorData::EntryPoint entry_point =
            stats::mediametrics_message::ExtractorData_EntryPoint_OTHER;
    if (item->getString("android.media.mediaextractor.entry", &entry_point_string)) {
      if (entry_point_string == "sdk") {
        entry_point = stats::mediametrics_message::ExtractorData_EntryPoint_SDK;
      } else if (entry_point_string == "ndk-with-jvm") {
        entry_point = stats::mediametrics_message::ExtractorData_EntryPoint_NDK_WITH_JVM;
      } else if (entry_point_string == "ndk-no-jvm") {
        entry_point = stats::mediametrics_message::ExtractorData_EntryPoint_NDK_NO_JVM;
      } else {
        entry_point = stats::mediametrics_message::ExtractorData_EntryPoint_OTHER;
      }
      metrics_proto.set_entry_point(entry_point);
    }

    std::string log_session_id;
    if (item->getString("android.media.mediaextractor.logSessionId", &log_session_id)) {
        log_session_id = mediametrics::stringutils::sanitizeLogSessionId(log_session_id);
        metrics_proto.set_log_session_id(log_session_id);
    }

    std::string serialized;
    if (!metrics_proto.SerializeToString(&serialized)) {
        ALOGE("Failed to serialize extractor metrics");
        return false;
    }

    android::util::BytesField bf_serialized( serialized.c_str(), serialized.size());
    int result = android::util::stats_write(android::util::MEDIAMETRICS_EXTRACTOR_REPORTED,
        timestamp_nanos, package_name.c_str(), package_version_code,
        media_apex_version,
        bf_serialized);
    std::stringstream log;
    log << "result:" << result << " {"
            << " mediametrics_extractor_reported:"
            << android::util::MEDIAMETRICS_EXTRACTOR_REPORTED
            << " timestamp_nanos:" << timestamp_nanos
            << " package_name:" << package_name
            << " package_version_code:" << package_version_code
            << " media_apex_version:" << media_apex_version

            << " format:" << format
            << " mime:" << mime
            << " tracks:" << tracks
            << " entry_point:" << entry_point_string << "(" << entry_point << ")"
            << " log_session_id:" << log_session_id
            << " }";
    statsdLog->log(android::util::MEDIAMETRICS_EXTRACTOR_REPORTED, log.str());
    return true;
}

} // namespace android
