/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "statsd_mediaparser"
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
#include "frameworks/proto_logging/stats/enums/stats/mediametrics/mediametrics.pb.h"
#include "iface_statsd.h"

namespace android {

bool statsd_mediaparser(const std::shared_ptr<const mediametrics::Item>& item,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog)
{
    if (item == nullptr) return false;

    const nsecs_t timestamp_nanos = MediaMetricsService::roundTime(item->getTimestamp());
    const std::string package_name = item->getPkgName();
    const int64_t package_version_code = item->getPkgVersionCode();

    std::string parserName;
    item->getString("android.media.mediaparser.parserName", &parserName);

    int32_t createdByName = -1;
    item->getInt32("android.media.mediaparser.createdByName", &createdByName);

    std::string parserPool;
    item->getString("android.media.mediaparser.parserPool", &parserPool);

    std::string lastException;
    item->getString("android.media.mediaparser.lastException", &lastException);

    int64_t resourceByteCount = -1;
    item->getInt64("android.media.mediaparser.resourceByteCount", &resourceByteCount);

    int64_t durationMillis = -1;
    item->getInt64("android.media.mediaparser.durationMillis", &durationMillis);

    std::string trackMimeTypes;
    item->getString("android.media.mediaparser.trackMimeTypes", &trackMimeTypes);

    std::string trackCodecs;
    item->getString("android.media.mediaparser.trackCodecs", &trackCodecs);

    std::string alteredParameters;
    item->getString("android.media.mediaparser.alteredParameters", &alteredParameters);

    int32_t videoWidth = -1;
    item->getInt32("android.media.mediaparser.videoWidth", &videoWidth);

    int32_t videoHeight = -1;
    item->getInt32("android.media.mediaparser.videoHeight", &videoHeight);

    std::string logSessionId;
    item->getString("android.media.mediaparser.logSessionId", &logSessionId);
    logSessionId = mediametrics::stringutils::sanitizeLogSessionId(logSessionId);

    int result = android::util::stats_write(android::util::MEDIAMETRICS_MEDIAPARSER_REPORTED,
                               timestamp_nanos,
                               package_name.c_str(),
                               package_version_code,
                               parserName.c_str(),
                               createdByName,
                               parserPool.c_str(),
                               lastException.c_str(),
                               resourceByteCount,
                               durationMillis,
                               trackMimeTypes.c_str(),
                               trackCodecs.c_str(),
                               alteredParameters.c_str(),
                               videoWidth,
                               videoHeight,
                               logSessionId.c_str());

    std::stringstream log;
    log << "result:" << result << " {"
            << " mediametrics_mediaparser_reported:"
            << android::util::MEDIAMETRICS_MEDIAPARSER_REPORTED
            << " timestamp_nanos:" << timestamp_nanos
            << " package_name:" << package_name
            << " package_version_code:" << package_version_code
            << " parser_name:" << parserName
            << " created_by_name:" << createdByName
            << " parser_pool:" << parserPool
            << " last_exception:" << lastException
            << " resource_byte_count:" << resourceByteCount
            << " duration_millis:" << durationMillis
            << " track_mime_types:" << trackMimeTypes
            << " track_codecs:" << trackCodecs
            << " altered_parameters:" << alteredParameters
            << " video_width:" << videoWidth
            << " video_height:" << videoHeight
            << " log_session_id:" << logSessionId
            << " }";
    statsdLog->log(android::util::MEDIAMETRICS_MEDIAPARSER_REPORTED, log.str());
    return true;
}

} // namespace android
