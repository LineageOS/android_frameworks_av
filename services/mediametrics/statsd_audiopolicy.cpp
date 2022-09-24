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
#define LOG_TAG "statsd_audiopolicy"
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

#include <stats_media_metrics.h>

#include "MediaMetricsService.h"
#include "frameworks/proto_logging/stats/message/mediametrics_message.pb.h"
#include "iface_statsd.h"

namespace android {

bool statsd_audiopolicy(const std::shared_ptr<const mediametrics::Item>& item,
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
    ::android::stats::mediametrics_message::AudioPolicyData metrics_proto;

    // flesh out the protobuf we'll hand off with our data
    //
    //int32 char kAudioPolicyStatus[] = "android.media.audiopolicy.status";
    int32_t status = -1;
    if (item->getInt32("android.media.audiopolicy.status", &status)) {
        metrics_proto.set_status(status);
    }
    //string char kAudioPolicyRqstSrc[] = "android.media.audiopolicy.rqst.src";
    std::string request_source;
    if (item->getString("android.media.audiopolicy.rqst.src", &request_source)) {
        metrics_proto.set_request_source(request_source);
    }
    //string char kAudioPolicyRqstPkg[] = "android.media.audiopolicy.rqst.pkg";
    std::string request_package;
    if (item->getString("android.media.audiopolicy.rqst.pkg", &request_package)) {
        metrics_proto.set_request_package(request_package);
    }
    //int32 char kAudioPolicyRqstSession[] = "android.media.audiopolicy.rqst.session";
    int32_t request_session = -1;
    if (item->getInt32("android.media.audiopolicy.rqst.session", &request_session)) {
        metrics_proto.set_request_session(request_session);
    }
    //string char kAudioPolicyRqstDevice[] = "android.media.audiopolicy.rqst.device";
    std::string request_device;
    if (item->getString("android.media.audiopolicy.rqst.device", &request_device)) {
        metrics_proto.set_request_device(request_device);
    }

    //string char kAudioPolicyActiveSrc[] = "android.media.audiopolicy.active.src";
    std::string active_source;
    if (item->getString("android.media.audiopolicy.active.src", &active_source)) {
        metrics_proto.set_active_source(active_source);
    }
    //string char kAudioPolicyActivePkg[] = "android.media.audiopolicy.active.pkg";
    std::string active_package;
    if (item->getString("android.media.audiopolicy.active.pkg", &active_package)) {
        metrics_proto.set_active_package(active_package);
    }
    //int32 char kAudioPolicyActiveSession[] = "android.media.audiopolicy.active.session";
    int32_t active_session = -1;
    if (item->getInt32("android.media.audiopolicy.active.session", &active_session)) {
        metrics_proto.set_active_session(active_session);
    }
    //string char kAudioPolicyActiveDevice[] = "android.media.audiopolicy.active.device";
    std::string active_device;
    if (item->getString("android.media.audiopolicy.active.device", &active_device)) {
        metrics_proto.set_active_device(active_device);
    }

    std::string serialized;
    if (!metrics_proto.SerializeToString(&serialized)) {
        ALOGE("Failed to serialize audipolicy metrics");
        return false;
    }

    const stats::media_metrics::BytesField bf_serialized( serialized.c_str(), serialized.size());
    const int result = stats::media_metrics::stats_write(
        stats::media_metrics::MEDIAMETRICS_AUDIOPOLICY_REPORTED,
        timestamp_nanos, package_name.c_str(), package_version_code,
        media_apex_version,
        bf_serialized);
    std::stringstream log;
    log << "result:" << result << " {"
            << " mediametrics_audiopolicy_reported:"
            << stats::media_metrics::MEDIAMETRICS_AUDIOPOLICY_REPORTED
            << " timestamp_nanos:" << timestamp_nanos
            << " package_name:" << package_name
            << " package_version_code:" << package_version_code
            << " media_apex_version:" << media_apex_version

            << " status:" << status
            << " request_source:" << request_source
            << " request_package:" << request_package
            << " request_session:" << request_session
            << " request_device:" << request_device
            << " active_source:" << active_source
            << " active_package:" << active_package
            << " active_session:" << active_session
            << " active_device:" << active_device
            << " }";
    statsdLog->log(stats::media_metrics::MEDIAMETRICS_AUDIOPOLICY_REPORTED, log.str());
    return true;
}

} // namespace android
