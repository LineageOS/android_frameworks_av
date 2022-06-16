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
#define LOG_TAG "statsd_audiorecord"
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
#include "ValidateId.h"
#include "frameworks/proto_logging/stats/message/mediametrics_message.pb.h"
#include "iface_statsd.h"

namespace android {

bool statsd_audiorecord(const std::shared_ptr<const mediametrics::Item>& item,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog) {
    if (item == nullptr) return false;

    // these go into the statsd wrapper
    const nsecs_t timestamp_nanos = MediaMetricsService::roundTime(item->getTimestamp());
    const std::string package_name = item->getPkgName();
    const int64_t package_version_code = item->getPkgVersionCode();
    const int64_t media_apex_version = 0;

    // the rest into our own proto
    //
    ::android::stats::mediametrics_message::AudioRecordData metrics_proto;

    // flesh out the protobuf we'll hand off with our data
    //
    std::string encoding;
    if (item->getString("android.media.audiorecord.encoding", &encoding)) {
        metrics_proto.set_encoding(encoding);
    }

    std::string source;
    if (item->getString("android.media.audiorecord.source", &source)) {
        metrics_proto.set_source(source);
    }

    int32_t latency = -1;
    if (item->getInt32("android.media.audiorecord.latency", &latency)) {
        metrics_proto.set_latency(latency);
    }

    int32_t samplerate = -1;
    if (item->getInt32("android.media.audiorecord.samplerate", &samplerate)) {
        metrics_proto.set_samplerate(samplerate);
    }

    int32_t channels = -1;
    if (item->getInt32("android.media.audiorecord.channels", &channels)) {
        metrics_proto.set_channels(channels);
    }

    int64_t created_millis = -1;
    // not currently sent from client.
    if (item->getInt64("android.media.audiorecord.createdMs", &created_millis)) {
        metrics_proto.set_created_millis(created_millis);
    }

    int64_t duration_millis = -1;
    double durationMs = 0.;
    if (item->getDouble("android.media.audiorecord.durationMs", &durationMs)) {
        duration_millis = (int64_t)durationMs;
        metrics_proto.set_duration_millis(duration_millis);
    }

    int32_t count = -1;
    // not currently sent from client.  (see start count instead).
    if (item->getInt32("android.media.audiorecord.n", &count)) {
        metrics_proto.set_count(count);
    }

    int32_t error_code = -1;
    if (item->getInt32("android.media.audiorecord.errcode", &error_code) ||
        item->getInt32("android.media.audiorecord.lastError.code", &error_code)) {
        metrics_proto.set_error_code(error_code);
    }

    std::string error_function;
    if (item->getString("android.media.audiorecord.errfunc", &error_function) ||
        item->getString("android.media.audiorecord.lastError.at", &error_function)) {
        metrics_proto.set_error_function(error_function);
    }

    int32_t port_id = -1;
    if (item->getInt32("android.media.audiorecord.portId", &port_id)) {
        metrics_proto.set_port_id(count);
    }

    int32_t frame_count = -1;
    if (item->getInt32("android.media.audiorecord.frameCount", &frame_count)) {
        metrics_proto.set_frame_count(frame_count);
    }

    std::string attributes;
    if (item->getString("android.media.audiorecord.attributes", &attributes)) {
        metrics_proto.set_attributes(attributes);
    }

    int64_t channel_mask = -1;
    if (item->getInt64("android.media.audiorecord.channelMask", &channel_mask)) {
        metrics_proto.set_channel_mask(channel_mask);
    }

    int64_t start_count = -1;
    if (item->getInt64("android.media.audiorecord.startCount", &start_count)) {
        metrics_proto.set_start_count(start_count);
    }

    std::string serialized;
    if (!metrics_proto.SerializeToString(&serialized)) {
        ALOGE("Failed to serialize audiorecord metrics");
        return false;
    }

    // Android S
    // log_session_id (string)
    std::string logSessionId;
    (void)item->getString("android.media.audiorecord.logSessionId", &logSessionId);
    const auto log_session_id = mediametrics::ValidateId::get()->validateId(logSessionId);

    android::util::BytesField bf_serialized( serialized.c_str(), serialized.size());
    int result = android::util::stats_write(android::util::MEDIAMETRICS_AUDIORECORD_REPORTED,
        timestamp_nanos, package_name.c_str(), package_version_code,
        media_apex_version,
        bf_serialized,
        log_session_id.c_str());
    std::stringstream log;
    log << "result:" << result << " {"
            << " mediametrics_audiorecord_reported:"
            << android::util::MEDIAMETRICS_AUDIORECORD_REPORTED
            << " timestamp_nanos:" << timestamp_nanos
            << " package_name:" << package_name
            << " package_version_code:" << package_version_code
            << " media_apex_version:" << media_apex_version

            << " encoding:" << encoding
            << " source:" << source
            << " latency:" << latency
            << " samplerate:" << samplerate
            << " channels:" << channels
            << " created_millis:" << created_millis
            << " duration_millis:" << duration_millis
            << " count:" << count
            << " error_code:" << error_code
            << " error_function:" << error_function

            << " port_id:" << port_id
            << " frame_count:" << frame_count
            << " attributes:" << attributes
            << " channel_mask:" << channel_mask
            << " start_count:" << start_count

            << " log_session_id:" << log_session_id
            << " }";
    statsdLog->log(android::util::MEDIAMETRICS_AUDIORECORD_REPORTED, log.str());
    return true;
}

} // namespace android
