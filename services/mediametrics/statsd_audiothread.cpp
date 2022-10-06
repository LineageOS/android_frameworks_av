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
#define LOG_TAG "statsd_audiothread"
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

bool statsd_audiothread(const std::shared_ptr<const mediametrics::Item>& item,
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
    ::android::stats::mediametrics_message::AudioThreadData metrics_proto;

#define	MM_PREFIX "android.media.audiothread."

    // flesh out the protobuf we'll hand off with our data
    //
    std::string mytype;
    if (item->getString(MM_PREFIX "type", &mytype)) {
        metrics_proto.set_type(std::move(mytype));
    }
    int32_t framecount = -1;
    if (item->getInt32(MM_PREFIX "framecount", &framecount)) {
        metrics_proto.set_framecount(framecount);
    }
    int32_t samplerate = -1;
    if (item->getInt32(MM_PREFIX "samplerate", &samplerate)) {
        metrics_proto.set_samplerate(samplerate);
    }
    std::string work_millis_hist;
    if (item->getString(MM_PREFIX "workMs.hist", &work_millis_hist)) {
        metrics_proto.set_work_millis_hist(work_millis_hist);
    }
    std::string latency_millis_hist;
    if (item->getString(MM_PREFIX "latencyMs.hist", &latency_millis_hist)) {
        metrics_proto.set_latency_millis_hist(latency_millis_hist);
    }
    std::string warmup_millis_hist;
    if (item->getString(MM_PREFIX "warmupMs.hist", &warmup_millis_hist)) {
        metrics_proto.set_warmup_millis_hist(warmup_millis_hist);
    }
    int64_t underruns = -1;
    if (item->getInt64(MM_PREFIX "underruns", &underruns)) {
        metrics_proto.set_underruns(underruns);
    }
    int64_t overruns = -1;
    if (item->getInt64(MM_PREFIX "overruns", &overruns)) {
        metrics_proto.set_overruns(overruns);
    }
    int64_t active_millis = -1;
    if (item->getInt64(MM_PREFIX "activeMs", &active_millis)) {
        metrics_proto.set_active_millis(active_millis);
    }
    int64_t duration_millis = -1;
    if (item->getInt64(MM_PREFIX "durationMs", &duration_millis)) {
        metrics_proto.set_duration_millis(duration_millis);
    }

    int32_t id = -1;
    if (item->getInt32(MM_PREFIX "id", &id)) {
        metrics_proto.set_id(id);
    }

    int32_t port_id = -1;
    if (item->getInt32(MM_PREFIX "portId", &port_id)) {
        metrics_proto.set_port_id(port_id);
    }
    // item->setCString(MM_PREFIX "type", threadTypeToString(mType));
    std::string type;
    if (item->getString(MM_PREFIX "type", &type)) {
        metrics_proto.set_type(type);
    }

    int32_t sample_rate = -1;
    if (item->getInt32(MM_PREFIX "sampleRate", &sample_rate)) {
        metrics_proto.set_sample_rate(sample_rate);
    }

    int32_t channel_mask = -1;
    if (item->getInt32(MM_PREFIX "channelMask", &channel_mask)) {
        metrics_proto.set_channel_mask(channel_mask);
    }

    std::string encoding;
    if (item->getString(MM_PREFIX "encoding", &encoding)) {
        metrics_proto.set_encoding(encoding);
    }

    int32_t frame_count = -1;
    if (item->getInt32(MM_PREFIX "frameCount", &frame_count)) {
        metrics_proto.set_frame_count(frame_count);
    }

    std::string output_device;
    if (item->getString(MM_PREFIX "outDevice", &output_device)) {
        metrics_proto.set_output_device(output_device);
    }

    std::string input_device;
    if (item->getString(MM_PREFIX "inDevice", &input_device)) {
        metrics_proto.set_input_device(input_device);
    }

    double io_jitter_mean_millis = -1;
    if (item->getDouble(MM_PREFIX "ioJitterMs.mean", &io_jitter_mean_millis)) {
        metrics_proto.set_io_jitter_mean_millis(io_jitter_mean_millis);
    }

    double io_jitter_stddev_millis = -1;
    if (item->getDouble(MM_PREFIX "ioJitterMs.std", &io_jitter_stddev_millis)) {
        metrics_proto.set_io_jitter_stddev_millis(io_jitter_stddev_millis);
    }

    double process_time_mean_millis = -1;
    if (item->getDouble(MM_PREFIX "processTimeMs.mean", &process_time_mean_millis)) {
        metrics_proto.set_process_time_mean_millis(process_time_mean_millis);
    }

    double process_time_stddev_millis = -1;
    if (item->getDouble(MM_PREFIX "processTimeMs.std", &process_time_stddev_millis)) {
        metrics_proto.set_process_time_stddev_millis(process_time_stddev_millis);
    }

    double timestamp_jitter_mean_millis = -1;
    if (item->getDouble(MM_PREFIX "timestampJitterMs.mean", &timestamp_jitter_mean_millis)) {
        metrics_proto.set_timestamp_jitter_mean_millis(timestamp_jitter_mean_millis);
    }

    double timestamp_jitter_stddev_millis = -1;
    if (item->getDouble(MM_PREFIX "timestampJitterMs.std", &timestamp_jitter_stddev_millis)) {
        metrics_proto.set_timestamp_jitter_stddev_millis(timestamp_jitter_stddev_millis);
    }

    double latency_mean_millis = -1;
    if (item->getDouble(MM_PREFIX "latencyMs.mean", &latency_mean_millis)) {
        metrics_proto.set_latency_mean_millis(latency_mean_millis);
    }

    double latency_stddev_millis = -1;
    if (item->getDouble(MM_PREFIX "latencyMs.std", &latency_stddev_millis)) {
        metrics_proto.set_latency_stddev_millis(latency_stddev_millis);
    }

    std::string serialized;
    if (!metrics_proto.SerializeToString(&serialized)) {
        ALOGE("Failed to serialize audiothread metrics");
        return false;
    }

    const stats::media_metrics::BytesField bf_serialized( serialized.c_str(), serialized.size());
    const int result = stats::media_metrics::stats_write(
        stats::media_metrics::MEDIAMETRICS_AUDIOTHREAD_REPORTED,
        timestamp_nanos, package_name.c_str(), package_version_code,
        media_apex_version,
        bf_serialized);
    std::stringstream log;
    log << "result:" << result << " {"
            << " mediametrics_audiothread_reported:"
            << stats::media_metrics::MEDIAMETRICS_AUDIOTHREAD_REPORTED
            << " timestamp_nanos:" << timestamp_nanos
            << " package_name:" << package_name
            << " package_version_code:" << package_version_code
            << " media_apex_version:" << media_apex_version

            << " type:" << type
            << " framecount:" << framecount
            << " samplerate:" << samplerate
            << " work_millis_hist:" << work_millis_hist
            << " latency_millis_hist:" << latency_millis_hist
            << " warmup_millis_hist:" << warmup_millis_hist
            << " underruns:" << underruns
            << " overruns:" << overruns
            << " active_millis:" << active_millis
            << " duration_millis:" << duration_millis

            << " id:" << id
            << " port_id:" << port_id
            << " sample_rate:" << sample_rate
            << " channel_mask:" << channel_mask
            << " encoding:" << encoding
            << " frame_count:" << frame_count
            << " output_device:" << output_device
            << " input_device:" << input_device
            << " io_jitter_mean_millis:" << io_jitter_mean_millis
            << " io_jitter_stddev_millis:" << io_jitter_stddev_millis

            << " process_time_mean_millis:" << process_time_mean_millis
            << " process_time_stddev_millis:" << process_time_stddev_millis
            << " timestamp_jitter_mean_millis:" << timestamp_jitter_mean_millis
            << " timestamp_jitter_stddev_millis:" << timestamp_jitter_stddev_millis
            << " latency_mean_millis:" << latency_mean_millis
            << " latency_stddev_millis:" << latency_stddev_millis
            << " }";
    statsdLog->log(stats::media_metrics::MEDIAMETRICS_AUDIOTHREAD_REPORTED, log.str());
    return true;
}

} // namespace android
