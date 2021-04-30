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
#define LOG_TAG "statsd_codec"
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

#include "cleaner.h"
#include "MediaMetricsService.h"
#include "frameworks/proto_logging/stats/message/mediametrics_message.pb.h"
#include "iface_statsd.h"

namespace android {

bool statsd_codec(const std::shared_ptr<const mediametrics::Item>& item,
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
    ::android::stats::mediametrics_message::CodecData metrics_proto;

    // flesh out the protobuf we'll hand off with our data
    //
    // android.media.mediacodec.codec   string
    std::string codec;
    if (item->getString("android.media.mediacodec.codec", &codec)) {
        metrics_proto.set_codec(codec);
    }

    std::string mime;
    if (item->getString("android.media.mediacodec.mime", &mime)) {
        metrics_proto.set_mime(mime);
    }

    std::string mode;
    if ( item->getString("android.media.mediacodec.mode", &mode)) {
        metrics_proto.set_mode(mode);
    }

    int32_t encoder = -1;
    if ( item->getInt32("android.media.mediacodec.encoder", &encoder)) {
        metrics_proto.set_encoder(encoder);
    }

    int32_t secure = -1;
    if ( item->getInt32("android.media.mediacodec.secure", &secure)) {
        metrics_proto.set_secure(secure);
    }

    int32_t width = -1;
    if ( item->getInt32("android.media.mediacodec.width", &width)) {
        metrics_proto.set_width(width);
    }

    int32_t height = -1;
    if ( item->getInt32("android.media.mediacodec.height", &height)) {
        metrics_proto.set_height(height);
    }

    int32_t rotation = -1;
    if ( item->getInt32("android.media.mediacodec.rotation-degrees", &rotation)) {
        metrics_proto.set_rotation(rotation);
    }
    // android.media.mediacodec.crypto  int32 (although missing if not needed)
    int32_t crypto = -1;
    if ( item->getInt32("android.media.mediacodec.crypto", &crypto)) {
        metrics_proto.set_crypto(crypto);
    }

    int32_t profile = -1;
    if ( item->getInt32("android.media.mediacodec.profile", &profile)) {
        metrics_proto.set_profile(profile);
    }

    int32_t level = -1;
    if ( item->getInt32("android.media.mediacodec.level", &level)) {
        metrics_proto.set_level(level);
    }

    int32_t max_width = -1;
    if ( item->getInt32("android.media.mediacodec.maxwidth", &max_width)) {
        metrics_proto.set_max_width(max_width);
    }

    int32_t max_height = -1;
    if ( item->getInt32("android.media.mediacodec.maxheight", &max_height)) {
        metrics_proto.set_max_height(max_height);
    }

    int32_t error_code = -1;
    if ( item->getInt32("android.media.mediacodec.errcode", &error_code)) {
        metrics_proto.set_error_code(error_code);
    }

    std::string error_state;
    if ( item->getString("android.media.mediacodec.errstate", &error_state)) {
        metrics_proto.set_error_state(error_state);
    }

    int64_t latency_max = -1;
    if ( item->getInt64("android.media.mediacodec.latency.max", &latency_max)) {
        metrics_proto.set_latency_max(latency_max);
    }

    int64_t latency_min = -1;
    if ( item->getInt64("android.media.mediacodec.latency.min", &latency_min)) {
        metrics_proto.set_latency_min(latency_min);
    }

    int64_t latency_avg = -1;
    if ( item->getInt64("android.media.mediacodec.latency.avg", &latency_avg)) {
        metrics_proto.set_latency_avg(latency_avg);
    }

    int64_t latency_count = -1;
    if ( item->getInt64("android.media.mediacodec.latency.n", &latency_count)) {
        metrics_proto.set_latency_count(latency_count);
    }

    int64_t latency_unknown = -1;
    if ( item->getInt64("android.media.mediacodec.latency.unknown", &latency_unknown)) {
        metrics_proto.set_latency_unknown(latency_unknown);
    }

    int32_t queue_secure_input_buffer_error = -1;
    if (item->getInt32("android.media.mediacodec.queueSecureInputBufferError",
                &queue_secure_input_buffer_error)) {
        metrics_proto.set_queue_secure_input_buffer_error(queue_secure_input_buffer_error);
    }

    int32_t queue_input_buffer_error = -1;
    if (item->getInt32("android.media.mediacodec.queueInputBufferError",
                &queue_input_buffer_error)) {
        metrics_proto.set_queue_input_buffer_error(queue_input_buffer_error);
    }
    // android.media.mediacodec.latency.hist    NOT EMITTED

    std::string bitrate_mode;
    if (item->getString("android.media.mediacodec.bitrate_mode", &bitrate_mode)) {
        metrics_proto.set_bitrate_mode(bitrate_mode);
    }

    int32_t bitrate = -1;
    if (item->getInt32("android.media.mediacodec.bitrate", &bitrate)) {
        metrics_proto.set_bitrate(bitrate);
    }

    int64_t lifetime_millis = -1;
    if (item->getInt64("android.media.mediacodec.lifetimeMs", &lifetime_millis)) {
        lifetime_millis = mediametrics::bucket_time_minutes(lifetime_millis);
        metrics_proto.set_lifetime_millis(lifetime_millis);
    }

    // android.media.mediacodec.channelCount
    int32_t channelCount = -1;
    if ( item->getInt32("android.media.mediacodec.channelCount", &channelCount)) {
        metrics_proto.set_channel_count(channelCount);
    }

    // android.media.mediacodec.sampleRate
    int32_t sampleRate = -1;
    if ( item->getInt32("android.media.mediacodec.sampleRate", &sampleRate)) {
        metrics_proto.set_sample_rate(sampleRate);
    }

    // TODO PWG may want these fuzzed up a bit to obscure some precision
    // android.media.mediacodec.vencode.bytes
    int64_t bytes = -1;
    if ( item->getInt64("android.media.mediacodec.vencode.bytes", &bytes)) {
        metrics_proto.set_video_encode_bytes(bytes);
    }

    // android.media.mediacodec.vencode.frames
    int64_t frames = -1;
    if ( item->getInt64("android.media.mediacodec.vencode.frames", &frames)) {
        metrics_proto.set_video_encode_frames(frames);
    }

    // android.media.mediacodec.vencode.durationUs
    int64_t durationUs = -1;
    if ( item->getInt64("android.media.mediacodec.vencode.durationUs", &durationUs)) {
        metrics_proto.set_video_encode_duration_us(durationUs);
    }

    // android.media.mediacodec.color-format
    int32_t colorFormat = -1;
    if ( item->getInt32("android.media.mediacodec.color-format", &colorFormat)) {
        metrics_proto.set_color_format(colorFormat);
    }

    // android.media.mediacodec.frame-rate
    double frameRate = -1.0;
    if ( item->getDouble("android.media.mediacodec.frame-rate", &frameRate)) {
        metrics_proto.set_frame_rate(frameRate);
    }

    // android.media.mediacodec.capture-rate
    double captureRate = -1.0;
    if ( item->getDouble("android.media.mediacodec.capture-rate", &captureRate)) {
        metrics_proto.set_capture_rate(captureRate);
    }

    // android.media.mediacodec.operating-rate
    double operatingRate = -1.0;
    if ( item->getDouble("android.media.mediacodec.operating-rate", &operatingRate)) {
        metrics_proto.set_operating_rate(operatingRate);
    }

    // android.media.mediacodec.priority
    int32_t priority = -1;
    if ( item->getInt32("android.media.mediacodec.priority", &priority)) {
        metrics_proto.set_priority(priority);
    }

    // android.media.mediacodec.video-qp-i-min
    int32_t qpIMin = -1;
    if ( item->getInt32("android.media.mediacodec.video-qp-i-min", &qpIMin)) {
        metrics_proto.set_video_qp_i_min(qpIMin);
    }

    // android.media.mediacodec.video-qp-i-max
    int32_t qpIMax = -1;
    if ( item->getInt32("android.media.mediacodec.video-qp-i-max", &qpIMax)) {
        metrics_proto.set_video_qp_i_max(qpIMax);
    }

    // android.media.mediacodec.video-qp-p-min
    int32_t qpPMin = -1;
    if ( item->getInt32("android.media.mediacodec.video-qp-p-min", &qpPMin)) {
        metrics_proto.set_video_qp_p_min(qpPMin);
    }

    // android.media.mediacodec.video-qp-p-max
    int32_t qpPMax = -1;
    if ( item->getInt32("android.media.mediacodec.video-qp-p-max", &qpPMax)) {
        metrics_proto.set_video_qp_p_max(qpPMax);
    }

    // android.media.mediacodec.video-qp-b-min
    int32_t qpBMin = -1;
    if ( item->getInt32("android.media.mediacodec.video-qp-b-min", &qpBMin)) {
        metrics_proto.set_video_qp_b_min(qpIMin);
    }

    // android.media.mediacodec.video-qp-b-max
    int32_t qpBMax = -1;
    if ( item->getInt32("android.media.mediacodec.video-qp-b-max", &qpBMax)) {
        metrics_proto.set_video_qp_b_max(qpBMax);
    }

    // android.media.mediacodec.video.input.bytes
    int64_t inputBytes = -1;
    if ( item->getInt64("android.media.mediacodec.video.input.bytes", &inputBytes)) {
        metrics_proto.set_video_input_bytes(inputBytes);
    }

    // android.media.mediacodec.video.input.frames
    int64_t inputFrames = -1;
    if ( item->getInt64("android.media.mediacodec.video.input.frames", &inputFrames)) {
        metrics_proto.set_video_input_frames(inputFrames);
    }

    // android.media.mediacodec.original.bitrate
    int32_t originalBitrate = -1;
    if ( item->getInt32("android.media.mediacodec.original.bitrate", &originalBitrate)) {
        metrics_proto.set_original_bitrate(originalBitrate);
    }

    std::string serialized;
    if (!metrics_proto.SerializeToString(&serialized)) {
        ALOGE("Failed to serialize codec metrics");
        return false;
    }
    android::util::BytesField bf_serialized( serialized.c_str(), serialized.size());
    int result = android::util::stats_write(android::util::MEDIAMETRICS_CODEC_REPORTED,
                               timestamp_nanos, package_name.c_str(), package_version_code,
                               media_apex_version,
                               bf_serialized);
    std::stringstream log;
    log << "result:" << result << " {"
            << " mediametrics_codec_reported:"
            << android::util::MEDIAMETRICS_CODEC_REPORTED
            << " timestamp_nanos:" << timestamp_nanos
            << " package_name:" << package_name
            << " package_version_code:" << package_version_code
            << " media_apex_version:" << media_apex_version

            << " codec:" << codec
            << " mime:" << mime
            << " mode:" << mode
            << " encoder:" << encoder
            << " secure:" << secure
            << " width:" << width
            << " height:" << height
            << " rotation:" << rotation
            << " crypto:" << crypto
            << " profile:" << profile

            << " level:" << level
            << " max_width:" << max_width
            << " max_height:" << max_height
            << " error_code:" << error_code
            << " error_state:" << error_state
            << " latency_max:" << latency_max
            << " latency_min:" << latency_min
            << " latency_avg:" << latency_avg
            << " latency_count:" << latency_count
            << " latency_unknown:" << latency_unknown

            << " queue_input_buffer_error:" << queue_input_buffer_error
            << " queue_secure_input_buffer_error:" << queue_secure_input_buffer_error
            << " bitrate_mode:" << bitrate_mode
            << " bitrate:" << bitrate
            << " lifetime_millis:" << lifetime_millis
            // TODO: add when log_session_id is merged.
            // << " log_session_id:" << log_session_id
            << " }";
    statsdLog->log(android::util::MEDIAMETRICS_CODEC_REPORTED, log.str());
    return true;
}

} // namespace android
