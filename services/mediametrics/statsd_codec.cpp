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
#include <stats_event.h>

#include "cleaner.h"
#include "MediaMetricsService.h"
#include "ValidateId.h"
#include "frameworks/proto_logging/stats/message/mediametrics_message.pb.h"
#include "iface_statsd.h"

namespace android {

bool statsd_codec(const std::shared_ptr<const mediametrics::Item>& item,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog)
{
    if (item == nullptr) return false;

    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, android::util::MEDIA_CODEC_REPORTED);

    const nsecs_t timestamp_nanos = MediaMetricsService::roundTime(item->getTimestamp());
    AStatsEvent_writeInt64(event, timestamp_nanos);

    std::string package_name = item->getPkgName();
    AStatsEvent_writeString(event, package_name.c_str());

    int64_t package_version_code = item->getPkgVersionCode();
    AStatsEvent_writeInt64(event, package_version_code);

    int64_t media_apex_version = 0;
    AStatsEvent_writeInt64(event, media_apex_version);

    // the rest into our own proto
    //
    ::android::stats::mediametrics_message::CodecData metrics_proto;

    // flesh out the protobuf we'll hand off with our data
    //
    std::string codec;
    if (item->getString("android.media.mediacodec.codec", &codec)) {
        metrics_proto.set_codec(codec);
    }
    AStatsEvent_writeString(event, codec.c_str());

    std::string mime;
    if (item->getString("android.media.mediacodec.mime", &mime)) {
        metrics_proto.set_mime(mime);
    }
    AStatsEvent_writeString(event, mime.c_str());

    std::string mode;
    if (item->getString("android.media.mediacodec.mode", &mode)) {
        metrics_proto.set_mode(mode);
    }
    AStatsEvent_writeString(event, mode.c_str());

    int32_t encoder = -1;
    if (item->getInt32("android.media.mediacodec.encoder", &encoder)) {
        metrics_proto.set_encoder(encoder);
    }
    AStatsEvent_writeInt32(event, encoder);

    int32_t secure = -1;
    if (item->getInt32("android.media.mediacodec.secure", &secure)) {
        metrics_proto.set_secure(secure);
    }
    AStatsEvent_writeInt32(event, secure);

    int32_t width = -1;
    if (item->getInt32("android.media.mediacodec.width", &width)) {
        metrics_proto.set_width(width);
    }
    AStatsEvent_writeInt32(event, width);

    int32_t height = -1;
    if (item->getInt32("android.media.mediacodec.height", &height)) {
        metrics_proto.set_height(height);
    }
    AStatsEvent_writeInt32(event, height);

    int32_t rotation = -1;
    if (item->getInt32("android.media.mediacodec.rotation-degrees", &rotation)) {
        metrics_proto.set_rotation(rotation);
    }
    AStatsEvent_writeInt32(event, rotation);

    int32_t crypto = -1;
    if (item->getInt32("android.media.mediacodec.crypto", &crypto)) {
        metrics_proto.set_crypto(crypto);
    }
    AStatsEvent_writeInt32(event, crypto);

    int32_t profile = -1;
    if (item->getInt32("android.media.mediacodec.profile", &profile)) {
        metrics_proto.set_profile(profile);
    }
    AStatsEvent_writeInt32(event, profile);

    int32_t level = -1;
    if (item->getInt32("android.media.mediacodec.level", &level)) {
        metrics_proto.set_level(level);
    }
    AStatsEvent_writeInt32(event, level);


    int32_t max_width = -1;
    if ( item->getInt32("android.media.mediacodec.maxwidth", &max_width)) {
        metrics_proto.set_max_width(max_width);
    }
    AStatsEvent_writeInt32(event, max_width);

    int32_t max_height = -1;
    if ( item->getInt32("android.media.mediacodec.maxheight", &max_height)) {
        metrics_proto.set_max_height(max_height);
    }
    AStatsEvent_writeInt32(event, max_height);

    int32_t error_code = -1;
    if ( item->getInt32("android.media.mediacodec.errcode", &error_code)) {
        metrics_proto.set_error_code(error_code);
    }
    AStatsEvent_writeInt32(event, error_code);

    std::string error_state;
    if ( item->getString("android.media.mediacodec.errstate", &error_state)) {
        metrics_proto.set_error_state(error_state);
    }
    AStatsEvent_writeString(event, error_state.c_str());

    int64_t latency_max = -1;
    if (item->getInt64("android.media.mediacodec.latency.max", &latency_max)) {
        metrics_proto.set_latency_max(latency_max);
    }
    AStatsEvent_writeInt64(event, latency_max);

    int64_t latency_min = -1;
    if (item->getInt64("android.media.mediacodec.latency.min", &latency_min)) {
        metrics_proto.set_latency_min(latency_min);
    }
    AStatsEvent_writeInt64(event, latency_min);

    int64_t latency_avg = -1;
    if (item->getInt64("android.media.mediacodec.latency.avg", &latency_avg)) {
        metrics_proto.set_latency_avg(latency_avg);
    }
    AStatsEvent_writeInt64(event, latency_avg);

    int64_t latency_count = -1;
    if (item->getInt64("android.media.mediacodec.latency.n", &latency_count)) {
        metrics_proto.set_latency_count(latency_count);
    }
    AStatsEvent_writeInt64(event, latency_count);

    int64_t latency_unknown = -1;
    if (item->getInt64("android.media.mediacodec.latency.unknown", &latency_unknown)) {
        metrics_proto.set_latency_unknown(latency_unknown);
    }
    AStatsEvent_writeInt64(event, latency_unknown);

    int32_t queue_secure_input_buffer_error = -1;
    if (item->getInt32("android.media.mediacodec.queueSecureInputBufferError",
            &queue_secure_input_buffer_error)) {
        metrics_proto.set_queue_secure_input_buffer_error(queue_secure_input_buffer_error);
    }
    AStatsEvent_writeInt32(event, queue_secure_input_buffer_error);

    int32_t queue_input_buffer_error = -1;
    if (item->getInt32("android.media.mediacodec.queueInputBufferError",
            &queue_input_buffer_error)) {
        metrics_proto.set_queue_input_buffer_error(queue_input_buffer_error);
    }
    AStatsEvent_writeInt32(event, queue_input_buffer_error);

    std::string bitrate_mode;
    if (item->getString("android.media.mediacodec.bitrate_mode", &bitrate_mode)) {
        metrics_proto.set_bitrate_mode(bitrate_mode);
    }
    AStatsEvent_writeString(event, bitrate_mode.c_str());

    int32_t bitrate = -1;
    if (item->getInt32("android.media.mediacodec.bitrate", &bitrate)) {
        metrics_proto.set_bitrate(bitrate);
    }
    AStatsEvent_writeInt32(event, bitrate);

    int64_t lifetime_millis = -1;
    if (item->getInt64("android.media.mediacodec.lifetimeMs", &lifetime_millis)) {
        lifetime_millis = mediametrics::bucket_time_minutes(lifetime_millis);
        metrics_proto.set_lifetime_millis(lifetime_millis);
    }
    AStatsEvent_writeInt64(event, lifetime_millis);

    int64_t playback_duration_sec = -1;
    item->getInt64("android.media.mediacodec.playback-duration-sec", &playback_duration_sec);
    // DO NOT record  playback-duration in the metrics_proto - it should only
    // exist in the flattened atom
    AStatsEvent_writeInt64(event, playback_duration_sec);

    std::string sessionId;
    if (item->getString("android.media.mediacodec.log-session-id", &sessionId)) {
        sessionId = mediametrics::ValidateId::get()->validateId(sessionId);
        metrics_proto.set_log_session_id(sessionId);
    }
    AStatsEvent_writeString(event, codec.c_str());

    int32_t channelCount = -1;
    if (item->getInt32("android.media.mediacodec.channelCount", &channelCount)) {
        metrics_proto.set_channel_count(channelCount);
    }
    AStatsEvent_writeInt32(event, channelCount);

    int32_t sampleRate = -1;
    if (item->getInt32("android.media.mediacodec.sampleRate", &sampleRate)) {
        metrics_proto.set_sample_rate(sampleRate);
    }
    AStatsEvent_writeInt32(event, sampleRate);

    // TODO PWG may want these fuzzed up a bit to obscure some precision
    int64_t bytes = -1;
    if (item->getInt64("android.media.mediacodec.vencode.bytes", &bytes)) {
        metrics_proto.set_video_encode_bytes(bytes);
    }
    AStatsEvent_writeInt64(event, bytes);

    int64_t frames = -1;
    if (item->getInt64("android.media.mediacodec.vencode.frames", &frames)) {
        metrics_proto.set_video_encode_frames(frames);
    }
    AStatsEvent_writeInt64(event, frames);

    int64_t inputBytes = -1;
    if (item->getInt64("android.media.mediacodec.video.input.bytes", &inputBytes)) {
        metrics_proto.set_video_input_bytes(inputBytes);
    }
    AStatsEvent_writeInt64(event, inputBytes);

    int64_t inputFrames = -1;
    if (item->getInt64("android.media.mediacodec.video.input.frames", &inputFrames)) {
        metrics_proto.set_video_input_frames(inputFrames);
    }
    AStatsEvent_writeInt64(event, inputFrames);

    int64_t durationUs = -1;
    if (item->getInt64("android.media.mediacodec.vencode.durationUs", &durationUs)) {
        metrics_proto.set_video_encode_duration_us(durationUs);
    }
    AStatsEvent_writeInt64(event, durationUs);

    int32_t colorFormat = -1;
    if (item->getInt32("android.media.mediacodec.color-format", &colorFormat)) {
        metrics_proto.set_color_format(colorFormat);
    }
    AStatsEvent_writeInt32(event, colorFormat);

    double frameRate = -1.0;
    if (item->getDouble("android.media.mediacodec.frame-rate", &frameRate)) {
        metrics_proto.set_frame_rate(frameRate);
    }
    AStatsEvent_writeFloat(event, (float) frameRate);

    double captureRate = -1.0;
    if (item->getDouble("android.media.mediacodec.capture-rate", &captureRate)) {
        metrics_proto.set_capture_rate(captureRate);
    }
    AStatsEvent_writeFloat(event, (float) captureRate);

    double operatingRate = -1.0;
    if (item->getDouble("android.media.mediacodec.operating-rate", &operatingRate)) {
        metrics_proto.set_operating_rate(operatingRate);
    }
    AStatsEvent_writeFloat(event, (float) operatingRate);

    int32_t priority = -1;
    if (item->getInt32("android.media.mediacodec.priority", &priority)) {
        metrics_proto.set_priority(priority);
    }
    AStatsEvent_writeInt32(event, priority);

    int32_t qpIMin = -1;
    if (item->getInt32("android.media.mediacodec.video-qp-i-min", &qpIMin)) {
        metrics_proto.set_video_qp_i_min(qpIMin);
    }
    AStatsEvent_writeInt32(event, qpIMin);

    int32_t qpIMax = -1;
    if (item->getInt32("android.media.mediacodec.video-qp-i-max", &qpIMax)) {
        metrics_proto.set_video_qp_i_max(qpIMax);
    }
    AStatsEvent_writeInt32(event, qpIMax);

    int32_t qpPMin = -1;
    if (item->getInt32("android.media.mediacodec.video-qp-p-min", &qpPMin)) {
        metrics_proto.set_video_qp_p_min(qpPMin);
    }
    AStatsEvent_writeInt32(event, qpPMin);

    int32_t qpPMax = -1;
    if (item->getInt32("android.media.mediacodec.video-qp-p-max", &qpPMax)) {
        metrics_proto.set_video_qp_p_max(qpPMax);
    }
    AStatsEvent_writeInt32(event, qpPMax);

    int32_t qpBMin = -1;
    if (item->getInt32("android.media.mediacodec.video-qp-b-min", &qpBMin)) {
        metrics_proto.set_video_qp_b_min(qpBMin);
    }
    AStatsEvent_writeInt32(event, qpBMin);

    int32_t qpBMax = -1;
    if (item->getInt32("android.media.mediacodec.video-qp-b-max", &qpBMax)) {
        metrics_proto.set_video_qp_b_max(qpBMax);
    }
    AStatsEvent_writeInt32(event, qpBMax);

    int32_t originalBitrate = -1;
    if (item->getInt32("android.media.mediacodec.original.bitrate", &originalBitrate)) {
        metrics_proto.set_original_bitrate(originalBitrate);
    }
    AStatsEvent_writeInt32(event, originalBitrate);

    int32_t shapingEnhanced = -1;
    if ( item->getInt32("android.media.mediacodec.shaped", &shapingEnhanced)) {
        metrics_proto.set_shaping_enhanced(shapingEnhanced);
    }
    AStatsEvent_writeInt32(event, shapingEnhanced);

    int32_t qpIMinOri = -1;
    if ( item->getInt32("android.media.mediacodec.original-video-qp-i-min", &qpIMinOri)) {
        metrics_proto.set_original_video_qp_i_min(qpIMinOri);
    }
    AStatsEvent_writeInt32(event, qpIMinOri);

    int32_t qpIMaxOri = -1;
    if ( item->getInt32("android.media.mediacodec.original-video-qp-i-max", &qpIMaxOri)) {
        metrics_proto.set_original_video_qp_i_max(qpIMaxOri);
    }
    AStatsEvent_writeInt32(event, qpIMaxOri);

    int32_t qpPMinOri = -1;
    if ( item->getInt32("android.media.mediacodec.original-video-qp-p-min", &qpPMinOri)) {
        metrics_proto.set_original_video_qp_p_min(qpPMinOri);
    }
    AStatsEvent_writeInt32(event, qpPMinOri);

    int32_t qpPMaxOri = -1;
    if ( item->getInt32("android.media.mediacodec.original-video-qp-p-max", &qpPMaxOri)) {
        metrics_proto.set_original_video_qp_p_max(qpPMaxOri);
    }
    AStatsEvent_writeInt32(event, qpPMaxOri);

    int32_t qpBMinOri = -1;
    if ( item->getInt32("android.media.mediacodec.original-video-qp-b-min", &qpBMinOri)) {
        metrics_proto.set_original_video_qp_b_min(qpBMinOri);
    }
    AStatsEvent_writeInt32(event, qpBMinOri);

    int32_t qpBMaxOri = -1;
    if ( item->getInt32("android.media.mediacodec.original-video-qp-b-max", &qpBMaxOri)) {
        metrics_proto.set_original_video_qp_b_max(qpBMaxOri);
    }
    AStatsEvent_writeInt32(event, qpBMaxOri);

    // int32_t configColorStandard = -1;
    // if (item->getInt32("android.media.mediacodec.config-color-standard", &configColorStandard)) {
    //     metrics_proto.set_config_color_standard(configColorStandard);
    // }
    // AStatsEvent_writeInt32(event, configColorStandard);

    // int32_t configColorRange = -1;
    // if (item->getInt32("android.media.mediacodec.config-color-range", &configColorRange)) {
    //     metrics_proto.set_config_color_range(configColorRange);
    // }
    // AStatsEvent_writeInt32(event, configColorRange);

    // int32_t configColorTransfer = -1;
    // if (item->getInt32("android.media.mediacodec.config-color-transfer", &configColorTransfer)) {
    //     metrics_proto.set_config_color_transfer(configColorTransfer);
    // }
    // AStatsEvent_writeInt32(event, configColorTransfer);

    // int32_t parsedColorStandard = -1;
    // if (item->getInt32("android.media.mediacodec.parsed-color-standard", &parsedColorStandard)) {
    //     metrics_proto.set_parsed_color_standard(parsedColorStandard);
    // }
    // AStatsEvent_writeInt32(event, parsedColorStandard);

    // int32_t parsedColorRange = -1;
    // if (item->getInt32("android.media.mediacodec.parsed-color-range", &parsedColorRange)) {
    //     metrics_proto.set_parsed_color_range(parsedColorRange);
    // }
    // AStatsEvent_writeInt32(event, parsedColorRange);

    // int32_t parsedColorTransfer = -1;
    // if (item->getInt32("android.media.mediacodec.parsed-color-transfer", &parsedColorTransfer)) {
    //     metrics_proto.set_parsed_color_transfer(parsedColorTransfer);
    // }
    // AStatsEvent_writeInt32(event, parsedColorTransfer);

    // int32_t hdrMetadataFlags = -1;
    // if (item->getInt32("android.media.mediacodec.hdr-metadata-flags", &hdrMetadataFlags)) {
    //     metrics_proto.set_hdr_metadata_flags(hdrMetadataFlags);
    // }
    // AStatsEvent_writeInt32(event, hdrMetadataFlags);

    int err = AStatsEvent_write(event);
    if (err < 0) {
      ALOGE("Failed to write codec metrics to statsd (%d)", err);
    }
    AStatsEvent_release(event);

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
            << " original_bitrate:" << originalBitrate
            << " lifetime_millis:" << lifetime_millis
            << " playback_duration_seconds:" << playback_duration_sec
            << " log_session_id:" << sessionId
            << " channel_count:" << channelCount
            << " sample_rate:" << sampleRate
            << " encode_bytes:" << bytes
            << " encode_frames:" << frames
            << " encode_duration_us:" << durationUs
            << " color_format:" << colorFormat
            << " frame_rate:" << frameRate
            << " capture_rate:" << captureRate
            << " operating_rate:" << operatingRate
            << " priority:" << priority
            << " shaping_enhanced:" << shapingEnhanced

            << " qp_i_min:" << qpIMin
            << " qp_i_max:" << qpIMax
            << " qp_p_min:" << qpPMin
            << " qp_p_max:" << qpPMax
            << " qp_b_min:" << qpBMin
            << " qp_b_max:" << qpBMax
            << " original_qp_i_min:" << qpIMinOri
            << " original_qp_i_max:" << qpIMaxOri
            << " original_qp_p_min:" << qpPMinOri
            << " original_qp_p_max:" << qpPMaxOri
            << " original_qp_b_min:" << qpBMinOri
            << " original_qp_b_max:" << qpBMaxOri
            << " }";
    statsdLog->log(android::util::MEDIAMETRICS_CODEC_REPORTED, log.str());


    return true;
}

} // namespace android
