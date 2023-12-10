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
#include <string>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <stats_media_metrics.h>
#include <stats_event.h>

#include <frameworks/proto_logging/stats/message/mediametrics_message.pb.h>
#include <mediametricsservice/cleaner.h>
#include <mediametricsservice/iface_statsd.h>
#include <mediametricsservice/MediaMetricsService.h>
#include <mediametricsservice/StringUtils.h>
#include <mediametricsservice/ValidateId.h>

namespace android {

using stats::media_metrics::stats_write;
using stats::media_metrics::MEDIA_CODEC_RENDERED;
using stats::media_metrics::MEDIA_CODEC_RENDERED__CODEC__CODEC_UNKNOWN;
using stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_INVALID;
using stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_ZERO;
using stats::media_metrics::MEDIA_CODEC_RENDERED__CONTENT_FRAMERATE__FRAMERATE_UNKNOWN;
using stats::media_metrics::MEDIA_CODEC_RENDERED__CONTENT_FRAMERATE__FRAMERATE_UNDETERMINED;
using stats::media_metrics::MEDIA_CODEC_RENDERED__CONTENT_FRAMERATE__FRAMERATE_24_3_2_PULLDOWN;
using stats::media_metrics::MEDIA_CODEC_RENDERED__HDR_FORMAT__HDR_FORMAT_NONE;
using stats::media_metrics::MEDIA_CODEC_RENDERED__HDR_FORMAT__HDR_FORMAT_HLG;
using stats::media_metrics::MEDIA_CODEC_RENDERED__HDR_FORMAT__HDR_FORMAT_HDR10;
using stats::media_metrics::MEDIA_CODEC_RENDERED__HDR_FORMAT__HDR_FORMAT_HDR10_PLUS;
using stats::media_metrics::MEDIA_CODEC_RENDERED__HDR_FORMAT__HDR_FORMAT_DOLBY_VISION;

static const int BITRATE_UNKNOWN =
        stats::media_metrics::MEDIA_CODEC_RENDERED__BITRATE__BITRATE_UNKNOWN;

static const std::pair<char const *, int> CODEC_LOOKUP[] = {
    { "avc", stats::media_metrics::MEDIA_CODEC_RENDERED__CODEC__CODEC_AVC },
    { "h264", stats::media_metrics::MEDIA_CODEC_RENDERED__CODEC__CODEC_AVC },
    { "hevc", stats::media_metrics::MEDIA_CODEC_RENDERED__CODEC__CODEC_HEVC },
    { "h265", stats::media_metrics::MEDIA_CODEC_RENDERED__CODEC__CODEC_HEVC },
    { "vp8", stats::media_metrics::MEDIA_CODEC_RENDERED__CODEC__CODEC_VP8 },
    { "vp9", stats::media_metrics::MEDIA_CODEC_RENDERED__CODEC__CODEC_VP9 },
    { "av1", stats::media_metrics::MEDIA_CODEC_RENDERED__CODEC__CODEC_AV1 },
    { "av01", stats::media_metrics::MEDIA_CODEC_RENDERED__CODEC__CODEC_AV1 },
    { "dolby-vision", stats::media_metrics::MEDIA_CODEC_RENDERED__CODEC__CODEC_HEVC },
};

static const int32_t RESOLUTION_LOOKUP[] = {
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_MAX_SIZE,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_32K,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_16K,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_8K_UHD,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_8K_UHD_ALMOST,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_4K_UHD_ALMOST,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_1440X2560,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_1080X2400,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_1080X2340,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_1080P_FHD,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_1080P_FHD_ALMOST,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_720P_HD,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_720P_HD_ALMOST,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_576X1024,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_540X960,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_480X854,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_480X640,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_360X640,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_352X640,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_VERY_LOW,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_SMALLEST,
    stats::media_metrics::MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_ZERO,
};

static const int32_t FRAMERATE_LOOKUP[] = {
    stats::media_metrics::MEDIA_CODEC_RENDERED__CONTENT_FRAMERATE__FRAMERATE_24,
    stats::media_metrics::MEDIA_CODEC_RENDERED__CONTENT_FRAMERATE__FRAMERATE_25,
    stats::media_metrics::MEDIA_CODEC_RENDERED__CONTENT_FRAMERATE__FRAMERATE_30,
    stats::media_metrics::MEDIA_CODEC_RENDERED__CONTENT_FRAMERATE__FRAMERATE_50,
    stats::media_metrics::MEDIA_CODEC_RENDERED__CONTENT_FRAMERATE__FRAMERATE_60,
    stats::media_metrics::MEDIA_CODEC_RENDERED__CONTENT_FRAMERATE__FRAMERATE_120,
};

static int32_t getMetricsCodecEnum(const std::string &mime, const std::string &componentName) {
    for (const auto & codecStrAndEnum : CODEC_LOOKUP) {
        if (strcasestr(mime.c_str(), codecStrAndEnum.first) != nullptr ||
            strcasestr(componentName.c_str(), codecStrAndEnum.first) != nullptr) {
            return codecStrAndEnum.second;
        }
    }
    return MEDIA_CODEC_RENDERED__CODEC__CODEC_UNKNOWN;
}

static int32_t getMetricsResolutionEnum(int32_t width, int32_t height) {
    if (width == 0 || height == 0) {
        return MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_ZERO;
    }
    int64_t pixels = int64_t(width) * height / 1000;
    if (width < 0 || height < 0 || pixels > RESOLUTION_LOOKUP[0]) {
        return MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_INVALID;
    }
    for (int32_t resolutionEnum : RESOLUTION_LOOKUP) {
        if (pixels > resolutionEnum) {
            return resolutionEnum;
        }
    }
    return MEDIA_CODEC_RENDERED__RESOLUTION__RESOLUTION_ZERO;
}

static int32_t getMetricsFramerateEnum(float inFramerate) {
    if (inFramerate == -1.0f) {
        return MEDIA_CODEC_RENDERED__CONTENT_FRAMERATE__FRAMERATE_UNDETERMINED;
    }
    if (inFramerate == -2.0f) {
        return MEDIA_CODEC_RENDERED__CONTENT_FRAMERATE__FRAMERATE_24_3_2_PULLDOWN;
    }
    int framerate = int(inFramerate * 100); // Table is in hundredths of frames per second
    static const int framerateTolerance = 40; // Tolerance is 0.4 frames per second - table is 100s
    for (int32_t framerateEnum : FRAMERATE_LOOKUP) {
        if (abs(framerate - framerateEnum) < framerateTolerance) {
            return framerateEnum;
        }
    }
    return MEDIA_CODEC_RENDERED__CONTENT_FRAMERATE__FRAMERATE_UNKNOWN;
}

static int32_t getMetricsHdrFormatEnum(std::string &mime, std::string &componentName,
                                       int32_t configColorTransfer, int32_t parsedColorTransfer,
                                       int32_t hdr10StaticInfo, int32_t hdr10PlusInfo) {
    if (hdr10PlusInfo) {
        return MEDIA_CODEC_RENDERED__HDR_FORMAT__HDR_FORMAT_HDR10_PLUS;
    }
    if (hdr10StaticInfo) {
        return MEDIA_CODEC_RENDERED__HDR_FORMAT__HDR_FORMAT_HDR10;
    }
    // 7 = COLOR_TRANSFER_HLG in MediaCodecConstants.h
    if (configColorTransfer == 7 || parsedColorTransfer == 7) {
        return MEDIA_CODEC_RENDERED__HDR_FORMAT__HDR_FORMAT_HLG;
    }
    if (strcasestr(mime.c_str(), "dolby-vision") != nullptr ||
        strcasestr(componentName.c_str(), "dvhe") != nullptr ||
        strcasestr(componentName.c_str(), "dvav") != nullptr ||
        strcasestr(componentName.c_str(), "dav1") != nullptr) {
        return MEDIA_CODEC_RENDERED__HDR_FORMAT__HDR_FORMAT_DOLBY_VISION;
    }
    return MEDIA_CODEC_RENDERED__HDR_FORMAT__HDR_FORMAT_NONE;
}

static void parseVector(const std::string &str, std::vector<int32_t> *vector) {
    if (!mediametrics::stringutils::parseVector(str, vector)) {
        ALOGE("failed to parse integer vector from '%s'", str.c_str());
    }
}

bool statsd_codec(const std::shared_ptr<const mediametrics::Item>& item,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog)
{
    if (item == nullptr) return false;

    AStatsEvent* event = AStatsEvent_obtain();
    AStatsEvent_setAtomId(event, stats::media_metrics::MEDIA_CODEC_REPORTED);

    const nsecs_t timestampNanos = MediaMetricsService::roundTime(item->getTimestamp());
    AStatsEvent_writeInt64(event, timestampNanos);

    std::string packageName = item->getPkgName();
    AStatsEvent_writeString(event, packageName.c_str());

    int64_t packageVersionCode = item->getPkgVersionCode();
    AStatsEvent_writeInt64(event, packageVersionCode);

    int64_t mediaApexVersion = 0;
    AStatsEvent_writeInt64(event, mediaApexVersion);

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

    int32_t isEncoder = -1;
    if (item->getInt32("android.media.mediacodec.encoder", &isEncoder)) {
        metrics_proto.set_encoder(isEncoder);
    }
    AStatsEvent_writeInt32(event, isEncoder);

    int32_t isSecure = -1;
    if (item->getInt32("android.media.mediacodec.secure", &isSecure)) {
        metrics_proto.set_secure(isSecure);
    }
    AStatsEvent_writeInt32(event, isSecure);

    int32_t isHardware = -1;
    item->getInt32("android.media.mediacodec.hardware", &isHardware);
    // not logged to MediaCodecReported or MediametricsCodecReported

    int32_t isTunneled = -1;
    item->getInt32("android.media.mediacodec.tunneled", &isTunneled);
    // not logged to MediaCodecReported or MediametricsCodecReported

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


    int32_t maxWidth = -1;
    if ( item->getInt32("android.media.mediacodec.maxwidth", &maxWidth)) {
        metrics_proto.set_max_width(maxWidth);
    }
    AStatsEvent_writeInt32(event, maxWidth);

    int32_t maxHeight = -1;
    if ( item->getInt32("android.media.mediacodec.maxheight", &maxHeight)) {
        metrics_proto.set_max_height(maxHeight);
    }
    AStatsEvent_writeInt32(event, maxHeight);

    int32_t errorCode = -1;
    if ( item->getInt32("android.media.mediacodec.errcode", &errorCode)) {
        metrics_proto.set_error_code(errorCode);
    }
    AStatsEvent_writeInt32(event, errorCode);

    std::string errorState;
    if ( item->getString("android.media.mediacodec.errstate", &errorState)) {
        metrics_proto.set_error_state(errorState);
    }
    AStatsEvent_writeString(event, errorState.c_str());

    int64_t latencyMax = -1;
    if (item->getInt64("android.media.mediacodec.latency.max", &latencyMax)) {
        metrics_proto.set_latency_max(latencyMax);
    }
    AStatsEvent_writeInt64(event, latencyMax);

    int64_t latencyMin = -1;
    if (item->getInt64("android.media.mediacodec.latency.min", &latencyMin)) {
        metrics_proto.set_latency_min(latencyMin);
    }
    AStatsEvent_writeInt64(event, latencyMin);

    int64_t latencyAvg = -1;
    if (item->getInt64("android.media.mediacodec.latency.avg", &latencyAvg)) {
        metrics_proto.set_latency_avg(latencyAvg);
    }
    AStatsEvent_writeInt64(event, latencyAvg);

    int64_t latencyCount = -1;
    if (item->getInt64("android.media.mediacodec.latency.n", &latencyCount)) {
        metrics_proto.set_latency_count(latencyCount);
    }
    AStatsEvent_writeInt64(event, latencyCount);

    int64_t latencyUnknown = -1;
    if (item->getInt64("android.media.mediacodec.latency.unknown", &latencyUnknown)) {
        metrics_proto.set_latency_unknown(latencyUnknown);
    }
    AStatsEvent_writeInt64(event, latencyUnknown);

    int32_t queueSecureInputBufferError = -1;
    if (item->getInt32("android.media.mediacodec.queueSecureInputBufferError",
            &queueSecureInputBufferError)) {
        metrics_proto.set_queue_secure_input_buffer_error(queueSecureInputBufferError);
    }
    AStatsEvent_writeInt32(event, queueSecureInputBufferError);

    int32_t queueInputBufferError = -1;
    if (item->getInt32("android.media.mediacodec.queueInputBufferError", &queueInputBufferError)) {
        metrics_proto.set_queue_input_buffer_error(queueInputBufferError);
    }
    AStatsEvent_writeInt32(event, queueInputBufferError);

    std::string bitrateMode;
    if (item->getString("android.media.mediacodec.bitrate_mode", &bitrateMode)) {
        metrics_proto.set_bitrate_mode(bitrateMode);
    }
    AStatsEvent_writeString(event, bitrateMode.c_str());

    int32_t bitrate = -1;
    if (item->getInt32("android.media.mediacodec.bitrate", &bitrate)) {
        metrics_proto.set_bitrate(bitrate);
    }
    AStatsEvent_writeInt32(event, bitrate);

    int64_t lifetimeMillis = -1;
    if (item->getInt64("android.media.mediacodec.lifetimeMs", &lifetimeMillis)) {
        lifetimeMillis = mediametrics::bucket_time_minutes(lifetimeMillis);
        metrics_proto.set_lifetime_millis(lifetimeMillis);
    }
    AStatsEvent_writeInt64(event, lifetimeMillis);

    int64_t playbackDurationSec = -1;
    item->getInt64("android.media.mediacodec.playback-duration-sec", &playbackDurationSec);
    // DO NOT record  playback-duration in the metrics_proto - it should only
    // exist in the flattened atom
    AStatsEvent_writeInt64(event, playbackDurationSec);

    std::string sessionId;
    if (item->getString("android.media.mediacodec.log-session-id", &sessionId)) {
        sessionId = mediametrics::ValidateId::get()->validateId(sessionId);
        metrics_proto.set_log_session_id(sessionId);
    }
    AStatsEvent_writeString(event, sessionId.c_str());

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

    int32_t configColorStandard = -1;
    if (item->getInt32("android.media.mediacodec.config-color-standard", &configColorStandard)) {
        metrics_proto.set_config_color_standard(configColorStandard);
    }
    AStatsEvent_writeInt32(event, configColorStandard);

    int32_t configColorRange = -1;
    if (item->getInt32("android.media.mediacodec.config-color-range", &configColorRange)) {
        metrics_proto.set_config_color_range(configColorRange);
    }
    AStatsEvent_writeInt32(event, configColorRange);

    int32_t configColorTransfer = -1;
    if (item->getInt32("android.media.mediacodec.config-color-transfer", &configColorTransfer)) {
        metrics_proto.set_config_color_transfer(configColorTransfer);
    }
    AStatsEvent_writeInt32(event, configColorTransfer);

    int32_t parsedColorStandard = -1;
    if (item->getInt32("android.media.mediacodec.parsed-color-standard", &parsedColorStandard)) {
        metrics_proto.set_parsed_color_standard(parsedColorStandard);
    }
    AStatsEvent_writeInt32(event, parsedColorStandard);

    int32_t parsedColorRange = -1;
    if (item->getInt32("android.media.mediacodec.parsed-color-range", &parsedColorRange)) {
        metrics_proto.set_parsed_color_range(parsedColorRange);
    }
    AStatsEvent_writeInt32(event, parsedColorRange);

    int32_t parsedColorTransfer = -1;
    if (item->getInt32("android.media.mediacodec.parsed-color-transfer", &parsedColorTransfer)) {
        metrics_proto.set_parsed_color_transfer(parsedColorTransfer);
    }
    AStatsEvent_writeInt32(event, parsedColorTransfer);

    int32_t hdrStaticInfo = -1;
    if (item->getInt32("android.media.mediacodec.hdr-static-info", &hdrStaticInfo)) {
        metrics_proto.set_hdr_static_info(hdrStaticInfo);
    }
    AStatsEvent_writeInt32(event, hdrStaticInfo);

    int32_t hdr10PlusInfo = -1;
    if (item->getInt32("android.media.mediacodec.hdr10-plus-info", &hdr10PlusInfo)) {
        metrics_proto.set_hdr10_plus_info(hdr10PlusInfo);
    }
    AStatsEvent_writeInt32(event, hdr10PlusInfo);

    int32_t hdrFormat = -1;
    if (item->getInt32("android.media.mediacodec.hdr-format", &hdrFormat)) {
        metrics_proto.set_hdr_format(hdrFormat);
    }
    AStatsEvent_writeInt32(event, hdrFormat);

    int64_t codecId = 0;
    if (item->getInt64("android.media.mediacodec.id", &codecId)) {
        metrics_proto.set_codec_id(codecId);
    }
    AStatsEvent_writeInt64(event, codecId);

    int32_t arrayMode = -1;
    if (item->getInt32("android.media.mediacodec.array-mode", &arrayMode)) {
        metrics_proto.set_array_mode(arrayMode);
    }
    AStatsEvent_writeInt32(event, arrayMode);

    int32_t operationMode = -1;
    if (item->getInt32("android.media.mediacodec.operation-mode", &operationMode)) {
        metrics_proto.set_operation_mode(operationMode);
    }
    AStatsEvent_writeInt32(event, operationMode);

    int32_t outputSurface = -1;
    if (item->getInt32("android.media.mediacodec.output-surface", &outputSurface)) {
        metrics_proto.set_output_surface(outputSurface);
    }
    AStatsEvent_writeInt32(event, outputSurface);

    int32_t appMaxInputSize = -1;
    if (item->getInt32("android.media.mediacodec.app-max-input-size", &appMaxInputSize)) {
        metrics_proto.set_app_max_input_size(appMaxInputSize);
    }
    AStatsEvent_writeInt32(event, appMaxInputSize);

    int32_t usedMaxInputSize = -1;
    if (item->getInt32("android.media.mediacodec.used-max-input-size", &usedMaxInputSize)) {
        metrics_proto.set_used_max_input_size(usedMaxInputSize);
    }
    AStatsEvent_writeInt32(event, usedMaxInputSize);

    int32_t codecMaxInputSize = -1;
    if (item->getInt32("android.media.mediacodec.codec-max-input-size", &codecMaxInputSize)) {
        metrics_proto.set_codec_max_input_size(codecMaxInputSize);
    }
    AStatsEvent_writeInt32(event, codecMaxInputSize);

    int32_t flushCount = -1;
    if (item->getInt32("android.media.mediacodec.flush-count", &flushCount)) {
        metrics_proto.set_flush_count(flushCount);
    }
    AStatsEvent_writeInt32(event, flushCount);

    int32_t setSurfaceCount = -1;
    if (item->getInt32("android.media.mediacodec.set-surface-count", &setSurfaceCount)) {
        metrics_proto.set_set_surface_count(setSurfaceCount);
    }
    AStatsEvent_writeInt32(event, setSurfaceCount);

    int32_t resolutionChangeCount = -1;
    if (item->getInt32("android.media.mediacodec.resolution-change-count",
            &resolutionChangeCount)) {
        metrics_proto.set_resolution_change_count(resolutionChangeCount);
    }
    AStatsEvent_writeInt32(event, resolutionChangeCount);

    int32_t componentColorFormat = -1;
    if (item->getInt32("android.media.mediacodec.component-color-format", &componentColorFormat)) {
        metrics_proto.set_component_color_format(componentColorFormat);
    }
    AStatsEvent_writeInt32(event, componentColorFormat);

    uid_t app_uid = item->getUid();
    metrics_proto.set_caller_uid(app_uid);
    AStatsEvent_writeInt32(event, app_uid);

    int64_t pixelFormat = -1;
    if (item->getInt64("android.media.mediacodec.pixel-format", &pixelFormat)) {
        metrics_proto.set_pixel_format(pixelFormat);
    }
    AStatsEvent_writeInt64(event, pixelFormat);

    int64_t firstRenderTimeUs = -1;
    item->getInt64("android.media.mediacodec.first-render-time-us", &firstRenderTimeUs);
    int64_t framesReleased = -1;
    item->getInt64("android.media.mediacodec.frames-released", &framesReleased);
    int64_t framesRendered = -1;
    item->getInt64("android.media.mediacodec.frames-rendered", &framesRendered);
    int64_t framesDropped = -1;
    item->getInt64("android.media.mediacodec.frames-dropped", &framesDropped);
    int64_t framesSkipped = -1;
    item->getInt64("android.media.mediacodec.frames-skipped", &framesSkipped);
    double framerateContent = -1;
    item->getDouble("android.media.mediacodec.framerate-content", &framerateContent);
    double framerateActual = -1;
    item->getDouble("android.media.mediacodec.framerate-actual", &framerateActual);
    int64_t freezeScore = -1;
    item->getInt64("android.media.mediacodec.freeze-score", &freezeScore);
    double freezeRate = -1;
    item->getDouble("android.media.mediacodec.freeze-rate", &freezeRate);
    std::string freezeScoreHistogramStr;
    item->getString("android.media.mediacodec.freeze-score-histogram", &freezeScoreHistogramStr);
    std::string freezeScoreHistogramBucketsStr;
    item->getString("android.media.mediacodec.freeze-score-histogram-buckets",
                    &freezeScoreHistogramBucketsStr);
    std::string freezeDurationMsHistogramStr;
    item->getString("android.media.mediacodec.freeze-duration-ms-histogram",
                    &freezeDurationMsHistogramStr);
    std::string freezeDurationMsHistogramBucketsStr;
    item->getString("android.media.mediacodec.freeze-duration-ms-histogram-buckets",
                    &freezeDurationMsHistogramBucketsStr);
    std::string freezeDistanceMsHistogramStr;
    item->getString("android.media.mediacodec.freeze-distance-ms-histogram",
                    &freezeDistanceMsHistogramStr);
    std::string freezeDistanceMsHistogramBucketsStr;
    item->getString("android.media.mediacodec.freeze-distance-ms-histogram-buckets",
                    &freezeDistanceMsHistogramBucketsStr);
    int64_t judderScore = -1;
    item->getInt64("android.media.mediacodec.judder-score", &judderScore);
    double judderRate = -1;
    item->getDouble("android.media.mediacodec.judder-rate", &judderRate);
    std::string judderScoreHistogramStr;
    item->getString("android.media.mediacodec.judder-score-histogram", &judderScoreHistogramStr);
    std::string judderScoreHistogramBucketsStr;
    item->getString("android.media.mediacodec.judder-score-histogram-buckets",
                    &judderScoreHistogramBucketsStr);

    int err = AStatsEvent_write(event);
    if (err < 0) {
      ALOGE("Failed to write codec metrics to statsd (%d)", err);
    }
    AStatsEvent_release(event);

    if (framesRendered > 0) {
        int32_t statsUid = item->getUid();
        int64_t statsCodecId = codecId;
        char const *statsLogSessionId = sessionId.c_str();
        int32_t statsIsHardware = isHardware;
        int32_t statsIsSecure = isSecure;
        int32_t statsIsTunneled = isTunneled;
        int32_t statsCodec = getMetricsCodecEnum(mime, codec);
        int32_t statsResolution = getMetricsResolutionEnum(width, height);
        int32_t statsBitrate = BITRATE_UNKNOWN;
        int32_t statsContentFramerate = getMetricsFramerateEnum(framerateContent);
        int32_t statsActualFramerate = getMetricsFramerateEnum(framerateActual);
        int32_t statsHdrFormat = getMetricsHdrFormatEnum(mime, codec, configColorTransfer,
                                                         parsedColorTransfer, hdrStaticInfo,
                                                         hdr10PlusInfo);
        int64_t statsFirstRenderTimeUs = firstRenderTimeUs;
        int64_t statsPlaybackDurationSeconds = playbackDurationSec;
        int64_t statsFramesTotal = framesReleased + framesSkipped;
        int64_t statsFramesReleased = framesReleased;
        int64_t statsFramesRendered = framesRendered;
        int64_t statsFramesDropped = framesDropped;
        int64_t statsFramesSkipped = framesSkipped;
        float statsFrameDropRate = float(double(framesDropped) / statsFramesTotal);
        float statsFrameSkipRate = float(double(framesSkipped) / statsFramesTotal);
        float statsFrameSkipDropRate = float(double(framesSkipped + framesDropped) /
                                             statsFramesTotal);
        int64_t statsFreezeScore = freezeScore;
        float statsFreezeRate = freezeRate;
        std::vector<int32_t> statsFreezeDurationMsHistogram;
        parseVector(freezeDurationMsHistogramStr, &statsFreezeDurationMsHistogram);
        std::vector<int32_t> statsFreezeDurationMsHistogramBuckets;
        parseVector(freezeDurationMsHistogramBucketsStr, &statsFreezeDurationMsHistogramBuckets);
        std::vector<int32_t> statsFreezeDistanceMsHistogram;
        parseVector(freezeDistanceMsHistogramStr, &statsFreezeDistanceMsHistogram);
        std::vector<int32_t> statsFreezeDistanceMsHistogramBuckets;
        parseVector(freezeDistanceMsHistogramBucketsStr, &statsFreezeDistanceMsHistogramBuckets);
        int64_t statsJudderScore = judderScore;
        float statsJudderRate = judderRate;
        std::vector<int32_t> statsJudderScoreHistogram;
        parseVector(judderScoreHistogramStr, &statsJudderScoreHistogram);
        std::vector<int32_t> statsJudderScoreHistogramBuckets;
        parseVector(judderScoreHistogramBucketsStr, &statsJudderScoreHistogramBuckets);
        int result = stats_write(
            MEDIA_CODEC_RENDERED,
            statsUid,
            statsCodecId,
            statsLogSessionId,
            statsIsHardware,
            statsIsSecure,
            statsIsTunneled,
            statsCodec,
            statsResolution,
            statsBitrate,
            statsContentFramerate,
            statsActualFramerate,
            statsHdrFormat,
            statsFirstRenderTimeUs,
            statsPlaybackDurationSeconds,
            statsFramesTotal,
            statsFramesReleased,
            statsFramesRendered,
            statsFramesDropped,
            statsFramesSkipped,
            statsFrameDropRate,
            statsFrameSkipRate,
            statsFrameSkipDropRate,
            statsFreezeScore,
            statsFreezeRate,
            statsFreezeDurationMsHistogram,
            statsFreezeDurationMsHistogramBuckets,
            statsFreezeDistanceMsHistogram,
            statsFreezeDistanceMsHistogramBuckets,
            statsJudderScore,
            statsJudderRate,
            statsJudderScoreHistogram,
            statsJudderScoreHistogramBuckets);
        ALOGE_IF(result < 0, "Failed to record MEDIA_CODEC_RENDERED atom (%d)", result);
    }

    std::string serialized;
    if (!metrics_proto.SerializeToString(&serialized)) {
        ALOGE("Failed to serialize codec metrics");
        return false;
    }
    const stats::media_metrics::BytesField bf_serialized(serialized.c_str(), serialized.size());
    const int result = stats::media_metrics::stats_write(stats::media_metrics::MEDIAMETRICS_CODEC_REPORTED,
                               timestampNanos, packageName.c_str(), packageVersionCode,
                               mediaApexVersion,
                               bf_serialized);

    std::stringstream log;
    log << "result:" << result << " {"
            << " mediametrics_codec_reported:"
            << stats::media_metrics::MEDIAMETRICS_CODEC_REPORTED
            << " timestamp_nanos:" << timestampNanos
            << " package_name:" << packageName
            << " package_version_code:" << packageVersionCode
            << " media_apex_version:" << mediaApexVersion
            << " codec:" << codec
            << " mime:" << mime
            << " mode:" << mode
            << " encoder:" << isEncoder
            << " secure:" << isSecure
            << " width:" << width
            << " height:" << height
            << " rotation:" << rotation
            << " crypto:" << crypto
            << " profile:" << profile
            << " level:" << level
            << " max_width:" << maxWidth
            << " max_height:" << maxHeight
            << " error_code:" << errorCode
            << " error_state:" << errorState
            << " latency_max:" << latencyMax
            << " latency_min:" << latencyMin
            << " latency_avg:" << latencyAvg
            << " latency_count:" << latencyCount
            << " latency_unknown:" << latencyUnknown
            << " queue_input_buffer_error:" << queueInputBufferError
            << " queue_secure_input_buffer_error:" << queueSecureInputBufferError
            << " bitrate_mode:" << bitrateMode
            << " bitrate:" << bitrate
            << " original_bitrate:" << originalBitrate
            << " lifetime_millis:" << lifetimeMillis
            << " playback_duration_seconds:" << playbackDurationSec
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
    statsdLog->log(stats::media_metrics::MEDIAMETRICS_CODEC_REPORTED, log.str());


    return true;
}

} // namespace android
