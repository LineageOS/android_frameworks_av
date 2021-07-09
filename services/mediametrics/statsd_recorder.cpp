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
#define LOG_TAG "statsd_recorder"
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

bool statsd_recorder(const std::shared_ptr<const mediametrics::Item>& item,
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
    ::android::stats::mediametrics_message::RecorderData metrics_proto;

    // flesh out the protobuf we'll hand off with our data
    //

    // string kRecorderLogSessionId = "android.media.mediarecorder.log-session-id";
    std::string log_session_id;
    if (item->getString("android.media.mediarecorder.log-session-id", &log_session_id)) {
        log_session_id = mediametrics::stringutils::sanitizeLogSessionId(log_session_id);
        metrics_proto.set_log_session_id(log_session_id);
    }
    // string kRecorderAudioMime = "android.media.mediarecorder.audio.mime";
    std::string audio_mime;
    if (item->getString("android.media.mediarecorder.audio.mime", &audio_mime)) {
        metrics_proto.set_audio_mime(audio_mime);
    }
    // string kRecorderVideoMime = "android.media.mediarecorder.video.mime";
    std::string video_mime;
    if (item->getString("android.media.mediarecorder.video.mime", &video_mime)) {
        metrics_proto.set_video_mime(video_mime);
    }
    // int32 kRecorderVideoProfile = "android.media.mediarecorder.video-encoder-profile";
    int32_t video_profile = -1;
    if (item->getInt32("android.media.mediarecorder.video-encoder-profile", &video_profile)) {
        metrics_proto.set_video_profile(video_profile);
    }
    // int32 kRecorderVideoLevel = "android.media.mediarecorder.video-encoder-level";
    int32_t video_level = -1;
    if (item->getInt32("android.media.mediarecorder.video-encoder-level", &video_level)) {
        metrics_proto.set_video_level(video_level);
    }
    // int32 kRecorderWidth = "android.media.mediarecorder.width";
    int32_t width = -1;
    if (item->getInt32("android.media.mediarecorder.width", &width)) {
        metrics_proto.set_width(width);
    }
    // int32 kRecorderHeight = "android.media.mediarecorder.height";
    int32_t height = -1;
    if (item->getInt32("android.media.mediarecorder.height", &height)) {
        metrics_proto.set_height(height);
    }
    // int32 kRecorderRotation = "android.media.mediarecorder.rotation";
    int32_t rotation = -1;                      // default to 0?
    if (item->getInt32("android.media.mediarecorder.rotation", &rotation)) {
        metrics_proto.set_rotation(rotation);
    }
    // int32 kRecorderFrameRate = "android.media.mediarecorder.frame-rate";
    int32_t framerate = -1;
    if (item->getInt32("android.media.mediarecorder.frame-rate", &framerate)) {
        metrics_proto.set_framerate(framerate);
    }

    // int32 kRecorderCaptureFps = "android.media.mediarecorder.capture-fps";
    int32_t capture_fps = -1;
    if (item->getInt32("android.media.mediarecorder.capture-fps", &capture_fps)) {
        metrics_proto.set_capture_fps(capture_fps);
    }
    // double kRecorderCaptureFpsEnable = "android.media.mediarecorder.capture-fpsenable";
    double capture_fps_enable = -1;
    if (item->getDouble("android.media.mediarecorder.capture-fpsenable", &capture_fps_enable)) {
        metrics_proto.set_capture_fps_enable(capture_fps_enable);
    }

    // int64 kRecorderDurationMs = "android.media.mediarecorder.durationMs";
    int64_t duration_millis = -1;
    if (item->getInt64("android.media.mediarecorder.durationMs", &duration_millis)) {
        metrics_proto.set_duration_millis(duration_millis);
    }
    // int64 kRecorderPaused = "android.media.mediarecorder.pausedMs";
    int64_t paused_millis = -1;
    if (item->getInt64("android.media.mediarecorder.pausedMs", &paused_millis)) {
        metrics_proto.set_paused_millis(paused_millis);
    }
    // int32 kRecorderNumPauses = "android.media.mediarecorder.NPauses";
    int32_t paused_count = -1;
    if (item->getInt32("android.media.mediarecorder.NPauses", &paused_count)) {
        metrics_proto.set_paused_count(paused_count);
    }

    // int32 kRecorderAudioBitrate = "android.media.mediarecorder.audio-bitrate";
    int32_t audio_bitrate = -1;
    if (item->getInt32("android.media.mediarecorder.audio-bitrate", &audio_bitrate)) {
        metrics_proto.set_audio_bitrate(audio_bitrate);
    }
    // int32 kRecorderAudioChannels = "android.media.mediarecorder.audio-channels";
    int32_t audio_channels = -1;
    if (item->getInt32("android.media.mediarecorder.audio-channels", &audio_channels)) {
        metrics_proto.set_audio_channels(audio_channels);
    }
    // int32 kRecorderAudioSampleRate = "android.media.mediarecorder.audio-samplerate";
    int32_t audio_samplerate = -1;
    if (item->getInt32("android.media.mediarecorder.audio-samplerate", &audio_samplerate)) {
        metrics_proto.set_audio_samplerate(audio_samplerate);
    }

    // int32 kRecorderMovieTimescale = "android.media.mediarecorder.movie-timescale";
    int32_t movie_timescale = -1;
    if (item->getInt32("android.media.mediarecorder.movie-timescale", &movie_timescale)) {
        metrics_proto.set_movie_timescale(movie_timescale);
    }
    // int32 kRecorderAudioTimescale = "android.media.mediarecorder.audio-timescale";
    int32_t audio_timescale = -1;
    if (item->getInt32("android.media.mediarecorder.audio-timescale", &audio_timescale)) {
        metrics_proto.set_audio_timescale(audio_timescale);
    }
    // int32 kRecorderVideoTimescale = "android.media.mediarecorder.video-timescale";
    int32_t video_timescale = -1;
    if (item->getInt32("android.media.mediarecorder.video-timescale", &video_timescale)) {
        metrics_proto.set_video_timescale(video_timescale);
    }

    // int32 kRecorderVideoBitrate = "android.media.mediarecorder.video-bitrate";
    int32_t video_bitrate = -1;
    if (item->getInt32("android.media.mediarecorder.video-bitrate", &video_bitrate)) {
        metrics_proto.set_video_bitrate(video_bitrate);
    }
    // int32 kRecorderVideoIframeInterval = "android.media.mediarecorder.video-iframe-interval";
    int32_t iframe_interval = -1;
    if (item->getInt32("android.media.mediarecorder.video-iframe-interval", &iframe_interval)) {
        metrics_proto.set_iframe_interval(iframe_interval);
    }

    std::string serialized;
    if (!metrics_proto.SerializeToString(&serialized)) {
        ALOGE("Failed to serialize recorder metrics");
        return false;
    }

    android::util::BytesField bf_serialized( serialized.c_str(), serialized.size());
    int result = android::util::stats_write(android::util::MEDIAMETRICS_RECORDER_REPORTED,
        timestamp_nanos, package_name.c_str(), package_version_code,
        media_apex_version,
        bf_serialized);
    std::stringstream log;
    log << "result:" << result << " {"
            << " mediametrics_recorder_reported:"
            << android::util::MEDIAMETRICS_RECORDER_REPORTED
            << " timestamp_nanos:" << timestamp_nanos
            << " package_name:" << package_name
            << " package_version_code:" << package_version_code
            << " media_apex_version:" << media_apex_version

            << " audio_mime:" << audio_mime
            << " video_mime:" << video_mime
            << " video_profile:" << video_profile
            << " video_level:" << video_level
            << " width:" << width
            << " height:" << height
            << " rotation:" << rotation
            << " framerate:" << framerate
            << " capture_fps:" << capture_fps
            << " capture_fps_enable:" << capture_fps_enable

            << " duration_millis:" << duration_millis
            << " paused_millis:" << paused_millis
            << " paused_count:" << paused_count
            << " audio_bitrate:" << audio_bitrate
            << " audio_channels:" << audio_channels
            << " audio_samplerate:" << audio_samplerate
            << " movie_timescale:" << movie_timescale
            << " audio_timescale:" << audio_timescale
            << " video_timescale:" << video_timescale
            << " video_bitrate:" << video_bitrate

            << " iframe_interval:" << iframe_interval
            << " log_session_id:" << log_session_id
            << " }";
    statsdLog->log(android::util::MEDIAMETRICS_RECORDER_REPORTED, log.str());
    return true;
}

} // namespace android
