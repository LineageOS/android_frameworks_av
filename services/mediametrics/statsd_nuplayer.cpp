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
#define LOG_TAG "statsd_nuplayer"
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

/*
 *  handles nuplayer AND nuplayer2
 *  checks for the union of what the two players generate
 */
bool statsd_nuplayer(const std::shared_ptr<const mediametrics::Item>& item,
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
    ::android::stats::mediametrics_message::NuPlayerData metrics_proto;

    // flesh out the protobuf we'll hand off with our data
    //

    // differentiate between nuplayer and nuplayer2
    std::string whichPlayer = item->getKey();
    metrics_proto.set_whichplayer(whichPlayer.c_str());

    std::string video_mime;
    if (item->getString("android.media.mediaplayer.video.mime", &video_mime)) {
        metrics_proto.set_video_mime(video_mime);
    }
    std::string video_codec;
    if (item->getString("android.media.mediaplayer.video.codec", &video_codec)) {
        metrics_proto.set_video_codec(video_codec);
    }

    int32_t width = -1;
    if (item->getInt32("android.media.mediaplayer.width", &width)) {
        metrics_proto.set_width(width);
    }
    int32_t height = -1;
    if (item->getInt32("android.media.mediaplayer.height", &height)) {
        metrics_proto.set_height(height);
    }

    int64_t frames = -1;
    if (item->getInt64("android.media.mediaplayer.frames", &frames)) {
        metrics_proto.set_frames(frames);
    }
    int64_t frames_dropped = -1;
    if (item->getInt64("android.media.mediaplayer.dropped", &frames_dropped)) {
        metrics_proto.set_frames_dropped(frames_dropped);
    }
    int64_t frames_dropped_startup = -1;
    if (item->getInt64("android.media.mediaplayer.startupdropped", &frames_dropped_startup)) {
        metrics_proto.set_frames_dropped_startup(frames_dropped_startup);
    }
    double framerate = -1.0;
    if (item->getDouble("android.media.mediaplayer.fps", &framerate)) {
        metrics_proto.set_framerate(framerate);
    }

    std::string audio_mime;
    if (item->getString("android.media.mediaplayer.audio.mime", &audio_mime)) {
        metrics_proto.set_audio_mime(audio_mime);
    }
    std::string audio_codec;
    if (item->getString("android.media.mediaplayer.audio.codec", &audio_codec)) {
        metrics_proto.set_audio_codec(audio_codec);
    }

    int64_t duration_millis = -1;
    if (item->getInt64("android.media.mediaplayer.durationMs", &duration_millis)) {
        metrics_proto.set_duration_millis(duration_millis);
    }
    int64_t playing_millis = -1;
    if (item->getInt64("android.media.mediaplayer.playingMs", &playing_millis)) {
        metrics_proto.set_playing_millis(playing_millis);
    }

    int32_t error = -1;
    if (item->getInt32("android.media.mediaplayer.err", &error)) {
        metrics_proto.set_error(error);
    }
    int32_t error_code = -1;
    if (item->getInt32("android.media.mediaplayer.errcode", &error_code)) {
        metrics_proto.set_error_code(error_code);
    }
    std::string error_state;
    if (item->getString("android.media.mediaplayer.errstate", &error_state)) {
        metrics_proto.set_error_state(error_state);
    }

    std::string data_source_type;
    if (item->getString("android.media.mediaplayer.dataSource", &data_source_type)) {
        metrics_proto.set_data_source_type(data_source_type);
    }

    int64_t rebuffering_millis = -1;
    if (item->getInt64("android.media.mediaplayer.rebufferingMs", &rebuffering_millis)) {
        metrics_proto.set_rebuffering_millis(rebuffering_millis);
    }
    int32_t rebuffers = -1;
    if (item->getInt32("android.media.mediaplayer.rebuffers", &rebuffers)) {
        metrics_proto.set_rebuffers(rebuffers);
    }
    int32_t rebuffer_at_exit = -1;
    if (item->getInt32("android.media.mediaplayer.rebufferExit", &rebuffer_at_exit)) {
        metrics_proto.set_rebuffer_at_exit(rebuffer_at_exit);
    }

    std::string serialized;
    if (!metrics_proto.SerializeToString(&serialized)) {
        ALOGE("Failed to serialize nuplayer metrics");
        return false;
    }

    const stats::media_metrics::BytesField bf_serialized( serialized.c_str(), serialized.size());
    const int result = stats::media_metrics::stats_write(
        stats::media_metrics::MEDIAMETRICS_NUPLAYER_REPORTED,
        timestamp_nanos, package_name.c_str(), package_version_code,
        media_apex_version,
        bf_serialized);

    std::stringstream log;
    log << "result:" << result << " {"
            << " mediametrics_nuplayer_reported:"
            << stats::media_metrics::MEDIAMETRICS_NUPLAYER_REPORTED
            << " timestamp_nanos:" << timestamp_nanos
            << " package_name:" << package_name
            << " package_version_code:" << package_version_code
            << " media_apex_version:" << media_apex_version

            << " whichPlayer:" << whichPlayer
            << " video_mime:" << video_mime
            << " video_codec:" << video_codec
            << " width:" << width
            << " height:" << height
            << " frames:" << frames
            << " frames_dropped:" << frames_dropped
            << " framerate:" << framerate
            << " audio_mime:" << audio_mime
            << " audio_codec:" << media_apex_version

            << " duration_millis:" << duration_millis
            << " playing_millis:" << playing_millis
            << " error:" << error
            << " error_code:" << error_code
            << " error_state:" << error_state
            << " data_source_type:" << data_source_type
            << " rebuffering_millis:" << rebuffering_millis
            << " rebuffers:" << rebuffers
            << " rebuffer_at_exit:" << rebuffer_at_exit
            << " frames_dropped_startup:" << frames_dropped_startup

            // TODO NuPlayer - add log_session_id
            // << " log_session_id:" << log_session_id
            << " }";
    statsdLog->log(stats::media_metrics::MEDIAMETRICS_NUPLAYER_REPORTED, log.str());
    return true;
}

} // namespace android
