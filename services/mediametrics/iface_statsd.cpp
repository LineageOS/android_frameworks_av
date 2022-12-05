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
#define LOG_TAG "iface_statsd"
#include <utils/Log.h>

#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <pthread.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <string>
#include <vector>
#include <string.h>
#include <pwd.h>

#include "MediaMetricsService.h"
#include "iface_statsd.h"

#include <statslog.h>

namespace android {

// set of routines that crack a mediametrics::Item
// and send it off to statsd with the appropriate hooks
//
// each mediametrics::Item type (extractor, codec, nuplayer, etc)
// has its own routine to handle this.
//

static bool enabled_statsd = true;

namespace {
template<typename Handler, typename... Args>
bool dump2StatsdInternal(const std::map<std::string, Handler>& handlers,
        const std::shared_ptr<const mediametrics::Item>& item, Args... args) {
    if (item == nullptr) return false;

    // get the key
    std::string key = item->getKey();

    if (!enabled_statsd) {
        ALOGV("statsd logging disabled for record key=%s", key.c_str());
        return false;
    }

    if (handlers.count(key)) {
        return (handlers.at(key))(item, args...);
    }
    return false;
}
} // namespace

// give me a record, I'll look at the type and upload appropriately
bool dump2Statsd(
        const std::shared_ptr<const mediametrics::Item>& item,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog) {
    static const std::map<std::string, statsd_pusher*> statsd_pushers =
    {
        { "audiopolicy", statsd_audiopolicy },
        { "audiorecord", statsd_audiorecord },
        { "audiothread", statsd_audiothread },
        { "audiotrack", statsd_audiotrack },
        { "codec", statsd_codec},
        { "drmmanager", statsd_drmmanager },
        { "extractor", statsd_extractor },
        { "mediadrm", statsd_mediadrm },
        { "mediadrm.created", statsd_mediadrm_created },
        { "mediadrm.errored", statsd_mediadrm_errored },
        { "mediadrm.session_opened", statsd_mediadrm_session_opened },
        { "mediaparser", statsd_mediaparser },
        { "nuplayer", statsd_nuplayer },
        { "nuplayer2", statsd_nuplayer },
        { "recorder", statsd_recorder },
    };
    return dump2StatsdInternal(statsd_pushers, item, statsdLog);
}

bool dump2Statsd(const std::shared_ptr<const mediametrics::Item>& item, AStatsEventList* out,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog) {
    static const std::map<std::string, statsd_puller*> statsd_pullers =
    {
        { "mediadrm", statsd_mediadrm_puller },
    };
    return dump2StatsdInternal(statsd_pullers, item, out, statsdLog);
}

} // namespace android
