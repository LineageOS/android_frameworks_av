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

#include <memory>
#include <stats_event.h>

namespace android {
namespace mediametrics {
class Item;
}

using statsd_pusher = bool (const std::shared_ptr<const mediametrics::Item>& item,
         const std::shared_ptr<mediametrics::StatsdLog>& statsdLog);
// component specific dumpers
extern statsd_pusher statsd_audiopolicy;
extern statsd_pusher statsd_audiorecord;
extern statsd_pusher statsd_audiothread;
extern statsd_pusher statsd_audiotrack;
extern statsd_pusher statsd_codec;
extern statsd_pusher statsd_extractor;
extern statsd_pusher statsd_mediaparser;

extern statsd_pusher statsd_nuplayer;
extern statsd_pusher statsd_recorder;
extern statsd_pusher statsd_mediadrm;
extern statsd_pusher statsd_drmmanager;

using statsd_puller = bool (const std::shared_ptr<const mediametrics::Item>& item,
        AStatsEventList *, const std::shared_ptr<mediametrics::StatsdLog>& statsdLog);
// component specific pullers
extern statsd_puller statsd_mediadrm_puller;

bool dump2Statsd(const std::shared_ptr<const mediametrics::Item>& item,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog);
bool dump2Statsd(const std::shared_ptr<const mediametrics::Item>& item, AStatsEventList* out,
        const std::shared_ptr<mediametrics::StatsdLog>& statsdLog);
} // namespace android
