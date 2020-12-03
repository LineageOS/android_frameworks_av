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
#define LOG_TAG "statsd_extractor"
#include <utils/Log.h>

#include <stdint.h>
#include <string.h>

#include <statslog.h>

#include <media/stagefright/RemoteMediaExtractor.h>
#include "MediaMetricsService.h"
#include "frameworks/proto_logging/stats/enums/stats/mediametrics/mediametrics.pb.h"
#include "iface_statsd.h"

namespace android {

bool statsd_extractor(const mediametrics::Item *item)
{
    if (item == nullptr) return false;

    // these go into the statsd wrapper
    const nsecs_t timestamp = MediaMetricsService::roundTime(item->getTimestamp());
    std::string pkgName = item->getPkgName();
    int64_t pkgVersionCode = item->getPkgVersionCode();
    int64_t mediaApexVersion = 0;


    // the rest into our own proto
    //
    ::android::stats::mediametrics::ExtractorData metrics_proto;

    // flesh out the protobuf we'll hand off with our data
    //

    // android.media.mediaextractor.fmt         string
    std::string fmt;
    if (item->getString(RemoteMediaExtractor::kExtractorFormat, &fmt)) {
        metrics_proto.set_format(std::move(fmt));
    }
    // android.media.mediaextractor.mime        string
    std::string mime;
    if (item->getString(RemoteMediaExtractor::kExtractorMime, &mime)) {
        metrics_proto.set_mime(std::move(mime));
    }
    // android.media.mediaextractor.ntrk        int32
    int32_t ntrk = -1;
    if (item->getInt32(RemoteMediaExtractor::kExtractorTracks, &ntrk)) {
        metrics_proto.set_tracks(ntrk);
    }

    // android.media.mediaextractor.entry       int32
    int32_t entry_point_int;
    if (item->getInt32(RemoteMediaExtractor::kExtractorEntryPoint,
            &entry_point_int)) {
        using stats::mediametrics::ExtractorData;
        ExtractorData::EntryPoint entry_point;
        switch (static_cast<IMediaExtractor::EntryPoint>(entry_point_int)) {
          case IMediaExtractor::EntryPoint::SDK:
              entry_point =
                  ExtractorData::EntryPoint::ExtractorData_EntryPoint_SDK;
              break;
          case IMediaExtractor::EntryPoint::NDK_WITH_JVM:
              entry_point =
                  ExtractorData::EntryPoint
                      ::ExtractorData_EntryPoint_NDK_WITH_JVM;
            break;
          case IMediaExtractor::EntryPoint::NDK_NO_JVM:
              entry_point =
                  ExtractorData::EntryPoint
                      ::ExtractorData_EntryPoint_NDK_NO_JVM;
              break;
          case IMediaExtractor::EntryPoint::OTHER:
            entry_point =
                  ExtractorData::EntryPoint
                      ::ExtractorData_EntryPoint_OTHER;
            break;
          default:
            entry_point =
                  ExtractorData::EntryPoint::ExtractorData_EntryPoint_UNSET;
        }
        metrics_proto.set_entry_point(entry_point);
    }

    std::string serialized;
    if (!metrics_proto.SerializeToString(&serialized)) {
        ALOGE("Failed to serialize extractor metrics");
        return false;
    }

    if (enabled_statsd) {
        android::util::BytesField bf_serialized( serialized.c_str(), serialized.size());
        (void)android::util::stats_write(android::util::MEDIAMETRICS_EXTRACTOR_REPORTED,
                                   timestamp, pkgName.c_str(), pkgVersionCode,
                                   mediaApexVersion,
                                   bf_serialized);

    } else {
        ALOGV("NOT sending: private data (len=%zu)", strlen(serialized.c_str()));
    }

    return true;
}

} // namespace android
