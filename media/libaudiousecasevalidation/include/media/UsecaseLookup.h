/*
 * Copyright (C) 2022 The Android Open Source Project
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
#ifndef MEDIA_LIBAUDIOUSECASEVALIDATION_INCLUDE_MEDIA_USECASELOOKUP_H_
#define MEDIA_LIBAUDIOUSECASEVALIDATION_INCLUDE_MEDIA_USECASELOOKUP_H_

#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <set>

namespace android {
namespace media {

typedef int STREAMID;
typedef int PORTID;

// List of streamId and outputFlag state.
typedef std::map<STREAMID, bool> STREAMLIST;
// List of portId and streamId.
typedef std::map<PORTID, STREAMID> TRACKLIST;
typedef std::lock_guard<std::mutex> mutex_lock;

class UsecaseLookup {
 public:
    UsecaseLookup() { }
    virtual ~UsecaseLookup() { }

    // Required for testing.
    void clear() {
        m_streams.clear();
        m_tracks.clear();
    }

    /**
     * Add streamId and outputFlag to stream list.
     */
    void addStream(STREAMID streamId, bool outputFlagGame = false);

    /**
     * Remove streamId from stream list.
     */
    void removeStream(STREAMID streamId);

    /**
     * Add streamId and portId to track list.
     */
    void addTrack(STREAMID streamId, PORTID portId);

    /**
     * Remove streamId and portId from track list.
     */
    void removeTrack(STREAMID streamId, PORTID portId);

    /**
     * Check if stream list contains streamId with Game output flag.
     */
    bool isGameStream(STREAMID streamId);

 protected:
    STREAMLIST m_streams;
    TRACKLIST m_tracks;
    std::mutex m_mutex;
};

}  // namespace media
}  // namespace android

#endif  // MEDIA_LIBAUDIOUSECASEVALIDATION_INCLUDE_MEDIA_USECASELOOKUP_H_
