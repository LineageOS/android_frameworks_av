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
#define LOG_TAG "UsecaseLookup"
// #define LOG_NDEBUG 0

#include "media/UsecaseLookup.h"

#include <utils/Log.h>

namespace android {
namespace media {

/**
 * Add streamId and outputFlags to stream list.
 */
void UsecaseLookup::addStream(STREAMID streamId, bool outputFlagGame) {
    ALOGV("%s streamId: %d outputFlagGame: %d", __func__, streamId, outputFlagGame);

    mutex_lock lock(m_mutex);
    m_streams[streamId] = outputFlagGame;
}

/**
 * Remove streamId from stream list.
 */
void UsecaseLookup::removeStream(STREAMID streamId) {
    ALOGV("%s streamId: %d ", __func__, streamId);

    mutex_lock lock(m_mutex);
    m_streams.erase(streamId);

    // Shouldn't happen but it might.
    for (auto it = m_tracks.begin(); it != m_tracks.end();) {
        if (it->second == streamId) {
            it = m_tracks.erase(it);
        } else {
            it++;
        }
    }
}

/**
 * Add streamId and portId to track list.
 */
void UsecaseLookup::addTrack(STREAMID streamId, PORTID portId) {
    ALOGV("%s streamId: %d portId: %d", __func__, streamId, portId);

    mutex_lock lock(m_mutex);

    if (m_tracks.find(portId) == m_tracks.end()) {
        m_tracks[portId] = streamId;
    }
}

/**
 * Remove streamId and portId from track list.
 */
void UsecaseLookup::removeTrack(STREAMID streamId, PORTID portId) {
    ALOGV("%s streamId: %d portId: %d", __func__, streamId, portId);

    mutex_lock lock(m_mutex);
    auto it = m_tracks.find(portId);

    if (it != m_tracks.end() && it->second == streamId) {
        m_tracks.erase(portId);
    }
}

/**
 * Check if stream list contains streamId with Game outputFlag.
 */
bool UsecaseLookup::isGameStream(STREAMID streamId) {
    ALOGV("%s streamId: %d ", __func__, streamId);
    mutex_lock lock(m_mutex);
    auto it = m_streams.find(streamId);

    return (it != m_streams.end()) ? it->second : false;
}

}  // namespace media
}  // namespace android
