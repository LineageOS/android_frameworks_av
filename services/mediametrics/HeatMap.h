/*
 * Copyright (C) 2021 The Android Open Source Project
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

#pragma once

#include <iomanip>
#include <map>
#include <sstream>
#include "MediaMetricsConstants.h"

namespace android::mediametrics {

/**
 * HeatData accumulates statistics on the status reported for a given key.
 *
 * HeatData is a helper class used by HeatMap to represent statistics.  We expose it
 * here for testing purposes currently.
 *
 * Note: This class is not thread safe, so mutual exclusion should be obtained by the caller
 * which in this case is HeatMap.  HeatMap getData() returns a local copy of HeatData, so use
 * of that is thread-safe.
 */
class HeatData {
    /* HeatData for a key is stored in a map based on the event (e.g. "start", "pause", create)
     * and then another map based on the status (e.g. "ok", "argument", "state").
     */
    std::map<std::string /* event */,
             std::map<std::string /* status name */, size_t /* count, nonzero */>> mMap;

public:
    /**
     * Add status data.
     *
     * \param suffix  (ignored) the suffix to the key that was stripped, if any.
     * \param event             the event (e.g. create, start, pause, stop, etc.).
     * \param uid     (ignored) the uid associated with the error.
     * \param message (ignored) the status message, if any.
     * \param subCode (ignored) the status subcode, if any.
     */
    void add(const std::string& suffix, const std::string& event, const std::string& status,
            uid_t uid, const std::string& message, int32_t subCode) {
        // Perhaps there could be a more detailed print.
        (void)suffix;
        (void)uid;
        (void)message;
        (void)subCode;
        ++mMap[event][status];
    }

    /** Returns the number of event names with status. */
    size_t size() const {
        return mMap.size();
    }

    /**
     * Returns a deque with pairs indicating the count of Oks and Errors.
     * The first pair is total, the other pairs are in order of mMap.
     *
     * Example return value of {ok, error} pairs:
     *     total     key1      key2
     * { { 2, 1 }, { 1, 0 }, { 1, 1 } }
     */
    std::deque<std::pair<size_t /* oks */, size_t /* errors */>> heatCount() const {
        size_t totalOk = 0;
        size_t totalError = 0;
        std::deque<std::pair<size_t /* oks */, size_t /* errors */>> heat;
        for (const auto &eventPair : mMap) {
            size_t ok = 0;
            size_t error = 0;
            for (const auto &[name, count] : eventPair.second) {
                if (name == AMEDIAMETRICS_PROP_STATUS_VALUE_OK) {
                    ok += count;
                } else {
                    error += count;
                }
            }
            totalOk += ok;
            totalError += error;
            heat.emplace_back(ok, error);
        }
        heat.emplace_front(totalOk, totalError);
        return heat;
    }

    /** Returns the error fraction from a pair <oks, errors>, a float between 0.f to 1.f. */
    static float fraction(const std::pair<size_t, size_t>& count) {
        return (float)count.second / (count.first + count.second);
    }

    /** Returns the HeatMap information in a single line string. */
    std::string dump() const {
        const auto heat = heatCount();
        auto it = heat.begin();
        std::stringstream ss;
        ss << "{ ";
        float errorFraction = fraction(*it++);
        if (errorFraction > 0.f) {
            ss << std::fixed << std::setprecision(2) << errorFraction << " ";
        }
        for (const auto &eventPair : mMap) {
            ss << eventPair.first << ": { ";
            errorFraction = fraction(*it++);
            if (errorFraction > 0.f) {
                ss << std::fixed << std::setprecision(2) << errorFraction << " ";
            }
            for (const auto &[name, count]: eventPair.second) {
                ss << "[ " << name << " : " << count << " ] ";
            }
            ss << "} ";
        }
        ss << " }";
        return ss.str();
    }
};

/**
 * HeatMap is a thread-safe collection that counts activity of status errors per key.
 *
 * The classic heat map is a 2D picture with intensity shown by color.
 * Here we accumulate the status results from keys to see if there are consistent
 * failures in the system.
 *
 * TODO(b/210855555): Heatmap improvements.
 *   1) heat decays in intensity in time for past events, currently we don't decay.
 */

class HeatMap {
    const size_t mMaxSize;
    mutable std::mutex mLock;
    size_t mRejected GUARDED_BY(mLock) = 0;
    std::map<std::string, HeatData> mMap GUARDED_BY(mLock);

public:
    /**
     * Constructs a HeatMap.
     *
     * \param maxSize the maximum number of elements that are tracked.
     */
    explicit HeatMap(size_t maxSize) : mMaxSize(maxSize) {
    }

    /** Returns the number of keys. */
    size_t size() const {
        std::lock_guard l(mLock);
        return mMap.size();
    }

    /** Clears error history. */
    void clear() {
        std::lock_guard l(mLock);
        return mMap.clear();
    }

    /** Returns number of keys rejected due to space. */
    size_t rejected() const {
        std::lock_guard l(mLock);
        return mRejected;
    }

    /** Returns a copy of the heat data associated with key. */
    HeatData getData(const std::string& key) const {
        std::lock_guard l(mLock);
        return mMap.count(key) == 0 ? HeatData{} : mMap.at(key);
    }

    /**
     * Adds a new entry.
     * \param key               the key category (e.g. audio.track).
     * \param suffix  (ignored) the suffix to the key that was stripped, if any.
     * \param event             the event (e.g. create, start, pause, stop, etc.).
     * \param uid     (ignored) the uid associated with the error.
     * \param message (ignored) the status message, if any.
     * \param subCode (ignored) the status subcode, if any.
     */
    void add(const std::string& key, const std::string& suffix, const std::string& event,
            const std::string& status, uid_t uid, const std::string& message, int32_t subCode) {
        std::lock_guard l(mLock);

        // Hard limit on heat map entries.
        // TODO: have better GC.
        if (mMap.size() == mMaxSize && mMap.count(key) == 0) {
            ++mRejected;
            return;
        }
        mMap[key].add(suffix, event, status, uid, message, subCode);
    }

    /**
     * Returns a pair consisting of the dump string and the number of lines in the string.
     */
    std::pair<std::string, int32_t> dump(int32_t lines = INT32_MAX) const {
        std::stringstream ss;
        int32_t ll = lines;
        std::lock_guard l(mLock);
        if (ll > 0) {
            ss << "Error Heat Map (rejected: " << mRejected << "):\n";
            --ll;
        }
        // TODO: restriction is implemented alphabetically not on priority.
        for (const auto& [name, data] : mMap) {
            if (ll <= 0) break;
            ss << name << ": " << data.dump() << "\n";
            --ll;
        }
        return { ss.str(), lines - ll };
    }
};

} // namespace android::mediametrics
