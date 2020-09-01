/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "TimeMachine.h"
#include "TransactionLog.h"

namespace android::mediametrics {

/**
 * AnalyticsState consists of a TimeMachine and TransactionLog for a set
 * of MediaMetrics Items.
 *
 * One can add new Items with the submit() method.
 *
 * The AnalyticsState may be cleared or duplicated to preserve state after crashes
 * in services are detected.
 *
 * As its members may not be moveable due to mutexes, we use this encapsulation
 * with a shared pointer in order to save it or duplicate it.
 */
class AnalyticsState {
public:
    /**
     * Returns success if AnalyticsState accepts the item.
     *
     * A trusted source can create a new key, an untrusted source
     * can only modify the key if the uid will match that authorized
     * on the existing key.
     *
     * \param item the item to be submitted.
     * \param isTrusted whether the transaction comes from a trusted source.
     *        In this case, a trusted source is verified by binder
     *        UID to be a system service by MediaMetrics service.
     *        Do not use true if you haven't really checked!
     *
     * \return NO_ERROR on success or
     *         PERMISSION_DENIED if the item cannot be put into the AnalyticsState.
     */
    status_t submit(const std::shared_ptr<const mediametrics::Item>& item, bool isTrusted) {
        return mTimeMachine.put(item, isTrusted) ?: mTransactionLog.put(item);
    }

    /**
     * Returns the TimeMachine.
     *
     * The TimeMachine object is internally locked, so access is safe and defined,
     * but multiple threaded access may change results after calling.
     */
    TimeMachine& timeMachine() { return mTimeMachine; }
    const TimeMachine& timeMachine() const { return mTimeMachine; }

    /**
     * Returns the TransactionLog.
     *
     * The TransactionLog object is internally locked, so access is safe and defined,
     * but multiple threaded access may change results after calling.
     */
    TransactionLog& transactionLog() { return mTransactionLog; }
    const TransactionLog& transactionLog() const { return mTransactionLog; }

    /**
     * Returns a pair consisting of the dump string, and the number of lines in the string.
     *
     * The number of lines in the returned pair is used as an optimization
     * for subsequent line limiting.
     *
     * The TimeMachine and the TransactionLog are dumped separately under
     * different locks, so may not be 100% consistent with the last data
     * delivered.
     *
     * \param lines the maximum number of lines in the string returned.
     * \param sinceNs the nanoseconds since Unix epoch to start dump (0 shows all)
     * \param prefix the desired key prefix to match (nullptr shows all)
     */
    std::pair<std::string, int32_t> dump(
            int32_t lines = INT32_MAX, int64_t sinceNs = 0, const char *prefix = nullptr) const {
        std::stringstream ss;
        int32_t ll = lines;

        if (ll > 0) {
            ss << "TransactionLog: gc(" << mTransactionLog.getGarbageCollectionCount() << ")\n";
            --ll;
        }
        if (ll > 0) {
            auto [s, l] = mTransactionLog.dump(ll, sinceNs, prefix);
            ss << s;
            ll -= l;
        }
        if (ll > 0) {
            ss << "TimeMachine: gc(" << mTimeMachine.getGarbageCollectionCount() << ")\n";
            --ll;
        }
        if (ll > 0) {
            auto [s, l] = mTimeMachine.dump(ll, sinceNs, prefix);
            ss << s;
            ll -= l;
        }
        return { ss.str(), lines - ll };
    }

    /**
     * Clears the AnalyticsState.
     */
    void clear() {
        mTimeMachine.clear();
        mTransactionLog.clear();
    }

private:
    // Note: TimeMachine and TransactionLog are individually locked.
    // Access to these objects under multiple threads will be weakly synchronized,
    // which is acceptable as modifications only increase the history (or with GC,
    // eliminates very old history).

    TimeMachine    mTimeMachine;
    TransactionLog mTransactionLog;
};

} // namespace android::mediametrics
