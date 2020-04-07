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

#pragma once

#include "AnalyticsActions.h"
#include "AnalyticsState.h"
#include "Wrap.h"

namespace android::mediametrics {

class AudioAnalytics
{
public:
    AudioAnalytics();
    ~AudioAnalytics();

    /**
     * Returns success if AudioAnalytics recognizes item.
     *
     * AudioAnalytics requires the item key to start with "audio.".
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
     * \return NO_ERROR on success,
     *         PERMISSION_DENIED if the item cannot be put into the AnalyticsState,
     *         BAD_VALUE if the item key does not start with "audio.".
     */
    status_t submit(const std::shared_ptr<const mediametrics::Item>& item, bool isTrusted);

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
            int32_t lines = INT32_MAX, int64_t sinceNs = 0, const char *prefix = nullptr) const;

    void clear() {
        // underlying state is locked.
        mPreviousAnalyticsState->clear();
        mAnalyticsState->clear();
    }

private:

    /**
     * Checks for any pending actions for a particular item.
     *
     * \param item to check against the current AnalyticsActions.
     */
    void checkActions(const std::shared_ptr<const mediametrics::Item>& item);

    // HELPER METHODS
    /**
     * Return the audio thread associated with an audio track name.
     * e.g. "audio.track.32" -> "audio.thread.10" if the associated
     * threadId for the audio track is 10.
     */
    std::string getThreadFromTrack(const std::string& track) const;

    // Actions is individually locked
    AnalyticsActions mActions;

    // AnalyticsState is individually locked, and we use SharedPtrWrap
    // to allow safe access even if the shared pointer changes underneath.

    SharedPtrWrap<AnalyticsState> mAnalyticsState;
    SharedPtrWrap<AnalyticsState> mPreviousAnalyticsState;
};

} // namespace android::mediametrics
