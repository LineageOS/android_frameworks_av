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
#define LOG_TAG "AudioAnalytics"
#include <utils/Log.h>

#include "AudioAnalytics.h"

#include <audio_utils/clock.h>                 // clock conversions

namespace android::mediametrics {

AudioAnalytics::AudioAnalytics()
{
    ALOGD("%s", __func__);

    // Add action to save AnalyticsState if audioserver is restarted.
    // This triggers on an item of "audio.flinger"
    // with a property "event" set to "AudioFlinger" (the constructor).
    mActions.addAction(
        "audio.flinger.event",
        std::string("AudioFlinger"),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &){
                ALOGW("Audioflinger() constructor event detected");
                mPreviousAnalyticsState.set(std::make_shared<AnalyticsState>(
                        *mAnalyticsState.get()));
                // Note: get returns shared_ptr temp, whose lifetime is extended
                // to end of full expression.
                mAnalyticsState->clear();  // TODO: filter the analytics state.
            }));
}

AudioAnalytics::~AudioAnalytics()
{
    ALOGD("%s", __func__);
}

status_t AudioAnalytics::submit(
        const std::shared_ptr<const mediametrics::Item>& item, bool isTrusted)
{
    if (!startsWith(item->getKey(), "audio.")) return BAD_VALUE;
    status_t status = mAnalyticsState->submit(item, isTrusted);
    if (status != NO_ERROR) return status;  // may not be permitted.

    // Only if the item was successfully submitted (permission)
    // do we check triggered actions.
    checkActions(item);
    return NO_ERROR;
}

std::pair<std::string, int32_t> AudioAnalytics::dump(int32_t lines) const
{
    std::stringstream ss;
    int32_t ll = lines;

    if (ll > 0) {
        auto [s, l] = mAnalyticsState->dump(ll);
        ss << s;
        ll -= l;
    }
    if (ll > 0) {
        ss << "Prior audioserver state:\n";
        --ll;
    }
    if (ll > 0) {
        auto [s, l] = mPreviousAnalyticsState->dump(ll);
        ss << s;
        ll -= l;
    }
    return { ss.str(), lines - ll };
}

void AudioAnalytics::checkActions(const std::shared_ptr<const mediametrics::Item>& item)
{
    auto actions = mActions.getActionsForItem(item); // internally locked.
    // Execute actions with no lock held.
    for (const auto& action : actions) {
        (*action)(item);
    }
}

} // namespace android
