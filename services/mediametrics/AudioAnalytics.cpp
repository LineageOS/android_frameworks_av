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
        AMEDIAMETRICS_KEY_AUDIO_FLINGER "." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_CTOR),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                ALOGW("(key=%s) Audioflinger constructor event detected", item->getKey().c_str());
                mPreviousAnalyticsState.set(std::make_shared<AnalyticsState>(
                        *mAnalyticsState.get()));
                // Note: get returns shared_ptr temp, whose lifetime is extended
                // to end of full expression.
                mAnalyticsState->clear();  // TODO: filter the analytics state.
                // Perhaps report this.
            }));

    // Check underruns
    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD "*." AMEDIAMETRICS_PROP_EVENT,
        std::string(AMEDIAMETRICS_PROP_EVENT_VALUE_UNDERRUN),
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                std::string threadId = item->getKey().substr(
                        sizeof(AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD) - 1);
                std::string outputDevices;
                mAnalyticsState->timeMachine().get(
                        item->getKey(), AMEDIAMETRICS_PROP_OUTPUTDEVICES, &outputDevices);
                ALOGD("(key=%s) Thread underrun event detected on io handle:%s device:%s",
                        item->getKey().c_str(), threadId.c_str(), outputDevices.c_str());
                if (outputDevices.find("AUDIO_DEVICE_OUT_BLUETOOTH") != std::string::npos) {
                    // report this for Bluetooth
                }
            }));

    // Check latencies, playback and startup
    mActions.addAction(
        AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK "*." AMEDIAMETRICS_PROP_LATENCYMS,
        std::monostate{},  // accept any value
        std::make_shared<AnalyticsActions::Function>(
            [this](const std::shared_ptr<const android::mediametrics::Item> &item){
                double latencyMs{};
                double startupMs{};
                if (!item->get(AMEDIAMETRICS_PROP_LATENCYMS, &latencyMs)
                        || !item->get(AMEDIAMETRICS_PROP_STARTUPMS, &startupMs)) return;

                std::string trackId = item->getKey().substr(
                        sizeof(AMEDIAMETRICS_KEY_PREFIX_AUDIO_TRACK) - 1);
                std::string thread = getThreadFromTrack(item->getKey());
                std::string outputDevices;
                mAnalyticsState->timeMachine().get(
                        thread, AMEDIAMETRICS_PROP_OUTPUTDEVICES, &outputDevices);
                ALOGD("(key=%s) Track latencyMs:%lf startupMs:%lf detected on port:%s device:%s",
                        item->getKey().c_str(), latencyMs, startupMs,
                        trackId.c_str(), outputDevices.c_str());
                if (outputDevices.find("AUDIO_DEVICE_OUT_BLUETOOTH") != std::string::npos) {
                    // report this for Bluetooth
                }
            }));
}

AudioAnalytics::~AudioAnalytics()
{
    ALOGD("%s", __func__);
}

status_t AudioAnalytics::submit(
        const std::shared_ptr<const mediametrics::Item>& item, bool isTrusted)
{
    if (!startsWith(item->getKey(), AMEDIAMETRICS_KEY_PREFIX_AUDIO)) return BAD_VALUE;
    status_t status = mAnalyticsState->submit(item, isTrusted);
    if (status != NO_ERROR) return status;  // may not be permitted.

    // Only if the item was successfully submitted (permission)
    // do we check triggered actions.
    checkActions(item);
    return NO_ERROR;
}

std::pair<std::string, int32_t> AudioAnalytics::dump(
        int32_t lines, int64_t sinceNs, const char *prefix) const
{
    std::stringstream ss;
    int32_t ll = lines;

    if (ll > 0) {
        auto [s, l] = mAnalyticsState->dump(ll, sinceNs, prefix);
        ss << std::move(s);
        ll -= l;
    }
    if (ll > 0) {
        ss << "Prior audioserver state:\n";
        --ll;
    }
    if (ll > 0) {
        auto [s, l] = mPreviousAnalyticsState->dump(ll, sinceNs, prefix);
        ss << std::move(s);
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

// HELPER METHODS

std::string AudioAnalytics::getThreadFromTrack(const std::string& track) const
{
    int32_t threadId_int32{};
    if (mAnalyticsState->timeMachine().get(
            track, AMEDIAMETRICS_PROP_THREADID, &threadId_int32) != NO_ERROR) {
        return {};
    }
    return std::string(AMEDIAMETRICS_KEY_PREFIX_AUDIO_THREAD) + std::to_string(threadId_int32);
}

} // namespace android
