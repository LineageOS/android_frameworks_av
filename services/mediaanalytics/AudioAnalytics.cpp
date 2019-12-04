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
}

AudioAnalytics::~AudioAnalytics()
{
    ALOGD("%s", __func__);
}

status_t AudioAnalytics::submit(
        const std::shared_ptr<const MediaAnalyticsItem>& item, bool isTrusted)
{
    if (startsWith(item->getKey(), "audio.")) {
        return mTimeMachine.put(item, isTrusted)
                ?: mTransactionLog.put(item);
    }
    return BAD_VALUE;
}

std::pair<std::string, int32_t> AudioAnalytics::dump(int32_t lines) const
{
    std::stringstream ss;
    int32_t ll = lines;

    if (ll > 0) {
        ss << "TransactionLog:\n";
        --ll;
    }
    if (ll > 0) {
        auto [s, l] = mTransactionLog.dump(ll);
        ss << s;
        ll -= l;
    }
    if (ll > 0) {
        ss << "TimeMachine:\n";
        --ll;
    }
    if (ll > 0) {
        auto [s, l] = mTimeMachine.dump(ll);
        ss << s;
        ll -= l;
    }
    return { ss.str(), lines - ll };
}

} // namespace android
