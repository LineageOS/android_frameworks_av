/*
**
** Copyright 2022, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

// #define LOG_NDEBUG 0
#define LOG_TAG "SoundDoseManager"

#include "SoundDoseManager.h"

#include <android-base/stringprintf.h>
#include <cinttypes>
#include <utils/Log.h>
#include <time.h>

namespace android {

namespace {

int64_t getMonotonicSecond() {
    struct timespec now_ts;
    if (clock_gettime(CLOCK_MONOTONIC, &now_ts) != 0) {
        ALOGE("%s: cannot get timestamp", __func__);
        return -1;
    }
    return now_ts.tv_sec;
}

}  // namespace

sp<audio_utils::MelProcessor::MelCallback> SoundDoseManager::getOrCreateCallbackForDevice(
        audio_port_handle_t deviceId,
        audio_io_handle_t streamHandle)
{
    std::lock_guard _l(mLock);

    auto streamHandleCallback = mActiveCallbacks.find(streamHandle);
    if (streamHandleCallback != mActiveCallbacks.end()) {
        ALOGV("%s: found callback for stream %d", __func__, streamHandle);
        auto callback = streamHandleCallback->second;
        callback->mDeviceHandle = deviceId;
        return callback;
    } else {
        ALOGV("%s: creating new callback for device %d", __func__, streamHandle);
        sp<Callback> melCallback = sp<Callback>::make(*this, deviceId);
        mActiveCallbacks[streamHandle] = melCallback;
        return melCallback;
    }
}

void SoundDoseManager::removeStreamCallback(audio_io_handle_t streamHandle)
{
    std::unordered_map<audio_io_handle_t, sp<Callback>>::iterator callbackToRemove;

    std::lock_guard _l(mLock);
    callbackToRemove = mActiveCallbacks.find(streamHandle);
    if (callbackToRemove != mActiveCallbacks.end()) {
        mActiveCallbacks.erase(callbackToRemove);
    }
}

void SoundDoseManager::Callback::onNewMelValues(const std::vector<float>& mels,
                                                size_t offset,
                                                size_t length) const
{
    ALOGV("%s", __func__);
    std::lock_guard _l(mSoundDoseManager.mLock);

    int64_t timestampSec = getMonotonicSecond();

    // only for internal callbacks
    mSoundDoseManager.mMelAggregator.aggregateAndAddNewMelRecord(
        audio_utils::MelRecord(mDeviceHandle, std::vector<float>(
                                   mels.begin() + offset,
                                   mels.begin() + offset + length),
                               timestampSec - length));
}

std::string SoundDoseManager::dump() const
{
    std::string output;
    mMelAggregator.foreachCsd([&output](audio_utils::CsdRecord csdRecord) {
        base::StringAppendF(&output,
                            "CSD %f with average MEL %f in interval [%" PRId64 ", %" PRId64 "]",
                            csdRecord.value,
                            csdRecord.averageMel,
                            csdRecord.timestamp,
                            csdRecord.timestamp + csdRecord.duration);
        base::StringAppendF(&output, "\n");
    });

    base::StringAppendF(&output, "\nCached Mel Records:\n");
    mMelAggregator.foreachCachedMel([&output](const audio_utils::MelRecord& melRecord) {
        base::StringAppendF(&output, "Continuous MELs for portId=%d, ", melRecord.portId);
        base::StringAppendF(&output, "starting at timestamp %" PRId64 ": ", melRecord.timestamp);

        for (const auto& mel : melRecord.mels) {
            base::StringAppendF(&output, "%.2f ", mel);
        }
        base::StringAppendF(&output, "\n");
    });

    return output;
}

size_t SoundDoseManager::getCachedMelRecordsSize() const {
    return mMelAggregator.getCachedMelRecordsSize();
}

}  // namespace android
