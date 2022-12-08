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

sp<audio_utils::MelProcessor> SoundDoseManager::getOrCreateProcessorForDevice(
        audio_port_handle_t deviceId,
        audio_io_handle_t streamHandle,
        uint32_t sampleRate,
        size_t channelCount,
        audio_format_t format)
{
    std::lock_guard _l(mLock);

    auto streamProcessor = mActiveProcessors.find(streamHandle);
    sp<audio_utils::MelProcessor> processor;
    if (streamProcessor != mActiveProcessors.end()
            && (processor = streamProcessor->second.promote())) {
        ALOGV("%s: found callback for stream %d", __func__, streamHandle);
        processor->setDeviceId(deviceId);
        return processor;
    } else {
        ALOGV("%s: creating new callback for device %d", __func__, streamHandle);
        sp<audio_utils::MelProcessor> melProcessor =
            sp<audio_utils::MelProcessor>::make(sampleRate,
                                                channelCount,
                                                format,
                                                *this,
                                                deviceId,
                                                mRs2Value);
        mActiveProcessors[streamHandle] = melProcessor;
        return melProcessor;
    }
}


void SoundDoseManager::setOutputRs2(float rs2Value)
{
    ALOGV("%s", __func__);
    std::lock_guard _l(mLock);

    for (auto& streamProcessor : mActiveProcessors) {
        sp<audio_utils::MelProcessor> processor = streamProcessor.second.promote();
        if (processor != nullptr) {
            status_t result = processor->setOutputRs2(rs2Value);
            if (result != NO_ERROR) {
                ALOGW("%s: could not set RS2 value %f for stream %d",
                      __func__,
                      rs2Value,
                      streamProcessor.first);
            }
        }
    }
}

void SoundDoseManager::removeStreamProcessor(audio_io_handle_t streamHandle)
{
    std::lock_guard _l(mLock);
    auto callbackToRemove = mActiveProcessors.find(streamHandle);
    if(callbackToRemove != mActiveProcessors.end()) {
        mActiveProcessors.erase(callbackToRemove);
    }
}

void SoundDoseManager::onNewMelValues(const std::vector<float>& mels,
                                      size_t offset,
                                      size_t length,
                                      audio_port_handle_t deviceId) const
{
    ALOGV("%s", __func__);
    std::lock_guard _l(mLock);

    int64_t timestampSec = getMonotonicSecond();

    // only for internal callbacks
    mMelAggregator->aggregateAndAddNewMelRecord(
        audio_utils::MelRecord(deviceId, std::vector<float>(
                                   mels.begin() + offset,
                                   mels.begin() + offset + length),
                               timestampSec - length));
}

void SoundDoseManager::onMomentaryExposure(float currentMel,
                                           audio_port_handle_t deviceId) const {
    ALOGV("%s: Momentary exposure for device %d triggered: %f MEL",
          __func__,
          deviceId,
          currentMel);
}

std::string SoundDoseManager::dump() const
{
    std::string output;
    mMelAggregator->foreachCsd([&output](audio_utils::CsdRecord csdRecord) {
        base::StringAppendF(&output,
                            "CSD %f with average MEL %f in interval [%" PRId64 ", %" PRId64 "]",
                            csdRecord.value,
                            csdRecord.averageMel,
                            csdRecord.timestamp,
                            csdRecord.timestamp + csdRecord.duration);
        base::StringAppendF(&output, "\n");
    });

    base::StringAppendF(&output, "\nCached Mel Records:\n");
    mMelAggregator->foreachCachedMel([&output](const audio_utils::MelRecord& melRecord) {
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
    return mMelAggregator->getCachedMelRecordsSize();
}

}  // namespace android
