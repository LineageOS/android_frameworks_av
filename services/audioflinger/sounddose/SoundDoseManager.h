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

#pragma once

#include <audio_utils/MelProcessor.h>
#include <audio_utils/MelAggregator.h>
#include <mutex>
#include <unordered_map>

namespace android {

/** CSD is computed with a rolling window of 7 days. */
constexpr int64_t kCsdWindowSeconds = 604800;  // 60 * 60 * 24 * 7

class SoundDoseManager {
public:
    SoundDoseManager() : mMelAggregator(kCsdWindowSeconds) {};

    /**
     * \brief Creates or gets the callback assigned to the streamHandle
     *
     * \param deviceId          id for the devices where the stream is active.
     * \param streanHandle      handle to the stream
     */
    sp<audio_utils::MelProcessor::MelCallback> getOrCreateCallbackForDevice(
        audio_port_handle_t deviceId,
        audio_io_handle_t streamHandle);

    /**
     * \brief Removes stream callback when MEL computation is not needed anymore
     *
     * \param streanHandle      handle to the stream
     */
    void removeStreamCallback(audio_io_handle_t streamHandle);

    std::string dump() const;

    // used for testing
    size_t getCachedMelRecordsSize() const;
private:
    /**
     * An implementation of the MelProcessor::MelCallback that is assigned to a
     * specific device.
     */
    class Callback : public audio_utils::MelProcessor::MelCallback {
    public:
        Callback(SoundDoseManager& soundDoseManager, audio_port_handle_t deviceHandle)
            : mSoundDoseManager(soundDoseManager), mDeviceHandle(deviceHandle) {}

        void onNewMelValues(const std::vector<float>& mels,
                            size_t offset,
                            size_t length) const override;

        SoundDoseManager& mSoundDoseManager;
        audio_port_handle_t mDeviceHandle;
    };

    // no need for lock since MelAggregator is thread-safe
    audio_utils::MelAggregator mMelAggregator;

    std::mutex mLock;
    std::unordered_map<audio_io_handle_t, sp<Callback>> mActiveCallbacks GUARDED_BY(mLock);
};

}  // namespace android
