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
#include <utils/Errors.h>

namespace android {

class SoundDoseManager : public audio_utils::MelProcessor::MelCallback {
public:
    /** CSD is computed with a rolling window of 7 days. */
    static constexpr int64_t kCsdWindowSeconds = 604800;  // 60s * 60m * 24h * 7d
    /** Default RS2 value in dBA as defined in IEC 62368-1 3rd edition. */
    static constexpr float kDefaultRs2Value = 100.f;

    SoundDoseManager()
        : mMelAggregator(sp<audio_utils::MelAggregator>::make(kCsdWindowSeconds)),
          mRs2Value(kDefaultRs2Value) {};

    /**
     * \brief Creates or gets the MelProcessor assigned to the streamHandle
     *
     * \param deviceId          id for the devices where the stream is active.
     * \param streanHandle      handle to the stream
     * \param sampleRate        sample rate for the processor
     * \param channelCount      number of channels to be processed.
     * \param format            format of the input samples.
     *
     * \return MelProcessor assigned to the stream and device id.
     */
    sp<audio_utils::MelProcessor> getOrCreateProcessorForDevice(
        audio_port_handle_t deviceId,
        audio_io_handle_t streamHandle,
        uint32_t sampleRate,
        size_t channelCount,
        audio_format_t format);

    /**
     * \brief Removes stream processor when MEL computation is not needed anymore
     *
     * \param streanHandle      handle to the stream
     */
    void removeStreamProcessor(audio_io_handle_t streamHandle);

    /**
     * Sets the output RS2 value for momentary exposure warnings. Must not be
     * higher than 100dBA and not lower than 80dBA.
     *
     * \param rs2Value value to use for momentary exposure
     */
    void setOutputRs2(float rs2Value);

    std::string dump() const;

    // used for testing
    size_t getCachedMelRecordsSize() const;

    // ------ Override audio_utils::MelProcessor::MelCallback ------
    void onNewMelValues(const std::vector<float>& mels,
                        size_t offset,
                        size_t length,
                        audio_port_handle_t deviceId) const override;

    void onMomentaryExposure(float currentMel, audio_port_handle_t deviceId) const override;
private:
    mutable std::mutex mLock;

    // no need for lock since MelAggregator is thread-safe
    const sp<audio_utils::MelAggregator> mMelAggregator;

    std::unordered_map<audio_io_handle_t,
                       wp<audio_utils::MelProcessor>> mActiveProcessors GUARDED_BY(mLock);

    float mRs2Value GUARDED_BY(mLock);
};

}  // namespace android
