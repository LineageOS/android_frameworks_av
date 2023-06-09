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

#include <aidl/android/hardware/audio/core/sounddose/ISoundDose.h>
#include <aidl/android/media/audio/common/AudioDevice.h>
#include <android/media/BnSoundDose.h>
#include <android/media/ISoundDoseCallback.h>
#include <media/AudioDeviceTypeAddr.h>
#include <audio_utils/MelAggregator.h>
#include <audio_utils/MelProcessor.h>
#include <binder/Status.h>
#include <mutex>
#include <unordered_map>

namespace android {

using aidl::android::hardware::audio::core::sounddose::ISoundDose;

class SoundDoseManager : public audio_utils::MelProcessor::MelCallback {
public:
    /** CSD is computed with a rolling window of 7 days. */
    static constexpr int64_t kCsdWindowSeconds = 604800;  // 60s * 60m * 24h * 7d
    /** Default RS2 upper bound in dBA as defined in IEC 62368-1 3rd edition. */
    static constexpr float kDefaultRs2UpperBound = 100.f;

    SoundDoseManager()
        : mMelAggregator(sp<audio_utils::MelAggregator>::make(kCsdWindowSeconds)),
          mRs2UpperBound(kDefaultRs2UpperBound) {};

    /**
     * \brief Creates or gets the MelProcessor assigned to the streamHandle
     *
     * \param deviceId          id for the devices where the stream is active.
     * \param streamHandle      handle to the stream
     * \param sampleRate        sample rate for the processor
     * \param channelCount      number of channels to be processed.
     * \param format            format of the input samples.
     *
     * \return MelProcessor assigned to the stream and device id.
     */
    sp<audio_utils::MelProcessor> getOrCreateProcessorForDevice(audio_port_handle_t deviceId,
                                                                audio_io_handle_t streamHandle,
                                                                uint32_t sampleRate,
                                                                size_t channelCount,
                                                                audio_format_t format);

    /**
     * \brief Removes stream processor when MEL computation is not needed anymore
     *
     * \param streamHandle      handle to the stream
     */
    void removeStreamProcessor(audio_io_handle_t streamHandle);

    /**
     * Sets the output RS2 upper bound for momentary exposure warnings. Must not be
     * higher than 100dBA and not lower than 80dBA.
     *
     * \param rs2Value value to use for momentary exposure
     */
    void setOutputRs2UpperBound(float rs2Value);

    /**
     * \brief Registers the interface for passing callbacks to the AudioService and gets
     * the ISoundDose interface.
     *
     * \returns the sound dose binder to send commands to the SoundDoseManager
     **/
    sp<media::ISoundDose> getSoundDoseInterface(const sp<media::ISoundDoseCallback>& callback);

    /**
     * Sets the HAL sound dose interface to use for the MEL computation. Use nullptr
     * for using the internal MEL computation.
     *
     * @return true if setting the HAL sound dose value was successful, false otherwise.
     */
    bool setHalSoundDoseInterface(const std::shared_ptr<ISoundDose>& halSoundDose);

    /** Returns the cached audio port id from the active devices. */
    audio_port_handle_t getIdForAudioDevice(
            const aidl::android::media::audio::common::AudioDevice& audioDevice) const;

    /** Caches mapping between address, device port id and device type. */
    void mapAddressToDeviceId(const AudioDeviceTypeAddr& adt, const audio_port_handle_t deviceId);

    /** Clear all map entries with passed audio_port_handle_t. */
    void clearMapDeviceIdEntries(audio_port_handle_t deviceId);

    /** Returns true if CSD is enabled. */
    bool isCsdEnabled();

    std::string dump() const;

    // used for testing only
    size_t getCachedMelRecordsSize() const;
    bool forceUseFrameworkMel() const;
    bool forceComputeCsdOnAllDevices() const;

    /** Method for converting from audio_utils::CsdRecord to media::SoundDoseRecord. */
    static media::SoundDoseRecord csdRecordToSoundDoseRecord(const audio_utils::CsdRecord& legacy);

    // ------ Override audio_utils::MelProcessor::MelCallback ------
    void onNewMelValues(const std::vector<float>& mels, size_t offset, size_t length,
                        audio_port_handle_t deviceId) const override;

    void onMomentaryExposure(float currentMel, audio_port_handle_t deviceId) const override;

private:
    class SoundDose : public media::BnSoundDose,
                      public IBinder::DeathRecipient {
    public:
        SoundDose(SoundDoseManager* manager, const sp<media::ISoundDoseCallback>& callback)
            : mSoundDoseManager(manager),
              mSoundDoseCallback(callback) {}

        /** IBinder::DeathRecipient. Listen to the death of ISoundDoseCallback. */
        void binderDied(const wp<IBinder>& who) override;

        /** BnSoundDose override */
        binder::Status setOutputRs2UpperBound(float value) override;
        binder::Status resetCsd(float currentCsd,
                                const std::vector<media::SoundDoseRecord>& records) override;
        binder::Status updateAttenuation(float attenuationDB, int device) override;
        binder::Status getOutputRs2UpperBound(float* value) override;
        binder::Status setCsdEnabled(bool enabled) override;

        binder::Status getCsd(float* value) override;
        binder::Status forceUseFrameworkMel(bool useFrameworkMel) override;
        binder::Status forceComputeCsdOnAllDevices(bool computeCsdOnAllDevices) override;
        binder::Status isSoundDoseHalSupported(bool* value) override;

        wp<SoundDoseManager> mSoundDoseManager;
        const sp<media::ISoundDoseCallback> mSoundDoseCallback;
    };

    class HalSoundDoseCallback : public ISoundDose::BnHalSoundDoseCallback {
    public:
        explicit HalSoundDoseCallback(SoundDoseManager* manager)
            : mSoundDoseManager(manager) {}

        ndk::ScopedAStatus onMomentaryExposureWarning(
                float in_currentDbA,
                const aidl::android::media::audio::common::AudioDevice& in_audioDevice) override;
        ndk::ScopedAStatus onNewMelValues(
                const ISoundDose::IHalSoundDoseCallback::MelRecord& in_melRecord,
                const aidl::android::media::audio::common::AudioDevice& in_audioDevice) override;

        wp<SoundDoseManager> mSoundDoseManager;
    };

    void resetSoundDose();

    void resetCsd(float currentCsd, const std::vector<media::SoundDoseRecord>& records);

    sp<media::ISoundDoseCallback> getSoundDoseCallback() const;

    void updateAttenuation(float attenuationDB, audio_devices_t deviceType);
    void setCsdEnabled(bool enabled);
    void setUseFrameworkMel(bool useFrameworkMel);
    void setComputeCsdOnAllDevices(bool computeCsdOnAllDevices);
    bool isSoundDoseHalSupported() const;
    /** Returns the HAL sound dose interface or null if internal MEL computation is used. */
    void getHalSoundDose(std::shared_ptr<ISoundDose>* halSoundDose) const;

    mutable std::mutex mLock;

    // no need for lock since MelAggregator is thread-safe
    const sp<audio_utils::MelAggregator> mMelAggregator;

    std::unordered_map<audio_io_handle_t, wp<audio_utils::MelProcessor>> mActiveProcessors
            GUARDED_BY(mLock);

    // map active device address and type to device id, used also for managing the pause/resume
    // logic for deviceId's that should not report MEL values (e.g.: do not have an active MUSIC
    // or GAME stream).
    std::map<AudioDeviceTypeAddr, audio_port_handle_t> mActiveDevices GUARDED_BY(mLock);
    std::unordered_map<audio_port_handle_t, audio_devices_t> mActiveDeviceTypes GUARDED_BY(mLock);

    float mRs2UpperBound GUARDED_BY(mLock);
    std::unordered_map<audio_devices_t, float> mMelAttenuationDB GUARDED_BY(mLock);

    sp<SoundDose> mSoundDose GUARDED_BY(mLock);

    std::shared_ptr<ISoundDose> mHalSoundDose GUARDED_BY(mLock);
    std::shared_ptr<HalSoundDoseCallback> mHalSoundDoseCallback GUARDED_BY(mLock);

    bool mUseFrameworkMel GUARDED_BY(mLock) = true;
    bool mComputeCsdOnAllDevices GUARDED_BY(mLock) = false;

    bool mEnabledCsd GUARDED_BY(mLock) = true;
};

}  // namespace android
