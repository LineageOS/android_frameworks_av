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

class IMelReporterCallback : public virtual RefBase {
public:
    IMelReporterCallback() {};
    virtual ~IMelReporterCallback() {};

    virtual void stopMelComputationForDeviceId(audio_port_handle_t deviceId) = 0;
    virtual void startMelComputationForDeviceId(audio_port_handle_t deviceId) = 0;

    virtual void applyAllAudioPatches() = 0;
};

class SoundDoseManager : public audio_utils::MelProcessor::MelCallback {
public:
    /** CSD is computed with a rolling window of 7 days. */
    static constexpr int64_t kCsdWindowSeconds = 604800;  // 60s * 60m * 24h * 7d
    /** Default RS2 upper bound in dBA as defined in IEC 62368-1 3rd edition. */
    static constexpr float kDefaultRs2UpperBound = 100.f;

    explicit SoundDoseManager(const sp<IMelReporterCallback>& melReporterCallback)
        : mMelReporterCallback(melReporterCallback),
          mMelAggregator(sp<audio_utils::MelAggregator>::make(kCsdWindowSeconds)),
          mRs2UpperBound(kDefaultRs2UpperBound) {};

    // Used only for testing
    SoundDoseManager(const sp<IMelReporterCallback>& melReporterCallback,
                     const sp<audio_utils::MelAggregator>& melAggregator)
            : mMelReporterCallback(melReporterCallback),
              mMelAggregator(melAggregator),
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
     * Sets the HAL sound dose interface for a specific module to use for the MEL computation.
     *
     * @return true if setting the HAL sound dose value was successful, false otherwise.
     */
    bool setHalSoundDoseInterface(const std::string &module,
                                  const std::shared_ptr<ISoundDose> &halSoundDose);

    /** Reset all the stored HAL sound dose interface. */
    void resetHalSoundDoseInterfaces();

    /** Returns the cached audio port id from the active devices. */
    audio_port_handle_t getIdForAudioDevice(
            const aidl::android::media::audio::common::AudioDevice& audioDevice) const;

    /** Caches mapping between address, device port id and device type. */
    void mapAddressToDeviceId(const AudioDeviceTypeAddr& adt, const audio_port_handle_t deviceId);

    /** Clear all map entries with passed audio_port_handle_t. */
    void clearMapDeviceIdEntries(audio_port_handle_t deviceId);

    /** Returns true if CSD is enabled. */
    bool isCsdEnabled();

    void initCachedAudioDeviceCategories(
            const std::vector<media::ISoundDose::AudioDeviceCategory>& deviceCategories);

    void setAudioDeviceCategory(
            const media::ISoundDose::AudioDeviceCategory& audioDevice);

    /**
     * Returns true if the type can compute CSD. For bluetooth devices we rely on whether we
     * categorized the address as headphones/headsets, only in this case we return true.
     */
    bool shouldComputeCsdForDeviceWithAddress(const audio_devices_t type,
                                              const std::string& deviceAddress);
    /** Returns true for all device types which could support CSD computation. */
    bool shouldComputeCsdForDeviceType(audio_devices_t device);

    std::string dump() const;

    // used for testing only
    size_t getCachedMelRecordsSize() const;
    bool isFrameworkMelForced() const;
    bool isComputeCsdForcedOnAllDevices() const;

    /** Method for converting from audio_utils::CsdRecord to media::SoundDoseRecord. */
    static media::SoundDoseRecord csdRecordToSoundDoseRecord(const audio_utils::CsdRecord& legacy);

    // ------ Override audio_utils::MelProcessor::MelCallback ------
    void onNewMelValues(const std::vector<float>& mels, size_t offset, size_t length,
                        audio_port_handle_t deviceId, bool attenuated) const override;

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

        binder::Status initCachedAudioDeviceCategories(
                const std::vector<media::ISoundDose::AudioDeviceCategory> &btDeviceCategories)
                override;

        binder::Status setAudioDeviceCategory(
                const media::ISoundDose::AudioDeviceCategory& btAudioDevice) override;

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
        std::mutex mCbLock;
    };

    void resetSoundDose();

    void resetCsd(float currentCsd, const std::vector<media::SoundDoseRecord>& records);

    sp<media::ISoundDoseCallback> getSoundDoseCallback() const;

    float getAttenuationForDeviceId(audio_port_handle_t id) const;

    void updateAttenuation(float attenuationDB, audio_devices_t deviceType);
    void setCsdEnabled(bool enabled);
    void setUseFrameworkMel(bool useFrameworkMel);
    void setComputeCsdOnAllDevices(bool computeCsdOnAllDevices);
    bool isSoundDoseHalSupported() const;
    /**
     * Returns true if there is one active HAL sound dose interface or null if internal MEL
     * computation is used.
     **/
    bool useHalSoundDose() const;

    mutable std::mutex mLock;

    const sp<IMelReporterCallback> mMelReporterCallback;

    // no need for lock since MelAggregator is thread-safe
    const sp<audio_utils::MelAggregator> mMelAggregator;

    std::unordered_map<audio_io_handle_t, wp<audio_utils::MelProcessor>> mActiveProcessors
            GUARDED_BY(mLock);

    // map active device address and type to device id, used also for managing the pause/resume
    // logic for deviceId's that should not report MEL values (e.g.: do not have an active MUSIC
    // or GAME stream).
    std::map<AudioDeviceTypeAddr, audio_port_handle_t> mActiveDevices GUARDED_BY(mLock);
    std::unordered_map<audio_port_handle_t, audio_devices_t> mActiveDeviceTypes GUARDED_BY(mLock);

    struct bt_device_type_hash {
        std::size_t operator() (const std::pair<std::string, audio_devices_t> &deviceType) const {
            return std::hash<std::string>()(deviceType.first) ^
                   std::hash<audio_devices_t>()(deviceType.second);
        }
    };
    // storing the BT cached information as received from the java side
    // see SoundDoseManager::setCachedAudioDeviceCategories
    std::unordered_map<std::pair<std::string, audio_devices_t>, bool, bt_device_type_hash>
            mBluetoothDevicesWithCsd GUARDED_BY(mLock);

    float mRs2UpperBound GUARDED_BY(mLock);
    std::unordered_map<audio_devices_t, float> mMelAttenuationDB GUARDED_BY(mLock);

    sp<SoundDose> mSoundDose GUARDED_BY(mLock);

    std::unordered_map<std::string, std::shared_ptr<ISoundDose>> mHalSoundDose GUARDED_BY(mLock);
    std::shared_ptr<HalSoundDoseCallback> mHalSoundDoseCallback GUARDED_BY(mLock);

    bool mUseFrameworkMel GUARDED_BY(mLock) = false;
    bool mComputeCsdOnAllDevices GUARDED_BY(mLock) = false;

    bool mEnabledCsd GUARDED_BY(mLock) = true;
};

}  // namespace android
