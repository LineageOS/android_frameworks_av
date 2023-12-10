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

#include "android/media/SoundDoseRecord.h"
#include <android-base/stringprintf.h>
#include <media/AidlConversionCppNdk.h>
#include <cinttypes>
#include <ctime>
#include <utils/Log.h>

namespace android {

using aidl::android::media::audio::common::AudioDevice;
using aidl::android::media::audio::common::AudioDeviceAddress;

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
        audio_port_handle_t deviceId, audio_io_handle_t streamHandle, uint32_t sampleRate,
        size_t channelCount, audio_format_t format) {
    std::lock_guard _l(mLock);

    if (mHalSoundDose.size() > 0 && mEnabledCsd) {
        ALOGD("%s: using HAL MEL computation, no MelProcessor needed.", __func__);
        return nullptr;
    }

    auto streamProcessor = mActiveProcessors.find(streamHandle);
    if (streamProcessor != mActiveProcessors.end()) {
        auto processor = streamProcessor->second.promote();
        // if processor is nullptr it means it was removed by the playback
        // thread and can be replaced in the mActiveProcessors map
        if (processor != nullptr) {
            ALOGV("%s: found callback for stream id %d", __func__, streamHandle);
            const auto activeTypeIt = mActiveDeviceTypes.find(deviceId);
            if (activeTypeIt != mActiveDeviceTypes.end()) {
                processor->setAttenuation(mMelAttenuationDB[activeTypeIt->second]);
            }
            processor->setDeviceId(deviceId);
            processor->setOutputRs2UpperBound(mRs2UpperBound);
            return processor;
        }
    }

    ALOGV("%s: creating new callback for stream id %d", __func__, streamHandle);
    sp<audio_utils::MelProcessor> melProcessor = sp<audio_utils::MelProcessor>::make(
            sampleRate, channelCount, format, this, deviceId, mRs2UpperBound);
    const auto activeTypeIt = mActiveDeviceTypes.find(deviceId);
    if (activeTypeIt != mActiveDeviceTypes.end()) {
        melProcessor->setAttenuation(mMelAttenuationDB[activeTypeIt->second]);
    }
    mActiveProcessors[streamHandle] = melProcessor;
    return melProcessor;
}

bool SoundDoseManager::setHalSoundDoseInterface(const std::string &module,
                                                const std::shared_ptr<ISoundDose> &halSoundDose) {
    ALOGV("%s", __func__);

    if (halSoundDose == nullptr) {
        ALOGI("%s: passed ISoundDose object is null", __func__);
        return false;
    }

    std::shared_ptr<HalSoundDoseCallback> halSoundDoseCallback;
    {
        std::lock_guard _l(mLock);

        if (mHalSoundDose.find(module) != mHalSoundDose.end()) {
            ALOGW("%s: Module %s already has a sound dose HAL assigned, skipping", __func__,
                  module.c_str());
            return false;
        }
        mHalSoundDose[module] = halSoundDose;

        if (!halSoundDose->setOutputRs2UpperBound(mRs2UpperBound).isOk()) {
            ALOGW("%s: Cannot set RS2 value for momentary exposure %f",
                  __func__,
                  mRs2UpperBound);
        }

        // initialize the HAL sound dose callback lazily
        if (mHalSoundDoseCallback == nullptr) {
            mHalSoundDoseCallback =
                ndk::SharedRefBase::make<HalSoundDoseCallback>(this);
        }
    }

    auto status = halSoundDose->registerSoundDoseCallback(mHalSoundDoseCallback);
    if (!status.isOk()) {
        // Not a warning since this can happen if the callback was registered before
        ALOGI("%s: Cannot register HAL sound dose callback with status message: %s",
              __func__,
              status.getMessage());
    }

    return true;
}

void SoundDoseManager::resetHalSoundDoseInterfaces() {
    ALOGV("%s", __func__);

    const std::lock_guard _l(mLock);
    mHalSoundDose.clear();
}

void SoundDoseManager::setOutputRs2UpperBound(float rs2Value) {
    ALOGV("%s", __func__);
    std::lock_guard _l(mLock);

    if (mHalSoundDose.size() > 0) {
        for (auto& halSoundDose : mHalSoundDose) {
            // using the HAL sound dose interface
            if (!halSoundDose.second->setOutputRs2UpperBound(rs2Value).isOk()) {
                ALOGE("%s: Cannot set RS2 value for momentary exposure %f", __func__, rs2Value);
                continue;
            }
        }

        mRs2UpperBound = rs2Value;
        return;
    }

    for (auto& streamProcessor : mActiveProcessors) {
        sp<audio_utils::MelProcessor> processor = streamProcessor.second.promote();
        if (processor != nullptr) {
            status_t result = processor->setOutputRs2UpperBound(rs2Value);
            if (result != NO_ERROR) {
                ALOGW("%s: could not set RS2 upper bound %f for stream %d", __func__, rs2Value,
                      streamProcessor.first);
                return;
            }
            mRs2UpperBound = rs2Value;
        }
    }
}

void SoundDoseManager::removeStreamProcessor(audio_io_handle_t streamHandle) {
    std::lock_guard _l(mLock);
    auto callbackToRemove = mActiveProcessors.find(streamHandle);
    if (callbackToRemove != mActiveProcessors.end()) {
        mActiveProcessors.erase(callbackToRemove);
    }
}

audio_port_handle_t SoundDoseManager::getIdForAudioDevice(const AudioDevice& audioDevice) const {
    std::lock_guard _l(mLock);

    audio_devices_t type;
    std::string address;
    auto result = aidl::android::aidl2legacy_AudioDevice_audio_device(
            audioDevice, &type, &address);
    if (result != NO_ERROR) {
        ALOGE("%s: could not convert from AudioDevice to AudioDeviceTypeAddr", __func__);
        return AUDIO_PORT_HANDLE_NONE;
    }

    auto adt = AudioDeviceTypeAddr(type, address);
    auto deviceIt = mActiveDevices.find(adt);
    if (deviceIt == mActiveDevices.end()) {
        ALOGI("%s: could not find port id for device %s", __func__, adt.toString().c_str());
        return AUDIO_PORT_HANDLE_NONE;
    }
    return deviceIt->second;
}

void SoundDoseManager::mapAddressToDeviceId(const AudioDeviceTypeAddr& adt,
                                            const audio_port_handle_t deviceId) {
    std::lock_guard _l(mLock);
    ALOGI("%s: map address: %d to device id: %d", __func__, adt.mType, deviceId);
    mActiveDevices[adt] = deviceId;
    mActiveDeviceTypes[deviceId] = adt.mType;
}

void SoundDoseManager::clearMapDeviceIdEntries(audio_port_handle_t deviceId) {
    std::lock_guard _l(mLock);
    for (auto activeDevice = mActiveDevices.begin(); activeDevice != mActiveDevices.end();) {
        if (activeDevice->second == deviceId) {
            ALOGI("%s: clear mapping type: %d to deviceId: %d",
                  __func__, activeDevice->first.mType, deviceId);
            activeDevice = mActiveDevices.erase(activeDevice);
            continue;
        }
        ++activeDevice;
    }
    mActiveDeviceTypes.erase(deviceId);
}

ndk::ScopedAStatus SoundDoseManager::HalSoundDoseCallback::onMomentaryExposureWarning(
        float in_currentDbA, const AudioDevice& in_audioDevice) {
    sp<SoundDoseManager> soundDoseManager;
    {
        const std::lock_guard _l(mCbLock);
        soundDoseManager = mSoundDoseManager.promote();
        if (soundDoseManager == nullptr) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
        }
    }

    if (!soundDoseManager->useHalSoundDose()) {
        ALOGW("%s: HAL sound dose interface deactivated. Ignoring", __func__);
        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
    }

    auto id = soundDoseManager->getIdForAudioDevice(in_audioDevice);
    if (id == AUDIO_PORT_HANDLE_NONE) {
        ALOGI("%s: no mapped id for audio device with type %d and address %s",
                __func__, in_audioDevice.type.type,
                in_audioDevice.address.toString().c_str());
        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    }
    soundDoseManager->onMomentaryExposure(in_currentDbA, id);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus SoundDoseManager::HalSoundDoseCallback::onNewMelValues(
        const ISoundDose::IHalSoundDoseCallback::MelRecord& in_melRecord,
        const AudioDevice& in_audioDevice) {
    sp<SoundDoseManager> soundDoseManager;
    {
        const std::lock_guard _l(mCbLock);
        soundDoseManager = mSoundDoseManager.promote();
        if (soundDoseManager == nullptr) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
        }
    }

    if (!soundDoseManager->useHalSoundDose()) {
        ALOGW("%s: HAL sound dose interface deactivated. Ignoring", __func__);
        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
    }

    auto id = soundDoseManager->getIdForAudioDevice(in_audioDevice);
    if (id == AUDIO_PORT_HANDLE_NONE) {
        ALOGI("%s: no mapped id for audio device with type %d and address %s",
                __func__, in_audioDevice.type.type,
                in_audioDevice.address.toString().c_str());
        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    }
    // TODO: introduce timestamp in onNewMelValues callback
    soundDoseManager->onNewMelValues(in_melRecord.melValues, 0,
                                     in_melRecord.melValues.size(), id);

    return ndk::ScopedAStatus::ok();
}

void SoundDoseManager::SoundDose::binderDied(__unused const wp<IBinder>& who) {
    ALOGV("%s", __func__);

    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        soundDoseManager->resetSoundDose();
    }
}

binder::Status SoundDoseManager::SoundDose::setOutputRs2UpperBound(float value) {
    ALOGV("%s", __func__);
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        soundDoseManager->setOutputRs2UpperBound(value);
    }
    return binder::Status::ok();
}

binder::Status SoundDoseManager::SoundDose::resetCsd(
        float currentCsd, const std::vector<media::SoundDoseRecord>& records) {
    ALOGV("%s", __func__);
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        soundDoseManager->resetCsd(currentCsd, records);
    }
    return binder::Status::ok();
}

binder::Status SoundDoseManager::SoundDose::updateAttenuation(float attenuationDB, int device) {
    ALOGV("%s", __func__);
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        soundDoseManager->updateAttenuation(attenuationDB, static_cast<audio_devices_t>(device));
    }
    return binder::Status::ok();
}

binder::Status SoundDoseManager::SoundDose::setCsdEnabled(bool enabled) {
    ALOGV("%s", __func__);
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        soundDoseManager->setCsdEnabled(enabled);
    }
    return binder::Status::ok();
}

binder::Status SoundDoseManager::SoundDose::initCachedAudioDeviceCategories(
        const std::vector<media::ISoundDose::AudioDeviceCategory>& btDeviceCategories) {
    ALOGV("%s", __func__);
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        soundDoseManager->initCachedAudioDeviceCategories(btDeviceCategories);
    }
    return binder::Status::ok();
}
binder::Status SoundDoseManager::SoundDose::setAudioDeviceCategory(
        const media::ISoundDose::AudioDeviceCategory& btAudioDevice) {
    ALOGV("%s", __func__);
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        soundDoseManager->setAudioDeviceCategory(btAudioDevice);
    }
    return binder::Status::ok();
}

binder::Status SoundDoseManager::SoundDose::getOutputRs2UpperBound(float* value) {
    ALOGV("%s", __func__);
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        std::lock_guard _l(soundDoseManager->mLock);
        *value = soundDoseManager->mRs2UpperBound;
    }
    return binder::Status::ok();
}

binder::Status SoundDoseManager::SoundDose::getCsd(float* value) {
    ALOGV("%s", __func__);
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        *value = soundDoseManager->mMelAggregator->getCsd();
    }
    return binder::Status::ok();
}

binder::Status SoundDoseManager::SoundDose::forceUseFrameworkMel(bool useFrameworkMel) {
    ALOGV("%s", __func__);
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        soundDoseManager->setUseFrameworkMel(useFrameworkMel);
    }
    return binder::Status::ok();
}

binder::Status SoundDoseManager::SoundDose::forceComputeCsdOnAllDevices(
        bool computeCsdOnAllDevices) {
    ALOGV("%s", __func__);
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        soundDoseManager->setComputeCsdOnAllDevices(computeCsdOnAllDevices);
    }
    return binder::Status::ok();
}

binder::Status SoundDoseManager::SoundDose::isSoundDoseHalSupported(bool* value) {
    ALOGV("%s", __func__);
    *value = false;
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        *value = soundDoseManager->isSoundDoseHalSupported();
    }
    return binder::Status::ok();
}

void SoundDoseManager::updateAttenuation(float attenuationDB, audio_devices_t deviceType) {
    std::lock_guard _l(mLock);
    ALOGV("%s: updating MEL processor attenuation for device type %d to %f",
            __func__, deviceType, attenuationDB);
    mMelAttenuationDB[deviceType] = attenuationDB;
    for (const auto& mp : mActiveProcessors) {
        auto melProcessor = mp.second.promote();
        if (melProcessor != nullptr) {
            auto deviceId = melProcessor->getDeviceId();
            const auto deviceTypeIt = mActiveDeviceTypes.find(deviceId);
            if (deviceTypeIt != mActiveDeviceTypes.end() &&
                deviceTypeIt->second == deviceType) {
                ALOGV("%s: set attenuation for deviceId %d to %f",
                        __func__, deviceId, attenuationDB);
                melProcessor->setAttenuation(attenuationDB);
            }
        }
    }
}

void SoundDoseManager::setCsdEnabled(bool enabled) {
    ALOGV("%s",  __func__);

    std::lock_guard _l(mLock);
    mEnabledCsd = enabled;

    for (auto& activeEntry : mActiveProcessors) {
        auto melProcessor = activeEntry.second.promote();
        if (melProcessor != nullptr) {
            if (enabled) {
                melProcessor->resume();
            } else {
                melProcessor->pause();
            }
        }
    }
}

bool SoundDoseManager::isCsdEnabled() {
    std::lock_guard _l(mLock);
    return mEnabledCsd;
}

void SoundDoseManager::initCachedAudioDeviceCategories(
        const std::vector<media::ISoundDose::AudioDeviceCategory>& deviceCategories) {
    ALOGV("%s", __func__);
    {
        const std::lock_guard _l(mLock);
        mBluetoothDevicesWithCsd.clear();
    }
    for (const auto& btDeviceCategory : deviceCategories) {
        setAudioDeviceCategory(btDeviceCategory);
    }
}

void SoundDoseManager::setAudioDeviceCategory(
        const media::ISoundDose::AudioDeviceCategory& audioDevice) {
    ALOGV("%s: set BT audio device type with address %s to headphone %d", __func__,
          audioDevice.address.c_str(), audioDevice.csdCompatible);

    std::vector<audio_port_handle_t> devicesToStart;
    std::vector<audio_port_handle_t> devicesToStop;
    {
        const std::lock_guard _l(mLock);
        const auto deviceIt = mBluetoothDevicesWithCsd.find(
                std::make_pair(audioDevice.address,
                               static_cast<audio_devices_t>(audioDevice.internalAudioType)));
        if (deviceIt != mBluetoothDevicesWithCsd.end()) {
            deviceIt->second = audioDevice.csdCompatible;
        } else {
            mBluetoothDevicesWithCsd.emplace(
                    std::make_pair(audioDevice.address,
                                   static_cast<audio_devices_t>(audioDevice.internalAudioType)),
                    audioDevice.csdCompatible);
        }

        for (const auto &activeDevice: mActiveDevices) {
            if (activeDevice.first.address() == audioDevice.address &&
                activeDevice.first.mType ==
                static_cast<audio_devices_t>(audioDevice.internalAudioType)) {
                if (audioDevice.csdCompatible) {
                    devicesToStart.push_back(activeDevice.second);
                } else {
                    devicesToStop.push_back(activeDevice.second);
                }
            }
        }
    }

    for (const auto& deviceToStart : devicesToStart) {
        mMelReporterCallback->startMelComputationForDeviceId(deviceToStart);
    }
    for (const auto& deviceToStop : devicesToStop) {
        mMelReporterCallback->stopMelComputationForDeviceId(deviceToStop);
    }
}

bool SoundDoseManager::shouldComputeCsdForDeviceType(audio_devices_t device) {
    if (!isCsdEnabled()) {
        ALOGV("%s csd is disabled", __func__);
        return false;
    }
    if (forceComputeCsdOnAllDevices()) {
        return true;
    }

    switch (device) {
        case AUDIO_DEVICE_OUT_WIRED_HEADSET:
        case AUDIO_DEVICE_OUT_WIRED_HEADPHONE:
        case AUDIO_DEVICE_OUT_BLUETOOTH_A2DP:
        case AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES:
        case AUDIO_DEVICE_OUT_USB_HEADSET:
        case AUDIO_DEVICE_OUT_BLE_HEADSET:
        case AUDIO_DEVICE_OUT_BLE_BROADCAST:
            return true;
        default:
            return false;
    }
}

bool SoundDoseManager::shouldComputeCsdForDeviceWithAddress(const audio_devices_t type,
                                                            const std::string& deviceAddress) {
    if (!isCsdEnabled()) {
        ALOGV("%s csd is disabled", __func__);
        return false;
    }
    if (forceComputeCsdOnAllDevices()) {
        return true;
    }

    if (!audio_is_ble_out_device(type) && !audio_is_a2dp_device(type)) {
        return shouldComputeCsdForDeviceType(type);
    }

    const std::lock_guard _l(mLock);
    const auto deviceIt = mBluetoothDevicesWithCsd.find(std::make_pair(deviceAddress, type));
    return deviceIt != mBluetoothDevicesWithCsd.end() && deviceIt->second;
}

void SoundDoseManager::setUseFrameworkMel(bool useFrameworkMel) {
    // invalidate any HAL sound dose interface used
    resetHalSoundDoseInterfaces();

    std::lock_guard _l(mLock);
    mUseFrameworkMel = useFrameworkMel;
}

bool SoundDoseManager::forceUseFrameworkMel() const {
    std::lock_guard _l(mLock);
    return mUseFrameworkMel;
}

void SoundDoseManager::setComputeCsdOnAllDevices(bool computeCsdOnAllDevices) {
    std::lock_guard _l(mLock);
    mComputeCsdOnAllDevices = computeCsdOnAllDevices;
}

bool SoundDoseManager::forceComputeCsdOnAllDevices() const {
    std::lock_guard _l(mLock);
    return mComputeCsdOnAllDevices;
}

bool SoundDoseManager::isSoundDoseHalSupported() const {
    if (!mEnabledCsd) {
        return false;
    }

    return useHalSoundDose();
}

bool SoundDoseManager::useHalSoundDose() const {
    const std::lock_guard _l(mLock);
    return mHalSoundDose.size() > 0;
}

void SoundDoseManager::resetSoundDose() {
    std::lock_guard lock(mLock);
    mSoundDose = nullptr;
}

void SoundDoseManager::resetCsd(float currentCsd,
                                const std::vector<media::SoundDoseRecord>& records) {
    std::lock_guard lock(mLock);
    std::vector<audio_utils::CsdRecord> resetRecords;
    for (const auto& record : records) {
        resetRecords.emplace_back(record.timestamp, record.duration, record.value,
                                  record.averageMel);
    }

    mMelAggregator->reset(currentCsd, resetRecords);
}

void SoundDoseManager::onNewMelValues(const std::vector<float>& mels, size_t offset, size_t length,
                                      audio_port_handle_t deviceId) const {
    ALOGV("%s", __func__);


    sp<media::ISoundDoseCallback> soundDoseCallback;
    std::vector<audio_utils::CsdRecord> records;
    float currentCsd;
    {
        std::lock_guard _l(mLock);
        if (!mEnabledCsd) {
            return;
        }


        int64_t timestampSec = getMonotonicSecond();

        // only for internal callbacks
        records = mMelAggregator->aggregateAndAddNewMelRecord(audio_utils::MelRecord(
                deviceId, std::vector<float>(mels.begin() + offset, mels.begin() + offset + length),
                timestampSec - length));

        currentCsd = mMelAggregator->getCsd();
    }

    soundDoseCallback = getSoundDoseCallback();

    if (records.size() > 0 && soundDoseCallback != nullptr) {
        std::vector<media::SoundDoseRecord> newRecordsToReport;
        for (const auto& record : records) {
            newRecordsToReport.emplace_back(csdRecordToSoundDoseRecord(record));
        }

        soundDoseCallback->onNewCsdValue(currentCsd, newRecordsToReport);
    }
}

sp<media::ISoundDoseCallback> SoundDoseManager::getSoundDoseCallback() const {
    std::lock_guard _l(mLock);
    if (mSoundDose == nullptr) {
        return nullptr;
    }

    return mSoundDose->mSoundDoseCallback;
}

void SoundDoseManager::onMomentaryExposure(float currentMel, audio_port_handle_t deviceId) const {
    ALOGV("%s: Momentary exposure for device %d triggered: %f MEL", __func__, deviceId, currentMel);

    {
        std::lock_guard _l(mLock);
        if (!mEnabledCsd) {
            return;
        }
    }

    auto soundDoseCallback = getSoundDoseCallback();
    if (soundDoseCallback != nullptr) {
        soundDoseCallback->onMomentaryExposure(currentMel, deviceId);
    }
}

sp<media::ISoundDose> SoundDoseManager::getSoundDoseInterface(
        const sp<media::ISoundDoseCallback>& callback) {
    ALOGV("%s: Register ISoundDoseCallback", __func__);

    std::lock_guard _l(mLock);
    if (mSoundDose == nullptr) {
        mSoundDose = sp<SoundDose>::make(this, callback);
    }
    return mSoundDose;
}

std::string SoundDoseManager::dump() const {
    std::string output;
    {
        std::lock_guard _l(mLock);
        if (!mEnabledCsd) {
            base::StringAppendF(&output, "CSD is disabled");
            return output;
        }
    }

    mMelAggregator->foreachCsd([&output](audio_utils::CsdRecord csdRecord) {
        base::StringAppendF(&output,
                            "CSD %f with average MEL %f in interval [%" PRId64 ", %" PRId64 "]",
                            csdRecord.value, csdRecord.averageMel, csdRecord.timestamp,
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

media::SoundDoseRecord SoundDoseManager::csdRecordToSoundDoseRecord(
        const audio_utils::CsdRecord& legacy) {
    media::SoundDoseRecord soundDoseRecord{};
    soundDoseRecord.timestamp = legacy.timestamp;
    soundDoseRecord.duration = legacy.duration;
    soundDoseRecord.value = legacy.value;
    soundDoseRecord.averageMel = legacy.averageMel;
    return soundDoseRecord;
}

}  // namespace android
