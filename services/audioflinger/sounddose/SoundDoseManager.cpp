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

#if !defined(BACKEND_NDK)
#define BACKEND_NDK
#endif

#include "android/media/SoundDoseRecord.h"
#include <android-base/stringprintf.h>
#include <media/AidlConversionCppNdk.h>
#include <cinttypes>
#include <time.h>
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

    if (mHalSoundDose != nullptr) {
        ALOGW("%s: using HAL MEL computation, no MelProcessor needed.", __func__);
        return nullptr;
    }

    auto streamProcessor = mActiveProcessors.find(streamHandle);
    sp<audio_utils::MelProcessor> processor;
    if (streamProcessor != mActiveProcessors.end() &&
            (processor = streamProcessor->second.promote())) {
        ALOGV("%s: found callback for stream %d", __func__, streamHandle);
        processor->setDeviceId(deviceId);
        processor->setOutputRs2(mRs2Value);
        return processor;
    } else {
        ALOGV("%s: creating new callback for device %d", __func__, streamHandle);
        sp<audio_utils::MelProcessor> melProcessor = sp<audio_utils::MelProcessor>::make(
                sampleRate, channelCount, format, *this, deviceId, mRs2Value);
        mActiveProcessors[streamHandle] = melProcessor;
        return melProcessor;
    }
}

bool SoundDoseManager::setHalSoundDoseInterface(const std::shared_ptr<ISoundDose>& halSoundDose) {
    ALOGV("%s", __func__);

    {
        std::lock_guard _l(mLock);

        mHalSoundDose = halSoundDose;
        if (halSoundDose == nullptr) {
            ALOGI("%s: passed ISoundDose object is null, switching to internal CSD", __func__);
            return false;
        }

        if (!mHalSoundDose->setOutputRs2(mRs2Value).isOk()) {
            ALOGW("%s: Cannot set RS2 value for momentary exposure %f",
                  __func__,
                  mRs2Value);
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

void SoundDoseManager::setOutputRs2(float rs2Value) {
    ALOGV("%s", __func__);
    std::lock_guard _l(mLock);

    if (mHalSoundDose != nullptr) {
        // using the HAL sound dose interface
        if (!mHalSoundDose->setOutputRs2(rs2Value).isOk()) {
            ALOGE("%s: Cannot set RS2 value for momentary exposure %f", __func__, rs2Value);
            return;
        }
        mRs2Value = rs2Value;
        return;
    }

    for (auto& streamProcessor : mActiveProcessors) {
        sp<audio_utils::MelProcessor> processor = streamProcessor.second.promote();
        if (processor != nullptr) {
            status_t result = processor->setOutputRs2(rs2Value);
            if (result != NO_ERROR) {
                ALOGW("%s: could not set RS2 value %f for stream %d", __func__, rs2Value,
                      streamProcessor.first);
                return;
            }
            mRs2Value = rs2Value;
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
    ALOGI("%s: map address: %s to device id: %d", __func__, adt.toString().c_str(), deviceId);
    mActiveDevices[adt] = deviceId;
}

void SoundDoseManager::clearMapDeviceIdEntries(audio_port_handle_t deviceId) {
    std::lock_guard _l(mLock);
    for (auto activeDevice = mActiveDevices.begin(); activeDevice != mActiveDevices.end();) {
        if (activeDevice->second == deviceId) {
            ALOGI("%s: clear mapping addr: %s to deviceId: %d",
                  __func__, activeDevice->first.toString().c_str(), deviceId);
            activeDevice = mActiveDevices.erase(activeDevice);
            continue;
        }
        ++activeDevice;
    }
}

ndk::ScopedAStatus SoundDoseManager::HalSoundDoseCallback::onMomentaryExposureWarning(
        float in_currentDbA, const AudioDevice& in_audioDevice) {
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager == nullptr) {
        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
    }

    std::shared_ptr<ISoundDose> halSoundDose;
    soundDoseManager->getHalSoundDose(&halSoundDose);
    if(halSoundDose == nullptr) {
        ALOGW("%s: HAL sound dose interface deactivated. Ignoring", __func__);
        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
    }

    auto id = soundDoseManager->getIdForAudioDevice(in_audioDevice);
    if (id == AUDIO_PORT_HANDLE_NONE) {
        ALOGI("%s: no mapped id for audio device with type %d and address %s",
                __func__, in_audioDevice.type.type,
                in_audioDevice.address.get<AudioDeviceAddress::id>().c_str());
        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    }
    soundDoseManager->onMomentaryExposure(in_currentDbA, id);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus SoundDoseManager::HalSoundDoseCallback::onNewMelValues(
        const ISoundDose::IHalSoundDoseCallback::MelRecord& in_melRecord,
        const AudioDevice& in_audioDevice) {
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager == nullptr) {
        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
    }

    std::shared_ptr<ISoundDose> halSoundDose;
    soundDoseManager->getHalSoundDose(&halSoundDose);
    if(halSoundDose == nullptr) {
        ALOGW("%s: HAL sound dose interface deactivated. Ignoring", __func__);
        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
    }

    auto id = soundDoseManager->getIdForAudioDevice(in_audioDevice);
    if (id == AUDIO_PORT_HANDLE_NONE) {
        ALOGI("%s: no mapped id for audio device with type %d and address %s",
                __func__, in_audioDevice.type.type,
                in_audioDevice.address.get<AudioDeviceAddress::id>().c_str());
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

binder::Status SoundDoseManager::SoundDose::setOutputRs2(float value) {
    ALOGV("%s", __func__);
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        soundDoseManager->setOutputRs2(value);
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

binder::Status SoundDoseManager::SoundDose::getOutputRs2(float* value) {
    ALOGV("%s", __func__);
    auto soundDoseManager = mSoundDoseManager.promote();
    if (soundDoseManager != nullptr) {
        std::lock_guard _l(soundDoseManager->mLock);
        *value = soundDoseManager->mRs2Value;
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

void SoundDoseManager::setUseFrameworkMel(bool useFrameworkMel) {
    // invalidate any HAL sound dose interface used
    setHalSoundDoseInterface(nullptr);

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

void SoundDoseManager::getHalSoundDose(std::shared_ptr<ISoundDose>* halSoundDose) const {
    std::lock_guard _l(mLock);
    *halSoundDose = mHalSoundDose;
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
