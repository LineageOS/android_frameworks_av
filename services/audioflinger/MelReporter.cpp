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
#define LOG_TAG "AudioFlinger::MelReporter"

#include "AudioFlinger.h"

#include <android/media/ISoundDoseCallback.h>
#include <audio_utils/power.h>
#include <android/binder_manager.h>
#include <utils/Log.h>

using aidl::android::hardware::audio::core::sounddose::ISoundDose;
using aidl::android::hardware::audio::sounddose::ISoundDoseFactory;

namespace android {

constexpr std::string_view kSoundDoseInterfaceModule = "/default";

bool AudioFlinger::MelReporter::activateHalSoundDoseComputation(const std::string& module) {
    if (mSoundDoseManager->forceUseFrameworkMel()) {
        ALOGD("%s: Forcing use of internal MEL computation.", __func__);
        activateInternalSoundDoseComputation();
        return false;
    }

    if (mSoundDoseFactory == nullptr) {
        ALOGW("%s: sound dose HAL reporting not available", __func__);
        activateInternalSoundDoseComputation();
        return false;
    }

    std::shared_ptr<ISoundDose> soundDoseInterface;
    auto result = mSoundDoseFactory->getSoundDose(module, &soundDoseInterface);
    if (!result.isOk()) {
        ALOGW("%s: HAL cannot provide sound dose interface for module %s",
              __func__, module.c_str());
        activateInternalSoundDoseComputation();
        return false;
    }

    if (!mSoundDoseManager->setHalSoundDoseInterface(soundDoseInterface)) {
        ALOGW("%s: cannot activate HAL MEL reporting for module %s", __func__, module.c_str());
        activateInternalSoundDoseComputation();
        return false;
    }

    stopInternalMelComputation();
    return true;
}

void AudioFlinger::MelReporter::activateInternalSoundDoseComputation() {
    {
        std::lock_guard _l(mLock);
        if (!mUseHalSoundDoseInterface) {
            // no need to start internal MEL on active patches
            return;
        }
        mUseHalSoundDoseInterface = false;
    }

    mSoundDoseManager->setHalSoundDoseInterface(nullptr);
}

void AudioFlinger::MelReporter::onFirstRef() {
    mAudioFlinger.mPatchCommandThread->addListener(this);

    std::string interface =
        std::string(ISoundDoseFactory::descriptor) + kSoundDoseInterfaceModule.data();
    AIBinder* binder = AServiceManager_checkService(interface.c_str());
    if (binder == nullptr) {
        ALOGW("%s service %s doesn't exist", __func__, interface.c_str());
        return;
    }

    mSoundDoseFactory = ISoundDoseFactory::fromBinder(ndk::SpAIBinder(binder));
}

bool AudioFlinger::MelReporter::shouldComputeMelForDeviceType(audio_devices_t device) {
    if (mSoundDoseManager->forceComputeCsdOnAllDevices()) {
        return true;
    }

    switch (device) {
        case AUDIO_DEVICE_OUT_WIRED_HEADSET:
        case AUDIO_DEVICE_OUT_WIRED_HEADPHONE:
        case AUDIO_DEVICE_OUT_BLUETOOTH_A2DP:
        case AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES:
        case AUDIO_DEVICE_OUT_HEARING_AID:
        case AUDIO_DEVICE_OUT_USB_HEADSET:
        case AUDIO_DEVICE_OUT_BLE_HEADSET:
        case AUDIO_DEVICE_OUT_BLE_BROADCAST:
            return true;
        default:
            return false;
    }
}

void AudioFlinger::MelReporter::onCreateAudioPatch(audio_patch_handle_t handle,
        const PatchPanel::Patch& patch) {
    ALOGV("%s: handle %d mHalHandle %d device sink %08x",
            __func__, handle, patch.mHalHandle,
            patch.mAudioPatch.num_sinks > 0 ? patch.mAudioPatch.sinks[0].ext.device.type : 0);
    if (patch.mAudioPatch.num_sources == 0
        || patch.mAudioPatch.sources[0].type != AUDIO_PORT_TYPE_MIX) {
        ALOGW("%s: patch does not contain any mix sources", __func__);
        return;
    }

    audio_io_handle_t streamHandle = patch.mAudioPatch.sources[0].ext.mix.handle;
    ActiveMelPatch newPatch;
    newPatch.streamHandle = streamHandle;
    for (int i = 0; i < patch.mAudioPatch.num_sinks; ++ i) {
        if (patch.mAudioPatch.sinks[i].type == AUDIO_PORT_TYPE_DEVICE
            && shouldComputeMelForDeviceType(patch.mAudioPatch.sinks[i].ext.device.type)) {
            audio_port_handle_t deviceId = patch.mAudioPatch.sinks[i].id;
            newPatch.deviceHandles.push_back(deviceId);
            AudioDeviceTypeAddr adt{patch.mAudioPatch.sinks[i].ext.device.type,
                                    patch.mAudioPatch.sinks[i].ext.device.address};
            mSoundDoseManager->mapAddressToDeviceId(adt, deviceId);

            bool useHalSoundDoseInterface = !mSoundDoseManager->forceUseFrameworkMel();
            {
                std::lock_guard _l(mLock);
                useHalSoundDoseInterface &= mUseHalSoundDoseInterface;
            }
            if (!useHalSoundDoseInterface) {
                startMelComputationForNewPatch(streamHandle, deviceId);
            }
        }
    }

    std::lock_guard _l(mLock);
    mActiveMelPatches[patch.mAudioPatch.id] = newPatch;
}

void AudioFlinger::MelReporter::startMelComputationForNewPatch(
        audio_io_handle_t streamHandle, audio_port_handle_t deviceId) {
    // Start the MEL calculation in the PlaybackThread
    std::lock_guard _lAf(mAudioFlinger.mLock);
    auto thread = mAudioFlinger.checkPlaybackThread_l(streamHandle);
    if (thread != nullptr) {
        thread->startMelComputation(mSoundDoseManager->getOrCreateProcessorForDevice(
            deviceId,
            streamHandle,
            thread->mSampleRate,
            thread->mChannelCount,
            thread->mFormat));
    }
}

void AudioFlinger::MelReporter::onReleaseAudioPatch(audio_patch_handle_t handle) {
    ALOGV("%s", __func__);

    ActiveMelPatch melPatch;
    {
        std::lock_guard _l(mLock);

        auto patchIt = mActiveMelPatches.find(handle);
        if (patchIt == mActiveMelPatches.end()) {
            ALOGW(
                "%s patch does not contain any mix sources with active MEL calculation",
                __func__);
            return;
        }

        melPatch = patchIt->second;
        mActiveMelPatches.erase(patchIt);
    }

    for (const auto& deviceId : melPatch.deviceHandles) {
        mSoundDoseManager->clearMapDeviceIdEntries(deviceId);
    }
    stopInternalMelComputationForStream(melPatch.streamHandle);
}

sp<media::ISoundDose> AudioFlinger::MelReporter::getSoundDoseInterface(
        const sp<media::ISoundDoseCallback>& callback) {
    // no need to lock since getSoundDoseInterface is synchronized
    return mSoundDoseManager->getSoundDoseInterface(callback);
}

void AudioFlinger::MelReporter::stopInternalMelComputation() {
    ALOGV("%s", __func__);
    std::lock_guard _l(mLock);
    mActiveMelPatches.clear();
    mUseHalSoundDoseInterface = true;
}

void AudioFlinger::MelReporter::stopInternalMelComputationForStream(audio_io_handle_t streamId) {
    ALOGV("%s: stop internal mel for stream id: %d", __func__, streamId);

    std::lock_guard _lAf(mAudioFlinger.mLock);
    mSoundDoseManager->removeStreamProcessor(streamId);
    auto thread = mAudioFlinger.checkPlaybackThread_l(streamId);
    if (thread != nullptr) {
        thread->stopMelComputation();
    }
}

std::string AudioFlinger::MelReporter::dump() {
    std::lock_guard _l(mLock);
    std::string output("\nSound Dose:\n");
    output.append(mSoundDoseManager->dump());
    return output;
}

}  // namespace android
