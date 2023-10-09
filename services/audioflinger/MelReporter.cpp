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
#include <utils/Log.h>

using aidl::android::hardware::audio::core::sounddose::ISoundDose;

namespace android {

bool AudioFlinger::MelReporter::activateHalSoundDoseComputation(const std::string& module,
        const sp<DeviceHalInterface>& device) {
    if (mSoundDoseManager->forceUseFrameworkMel()) {
        ALOGD("%s: Forcing use of internal MEL computation.", __func__);
        activateInternalSoundDoseComputation();
        return false;
    }

    ndk::SpAIBinder soundDoseBinder;
    if (device->getSoundDoseInterface(module, &soundDoseBinder) != OK) {
        ALOGW("%s: HAL cannot provide sound dose interface for module %s, use internal MEL",
              __func__, module.c_str());
        activateInternalSoundDoseComputation();
        return false;
    }

    if (soundDoseBinder == nullptr) {
         ALOGW("%s: HAL doesn't implement a sound dose interface for module %s, use internal MEL",
              __func__, module.c_str());
        activateInternalSoundDoseComputation();
        return false;
    }

    std::shared_ptr<ISoundDose> soundDoseInterface = ISoundDose::fromBinder(soundDoseBinder);

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
}

bool AudioFlinger::MelReporter::shouldComputeMelForDeviceType(audio_devices_t device) {
    if (!mSoundDoseManager->isCsdEnabled()) {
        ALOGV("%s csd is disabled", __func__);
        return false;
    }
    if (mSoundDoseManager->forceComputeCsdOnAllDevices()) {
        return true;
    }

    switch (device) {
        case AUDIO_DEVICE_OUT_WIRED_HEADSET:
        case AUDIO_DEVICE_OUT_WIRED_HEADPHONE:
        // TODO(b/278265907): enable A2DP when we can distinguish A2DP headsets
        // case AUDIO_DEVICE_OUT_BLUETOOTH_A2DP:
        case AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES:
        case AUDIO_DEVICE_OUT_USB_HEADSET:
        case AUDIO_DEVICE_OUT_BLE_HEADSET:
        case AUDIO_DEVICE_OUT_BLE_BROADCAST:
            return true;
        default:
            return false;
    }
}

void AudioFlinger::MelReporter::updateMetadataForCsd(audio_io_handle_t streamHandle,
        const std::vector<playback_track_metadata_v7_t>& metadataVec) {
    if (!mSoundDoseManager->isCsdEnabled()) {
        ALOGV("%s csd is disabled", __func__);
        return;
    }

    std::lock_guard _laf(mAudioFlinger.mLock);
    std::lock_guard _l(mLock);
    auto activeMelPatchId = activePatchStreamHandle_l(streamHandle);
    if (!activeMelPatchId) {
        ALOGV("%s stream handle %d does not have an active patch", __func__, streamHandle);
        return;
    }

    bool shouldActivateCsd = false;
    for (const auto& metadata : metadataVec) {
        if (metadata.base.usage == AUDIO_USAGE_GAME || metadata.base.usage == AUDIO_USAGE_MEDIA) {
            shouldActivateCsd = true;
        }
    }

    auto activeMelPatchIt = mActiveMelPatches.find(activeMelPatchId.value());
    if (activeMelPatchIt != mActiveMelPatches.end()
        && shouldActivateCsd != activeMelPatchIt->second.csdActive) {
        if (activeMelPatchIt->second.csdActive) {
            ALOGV("%s should not compute CSD for stream handle %d", __func__, streamHandle);
            stopMelComputationForPatch_l(activeMelPatchIt->second);
        } else {
            ALOGV("%s should compute CSD for stream handle %d", __func__, streamHandle);
            startMelComputationForActivePatch_l(activeMelPatchIt->second);
        }
        activeMelPatchIt->second.csdActive = shouldActivateCsd;
    }
}

void AudioFlinger::MelReporter::onCreateAudioPatch(audio_patch_handle_t handle,
        const IAfPatchPanel::Patch& patch) {
    if (!mSoundDoseManager->isCsdEnabled()) {
        ALOGV("%s csd is disabled", __func__);
        return;
    }

    ALOGV("%s: handle %d mHalHandle %d device sink %08x",
            __func__, handle, patch.mHalHandle,
            patch.mAudioPatch.num_sinks > 0 ? patch.mAudioPatch.sinks[0].ext.device.type : 0);
    if (patch.mAudioPatch.num_sources == 0
        || patch.mAudioPatch.sources[0].type != AUDIO_PORT_TYPE_MIX) {
        ALOGV("%s: patch does not contain any mix sources", __func__);
        return;
    }

    audio_io_handle_t streamHandle = patch.mAudioPatch.sources[0].ext.mix.handle;
    ActiveMelPatch newPatch;
    newPatch.streamHandle = streamHandle;
    for (size_t i = 0; i < patch.mAudioPatch.num_sinks; ++i) {
        if (patch.mAudioPatch.sinks[i].type == AUDIO_PORT_TYPE_DEVICE
            && shouldComputeMelForDeviceType(patch.mAudioPatch.sinks[i].ext.device.type)) {
            audio_port_handle_t deviceId = patch.mAudioPatch.sinks[i].id;
            newPatch.deviceHandles.push_back(deviceId);
            AudioDeviceTypeAddr adt{patch.mAudioPatch.sinks[i].ext.device.type,
                                    patch.mAudioPatch.sinks[i].ext.device.address};
            mSoundDoseManager->mapAddressToDeviceId(adt, deviceId);
        }
    }

    if (!newPatch.deviceHandles.empty()) {
        std::lock_guard _afl(mAudioFlinger.mLock);
        std::lock_guard _l(mLock);
        ALOGV("%s add patch handle %d to active devices", __func__, handle);
        startMelComputationForActivePatch_l(newPatch);
        newPatch.csdActive = true;
        mActiveMelPatches[handle] = newPatch;
    }
}

void AudioFlinger::MelReporter::startMelComputationForActivePatch_l(const ActiveMelPatch& patch)
NO_THREAD_SAFETY_ANALYSIS  // access of AudioFlinger::checkOutputThread_l
{
    auto outputThread = mAudioFlinger.checkOutputThread_l(patch.streamHandle);
    if (outputThread == nullptr) {
        ALOGE("%s cannot find thread for stream handle %d", __func__, patch.streamHandle);
        return;
    }

    for (const auto& deviceHandle : patch.deviceHandles) {
        ++mActiveDevices[deviceHandle];
        ALOGI("%s add stream %d that uses device %d for CSD, nr of streams: %d", __func__,
              patch.streamHandle, deviceHandle, mActiveDevices[deviceHandle]);

        if (outputThread != nullptr && !useHalSoundDoseInterface_l()) {
            outputThread->startMelComputation_l(mSoundDoseManager->getOrCreateProcessorForDevice(
                deviceHandle,
                patch.streamHandle,
                outputThread->sampleRate(),
                outputThread->channelCount(),
                outputThread->format()));
        }
    }
}

void AudioFlinger::MelReporter::onReleaseAudioPatch(audio_patch_handle_t handle) {
    if (!mSoundDoseManager->isCsdEnabled()) {
        ALOGV("%s csd is disabled", __func__);
        return;
    }

    ActiveMelPatch melPatch;
    {
        std::lock_guard _l(mLock);

        auto patchIt = mActiveMelPatches.find(handle);
        if (patchIt == mActiveMelPatches.end()) {
            ALOGV("%s patch handle %d does not contain any mix sources with active MEL calculation",
                    __func__, handle);
            return;
        }

        melPatch = patchIt->second;
        mActiveMelPatches.erase(patchIt);
    }

    std::lock_guard _afl(mAudioFlinger.mLock);
    std::lock_guard _l(mLock);
    stopMelComputationForPatch_l(melPatch);
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

void AudioFlinger::MelReporter::stopMelComputationForPatch_l(const ActiveMelPatch& patch)
NO_THREAD_SAFETY_ANALYSIS  // access of AudioFlinger::checkOutputThread_l
{
    if (!patch.csdActive) {
        // no need to stop CSD inactive patches
        return;
    }

    auto outputThread = mAudioFlinger.checkOutputThread_l(patch.streamHandle);

    ALOGV("%s: stop MEL for stream id: %d", __func__, patch.streamHandle);
    for (const auto& deviceId : patch.deviceHandles) {
        if (mActiveDevices[deviceId] > 0) {
            --mActiveDevices[deviceId];
            if (mActiveDevices[deviceId] == 0) {
                // no stream is using deviceId anymore
                ALOGI("%s removing device %d from active CSD devices", __func__, deviceId);
                mSoundDoseManager->clearMapDeviceIdEntries(deviceId);
            }
        }
    }

    if (outputThread != nullptr && !useHalSoundDoseInterface_l()) {
        outputThread->stopMelComputation_l();
    }
}


std::optional<audio_patch_handle_t> AudioFlinger::MelReporter::activePatchStreamHandle_l(
        audio_io_handle_t streamHandle) {
    for(const auto& patchIt : mActiveMelPatches) {
        if (patchIt.second.streamHandle == streamHandle) {
            return patchIt.first;
        }
    }
    return std::nullopt;
}

bool AudioFlinger::MelReporter::useHalSoundDoseInterface_l() {
    return !mSoundDoseManager->forceUseFrameworkMel() & mUseHalSoundDoseInterface;
}

std::string AudioFlinger::MelReporter::dump() {
    std::lock_guard _l(mLock);
    std::string output("\nSound Dose:\n");
    output.append(mSoundDoseManager->dump());
    return output;
}

}  // namespace android
