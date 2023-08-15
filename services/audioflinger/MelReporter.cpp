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
#define LOG_TAG "MelReporter"

#include "MelReporter.h"

#include <android/media/ISoundDoseCallback.h>
#include <audio_utils/power.h>
#include <utils/Log.h>

using aidl::android::hardware::audio::core::sounddose::ISoundDose;

namespace android {

bool MelReporter::activateHalSoundDoseComputation(const std::string& module,
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

void MelReporter::activateInternalSoundDoseComputation() {
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

void MelReporter::onFirstRef() {
    mAfMelReporterCallback->getPatchCommandThread()->addListener(this);

    mSoundDoseManager = sp<SoundDoseManager>::make(sp<IMelReporterCallback>::fromExisting(this));
}

void MelReporter::updateMetadataForCsd(audio_io_handle_t streamHandle,
        const std::vector<playback_track_metadata_v7_t>& metadataVec) {
    if (!mSoundDoseManager->isCsdEnabled()) {
        ALOGV("%s csd is disabled", __func__);
        return;
    }

    std::lock_guard _laf(mAfMelReporterCallback->mutex());
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
    if (activeMelPatchIt != mActiveMelPatches.end()) {
        if (shouldActivateCsd != activeMelPatchIt->second.csdActive) {
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
}

void MelReporter::onCreateAudioPatch(audio_patch_handle_t handle,
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
    newPatch.csdActive = false;
    for (size_t i = 0; i < patch.mAudioPatch.num_sinks; ++i) {
        if (patch.mAudioPatch.sinks[i].type == AUDIO_PORT_TYPE_DEVICE &&
                mSoundDoseManager->shouldComputeCsdForDeviceType(
                        patch.mAudioPatch.sinks[i].ext.device.type)) {
            audio_port_handle_t deviceId = patch.mAudioPatch.sinks[i].id;
            bool shouldComputeCsd = mSoundDoseManager->shouldComputeCsdForDeviceWithAddress(
                    patch.mAudioPatch.sinks[i].ext.device.type,
                    patch.mAudioPatch.sinks[i].ext.device.address);
            newPatch.deviceStates.push_back({deviceId, shouldComputeCsd});
            newPatch.csdActive |= shouldComputeCsd;
            AudioDeviceTypeAddr adt{patch.mAudioPatch.sinks[i].ext.device.type,
                                    patch.mAudioPatch.sinks[i].ext.device.address};
            mSoundDoseManager->mapAddressToDeviceId(adt, deviceId);
        }
    }

    if (!newPatch.deviceStates.empty() && newPatch.csdActive) {
        std::lock_guard _afl(mAfMelReporterCallback->mutex());
        std::lock_guard _l(mLock);
        ALOGV("%s add patch handle %d to active devices", __func__, handle);
        startMelComputationForActivePatch_l(newPatch);
        mActiveMelPatches[handle] = newPatch;
    }
}

void MelReporter::startMelComputationForActivePatch_l(const ActiveMelPatch& patch)
NO_THREAD_SAFETY_ANALYSIS  // access of AudioFlinger::checkOutputThread_l
{
    auto outputThread = mAfMelReporterCallback->checkOutputThread_l(patch.streamHandle);
    if (outputThread == nullptr) {
        ALOGE("%s cannot find thread for stream handle %d", __func__, patch.streamHandle);
        return;
    }

    for (const auto& device : patch.deviceStates) {
        if (device.second) {
            ++mActiveDevices[device.first];
            ALOGI("%s add stream %d that uses device %d for CSD, nr of streams: %d", __func__,
                  patch.streamHandle, device.first, mActiveDevices[device.first]);

            if (outputThread != nullptr && !useHalSoundDoseInterface_l()) {
                outputThread->startMelComputation_l(
                        mSoundDoseManager->getOrCreateProcessorForDevice(
                                device.first,
                                patch.streamHandle,
                                outputThread->sampleRate(),
                                outputThread->channelCount(),
                                outputThread->format()));
            }
        }
    }
}

void MelReporter::startMelComputationForDeviceId(audio_port_handle_t deviceId) {
    ALOGV("%s(%d)", __func__, deviceId);
    std::lock_guard _laf(mAfMelReporterCallback->mutex());
    std::lock_guard _l(mLock);

    for (auto& activeMelPatch : mActiveMelPatches) {
        bool csdActive = false;
        for (auto& device: activeMelPatch.second.deviceStates) {
            if (device.first == deviceId && !device.second) {
                device.second = true;
            }
            csdActive |= device.second;
        }
        if (csdActive && !activeMelPatch.second.csdActive) {
            activeMelPatch.second.csdActive = csdActive;
            startMelComputationForActivePatch_l(activeMelPatch.second);
        }
    }
}

void MelReporter::onReleaseAudioPatch(audio_patch_handle_t handle) {
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

    std::lock_guard _afl(mAfMelReporterCallback->mutex());
    std::lock_guard _l(mLock);
    stopMelComputationForPatch_l(melPatch);
}

sp<media::ISoundDose> MelReporter::getSoundDoseInterface(
        const sp<media::ISoundDoseCallback>& callback) {
    // no need to lock since getSoundDoseInterface is synchronized
    return mSoundDoseManager->getSoundDoseInterface(callback);
}

void MelReporter::stopInternalMelComputation() {
    ALOGV("%s", __func__);
    std::lock_guard _l(mLock);
    mActiveMelPatches.clear();
    mUseHalSoundDoseInterface = true;
}

void MelReporter::stopMelComputationForPatch_l(const ActiveMelPatch& patch)
NO_THREAD_SAFETY_ANALYSIS  // access of AudioFlinger::checkOutputThread_l
{
    auto outputThread = mAfMelReporterCallback->checkOutputThread_l(patch.streamHandle);

    ALOGV("%s: stop MEL for stream id: %d", __func__, patch.streamHandle);
    for (const auto& device : patch.deviceStates) {
        if (mActiveDevices[device.first] > 0) {
            --mActiveDevices[device.first];
            if (mActiveDevices[device.first] == 0) {
                // no stream is using deviceId anymore
                ALOGI("%s removing device %d from active CSD devices", __func__, device.first);
                mSoundDoseManager->clearMapDeviceIdEntries(device.first);
            }
        }
    }

    mSoundDoseManager->removeStreamProcessor(patch.streamHandle);
    if (outputThread != nullptr && !useHalSoundDoseInterface_l()) {
        outputThread->stopMelComputation_l();
    }
}

void MelReporter::stopMelComputationForDeviceId(audio_port_handle_t deviceId) {
    ALOGV("%s(%d)", __func__, deviceId);
    std::lock_guard _laf(mAfMelReporterCallback->mutex());
    std::lock_guard _l(mLock);

    for (auto& activeMelPatch : mActiveMelPatches) {
        bool csdActive = false;
        for (auto& device: activeMelPatch.second.deviceStates) {
            if (device.first == deviceId && device.second) {
                device.second = false;
            }
            csdActive |= device.second;
        }

        if (!csdActive && activeMelPatch.second.csdActive) {
            activeMelPatch.second.csdActive = csdActive;
            stopMelComputationForPatch_l(activeMelPatch.second);
        }
    }

}

std::optional<audio_patch_handle_t> MelReporter::activePatchStreamHandle_l(
        audio_io_handle_t streamHandle) {
    for(const auto& patchIt : mActiveMelPatches) {
        if (patchIt.second.streamHandle == streamHandle) {
            return patchIt.first;
        }
    }
    return std::nullopt;
}

bool MelReporter::useHalSoundDoseInterface_l() {
    return !mSoundDoseManager->forceUseFrameworkMel() & mUseHalSoundDoseInterface;
}

std::string MelReporter::dump() {
    std::lock_guard _l(mLock);
    std::string output("\nSound Dose:\n");
    output.append(mSoundDoseManager->dump());
    return output;
}

}  // namespace android
