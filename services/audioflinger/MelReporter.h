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

#include "IAfPatchPanel.h"
#include "PatchCommandThread.h"

#include <sounddose/SoundDoseManager.h>

#include <mutex>
#include <unordered_map>

namespace android {

constexpr static int kMaxTimestampDeltaInSec = 120;

class IAfMelReporterCallback : public virtual RefBase {
public:
    virtual Mutex& mutex() const = 0;
    virtual const sp<PatchCommandThread>& getPatchCommandThread() = 0;
    virtual sp<IAfThreadBase> checkOutputThread_l(audio_io_handle_t ioHandle) const = 0;
};

/**
 * Class for listening to new patches and starting the MEL computation. MelReporter is
 * concealed within AudioFlinger, their lifetimes are the same.
 */
class MelReporter : public PatchCommandThread::PatchCommandListener {
public:
    explicit MelReporter(const sp<IAfMelReporterCallback>& afMelReporterCallback)
        : mAfMelReporterCallback(afMelReporterCallback),
         mSoundDoseManager(sp<SoundDoseManager>::make()) {}

    void onFirstRef() override;

    /**
     * Activates the MEL reporting from the HAL sound dose interface. If the HAL
     * does not support the sound dose interface for this module, the internal MEL
     * calculation will be use.
     *
     * <p>If the device is using the audio AIDL HAL then this method will try to get the sound
     * dose interface from IModule#getSoundDose(). Otherwise, if the legacy audio HIDL HAL is used
     * this method will be looking for the standalone sound dose implementation. It falls back to
     * the internal MEL computation if no valid sound dose interface can be retrieved.
     *
     * @return true if the MEL reporting will be done from any sound dose HAL interface
     * implementation, false otherwise.
     */
    bool activateHalSoundDoseComputation(const std::string& module,
                                         const sp<DeviceHalInterface>& device);

    /**
     * Activates the MEL reporting from internal framework values. These are used
     * as a fallback when there is no sound dose interface implementation from HAL.
     * Note: the internal CSD computation does not guarantee a certification with
     * IEC62368-1 3rd edition or EN50332-3
     */
    void activateInternalSoundDoseComputation();

    sp<media::ISoundDose> getSoundDoseInterface(const sp<media::ISoundDoseCallback>& callback);

    std::string dump();

    // PatchCommandListener methods
    void onCreateAudioPatch(audio_patch_handle_t handle,
        const IAfPatchPanel::Patch& patch) final;
    void onReleaseAudioPatch(audio_patch_handle_t handle) final;

    /**
     * The new metadata can determine whether we should compute MEL for the given thread.
     * This is the case only if one of the tracks in the thread mix is using MEDIA or GAME.
     * Otherwise, this method will disable CSD.
     **/
    void updateMetadataForCsd(audio_io_handle_t streamHandle,
                              const std::vector<playback_track_metadata_v7_t>& metadataVec);
private:
    struct ActiveMelPatch {
        audio_io_handle_t streamHandle{AUDIO_IO_HANDLE_NONE};
        std::vector<audio_port_handle_t> deviceHandles;
        bool csdActive;
    };

    /** Returns true if we should compute MEL for the given device. */
    bool shouldComputeMelForDeviceType(audio_devices_t device);

    void stopInternalMelComputation();

    /** Should be called with the following order of locks: mAudioFlinger.mLock -> mLock. */
    void stopMelComputationForPatch_l(const ActiveMelPatch& patch) REQUIRES(mLock);

    /** Should be called with the following order of locks: mAudioFlinger.mLock -> mLock. */
    void startMelComputationForActivePatch_l(const ActiveMelPatch& patch) REQUIRES(mLock);

    std::optional<audio_patch_handle_t>
    activePatchStreamHandle_l(audio_io_handle_t streamHandle) REQUIRES(mLock);

    bool useHalSoundDoseInterface_l() REQUIRES(mLock);

    const sp<IAfMelReporterCallback> mAfMelReporterCallback;

    sp<SoundDoseManager> mSoundDoseManager;

    /**
     * Lock for protecting the active mel patches. Do not mix with the AudioFlinger lock.
     * Locking order AudioFlinger::mLock -> PatchCommandThread::mLock -> MelReporter::mLock.
     */
    std::mutex mLock;
    std::unordered_map<audio_patch_handle_t, ActiveMelPatch> mActiveMelPatches GUARDED_BY(mLock);
    std::unordered_map<audio_port_handle_t, int> mActiveDevices GUARDED_BY(mLock);
    bool mUseHalSoundDoseInterface GUARDED_BY(mLock) = false;
};

}  // namespace android
