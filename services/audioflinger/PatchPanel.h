/*
**
** Copyright 2014, The Android Open Source Project
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

#include <map>  // avoid transitive dependency
#include <set>  // avoid transitive dependency

namespace android {

class PatchPanel : public IAfPatchPanel {
public:
    explicit PatchPanel(const sp<IAfPatchPanelCallback>& afPatchPanelCallback)
        : mAfPatchPanelCallback(afPatchPanelCallback) {}

    /* List connected audio ports and their attributes */
    status_t listAudioPorts_l(unsigned int *num_ports,
            struct audio_port* ports) final REQUIRES(audio_utils::AudioFlinger_Mutex);

    /* Get supported attributes for a given audio port */
    status_t getAudioPort_l(struct audio_port_v7* port) final
            REQUIRES(audio_utils::AudioFlinger_Mutex);

    /* Create a patch between several source and sink ports */
    status_t createAudioPatch_l(const struct audio_patch *patch,
                              audio_patch_handle_t *handle,
                              bool endpointPatch = false) final
            REQUIRES(audio_utils::AudioFlinger_Mutex);

    /* Release a patch */
    status_t releaseAudioPatch_l(audio_patch_handle_t handle) final
            REQUIRES(audio_utils::AudioFlinger_Mutex);

    /* List connected audio devices and they attributes */
    status_t listAudioPatches_l(unsigned int *num_patches,
            struct audio_patch* patches) final
            REQUIRES(audio_utils::AudioFlinger_Mutex);

    // Retrieves all currently established software patches for a stream
    // opened on an intermediate module.
    status_t getDownstreamSoftwarePatches(audio_io_handle_t stream,
            std::vector<SoftwarePatch>* patches) const final;

    // Notifies patch panel about all opened and closed streams.
    void notifyStreamOpened(AudioHwDevice *audioHwDevice, audio_io_handle_t stream,
                            struct audio_patch* patch) final;
    void notifyStreamClosed(audio_io_handle_t stream) final;

    void dump(int fd) const final;

    const std::map<audio_patch_handle_t, Patch>& patches_l() const final
            REQUIRES(audio_utils::AudioFlinger_Mutex) { return mPatches; }

    status_t getLatencyMs_l(audio_patch_handle_t patchHandle, double* latencyMs) const final
            REQUIRES(audio_utils::AudioFlinger_Mutex);

    void closeThreadInternal_l(const sp<IAfThreadBase>& thread) const final
            REQUIRES(audio_utils::AudioFlinger_Mutex);

private:
    AudioHwDevice* findAudioHwDeviceByModule_l(audio_module_handle_t module)
            REQUIRES(audio_utils::AudioFlinger_Mutex);
    sp<DeviceHalInterface> findHwDeviceByModule_l(audio_module_handle_t module)
            REQUIRES(audio_utils::AudioFlinger_Mutex);
    void addSoftwarePatchToInsertedModules_l(
            audio_module_handle_t module, audio_patch_handle_t handle,
            const struct audio_patch *patch)
            REQUIRES(audio_utils::AudioFlinger_Mutex);
    void removeSoftwarePatchFromInsertedModules(audio_patch_handle_t handle);
    void erasePatch(audio_patch_handle_t handle);

    const sp<IAfPatchPanelCallback> mAfPatchPanelCallback;
    std::map<audio_patch_handle_t, Patch> mPatches;

    // This map allows going from a thread to "downstream" software patches
    // when a processing module inserted in between. Example:
    //
    //  from map value.streams                               map key
    //  [Mixer thread] --> [Virtual output device] --> [Processing module] ---\
    //       [Harware module] <-- [Physical output device] <-- [S/W Patch] <--/
    //                                                 from map value.sw_patches
    //
    // This allows the mixer thread to look up the threads of the software patch
    // for propagating timing info, parameters, etc.
    //
    // The current assumptions are:
    //   1) The processing module acts as a mixer with several outputs which
    //      represent differently downmixed and / or encoded versions of the same
    //      mixed stream. There is no 1:1 correspondence between the input streams
    //      and the software patches, but rather a N:N correspondence between
    //      a group of streams and a group of patches.
    //   2) There are only a couple of inserted processing modules in the system,
    //      so when looking for a stream or patch handle we can iterate over
    //      all modules.
    struct ModuleConnections {
        std::set<audio_io_handle_t> streams;
        std::set<audio_patch_handle_t> sw_patches;
    };
    std::map<audio_module_handle_t, ModuleConnections> mInsertedModules;
};

}  // namespace android
