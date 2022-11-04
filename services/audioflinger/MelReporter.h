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

#ifndef INCLUDING_FROM_AUDIOFLINGER_H
    #error This header file should only be included from AudioFlinger.h
#endif

#include <unordered_map>
#include <mutex>

constexpr static int kMaxTimestampDeltaInSec = 120;

/**
 * Class for listening to new patches and starting the MEL computation. MelReporter is
 * concealed within AudioFlinger, their lifetimes are the same.
 */
class MelReporter : public PatchCommandThread::PatchCommandListener {
public:
    explicit MelReporter(AudioFlinger& audioFlinger)
        : mAudioFlinger(audioFlinger),
          mMelAggregator(kMaxTimestampDeltaInSec) {}

    void onFirstRef() override {
        mAudioFlinger.mPatchCommandThread->addListener(this);
    }

    /** Returns true if we should compute MEL for the given device. */
    static bool shouldComputeMelForDeviceType(audio_devices_t device);

    // For now only support internal MelReporting
    [[nodiscard]] bool isHalReportingEnabled() const { return false; }

    std::string dump();

    // PatchCommandListener methods
    void onCreateAudioPatch(audio_patch_handle_t handle,
                            const PatchPanel::Patch& patch) override;
    void onReleaseAudioPatch(audio_patch_handle_t handle) override;

private:
    AudioFlinger& mAudioFlinger;  // does not own the object

    audio_utils::MelAggregator mMelAggregator;

    struct ActiveMelPatch {
        audio_io_handle_t streamHandle{AUDIO_IO_HANDLE_NONE};
        std::vector<audio_port_handle_t> deviceHandles;
    };

    /**
     * Lock for protecting the active mel patches. Do not mix with the AudioFlinger lock.
     * Locking order AudioFlinger::mLock -> PatchCommandThread::mLock -> MelReporter::mLock.
     */
    std::mutex mLock;
    std::unordered_map<audio_patch_handle_t, ActiveMelPatch>
        mActiveMelPatches GUARDED_BY(AudioFlinger::MelReporter::mLock);
};
