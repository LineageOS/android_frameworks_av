/*
 * Copyright (C) 2023 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <android/content/AttributionSourceState.h>
#include <binder/AppOpsManager.h>
#include <system/audio.h>
#include <utils/RefBase.h>

#include <cstdint>

#include "AudioPolicyService.h"

namespace android::media::audiopolicy {

using ::android::content::AttributionSourceState;

// Checks and monitors app ops for AudioRecordClient
class OpRecordAudioMonitor : public RefBase {
public:
    ~OpRecordAudioMonitor() override;
    bool hasOp() const;
    int32_t getOp() const { return mAppOp; }

    static sp<OpRecordAudioMonitor> createIfNeeded(
            const AttributionSourceState& attributionSource,
            uint32_t virtualDeviceId,
            const audio_attributes_t& attr,
            wp<AudioPolicyService::AudioCommandThread> commandThread);

private:
    OpRecordAudioMonitor(const AttributionSourceState &attributionSource,
                         uint32_t virtualDeviceId,
                         const audio_attributes_t &attr,
                         int32_t appOp,
                         wp<AudioPolicyService::AudioCommandThread> commandThread);

    void onFirstRef() override;

    AppOpsManager mAppOpsManager;

    class RecordAudioOpCallback : public BnAppOpsCallback {
    public:
        explicit RecordAudioOpCallback(const wp<OpRecordAudioMonitor>& monitor);
        void opChanged(int32_t op, const String16& packageName) override;

    private:
        const wp<OpRecordAudioMonitor> mMonitor;
    };

    sp<RecordAudioOpCallback> mOpCallback;
    // called by RecordAudioOpCallback when the app op for this OpRecordAudioMonitor is updated
    // in AppOp callback and in onFirstRef()
    // updateUidStates is true when the silenced state of active AudioRecordClients must be
    // re-evaluated
    void checkOp(bool updateUidStates = false);

    std::atomic_bool mHasOp;
    const AttributionSourceState mAttributionSource;
    const uint32_t mVirtualDeviceId;
    const audio_attributes_t mAttr;
    const int32_t mAppOp;
    wp<AudioPolicyService::AudioCommandThread> mCommandThread;
};

// --- AudioRecordClient ---
// Information about each registered AudioRecord client
// (between calls to getInputForAttr() and releaseInput())
class AudioRecordClient : public AudioPolicyService::AudioClient {
public:
            AudioRecordClient(const audio_attributes_t attributes,
                      const audio_io_handle_t io,
                      const audio_session_t session, audio_port_handle_t portId,
                      const audio_port_handle_t deviceId,
                      const AttributionSourceState& attributionSource,
                      const uint32_t virtualDeviceId,
                      bool canCaptureOutput, bool canCaptureHotword,
                      wp<AudioPolicyService::AudioCommandThread> commandThread) :
                AudioClient(attributes, io, attributionSource,
                    session, portId, deviceId), attributionSource(attributionSource),
                    virtualDeviceId(virtualDeviceId),
                    startTimeNs(0), canCaptureOutput(canCaptureOutput),
                    canCaptureHotword(canCaptureHotword), silenced(false),
                    mOpRecordAudioMonitor(
                            OpRecordAudioMonitor::createIfNeeded(attributionSource,
                                                                 virtualDeviceId,
                                                                 attributes, commandThread)) {

            }
            ~AudioRecordClient() override = default;

    bool hasOp() const {
        return mOpRecordAudioMonitor ? mOpRecordAudioMonitor->hasOp() : true;
    }

    const AttributionSourceState attributionSource; // attribution source of client
    const uint32_t virtualDeviceId; // id of the virtual device associated with the audio device
    nsecs_t startTimeNs;
    const bool canCaptureOutput;
    const bool canCaptureHotword;
    bool silenced;

private:
    sp<OpRecordAudioMonitor>           mOpRecordAudioMonitor;
};

}; // namespace android::media::audiopolicy::internal
