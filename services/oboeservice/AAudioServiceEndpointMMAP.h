/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef AAUDIO_SERVICE_ENDPOINT_MMAP_H
#define AAUDIO_SERVICE_ENDPOINT_MMAP_H

#include <atomic>
#include <functional>
#include <vector>

#include "client/AudioStreamInternal.h"
#include "client/AudioStreamInternalPlay.h"
#include "binding/AAudioServiceMessage.h"
#include "AAudioServiceEndpointShared.h"
#include "AAudioServiceStreamShared.h"
#include "AAudioServiceStreamMMAP.h"
#include "AAudioMixer.h"
#include "AAudioService.h"
#include "SharedMemoryWrapper.h"

namespace aaudio {

/**
 * This is used by AAudioServiceStreamMMAP to access the MMAP devices
 * through AudioFlinger.
 */
class AAudioServiceEndpointMMAP
        : public AAudioServiceEndpoint
        , public android::MmapStreamCallback {

public:
    explicit AAudioServiceEndpointMMAP(android::AAudioService &audioService);

    ~AAudioServiceEndpointMMAP() override = default;

    std::string dump() const override;

    aaudio_result_t open(const aaudio::AAudioStreamRequest &request) override;

    void close() override EXCLUDES(mMmapStreamLock);

    aaudio_result_t startStream(android::sp<AAudioServiceStreamBase> stream,
                                audio_port_handle_t *clientHandle) override;

    aaudio_result_t stopStream(android::sp<AAudioServiceStreamBase> stream,
                               audio_port_handle_t clientHandle) override;

    aaudio_result_t startClient(const android::AudioClient& client,
                                const audio_attributes_t *attr,
                                audio_port_handle_t *clientHandle)  override
                                EXCLUDES(mMmapStreamLock);

    aaudio_result_t stopClient(audio_port_handle_t clientHandle)  override
            EXCLUDES(mMmapStreamLock);

    aaudio_result_t standby() override EXCLUDES(mMmapStreamLock);

    aaudio_result_t exitStandby(AudioEndpointParcelable* parcelable) override
            EXCLUDES(mMmapStreamLock);

    aaudio_result_t getFreeRunningPosition(int64_t *positionFrames, int64_t *timeNanos) override
             EXCLUDES(mMmapStreamLock);

    aaudio_result_t getTimestamp(int64_t *positionFrames, int64_t *timeNanos) override;

    void handleTearDownAsync(audio_port_handle_t portHandle);

    // -------------- Callback functions for MmapStreamCallback ---------------------
    void onTearDown(audio_port_handle_t portHandle) override;

    void onVolumeChanged(float volume) override;

    void onRoutingChanged(audio_port_handle_t portHandle) override;
    // ------------------------------------------------------------------------------

    aaudio_result_t getDownDataDescription(AudioEndpointParcelable* parcelable);

    int64_t getHardwareTimeOffsetNanos() const {
        return mHardwareTimeOffsetNanos;
    }

    aaudio_result_t getExternalPosition(uint64_t *positionFrames, int64_t *timeNanos)
            EXCLUDES(mMmapStreamLock);

    int64_t nextDataReportTime() EXCLUDES(mMmapStreamLock);

    void reportData() EXCLUDES(mMmapStreamLock);

private:

    /**
     *
     * @return true if mMapStream was cleared
     */
    bool close_l() REQUIRES(mMmapStreamLock);

    aaudio_result_t openWithConfig(audio_config_base_t* config) EXCLUDES(mMmapStreamLock);

    aaudio_result_t createMmapBuffer_l() REQUIRES(mMmapStreamLock);

    MonotonicCounter                          mFramesTransferred;

    // Interface to the AudioFlinger MMAP support.
    mutable std::mutex                        mMmapStreamLock;
    android::sp<android::MmapStreamInterface> mMmapStream GUARDED_BY(mMmapStreamLock);

    struct audio_mmap_buffer_info             mMmapBufferinfo;

    // There is only one port associated with an MMAP endpoint.
    audio_port_handle_t                       mPortHandle = AUDIO_PORT_HANDLE_NONE;

    android::AAudioService                    &mAAudioService;

    std::unique_ptr<SharedMemoryWrapper>      mAudioDataWrapper;

    int64_t                                   mHardwareTimeOffsetNanos = 0; // TODO get from HAL

    aaudio_result_t                           mHalExternalPositionStatus = AAUDIO_OK;
    uint64_t                                  mLastPositionFrames = 0;
    int64_t                                   mTimestampNanosForLastPosition = 0;
    int32_t                                   mTimestampGracePeriodMs;
    int32_t                                   mFrozenPositionCount = 0;
    int32_t                                   mFrozenTimestampCount = 0;
    int64_t                                   mDataReportOffsetNanos = 0;

};

} /* namespace aaudio */

#endif //AAUDIO_SERVICE_ENDPOINT_MMAP_H

