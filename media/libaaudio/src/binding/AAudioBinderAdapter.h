/*
 * Copyright (C) 2020 The Android Open Source Project
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

// go/keep-sorted start
#include <aaudio/IAAudioService.h>
#include <binding/AAudioServiceInterface.h>
// go/keep-sorted end

namespace aaudio {

/**
 * An adapter that takes in an underlying IAAudioService and exposes an
 * AAudioServiceInterface.
 *
 * This class is abstract: the client is expected to inherit from this class and implement those
 * methods from AAudioServiceInterface that don't have counterparts in IAAudioService.
 */
class AAudioBinderAdapter : public AAudioServiceInterface {
public:
    AAudioBinderAdapter(IAAudioService* delegate, int32_t serviceLifetimeId);

    void registerClient(const android::sp<IAAudioClient>& client) override;

    AAudioHandleInfo openStream(const AAudioStreamRequest& request,
                                AAudioStreamConfiguration& configuration) override;

    aaudio_result_t closeStream(const AAudioHandleInfo& streamHandleInfo, bool force) override;

    aaudio_result_t getStreamDescription(const AAudioHandleInfo& streamHandleInfo,
                                         AudioEndpointParcelable& endpoint) override;

    aaudio_result_t startStream(const AAudioHandleInfo& streamHandleInfo) override;

    aaudio_result_t pauseStream(const AAudioHandleInfo& streamHandleInfo) override;

    aaudio_result_t stopStream(const AAudioHandleInfo& streamHandleInfo) override;

    aaudio_result_t flushStream(const AAudioHandleInfo& streamHandleInfo) override;

    aaudio_result_t registerAudioThread(const AAudioHandleInfo& streamHandleInfo,
                                        pid_t clientThreadId,
                                        int64_t periodNanoseconds) override;

    aaudio_result_t unregisterAudioThread(const AAudioHandleInfo& streamHandleInfo,
                                          pid_t clientThreadId) override;

    aaudio_result_t exitStandby(const AAudioHandleInfo& streamHandleInfo,
                                AudioEndpointParcelable &parcelable) override;

    aaudio_result_t updateTimestamp(const AAudioHandleInfo& streamHandleInfo) override;

    aaudio_result_t drainStream(const AAudioHandleInfo& streamHandleInfo,
                                int64_t wakeUpNanos,
                                bool allowSoftWakeUp,
                                android::audio_utils::TimerQueue::handle_t* handle) override;

    aaudio_result_t activateStream(const AAudioHandleInfo& streamHandleInfo,
                                   android::audio_utils::TimerQueue::handle_t handle) override;

    aaudio_result_t setPlaybackParameters(const AAudioHandleInfo& streamHandleInfo,
                                          const android::AudioPlaybackRate& rate) override;

    aaudio_result_t getPlaybackParameters(const AAudioHandleInfo& streamHandleInfo,
                                          android::AudioPlaybackRate* rate) override;

private:
    IAAudioService* const mDelegate;
    // A unique id to recognize the service that the adapter connected to.
    const int32_t mServiceLifetimeId;
};

}  // namespace aaudio
