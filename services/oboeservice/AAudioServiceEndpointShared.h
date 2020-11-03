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

#ifndef AAUDIO_SERVICE_ENDPOINT_SHARED_H
#define AAUDIO_SERVICE_ENDPOINT_SHARED_H

#include <atomic>
#include <mutex>

#include <android-base/thread_annotations.h>

#include "AAudioServiceEndpoint.h"
#include "client/AudioStreamInternal.h"
#include "client/AudioStreamInternalPlay.h"
#include "AAudioServiceStreamShared.h"
#include "AAudioServiceStreamMMAP.h"
#include "AAudioService.h"

namespace aaudio {

/**
 * This manages an AudioStreamInternal that is shared by multiple Client streams.
 */
class AAudioServiceEndpointShared : public AAudioServiceEndpoint {

public:
    explicit AAudioServiceEndpointShared(AudioStreamInternal *streamInternal);

    virtual ~AAudioServiceEndpointShared() = default;

    std::string dump() const override;

    aaudio_result_t open(const aaudio::AAudioStreamRequest &request) override;

    void close() override;

    aaudio_result_t startStream(android::sp<AAudioServiceStreamBase> stream,
                                audio_port_handle_t *clientHandle) override;

    aaudio_result_t stopStream(android::sp<AAudioServiceStreamBase> stream,
                               audio_port_handle_t clientHandle) override;

    aaudio_result_t getFreeRunningPosition(int64_t *positionFrames, int64_t *timeNanos) override;

    aaudio_result_t getTimestamp(int64_t *positionFrames, int64_t *timeNanos) override;

    virtual void   *callbackLoop() = 0;

    AudioStreamInternal *getStreamInternal() const {
        return mStreamInternal.get();
    };

protected:

    aaudio_result_t          startSharingThread_l() REQUIRES(mLockStreams);

    aaudio_result_t          stopSharingThread();

    // An MMAP stream that is shared by multiple clients.
    android::sp<AudioStreamInternal> mStreamInternal;

    std::atomic<bool>        mCallbackEnabled{false};

    std::atomic<int>         mRunningStreamCount{0};
};

}

#endif //AAUDIO_SERVICE_ENDPOINT_SHARED_H
