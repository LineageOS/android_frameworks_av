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

#ifndef AAUDIO_SERVICE_ENDPOINT_H
#define AAUDIO_SERVICE_ENDPOINT_H

#include <atomic>
#include <functional>
#include <mutex>
#include <vector>

#include "client/AudioStreamInternal.h"
#include "client/AudioStreamInternalPlay.h"
#include "binding/AAudioServiceMessage.h"
#include "AAudioServiceStreamShared.h"
#include "AAudioServiceStreamMMAP.h"
#include "AAudioMixer.h"
#include "AAudioService.h"

namespace aaudio {

class AAudioServiceEndpoint {
public:
    virtual ~AAudioServiceEndpoint() = default;

    std::string dump() const;

    virtual aaudio_result_t open(const AAudioStreamConfiguration& configuration);

    int32_t getSampleRate() const { return mStreamInternal->getSampleRate(); }
    int32_t getSamplesPerFrame() const { return mStreamInternal->getSamplesPerFrame();  }
    int32_t getFramesPerBurst() const { return mStreamInternal->getFramesPerBurst();  }

    aaudio_result_t registerStream(android::sp<AAudioServiceStreamShared> sharedStream);
    aaudio_result_t unregisterStream(android::sp<AAudioServiceStreamShared> sharedStream);
    aaudio_result_t startStream(android::sp<AAudioServiceStreamShared> sharedStream);
    aaudio_result_t stopStream(android::sp<AAudioServiceStreamShared> sharedStream);
    aaudio_result_t close();

    int32_t getRequestedDeviceId() const { return mRequestedDeviceId; }
    int32_t getDeviceId() const { return mStreamInternal->getDeviceId(); }

    aaudio_direction_t getDirection() const { return mStreamInternal->getDirection(); }

    void disconnectRegisteredStreams();

    virtual void *callbackLoop() = 0;

    // This should only be called from the AAudioEndpointManager under a mutex.
    int32_t getReferenceCount() const {
        return mReferenceCount;
    }

    // This should only be called from the AAudioEndpointManager under a mutex.
    void setReferenceCount(int32_t count) {
        mReferenceCount = count;
    }

    bool matches(const AAudioStreamConfiguration& configuration);

    virtual AudioStreamInternal *getStreamInternal() = 0;

    std::atomic<bool>        mCallbackEnabled{false};

    mutable std::mutex       mLockStreams;

    std::vector<android::sp<AAudioServiceStreamShared>> mRegisteredStreams;

    std::atomic<int>         mRunningStreams{0};

private:
    aaudio_result_t startSharingThread_l();
    aaudio_result_t stopSharingThread();

    AudioStreamInternal     *mStreamInternal = nullptr;
    int32_t                  mReferenceCount = 0;
    int32_t                  mRequestedDeviceId = 0;
};

} /* namespace aaudio */


#endif //AAUDIO_SERVICE_ENDPOINT_H
