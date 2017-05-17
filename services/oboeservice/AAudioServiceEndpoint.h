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
#include "binding/AAudioServiceMessage.h"
#include "AAudioServiceStreamShared.h"
#include "AAudioServiceStreamMMAP.h"
#include "AAudioMixer.h"
#include "AAudioService.h"

namespace aaudio {

class AAudioServiceEndpoint {
public:
    explicit AAudioServiceEndpoint(android::AAudioService &audioService);
    virtual ~AAudioServiceEndpoint();

    aaudio_result_t open(int32_t deviceId, aaudio_direction_t direction);

    int32_t getSampleRate() const { return mStreamInternal.getSampleRate(); }
    int32_t getSamplesPerFrame() const { return mStreamInternal.getSamplesPerFrame();  }
    int32_t getFramesPerBurst() const { return mStreamInternal.getFramesPerBurst();  }

    aaudio_result_t registerStream(AAudioServiceStreamShared *sharedStream);
    aaudio_result_t unregisterStream(AAudioServiceStreamShared *sharedStream);
    aaudio_result_t startStream(AAudioServiceStreamShared *sharedStream);
    aaudio_result_t stopStream(AAudioServiceStreamShared *sharedStream);
    aaudio_result_t close();

    int32_t getDeviceId() const { return mStreamInternal.getDeviceId(); }

    aaudio_direction_t getDirection() const { return mStreamInternal.getDirection(); }

    void disconnectRegisteredStreams();

    void *callbackLoop();

    // This should only be called from the AAudioEndpointManager under a mutex.
    int32_t getReferenceCount() const {
        return mReferenceCount;
    }

    // This should only be called from the AAudioEndpointManager under a mutex.
    void setReferenceCount(int32_t count) {
        mReferenceCount = count;
    }

private:
    aaudio_result_t startMixer_l();
    aaudio_result_t stopMixer_l();

    int64_t calculateReasonableTimeout(int32_t framesPerOperation);

    AudioStreamInternal      mStreamInternal;
    AAudioMixer              mMixer;

    std::atomic<bool>        mCallbackEnabled;
    int32_t                  mReferenceCount = 0;
    bool                     mLatencyTuningEnabled = false; // TODO implement tuning

    std::mutex               mLockStreams;
    std::vector<AAudioServiceStreamShared *> mRegisteredStreams;
    std::vector<AAudioServiceStreamShared *> mRunningStreams;

};

} /* namespace aaudio */


#endif //AAUDIO_SERVICE_ENDPOINT_H
