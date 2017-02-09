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

#include <assert.h>
#include <map>
#include <mutex>
#include <utils/Singleton.h>

#include "AAudioEndpointManager.h"
#include "AAudioServiceEndpoint.h"

using namespace android;
using namespace aaudio;

ANDROID_SINGLETON_STATIC_INSTANCE(AAudioEndpointManager);

AAudioEndpointManager::AAudioEndpointManager()
        : Singleton<AAudioEndpointManager>() {
}

AAudioServiceEndpoint *AAudioEndpointManager::findEndpoint(AAudioService &audioService, int32_t deviceId,
                                                           aaudio_direction_t direction) {
    AAudioServiceEndpoint *endpoint = nullptr;
    std::lock_guard<std::mutex> lock(mLock);
    switch (direction) {
        case AAUDIO_DIRECTION_INPUT:
            endpoint = mInputs[deviceId];
            break;
        case AAUDIO_DIRECTION_OUTPUT:
            endpoint = mOutputs[deviceId];
            break;
        default:
            assert(false); // There are only two possible directions.
            break;
    }

    // If we can't find an existing one then open one.
    ALOGD("AAudioEndpointManager::findEndpoint(), found %p", endpoint);
    if (endpoint == nullptr) {
        endpoint = new AAudioServiceEndpoint(audioService);
        if (endpoint->open(deviceId, direction) != AAUDIO_OK) {
            ALOGD("AAudioEndpointManager::findEndpoint(), open failed");
            delete endpoint;
            endpoint = nullptr;
        } else {
            switch(direction) {
                case AAUDIO_DIRECTION_INPUT:
                    mInputs[deviceId] = endpoint;
                    break;
                case AAUDIO_DIRECTION_OUTPUT:
                    mOutputs[deviceId] = endpoint;
                    break;
            }
        }
    }
    return endpoint;
}

// FIXME add reference counter for serviceEndpoints and removed on last use.

void AAudioEndpointManager::removeEndpoint(AAudioServiceEndpoint *serviceEndpoint) {
    aaudio_direction_t direction = serviceEndpoint->getDirection();
    int32_t deviceId = serviceEndpoint->getDeviceId();

    std::lock_guard<std::mutex> lock(mLock);
    switch(direction) {
        case AAUDIO_DIRECTION_INPUT:
            mInputs.erase(deviceId);
            break;
        case AAUDIO_DIRECTION_OUTPUT:
            mOutputs.erase(deviceId);
            break;
    }
}