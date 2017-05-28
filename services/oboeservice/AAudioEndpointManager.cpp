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

#define LOG_TAG "AAudioService"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <assert.h>
#include <map>
#include <mutex>

#include "AAudioEndpointManager.h"

using namespace android;
using namespace aaudio;

ANDROID_SINGLETON_STATIC_INSTANCE(AAudioEndpointManager);

AAudioEndpointManager::AAudioEndpointManager()
        : Singleton<AAudioEndpointManager>()
        , mInputs()
        , mOutputs() {
}

AAudioServiceEndpoint *AAudioEndpointManager::openEndpoint(AAudioService &audioService, int32_t deviceId,
                                                           aaudio_direction_t direction) {
    AAudioServiceEndpoint *endpoint = nullptr;
    std::lock_guard<std::mutex> lock(mLock);

    // Try to find an existing endpoint.
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
    ALOGD("AAudioEndpointManager::openEndpoint(), found %p for device = %d, dir = %d",
          endpoint, deviceId, (int)direction);

    // If we can't find an existing one then open a new one.
    if (endpoint == nullptr) {
        if (direction == AAUDIO_DIRECTION_INPUT) {
            AAudioServiceEndpointCapture *capture = new AAudioServiceEndpointCapture(audioService);
            if (capture->open(deviceId) != AAUDIO_OK) {
                ALOGE("AAudioEndpointManager::openEndpoint(), open failed");
                delete capture;
            } else {
                mInputs[deviceId] = capture;
                endpoint = capture;
            }
        } else if (direction == AAUDIO_DIRECTION_OUTPUT) {
            AAudioServiceEndpointPlay *player = new AAudioServiceEndpointPlay(audioService);
            if (player->open(deviceId) != AAUDIO_OK) {
                ALOGE("AAudioEndpointManager::openEndpoint(), open failed");
                delete player;
            } else {
                mOutputs[deviceId] = player;
                endpoint = player;
            }
        }

    }

    if (endpoint != nullptr) {
        // Increment the reference count under this lock.
        endpoint->setReferenceCount(endpoint->getReferenceCount() + 1);
    }
    return endpoint;
}

void AAudioEndpointManager::closeEndpoint(AAudioServiceEndpoint *serviceEndpoint) {
    std::lock_guard<std::mutex> lock(mLock);
    if (serviceEndpoint == nullptr) {
        return;
    }

    // Decrement the reference count under this lock.
    int32_t newRefCount = serviceEndpoint->getReferenceCount() - 1;
    serviceEndpoint->setReferenceCount(newRefCount);
    if (newRefCount <= 0) {
        aaudio_direction_t direction = serviceEndpoint->getDirection();
        int32_t deviceId = serviceEndpoint->getDeviceId();

        switch (direction) {
            case AAUDIO_DIRECTION_INPUT:
                mInputs.erase(deviceId);
                break;
            case AAUDIO_DIRECTION_OUTPUT:
                mOutputs.erase(deviceId);
                break;
        }

        serviceEndpoint->close();
        delete serviceEndpoint;
    }
}
