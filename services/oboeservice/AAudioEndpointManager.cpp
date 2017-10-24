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

#define LOG_TAG "AAudioEndpointManager"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <assert.h>
#include <functional>
#include <map>
#include <mutex>
#include <sstream>
#include <utility/AAudioUtilities.h>

#include "AAudioEndpointManager.h"

using namespace android;
using namespace aaudio;

ANDROID_SINGLETON_STATIC_INSTANCE(AAudioEndpointManager);

AAudioEndpointManager::AAudioEndpointManager()
        : Singleton<AAudioEndpointManager>()
        , mInputs()
        , mOutputs() {
}

std::string AAudioEndpointManager::dump() const {
    std::stringstream result;
    const bool isLocked = AAudio_tryUntilTrue(
            [this]()->bool { return mLock.try_lock(); } /* f */,
            50 /* times */,
            20 /* sleepMs */);
    if (!isLocked) {
        result << "EndpointManager may be deadlocked\n";
    }

    result << "AAudioEndpointManager:" << "\n";
    size_t inputs = mInputs.size();
    result << "Input Endpoints: " << inputs << "\n";
    for (const auto &input : mInputs) {
        result << "  Input: " << input->dump() << "\n";
    }

    size_t outputs = mOutputs.size();
    result << "Output Endpoints: " << outputs << "\n";
    for (const auto &output : mOutputs) {
        result << "  Output: " << output->dump() << "\n";
    }

    if (isLocked) {
        mLock.unlock();
    }
    return result.str();
}

AAudioServiceEndpoint *AAudioEndpointManager::openEndpoint(AAudioService &audioService,
        const AAudioStreamConfiguration& configuration, aaudio_direction_t direction) {
    AAudioServiceEndpoint *endpoint = nullptr;
    AAudioServiceEndpointCapture *capture = nullptr;
    AAudioServiceEndpointPlay *player = nullptr;
    std::lock_guard<std::mutex> lock(mLock);

    // Try to find an existing endpoint.



    switch (direction) {
        case AAUDIO_DIRECTION_INPUT:
            for (AAudioServiceEndpoint *ep : mInputs) {
                if (ep->matches(configuration)) {
                    endpoint = ep;
                    break;
                }
            }
            break;
        case AAUDIO_DIRECTION_OUTPUT:
            for (AAudioServiceEndpoint *ep : mOutputs) {
                if (ep->matches(configuration)) {
                    endpoint = ep;
                    break;
                }
            }
            break;
        default:
            assert(false); // There are only two possible directions.
            break;
    }
    ALOGD("AAudioEndpointManager::openEndpoint(), found %p for device = %d, dir = %d",
          endpoint, configuration.getDeviceId(), (int)direction);

    // If we can't find an existing one then open a new one.
    if (endpoint == nullptr) {
        // we must call openStream with audioserver identity
        int64_t token = IPCThreadState::self()->clearCallingIdentity();
        switch(direction) {
            case AAUDIO_DIRECTION_INPUT:
                capture = new AAudioServiceEndpointCapture(audioService);
                endpoint = capture;
                break;
            case AAUDIO_DIRECTION_OUTPUT:
                player = new AAudioServiceEndpointPlay(audioService);
                endpoint = player;
                break;
            default:
                break;
        }

        if (endpoint != nullptr) {
            aaudio_result_t result = endpoint->open(configuration);
            if (result != AAUDIO_OK) {
                ALOGE("AAudioEndpointManager::findEndpoint(), open failed");
                delete endpoint;
                endpoint = nullptr;
            } else {
                switch(direction) {
                    case AAUDIO_DIRECTION_INPUT:
                        mInputs.push_back(capture);
                        break;
                    case AAUDIO_DIRECTION_OUTPUT:
                        mOutputs.push_back(player);
                        break;
                    default:
                        break;
                }
            }
        }
        ALOGD("AAudioEndpointManager::openEndpoint(), created %p for device = %d, dir = %d",
              endpoint, configuration.getDeviceId(), (int)direction);
        IPCThreadState::self()->restoreCallingIdentity(token);
    }

    if (endpoint != nullptr) {
        ALOGD("AAudioEndpointManager::openEndpoint(), sampleRate = %d, framesPerBurst = %d",
              endpoint->getSampleRate(), endpoint->getFramesPerBurst());
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
    ALOGD("AAudioEndpointManager::closeEndpoint(%p) newRefCount = %d",
          serviceEndpoint, newRefCount);

    // If no longer in use then close and delete it.
    if (newRefCount <= 0) {
        aaudio_direction_t direction = serviceEndpoint->getDirection();
        // Track endpoints based on requested deviceId because UNSPECIFIED
        // can change to a specific device after opening.
        int32_t deviceId = serviceEndpoint->getRequestedDeviceId();

        switch (direction) {
            case AAUDIO_DIRECTION_INPUT:
                mInputs.erase(
                  std::remove(mInputs.begin(), mInputs.end(), serviceEndpoint), mInputs.end());
                break;
            case AAUDIO_DIRECTION_OUTPUT:
                mOutputs.erase(
                  std::remove(mOutputs.begin(), mOutputs.end(), serviceEndpoint), mOutputs.end());
                break;
            default:
                break;
        }

        serviceEndpoint->close();
        ALOGD("AAudioEndpointManager::closeEndpoint() delete %p for device %d, dir = %d",
              serviceEndpoint, deviceId, (int)direction);
        delete serviceEndpoint;
    }
}
