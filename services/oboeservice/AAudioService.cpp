/*
 * Copyright (C) 2016 The Android Open Source Project
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

//#include <time.h>
//#include <pthread.h>

#include <aaudio/AAudio.h>
#include <mediautils/SchedulingPolicyService.h>
#include <utils/String16.h>

#include "binding/AAudioServiceMessage.h"
#include "AAudioService.h"
#include "AAudioServiceStreamMMAP.h"
#include "AAudioServiceStreamShared.h"
#include "AAudioServiceStreamMMAP.h"
#include "binding/IAAudioService.h"
#include "utility/HandleTracker.h"

using namespace android;
using namespace aaudio;

typedef enum
{
    AAUDIO_HANDLE_TYPE_STREAM
} aaudio_service_handle_type_t;
static_assert(AAUDIO_HANDLE_TYPE_STREAM < HANDLE_TRACKER_MAX_TYPES, "Too many handle types.");

android::AAudioService::AAudioService()
    : BnAAudioService() {
}

AAudioService::~AAudioService() {
}

aaudio_handle_t AAudioService::openStream(const aaudio::AAudioStreamRequest &request,
                                          aaudio::AAudioStreamConfiguration &configurationOutput) {
    aaudio_result_t result = AAUDIO_OK;
    AAudioServiceStreamBase *serviceStream = nullptr;
    const AAudioStreamConfiguration &configurationInput = request.getConstantConfiguration();
    bool sharingModeMatchRequired = request.isSharingModeMatchRequired();
    aaudio_sharing_mode_t sharingMode = configurationInput.getSharingMode();

    if (sharingMode != AAUDIO_SHARING_MODE_EXCLUSIVE && sharingMode != AAUDIO_SHARING_MODE_SHARED) {
        ALOGE("AAudioService::openStream(): unrecognized sharing mode = %d", sharingMode);
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }

    if (sharingMode == AAUDIO_SHARING_MODE_EXCLUSIVE) {
        serviceStream = new AAudioServiceStreamMMAP();
        result = serviceStream->open(request, configurationOutput);
        if (result != AAUDIO_OK) {
            // fall back to using a shared stream
            ALOGD("AAudioService::openStream(), EXCLUSIVE mode failed");
            delete serviceStream;
            serviceStream = nullptr;
        } else {
            configurationOutput.setSharingMode(AAUDIO_SHARING_MODE_EXCLUSIVE);
        }
    }

    // if SHARED requested or if EXCLUSIVE failed
    if (sharingMode == AAUDIO_SHARING_MODE_SHARED
         || (serviceStream == nullptr && !sharingModeMatchRequired)) {
        serviceStream =  new AAudioServiceStreamShared(*this);
        result = serviceStream->open(request, configurationOutput);
        configurationOutput.setSharingMode(AAUDIO_SHARING_MODE_SHARED);
    }

    if (result != AAUDIO_OK) {
        delete serviceStream;
        ALOGE("AAudioService::openStream(): failed, return %d", result);
        return result;
    } else {
        aaudio_handle_t handle = mHandleTracker.put(AAUDIO_HANDLE_TYPE_STREAM, serviceStream);
        ALOGV("AAudioService::openStream(): handle = 0x%08X", handle);
        if (handle < 0) {
            ALOGE("AAudioService::openStream(): handle table full");
            delete serviceStream;
        }
        return handle;
    }
}

aaudio_result_t AAudioService::closeStream(aaudio_handle_t streamHandle) {
    AAudioServiceStreamBase *serviceStream = (AAudioServiceStreamBase *)
            mHandleTracker.remove(AAUDIO_HANDLE_TYPE_STREAM,
                                  streamHandle);
    ALOGV("AAudioService.closeStream(0x%08X)", streamHandle);
    if (serviceStream != nullptr) {
        serviceStream->close();
        delete serviceStream;
        return AAUDIO_OK;
    }
    return AAUDIO_ERROR_INVALID_HANDLE;
}

AAudioServiceStreamBase *AAudioService::convertHandleToServiceStream(
        aaudio_handle_t streamHandle) const {
    return (AAudioServiceStreamBase *) mHandleTracker.get(AAUDIO_HANDLE_TYPE_STREAM,
                              (aaudio_handle_t)streamHandle);
}

aaudio_result_t AAudioService::getStreamDescription(
                aaudio_handle_t streamHandle,
                aaudio::AudioEndpointParcelable &parcelable) {
    AAudioServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream == nullptr) {
        ALOGE("AAudioService::getStreamDescription(), illegal stream handle = 0x%0x", streamHandle);
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    aaudio_result_t result = serviceStream->getDescription(parcelable);
    // parcelable.dump();
    return result;
}

aaudio_result_t AAudioService::startStream(aaudio_handle_t streamHandle) {
    AAudioServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream == nullptr) {
        ALOGE("AAudioService::startStream(), illegal stream handle = 0x%0x", streamHandle);
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    aaudio_result_t result = serviceStream->start();
    return result;
}

aaudio_result_t AAudioService::pauseStream(aaudio_handle_t streamHandle) {
    AAudioServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream == nullptr) {
        ALOGE("AAudioService::pauseStream(), illegal stream handle = 0x%0x", streamHandle);
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    aaudio_result_t result = serviceStream->pause();
    return result;
}

aaudio_result_t AAudioService::stopStream(aaudio_handle_t streamHandle) {
    AAudioServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream == nullptr) {
        ALOGE("AAudioService::pauseStream(), illegal stream handle = 0x%0x", streamHandle);
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    aaudio_result_t result = serviceStream->stop();
    return result;
}

aaudio_result_t AAudioService::flushStream(aaudio_handle_t streamHandle) {
    AAudioServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream == nullptr) {
        ALOGE("AAudioService::flushStream(), illegal stream handle = 0x%0x", streamHandle);
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    return serviceStream->flush();
}

aaudio_result_t AAudioService::registerAudioThread(aaudio_handle_t streamHandle,
                                                         pid_t clientProcessId,
                                                         pid_t clientThreadId,
                                                         int64_t periodNanoseconds) {
    AAudioServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream == nullptr) {
        ALOGE("AAudioService::registerAudioThread(), illegal stream handle = 0x%0x", streamHandle);
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    if (serviceStream->getRegisteredThread() != AAudioServiceStreamBase::ILLEGAL_THREAD_ID) {
        ALOGE("AAudioService::registerAudioThread(), thread already registered");
        return AAUDIO_ERROR_INVALID_STATE;
    }
    serviceStream->setRegisteredThread(clientThreadId);
    int err = android::requestPriority(clientProcessId, clientThreadId,
                                       DEFAULT_AUDIO_PRIORITY, true /* isForApp */);
    if (err != 0){
        ALOGE("AAudioService::registerAudioThread() failed, errno = %d, priority = %d",
              errno, DEFAULT_AUDIO_PRIORITY);
        return AAUDIO_ERROR_INTERNAL;
    } else {
        return AAUDIO_OK;
    }
}

aaudio_result_t AAudioService::unregisterAudioThread(aaudio_handle_t streamHandle,
                                                     pid_t clientProcessId,
                                                     pid_t clientThreadId) {
    AAudioServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream == nullptr) {
        ALOGE("AAudioService::unregisterAudioThread(), illegal stream handle = 0x%0x",
              streamHandle);
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    if (serviceStream->getRegisteredThread() != clientThreadId) {
        ALOGE("AAudioService::unregisterAudioThread(), wrong thread");
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }
    serviceStream->setRegisteredThread(0);
    return AAUDIO_OK;
}
