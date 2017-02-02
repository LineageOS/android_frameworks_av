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

#include <time.h>
#include <pthread.h>

#include <aaudio/AAudioDefinitions.h>

#include "HandleTracker.h"
#include "IAAudioService.h"
#include "AAudioServiceDefinitions.h"
#include "AAudioService.h"
#include "AAudioServiceStreamFakeHal.h"

using namespace android;
using namespace aaudio;

typedef enum
{
    AAUDIO_HANDLE_TYPE_DUMMY1, // TODO remove DUMMYs
    AAUDIO_HANDLE_TYPE_DUMMY2, // make server handles different than client
    AAUDIO_HANDLE_TYPE_STREAM,
    AAUDIO_HANDLE_TYPE_COUNT
} aaudio_service_handle_type_t;
static_assert(AAUDIO_HANDLE_TYPE_COUNT <= HANDLE_TRACKER_MAX_TYPES, "Too many handle types.");

android::AAudioService::AAudioService()
    : BnAAudioService() {
}

AAudioService::~AAudioService() {
}

aaudio_handle_t AAudioService::openStream(aaudio::AAudioStreamRequest &request,
                                                aaudio::AAudioStreamConfiguration &configuration) {
    AAudioServiceStreamBase *serviceStream =  new AAudioServiceStreamFakeHal();
    ALOGD("AAudioService::openStream(): created serviceStream = %p", serviceStream);
    aaudio_result_t result = serviceStream->open(request, configuration);
    if (result < 0) {
        ALOGE("AAudioService::openStream(): open returned %d", result);
        return result;
    } else {
        AAudioStream handle = mHandleTracker.put(AAUDIO_HANDLE_TYPE_STREAM, serviceStream);
        ALOGD("AAudioService::openStream(): handle = 0x%08X", handle);
        if (handle < 0) {
            delete serviceStream;
        }
        return handle;
    }
}

aaudio_result_t AAudioService::closeStream(aaudio_handle_t streamHandle) {
    AAudioServiceStreamBase *serviceStream = (AAudioServiceStreamBase *)
            mHandleTracker.remove(AAUDIO_HANDLE_TYPE_STREAM,
                                  streamHandle);
    ALOGD("AAudioService.closeStream(0x%08X)", streamHandle);
    if (serviceStream != nullptr) {
        ALOGD("AAudioService::closeStream(): deleting serviceStream = %p", serviceStream);
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
    ALOGD("AAudioService::getStreamDescription(), serviceStream = %p", serviceStream);
    if (serviceStream == nullptr) {
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    return serviceStream->getDescription(parcelable);
}

aaudio_result_t AAudioService::startStream(aaudio_handle_t streamHandle) {
    AAudioServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    ALOGD("AAudioService::startStream(), serviceStream = %p", serviceStream);
    if (serviceStream == nullptr) {
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    aaudio_result_t result = serviceStream->start();
    return result;
}

aaudio_result_t AAudioService::pauseStream(aaudio_handle_t streamHandle) {
    AAudioServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    ALOGD("AAudioService::pauseStream(), serviceStream = %p", serviceStream);
    if (serviceStream == nullptr) {
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    aaudio_result_t result = serviceStream->pause();
    return result;
}

aaudio_result_t AAudioService::flushStream(aaudio_handle_t streamHandle) {
    AAudioServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    ALOGD("AAudioService::flushStream(), serviceStream = %p", serviceStream);
    if (serviceStream == nullptr) {
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    return serviceStream->flush();
}

aaudio_result_t AAudioService::registerAudioThread(aaudio_handle_t streamHandle,
                                                         pid_t clientThreadId,
                                                         aaudio_nanoseconds_t periodNanoseconds) {
    AAudioServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    ALOGD("AAudioService::registerAudioThread(), serviceStream = %p", serviceStream);
    if (serviceStream == nullptr) {
        ALOGE("AAudioService::registerAudioThread(), serviceStream == nullptr");
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    if (serviceStream->getRegisteredThread() != AAudioServiceStreamBase::ILLEGAL_THREAD_ID) {
        ALOGE("AAudioService::registerAudioThread(), thread already registered");
        return AAUDIO_ERROR_INVALID_ORDER;
    }
    serviceStream->setRegisteredThread(clientThreadId);
    // Boost client thread to SCHED_FIFO
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = 2; // TODO use 'requestPriority' function from frameworks/av/media/utils
    int err = sched_setscheduler(clientThreadId, SCHED_FIFO, &sp);
    if (err != 0){
        ALOGE("AAudioService::sched_setscheduler() failed, errno = %d, priority = %d",
              errno, sp.sched_priority);
        return AAUDIO_ERROR_INTERNAL;
    } else {
        return AAUDIO_OK;
    }
}

aaudio_result_t AAudioService::unregisterAudioThread(aaudio_handle_t streamHandle,
                                                           pid_t clientThreadId) {
    AAudioServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    ALOGI("AAudioService::unregisterAudioThread(), serviceStream = %p", serviceStream);
    if (serviceStream == nullptr) {
        ALOGE("AAudioService::unregisterAudioThread(), serviceStream == nullptr");
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    if (serviceStream->getRegisteredThread() != clientThreadId) {
        ALOGE("AAudioService::unregisterAudioThread(), wrong thread");
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }
    serviceStream->setRegisteredThread(0);
    return AAUDIO_OK;
}
