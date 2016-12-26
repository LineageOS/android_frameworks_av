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

#define LOG_TAG "OboeService"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <time.h>
#include <pthread.h>

#include <oboe/OboeDefinitions.h>

#include "HandleTracker.h"
#include "IOboeAudioService.h"
#include "OboeService.h"
#include "OboeAudioService.h"
#include "OboeServiceStreamFakeHal.h"

using namespace android;
using namespace oboe;

typedef enum
{
    OBOE_HANDLE_TYPE_STREAM,
    OBOE_HANDLE_TYPE_COUNT
} oboe_service_handle_type_t;
static_assert(OBOE_HANDLE_TYPE_COUNT <= HANDLE_TRACKER_MAX_TYPES, "Too many handle types.");

oboe_handle_t OboeAudioService::openStream(oboe::OboeStreamRequest &request,
                                                oboe::OboeStreamConfiguration &configuration) {
    OboeServiceStreamBase *serviceStream =  new OboeServiceStreamFakeHal();
    ALOGD("OboeAudioService::openStream(): created serviceStream = %p", serviceStream);
    oboe_result_t result = serviceStream->open(request, configuration);
    if (result < 0) {
        ALOGE("OboeAudioService::openStream(): open returned %d", result);
        return result;
    } else {
        OboeStream handle = mHandleTracker.put(OBOE_HANDLE_TYPE_STREAM, serviceStream);
        ALOGD("OboeAudioService::openStream(): handle = 0x%08X", handle);
        if (handle < 0) {
            delete serviceStream;
        }
        return handle;
    }
}

oboe_result_t OboeAudioService::closeStream(oboe_handle_t streamHandle) {
    OboeServiceStreamBase *serviceStream = (OboeServiceStreamBase *)
            mHandleTracker.remove(OBOE_HANDLE_TYPE_STREAM,
                                  streamHandle);
    ALOGI("OboeAudioService.closeStream(0x%08X)", streamHandle);
    if (serviceStream != nullptr) {
        ALOGD("OboeAudioService::closeStream(): deleting serviceStream = %p", serviceStream);
        delete serviceStream;
        return OBOE_OK;
    }
    return OBOE_ERROR_INVALID_HANDLE;
}

OboeServiceStreamBase *OboeAudioService::convertHandleToServiceStream(
        oboe_handle_t streamHandle) const {
    return (OboeServiceStreamBase *) mHandleTracker.get(OBOE_HANDLE_TYPE_STREAM,
                              (oboe_handle_t)streamHandle);
}

oboe_result_t OboeAudioService::getStreamDescription(
                oboe_handle_t streamHandle,
                oboe::AudioEndpointParcelable &parcelable) {
    ALOGI("OboeAudioService::getStreamDescriptor(), streamHandle = 0x%08x", streamHandle);
    OboeServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    ALOGI("OboeAudioService::getStreamDescriptor(), serviceStream = %p", serviceStream);
    if (serviceStream == nullptr) {
        return OBOE_ERROR_INVALID_HANDLE;
    }
    return serviceStream->getDescription(parcelable);
}

oboe_result_t OboeAudioService::startStream(oboe_handle_t streamHandle) {
    OboeServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    ALOGI("OboeAudioService::startStream(), serviceStream = %p", serviceStream);
    if (serviceStream == nullptr) {
        return OBOE_ERROR_INVALID_HANDLE;
    }
    mLatestHandle = streamHandle;
    return serviceStream->start();
}

oboe_result_t OboeAudioService::pauseStream(oboe_handle_t streamHandle) {
    OboeServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    ALOGI("OboeAudioService::pauseStream(), serviceStream = %p", serviceStream);
    if (serviceStream == nullptr) {
        return OBOE_ERROR_INVALID_HANDLE;
    }
    return serviceStream->pause();
}

oboe_result_t OboeAudioService::flushStream(oboe_handle_t streamHandle) {
    OboeServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    ALOGI("OboeAudioService::flushStream(), serviceStream = %p", serviceStream);
    if (serviceStream == nullptr) {
        return OBOE_ERROR_INVALID_HANDLE;
    }
    return serviceStream->flush();
}

void OboeAudioService::tickle() {
    OboeServiceStreamBase *serviceStream = convertHandleToServiceStream(mLatestHandle);
    //ALOGI("OboeAudioService::tickle(), serviceStream = %p", serviceStream);
    if (serviceStream != nullptr) {
        serviceStream->tickle();
    }
}

oboe_result_t OboeAudioService::registerAudioThread(oboe_handle_t streamHandle,
                                                         pid_t clientThreadId,
                                                         oboe_nanoseconds_t periodNanoseconds) {
    OboeServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    ALOGI("OboeAudioService::registerAudioThread(), serviceStream = %p", serviceStream);
    if (serviceStream == nullptr) {
        ALOGE("OboeAudioService::registerAudioThread(), serviceStream == nullptr");
        return OBOE_ERROR_INVALID_HANDLE;
    }
    if (serviceStream->getRegisteredThread() != OboeServiceStreamBase::ILLEGAL_THREAD_ID) {
        ALOGE("OboeAudioService::registerAudioThread(), thread already registered");
        return OBOE_ERROR_INVALID_ORDER;
    }
    serviceStream->setRegisteredThread(clientThreadId);
    // Boost client thread to SCHED_FIFO
    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = 2; // TODO use 'requestPriority' function from frameworks/av/media/utils
    int err = sched_setscheduler(clientThreadId, SCHED_FIFO, &sp);
    if (err != 0){
        ALOGE("OboeAudioService::sched_setscheduler() failed, errno = %d, priority = %d",
              errno, sp.sched_priority);
        return OBOE_ERROR_INTERNAL;
    } else {
        return OBOE_OK;
    }
}

oboe_result_t OboeAudioService::unregisterAudioThread(oboe_handle_t streamHandle,
                                                           pid_t clientThreadId) {
    OboeServiceStreamBase *serviceStream = convertHandleToServiceStream(streamHandle);
    ALOGI("OboeAudioService::unregisterAudioThread(), serviceStream = %p", serviceStream);
    if (serviceStream == nullptr) {
        ALOGE("OboeAudioService::unregisterAudioThread(), serviceStream == nullptr");
        return OBOE_ERROR_INVALID_HANDLE;
    }
    if (serviceStream->getRegisteredThread() != clientThreadId) {
        ALOGE("OboeAudioService::unregisterAudioThread(), wrong thread");
        return OBOE_ERROR_ILLEGAL_ARGUMENT;
    }
    serviceStream->setRegisteredThread(0);
    return OBOE_OK;
}
