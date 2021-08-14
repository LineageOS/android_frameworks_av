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

#include <iomanip>
#include <iostream>
#include <sstream>

#include <android/content/AttributionSourceState.h>
#include <aaudio/AAudio.h>
#include <media/AidlConversion.h>
#include <mediautils/ServiceUtilities.h>
#include <utils/String16.h>

#include "binding/AAudioServiceMessage.h"
#include "AAudioClientTracker.h"
#include "AAudioEndpointManager.h"
#include "AAudioService.h"
#include "AAudioServiceStreamMMAP.h"
#include "AAudioServiceStreamShared.h"

using namespace android;
using namespace aaudio;

#define MAX_STREAMS_PER_PROCESS   8
#define AIDL_RETURN(x) { *_aidl_return = (x); return Status::ok(); }

#define VALUE_OR_RETURN_ILLEGAL_ARG_STATUS(x) \
    ({ auto _tmp = (x); \
       if (!_tmp.ok()) AIDL_RETURN(AAUDIO_ERROR_ILLEGAL_ARGUMENT); \
       std::move(_tmp.value()); })

using android::AAudioService;
using android::content::AttributionSourceState;
using binder::Status;

android::AAudioService::AAudioService()
    : BnAAudioService(),
      mAdapter(this) {
    // TODO consider using geteuid()
    // TODO b/182392769: use attribution source util
    mAudioClient.attributionSource.uid = VALUE_OR_FATAL(legacy2aidl_uid_t_int32_t(getuid()));
    mAudioClient.attributionSource.pid = VALUE_OR_FATAL(legacy2aidl_pid_t_int32_t(getpid()));
    mAudioClient.attributionSource.packageName = std::nullopt;
    mAudioClient.attributionSource.attributionTag = std::nullopt;
    AAudioClientTracker::getInstance().setAAudioService(this);
}

status_t AAudioService::dump(int fd, const Vector<String16>& args) {
    std::string result;

    if (!dumpAllowed()) {
        std::stringstream ss;
        ss << "Permission Denial: can't dump AAudioService from pid="
                << IPCThreadState::self()->getCallingPid() << ", uid="
                << IPCThreadState::self()->getCallingUid() << "\n";
        result = ss.str();
        ALOGW("%s", result.c_str());
    } else {
        result = "------------ AAudio Service ------------\n"
                 + mStreamTracker.dump()
                 + AAudioClientTracker::getInstance().dump()
                 + AAudioEndpointManager::getInstance().dump();
    }
    (void)write(fd, result.c_str(), result.size());
    return NO_ERROR;
}

Status AAudioService::registerClient(const sp<IAAudioClient> &client) {
    pid_t pid = IPCThreadState::self()->getCallingPid();
    AAudioClientTracker::getInstance().registerClient(pid, client);
    return Status::ok();
}

Status
AAudioService::openStream(const StreamRequest &_request, StreamParameters* _paramsOut,
                          int32_t *_aidl_return) {
    static_assert(std::is_same_v<aaudio_result_t, std::decay_t<typeof(*_aidl_return)>>);

    // Create wrapper objects for simple usage of the parcelables.
    const AAudioStreamRequest request(_request);
    AAudioStreamConfiguration paramsOut;

    // A lock in is used to order the opening of endpoints when an
    // EXCLUSIVE endpoint is stolen. We want the order to be:
    // 1) Thread A opens exclusive MMAP endpoint
    // 2) Thread B wants to open an exclusive MMAP endpoint so it steals the one from A
    //    under this lock.
    // 3) Thread B opens a shared MMAP endpoint.
    // 4) Thread A can then get the lock and also open a shared stream.
    // Without the lock. Thread A might sneak in and reallocate an exclusive stream
    // before B can open the shared stream.
    std::unique_lock<std::recursive_mutex> lock(mOpenLock);

    aaudio_result_t result = AAUDIO_OK;
    sp<AAudioServiceStreamBase> serviceStream;
    const AAudioStreamConfiguration &configurationInput = request.getConstantConfiguration();
    bool sharingModeMatchRequired = request.isSharingModeMatchRequired();
    aaudio_sharing_mode_t sharingMode = configurationInput.getSharingMode();

    // Enforce limit on client processes.
    AttributionSourceState attributionSource = request.getAttributionSource();
    pid_t pid = IPCThreadState::self()->getCallingPid();
    attributionSource.pid = VALUE_OR_RETURN_ILLEGAL_ARG_STATUS(
        legacy2aidl_pid_t_int32_t(pid));
    attributionSource.uid = VALUE_OR_RETURN_ILLEGAL_ARG_STATUS(
        legacy2aidl_uid_t_int32_t(IPCThreadState::self()->getCallingUid()));
    attributionSource.token = sp<BBinder>::make();
    if (attributionSource.pid != mAudioClient.attributionSource.pid) {
        int32_t count = AAudioClientTracker::getInstance().getStreamCount(pid);
        if (count >= MAX_STREAMS_PER_PROCESS) {
            ALOGE("openStream(): exceeded max streams per process %d >= %d",
                  count,  MAX_STREAMS_PER_PROCESS);
            AIDL_RETURN(AAUDIO_ERROR_UNAVAILABLE);
        }
    }

    if (sharingMode != AAUDIO_SHARING_MODE_EXCLUSIVE && sharingMode != AAUDIO_SHARING_MODE_SHARED) {
        ALOGE("openStream(): unrecognized sharing mode = %d", sharingMode);
        AIDL_RETURN(AAUDIO_ERROR_ILLEGAL_ARGUMENT);
    }

    if (sharingMode == AAUDIO_SHARING_MODE_EXCLUSIVE
        && AAudioClientTracker::getInstance().isExclusiveEnabled(pid)) {
        // only trust audioserver for in service indication
        bool inService = false;
        if (isCallerInService()) {
            inService = request.isInService();
        }
        serviceStream = new AAudioServiceStreamMMAP(*this, inService);
        result = serviceStream->open(request);
        if (result != AAUDIO_OK) {
            // Clear it so we can possibly fall back to using a shared stream.
            ALOGW("openStream(), could not open in EXCLUSIVE mode");
            serviceStream.clear();
        }
    }

    // Try SHARED if SHARED requested or if EXCLUSIVE failed.
    if (sharingMode == AAUDIO_SHARING_MODE_SHARED) {
        serviceStream =  new AAudioServiceStreamShared(*this);
        result = serviceStream->open(request);
    } else if (serviceStream.get() == nullptr && !sharingModeMatchRequired) {
        aaudio::AAudioStreamRequest modifiedRequest = request;
        // Overwrite the original EXCLUSIVE mode with SHARED.
        modifiedRequest.getConfiguration().setSharingMode(AAUDIO_SHARING_MODE_SHARED);
        serviceStream =  new AAudioServiceStreamShared(*this);
        result = serviceStream->open(modifiedRequest);
    }

    if (result != AAUDIO_OK) {
        serviceStream.clear();
        AIDL_RETURN(result);
    } else {
        aaudio_handle_t handle = mStreamTracker.addStreamForHandle(serviceStream.get());
        serviceStream->setHandle(handle);
        AAudioClientTracker::getInstance().registerClientStream(pid, serviceStream);
        paramsOut.copyFrom(*serviceStream);
        *_paramsOut = std::move(paramsOut).parcelable();
        // Log open in MediaMetrics after we have the handle because we need the handle to
        // create the metrics ID.
        serviceStream->logOpen(handle);
        ALOGV("%s(): return handle = 0x%08X", __func__, handle);
        AIDL_RETURN(handle);
    }
}

Status AAudioService::closeStream(int32_t streamHandle, int32_t *_aidl_return) {
    static_assert(std::is_same_v<aaudio_result_t, std::decay_t<typeof(*_aidl_return)>>);

    // Check permission and ownership first.
    sp<AAudioServiceStreamBase> serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream.get() == nullptr) {
        ALOGE("closeStream(0x%0x), illegal stream handle", streamHandle);
        AIDL_RETURN(AAUDIO_ERROR_INVALID_HANDLE);
    }
    AIDL_RETURN(closeStream(serviceStream));
}

Status AAudioService::getStreamDescription(int32_t streamHandle, Endpoint* endpoint,
                                           int32_t *_aidl_return) {
    static_assert(std::is_same_v<aaudio_result_t, std::decay_t<typeof(*_aidl_return)>>);

    sp<AAudioServiceStreamBase> serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream.get() == nullptr) {
        ALOGE("getStreamDescription(), illegal stream handle = 0x%0x", streamHandle);
        AIDL_RETURN(AAUDIO_ERROR_INVALID_HANDLE);
    }
    AudioEndpointParcelable endpointParcelable;
    aaudio_result_t result = serviceStream->getDescription(endpointParcelable);
    if (result == AAUDIO_OK) {
        *endpoint = std::move(endpointParcelable).parcelable();
    }
    AIDL_RETURN(result);
}

Status AAudioService::startStream(int32_t streamHandle, int32_t *_aidl_return) {
    static_assert(std::is_same_v<aaudio_result_t, std::decay_t<typeof(*_aidl_return)>>);

    sp<AAudioServiceStreamBase> serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream.get() == nullptr) {
        ALOGW("%s(), invalid streamHandle = 0x%0x", __func__, streamHandle);
        AIDL_RETURN(AAUDIO_ERROR_INVALID_HANDLE);
    }
    AIDL_RETURN(serviceStream->start());
}

Status AAudioService::pauseStream(int32_t streamHandle, int32_t *_aidl_return) {
    static_assert(std::is_same_v<aaudio_result_t, std::decay_t<typeof(*_aidl_return)>>);

    sp<AAudioServiceStreamBase> serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream.get() == nullptr) {
        ALOGW("%s(), invalid streamHandle = 0x%0x", __func__, streamHandle);
        AIDL_RETURN(AAUDIO_ERROR_INVALID_HANDLE);
    }
    AIDL_RETURN(serviceStream->pause());
}

Status AAudioService::stopStream(int32_t streamHandle, int32_t *_aidl_return) {
    static_assert(std::is_same_v<aaudio_result_t, std::decay_t<typeof(*_aidl_return)>>);

    sp<AAudioServiceStreamBase> serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream.get() == nullptr) {
        ALOGW("%s(), invalid streamHandle = 0x%0x", __func__, streamHandle);
        AIDL_RETURN(AAUDIO_ERROR_INVALID_HANDLE);
    }
    AIDL_RETURN(serviceStream->stop());
}

Status AAudioService::flushStream(int32_t streamHandle, int32_t *_aidl_return) {
    static_assert(std::is_same_v<aaudio_result_t, std::decay_t<typeof(*_aidl_return)>>);

    sp<AAudioServiceStreamBase> serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream.get() == nullptr) {
        ALOGW("%s(), invalid streamHandle = 0x%0x", __func__, streamHandle);
        AIDL_RETURN(AAUDIO_ERROR_INVALID_HANDLE);
    }
    AIDL_RETURN(serviceStream->flush());
}

Status AAudioService::registerAudioThread(int32_t streamHandle, int32_t clientThreadId, int64_t periodNanoseconds,
                                          int32_t *_aidl_return) {
    static_assert(std::is_same_v<aaudio_result_t, std::decay_t<typeof(*_aidl_return)>>);

    sp<AAudioServiceStreamBase> serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream.get() == nullptr) {
        ALOGW("%s(), invalid streamHandle = 0x%0x", __func__, streamHandle);
        AIDL_RETURN(AAUDIO_ERROR_INVALID_HANDLE);
    }
    int32_t priority = isCallerInService()
        ? kRealTimeAudioPriorityService : kRealTimeAudioPriorityClient;
    AIDL_RETURN(serviceStream->registerAudioThread(clientThreadId, priority));
}

Status AAudioService::unregisterAudioThread(int32_t streamHandle, int32_t clientThreadId,
                                            int32_t *_aidl_return) {
    static_assert(std::is_same_v<aaudio_result_t, std::decay_t<typeof(*_aidl_return)>>);

    sp<AAudioServiceStreamBase> serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream.get() == nullptr) {
        ALOGW("%s(), invalid streamHandle = 0x%0x", __func__, streamHandle);
        AIDL_RETURN(AAUDIO_ERROR_INVALID_HANDLE);
    }
    AIDL_RETURN(serviceStream->unregisterAudioThread(clientThreadId));
}

bool AAudioService::isCallerInService() {
    pid_t clientPid = VALUE_OR_FATAL(aidl2legacy_int32_t_pid_t(mAudioClient.attributionSource.pid));
    uid_t clientUid = VALUE_OR_FATAL(aidl2legacy_int32_t_uid_t(mAudioClient.attributionSource.uid));
    return clientPid == IPCThreadState::self()->getCallingPid() &&
        clientUid == IPCThreadState::self()->getCallingUid();
}

aaudio_result_t AAudioService::closeStream(sp<AAudioServiceStreamBase> serviceStream) {
    // This is protected by a lock in AAudioClientTracker.
    // It is safe to unregister the same stream twice.
    pid_t pid = serviceStream->getOwnerProcessId();
    AAudioClientTracker::getInstance().unregisterClientStream(pid, serviceStream);
    // This is protected by a lock in mStreamTracker.
    // It is safe to remove the same stream twice.
    mStreamTracker.removeStreamByHandle(serviceStream->getHandle());

    return serviceStream->close();
}

sp<AAudioServiceStreamBase> AAudioService::convertHandleToServiceStream(
        aaudio_handle_t streamHandle) {
    sp<AAudioServiceStreamBase> serviceStream = mStreamTracker.getStreamByHandle(
            streamHandle);
    if (serviceStream.get() != nullptr) {
        // Only allow owner or the aaudio service to access the stream.
        const uid_t callingUserId = IPCThreadState::self()->getCallingUid();
        const uid_t ownerUserId = serviceStream->getOwnerUserId();
        const uid_t clientUid = VALUE_OR_FATAL(
            aidl2legacy_int32_t_uid_t(mAudioClient.attributionSource.uid));
        bool callerOwnsIt = callingUserId == ownerUserId;
        bool serverCalling = callingUserId == clientUid;
        bool serverOwnsIt = ownerUserId == clientUid;
        bool allowed = callerOwnsIt || serverCalling || serverOwnsIt;
        if (!allowed) {
            ALOGE("AAudioService: calling uid %d cannot access stream 0x%08X owned by %d",
                  callingUserId, streamHandle, ownerUserId);
            serviceStream.clear();
        }
    }
    return serviceStream;
}

aaudio_result_t AAudioService::startClient(aaudio_handle_t streamHandle,
                                           const android::AudioClient& client,
                                           const audio_attributes_t *attr,
                                           audio_port_handle_t *clientHandle) {
    sp<AAudioServiceStreamBase> serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream.get() == nullptr) {
        ALOGW("%s(), invalid streamHandle = 0x%0x", __func__, streamHandle);
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    return serviceStream->startClient(client, attr, clientHandle);
}

aaudio_result_t AAudioService::stopClient(aaudio_handle_t streamHandle,
                                          audio_port_handle_t portHandle) {
    sp<AAudioServiceStreamBase> serviceStream = convertHandleToServiceStream(streamHandle);
    if (serviceStream.get() == nullptr) {
        ALOGW("%s(), invalid streamHandle = 0x%0x", __func__, streamHandle);
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    return serviceStream->stopClient(portHandle);
}

// This is only called internally when AudioFlinger wants to tear down a stream.
// So we do not have to check permissions.
aaudio_result_t AAudioService::disconnectStreamByPortHandle(audio_port_handle_t portHandle) {
    ALOGD("%s(%d) called", __func__, portHandle);
    sp<AAudioServiceStreamBase> serviceStream =
            mStreamTracker.findStreamByPortHandle(portHandle);
    if (serviceStream.get() == nullptr) {
        ALOGE("%s(), could not find stream with portHandle = %d", __func__, portHandle);
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
    // This is protected by a lock and will just return if already stopped.
    aaudio_result_t result = serviceStream->stop();
    serviceStream->disconnect();
    return result;
}
