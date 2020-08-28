/*
 * Copyright (C) 2019 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaTranscodingService"
#include <MediaTranscodingService.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <private/android_filesystem_config.h>
#include <utils/Log.h>
#include <utils/Vector.h>

namespace android {

// Convenience methods for constructing binder::Status objects for error returns
#define STATUS_ERROR_FMT(errorCode, errorString, ...) \
    Status::fromServiceSpecificErrorWithMessage(      \
            errorCode,                                \
            String8::format("%s:%d: " errorString, __FUNCTION__, __LINE__, ##__VA_ARGS__))

// Can MediaTranscoding service trust the caller based on the calling UID?
// TODO(hkuang): Add MediaProvider's UID.
static bool isTrustedCallingUid(uid_t uid) {
    switch (uid) {
    case AID_ROOT:  // root user
    case AID_SYSTEM:
    case AID_SHELL:
    case AID_MEDIA:  // mediaserver
        return true;
    default:
        return false;
    }
}

MediaTranscodingService::MediaTranscodingService()
      : mTranscodingClientManager(TranscodingClientManager::getInstance()) {
    ALOGV("MediaTranscodingService is created");
}

MediaTranscodingService::~MediaTranscodingService() {
    ALOGE("Should not be in ~MediaTranscodingService");
}

binder_status_t MediaTranscodingService::dump(int fd, const char** /*args*/, uint32_t /*numArgs*/) {
    String8 result;
    const size_t SIZE = 256;
    char buffer[SIZE];

    snprintf(buffer, SIZE, "MediaTranscodingService: %p\n", this);
    result.append(buffer);
    write(fd, result.string(), result.size());

    Vector<String16> args;
    mTranscodingClientManager.dumpAllClients(fd, args);
    return OK;
}

//static
void MediaTranscodingService::instantiate() {
    std::shared_ptr<MediaTranscodingService> service =
            ::ndk::SharedRefBase::make<MediaTranscodingService>();
    binder_status_t status =
            AServiceManager_addService(service->asBinder().get(), getServiceName());
    if (status != STATUS_OK) {
        return;
    }
}

Status MediaTranscodingService::registerClient(
        const std::shared_ptr<ITranscodingServiceClient>& in_client,
        const std::string& in_opPackageName, int32_t in_clientUid, int32_t in_clientPid,
        int32_t* _aidl_return) {
    if (in_client == nullptr) {
        ALOGE("Client can not be null");
        *_aidl_return = kInvalidJobId;
        return Status::fromServiceSpecificError(ERROR_ILLEGAL_ARGUMENT);
    }

    int32_t callingPid = AIBinder_getCallingPid();
    int32_t callingUid = AIBinder_getCallingUid();

    // Check if we can trust clientUid. Only privilege caller could forward the uid on app client's behalf.
    if (in_clientUid == USE_CALLING_UID) {
        in_clientUid = callingUid;
    } else if (!isTrustedCallingUid(callingUid)) {
        ALOGE("MediaTranscodingService::registerClient failed (calling PID %d, calling UID %d) "
              "rejected "
              "(don't trust clientUid %d)",
              in_clientPid, in_clientUid, in_clientUid);
        return STATUS_ERROR_FMT(ERROR_PERMISSION_DENIED,
                                "Untrusted caller (calling PID %d, UID %d) trying to "
                                "register client",
                                in_clientPid, in_clientUid);
    }

    // Check if we can trust clientPid. Only privilege caller could forward the pid on app client's behalf.
    if (in_clientPid == USE_CALLING_PID) {
        in_clientPid = callingPid;
    } else if (!isTrustedCallingUid(callingUid)) {
        ALOGE("MediaTranscodingService::registerClient client failed (calling PID %d, calling UID "
              "%d) rejected "
              "(don't trust clientPid %d)",
              in_clientPid, in_clientUid, in_clientPid);
        return STATUS_ERROR_FMT(ERROR_PERMISSION_DENIED,
                                "Untrusted caller (calling PID %d, UID %d) trying to "
                                "register client",
                                in_clientPid, in_clientUid);
    }

    // We know the clientId must be equal to its pid as we assigned client's pid as its clientId.
    int32_t clientId = in_clientPid;

    // Checks if the client already registers.
    if (mTranscodingClientManager.isClientIdRegistered(clientId)) {
        return Status::fromServiceSpecificError(ERROR_ALREADY_EXISTS);
    }

    // Creates the client and uses its process id as client id.
    std::unique_ptr<TranscodingClientManager::ClientInfo> newClient =
            std::make_unique<TranscodingClientManager::ClientInfo>(
                    in_client, clientId, in_clientPid, in_clientUid, in_opPackageName);
    status_t err = mTranscodingClientManager.addClient(std::move(newClient));
    if (err != OK) {
        *_aidl_return = kInvalidClientId;
        return STATUS_ERROR_FMT(err, "Failed to add client to TranscodingClientManager");
    }

    ALOGD("Assign client: %s pid: %d, uid: %d with id: %d", in_opPackageName.c_str(), in_clientPid,
          in_clientUid, clientId);

    *_aidl_return = clientId;
    return Status::ok();
}

Status MediaTranscodingService::unregisterClient(int32_t clientId, bool* _aidl_return) {
    ALOGD("unregisterClient id: %d", clientId);
    int32_t callingUid = AIBinder_getCallingUid();
    int32_t callingPid = AIBinder_getCallingPid();

    // Only the client with clientId or the trusted caller could unregister the client.
    if (callingPid != clientId) {
        if (!isTrustedCallingUid(callingUid)) {
            ALOGE("Untrusted caller (calling PID %d, UID %d) trying to "
                  "unregister client with id: %d",
                  callingUid, callingPid, clientId);
            *_aidl_return = true;
            return STATUS_ERROR_FMT(ERROR_PERMISSION_DENIED,
                                    "Untrusted caller (calling PID %d, UID %d) trying to "
                                    "unregister client with id: %d",
                                    callingUid, callingPid, clientId);
        }
    }

    *_aidl_return = (mTranscodingClientManager.removeClient(clientId) == OK);
    return Status::ok();
}

Status MediaTranscodingService::getNumOfClients(int32_t* _aidl_return) {
    ALOGD("MediaTranscodingService::getNumOfClients");
    *_aidl_return = mTranscodingClientManager.getNumOfClients();
    return Status::ok();
}

Status MediaTranscodingService::submitRequest(int32_t /*clientId*/,
                                              const TranscodingRequestParcel& /*request*/,
                                              TranscodingJobParcel* /*job*/,
                                              int32_t* /*_aidl_return*/) {
    // TODO(hkuang): Add implementation.
    return Status::ok();
}

Status MediaTranscodingService::cancelJob(int32_t /*in_clientId*/, int32_t /*in_jobId*/,
                                          bool* /*_aidl_return*/) {
    // TODO(hkuang): Add implementation.
    return Status::ok();
}

Status MediaTranscodingService::getJobWithId(int32_t /*in_jobId*/,
                                             TranscodingJobParcel* /*out_job*/,
                                             bool* /*_aidl_return*/) {
    // TODO(hkuang): Add implementation.
    return Status::ok();
}

}  // namespace android
