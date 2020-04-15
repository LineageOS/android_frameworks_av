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
#include "MediaTranscodingService.h"

#include <android/binder_manager.h>
#include <android/binder_process.h>
#include <media/TranscodingClientManager.h>
#include <media/TranscodingJobScheduler.h>
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

// DummyTranscoder and DummyProcessInfo are currently used to instantiate
// MediaTranscodingService on service side for testing, so that we could
// actually test the IPC calls of MediaTranscodingService to expose some
// issues that's observable only over IPC.
class DummyTranscoder : public TranscoderInterface {
    void start(int64_t clientId, int32_t jobId) override {
        (void)clientId;
        (void)jobId;
    }
    void pause(int64_t clientId, int32_t jobId) override {
        (void)clientId;
        (void)jobId;
    }
    void resume(int64_t clientId, int32_t jobId) override {
        (void)clientId;
        (void)jobId;
    }
};

class DummyProcessInfo : public ProcessInfoInterface {
    bool isProcessOnTop(int32_t pid) override {
        (void)pid;
        return true;
    }
};

MediaTranscodingService::MediaTranscodingService()
      : MediaTranscodingService(std::make_shared<DummyTranscoder>(),
                                std::make_shared<DummyProcessInfo>()) {}

MediaTranscodingService::MediaTranscodingService(
        const std::shared_ptr<TranscoderInterface>& transcoder,
        const std::shared_ptr<ProcessInfoInterface>& procInfo)
      : mJobScheduler(new TranscodingJobScheduler(transcoder, procInfo)),
        mClientManager(new TranscodingClientManager(mJobScheduler)) {
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
    mClientManager->dumpAllClients(fd, args);
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
        const std::shared_ptr<ITranscodingClientCallback>& in_callback,
        const std::string& in_clientName, const std::string& in_opPackageName, int32_t in_clientUid,
        int32_t in_clientPid, std::shared_ptr<ITranscodingClient>* _aidl_return) {
    if (in_callback == nullptr) {
        ALOGE("Client callback can not be null");
        *_aidl_return = nullptr;
        return Status::fromServiceSpecificError(ERROR_ILLEGAL_ARGUMENT);
    }

    int32_t callingPid = AIBinder_getCallingPid();
    int32_t callingUid = AIBinder_getCallingUid();

    // Check if we can trust clientUid. Only privilege caller could forward the
    // uid on app client's behalf.
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

    // Check if we can trust clientPid. Only privilege caller could forward the
    // pid on app client's behalf.
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

    // Creates the client and uses its process id as client id.
    std::shared_ptr<ITranscodingClient> newClient;

    status_t err = mClientManager->addClient(in_callback, in_clientPid, in_clientUid, in_clientName,
                                             in_opPackageName, &newClient);
    if (err != OK) {
        *_aidl_return = nullptr;
        return STATUS_ERROR_FMT(err, "Failed to add client to TranscodingClientManager");
    }

    *_aidl_return = newClient;
    return Status::ok();
}

Status MediaTranscodingService::getNumOfClients(int32_t* _aidl_return) {
    ALOGD("MediaTranscodingService::getNumOfClients");
    *_aidl_return = mClientManager->getNumOfClients();
    return Status::ok();
}

}  // namespace android
