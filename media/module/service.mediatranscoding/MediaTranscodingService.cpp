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
#include <android/permission_manager.h>
#include <cutils/properties.h>
#include <media/TranscoderWrapper.h>
#include <media/TranscodingClientManager.h>
#include <media/TranscodingDefs.h>
#include <media/TranscodingLogger.h>
#include <media/TranscodingResourcePolicy.h>
#include <media/TranscodingSessionController.h>
#include <media/TranscodingThermalPolicy.h>
#include <media/TranscodingUidPolicy.h>
#include <utils/Log.h>
#include <utils/Vector.h>

#include "SimulatedTranscoder.h"

namespace android {

// Convenience methods for constructing binder::Status objects for error returns
#define STATUS_ERROR_FMT(errorCode, errorString, ...) \
    Status::fromServiceSpecificErrorWithMessage(      \
            errorCode,                                \
            String8::format("%s:%d: " errorString, __FUNCTION__, __LINE__, ##__VA_ARGS__))

static constexpr int64_t kTranscoderHeartBeatIntervalUs = 1000000LL;

MediaTranscodingService::MediaTranscodingService()
      : mUidPolicy(new TranscodingUidPolicy()),
        mResourcePolicy(new TranscodingResourcePolicy()),
        mThermalPolicy(new TranscodingThermalPolicy()),
        mLogger(new TranscodingLogger()) {
    ALOGV("MediaTranscodingService is created");
    bool simulated = property_get_bool("debug.transcoding.simulated_transcoder", false);
    if (simulated) {
        // Overrid default config params with shorter values for testing.
        TranscodingSessionController::ControllerConfig config = {
                .pacerBurstThresholdMs = 500,
                .pacerBurstCountQuota = 10,
                .pacerBurstTimeQuotaSeconds = 3,
        };
        mSessionController.reset(new TranscodingSessionController(
                [](const std::shared_ptr<TranscoderCallbackInterface>& cb)
                        -> std::shared_ptr<TranscoderInterface> {
                    return std::make_shared<SimulatedTranscoder>(cb);
                },
                mUidPolicy, mResourcePolicy, mThermalPolicy, &config));
    } else {
        int32_t overrideBurstCountQuota =
                property_get_int32("persist.transcoding.burst_count_quota", -1);
        int32_t pacerBurstTimeQuotaSeconds =
                property_get_int32("persist.transcoding.burst_time_quota_seconds", -1);
        // Override default config params with properties if present.
        TranscodingSessionController::ControllerConfig config;
        if (overrideBurstCountQuota > 0) {
            config.pacerBurstCountQuota = overrideBurstCountQuota;
        }
        if (pacerBurstTimeQuotaSeconds > 0) {
            config.pacerBurstTimeQuotaSeconds = pacerBurstTimeQuotaSeconds;
        }
        mSessionController.reset(new TranscodingSessionController(
                [logger = mLogger](const std::shared_ptr<TranscoderCallbackInterface>& cb)
                        -> std::shared_ptr<TranscoderInterface> {
                    return std::make_shared<TranscoderWrapper>(cb, logger,
                                                               kTranscoderHeartBeatIntervalUs);
                },
                mUidPolicy, mResourcePolicy, mThermalPolicy, &config));
    }
    mClientManager.reset(new TranscodingClientManager(mSessionController));
    mUidPolicy->setCallback(mSessionController);
    mResourcePolicy->setCallback(mSessionController);
    mThermalPolicy->setCallback(mSessionController);
}

MediaTranscodingService::~MediaTranscodingService() {
    ALOGE("Should not be in ~MediaTranscodingService");
}

binder_status_t MediaTranscodingService::dump(int fd, const char** /*args*/, uint32_t /*numArgs*/) {
    String8 result;

    uid_t callingUid = AIBinder_getCallingUid();
    pid_t callingPid = AIBinder_getCallingPid();
    if (__builtin_available(android __TRANSCODING_MIN_API__, *)) {
        int32_t permissionResult;
        if (APermissionManager_checkPermission("android.permission.DUMP", callingPid, callingUid,
                                               &permissionResult) != PERMISSION_MANAGER_STATUS_OK ||
            permissionResult != PERMISSION_MANAGER_PERMISSION_GRANTED) {
            result.format(
                    "Permission Denial: "
                    "can't dump MediaTranscodingService from pid=%d, uid=%d\n",
                    AIBinder_getCallingPid(), AIBinder_getCallingUid());
            write(fd, result.c_str(), result.size());
            return PERMISSION_DENIED;
        }
    }

    const size_t SIZE = 256;
    char buffer[SIZE];

    snprintf(buffer, SIZE, "MediaTranscodingService: %p\n", this);
    result.append(buffer);
    write(fd, result.c_str(), result.size());

    Vector<String16> args;
    mClientManager->dumpAllClients(fd, args);
    mSessionController->dumpAllSessions(fd, args);
    return OK;
}

//static
void MediaTranscodingService::instantiate() {
    std::shared_ptr<MediaTranscodingService> service =
            ::ndk::SharedRefBase::make<MediaTranscodingService>();
    if (__builtin_available(android __TRANSCODING_MIN_API__, *)) {
        // Once service is started, we want it to stay even is client side perished.
        AServiceManager_forceLazyServicesPersist(true /*persist*/);
        (void)AServiceManager_registerLazyService(service->asBinder().get(), getServiceName());
    }
}

Status MediaTranscodingService::registerClient(
        const std::shared_ptr<ITranscodingClientCallback>& in_callback,
        const std::string& in_clientName, const std::string& in_opPackageName,
        std::shared_ptr<ITranscodingClient>* _aidl_return) {
    if (in_callback == nullptr) {
        *_aidl_return = nullptr;
        return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT, "Client callback cannot be null!");
    }

    // Creates the client and uses its process id as client id.
    std::shared_ptr<ITranscodingClient> newClient;

    status_t err =
            mClientManager->addClient(in_callback, in_clientName, in_opPackageName, &newClient);
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
