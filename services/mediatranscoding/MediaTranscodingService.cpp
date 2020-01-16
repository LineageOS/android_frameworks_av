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
#include <utils/Log.h>
#include <utils/Vector.h>

namespace android {

MediaTranscodingService::MediaTranscodingService() {
    ALOGV("MediaTranscodingService is created");
}

MediaTranscodingService::~MediaTranscodingService() {
    ALOGE("Should not be in ~MediaTranscodingService");
}

binder_status_t MediaTranscodingService::dump(int /* fd */, const char** /*args*/,
                                              uint32_t /*numArgs*/) {
    // TODO(hkuang): Add implementation.
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
        const std::shared_ptr<ITranscodingServiceClient>& /*in_client*/,
        const std::string& /* in_opPackageName */, int32_t /* in_clientUid */,
        int32_t /* in_clientPid */, int32_t* /*_aidl_return*/) {
    // TODO(hkuang): Add implementation.
    return Status::ok();
}

Status MediaTranscodingService::unregisterClient(int32_t /*clientId*/, bool* /*_aidl_return*/) {
    // TODO(hkuang): Add implementation.
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
