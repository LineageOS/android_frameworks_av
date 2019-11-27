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

#ifndef ANDROID_MEDIA_TRANSCODING_SERVICE_H
#define ANDROID_MEDIA_TRANSCODING_SERVICE_H

#include <aidl/android/media/BnMediaTranscodingService.h>
#include <binder/IServiceManager.h>

namespace android {

namespace media {

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::BnMediaTranscodingService;
using ::aidl::android::media::ITranscodingServiceClient;
using ::aidl::android::media::TranscodingJob;
using ::aidl::android::media::TranscodingRequest;

class MediaTranscodingService : public BnMediaTranscodingService {
public:
    MediaTranscodingService();
    virtual ~MediaTranscodingService();

    static void instantiate();

    static const char* getServiceName() { return "media.transcoding"; }

    Status registerClient(const std::shared_ptr<ITranscodingServiceClient>& in_client,
                          int32_t* _aidl_return) override;

    Status unregisterClient(int32_t clientId, bool* _aidl_return) override;

    Status submitRequest(int32_t in_clientId, const TranscodingRequest& in_request,
                         TranscodingJob* out_job, int32_t* _aidl_return) override;

    Status cancelJob(int32_t in_clientId, int32_t in_jobId, bool* _aidl_return) override;

    Status getJobWithId(int32_t in_jobId, TranscodingJob* out_job, bool* _aidl_return) override;

    virtual inline binder_status_t dump(int /*fd*/, const char** /*args*/, uint32_t /*numArgs*/);

private:
};

}  // namespace media
}  // namespace android

#endif  // ANDROID_MEDIA_TRANSCODING_SERVICE_H
