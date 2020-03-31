/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef ANDROID_MEDIA_TRANSCODER_INTERFACE_H
#define ANDROID_MEDIA_TRANSCODER_INTERFACE_H

#include <aidl/android/media/TranscodingErrorCode.h>

namespace android {

using ::aidl::android::media::TranscodingErrorCode;

// Interface for the scheduler to call the transcoder to take actions.
class TranscoderInterface {
public:
    // TODO(chz): determine what parameters are needed here.
    // For now, always pass in clientId&jobId.
    virtual void start(int64_t clientId, int32_t jobId) = 0;
    virtual void pause(int64_t clientId, int32_t jobId) = 0;
    virtual void resume(int64_t clientId, int32_t jobId) = 0;

protected:
    virtual ~TranscoderInterface() = default;
};

// Interface for the transcoder to notify the scheduler of the status of
// the currently running job, or temporary loss of transcoding resources.
class TranscoderCallbackInterface {
public:
    // TODO(chz): determine what parameters are needed here.
    virtual void onFinish(int64_t clientId, int32_t jobId) = 0;
    virtual void onError(int64_t clientId, int32_t jobId, TranscodingErrorCode err) = 0;

    // Called when transcoding becomes temporarily inaccessible due to loss of resource.
    // If there is any job currently running, it will be paused. When resource contention
    // is solved, the scheduler should call TranscoderInterface's to either start a new job,
    // or resume a paused job.
    virtual void onResourceLost() = 0;

protected:
    virtual ~TranscoderCallbackInterface() = default;
};

}  // namespace android
#endif  // ANDROID_MEDIA_TRANSCODER_INTERFACE_H
