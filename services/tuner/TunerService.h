/**
 * Copyright (c) 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_MEDIA_TUNERSERVICE_H
#define ANDROID_MEDIA_TUNERSERVICE_H

#include <aidl/android/media/tv/tuner/BnTunerService.h>
#include <aidl/android/media/tv/tuner/TunerServiceFrontendInfo.h>
#include <android/hardware/tv/tuner/1.0/ITuner.h>

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::tv::tuner::BnTunerService;
using ::aidl::android::media::tv::tuner::ITunerFrontend;
using ::aidl::android::media::tv::tuner::TunerServiceFrontendInfo;
using ::android::hardware::tv::tuner::V1_0::FrontendInfo;
using ::android::hardware::tv::tuner::V1_0::ITuner;

namespace android {

class TunerService : public BnTunerService {

public:
    static char const *getServiceName() { return "media.tuner"; }
    static void instantiate();
    TunerService();
    virtual ~TunerService();

    static int getResourceIdFromHandle(int resourceHandle) {
        return (resourceHandle & 0x00ff0000) >> 16;
    }

    Status getFrontendIds(std::vector<int32_t>* ids, int32_t* _aidl_return) override;
    Status getFrontendInfo(int32_t frontendHandle, TunerServiceFrontendInfo* _aidl_return) override;
    Status openFrontend(
            int32_t frontendHandle, std::shared_ptr<ITunerFrontend>* _aidl_return) override;

private:
    static sp<ITuner> mTuner;

    TunerServiceFrontendInfo convertToAidlFrontendInfo(int feId, FrontendInfo halInfo);
};

} // namespace android

#endif // ANDROID_MEDIA_TUNERSERVICE_H
