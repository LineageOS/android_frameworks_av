/**
 * Copyright 2021, The Android Open Source Project
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

#ifndef ANDROID_MEDIA_TUNERFRONTEND_H
#define ANDROID_MEDIA_TUNERFRONTEND_H

#include <aidl/android/hardware/tv/tuner/BnFrontendCallback.h>
#include <aidl/android/hardware/tv/tuner/IFrontend.h>
#include <aidl/android/hardware/tv/tuner/IFrontendCallback.h>
#include <aidl/android/media/tv/tuner/BnTunerFrontend.h>
#include <utils/Log.h>

using ::aidl::android::hardware::tv::tuner::BnFrontendCallback;
using ::aidl::android::hardware::tv::tuner::FrontendEventType;
using ::aidl::android::hardware::tv::tuner::FrontendScanMessage;
using ::aidl::android::hardware::tv::tuner::FrontendScanMessageType;
using ::aidl::android::hardware::tv::tuner::FrontendScanType;
using ::aidl::android::hardware::tv::tuner::FrontendSettings;
using ::aidl::android::hardware::tv::tuner::FrontendStatus;
using ::aidl::android::hardware::tv::tuner::FrontendStatusReadiness;
using ::aidl::android::hardware::tv::tuner::FrontendStatusType;
using ::aidl::android::hardware::tv::tuner::IFrontend;
using ::aidl::android::hardware::tv::tuner::IFrontendCallback;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

class TunerFrontend : public BnTunerFrontend {

public:
    TunerFrontend(shared_ptr<IFrontend> frontend, int id);
    virtual ~TunerFrontend();

    ::ndk::ScopedAStatus setCallback(
            const shared_ptr<ITunerFrontendCallback>& in_tunerFrontendCallback) override;
    ::ndk::ScopedAStatus tune(const FrontendSettings& in_settings) override;
    ::ndk::ScopedAStatus stopTune() override;
    ::ndk::ScopedAStatus scan(const FrontendSettings& in_settings,
                              FrontendScanType in_frontendScanType) override;
    ::ndk::ScopedAStatus stopScan() override;
    ::ndk::ScopedAStatus setLnb(const shared_ptr<ITunerLnb>& in_lnb) override;
    ::ndk::ScopedAStatus linkCiCamToFrontend(int32_t in_ciCamId, int32_t* _aidl_return) override;
    ::ndk::ScopedAStatus unlinkCiCamToFrontend(int32_t in_ciCamId) override;
    ::ndk::ScopedAStatus close() override;
    ::ndk::ScopedAStatus getStatus(const vector<FrontendStatusType>& in_statusTypes,
                                   vector<FrontendStatus>* _aidl_return) override;
    ::ndk::ScopedAStatus getFrontendId(int32_t* _aidl_return) override;
    ::ndk::ScopedAStatus getHardwareInfo(std::string* _aidl_return) override;
    ::ndk::ScopedAStatus removeOutputPid(int32_t in_pid) override;
    ::ndk::ScopedAStatus getFrontendStatusReadiness(
            const std::vector<FrontendStatusType>& in_statusTypes,
            std::vector<FrontendStatusReadiness>* _aidl_return) override;

    struct FrontendCallback : public BnFrontendCallback {
        FrontendCallback(const shared_ptr<ITunerFrontendCallback> tunerFrontendCallback)
              : mTunerFrontendCallback(tunerFrontendCallback){};

        ::ndk::ScopedAStatus onEvent(FrontendEventType frontendEventType) override;
        ::ndk::ScopedAStatus onScanMessage(FrontendScanMessageType type,
                                           const FrontendScanMessage& message) override;

        shared_ptr<ITunerFrontendCallback> mTunerFrontendCallback;
    };

private:
    int mId;
    shared_ptr<IFrontend> mFrontend;
    bool isClosed = false;
};

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl

#endif // ANDROID_MEDIA_TUNERFRONTEND_H
