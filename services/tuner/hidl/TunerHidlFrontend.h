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

#ifndef ANDROID_MEDIA_TUNERHIDLFRONTEND_H
#define ANDROID_MEDIA_TUNERHIDLFRONTEND_H

#include <aidl/android/hardware/tv/tuner/IFrontendCallback.h>
#include <aidl/android/media/tv/tuner/BnTunerFrontend.h>
#include <android/hardware/tv/tuner/1.0/ITuner.h>
#include <android/hardware/tv/tuner/1.1/IFrontend.h>
#include <android/hardware/tv/tuner/1.1/IFrontendCallback.h>
#include <utils/Log.h>

using ::aidl::android::hardware::tv::tuner::FrontendAtsc3Settings;
using ::aidl::android::hardware::tv::tuner::FrontendDvbsCodeRate;
using ::aidl::android::hardware::tv::tuner::FrontendEventType;
using ::aidl::android::hardware::tv::tuner::FrontendScanMessage;
using ::aidl::android::hardware::tv::tuner::FrontendScanMessageType;
using ::aidl::android::hardware::tv::tuner::FrontendScanType;
using ::aidl::android::hardware::tv::tuner::FrontendSettings;
using ::aidl::android::hardware::tv::tuner::FrontendStatus;
using ::aidl::android::hardware::tv::tuner::FrontendStatusReadiness;
using ::aidl::android::hardware::tv::tuner::FrontendStatusType;
using ::android::sp;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::std::shared_ptr;
using ::std::vector;

using HidlFrontendAtsc3PlpSettings = ::android::hardware::tv::tuner::V1_0::FrontendAtsc3PlpSettings;
using HidlFrontendDvbsCodeRate = ::android::hardware::tv::tuner::V1_0::FrontendDvbsCodeRate;
using HidlFrontendEventType = ::android::hardware::tv::tuner::V1_0::FrontendEventType;
using HidlFrontendId = ::android::hardware::tv::tuner::V1_0::FrontendId;
using HidlFrontendScanMessage = ::android::hardware::tv::tuner::V1_0::FrontendScanMessage;
using HidlFrontendScanMessageType = ::android::hardware::tv::tuner::V1_0::FrontendScanMessageType;
using HidlFrontendSettings = ::android::hardware::tv::tuner::V1_0::FrontendSettings;
using HidlFrontendStatus = ::android::hardware::tv::tuner::V1_0::FrontendStatus;
using HidlIFrontend = ::android::hardware::tv::tuner::V1_0::IFrontend;
using HidlIFrontendCallback = ::android::hardware::tv::tuner::V1_1::IFrontendCallback;
using HidlFrontendScanMessageExt1_1 =
        ::android::hardware::tv::tuner::V1_1::FrontendScanMessageExt1_1;
using HidlFrontendScanMessageTypeExt1_1 =
        ::android::hardware::tv::tuner::V1_1::FrontendScanMessageTypeExt1_1;
using HidlFrontendSettingsExt1_1 = ::android::hardware::tv::tuner::V1_1::FrontendSettingsExt1_1;
using HidlFrontendStatusExt1_1 = ::android::hardware::tv::tuner::V1_1::FrontendStatusExt1_1;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

class TunerHidlService;

class TunerHidlFrontend : public BnTunerFrontend {
public:
    TunerHidlFrontend(const sp<HidlIFrontend> frontend, const int id,
                      const shared_ptr<TunerHidlService> tuner);
    virtual ~TunerHidlFrontend();

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

    void setLna(bool in_bEnable);

    struct FrontendCallback : public HidlIFrontendCallback {
        FrontendCallback(const shared_ptr<ITunerFrontendCallback> tunerFrontendCallback)
              : mTunerFrontendCallback(tunerFrontendCallback){};

        virtual Return<void> onEvent(HidlFrontendEventType frontendEventType);
        virtual Return<void> onScanMessage(HidlFrontendScanMessageType type,
                                           const HidlFrontendScanMessage& message);
        virtual Return<void> onScanMessageExt1_1(HidlFrontendScanMessageTypeExt1_1 type,
                                                 const HidlFrontendScanMessageExt1_1& message);

        shared_ptr<ITunerFrontendCallback> mTunerFrontendCallback;
    };

private:
    hidl_vec<HidlFrontendAtsc3PlpSettings> getAtsc3PlpSettings(
            const FrontendAtsc3Settings& settings);
    HidlFrontendDvbsCodeRate getDvbsCodeRate(const FrontendDvbsCodeRate& codeRate);
    void getHidlFrontendSettings(const FrontendSettings& aidlSettings,
                                 HidlFrontendSettings& settings,
                                 HidlFrontendSettingsExt1_1& settingsExt);
    void getAidlFrontendStatus(const vector<HidlFrontendStatus>& hidlStatus,
                               const vector<HidlFrontendStatusExt1_1>& hidlStatusExt,
                               vector<FrontendStatus>& aidlStatus);

    int mId;
    sp<HidlIFrontend> mFrontend;
    sp<::android::hardware::tv::tuner::V1_1::IFrontend> mFrontend_1_1;
    shared_ptr<TunerHidlService> mTunerService;
};

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl

#endif  // ANDROID_MEDIA_TUNERHIDLFRONTEND_H
