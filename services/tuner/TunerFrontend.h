/**
 * Copyright 2020, The Android Open Source Project
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

#include <aidl/android/media/tv/tuner/BnTunerFrontend.h>
#include <android/hardware/tv/tuner/1.0/ITuner.h>
#include <android/hardware/tv/tuner/1.1/IFrontend.h>
#include <android/hardware/tv/tuner/1.1/IFrontendCallback.h>
#include <media/stagefright/foundation/ADebug.h>
#include <utils/Log.h>

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::tv::tuner::BnTunerFrontend;
using ::aidl::android::media::tv::tuner::ITunerFrontendCallback;
using ::aidl::android::media::tv::tuner::ITunerLnb;
using ::aidl::android::media::tv::tuner::TunerFrontendAtsc3Settings;
using ::aidl::android::media::tv::tuner::TunerFrontendDvbsCodeRate;
using ::aidl::android::media::tv::tuner::TunerFrontendScanMessage;
using ::aidl::android::media::tv::tuner::TunerFrontendSettings;
using ::aidl::android::media::tv::tuner::TunerFrontendStatus;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::hidl_vec;
using ::android::hardware::tv::tuner::V1_0::FrontendAtsc3PlpSettings;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbsCodeRate;
using ::android::hardware::tv::tuner::V1_0::FrontendEventType;
using ::android::hardware::tv::tuner::V1_0::FrontendId;
using ::android::hardware::tv::tuner::V1_0::FrontendScanMessage;
using ::android::hardware::tv::tuner::V1_0::FrontendScanMessageType;
using ::android::hardware::tv::tuner::V1_0::FrontendSettings;
using ::android::hardware::tv::tuner::V1_0::FrontendStatus;
using ::android::hardware::tv::tuner::V1_0::IFrontend;
using ::android::hardware::tv::tuner::V1_1::IFrontendCallback;
using ::android::hardware::tv::tuner::V1_1::FrontendScanMessageExt1_1;
using ::android::hardware::tv::tuner::V1_1::FrontendScanMessageTypeExt1_1;
using ::android::hardware::tv::tuner::V1_1::FrontendSettingsExt1_1;
using ::android::hardware::tv::tuner::V1_1::FrontendStatusExt1_1;

using namespace std;

namespace android {

class TunerFrontend : public BnTunerFrontend {

public:
    TunerFrontend(sp<IFrontend> frontend, int id);
    virtual ~TunerFrontend();
    Status setCallback(
            const shared_ptr<ITunerFrontendCallback>& tunerFrontendCallback) override;
    Status tune(const TunerFrontendSettings& settings) override;
    Status stopTune() override;
    Status scan(const TunerFrontendSettings& settings, int frontendScanType) override;
    Status stopScan() override;
    Status setLnb(const shared_ptr<ITunerLnb>& lnb) override;
    Status setLna(bool bEnable) override;
    Status linkCiCamToFrontend(int ciCamId, int32_t* _aidl_return) override;
    Status unlinkCiCamToFrontend(int ciCamId) override;
    Status close() override;
    Status getStatus(const vector<int32_t>& statusTypes,
            vector<TunerFrontendStatus>* _aidl_return) override;
    Status getStatusExtended_1_1(const vector<int32_t>& statusTypes,
            vector<TunerFrontendStatus>* _aidl_return) override;
    Status getFrontendId(int* _aidl_return) override;

    struct FrontendCallback : public IFrontendCallback {
        FrontendCallback(const shared_ptr<ITunerFrontendCallback> tunerFrontendCallback)
                : mTunerFrontendCallback(tunerFrontendCallback) {};

        virtual Return<void> onEvent(FrontendEventType frontendEventType);
        virtual Return<void> onScanMessage(
                FrontendScanMessageType type, const FrontendScanMessage& message);
        virtual Return<void> onScanMessageExt1_1(
                FrontendScanMessageTypeExt1_1 type, const FrontendScanMessageExt1_1& message);

        shared_ptr<ITunerFrontendCallback> mTunerFrontendCallback;
    };

private:
    hidl_vec<FrontendAtsc3PlpSettings> getAtsc3PlpSettings(
            const TunerFrontendAtsc3Settings& settings);
    FrontendDvbsCodeRate getDvbsCodeRate(const TunerFrontendDvbsCodeRate& codeRate);
    FrontendSettings getHidlFrontendSettings(const TunerFrontendSettings& aidlSettings);
    FrontendSettingsExt1_1 getHidlFrontendSettingsExt(const TunerFrontendSettings& aidlSettings);
    void getAidlFrontendStatus(
            vector<FrontendStatus>& hidlStatus, vector<TunerFrontendStatus>& aidlStatus);
    void getAidlFrontendStatusExt(
            vector<FrontendStatusExt1_1>& hidlStatus, vector<TunerFrontendStatus>& aidlStatus);

    int mId;
    sp<IFrontend> mFrontend;
    sp<::android::hardware::tv::tuner::V1_1::IFrontend> mFrontend_1_1;
};

} // namespace android

#endif // ANDROID_MEDIA_TUNERFRONTEND_H
