/**
 * Copyright (c) 2021, The Android Open Source Project
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

#ifndef ANDROID_MEDIA_TUNERHIDLSERVICE_H
#define ANDROID_MEDIA_TUNERHIDLSERVICE_H

#include <aidl/android/hardware/tv/tuner/DemuxFilterEvent.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterStatus.h>
#include <aidl/android/media/tv/tuner/BnTunerService.h>
#include <aidl/android/media/tv/tunerresourcemanager/TunerFrontendInfo.h>
#include <android/hardware/tv/tuner/1.1/ITuner.h>
#include <utils/Mutex.h>

#include <unordered_set>

#include "TunerHelper.h"
#include "TunerHidlFilter.h"
#include "TunerHidlFrontend.h"

using ::aidl::android::hardware::tv::tuner::DemuxCapabilities;
using ::aidl::android::hardware::tv::tuner::DemuxFilterEvent;
using ::aidl::android::hardware::tv::tuner::DemuxFilterStatus;
using ::aidl::android::hardware::tv::tuner::DemuxInfo;
using ::aidl::android::hardware::tv::tuner::FrontendInfo;
using ::aidl::android::hardware::tv::tuner::FrontendType;
using ::aidl::android::media::tv::tuner::ITunerDemux;
using ::aidl::android::media::tv::tuner::ITunerDescrambler;
using ::aidl::android::media::tv::tuner::ITunerFrontend;
using ::aidl::android::media::tv::tuner::ITunerLnb;
using ::aidl::android::media::tv::tunerresourcemanager::TunerFrontendInfo;
using ::android::Mutex;
using ::android::sp;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::std::shared_ptr;
using ::std::string;
using ::std::vector;

using HidlFrontendDtmbCapabilities = ::android::hardware::tv::tuner::V1_1::FrontendDtmbCapabilities;
using HidlDemuxFilterEvent = ::android::hardware::tv::tuner::V1_0::DemuxFilterEvent;
using HidlDemuxFilterStatus = ::android::hardware::tv::tuner::V1_0::DemuxFilterStatus;
using HidlDemuxCapabilities = ::android::hardware::tv::tuner::V1_0::DemuxCapabilities;
using HidlFrontendInfo = ::android::hardware::tv::tuner::V1_0::FrontendInfo;
using HidlITuner = ::android::hardware::tv::tuner::V1_0::ITuner;
using HidlResult = ::android::hardware::tv::tuner::V1_0::Result;
using HidlFrontendId = ::android::hardware::tv::tuner::V1_0::FrontendId;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

class TunerHidlService : public BnTunerService {
public:
    static char const* getServiceName() { return "media.tuner"; }
    static binder_status_t instantiate();
    TunerHidlService();
    virtual ~TunerHidlService();

    ::ndk::ScopedAStatus getFrontendIds(vector<int32_t>* out_ids) override;
    ::ndk::ScopedAStatus getFrontendInfo(int32_t in_frontendHandle,
                                         FrontendInfo* _aidl_return) override;
    ::ndk::ScopedAStatus openFrontend(int32_t in_frontendHandle,
                                      shared_ptr<ITunerFrontend>* _aidl_return) override;
    ::ndk::ScopedAStatus openLnb(int32_t in_lnbHandle,
                                 shared_ptr<ITunerLnb>* _aidl_return) override;
    ::ndk::ScopedAStatus openLnbByName(const std::string& in_lnbName,
                                       shared_ptr<ITunerLnb>* _aidl_return) override;
    ::ndk::ScopedAStatus openDemux(int32_t in_demuxHandle,
                                   shared_ptr<ITunerDemux>* _aidl_return) override;
    ::ndk::ScopedAStatus getDemuxCaps(DemuxCapabilities* _aidl_return) override;
    ::ndk::ScopedAStatus getDemuxInfo(int32_t in_demuxHandle, DemuxInfo* _aidl_return) override;
    ::ndk::ScopedAStatus getDemuxInfoList(vector<DemuxInfo>* _aidl_return) override;
    ::ndk::ScopedAStatus openDescrambler(int32_t in_descramblerHandle,
                                         shared_ptr<ITunerDescrambler>* _aidl_return) override;
    ::ndk::ScopedAStatus getTunerHalVersion(int32_t* _aidl_return) override;
    ::ndk::ScopedAStatus openSharedFilter(const string& in_filterToken,
                                          const shared_ptr<ITunerFilterCallback>& in_cb,
                                          shared_ptr<ITunerFilter>* _aidl_return) override;
    ::ndk::ScopedAStatus isLnaSupported(bool* _aidl_return) override;
    ::ndk::ScopedAStatus setLna(bool in_bEnable) override;
    ::ndk::ScopedAStatus setMaxNumberOfFrontends(FrontendType in_frontendType,
                                                 int32_t in_maxNumber) override;
    ::ndk::ScopedAStatus getMaxNumberOfFrontends(FrontendType in_frontendType,
                                                 int32_t* _aidl_return) override;

    string addFilterToShared(const shared_ptr<TunerHidlFilter>& sharedFilter);
    void removeSharedFilter(const shared_ptr<TunerHidlFilter>& sharedFilter);
    void removeFrontend(const shared_ptr<TunerHidlFrontend>& frontend);

private:
    void updateTunerResources();
    vector<TunerFrontendInfo> getTRMFrontendInfos();
    vector<int32_t> getTRMLnbHandles();
    HidlResult getHidlFrontendIds(hidl_vec<HidlFrontendId>& ids);
    HidlResult getHidlFrontendInfo(const int id, HidlFrontendInfo& info);
    DemuxCapabilities getAidlDemuxCaps(const HidlDemuxCapabilities& caps);
    FrontendInfo getAidlFrontendInfo(const HidlFrontendInfo& halInfo,
                                     const HidlFrontendDtmbCapabilities& dtmbCaps);

    sp<HidlITuner> mTuner;
    sp<::android::hardware::tv::tuner::V1_1::ITuner> mTuner_1_1;
    int mTunerVersion = TUNER_HAL_VERSION_UNKNOWN;
    Mutex mSharedFiltersLock;
    map<string, shared_ptr<TunerHidlFilter>> mSharedFilters;
    Mutex mOpenedFrontendsLock;
    unordered_set<shared_ptr<TunerHidlFrontend>> mOpenedFrontends;
    int mLnaStatus = -1;
};

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl

#endif  // ANDROID_MEDIA_TUNERHIDLSERVICE_H
