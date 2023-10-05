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

//#define LOG_NDEBUG 0
#define LOG_TAG "TunerHidlService"

#include "TunerHidlService.h"

#include <aidl/android/hardware/tv/tuner/FrontendIsdbtTimeInterleaveMode.h>
#include <aidl/android/hardware/tv/tuner/Result.h>
#include <android/binder_manager.h>
#include <binder/IPCThreadState.h>
#include <binder/PermissionCache.h>
#include <cutils/properties.h>
#include <utils/Log.h>

#include "TunerHelper.h"
#include "TunerHidlDemux.h"
#include "TunerHidlDescrambler.h"
#include "TunerHidlFrontend.h"
#include "TunerHidlLnb.h"

using ::aidl::android::hardware::tv::tuner::FrontendAnalogCapabilities;
using ::aidl::android::hardware::tv::tuner::FrontendAtsc3Capabilities;
using ::aidl::android::hardware::tv::tuner::FrontendAtscCapabilities;
using ::aidl::android::hardware::tv::tuner::FrontendCapabilities;
using ::aidl::android::hardware::tv::tuner::FrontendDtmbCapabilities;
using ::aidl::android::hardware::tv::tuner::FrontendDvbcCapabilities;
using ::aidl::android::hardware::tv::tuner::FrontendDvbsCapabilities;
using ::aidl::android::hardware::tv::tuner::FrontendDvbtCapabilities;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbs3Capabilities;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbsCapabilities;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbtCapabilities;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbtTimeInterleaveMode;
using ::aidl::android::hardware::tv::tuner::FrontendType;
using ::aidl::android::hardware::tv::tuner::Result;
using ::android::IPCThreadState;
using ::android::PermissionCache;
using ::android::hardware::hidl_vec;

using HidlFrontendId = ::android::hardware::tv::tuner::V1_0::FrontendId;
using HidlLnbId = ::android::hardware::tv::tuner::V1_0::LnbId;
using HidlFrontendType = ::android::hardware::tv::tuner::V1_1::FrontendType;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerHidlService::TunerHidlService() {
    mTuner = HidlITuner::getService();
    ALOGE_IF(mTuner == nullptr, "Failed to get ITuner service");
    mTunerVersion = TUNER_HAL_VERSION_1_0;

    mTuner_1_1 = ::android::hardware::tv::tuner::V1_1::ITuner::castFrom(mTuner);
    if (mTuner_1_1 != nullptr) {
        mTunerVersion = TUNER_HAL_VERSION_1_1;
    } else {
        ALOGD("Failed to get ITuner_1_1 service");
    }

    // Register tuner resources to TRM.
    updateTunerResources();
}

TunerHidlService::~TunerHidlService() {
    mOpenedFrontends.clear();
    mLnaStatus = -1;
    mTuner = nullptr;
    mTuner_1_1 = nullptr;
}

binder_status_t TunerHidlService::instantiate() {
    if (HidlITuner::getService() == nullptr) {
        ALOGD("Failed to get ITuner HIDL HAL");
        return STATUS_NAME_NOT_FOUND;
    }

    shared_ptr<TunerHidlService> tunerService = ::ndk::SharedRefBase::make<TunerHidlService>();
    bool lazyHal = property_get_bool("ro.tuner.lazyhal", false);
    if (lazyHal) {
        return AServiceManager_registerLazyService(tunerService->asBinder().get(),
                                                   getServiceName());
    }
    return AServiceManager_addService(tunerService->asBinder().get(), getServiceName());
}

::ndk::ScopedAStatus TunerHidlService::openDemux(int32_t /* in_demuxHandle */,
                                                 shared_ptr<ITunerDemux>* _aidl_return) {
    ALOGV("openDemux");
    HidlResult res;
    uint32_t id;
    sp<IDemux> demuxSp = nullptr;
    mTuner->openDemux([&](HidlResult r, uint32_t demuxId, const sp<IDemux>& demux) {
        demuxSp = demux;
        id = demuxId;
        res = r;
        ALOGD("open demux, id = %d", demuxId);
    });
    if (res == HidlResult::SUCCESS) {
        *_aidl_return = ::ndk::SharedRefBase::make<TunerHidlDemux>(demuxSp, id,
                                                                   this->ref<TunerHidlService>());
        return ::ndk::ScopedAStatus::ok();
    }

    ALOGW("open demux failed, res = %d", res);
    return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
}

::ndk::ScopedAStatus TunerHidlService::getDemuxInfo(int32_t /* in_demuxHandle */,
                                                    DemuxInfo* /* _aidl_return */) {
    ALOGE("getDemuxInfo is not supported");
    return ::ndk::ScopedAStatus::fromServiceSpecificError(
            static_cast<int32_t>(HidlResult::UNAVAILABLE));
}

::ndk::ScopedAStatus TunerHidlService::getDemuxInfoList(
        vector<DemuxInfo>* /* _aidle_return */) {
    ALOGE("getDemuxInfoList is not supported");
    return ::ndk::ScopedAStatus::fromServiceSpecificError(
            static_cast<int32_t>(HidlResult::UNAVAILABLE));
}

::ndk::ScopedAStatus TunerHidlService::getDemuxCaps(DemuxCapabilities* _aidl_return) {
    ALOGV("getDemuxCaps");
    HidlResult res;
    HidlDemuxCapabilities caps;
    mTuner->getDemuxCaps([&](HidlResult r, const HidlDemuxCapabilities& demuxCaps) {
        caps = demuxCaps;
        res = r;
    });
    if (res == HidlResult::SUCCESS) {
        *_aidl_return = getAidlDemuxCaps(caps);
        return ::ndk::ScopedAStatus::ok();
    }

    ALOGW("Get demux caps failed, res = %d", res);
    return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
}

::ndk::ScopedAStatus TunerHidlService::getFrontendIds(vector<int32_t>* ids) {
    hidl_vec<HidlFrontendId> feIds;
    HidlResult res = getHidlFrontendIds(feIds);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    ids->resize(feIds.size());
    copy(feIds.begin(), feIds.end(), ids->begin());

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlService::getFrontendInfo(int32_t id, FrontendInfo* _aidl_return) {
    HidlFrontendInfo info;
    HidlResult res = getHidlFrontendInfo(id, info);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    HidlFrontendDtmbCapabilities dtmbCaps;
    if (static_cast<HidlFrontendType>(info.type) == HidlFrontendType::DTMB) {
        if (mTuner_1_1 == nullptr) {
            ALOGE("ITuner_1_1 service is not init.");
            return ::ndk::ScopedAStatus::fromServiceSpecificError(
                    static_cast<int32_t>(Result::UNAVAILABLE));
        }

        mTuner_1_1->getFrontendDtmbCapabilities(
                id, [&](HidlResult r, const HidlFrontendDtmbCapabilities& caps) {
                    dtmbCaps = caps;
                    res = r;
                });
        if (res != HidlResult::SUCCESS) {
            return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
        }
    }

    *_aidl_return = getAidlFrontendInfo(info, dtmbCaps);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlService::openFrontend(int32_t frontendHandle,
                                                    shared_ptr<ITunerFrontend>* _aidl_return) {
    HidlResult status;
    sp<HidlIFrontend> frontend;
    int id = TunerHelper::getResourceIdFromHandle(frontendHandle, FRONTEND);
    mTuner->openFrontendById(id, [&](HidlResult result, const sp<HidlIFrontend>& fe) {
        frontend = fe;
        status = result;
    });
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    shared_ptr<TunerHidlFrontend> tunerFrontend = ::ndk::SharedRefBase::make<TunerHidlFrontend>(
            frontend, id, this->ref<TunerHidlService>());
    if (mLnaStatus != -1) {
        tunerFrontend->setLna(mLnaStatus == 1);
    }
    {
        Mutex::Autolock _l(mOpenedFrontendsLock);
        mOpenedFrontends.insert(tunerFrontend);
    }
    *_aidl_return = tunerFrontend;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlService::openLnb(int lnbHandle, shared_ptr<ITunerLnb>* _aidl_return) {
    HidlResult status;
    sp<HidlILnb> lnb;
    int id = TunerHelper::getResourceIdFromHandle(lnbHandle, LNB);
    mTuner->openLnbById(id, [&](HidlResult result, const sp<HidlILnb>& lnbSp) {
        lnb = lnbSp;
        status = result;
    });
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    *_aidl_return = ::ndk::SharedRefBase::make<TunerHidlLnb>(lnb, id);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlService::openLnbByName(const string& lnbName,
                                                     shared_ptr<ITunerLnb>* _aidl_return) {
    int lnbId;
    HidlResult status;
    sp<HidlILnb> lnb;
    mTuner->openLnbByName(lnbName, [&](HidlResult r, HidlLnbId id, const sp<HidlILnb>& lnbSp) {
        status = r;
        lnb = lnbSp;
        lnbId = static_cast<int32_t>(id);
    });
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    *_aidl_return = ::ndk::SharedRefBase::make<TunerHidlLnb>(lnb, lnbId);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlService::openDescrambler(
        int32_t /*descramblerHandle*/, shared_ptr<ITunerDescrambler>* _aidl_return) {
    HidlResult status;
    sp<HidlIDescrambler> descrambler;
    //int id = TunerHelper::getResourceIdFromHandle(descramblerHandle, DESCRAMBLER);
    mTuner->openDescrambler([&](HidlResult r, const sp<HidlIDescrambler>& descramblerSp) {
        status = r;
        descrambler = descramblerSp;
    });
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    *_aidl_return = ::ndk::SharedRefBase::make<TunerHidlDescrambler>(descrambler);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlService::getTunerHalVersion(int* _aidl_return) {
    *_aidl_return = mTunerVersion;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlService::openSharedFilter(
        const string& in_filterToken, const shared_ptr<ITunerFilterCallback>& in_cb,
        shared_ptr<ITunerFilter>* _aidl_return) {
    if (mTuner == nullptr) {
        ALOGE("get ITuner failed");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (!PermissionCache::checkCallingPermission(sSharedFilterPermission)) {
        ALOGE("Request requires android.permission.ACCESS_TV_SHARED_FILTER");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Mutex::Autolock _l(mSharedFiltersLock);
    if (mSharedFilters.find(in_filterToken) == mSharedFilters.end()) {
        *_aidl_return = nullptr;
        ALOGD("fail to find %s", in_filterToken.c_str());
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    shared_ptr<TunerHidlFilter> filter = mSharedFilters.at(in_filterToken);
    IPCThreadState* ipc = IPCThreadState::self();
    const int pid = ipc->getCallingPid();
    if (!filter->isSharedFilterAllowed(pid)) {
        *_aidl_return = nullptr;
        ALOGD("shared filter %s is opened in the same process", in_filterToken.c_str());
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    filter->attachSharedFilterCallback(in_cb);

    *_aidl_return = filter;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlService::isLnaSupported(bool* /* _aidl_return */) {
    return ::ndk::ScopedAStatus::fromServiceSpecificError(
            static_cast<int32_t>(Result::UNAVAILABLE));
}

::ndk::ScopedAStatus TunerHidlService::setLna(bool bEnable) {
    if (mTuner == nullptr) {
        ALOGE("get ITuner failed");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    mLnaStatus = bEnable ? 1 : 0;

    {
        Mutex::Autolock _l(mOpenedFrontendsLock);
        for (auto it = mOpenedFrontends.begin(); it != mOpenedFrontends.end(); ++it) {
            (*it)->setLna(mLnaStatus == 1);
        }
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlService::setMaxNumberOfFrontends(FrontendType /* in_frontendType */,
                                                               int32_t /* in_maxNumber */) {
    return ::ndk::ScopedAStatus::fromServiceSpecificError(
            static_cast<int32_t>(Result::UNAVAILABLE));
}

::ndk::ScopedAStatus TunerHidlService::getMaxNumberOfFrontends(FrontendType /* in_frontendType */,
                                                               int32_t* _aidl_return) {
    *_aidl_return = -1;
    return ::ndk::ScopedAStatus::fromServiceSpecificError(
            static_cast<int32_t>(Result::UNAVAILABLE));
}

string TunerHidlService::addFilterToShared(const shared_ptr<TunerHidlFilter>& sharedFilter) {
    Mutex::Autolock _l(mSharedFiltersLock);

    // Use sharedFilter address as token.
    string token = to_string(reinterpret_cast<std::uintptr_t>(sharedFilter.get()));
    mSharedFilters[token] = sharedFilter;

    return token;
}

void TunerHidlService::removeSharedFilter(const shared_ptr<TunerHidlFilter>& sharedFilter) {
    Mutex::Autolock _l(mSharedFiltersLock);

    // Use sharedFilter address as token.
    mSharedFilters.erase(to_string(reinterpret_cast<std::uintptr_t>(sharedFilter.get())));
}

void TunerHidlService::removeFrontend(const shared_ptr<TunerHidlFrontend>& frontend) {
    Mutex::Autolock _l(mOpenedFrontendsLock);
    for (auto it = mOpenedFrontends.begin(); it != mOpenedFrontends.end(); ++it) {
        if (it->get() == frontend.get()) {
            mOpenedFrontends.erase(it);
            break;
        }
    }
}

void TunerHidlService::updateTunerResources() {
    TunerHelper::updateTunerResources(getTRMFrontendInfos(), getTRMLnbHandles());
}

vector<TunerFrontendInfo> TunerHidlService::getTRMFrontendInfos() {
    vector<TunerFrontendInfo> infos;
    hidl_vec<HidlFrontendId> ids;
    HidlResult res = getHidlFrontendIds(ids);
    if (res != HidlResult::SUCCESS) {
        return infos;
    }

    for (int i = 0; i < ids.size(); i++) {
        HidlFrontendInfo frontendInfo;
        HidlResult res = getHidlFrontendInfo(static_cast<int32_t>(ids[i]), frontendInfo);
        if (res != HidlResult::SUCCESS) {
            continue;
        }
        TunerFrontendInfo tunerFrontendInfo{
                .handle = TunerHelper::getResourceHandleFromId(static_cast<int32_t>(ids[i]),
                                                               FRONTEND),
                .type = static_cast<int32_t>(frontendInfo.type),
                .exclusiveGroupId = static_cast<int32_t>(frontendInfo.exclusiveGroupId),
        };
        infos.push_back(tunerFrontendInfo);
    }

    return infos;
}

vector<int32_t> TunerHidlService::getTRMLnbHandles() {
    vector<int32_t> lnbHandles;
    if (mTuner != nullptr) {
        HidlResult res;
        vector<HidlLnbId> lnbIds;
        mTuner->getLnbIds([&](HidlResult r, const hidl_vec<HidlLnbId>& ids) {
            lnbIds = ids;
            res = r;
        });
        if (res == HidlResult::SUCCESS && lnbIds.size() > 0) {
            for (int i = 0; i < lnbIds.size(); i++) {
                lnbHandles.push_back(
                        TunerHelper::getResourceHandleFromId(static_cast<int32_t>(lnbIds[i]), LNB));
            }
        }
    }

    return lnbHandles;
}

HidlResult TunerHidlService::getHidlFrontendIds(hidl_vec<HidlFrontendId>& ids) {
    if (mTuner == nullptr) {
        return HidlResult::NOT_INITIALIZED;
    }
    HidlResult res;
    mTuner->getFrontendIds([&](HidlResult r, const hidl_vec<HidlFrontendId>& frontendIds) {
        ids = frontendIds;
        res = r;
    });
    return res;
}

HidlResult TunerHidlService::getHidlFrontendInfo(const int id, HidlFrontendInfo& info) {
    if (mTuner == nullptr) {
        return HidlResult::NOT_INITIALIZED;
    }
    HidlResult res;
    mTuner->getFrontendInfo(id, [&](HidlResult r, const HidlFrontendInfo& feInfo) {
        info = feInfo;
        res = r;
    });
    return res;
}

DemuxCapabilities TunerHidlService::getAidlDemuxCaps(const HidlDemuxCapabilities& caps) {
    DemuxCapabilities aidlCaps{
            .numDemux = static_cast<int32_t>(caps.numDemux),
            .numRecord = static_cast<int32_t>(caps.numRecord),
            .numPlayback = static_cast<int32_t>(caps.numPlayback),
            .numTsFilter = static_cast<int32_t>(caps.numTsFilter),
            .numSectionFilter = static_cast<int32_t>(caps.numSectionFilter),
            .numAudioFilter = static_cast<int32_t>(caps.numAudioFilter),
            .numVideoFilter = static_cast<int32_t>(caps.numVideoFilter),
            .numPesFilter = static_cast<int32_t>(caps.numPesFilter),
            .numPcrFilter = static_cast<int32_t>(caps.numPcrFilter),
            .numBytesInSectionFilter = static_cast<int64_t>(caps.numBytesInSectionFilter),
            .filterCaps = static_cast<int32_t>(caps.filterCaps),
            .bTimeFilter = caps.bTimeFilter,
    };
    aidlCaps.linkCaps.resize(caps.linkCaps.size());
    copy(caps.linkCaps.begin(), caps.linkCaps.end(), aidlCaps.linkCaps.begin());
    return aidlCaps;
}

FrontendInfo TunerHidlService::getAidlFrontendInfo(
        const HidlFrontendInfo& halInfo, const HidlFrontendDtmbCapabilities& halDtmbCaps) {
    FrontendInfo info{
            .type = static_cast<FrontendType>(halInfo.type),
            .minFrequency = static_cast<int64_t>(halInfo.minFrequency),
            .maxFrequency = static_cast<int64_t>(halInfo.maxFrequency),
            .minSymbolRate = static_cast<int32_t>(halInfo.minSymbolRate),
            .maxSymbolRate = static_cast<int32_t>(halInfo.maxSymbolRate),
            .acquireRange = static_cast<int64_t>(halInfo.acquireRange),
            .exclusiveGroupId = static_cast<int32_t>(halInfo.exclusiveGroupId),
    };
    for (int i = 0; i < halInfo.statusCaps.size(); i++) {
        info.statusCaps.push_back(static_cast<FrontendStatusType>(halInfo.statusCaps[i]));
    }

    FrontendCapabilities caps;
    switch (halInfo.type) {
    case ::android::hardware::tv::tuner::V1_0::FrontendType::ANALOG: {
        if (HidlFrontendInfo::FrontendCapabilities::hidl_discriminator::analogCaps ==
            halInfo.frontendCaps.getDiscriminator()) {
            FrontendAnalogCapabilities analogCaps{
                    .typeCap = static_cast<int32_t>(halInfo.frontendCaps.analogCaps().typeCap),
                    .sifStandardCap =
                            static_cast<int32_t>(halInfo.frontendCaps.analogCaps().sifStandardCap),
            };
            caps.set<FrontendCapabilities::analogCaps>(analogCaps);
        }
        break;
    }
    case ::android::hardware::tv::tuner::V1_0::FrontendType::ATSC: {
        if (HidlFrontendInfo::FrontendCapabilities::hidl_discriminator::atscCaps ==
            halInfo.frontendCaps.getDiscriminator()) {
            FrontendAtscCapabilities atscCaps{
                    .modulationCap =
                            static_cast<int32_t>(halInfo.frontendCaps.atscCaps().modulationCap),
            };
            caps.set<FrontendCapabilities::atscCaps>(atscCaps);
        }
        break;
    }
    case ::android::hardware::tv::tuner::V1_0::FrontendType::ATSC3: {
        if (HidlFrontendInfo::FrontendCapabilities::hidl_discriminator::atsc3Caps ==
            halInfo.frontendCaps.getDiscriminator()) {
            FrontendAtsc3Capabilities atsc3Caps{
                    .bandwidthCap =
                            static_cast<int32_t>(halInfo.frontendCaps.atsc3Caps().bandwidthCap),
                    .modulationCap =
                            static_cast<int32_t>(halInfo.frontendCaps.atsc3Caps().modulationCap),
                    .timeInterleaveModeCap = static_cast<int32_t>(
                            halInfo.frontendCaps.atsc3Caps().timeInterleaveModeCap),
                    .codeRateCap =
                            static_cast<int32_t>(halInfo.frontendCaps.atsc3Caps().codeRateCap),
                    .demodOutputFormatCap = static_cast<int8_t>(
                            halInfo.frontendCaps.atsc3Caps().demodOutputFormatCap),
                    .fecCap = static_cast<int32_t>(halInfo.frontendCaps.atsc3Caps().fecCap),
            };
            caps.set<FrontendCapabilities::atsc3Caps>(atsc3Caps);
        }
        break;
    }
    case ::android::hardware::tv::tuner::V1_0::FrontendType::DVBC: {
        if (HidlFrontendInfo::FrontendCapabilities::hidl_discriminator::dvbcCaps ==
            halInfo.frontendCaps.getDiscriminator()) {
            FrontendDvbcCapabilities dvbcCaps{
                    .modulationCap =
                            static_cast<int32_t>(halInfo.frontendCaps.dvbcCaps().modulationCap),
                    .fecCap = static_cast<int64_t>(halInfo.frontendCaps.dvbcCaps().fecCap),
                    .annexCap = static_cast<int8_t>(halInfo.frontendCaps.dvbcCaps().annexCap),
            };
            caps.set<FrontendCapabilities::dvbcCaps>(dvbcCaps);
        }
        break;
    }
    case ::android::hardware::tv::tuner::V1_0::FrontendType::DVBS: {
        if (HidlFrontendInfo::FrontendCapabilities::hidl_discriminator::dvbsCaps ==
            halInfo.frontendCaps.getDiscriminator()) {
            FrontendDvbsCapabilities dvbsCaps{
                    .modulationCap =
                            static_cast<int32_t>(halInfo.frontendCaps.dvbsCaps().modulationCap),
                    .innerfecCap =
                            static_cast<int64_t>(halInfo.frontendCaps.dvbsCaps().innerfecCap),
                    .standard = static_cast<int8_t>(halInfo.frontendCaps.dvbsCaps().standard),
            };
            caps.set<FrontendCapabilities::dvbsCaps>(dvbsCaps);
        }
        break;
    }
    case ::android::hardware::tv::tuner::V1_0::FrontendType::DVBT: {
        if (HidlFrontendInfo::FrontendCapabilities::hidl_discriminator::dvbtCaps ==
            halInfo.frontendCaps.getDiscriminator()) {
            FrontendDvbtCapabilities dvbtCaps{
                    .transmissionModeCap = static_cast<int32_t>(
                            halInfo.frontendCaps.dvbtCaps().transmissionModeCap),
                    .bandwidthCap =
                            static_cast<int32_t>(halInfo.frontendCaps.dvbtCaps().bandwidthCap),
                    .constellationCap =
                            static_cast<int32_t>(halInfo.frontendCaps.dvbtCaps().constellationCap),
                    .coderateCap =
                            static_cast<int32_t>(halInfo.frontendCaps.dvbtCaps().coderateCap),
                    .hierarchyCap =
                            static_cast<int32_t>(halInfo.frontendCaps.dvbtCaps().hierarchyCap),
                    .guardIntervalCap =
                            static_cast<int32_t>(halInfo.frontendCaps.dvbtCaps().guardIntervalCap),
                    .isT2Supported = halInfo.frontendCaps.dvbtCaps().isT2Supported,
                    .isMisoSupported = halInfo.frontendCaps.dvbtCaps().isMisoSupported,
            };
            caps.set<FrontendCapabilities::dvbtCaps>(dvbtCaps);
        }
        break;
    }
    case ::android::hardware::tv::tuner::V1_0::FrontendType::ISDBS: {
        if (HidlFrontendInfo::FrontendCapabilities::hidl_discriminator::isdbsCaps ==
            halInfo.frontendCaps.getDiscriminator()) {
            FrontendIsdbsCapabilities isdbsCaps{
                    .modulationCap =
                            static_cast<int32_t>(halInfo.frontendCaps.isdbsCaps().modulationCap),
                    .coderateCap =
                            static_cast<int32_t>(halInfo.frontendCaps.isdbsCaps().coderateCap),
            };
            caps.set<FrontendCapabilities::isdbsCaps>(isdbsCaps);
        }
        break;
    }
    case ::android::hardware::tv::tuner::V1_0::FrontendType::ISDBS3: {
        if (HidlFrontendInfo::FrontendCapabilities::hidl_discriminator::isdbs3Caps ==
            halInfo.frontendCaps.getDiscriminator()) {
            FrontendIsdbs3Capabilities isdbs3Caps{
                    .modulationCap =
                            static_cast<int32_t>(halInfo.frontendCaps.isdbs3Caps().modulationCap),
                    .coderateCap =
                            static_cast<int32_t>(halInfo.frontendCaps.isdbs3Caps().coderateCap),
            };
            caps.set<FrontendCapabilities::isdbs3Caps>(isdbs3Caps);
        }
        break;
    }
    case ::android::hardware::tv::tuner::V1_0::FrontendType::ISDBT: {
        if (HidlFrontendInfo::FrontendCapabilities::hidl_discriminator::isdbtCaps ==
            halInfo.frontendCaps.getDiscriminator()) {
            FrontendIsdbtCapabilities isdbtCaps{
                    .modeCap = static_cast<int32_t>(halInfo.frontendCaps.isdbtCaps().modeCap),
                    .bandwidthCap =
                            static_cast<int32_t>(halInfo.frontendCaps.isdbtCaps().bandwidthCap),
                    .modulationCap =
                            static_cast<int32_t>(halInfo.frontendCaps.isdbtCaps().modulationCap),
                    .coderateCap =
                            static_cast<int32_t>(halInfo.frontendCaps.isdbtCaps().coderateCap),
                    .guardIntervalCap =
                            static_cast<int32_t>(halInfo.frontendCaps.isdbtCaps().guardIntervalCap),
                    .timeInterleaveCap =
                            static_cast<int32_t>(FrontendIsdbtTimeInterleaveMode::UNDEFINED),
                    .isSegmentAuto = false,
                    .isFullSegment = false,
            };
            caps.set<FrontendCapabilities::isdbtCaps>(isdbtCaps);
        }
        break;
    }
    default: {
        if (static_cast<HidlFrontendType>(info.type) == HidlFrontendType::DTMB) {
            FrontendDtmbCapabilities dtmbCaps{
                    .transmissionModeCap = static_cast<int32_t>(halDtmbCaps.transmissionModeCap),
                    .bandwidthCap = static_cast<int32_t>(halDtmbCaps.bandwidthCap),
                    .modulationCap = static_cast<int32_t>(halDtmbCaps.modulationCap),
                    .codeRateCap = static_cast<int32_t>(halDtmbCaps.codeRateCap),
                    .guardIntervalCap = static_cast<int32_t>(halDtmbCaps.guardIntervalCap),
                    .interleaveModeCap = static_cast<int32_t>(halDtmbCaps.interleaveModeCap),
            };
            caps.set<FrontendCapabilities::dtmbCaps>(dtmbCaps);
        }
        break;
    }
    }

    info.frontendCaps = caps;
    return info;
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
