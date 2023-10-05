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
#define LOG_TAG "TunerService"

#include "TunerService.h"

#include <aidl/android/hardware/tv/tuner/IDemux.h>
#include <aidl/android/hardware/tv/tuner/IDescrambler.h>
#include <aidl/android/hardware/tv/tuner/IFrontend.h>
#include <aidl/android/hardware/tv/tuner/ILnb.h>
#include <aidl/android/hardware/tv/tuner/Result.h>
#include <android/binder_manager.h>
#include <binder/IPCThreadState.h>
#include <binder/PermissionCache.h>
#include <cutils/properties.h>
#include <utils/Log.h>

#include <string>

#include "TunerDemux.h"
#include "TunerDescrambler.h"
#include "TunerFrontend.h"
#include "TunerHelper.h"
#include "TunerLnb.h"

using ::aidl::android::hardware::tv::tuner::IDemux;
using ::aidl::android::hardware::tv::tuner::IDescrambler;
using ::aidl::android::hardware::tv::tuner::IFrontend;
using ::aidl::android::hardware::tv::tuner::Result;
using ::android::IPCThreadState;
using ::android::PermissionCache;
using ::android::sp;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerService::TunerService() {
    const string statsServiceName = string() + ITuner::descriptor + "/default";
    ::ndk::SpAIBinder binder(AServiceManager_waitForService(statsServiceName.c_str()));
    mTuner = ITuner::fromBinder(binder);
    ALOGE_IF(mTuner == nullptr, "Failed to get Tuner HAL Service");

    mTunerVersion = TUNER_HAL_VERSION_2_0;
    if (mTuner->getInterfaceVersion(&mTunerVersion).isOk()) {
        // Tuner AIDL HAL version 1 will be Tuner HAL 2.0
        mTunerVersion = (mTunerVersion + 1) << 16;
    }

    // Register the tuner resources to TRM.
    updateTunerResources();
}

TunerService::~TunerService() {
    mTuner = nullptr;
}

binder_status_t TunerService::instantiate() {
    shared_ptr<TunerService> tunerService = ::ndk::SharedRefBase::make<TunerService>();
    bool lazyHal = property_get_bool("ro.tuner.lazyhal", false);
    if (lazyHal) {
        return AServiceManager_registerLazyService(tunerService->asBinder().get(),
                                                   getServiceName());
    }
    return AServiceManager_addService(tunerService->asBinder().get(), getServiceName());
}

::ndk::ScopedAStatus TunerService::openDemux(int32_t in_demuxHandle,
                                             shared_ptr<ITunerDemux>* _aidl_return) {
    ALOGV("openDemux");
    shared_ptr<IDemux> demux;
    bool fallBackToOpenDemux = false;
    vector<int32_t> ids;

    if (mTunerVersion <= TUNER_HAL_VERSION_2_0) {
        fallBackToOpenDemux = true;
    } else {
        mTuner->getDemuxIds(&ids);
        if (ids.size() == 0) {
            fallBackToOpenDemux = true;
        }
    }

    if (fallBackToOpenDemux) {
        auto status = mTuner->openDemux(&ids, &demux);
        if (status.isOk()) {
            *_aidl_return = ::ndk::SharedRefBase::make<TunerDemux>(demux, ids[0],
                                                                   this->ref<TunerService>());
        }
        return status;
    } else {
        int id = TunerHelper::getResourceIdFromHandle(in_demuxHandle, DEMUX);
        auto status = mTuner->openDemuxById(id, &demux);
        if (status.isOk()) {
            *_aidl_return =
                    ::ndk::SharedRefBase::make<TunerDemux>(demux, id, this->ref<TunerService>());
        }
        return status;
    }
}

::ndk::ScopedAStatus TunerService::getDemuxInfo(int32_t in_demuxHandle, DemuxInfo* _aidl_return) {
    if (mTunerVersion <= TUNER_HAL_VERSION_2_0) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }
    int id = TunerHelper::getResourceIdFromHandle(in_demuxHandle, DEMUX);
    return mTuner->getDemuxInfo(id, _aidl_return);
}

::ndk::ScopedAStatus TunerService::getDemuxInfoList(vector<DemuxInfo>* _aidl_return) {
    if (mTunerVersion <= TUNER_HAL_VERSION_2_0) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }
    vector<DemuxInfo> demuxInfoList;
    vector<int32_t> ids;
    auto status = mTuner->getDemuxIds(&ids);
    if (!status.isOk()) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    for (int i = 0; i < ids.size(); i++) {
        DemuxInfo demuxInfo;
        auto res = mTuner->getDemuxInfo(ids[i], &demuxInfo);
        if (!res.isOk()) {
            continue;
        }
        demuxInfoList.push_back(demuxInfo);
    }

    if (demuxInfoList.size() > 0) {
        *_aidl_return = demuxInfoList;
        return ::ndk::ScopedAStatus::ok();
    } else {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }
}

::ndk::ScopedAStatus TunerService::getDemuxCaps(DemuxCapabilities* _aidl_return) {
    ALOGV("getDemuxCaps");
    return mTuner->getDemuxCaps(_aidl_return);
}

::ndk::ScopedAStatus TunerService::getFrontendIds(vector<int32_t>* ids) {
    return mTuner->getFrontendIds(ids);
}

::ndk::ScopedAStatus TunerService::getFrontendInfo(int32_t id, FrontendInfo* _aidl_return) {
    return mTuner->getFrontendInfo(id, _aidl_return);
}

::ndk::ScopedAStatus TunerService::openFrontend(int32_t frontendHandle,
                                                shared_ptr<ITunerFrontend>* _aidl_return) {
    int id = TunerHelper::getResourceIdFromHandle(frontendHandle, FRONTEND);
    shared_ptr<IFrontend> frontend;
    auto status = mTuner->openFrontendById(id, &frontend);
    if (status.isOk()) {
        *_aidl_return = ::ndk::SharedRefBase::make<TunerFrontend>(frontend, id);
    }

    return status;
}

::ndk::ScopedAStatus TunerService::openLnb(int lnbHandle, shared_ptr<ITunerLnb>* _aidl_return) {
    shared_ptr<ILnb> lnb;
    int id = TunerHelper::getResourceIdFromHandle(lnbHandle, LNB);
    auto status = mTuner->openLnbById(id, &lnb);
    if (status.isOk()) {
        *_aidl_return = ::ndk::SharedRefBase::make<TunerLnb>(lnb, id);
    }

    return status;
}

::ndk::ScopedAStatus TunerService::openLnbByName(const string& lnbName,
                                                 shared_ptr<ITunerLnb>* _aidl_return) {
    vector<int32_t> id;
    shared_ptr<ILnb> lnb;
    auto status = mTuner->openLnbByName(lnbName, &id, &lnb);
    if (status.isOk()) {
        *_aidl_return = ::ndk::SharedRefBase::make<TunerLnb>(lnb, id[0]);
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerService::openDescrambler(int32_t /*descramblerHandle*/,
                                                   shared_ptr<ITunerDescrambler>* _aidl_return) {
    shared_ptr<IDescrambler> descrambler;
    // int id = TunerHelper::getResourceIdFromHandle(descramblerHandle, DESCRAMBLER);
    auto status = mTuner->openDescrambler(&descrambler);
    if (status.isOk()) {
        *_aidl_return = ::ndk::SharedRefBase::make<TunerDescrambler>(descrambler);
    }

    return status;
}

::ndk::ScopedAStatus TunerService::getTunerHalVersion(int* _aidl_return) {
    *_aidl_return = mTunerVersion;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerService::openSharedFilter(const string& in_filterToken,
                                                    const shared_ptr<ITunerFilterCallback>& in_cb,
                                                    shared_ptr<ITunerFilter>* _aidl_return) {
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

    shared_ptr<TunerFilter> filter = mSharedFilters.at(in_filterToken);
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

::ndk::ScopedAStatus TunerService::isLnaSupported(bool* _aidl_return) {
    ALOGV("isLnaSupported");
    return mTuner->isLnaSupported(_aidl_return);
}

::ndk::ScopedAStatus TunerService::setLna(bool bEnable) {
    return mTuner->setLna(bEnable);
}

::ndk::ScopedAStatus TunerService::setMaxNumberOfFrontends(FrontendType in_frontendType,
                                                           int32_t in_maxNumber) {
    return mTuner->setMaxNumberOfFrontends(in_frontendType, in_maxNumber);
}

::ndk::ScopedAStatus TunerService::getMaxNumberOfFrontends(FrontendType in_frontendType,
                                                           int32_t* _aidl_return) {
    return mTuner->getMaxNumberOfFrontends(in_frontendType, _aidl_return);
}

string TunerService::addFilterToShared(const shared_ptr<TunerFilter>& sharedFilter) {
    Mutex::Autolock _l(mSharedFiltersLock);

    // Use sharedFilter address as token.
    string token = to_string(reinterpret_cast<std::uintptr_t>(sharedFilter.get()));
    mSharedFilters[token] = sharedFilter;
    return token;
}

void TunerService::removeSharedFilter(const shared_ptr<TunerFilter>& sharedFilter) {
    Mutex::Autolock _l(mSharedFiltersLock);

    // Use sharedFilter address as token.
    mSharedFilters.erase(to_string(reinterpret_cast<std::uintptr_t>(sharedFilter.get())));
}

void TunerService::updateTunerResources() {
    TunerHelper::updateTunerResources(getTRMFrontendInfos(),
                                      getTRMDemuxInfos(),
                                      getTRMLnbHandles());
}

vector<TunerFrontendInfo> TunerService::getTRMFrontendInfos() {
    vector<TunerFrontendInfo> infos;
    vector<int32_t> ids;
    auto status = mTuner->getFrontendIds(&ids);
    if (!status.isOk()) {
        return infos;
    }

    for (int i = 0; i < ids.size(); i++) {
        FrontendInfo frontendInfo;
        auto res = mTuner->getFrontendInfo(ids[i], &frontendInfo);
        if (!res.isOk()) {
            continue;
        }
        TunerFrontendInfo tunerFrontendInfo{
                .handle = TunerHelper::getResourceHandleFromId((int)ids[i], FRONTEND),
                .type = static_cast<int>(frontendInfo.type),
                .exclusiveGroupId = frontendInfo.exclusiveGroupId,
        };
        infos.push_back(tunerFrontendInfo);
    }

    return infos;
}

vector<TunerDemuxInfo> TunerService::getTRMDemuxInfos() {
    vector<TunerDemuxInfo> infos;
    vector<int32_t> ids;

    if (mTunerVersion <= TUNER_HAL_VERSION_2_0) {
        return infos;
    }

    auto status = mTuner->getDemuxIds(&ids);
    if (!status.isOk()) {
        return infos;
    }

    for (int i = 0; i < ids.size(); i++) {
        DemuxInfo demuxInfo;
        mTuner->getDemuxInfo(ids[i], &demuxInfo);
        TunerDemuxInfo tunerDemuxInfo{
                .handle = TunerHelper::getResourceHandleFromId((int)ids[i], DEMUX),
                .filterTypes = static_cast<int>(demuxInfo.filterTypes)
        };
        infos.push_back(tunerDemuxInfo);
    }

    return infos;
}

vector<int32_t> TunerService::getTRMLnbHandles() {
    vector<int32_t> lnbHandles;
    if (mTuner != nullptr) {
        vector<int32_t> lnbIds;
        auto res = mTuner->getLnbIds(&lnbIds);
        if (res.isOk()) {
            for (int i = 0; i < lnbIds.size(); i++) {
                lnbHandles.push_back(TunerHelper::getResourceHandleFromId(lnbIds[i], LNB));
            }
        }
    }

    return lnbHandles;
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
