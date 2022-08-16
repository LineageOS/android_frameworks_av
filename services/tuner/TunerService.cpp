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

shared_ptr<TunerService> TunerService::sTunerService = nullptr;

TunerService::TunerService() {
    if (!TunerHelper::checkTunerFeature()) {
        ALOGD("Device doesn't have tuner hardware.");
        return;
    }

    updateTunerResources();
}

TunerService::~TunerService() {}

binder_status_t TunerService::instantiate() {
    sTunerService = ::ndk::SharedRefBase::make<TunerService>();
    return AServiceManager_addService(sTunerService->asBinder().get(), getServiceName());
}

shared_ptr<TunerService> TunerService::getTunerService() {
    return sTunerService;
}

bool TunerService::hasITuner() {
    ALOGV("hasITuner");
    if (mTuner != nullptr) {
        return true;
    }
    const string statsServiceName = string() + ITuner::descriptor + "/default";
    if (AServiceManager_isDeclared(statsServiceName.c_str())) {
        ::ndk::SpAIBinder binder(AServiceManager_waitForService(statsServiceName.c_str()));
        mTuner = ITuner::fromBinder(binder);
    } else {
        mTuner = nullptr;
        ALOGE("Failed to get Tuner HAL Service");
        return false;
    }

    mTunerVersion = TUNER_HAL_VERSION_2_0;
    // TODO: Enable this after Tuner HAL is frozen.
    // if (mTuner->getInterfaceVersion(&mTunerVersion).isOk()) {
    //  // Tuner AIDL HAL version 1 will be Tuner HAL 2.0
    //  mTunerVersion = (mTunerVersion + 1) << 16;
    //}

    return true;
}

::ndk::ScopedAStatus TunerService::openDemux(int32_t /* in_demuxHandle */,
                                             shared_ptr<ITunerDemux>* _aidl_return) {
    ALOGV("openDemux");
    if (!hasITuner()) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }
    vector<int32_t> id;
    shared_ptr<IDemux> demux;
    auto status = mTuner->openDemux(&id, &demux);
    if (status.isOk()) {
        *_aidl_return = ::ndk::SharedRefBase::make<TunerDemux>(demux, id[0]);
    }

    return status;
}

::ndk::ScopedAStatus TunerService::getDemuxCaps(DemuxCapabilities* _aidl_return) {
    ALOGV("getDemuxCaps");
    if (!hasITuner()) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mTuner->getDemuxCaps(_aidl_return);
}

::ndk::ScopedAStatus TunerService::getFrontendIds(vector<int32_t>* ids) {
    if (!hasITuner()) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mTuner->getFrontendIds(ids);
}

::ndk::ScopedAStatus TunerService::getFrontendInfo(int32_t id, FrontendInfo* _aidl_return) {
    if (!hasITuner()) {
        ALOGE("ITuner service is not init.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mTuner->getFrontendInfo(id, _aidl_return);
}

::ndk::ScopedAStatus TunerService::openFrontend(int32_t frontendHandle,
                                                shared_ptr<ITunerFrontend>* _aidl_return) {
    if (!hasITuner()) {
        ALOGE("ITuner service is not init.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    int id = TunerHelper::getResourceIdFromHandle(frontendHandle, FRONTEND);
    shared_ptr<IFrontend> frontend;
    auto status = mTuner->openFrontendById(id, &frontend);
    if (status.isOk()) {
        *_aidl_return = ::ndk::SharedRefBase::make<TunerFrontend>(frontend, id);
    }

    return status;
}

::ndk::ScopedAStatus TunerService::openLnb(int lnbHandle, shared_ptr<ITunerLnb>* _aidl_return) {
    if (!hasITuner()) {
        ALOGD("get ITuner failed");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

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
    if (!hasITuner()) {
        ALOGE("get ITuner failed");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

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
    if (!hasITuner()) {
        ALOGD("get ITuner failed");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    shared_ptr<IDescrambler> descrambler;
    // int id = TunerHelper::getResourceIdFromHandle(descramblerHandle, DESCRAMBLER);
    auto status = mTuner->openDescrambler(&descrambler);
    if (status.isOk()) {
        *_aidl_return = ::ndk::SharedRefBase::make<TunerDescrambler>(descrambler);
    }

    return status;
}

::ndk::ScopedAStatus TunerService::getTunerHalVersion(int* _aidl_return) {
    hasITuner();
    *_aidl_return = mTunerVersion;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerService::openSharedFilter(const string& in_filterToken,
                                                    const shared_ptr<ITunerFilterCallback>& in_cb,
                                                    shared_ptr<ITunerFilter>* _aidl_return) {
    if (!hasITuner()) {
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

::ndk::ScopedAStatus TunerService::setLna(bool bEnable) {
    if (!hasITuner()) {
        ALOGD("get ITuner failed");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mTuner->setLna(bEnable);
}

::ndk::ScopedAStatus TunerService::setMaxNumberOfFrontends(FrontendType in_frontendType,
                                                           int32_t in_maxNumber) {
    if (!hasITuner()) {
        ALOGD("get ITuner failed");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mTuner->setMaxNumberOfFrontends(in_frontendType, in_maxNumber);
}

::ndk::ScopedAStatus TunerService::getMaxNumberOfFrontends(FrontendType in_frontendType,
                                                           int32_t* _aidl_return) {
    if (!hasITuner()) {
        ALOGD("get ITuner failed");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

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
    if (!hasITuner()) {
        ALOGE("Failed to updateTunerResources");
        return;
    }

    TunerHelper::updateTunerResources(getTRMFrontendInfos(), getTRMLnbHandles());
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
