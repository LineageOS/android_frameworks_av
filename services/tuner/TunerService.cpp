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
#include <aidl/android/media/tv/tunerresourcemanager/TunerFrontendInfo.h>
#include <android/binder_manager.h>
#include <android/content/pm/IPackageManagerNative.h>
#include <binder/IServiceManager.h>
#include <utils/Log.h>

#include "TunerDemux.h"
#include "TunerDescrambler.h"
#include "TunerFrontend.h"
#include "TunerLnb.h"

using ::aidl::android::hardware::tv::tuner::IDemux;
using ::aidl::android::hardware::tv::tuner::IDescrambler;
using ::aidl::android::hardware::tv::tuner::IFrontend;
using ::aidl::android::hardware::tv::tuner::Result;
using ::aidl::android::media::tv::tunerresourcemanager::TunerFrontendInfo;
using ::android::defaultServiceManager;
using ::android::IBinder;
using ::android::interface_cast;
using ::android::IServiceManager;
using ::android::sp;
using ::android::String16;
using ::android::binder::Status;
using ::android::content::pm::IPackageManagerNative;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerService::TunerService() {
    sp<IServiceManager> serviceMgr = defaultServiceManager();
    sp<IPackageManagerNative> packageMgr;
    if (serviceMgr.get() == nullptr) {
        ALOGE("%s: Cannot find service manager", __func__);
        return;
    } else {
        sp<IBinder> binder = serviceMgr->waitForService(String16("package_native"));
        packageMgr = interface_cast<IPackageManagerNative>(binder);
    }

    if (packageMgr != nullptr) {
        bool hasFeature = false;
        Status status = packageMgr->hasSystemFeature(FEATURE_TUNER, 0, &hasFeature);
        if (!status.isOk()) {
            ALOGE("%s: hasSystemFeature failed: %s", __func__, status.exceptionMessage().c_str());
            return;
        }
        if (!hasFeature) {
            ALOGD("Current device does not support tuner feaure.");
            return;
        }
    } else {
        ALOGD("%s: Cannot find package manager.", __func__);
        return;
    }

    ::ndk::SpAIBinder binder(AServiceManager_waitForService("tv_tuner_resource_mgr"));
    mTunerResourceManager = ITunerResourceManager::fromBinder(binder);
    updateTunerResources();
}

TunerService::~TunerService() {}

binder_status_t TunerService::instantiate() {
    shared_ptr<TunerService> service =
            ::ndk::SharedRefBase::make<TunerService>();
    return AServiceManager_addService(service->asBinder().get(), getServiceName());
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

    int id = getResourceIdFromHandle(frontendHandle, FRONTEND);
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
    int id = getResourceIdFromHandle(lnbHandle, LNB);
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
    // int id = getResourceIdFromHandle(descramblerHandle, DESCRAMBLER);
    auto status = mTuner->openDescrambler(&descrambler);
    if (status.isOk()) {
        *_aidl_return = ::ndk::SharedRefBase::make<TunerDescrambler>(descrambler);
    }

    return status;
}

void TunerService::updateTunerResources() {
    if (!hasITuner() || mTunerResourceManager == nullptr) {
        ALOGE("Failed to updateTunerResources");
        return;
    }

    updateFrontendResources();
    updateLnbResources();
    // TODO: update Demux, Descrambler.
}

::ndk::ScopedAStatus TunerService::getTunerHalVersion(int* _aidl_return) {
    hasITuner();
    *_aidl_return = mTunerVersion;
    return ::ndk::ScopedAStatus::ok();
}

void TunerService::updateFrontendResources() {
    vector<int32_t> ids;
    auto status = mTuner->getFrontendIds(&ids);
    if (!status.isOk()) {
        return;
    }

    vector<TunerFrontendInfo> infos;
    for (int i = 0; i < ids.size(); i++) {
        FrontendInfo frontendInfo;
        auto res = mTuner->getFrontendInfo(ids[i], &frontendInfo);
        if (!res.isOk()) {
            continue;
        }
        TunerFrontendInfo tunerFrontendInfo{
                .handle = getResourceHandleFromId((int)ids[i], FRONTEND),
                .type = static_cast<int>(frontendInfo.type),
                .exclusiveGroupId = frontendInfo.exclusiveGroupId,
        };
        infos.push_back(tunerFrontendInfo);
    }
    mTunerResourceManager->setFrontendInfoList(infos);
}

void TunerService::updateLnbResources() {
    vector<int32_t> handles = getLnbHandles();
    if (handles.size() == 0) {
        return;
    }
    mTunerResourceManager->setLnbInfoList(handles);
}

vector<int32_t> TunerService::getLnbHandles() {
    vector<int32_t> lnbHandles;
    if (mTuner != nullptr) {
        vector<int32_t> lnbIds;
        auto res = mTuner->getLnbIds(&lnbIds);
        if (res.isOk()) {
            for (int i = 0; i < lnbIds.size(); i++) {
                lnbHandles.push_back(getResourceHandleFromId(lnbIds[i], LNB));
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
