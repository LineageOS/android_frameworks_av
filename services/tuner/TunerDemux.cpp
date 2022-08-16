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

#define LOG_TAG "TunerDemux"

#include "TunerDemux.h"

#include <aidl/android/hardware/tv/tuner/IDvr.h>
#include <aidl/android/hardware/tv/tuner/IDvrCallback.h>
#include <aidl/android/hardware/tv/tuner/IFilter.h>
#include <aidl/android/hardware/tv/tuner/IFilterCallback.h>
#include <aidl/android/hardware/tv/tuner/ITimeFilter.h>
#include <aidl/android/hardware/tv/tuner/Result.h>

#include "TunerDvr.h"
#include "TunerTimeFilter.h"

using ::aidl::android::hardware::tv::tuner::IDvr;
using ::aidl::android::hardware::tv::tuner::IDvrCallback;
using ::aidl::android::hardware::tv::tuner::IFilter;
using ::aidl::android::hardware::tv::tuner::IFilterCallback;
using ::aidl::android::hardware::tv::tuner::ITimeFilter;
using ::aidl::android::hardware::tv::tuner::Result;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerDemux::TunerDemux(shared_ptr<IDemux> demux, int id) {
    mDemux = demux;
    mDemuxId = id;
}

TunerDemux::~TunerDemux() {
    mDemux = nullptr;
}

::ndk::ScopedAStatus TunerDemux::setFrontendDataSource(
        const shared_ptr<ITunerFrontend>& in_frontend) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    int frontendId;
    in_frontend->getFrontendId(&frontendId);

    return mDemux->setFrontendDataSource(frontendId);
}

::ndk::ScopedAStatus TunerDemux::setFrontendDataSourceById(int frontendId) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mDemux->setFrontendDataSource(frontendId);
}

::ndk::ScopedAStatus TunerDemux::openFilter(const DemuxFilterType& in_type, int32_t in_bufferSize,
                                            const shared_ptr<ITunerFilterCallback>& in_cb,
                                            shared_ptr<ITunerFilter>* _aidl_return) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    shared_ptr<IFilter> filter;
    shared_ptr<TunerFilter::FilterCallback> filterCb =
            ::ndk::SharedRefBase::make<TunerFilter::FilterCallback>(in_cb);
    shared_ptr<IFilterCallback> cb = filterCb;
    auto status = mDemux->openFilter(in_type, in_bufferSize, cb, &filter);
    if (status.isOk()) {
        *_aidl_return = ::ndk::SharedRefBase::make<TunerFilter>(filter, filterCb, in_type);
    }

    return status;
}

::ndk::ScopedAStatus TunerDemux::openTimeFilter(shared_ptr<ITunerTimeFilter>* _aidl_return) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    shared_ptr<ITimeFilter> filter;
    auto status = mDemux->openTimeFilter(&filter);
    if (status.isOk()) {
        *_aidl_return = ::ndk::SharedRefBase::make<TunerTimeFilter>(filter);
    }

    return status;
}

::ndk::ScopedAStatus TunerDemux::getAvSyncHwId(const shared_ptr<ITunerFilter>& tunerFilter,
                                               int32_t* _aidl_return) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    shared_ptr<IFilter> halFilter = (static_cast<TunerFilter*>(tunerFilter.get()))->getHalFilter();
    return mDemux->getAvSyncHwId(halFilter, _aidl_return);
}

::ndk::ScopedAStatus TunerDemux::getAvSyncTime(int32_t avSyncHwId, int64_t* _aidl_return) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mDemux->getAvSyncTime(avSyncHwId, _aidl_return);
}

::ndk::ScopedAStatus TunerDemux::openDvr(DvrType in_dvbType, int32_t in_bufferSize,
                                         const shared_ptr<ITunerDvrCallback>& in_cb,
                                         shared_ptr<ITunerDvr>* _aidl_return) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    shared_ptr<IDvrCallback> callback = ::ndk::SharedRefBase::make<TunerDvr::DvrCallback>(in_cb);
    shared_ptr<IDvr> halDvr;
    auto res = mDemux->openDvr(in_dvbType, in_bufferSize, callback, &halDvr);
    if (res.isOk()) {
        *_aidl_return = ::ndk::SharedRefBase::make<TunerDvr>(halDvr, in_dvbType);
    }

    return res;
}

::ndk::ScopedAStatus TunerDemux::connectCiCam(int32_t ciCamId) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mDemux->connectCiCam(ciCamId);
}

::ndk::ScopedAStatus TunerDemux::disconnectCiCam() {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mDemux->disconnectCiCam();
}

::ndk::ScopedAStatus TunerDemux::close() {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    auto res = mDemux->close();
    mDemux = nullptr;

    return res;
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
