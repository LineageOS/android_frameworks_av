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

#define LOG_TAG "TunerHidlDemux"

#include "TunerHidlDemux.h"

#include "TunerHidlDvr.h"
#include "TunerHidlFilter.h"
#include "TunerHidlService.h"
#include "TunerHidlTimeFilter.h"

using ::aidl::android::hardware::tv::tuner::DemuxFilterSubType;

using HidlDemuxAlpFilterType = ::android::hardware::tv::tuner::V1_0::DemuxAlpFilterType;
using HidlDemuxFilterMainType = ::android::hardware::tv::tuner::V1_0::DemuxFilterMainType;
using HidlDemuxFilterType = ::android::hardware::tv::tuner::V1_0::DemuxFilterType;
using HidlDemuxIpFilterType = ::android::hardware::tv::tuner::V1_0::DemuxIpFilterType;
using HidlDemuxMmtpFilterType = ::android::hardware::tv::tuner::V1_0::DemuxMmtpFilterType;
using HidlDemuxTlvFilterType = ::android::hardware::tv::tuner::V1_0::DemuxTlvFilterType;
using HidlDemuxTsFilterType = ::android::hardware::tv::tuner::V1_0::DemuxTsFilterType;
using HidlDvrType = ::android::hardware::tv::tuner::V1_0::DvrType;
using HidlResult = ::android::hardware::tv::tuner::V1_0::Result;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerHidlDemux::TunerHidlDemux(const sp<IDemux> demux, const int id,
                               const shared_ptr<TunerHidlService> tuner) {
    mDemux = demux;
    mDemuxId = id;
    mTunerService = tuner;
}

TunerHidlDemux::~TunerHidlDemux() {
    mDemux = nullptr;
    mTunerService = nullptr;
}

::ndk::ScopedAStatus TunerHidlDemux::setFrontendDataSource(
        const shared_ptr<ITunerFrontend>& in_frontend) {
    int frontendId;
    in_frontend->getFrontendId(&frontendId);
    HidlResult res = mDemux->setFrontendDataSource(frontendId);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDemux::setFrontendDataSourceById(int frontendId) {
    HidlResult res = mDemux->setFrontendDataSource(frontendId);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDemux::openFilter(const DemuxFilterType& in_type,
                                                int32_t in_bufferSize,
                                                const shared_ptr<ITunerFilterCallback>& in_cb,
                                                shared_ptr<ITunerFilter>* _aidl_return) {
    HidlDemuxFilterMainType mainType = static_cast<HidlDemuxFilterMainType>(in_type.mainType);
    HidlDemuxFilterType filterType{
            .mainType = mainType,
    };

    switch (mainType) {
    case HidlDemuxFilterMainType::TS:
        filterType.subType.tsFilterType(static_cast<HidlDemuxTsFilterType>(
                in_type.subType.get<DemuxFilterSubType::Tag::tsFilterType>()));
        break;
    case HidlDemuxFilterMainType::MMTP:
        filterType.subType.mmtpFilterType(static_cast<HidlDemuxMmtpFilterType>(
                in_type.subType.get<DemuxFilterSubType::Tag::mmtpFilterType>()));
        break;
    case HidlDemuxFilterMainType::IP:
        filterType.subType.ipFilterType(static_cast<HidlDemuxIpFilterType>(
                in_type.subType.get<DemuxFilterSubType::Tag::ipFilterType>()));
        break;
    case HidlDemuxFilterMainType::TLV:
        filterType.subType.tlvFilterType(static_cast<HidlDemuxTlvFilterType>(
                in_type.subType.get<DemuxFilterSubType::Tag::tlvFilterType>()));
        break;
    case HidlDemuxFilterMainType::ALP:
        filterType.subType.alpFilterType(static_cast<HidlDemuxAlpFilterType>(
                in_type.subType.get<DemuxFilterSubType::Tag::alpFilterType>()));
        break;
    }
    HidlResult status;
    sp<HidlIFilter> filterSp;
    sp<TunerHidlFilter::FilterCallback> filterCb = new TunerHidlFilter::FilterCallback(in_cb);
    sp<::android::hardware::tv::tuner::V1_0::IFilterCallback> cbSp = filterCb;
    mDemux->openFilter(filterType, static_cast<uint32_t>(in_bufferSize), cbSp,
                       [&](HidlResult r, const sp<HidlIFilter>& filter) {
                           filterSp = filter;
                           status = r;
                       });
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    *_aidl_return =
            ::ndk::SharedRefBase::make<TunerHidlFilter>(filterSp, filterCb, in_type, mTunerService);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDemux::openTimeFilter(shared_ptr<ITunerTimeFilter>* _aidl_return) {
    HidlResult status;
    sp<HidlITimeFilter> filterSp;
    mDemux->openTimeFilter([&](HidlResult r, const sp<HidlITimeFilter>& filter) {
        filterSp = filter;
        status = r;
    });
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    *_aidl_return = ::ndk::SharedRefBase::make<TunerHidlTimeFilter>(filterSp);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDemux::getAvSyncHwId(const shared_ptr<ITunerFilter>& tunerFilter,
                                                   int32_t* _aidl_return) {
    uint32_t avSyncHwId;
    HidlResult res;
    sp<HidlIFilter> halFilter = static_cast<TunerHidlFilter*>(tunerFilter.get())->getHalFilter();
    mDemux->getAvSyncHwId(halFilter, [&](HidlResult r, uint32_t id) {
        res = r;
        avSyncHwId = id;
    });
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    *_aidl_return = (int)avSyncHwId;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDemux::getAvSyncTime(int32_t avSyncHwId, int64_t* _aidl_return) {
    uint64_t time;
    HidlResult res;
    mDemux->getAvSyncTime(static_cast<uint32_t>(avSyncHwId), [&](HidlResult r, uint64_t ts) {
        res = r;
        time = ts;
    });
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    *_aidl_return = (int64_t)time;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDemux::openDvr(DvrType in_dvbType, int32_t in_bufferSize,
                                             const shared_ptr<ITunerDvrCallback>& in_cb,
                                             shared_ptr<ITunerDvr>* _aidl_return) {
    HidlResult res;
    sp<HidlIDvrCallback> callback = new TunerHidlDvr::DvrCallback(in_cb);
    sp<HidlIDvr> hidlDvr;
    mDemux->openDvr(static_cast<HidlDvrType>(in_dvbType), in_bufferSize, callback,
                    [&](HidlResult r, const sp<HidlIDvr>& dvr) {
                        hidlDvr = dvr;
                        res = r;
                    });
    if (res != HidlResult::SUCCESS) {
        *_aidl_return = nullptr;
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    *_aidl_return = ::ndk::SharedRefBase::make<TunerHidlDvr>(hidlDvr, in_dvbType);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDemux::connectCiCam(int32_t ciCamId) {
    HidlResult res = mDemux->connectCiCam(static_cast<uint32_t>(ciCamId));
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDemux::disconnectCiCam() {
    HidlResult res = mDemux->disconnectCiCam();
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDemux::close() {
    HidlResult res = mDemux->close();
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
