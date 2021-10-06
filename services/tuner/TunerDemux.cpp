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

#include "TunerDvr.h"
#include "TunerDemux.h"
#include "TunerTimeFilter.h"

using ::android::hardware::tv::tuner::V1_0::DemuxAlpFilterType;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterMainType;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterType;
using ::android::hardware::tv::tuner::V1_0::DemuxIpFilterType;
using ::android::hardware::tv::tuner::V1_0::DemuxMmtpFilterType;
using ::android::hardware::tv::tuner::V1_0::DemuxTlvFilterType;
using ::android::hardware::tv::tuner::V1_0::DemuxTsFilterType;
using ::android::hardware::tv::tuner::V1_0::DvrType;
using ::android::hardware::tv::tuner::V1_0::Result;

namespace android {

TunerDemux::TunerDemux(sp<IDemux> demux, int id) {
    mDemux = demux;
    mDemuxId = id;
}

TunerDemux::~TunerDemux() {
    mDemux = nullptr;
}

Status TunerDemux::setFrontendDataSource(const std::shared_ptr<ITunerFrontend>& frontend) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    int frontendId;
    frontend->getFrontendId(&frontendId);
    Result res = mDemux->setFrontendDataSource(frontendId);
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDemux::openFilter(
        int type, int subType, int bufferSize, const std::shared_ptr<ITunerFilterCallback>& cb,
        std::shared_ptr<ITunerFilter>* _aidl_return) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    DemuxFilterMainType mainType = static_cast<DemuxFilterMainType>(type);
    DemuxFilterType filterType {
        .mainType = mainType,
    };

    switch(mainType) {
        case DemuxFilterMainType::TS:
            filterType.subType.tsFilterType(static_cast<DemuxTsFilterType>(subType));
            break;
        case DemuxFilterMainType::MMTP:
            filterType.subType.mmtpFilterType(static_cast<DemuxMmtpFilterType>(subType));
            break;
        case DemuxFilterMainType::IP:
            filterType.subType.ipFilterType(static_cast<DemuxIpFilterType>(subType));
            break;
        case DemuxFilterMainType::TLV:
            filterType.subType.tlvFilterType(static_cast<DemuxTlvFilterType>(subType));
            break;
        case DemuxFilterMainType::ALP:
            filterType.subType.alpFilterType(static_cast<DemuxAlpFilterType>(subType));
            break;
    }
    Result status;
    sp<IFilter> filterSp;
    sp<IFilterCallback> cbSp = new TunerFilter::FilterCallback(cb);
    mDemux->openFilter(filterType, bufferSize, cbSp,
            [&](Result r, const sp<IFilter>& filter) {
                filterSp = filter;
                status = r;
            });
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    *_aidl_return = ::ndk::SharedRefBase::make<TunerFilter>(filterSp, type, subType);
    return Status::ok();
}

Status TunerDemux::openTimeFilter(shared_ptr<ITunerTimeFilter>* _aidl_return) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status;
    sp<ITimeFilter> filterSp;
    mDemux->openTimeFilter([&](Result r, const sp<ITimeFilter>& filter) {
        filterSp = filter;
        status = r;
    });
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    *_aidl_return = ::ndk::SharedRefBase::make<TunerTimeFilter>(filterSp);
    return Status::ok();
}

Status TunerDemux::getAvSyncHwId(const shared_ptr<ITunerFilter>& tunerFilter, int* _aidl_return) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    uint32_t avSyncHwId;
    Result res;
    sp<IFilter> halFilter = static_cast<TunerFilter*>(tunerFilter.get())->getHalFilter();
    mDemux->getAvSyncHwId(halFilter,
            [&](Result r, uint32_t id) {
                res = r;
                avSyncHwId = id;
            });
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    *_aidl_return = (int)avSyncHwId;
    return Status::ok();
}

Status TunerDemux::getAvSyncTime(int avSyncHwId, int64_t* _aidl_return) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    uint64_t time;
    Result res;
    mDemux->getAvSyncTime(static_cast<uint32_t>(avSyncHwId),
            [&](Result r, uint64_t ts) {
                res = r;
                time = ts;
            });
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    *_aidl_return = (int64_t)time;
    return Status::ok();
}

Status TunerDemux::openDvr(int dvrType, int bufferSize, const shared_ptr<ITunerDvrCallback>& cb,
        shared_ptr<ITunerDvr>* _aidl_return) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res;
    sp<IDvrCallback> callback = new TunerDvr::DvrCallback(cb);
    sp<IDvr> hidlDvr;
    mDemux->openDvr(static_cast<DvrType>(dvrType), bufferSize, callback,
            [&](Result r, const sp<IDvr>& dvr) {
                hidlDvr = dvr;
                res = r;
            });
    if (res != Result::SUCCESS) {
        *_aidl_return = NULL;
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    *_aidl_return = ::ndk::SharedRefBase::make<TunerDvr>(hidlDvr, dvrType);
    return Status::ok();
}

Status TunerDemux::connectCiCam(int ciCamId) {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mDemux->connectCiCam(static_cast<uint32_t>(ciCamId));
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDemux::disconnectCiCam() {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mDemux->disconnectCiCam();
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDemux::close() {
    if (mDemux == nullptr) {
        ALOGE("IDemux is not initialized.");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mDemux->close();
    mDemux = NULL;

    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}
}  // namespace android
