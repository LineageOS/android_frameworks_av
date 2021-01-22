/**
 * Copyright (c) 2020, The Android Open Source Project
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

#define LOG_TAG "TunerService"

#include <android/binder_manager.h>
#include <utils/Log.h>
#include "TunerService.h"
#include "TunerFrontend.h"
#include "TunerLnb.h"
#include "TunerDemux.h"

using ::aidl::android::media::tv::tuner::TunerFrontendAnalogCapabilities;
using ::aidl::android::media::tv::tuner::TunerFrontendAtsc3Capabilities;
using ::aidl::android::media::tv::tuner::TunerFrontendAtscCapabilities;
using ::aidl::android::media::tv::tuner::TunerFrontendCableCapabilities;
using ::aidl::android::media::tv::tuner::TunerFrontendCapabilities;
using ::aidl::android::media::tv::tuner::TunerFrontendDvbsCapabilities;
using ::aidl::android::media::tv::tuner::TunerFrontendDvbtCapabilities;
using ::aidl::android::media::tv::tuner::TunerFrontendIsdbs3Capabilities;
using ::aidl::android::media::tv::tuner::TunerFrontendIsdbsCapabilities;
using ::aidl::android::media::tv::tuner::TunerFrontendIsdbtCapabilities;
using ::android::hardware::hidl_vec;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterAvSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterMainType;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterType;
using ::android::hardware::tv::tuner::V1_0::DemuxTsFilterType;
using ::android::hardware::tv::tuner::V1_0::FrontendId;
using ::android::hardware::tv::tuner::V1_0::FrontendType;
using ::android::hardware::tv::tuner::V1_0::IFrontend;
using ::android::hardware::tv::tuner::V1_0::ILnb;
using ::android::hardware::tv::tuner::V1_0::LnbId;
using ::android::hardware::tv::tuner::V1_0::Result;

namespace android {

TunerService::TunerService() {}
TunerService::~TunerService() {}

void TunerService::instantiate() {
    shared_ptr<TunerService> service =
            ::ndk::SharedRefBase::make<TunerService>();
    AServiceManager_addService(service->asBinder().get(), getServiceName());
}

template <typename HidlPayload, typename AidlPayload, typename AidlFlavor>
bool TunerService::unsafeHidlToAidlMQDescriptor(
        const hardware::MQDescriptor<HidlPayload, FlavorTypeToValue<AidlFlavor>::value>& hidlDesc,
        MQDescriptor<AidlPayload, AidlFlavor>* aidlDesc) {
    // TODO: use the builtin coversion method when it's merged.
    ALOGD("unsafeHidlToAidlMQDescriptor");
    static_assert(sizeof(HidlPayload) == sizeof(AidlPayload), "Payload types are incompatible");
    static_assert(
            has_typedef_fixed_size<AidlPayload>::value == true ||
            is_fundamental<AidlPayload>::value ||
            is_enum<AidlPayload>::value,
            "Only fundamental types, enums, and AIDL parcelables annotated with @FixedSize "
            "and built for the NDK backend are supported as AIDL payload types.");
    aidlDesc->fileDescriptor = ndk::ScopedFileDescriptor(dup(hidlDesc.handle()->data[0]));
    for (const auto& grantor : hidlDesc.grantors()) {
        if (static_cast<int32_t>(grantor.offset) < 0 || static_cast<int64_t>(grantor.extent) < 0) {
            ALOGD("Unsafe static_cast of grantor fields. offset=%d, extend=%ld",
                    static_cast<int32_t>(grantor.offset), static_cast<long>(grantor.extent));
            logError(
                    "Unsafe static_cast of grantor fields. Either the hardware::MQDescriptor is "
                    "invalid, or the MessageQueue is too large to be described by AIDL.");
            return false;
        }
        aidlDesc->grantors.push_back(
                GrantorDescriptor {
                        .offset = static_cast<int32_t>(grantor.offset),
                        .extent = static_cast<int64_t>(grantor.extent)
                });
    }
    if (static_cast<int32_t>(hidlDesc.getQuantum()) < 0 ||
            static_cast<int32_t>(hidlDesc.getFlags()) < 0) {
        ALOGD("Unsafe static_cast of quantum or flags. Quantum=%d, flags=%d",
                static_cast<int32_t>(hidlDesc.getQuantum()),
                static_cast<int32_t>(hidlDesc.getFlags()));
        logError(
                "Unsafe static_cast of quantum or flags. Either the hardware::MQDescriptor is "
                "invalid, or the MessageQueue is too large to be described by AIDL.");
        return false;
    }
    aidlDesc->quantum = static_cast<int32_t>(hidlDesc.getQuantum());
    aidlDesc->flags = static_cast<int32_t>(hidlDesc.getFlags());
    return true;
}

bool TunerService::getITuner() {
    ALOGD("getITuner");
    if (mTuner != nullptr) {
        return true;
    }
    mTuner = ITuner::getService();
    if (mTuner == nullptr) {
        ALOGE("Failed to get ITuner service");
        return false;
    }
    return true;
}

Status TunerService::openDemux(
        int /* demuxHandle */, std::shared_ptr<ITunerDemux>* _aidl_return) {
    ALOGD("openDemux");
    if (!getITuner()) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::NOT_INITIALIZED));
    }
    if (mDemux != nullptr) {
        *_aidl_return = mDemux->ref<ITunerDemux>();
        return Status::ok();
    }
    Result res;
    uint32_t id;
    sp<IDemux> demuxSp = nullptr;
    mTuner->openDemux([&](Result r, uint32_t demuxId, const sp<IDemux>& demux) {
        demuxSp = demux;
        id = demuxId;
        res = r;
        ALOGD("open demux, id = %d", demuxId);
    });
    if (res == Result::SUCCESS) {
        mDemux = ::ndk::SharedRefBase::make<TunerDemux>(demuxSp, id);
        *_aidl_return = mDemux->ref<ITunerDemux>();
        return Status::ok();
    }

    ALOGD("open demux failed, res = %d", res);
    mDemux = nullptr;
    return Status::fromServiceSpecificError(static_cast<int32_t>(res));
}

Result TunerService::configFilter() {
    ALOGD("configFilter");
    if (mFilter == NULL) {
        ALOGD("Failed to configure filter: filter not found");
        return Result::NOT_INITIALIZED;
    }
    DemuxFilterSettings filterSettings;
    DemuxTsFilterSettings tsFilterSettings {
        .tpid = 256,
    };
    DemuxFilterAvSettings filterAvSettings {
        .isPassthrough = false,
    };
    tsFilterSettings.filterSettings.av(filterAvSettings);
    filterSettings.ts(tsFilterSettings);
    Result res = mFilter->configure(filterSettings);

    if (res != Result::SUCCESS) {
        ALOGD("config filter failed, res = %d", res);
        return res;
    }

    Result getQueueDescResult = Result::UNKNOWN_ERROR;
    mFilter->getQueueDesc(
            [&](Result r, const MQDescriptorSync<uint8_t>& desc) {
                mFilterMQDesc = desc;
                getQueueDescResult = r;
                ALOGD("getFilterQueueDesc");
            });
    if (getQueueDescResult == Result::SUCCESS) {
        unsafeHidlToAidlMQDescriptor<uint8_t, int8_t, SynchronizedReadWrite>(
                mFilterMQDesc,  &mAidlMQDesc);
        mAidlMq = new (nothrow) AidlMessageQueue(mAidlMQDesc);
        EventFlag::createEventFlag(mAidlMq->getEventFlagWord(), &mEventFlag);
    } else {
        ALOGD("get MQDesc failed, res = %d", getQueueDescResult);
    }
    return getQueueDescResult;
}

Status TunerService::getFrontendIds(vector<int32_t>* ids, int32_t* /* _aidl_return */) {
    if (!getITuner()) {
        return Status::fromServiceSpecificError(
                static_cast<int32_t>(Result::NOT_INITIALIZED));
    }
    hidl_vec<FrontendId> feIds;
    Result res;
    mTuner->getFrontendIds([&](Result r, const hidl_vec<FrontendId>& frontendIds) {
        feIds = frontendIds;
        res = r;
    });
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    ids->resize(feIds.size());
    copy(feIds.begin(), feIds.end(), ids->begin());

    return Status::ok();
}

Status TunerService::getFrontendInfo(
        int32_t frontendHandle, TunerFrontendInfo* _aidl_return) {
    if (mTuner == nullptr) {
        ALOGE("ITuner service is not init.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res;
    FrontendInfo info;
    int feId = getResourceIdFromHandle(frontendHandle, FRONTEND);
    mTuner->getFrontendInfo(feId, [&](Result r, const FrontendInfo& feInfo) {
        info = feInfo;
        res = r;
    });
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    TunerFrontendInfo tunerInfo = convertToAidlFrontendInfo(info);
    *_aidl_return = tunerInfo;
    return Status::ok();
}

Status TunerService::openFrontend(
        int32_t frontendHandle, shared_ptr<ITunerFrontend>* _aidl_return) {
    if (mTuner == nullptr) {
        ALOGE("ITuner service is not init.");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status;
    sp<IFrontend> frontend;
    int id = getResourceIdFromHandle(frontendHandle, FRONTEND);
    mTuner->openFrontendById(id, [&](Result result, const sp<IFrontend>& fe) {
        frontend = fe;
        status = result;
    });
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    *_aidl_return = ::ndk::SharedRefBase::make<TunerFrontend>(frontend, id);
    return Status::ok();
}

Status TunerService::getFmqSyncReadWrite(
        MQDescriptor<int8_t, SynchronizedReadWrite>* mqDesc, bool* _aidl_return) {
    ALOGD("getFmqSyncReadWrite");
    // TODO: put the following methods AIDL, and should be called from clients.
    configFilter();
    mFilter->start();
    if (mqDesc == nullptr) {
        ALOGD("getFmqSyncReadWrite null MQDescriptor.");
        *_aidl_return = false;
    } else {
        ALOGD("getFmqSyncReadWrite true");
        *_aidl_return = true;
        *mqDesc = move(mAidlMQDesc);
    }
    return ndk::ScopedAStatus::ok();
}

Status TunerService::openLnb(int lnbHandle, shared_ptr<ITunerLnb>* _aidl_return) {
    if (mTuner == nullptr) {
        ALOGE("ITuner service is not init.");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status;
    sp<ILnb> lnb;
    int id = getResourceIdFromHandle(lnbHandle, LNB);
    mTuner->openLnbById(id, [&](Result result, const sp<ILnb>& lnbSp){
        lnb = lnbSp;
        status = result;
    });
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    *_aidl_return = ::ndk::SharedRefBase::make<TunerLnb>(lnb, id);
    return Status::ok();
}

Status TunerService::openLnbByName(const string& lnbName, shared_ptr<ITunerLnb>* _aidl_return) {
    if (mTuner == nullptr) {
        ALOGE("ITuner service is not init.");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    int lnbId;
    Result status;
    sp<ILnb> lnb;
    mTuner->openLnbByName(lnbName, [&](Result r, LnbId id, const sp<ILnb>& lnbSp) {
        status = r;
        lnb = lnbSp;
        lnbId = (int)id;
    });
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    *_aidl_return = ::ndk::SharedRefBase::make<TunerLnb>(lnb, lnbId);
    return Status::ok();
}

TunerFrontendInfo TunerService::convertToAidlFrontendInfo(FrontendInfo halInfo) {
    TunerFrontendInfo info{
        .type = (int)halInfo.type,
        .minFrequency = (int)halInfo.minFrequency,
        .maxFrequency = (int)halInfo.maxFrequency,
        .minSymbolRate = (int)halInfo.minSymbolRate,
        .maxSymbolRate = (int)halInfo.maxSymbolRate,
        .acquireRange = (int)halInfo.acquireRange,
        .exclusiveGroupId = (int)halInfo.exclusiveGroupId,
    };
    for (int i = 0; i < halInfo.statusCaps.size(); i++) {
        info.statusCaps.push_back((int)halInfo.statusCaps[i]);
    }

    TunerFrontendCapabilities caps;
    switch (halInfo.type) {
        case FrontendType::ANALOG: {
            TunerFrontendAnalogCapabilities analogCaps{
                .typeCap = (int)halInfo.frontendCaps.analogCaps().typeCap,
                .sifStandardCap = (int)halInfo.frontendCaps.analogCaps().sifStandardCap,
            };
            caps.set<TunerFrontendCapabilities::analogCaps>(analogCaps);
            break;
        }
        case FrontendType::ATSC: {
            TunerFrontendAtscCapabilities atscCaps{
                .modulationCap = (int)halInfo.frontendCaps.atscCaps().modulationCap,
            };
            caps.set<TunerFrontendCapabilities::atscCaps>(atscCaps);
            break;
        }
        case FrontendType::ATSC3: {
            TunerFrontendAtsc3Capabilities atsc3Caps{
                .bandwidthCap = (int)halInfo.frontendCaps.atsc3Caps().bandwidthCap,
                .modulationCap = (int)halInfo.frontendCaps.atsc3Caps().modulationCap,
                .timeInterleaveModeCap =
                        (int)halInfo.frontendCaps.atsc3Caps().timeInterleaveModeCap,
                .codeRateCap = (int)halInfo.frontendCaps.atsc3Caps().codeRateCap,
                .demodOutputFormatCap = (int)halInfo.frontendCaps.atsc3Caps().demodOutputFormatCap,
                .fecCap = (int)halInfo.frontendCaps.atsc3Caps().fecCap,
            };
            caps.set<TunerFrontendCapabilities::atsc3Caps>(atsc3Caps);
            break;
        }
        case FrontendType::DVBC: {
            TunerFrontendCableCapabilities cableCaps{
                .modulationCap = (int)halInfo.frontendCaps.dvbcCaps().modulationCap,
                .codeRateCap = (int)halInfo.frontendCaps.dvbcCaps().fecCap,
                .annexCap = (int)halInfo.frontendCaps.dvbcCaps().annexCap,
            };
            caps.set<TunerFrontendCapabilities::cableCaps>(cableCaps);
            break;
        }
        case FrontendType::DVBS: {
            TunerFrontendDvbsCapabilities dvbsCaps{
                .modulationCap = (int)halInfo.frontendCaps.dvbsCaps().modulationCap,
                .codeRateCap = (long)halInfo.frontendCaps.dvbsCaps().innerfecCap,
                .standard = (int)halInfo.frontendCaps.dvbsCaps().standard,
            };
            caps.set<TunerFrontendCapabilities::dvbsCaps>(dvbsCaps);
            break;
        }
        case FrontendType::DVBT: {
            TunerFrontendDvbtCapabilities dvbtCaps{
                .transmissionModeCap = (int)halInfo.frontendCaps.dvbtCaps().transmissionModeCap,
                .bandwidthCap = (int)halInfo.frontendCaps.dvbtCaps().bandwidthCap,
                .constellationCap = (int)halInfo.frontendCaps.dvbtCaps().constellationCap,
                .codeRateCap = (int)halInfo.frontendCaps.dvbtCaps().coderateCap,
                .hierarchyCap = (int)halInfo.frontendCaps.dvbtCaps().hierarchyCap,
                .guardIntervalCap = (int)halInfo.frontendCaps.dvbtCaps().guardIntervalCap,
                .isT2Supported = (bool)halInfo.frontendCaps.dvbtCaps().isT2Supported,
                .isMisoSupported = (bool)halInfo.frontendCaps.dvbtCaps().isMisoSupported,
            };
            caps.set<TunerFrontendCapabilities::dvbtCaps>(dvbtCaps);
            break;
        }
        case FrontendType::ISDBS: {
            TunerFrontendIsdbsCapabilities isdbsCaps{
                .modulationCap = (int)halInfo.frontendCaps.isdbsCaps().modulationCap,
                .codeRateCap = (int)halInfo.frontendCaps.isdbsCaps().coderateCap,
            };
            caps.set<TunerFrontendCapabilities::isdbsCaps>(isdbsCaps);
            break;
        }
        case FrontendType::ISDBS3: {
            TunerFrontendIsdbs3Capabilities isdbs3Caps{
                .modulationCap = (int)halInfo.frontendCaps.isdbs3Caps().modulationCap,
                .codeRateCap = (int)halInfo.frontendCaps.isdbs3Caps().coderateCap,
            };
            caps.set<TunerFrontendCapabilities::isdbs3Caps>(isdbs3Caps);
            break;
        }
        case FrontendType::ISDBT: {
            TunerFrontendIsdbtCapabilities isdbtCaps{
                .modeCap = (int)halInfo.frontendCaps.isdbtCaps().modeCap,
                .bandwidthCap = (int)halInfo.frontendCaps.isdbtCaps().bandwidthCap,
                .modulationCap = (int)halInfo.frontendCaps.isdbtCaps().modulationCap,
                .codeRateCap = (int)halInfo.frontendCaps.isdbtCaps().coderateCap,
                .guardIntervalCap = (int)halInfo.frontendCaps.isdbtCaps().guardIntervalCap,
            };
            caps.set<TunerFrontendCapabilities::isdbtCaps>(isdbtCaps);
            break;
        }
        default:
            break;
    }

    info.caps = caps;
    return info;
}
} // namespace android
