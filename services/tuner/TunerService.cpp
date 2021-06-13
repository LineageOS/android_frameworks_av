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
#include <android/content/pm/IPackageManagerNative.h>
#include <binder/IServiceManager.h>
#include <utils/Log.h>
#include "TunerService.h"
#include "TunerFrontend.h"
#include "TunerLnb.h"
#include "TunerDemux.h"
#include "TunerDescrambler.h"

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
using ::android::hardware::tv::tuner::V1_1::FrontendDtmbCapabilities;

namespace android {

TunerService::TunerService() {
    sp<IServiceManager> serviceMgr = defaultServiceManager();
    sp<content::pm::IPackageManagerNative> packageMgr;
    if (serviceMgr.get() == nullptr) {
        ALOGE("%s: Cannot find service manager", __func__);
        return;
    } else {
        sp<IBinder> binder = serviceMgr->waitForService(String16("package_native"));
        packageMgr = interface_cast<content::pm::IPackageManagerNative>(binder);
    }

    bool hasFeature = false;
    if (packageMgr != nullptr) {
        binder::Status status = packageMgr->hasSystemFeature(FEATURE_TUNER, 0, &hasFeature);
        if (!status.isOk()) {
            ALOGE("%s: hasSystemFeature failed: %s",
                    __func__, status.exceptionMessage().c_str());
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
    ALOGD("hasITuner");
    if (mTuner != nullptr) {
        return true;
    }
    mTuner = ITuner::getService();
    if (mTuner == nullptr) {
        ALOGE("Failed to get ITuner service");
        return false;
    }
    mTunerVersion = TUNER_HAL_VERSION_1_0;
    mTuner_1_1 = ::android::hardware::tv::tuner::V1_1::ITuner::castFrom(mTuner);
    if (mTuner_1_1 != nullptr) {
        mTunerVersion = TUNER_HAL_VERSION_1_1;
    } else {
        ALOGE("Failed to get ITuner_1_1 service");
    }
    return true;
}

bool TunerService::hasITuner_1_1() {
    ALOGD("hasITuner_1_1");
    hasITuner();
    return (mTunerVersion == TUNER_HAL_VERSION_1_1);
}

Status TunerService::openDemux(
        int /* demuxHandle */, std::shared_ptr<ITunerDemux>* _aidl_return) {
    ALOGD("openDemux");
    if (!hasITuner()) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::NOT_INITIALIZED));
    }
    Result res;
    uint32_t id;
    sp<IDemux> demuxSp = nullptr;
    shared_ptr<ITunerDemux> tunerDemux = nullptr;
    mTuner->openDemux([&](Result r, uint32_t demuxId, const sp<IDemux>& demux) {
        demuxSp = demux;
        id = demuxId;
        res = r;
        ALOGD("open demux, id = %d", demuxId);
    });
    if (res == Result::SUCCESS) {
        tunerDemux = ::ndk::SharedRefBase::make<TunerDemux>(demuxSp, id);
        *_aidl_return = tunerDemux->ref<ITunerDemux>();
        return Status::ok();
    }

    ALOGW("open demux failed, res = %d", res);
    return Status::fromServiceSpecificError(static_cast<int32_t>(res));
}

Status TunerService::getDemuxCaps(TunerDemuxCapabilities* _aidl_return) {
    ALOGD("getDemuxCaps");
    if (!hasITuner()) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::NOT_INITIALIZED));
    }
    Result res;
    DemuxCapabilities caps;
    mTuner->getDemuxCaps([&](Result r, const DemuxCapabilities& demuxCaps) {
        caps = demuxCaps;
        res = r;
    });
    if (res == Result::SUCCESS) {
        *_aidl_return = getAidlDemuxCaps(caps);
        return Status::ok();
    }

    ALOGW("Get demux caps failed, res = %d", res);
    return Status::fromServiceSpecificError(static_cast<int32_t>(res));
}

Status TunerService::getFrontendIds(vector<int32_t>* ids) {
    if (!hasITuner()) {
        return Status::fromServiceSpecificError(
                static_cast<int32_t>(Result::NOT_INITIALIZED));
    }
    hidl_vec<FrontendId> feIds;
    Result res = getHidlFrontendIds(feIds);
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    ids->resize(feIds.size());
    copy(feIds.begin(), feIds.end(), ids->begin());

    return Status::ok();
}

Status TunerService::getFrontendInfo(int32_t id, TunerFrontendInfo* _aidl_return) {
    if (!hasITuner()) {
        ALOGE("ITuner service is not init.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    FrontendInfo info;
    Result res = getHidlFrontendInfo(id, info);
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    TunerFrontendInfo tunerInfo = convertToAidlFrontendInfo(info);
    *_aidl_return = tunerInfo;
    return Status::ok();
}

Status TunerService::getFrontendDtmbCapabilities(
        int32_t id, TunerFrontendDtmbCapabilities* _aidl_return) {
    if (!hasITuner_1_1()) {
        ALOGE("ITuner_1_1 service is not init.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res;
    FrontendDtmbCapabilities dtmbCaps;
    mTuner_1_1->getFrontendDtmbCapabilities(id,
            [&](Result r, const FrontendDtmbCapabilities& caps) {
        dtmbCaps = caps;
        res = r;
    });
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    TunerFrontendDtmbCapabilities aidlDtmbCaps{
        .transmissionModeCap = (int)dtmbCaps.transmissionModeCap,
        .bandwidthCap = (int)dtmbCaps.bandwidthCap,
        .modulationCap = (int)dtmbCaps.modulationCap,
        .codeRateCap = (int)dtmbCaps.codeRateCap,
        .guardIntervalCap = (int)dtmbCaps.guardIntervalCap,
        .interleaveModeCap = (int)dtmbCaps.interleaveModeCap,
    };

    *_aidl_return = aidlDtmbCaps;
    return Status::ok();
}

Status TunerService::openFrontend(
        int32_t frontendHandle, shared_ptr<ITunerFrontend>* _aidl_return) {
    if (!hasITuner()) {
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

Status TunerService::openLnb(int lnbHandle, shared_ptr<ITunerLnb>* _aidl_return) {
    if (!hasITuner()) {
        ALOGD("get ITuner failed");
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
    if (!hasITuner()) {
        ALOGE("get ITuner failed");
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

Status TunerService::openDescrambler(int32_t /*descramblerHandle*/,
            std::shared_ptr<ITunerDescrambler>* _aidl_return) {
    if (!hasITuner()) {
        ALOGD("get ITuner failed");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status;
    sp<IDescrambler> descrambler;
    //int id = getResourceIdFromHandle(descramblerHandle, DESCRAMBLER);
    mTuner->openDescrambler([&](Result r, const sp<IDescrambler>& descramblerSp) {
        status = r;
        descrambler = descramblerSp;
    });
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    *_aidl_return = ::ndk::SharedRefBase::make<TunerDescrambler>(descrambler);
    return Status::ok();
}

void TunerService::updateTunerResources() {
    if (!hasITuner() || mTunerResourceManager == NULL) {
        ALOGE("Failed to updateTunerResources");
        return;
    }

    updateFrontendResources();
    updateLnbResources();
    // TODO: update Demux, Descrambler.
}

Status TunerService::getTunerHalVersion(int* _aidl_return) {
    hasITuner();
    *_aidl_return = mTunerVersion;
    return Status::ok();
}

void TunerService::updateFrontendResources() {
    hidl_vec<FrontendId> ids;
    Result res = getHidlFrontendIds(ids);
    if (res != Result::SUCCESS) {
        return;
    }
    vector<TunerFrontendInfo> infos;
    for (int i = 0; i < ids.size(); i++) {
        FrontendInfo frontendInfo;
        Result res = getHidlFrontendInfo((int)ids[i], frontendInfo);
        if (res != Result::SUCCESS) {
            continue;
        }
        TunerFrontendInfo tunerFrontendInfo{
            .handle = getResourceHandleFromId((int)ids[i], FRONTEND),
            .type = static_cast<int>(frontendInfo.type),
            .exclusiveGroupId = static_cast<int>(frontendInfo.exclusiveGroupId),
        };
        infos.push_back(tunerFrontendInfo);
    }
    mTunerResourceManager->setFrontendInfoList(infos);
}

void TunerService::updateLnbResources() {
    vector<int> handles = getLnbHandles();
    if (handles.size() == 0) {
        return;
    }
    mTunerResourceManager->setLnbInfoList(handles);
}

vector<int> TunerService::getLnbHandles() {
    vector<int> lnbHandles;
    if (mTuner != NULL) {
        Result res;
        vector<LnbId> lnbIds;
        mTuner->getLnbIds([&](Result r, const hardware::hidl_vec<LnbId>& ids) {
            lnbIds = ids;
            res = r;
        });
        if (res != Result::SUCCESS || lnbIds.size() == 0) {
        } else {
            for (int i = 0; i < lnbIds.size(); i++) {
                lnbHandles.push_back(getResourceHandleFromId((int)lnbIds[i], LNB));
            }
        }
    }

    return lnbHandles;
}

Result TunerService::getHidlFrontendIds(hidl_vec<FrontendId>& ids) {
    if (mTuner == NULL) {
        return Result::NOT_INITIALIZED;
    }
    Result res;
    mTuner->getFrontendIds([&](Result r, const hidl_vec<FrontendId>& frontendIds) {
        ids = frontendIds;
        res = r;
    });
    return res;
}

Result TunerService::getHidlFrontendInfo(int id, FrontendInfo& info) {
    if (mTuner == NULL) {
        return Result::NOT_INITIALIZED;
    }
    Result res;
    mTuner->getFrontendInfo(id, [&](Result r, const FrontendInfo& feInfo) {
        info = feInfo;
        res = r;
    });
    return res;
}

TunerDemuxCapabilities TunerService::getAidlDemuxCaps(DemuxCapabilities caps) {
    TunerDemuxCapabilities aidlCaps{
        .numDemux = (int)caps.numDemux,
        .numRecord = (int)caps.numRecord,
        .numPlayback = (int)caps.numPlayback,
        .numTsFilter = (int)caps.numTsFilter,
        .numSectionFilter = (int)caps.numSectionFilter,
        .numAudioFilter = (int)caps.numAudioFilter,
        .numVideoFilter = (int)caps.numVideoFilter,
        .numPesFilter = (int)caps.numPesFilter,
        .numPcrFilter = (int)caps.numPcrFilter,
        .numBytesInSectionFilter = (int)caps.numBytesInSectionFilter,
        .filterCaps = (int)caps.filterCaps,
        .bTimeFilter = caps.bTimeFilter,
    };
    aidlCaps.linkCaps.resize(caps.linkCaps.size());
    copy(caps.linkCaps.begin(), caps.linkCaps.end(), aidlCaps.linkCaps.begin());
    return aidlCaps;
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
            if (FrontendInfo::FrontendCapabilities::hidl_discriminator::analogCaps
                    == halInfo.frontendCaps.getDiscriminator()) {
                TunerFrontendAnalogCapabilities analogCaps{
                    .typeCap = (int)halInfo.frontendCaps.analogCaps().typeCap,
                    .sifStandardCap = (int)halInfo.frontendCaps.analogCaps().sifStandardCap,
                };
                caps.set<TunerFrontendCapabilities::analogCaps>(analogCaps);
            }
            break;
        }
        case FrontendType::ATSC: {
            if (FrontendInfo::FrontendCapabilities::hidl_discriminator::atscCaps
                    == halInfo.frontendCaps.getDiscriminator()) {
                TunerFrontendAtscCapabilities atscCaps{
                    .modulationCap = (int)halInfo.frontendCaps.atscCaps().modulationCap,
                };
                caps.set<TunerFrontendCapabilities::atscCaps>(atscCaps);
            }
            break;
        }
        case FrontendType::ATSC3: {
            if (FrontendInfo::FrontendCapabilities::hidl_discriminator::atsc3Caps
                    == halInfo.frontendCaps.getDiscriminator()) {
                TunerFrontendAtsc3Capabilities atsc3Caps{
                    .bandwidthCap = (int)halInfo.frontendCaps.atsc3Caps().bandwidthCap,
                    .modulationCap = (int)halInfo.frontendCaps.atsc3Caps().modulationCap,
                    .timeInterleaveModeCap =
                            (int)halInfo.frontendCaps.atsc3Caps().timeInterleaveModeCap,
                    .codeRateCap = (int)halInfo.frontendCaps.atsc3Caps().codeRateCap,
                    .demodOutputFormatCap
                        = (int)halInfo.frontendCaps.atsc3Caps().demodOutputFormatCap,
                    .fecCap = (int)halInfo.frontendCaps.atsc3Caps().fecCap,
                };
                caps.set<TunerFrontendCapabilities::atsc3Caps>(atsc3Caps);
            }
            break;
        }
        case FrontendType::DVBC: {
            if (FrontendInfo::FrontendCapabilities::hidl_discriminator::dvbcCaps
                    == halInfo.frontendCaps.getDiscriminator()) {
                TunerFrontendCableCapabilities cableCaps{
                    .modulationCap = (int)halInfo.frontendCaps.dvbcCaps().modulationCap,
                    .codeRateCap = (int64_t)halInfo.frontendCaps.dvbcCaps().fecCap,
                    .annexCap = (int)halInfo.frontendCaps.dvbcCaps().annexCap,
                };
                caps.set<TunerFrontendCapabilities::cableCaps>(cableCaps);
            }
            break;
        }
        case FrontendType::DVBS: {
            if (FrontendInfo::FrontendCapabilities::hidl_discriminator::dvbsCaps
                    == halInfo.frontendCaps.getDiscriminator()) {
                TunerFrontendDvbsCapabilities dvbsCaps{
                    .modulationCap = (int)halInfo.frontendCaps.dvbsCaps().modulationCap,
                    .codeRateCap = (long)halInfo.frontendCaps.dvbsCaps().innerfecCap,
                    .standard = (int)halInfo.frontendCaps.dvbsCaps().standard,
                };
                caps.set<TunerFrontendCapabilities::dvbsCaps>(dvbsCaps);
            }
            break;
        }
        case FrontendType::DVBT: {
            if (FrontendInfo::FrontendCapabilities::hidl_discriminator::dvbtCaps
                    == halInfo.frontendCaps.getDiscriminator()) {
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
            }
            break;
        }
        case FrontendType::ISDBS: {
            if (FrontendInfo::FrontendCapabilities::hidl_discriminator::isdbsCaps
                    == halInfo.frontendCaps.getDiscriminator()) {
                TunerFrontendIsdbsCapabilities isdbsCaps{
                    .modulationCap = (int)halInfo.frontendCaps.isdbsCaps().modulationCap,
                    .codeRateCap = (int)halInfo.frontendCaps.isdbsCaps().coderateCap,
                };
                caps.set<TunerFrontendCapabilities::isdbsCaps>(isdbsCaps);
            }
            break;
        }
        case FrontendType::ISDBS3: {
            if (FrontendInfo::FrontendCapabilities::hidl_discriminator::isdbs3Caps
                    == halInfo.frontendCaps.getDiscriminator()) {
                TunerFrontendIsdbs3Capabilities isdbs3Caps{
                    .modulationCap = (int)halInfo.frontendCaps.isdbs3Caps().modulationCap,
                    .codeRateCap = (int)halInfo.frontendCaps.isdbs3Caps().coderateCap,
                };
                caps.set<TunerFrontendCapabilities::isdbs3Caps>(isdbs3Caps);
            }
            break;
        }
        case FrontendType::ISDBT: {
            if (FrontendInfo::FrontendCapabilities::hidl_discriminator::isdbtCaps
                    == halInfo.frontendCaps.getDiscriminator()) {
                TunerFrontendIsdbtCapabilities isdbtCaps{
                    .modeCap = (int)halInfo.frontendCaps.isdbtCaps().modeCap,
                    .bandwidthCap = (int)halInfo.frontendCaps.isdbtCaps().bandwidthCap,
                    .modulationCap = (int)halInfo.frontendCaps.isdbtCaps().modulationCap,
                    .codeRateCap = (int)halInfo.frontendCaps.isdbtCaps().coderateCap,
                    .guardIntervalCap = (int)halInfo.frontendCaps.isdbtCaps().guardIntervalCap,
                };
                caps.set<TunerFrontendCapabilities::isdbtCaps>(isdbtCaps);
            }
            break;
        }
        default:
            break;
    }

    info.caps = caps;
    return info;
}
} // namespace android
