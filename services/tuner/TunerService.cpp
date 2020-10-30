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
#include "TunerFrontend.h"
#include "TunerService.h"

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
using ::android::hardware::tv::tuner::V1_0::FrontendId;
using ::android::hardware::tv::tuner::V1_0::FrontendType;
using ::android::hardware::tv::tuner::V1_0::Result;

namespace android {

sp<ITuner> TunerService::mTuner;

TunerService::TunerService() {}
TunerService::~TunerService() {}

void TunerService::instantiate() {
    std::shared_ptr<TunerService> service =
            ::ndk::SharedRefBase::make<TunerService>();
    AServiceManager_addService(service->asBinder().get(), getServiceName());
    mTuner = ITuner::getService();
    if (mTuner == nullptr) {
        ALOGE("Failed to get ITuner service.");
    }
}

Status TunerService::getFrontendIds(std::vector<int32_t>* ids, int32_t* /* _aidl_return */) {
    if (mTuner == nullptr) {
        ALOGE("ITuner service is not init.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }
    hidl_vec<FrontendId> feIds;
    Result res;
    mTuner->getFrontendIds([&](Result r, const hidl_vec<FrontendId>& frontendIds) {
        feIds = frontendIds;
        res = r;
    });
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    ids->resize(feIds.size());
    std::copy(feIds.begin(), feIds.end(), ids->begin());

    return Status::ok();
}

Status TunerService::getFrontendInfo(
        int32_t frontendHandle, TunerServiceFrontendInfo* _aidl_return) {
    if (mTuner == nullptr) {
        ALOGE("ITuner service is not init.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res;
    FrontendInfo info;
    int feId = getResourceIdFromHandle(frontendHandle);
    mTuner->getFrontendInfo(feId, [&](Result r, const FrontendInfo& feInfo) {
        info = feInfo;
        res = r;
    });
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    TunerServiceFrontendInfo tunerInfo = convertToAidlFrontendInfo(feId, info);
    *_aidl_return = tunerInfo;
    return Status::ok();
}

Status TunerService::openFrontend(
        int32_t frontendHandle, std::shared_ptr<ITunerFrontend>* _aidl_return) {
    if (mTuner == nullptr) {
        ALOGE("ITuner service is not init.");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    *_aidl_return = ::ndk::SharedRefBase::make<TunerFrontend>(mTuner, frontendHandle);
    return Status::ok();
}

TunerServiceFrontendInfo TunerService::convertToAidlFrontendInfo(int feId, FrontendInfo halInfo) {
    TunerServiceFrontendInfo info{
        .id = feId,
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
