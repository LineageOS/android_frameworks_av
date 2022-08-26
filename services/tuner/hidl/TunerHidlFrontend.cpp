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

//#define LOG_NDEBUG 0
#define LOG_TAG "TunerHidlFrontend"

#include "TunerHidlFrontend.h"

#include <aidl/android/hardware/tv/tuner/Result.h>

#include "TunerHidlLnb.h"
#include "TunerHidlService.h"

using ::aidl::android::hardware::tv::tuner::FrontendAnalogSettings;
using ::aidl::android::hardware::tv::tuner::FrontendAnalogSifStandard;
using ::aidl::android::hardware::tv::tuner::FrontendAnalogType;
using ::aidl::android::hardware::tv::tuner::FrontendAtsc3Bandwidth;
using ::aidl::android::hardware::tv::tuner::FrontendAtsc3CodeRate;
using ::aidl::android::hardware::tv::tuner::FrontendAtsc3Fec;
using ::aidl::android::hardware::tv::tuner::FrontendAtsc3Modulation;
using ::aidl::android::hardware::tv::tuner::FrontendAtsc3PlpSettings;
using ::aidl::android::hardware::tv::tuner::FrontendAtsc3Settings;
using ::aidl::android::hardware::tv::tuner::FrontendAtsc3TimeInterleaveMode;
using ::aidl::android::hardware::tv::tuner::FrontendAtscModulation;
using ::aidl::android::hardware::tv::tuner::FrontendAtscSettings;
using ::aidl::android::hardware::tv::tuner::FrontendBandwidth;
using ::aidl::android::hardware::tv::tuner::FrontendCableTimeInterleaveMode;
using ::aidl::android::hardware::tv::tuner::FrontendDtmbBandwidth;
using ::aidl::android::hardware::tv::tuner::FrontendDtmbGuardInterval;
using ::aidl::android::hardware::tv::tuner::FrontendDtmbModulation;
using ::aidl::android::hardware::tv::tuner::FrontendDtmbSettings;
using ::aidl::android::hardware::tv::tuner::FrontendDtmbTimeInterleaveMode;
using ::aidl::android::hardware::tv::tuner::FrontendDtmbTransmissionMode;
using ::aidl::android::hardware::tv::tuner::FrontendDvbcAnnex;
using ::aidl::android::hardware::tv::tuner::FrontendDvbcBandwidth;
using ::aidl::android::hardware::tv::tuner::FrontendDvbcModulation;
using ::aidl::android::hardware::tv::tuner::FrontendDvbcSettings;
using ::aidl::android::hardware::tv::tuner::FrontendDvbsModulation;
using ::aidl::android::hardware::tv::tuner::FrontendDvbsRolloff;
using ::aidl::android::hardware::tv::tuner::FrontendDvbsSettings;
using ::aidl::android::hardware::tv::tuner::FrontendDvbsStandard;
using ::aidl::android::hardware::tv::tuner::FrontendDvbtBandwidth;
using ::aidl::android::hardware::tv::tuner::FrontendDvbtConstellation;
using ::aidl::android::hardware::tv::tuner::FrontendDvbtGuardInterval;
using ::aidl::android::hardware::tv::tuner::FrontendDvbtHierarchy;
using ::aidl::android::hardware::tv::tuner::FrontendDvbtSettings;
using ::aidl::android::hardware::tv::tuner::FrontendDvbtStandard;
using ::aidl::android::hardware::tv::tuner::FrontendDvbtTransmissionMode;
using ::aidl::android::hardware::tv::tuner::FrontendGuardInterval;
using ::aidl::android::hardware::tv::tuner::FrontendInnerFec;
using ::aidl::android::hardware::tv::tuner::FrontendInterleaveMode;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbs3Modulation;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbs3Rolloff;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbs3Settings;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbsModulation;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbsRolloff;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbsSettings;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbtBandwidth;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbtCoderate;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbtGuardInterval;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbtMode;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbtModulation;
using ::aidl::android::hardware::tv::tuner::FrontendIsdbtSettings;
using ::aidl::android::hardware::tv::tuner::FrontendModulation;
using ::aidl::android::hardware::tv::tuner::FrontendModulationStatus;
using ::aidl::android::hardware::tv::tuner::FrontendRollOff;
using ::aidl::android::hardware::tv::tuner::FrontendScanAtsc3PlpInfo;
using ::aidl::android::hardware::tv::tuner::FrontendScanMessageStandard;
using ::aidl::android::hardware::tv::tuner::FrontendSpectralInversion;
using ::aidl::android::hardware::tv::tuner::FrontendStatusAtsc3PlpInfo;
using ::aidl::android::hardware::tv::tuner::FrontendTransmissionMode;
using ::aidl::android::hardware::tv::tuner::Result;

using HidlFrontendStatusAtsc3PlpInfo =
        ::aidl::android::hardware::tv::tuner::FrontendStatusAtsc3PlpInfo;
using HidlFrontendAnalogSifStandard =
        ::android::hardware::tv::tuner::V1_0::FrontendAnalogSifStandard;
using HidlFrontendAnalogType = ::android::hardware::tv::tuner::V1_0::FrontendAnalogType;
using HidlFrontendAtscModulation = ::android::hardware::tv::tuner::V1_0::FrontendAtscModulation;
using HidlFrontendAtsc3Bandwidth = ::android::hardware::tv::tuner::V1_0::FrontendAtsc3Bandwidth;
using HidlFrontendAtsc3CodeRate = ::android::hardware::tv::tuner::V1_0::FrontendAtsc3CodeRate;
using HidlFrontendAtsc3DemodOutputFormat =
        ::android::hardware::tv::tuner::V1_0::FrontendAtsc3DemodOutputFormat;
using HidlFrontendAtsc3Fec = ::android::hardware::tv::tuner::V1_0::FrontendAtsc3Fec;
using HidlFrontendAtsc3Modulation = ::android::hardware::tv::tuner::V1_0::FrontendAtsc3Modulation;
using HidlFrontendAtsc3TimeInterleaveMode =
        ::android::hardware::tv::tuner::V1_0::FrontendAtsc3TimeInterleaveMode;
using HidlFrontendDvbcAnnex = ::android::hardware::tv::tuner::V1_0::FrontendDvbcAnnex;
using HidlFrontendDvbcModulation = ::android::hardware::tv::tuner::V1_0::FrontendDvbcModulation;
using HidlFrontendDvbcOuterFec = ::android::hardware::tv::tuner::V1_0::FrontendDvbcOuterFec;
using HidlFrontendDvbcSpectralInversion =
        ::android::hardware::tv::tuner::V1_0::FrontendDvbcSpectralInversion;
using HidlFrontendDvbsModulation = ::android::hardware::tv::tuner::V1_0::FrontendDvbsModulation;
using HidlFrontendDvbsPilot = ::android::hardware::tv::tuner::V1_0::FrontendDvbsPilot;
using HidlFrontendDvbsRolloff = ::android::hardware::tv::tuner::V1_0::FrontendDvbsRolloff;
using HidlFrontendDvbsSettings = ::android::hardware::tv::tuner::V1_0::FrontendDvbsSettings;
using HidlFrontendDvbsStandard = ::android::hardware::tv::tuner::V1_0::FrontendDvbsStandard;
using HidlFrontendDvbsVcmMode = ::android::hardware::tv::tuner::V1_0::FrontendDvbsVcmMode;
using HidlFrontendDvbtBandwidth = ::android::hardware::tv::tuner::V1_0::FrontendDvbtBandwidth;
using HidlFrontendDvbtCoderate = ::android::hardware::tv::tuner::V1_0::FrontendDvbtCoderate;
using HidlFrontendDvbtConstellation =
        ::android::hardware::tv::tuner::V1_0::FrontendDvbtConstellation;
using HidlFrontendDvbtGuardInterval =
        ::android::hardware::tv::tuner::V1_0::FrontendDvbtGuardInterval;
using HidlFrontendDvbtHierarchy = ::android::hardware::tv::tuner::V1_0::FrontendDvbtHierarchy;
using HidlFrontendDvbtPlpMode = ::android::hardware::tv::tuner::V1_0::FrontendDvbtPlpMode;
using HidlFrontendDvbtSettings = ::android::hardware::tv::tuner::V1_0::FrontendDvbtSettings;
using HidlFrontendDvbtStandard = ::android::hardware::tv::tuner::V1_0::FrontendDvbtStandard;
using HidlFrontendDvbtTransmissionMode =
        ::android::hardware::tv::tuner::V1_0::FrontendDvbtTransmissionMode;
using HidlFrontendInnerFec = ::android::hardware::tv::tuner::V1_0::FrontendInnerFec;
using HidlFrontendIsdbs3Coderate = ::android::hardware::tv::tuner::V1_0::FrontendIsdbs3Coderate;
using HidlFrontendIsdbs3Modulation = ::android::hardware::tv::tuner::V1_0::FrontendIsdbs3Modulation;
using HidlFrontendIsdbs3Rolloff = ::android::hardware::tv::tuner::V1_0::FrontendIsdbs3Rolloff;
using HidlFrontendIsdbs3Settings = ::android::hardware::tv::tuner::V1_0::FrontendIsdbs3Settings;
using HidlFrontendIsdbsCoderate = ::android::hardware::tv::tuner::V1_0::FrontendIsdbsCoderate;
using HidlFrontendIsdbsModulation = ::android::hardware::tv::tuner::V1_0::FrontendIsdbsModulation;
using HidlFrontendIsdbsRolloff = ::android::hardware::tv::tuner::V1_0::FrontendIsdbsRolloff;
using HidlFrontendIsdbsSettings = ::android::hardware::tv::tuner::V1_0::FrontendIsdbsSettings;
using HidlFrontendIsdbsStreamIdType =
        ::android::hardware::tv::tuner::V1_0::FrontendIsdbsStreamIdType;
using HidlFrontendIsdbtBandwidth = ::android::hardware::tv::tuner::V1_0::FrontendIsdbtBandwidth;
using HidlFrontendIsdbtCoderate = ::android::hardware::tv::tuner::V1_0::FrontendIsdbtCoderate;
using HidlFrontendIsdbtGuardInterval =
        ::android::hardware::tv::tuner::V1_0::FrontendIsdbtGuardInterval;
using HidlFrontendIsdbtMode = ::android::hardware::tv::tuner::V1_0::FrontendIsdbtMode;
using HidlFrontendIsdbtModulation = ::android::hardware::tv::tuner::V1_0::FrontendIsdbtModulation;
using HidlFrontendIsdbtSettings = ::android::hardware::tv::tuner::V1_0::FrontendIsdbtSettings;
using HidlFrontendModulationStatus = ::android::hardware::tv::tuner::V1_0::FrontendModulationStatus;
using HidlFrontendScanAtsc3PlpInfo = ::android::hardware::tv::tuner::V1_0::FrontendScanAtsc3PlpInfo;
using HidlFrontendScanType = ::android::hardware::tv::tuner::V1_0::FrontendScanType;
using HidlFrontendStatusType = ::android::hardware::tv::tuner::V1_0::FrontendStatusType;
using HidlResult = ::android::hardware::tv::tuner::V1_0::Result;
using HidlFrontendAnalogAftFlag = ::android::hardware::tv::tuner::V1_1::FrontendAnalogAftFlag;
using HidlFrontendBandwidth = ::android::hardware::tv::tuner::V1_1::FrontendBandwidth;
using HidlFrontendCableTimeInterleaveMode =
        ::android::hardware::tv::tuner::V1_1::FrontendCableTimeInterleaveMode;
using HidlFrontendDvbcBandwidth = ::android::hardware::tv::tuner::V1_1::FrontendDvbcBandwidth;
using HidlFrontendDtmbBandwidth = ::android::hardware::tv::tuner::V1_1::FrontendDtmbBandwidth;
using HidlFrontendDtmbCodeRate = ::android::hardware::tv::tuner::V1_1::FrontendDtmbCodeRate;
using HidlFrontendDtmbGuardInterval =
        ::android::hardware::tv::tuner::V1_1::FrontendDtmbGuardInterval;
using HidlFrontendDtmbModulation = ::android::hardware::tv::tuner::V1_1::FrontendDtmbModulation;
using HidlFrontendDtmbTimeInterleaveMode =
        ::android::hardware::tv::tuner::V1_1::FrontendDtmbTimeInterleaveMode;
using HidlFrontendDtmbTransmissionMode =
        ::android::hardware::tv::tuner::V1_1::FrontendDtmbTransmissionMode;
using HidlFrontendDvbsScanType = ::android::hardware::tv::tuner::V1_1::FrontendDvbsScanType;
using HidlFrontendGuardInterval = ::android::hardware::tv::tuner::V1_1::FrontendGuardInterval;
using HidlFrontendInterleaveMode = ::android::hardware::tv::tuner::V1_1::FrontendInterleaveMode;
using HidlFrontendModulation = ::android::hardware::tv::tuner::V1_1::FrontendModulation;
using HidlFrontendRollOff = ::android::hardware::tv::tuner::V1_1::FrontendRollOff;
using HidlFrontendTransmissionMode = ::android::hardware::tv::tuner::V1_1::FrontendTransmissionMode;
using HidlFrontendSpectralInversion =
        ::android::hardware::tv::tuner::V1_1::FrontendSpectralInversion;
using HidlFrontendStatusTypeExt1_1 = ::android::hardware::tv::tuner::V1_1::FrontendStatusTypeExt1_1;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerHidlFrontend::TunerHidlFrontend(const sp<HidlIFrontend> frontend, const int id,
                                     const shared_ptr<TunerHidlService> tuner) {
    mFrontend = frontend;
    mFrontend_1_1 = ::android::hardware::tv::tuner::V1_1::IFrontend::castFrom(mFrontend);
    mId = id;
    mTunerService = tuner;
}

TunerHidlFrontend::~TunerHidlFrontend() {
    mFrontend = nullptr;
    mFrontend_1_1 = nullptr;
    mId = -1;
    mTunerService = nullptr;
}

::ndk::ScopedAStatus TunerHidlFrontend::setCallback(
        const shared_ptr<ITunerFrontendCallback>& tunerFrontendCallback) {
    if (tunerFrontendCallback == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    sp<HidlIFrontendCallback> frontendCallback = new FrontendCallback(tunerFrontendCallback);
    HidlResult status = mFrontend->setCallback(frontendCallback);
    if (status == HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::ok();
    }

    return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
}

::ndk::ScopedAStatus TunerHidlFrontend::tune(const FrontendSettings& settings) {
    HidlResult status;
    HidlFrontendSettings frontendSettings;
    HidlFrontendSettingsExt1_1 frontendSettingsExt;
    getHidlFrontendSettings(settings, frontendSettings, frontendSettingsExt);
    if (mFrontend_1_1 != nullptr) {
        status = mFrontend_1_1->tune_1_1(frontendSettings, frontendSettingsExt);
    } else {
        status = mFrontend->tune(frontendSettings);
    }
    if (status == HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::ok();
    }

    return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
}

::ndk::ScopedAStatus TunerHidlFrontend::stopTune() {
    HidlResult status = mFrontend->stopTune();
    if (status == HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::ok();
    }

    return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
}

::ndk::ScopedAStatus TunerHidlFrontend::scan(const FrontendSettings& settings,
                                             FrontendScanType frontendScanType) {
    HidlResult status;
    HidlFrontendSettings frontendSettings;
    HidlFrontendSettingsExt1_1 frontendSettingsExt;
    getHidlFrontendSettings(settings, frontendSettings, frontendSettingsExt);
    if (mFrontend_1_1 != nullptr) {
        status = mFrontend_1_1->scan_1_1(frontendSettings,
                                         static_cast<HidlFrontendScanType>(frontendScanType),
                                         frontendSettingsExt);
    } else {
        status = mFrontend->scan(frontendSettings,
                                 static_cast<HidlFrontendScanType>(frontendScanType));
    }
    if (status == HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::ok();
    }

    return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
}

::ndk::ScopedAStatus TunerHidlFrontend::stopScan() {
    HidlResult status = mFrontend->stopScan();
    if (status == HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::ok();
    }

    return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
}

::ndk::ScopedAStatus TunerHidlFrontend::setLnb(const shared_ptr<ITunerLnb>& lnb) {
    if (lnb == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    HidlResult status = mFrontend->setLnb(static_cast<TunerHidlLnb*>(lnb.get())->getId());
    if (status == HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::ok();
    }

    return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
}

::ndk::ScopedAStatus TunerHidlFrontend::linkCiCamToFrontend(int32_t ciCamId,
                                                            int32_t* _aidl_return) {
    if (mFrontend_1_1 == nullptr) {
        ALOGD("IFrontend_1_1 is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    int ltsId;
    HidlResult status;
    mFrontend_1_1->linkCiCam(static_cast<uint32_t>(ciCamId), [&](HidlResult r, uint32_t id) {
        status = r;
        ltsId = id;
    });

    if (status == HidlResult::SUCCESS) {
        *_aidl_return = ltsId;
        return ::ndk::ScopedAStatus::ok();
    }

    return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
}

::ndk::ScopedAStatus TunerHidlFrontend::unlinkCiCamToFrontend(int32_t ciCamId) {
    if (mFrontend_1_1 == nullptr) {
        ALOGD("IFrontend_1_1 is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    HidlResult status = mFrontend_1_1->unlinkCiCam(ciCamId);
    if (status == HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::ok();
    }

    return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
}

::ndk::ScopedAStatus TunerHidlFrontend::close() {
    mTunerService->removeFrontend(this->ref<TunerHidlFrontend>());
    HidlResult status = mFrontend->close();
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFrontend::getStatus(const vector<FrontendStatusType>& in_statusTypes,
                                                  vector<FrontendStatus>* _aidl_return) {
    HidlResult res;
    vector<HidlFrontendStatus> status;
    vector<HidlFrontendStatusExt1_1> statusExt;
    vector<HidlFrontendStatusType> types;
    vector<HidlFrontendStatusTypeExt1_1> typesExt;
    for (auto s : in_statusTypes) {
        if (static_cast<int32_t>(s) <=
            static_cast<int32_t>(HidlFrontendStatusType::ATSC3_PLP_INFO)) {
            types.push_back(static_cast<HidlFrontendStatusType>(s));
        } else {
            typesExt.push_back(static_cast<HidlFrontendStatusTypeExt1_1>(s));
        }
    }

    mFrontend->getStatus(types, [&](HidlResult r, const hidl_vec<HidlFrontendStatus>& ss) {
        res = r;
        for (auto s : ss) {
            status.push_back(s);
        }
    });
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    if (mFrontend_1_1 != nullptr) {
        mFrontend_1_1->getStatusExt1_1(
                typesExt, [&](HidlResult r, const hidl_vec<HidlFrontendStatusExt1_1>& ss) {
                    res = r;
                    for (auto s : ss) {
                        statusExt.push_back(s);
                    }
                });
        if (res != HidlResult::SUCCESS) {
            return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
        }
    }

    getAidlFrontendStatus(status, statusExt, *_aidl_return);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFrontend::getFrontendId(int32_t* _aidl_return) {
    *_aidl_return = mId;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFrontend::getHardwareInfo(std::string* _aidl_return) {
    _aidl_return->clear();
    return ::ndk::ScopedAStatus::fromServiceSpecificError(
            static_cast<int32_t>(Result::UNAVAILABLE));
}

::ndk::ScopedAStatus TunerHidlFrontend::removeOutputPid(int32_t /* in_pid */) {
    return ::ndk::ScopedAStatus::fromServiceSpecificError(
            static_cast<int32_t>(Result::UNAVAILABLE));
}

::ndk::ScopedAStatus TunerHidlFrontend::getFrontendStatusReadiness(
        const std::vector<FrontendStatusType>& /* in_statusTypes */,
        std::vector<FrontendStatusReadiness>* _aidl_return) {
    _aidl_return->clear();
    return ::ndk::ScopedAStatus::fromServiceSpecificError(
            static_cast<int32_t>(Result::UNAVAILABLE));
}

void TunerHidlFrontend::setLna(bool bEnable) {
    mFrontend->setLna(bEnable);
}

/////////////// FrontendCallback ///////////////////////
Return<void> TunerHidlFrontend::FrontendCallback::onEvent(HidlFrontendEventType frontendEventType) {
    ALOGV("FrontendCallback::onEvent, type=%d", frontendEventType);
    mTunerFrontendCallback->onEvent(static_cast<FrontendEventType>(frontendEventType));
    return Void();
}

Return<void> TunerHidlFrontend::FrontendCallback::onScanMessage(
        HidlFrontendScanMessageType type, const HidlFrontendScanMessage& message) {
    ALOGV("FrontendCallback::onScanMessage, type=%d", type);
    FrontendScanMessage scanMessage;
    switch (type) {
    case HidlFrontendScanMessageType::LOCKED: {
        scanMessage.set<FrontendScanMessage::isLocked>(message.isLocked());
        break;
    }
    case HidlFrontendScanMessageType::END: {
        scanMessage.set<FrontendScanMessage::isEnd>(message.isEnd());
        break;
    }
    case HidlFrontendScanMessageType::PROGRESS_PERCENT: {
        scanMessage.set<FrontendScanMessage::progressPercent>(message.progressPercent());
        break;
    }
    case HidlFrontendScanMessageType::FREQUENCY: {
        const vector<uint32_t>& f = message.frequencies();
        vector<int64_t> lf(begin(f), end(f));
        scanMessage.set<FrontendScanMessage::frequencies>(lf);
        break;
    }
    case HidlFrontendScanMessageType::SYMBOL_RATE: {
        const vector<uint32_t>& s = message.symbolRates();
        vector<int32_t> symbolRates(begin(s), end(s));
        scanMessage.set<FrontendScanMessage::symbolRates>(symbolRates);
        break;
    }
    case HidlFrontendScanMessageType::HIERARCHY: {
        scanMessage.set<FrontendScanMessage::hierarchy>(
                static_cast<FrontendDvbtHierarchy>(message.hierarchy()));
        break;
    }
    case HidlFrontendScanMessageType::ANALOG_TYPE: {
        scanMessage.set<FrontendScanMessage::analogType>(
                static_cast<FrontendAnalogType>(message.analogType()));
        break;
    }
    case HidlFrontendScanMessageType::PLP_IDS: {
        const vector<uint8_t>& p = message.plpIds();
        vector<int32_t> plpIds(begin(p), end(p));
        scanMessage.set<FrontendScanMessage::plpIds>(plpIds);
        break;
    }
    case HidlFrontendScanMessageType::GROUP_IDS: {
        const vector<uint8_t>& g = message.groupIds();
        vector<int32_t> groupIds(begin(g), end(g));
        scanMessage.set<FrontendScanMessage::groupIds>(groupIds);
        break;
    }
    case HidlFrontendScanMessageType::INPUT_STREAM_IDS: {
        const vector<uint16_t>& i = message.inputStreamIds();
        vector<int32_t> streamIds(begin(i), end(i));
        scanMessage.set<FrontendScanMessage::inputStreamIds>(streamIds);
        break;
    }
    case HidlFrontendScanMessageType::STANDARD: {
        const HidlFrontendScanMessage::Standard& std = message.std();
        FrontendScanMessageStandard standard;
        if (std.getDiscriminator() == HidlFrontendScanMessage::Standard::hidl_discriminator::sStd) {
            standard.set<FrontendScanMessageStandard::sStd>(
                    static_cast<FrontendDvbsStandard>(std.sStd()));
        } else if (std.getDiscriminator() ==
                   HidlFrontendScanMessage::Standard::hidl_discriminator::tStd) {
            standard.set<FrontendScanMessageStandard::tStd>(
                    static_cast<FrontendDvbtStandard>(std.tStd()));
        } else if (std.getDiscriminator() ==
                   HidlFrontendScanMessage::Standard::hidl_discriminator::sifStd) {
            standard.set<FrontendScanMessageStandard::sifStd>(
                    static_cast<FrontendAnalogSifStandard>(std.sifStd()));
        }
        scanMessage.set<FrontendScanMessage::std>(standard);
        break;
    }
    case HidlFrontendScanMessageType::ATSC3_PLP_INFO: {
        const vector<HidlFrontendScanAtsc3PlpInfo>& plpInfos = message.atsc3PlpInfos();
        vector<FrontendScanAtsc3PlpInfo> tunerPlpInfos;
        for (int i = 0; i < plpInfos.size(); i++) {
            FrontendScanAtsc3PlpInfo plpInfo{
                    .plpId = static_cast<int32_t>(plpInfos[i].plpId),
                    .bLlsFlag = plpInfos[i].bLlsFlag,
            };
            tunerPlpInfos.push_back(plpInfo);
        }
        scanMessage.set<FrontendScanMessage::atsc3PlpInfos>(tunerPlpInfos);
        break;
    }
    default:
        break;
    }
    mTunerFrontendCallback->onScanMessage(static_cast<FrontendScanMessageType>(type), scanMessage);
    return Void();
}

Return<void> TunerHidlFrontend::FrontendCallback::onScanMessageExt1_1(
        HidlFrontendScanMessageTypeExt1_1 type, const HidlFrontendScanMessageExt1_1& message) {
    ALOGV("onScanMessageExt1_1::onScanMessage, type=%d", type);
    FrontendScanMessage scanMessage;
    switch (type) {
    case HidlFrontendScanMessageTypeExt1_1::MODULATION: {
        HidlFrontendModulation m = message.modulation();
        FrontendModulation modulation;
        switch (m.getDiscriminator()) {
        case HidlFrontendModulation::hidl_discriminator::dvbc: {
            modulation.set<FrontendModulation::dvbc>(static_cast<FrontendDvbcModulation>(m.dvbc()));
            break;
        }
        case HidlFrontendModulation::hidl_discriminator::dvbt: {
            modulation.set<FrontendModulation::dvbt>(
                    static_cast<FrontendDvbtConstellation>(m.dvbt()));
            break;
        }
        case HidlFrontendModulation::hidl_discriminator::dvbs: {
            modulation.set<FrontendModulation::dvbs>(static_cast<FrontendDvbsModulation>(m.dvbs()));
            break;
        }
        case HidlFrontendModulation::hidl_discriminator::isdbs: {
            modulation.set<FrontendModulation::isdbs>(
                    static_cast<FrontendIsdbsModulation>(m.isdbs()));
            break;
        }
        case HidlFrontendModulation::hidl_discriminator::isdbs3: {
            modulation.set<FrontendModulation::isdbs3>(
                    static_cast<FrontendIsdbs3Modulation>(m.isdbs3()));
            break;
        }
        case HidlFrontendModulation::hidl_discriminator::isdbt: {
            modulation.set<FrontendModulation::isdbt>(
                    static_cast<FrontendIsdbtModulation>(m.isdbt()));
            break;
        }
        case HidlFrontendModulation::hidl_discriminator::atsc: {
            modulation.set<FrontendModulation::atsc>(static_cast<FrontendAtscModulation>(m.atsc()));
            break;
        }
        case HidlFrontendModulation::hidl_discriminator::atsc3: {
            modulation.set<FrontendModulation::atsc3>(
                    static_cast<FrontendAtsc3Modulation>(m.atsc3()));
            break;
        }
        case HidlFrontendModulation::hidl_discriminator::dtmb: {
            modulation.set<FrontendModulation::dtmb>(static_cast<FrontendDtmbModulation>(m.dtmb()));
            break;
        }
        }
        scanMessage.set<FrontendScanMessage::modulation>(modulation);
        break;
    }
    case HidlFrontendScanMessageTypeExt1_1::DVBC_ANNEX: {
        scanMessage.set<FrontendScanMessage::annex>(
                static_cast<FrontendDvbcAnnex>(message.annex()));
        break;
    }
    case HidlFrontendScanMessageTypeExt1_1::HIGH_PRIORITY: {
        scanMessage.set<FrontendScanMessage::isHighPriority>(message.isHighPriority());
        break;
    }
    default: {
        break;
    }
    }
    mTunerFrontendCallback->onScanMessage(static_cast<FrontendScanMessageType>(type), scanMessage);
    return Void();
}

/////////////// TunerHidlFrontend Helper Methods ///////////////////////
void TunerHidlFrontend::getAidlFrontendStatus(const vector<HidlFrontendStatus>& hidlStatus,
                                              const vector<HidlFrontendStatusExt1_1>& hidlStatusExt,
                                              vector<FrontendStatus>& aidlStatus) {
    for (HidlFrontendStatus s : hidlStatus) {
        FrontendStatus status;
        switch (s.getDiscriminator()) {
        case HidlFrontendStatus::hidl_discriminator::isDemodLocked: {
            status.set<FrontendStatus::isDemodLocked>(s.isDemodLocked());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::snr: {
            status.set<FrontendStatus::snr>((int)s.snr());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::ber: {
            status.set<FrontendStatus::ber>((int)s.ber());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::per: {
            status.set<FrontendStatus::per>((int)s.per());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::preBer: {
            status.set<FrontendStatus::preBer>((int)s.preBer());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::signalQuality: {
            status.set<FrontendStatus::signalQuality>((int)s.signalQuality());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::signalStrength: {
            status.set<FrontendStatus::signalStrength>((int)s.signalStrength());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::symbolRate: {
            status.set<FrontendStatus::symbolRate>((int)s.symbolRate());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::innerFec: {
            status.set<FrontendStatus::innerFec>(static_cast<FrontendInnerFec>(s.innerFec()));
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::modulation: {
            FrontendModulationStatus modulationStatus;
            switch (s.modulation().getDiscriminator()) {
            case HidlFrontendModulationStatus::hidl_discriminator::dvbc:
                modulationStatus.set<FrontendModulationStatus::dvbc>(
                        static_cast<FrontendDvbcModulation>(s.modulation().dvbc()));
                break;
            case HidlFrontendModulationStatus::hidl_discriminator::dvbs:
                modulationStatus.set<FrontendModulationStatus::dvbs>(
                        static_cast<FrontendDvbsModulation>(s.modulation().dvbs()));
                break;
            case HidlFrontendModulationStatus::hidl_discriminator::isdbs:
                modulationStatus.set<FrontendModulationStatus::isdbs>(
                        static_cast<FrontendIsdbsModulation>(s.modulation().isdbs()));
                break;
            case HidlFrontendModulationStatus::hidl_discriminator::isdbs3:
                modulationStatus.set<FrontendModulationStatus::isdbs3>(
                        static_cast<FrontendIsdbs3Modulation>(s.modulation().isdbs3()));
                break;
            case HidlFrontendModulationStatus::hidl_discriminator::isdbt:
                modulationStatus.set<FrontendModulationStatus::isdbt>(
                        static_cast<FrontendIsdbtModulation>(s.modulation().isdbt()));
                break;
            }
            status.set<FrontendStatus::modulationStatus>(modulationStatus);
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::inversion: {
            status.set<FrontendStatus::inversion>(
                    static_cast<FrontendSpectralInversion>(s.inversion()));
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::lnbVoltage: {
            status.set<FrontendStatus::lnbVoltage>(static_cast<LnbVoltage>(s.lnbVoltage()));
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::plpId: {
            status.set<FrontendStatus::plpId>((int32_t)s.plpId());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::isEWBS: {
            status.set<FrontendStatus::isEWBS>(s.isEWBS());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::agc: {
            status.set<FrontendStatus::agc>((int32_t)s.agc());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::isLnaOn: {
            status.set<FrontendStatus::isLnaOn>(s.isLnaOn());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::isLayerError: {
            vector<bool> e(s.isLayerError().begin(), s.isLayerError().end());
            status.set<FrontendStatus::isLayerError>(e);
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::mer: {
            status.set<FrontendStatus::mer>(static_cast<int32_t>(s.mer()));
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::freqOffset: {
            status.set<FrontendStatus::freqOffset>(static_cast<int64_t>(s.freqOffset()));
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::hierarchy: {
            status.set<FrontendStatus::hierarchy>(
                    static_cast<FrontendDvbtHierarchy>(s.hierarchy()));
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::isRfLocked: {
            status.set<FrontendStatus::isRfLocked>(s.isRfLocked());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatus::hidl_discriminator::plpInfo: {
            vector<FrontendStatusAtsc3PlpInfo> info;
            for (auto i : s.plpInfo()) {
                info.push_back({
                        .plpId = static_cast<int32_t>(i.plpId),
                        .isLocked = i.isLocked,
                        .uec = static_cast<int32_t>(i.uec),
                });
            }
            status.set<FrontendStatus::plpInfo>(info);
            aidlStatus.push_back(status);
            break;
        }
        }
    }

    for (HidlFrontendStatusExt1_1 s : hidlStatusExt) {
        FrontendStatus status;
        switch (s.getDiscriminator()) {
        case HidlFrontendStatusExt1_1::hidl_discriminator::modulations: {
            vector<FrontendModulation> aidlMod;
            for (auto m : s.modulations()) {
                switch (m.getDiscriminator()) {
                case HidlFrontendModulation::hidl_discriminator::dvbc:
                    aidlMod.push_back(static_cast<FrontendDvbcModulation>(m.dvbc()));
                    break;
                case HidlFrontendModulation::hidl_discriminator::dvbs:
                    aidlMod.push_back(static_cast<FrontendDvbsModulation>(m.dvbs()));
                    break;
                case HidlFrontendModulation::hidl_discriminator::dvbt:
                    aidlMod.push_back(static_cast<FrontendDvbtConstellation>(m.dvbt()));
                    break;
                case HidlFrontendModulation::hidl_discriminator::isdbs:
                    aidlMod.push_back(static_cast<FrontendIsdbsModulation>(m.isdbs()));
                    break;
                case HidlFrontendModulation::hidl_discriminator::isdbs3:
                    aidlMod.push_back(static_cast<FrontendIsdbs3Modulation>(m.isdbs3()));
                    break;
                case HidlFrontendModulation::hidl_discriminator::isdbt:
                    aidlMod.push_back(static_cast<FrontendIsdbtModulation>(m.isdbt()));
                    break;
                case HidlFrontendModulation::hidl_discriminator::atsc:
                    aidlMod.push_back(static_cast<FrontendAtscModulation>(m.atsc()));
                    break;
                case HidlFrontendModulation::hidl_discriminator::atsc3:
                    aidlMod.push_back(static_cast<FrontendAtsc3Modulation>(m.atsc3()));
                    break;
                case HidlFrontendModulation::hidl_discriminator::dtmb:
                    aidlMod.push_back(static_cast<FrontendDtmbModulation>(m.dtmb()));
                    break;
                }
            }
            status.set<FrontendStatus::modulations>(aidlMod);
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::bers: {
            vector<int> b(s.bers().begin(), s.bers().end());
            status.set<FrontendStatus::bers>(b);
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::codeRates: {
            vector<FrontendInnerFec> codeRates;
            for (auto c : s.codeRates()) {
                codeRates.push_back(static_cast<FrontendInnerFec>(c));
            }
            status.set<FrontendStatus::codeRates>(codeRates);
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::bandwidth: {
            FrontendBandwidth bandwidth;
            switch (s.bandwidth().getDiscriminator()) {
            case HidlFrontendBandwidth::hidl_discriminator::atsc3:
                bandwidth.set<FrontendBandwidth::atsc3>(
                        static_cast<FrontendAtsc3Bandwidth>(s.bandwidth().atsc3()));
                break;
            case HidlFrontendBandwidth::hidl_discriminator::dvbc:
                bandwidth.set<FrontendBandwidth::dvbc>(
                        static_cast<FrontendDvbcBandwidth>(s.bandwidth().dvbc()));
                break;
            case HidlFrontendBandwidth::hidl_discriminator::dvbt:
                bandwidth.set<FrontendBandwidth::dvbt>(
                        static_cast<FrontendDvbtBandwidth>(s.bandwidth().dvbt()));
                break;
            case HidlFrontendBandwidth::hidl_discriminator::isdbt:
                bandwidth.set<FrontendBandwidth::isdbt>(
                        static_cast<FrontendIsdbtBandwidth>(s.bandwidth().isdbt()));
                break;
            case HidlFrontendBandwidth::hidl_discriminator::dtmb:
                bandwidth.set<FrontendBandwidth::dtmb>(
                        static_cast<FrontendDtmbBandwidth>(s.bandwidth().dtmb()));
                break;
            }
            status.set<FrontendStatus::bandwidth>(bandwidth);
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::interval: {
            FrontendGuardInterval interval;
            switch (s.interval().getDiscriminator()) {
            case HidlFrontendGuardInterval::hidl_discriminator::dvbt:
                interval.set<FrontendGuardInterval::dvbt>(
                        static_cast<FrontendDvbtGuardInterval>(s.interval().dvbt()));
                break;
            case HidlFrontendGuardInterval::hidl_discriminator::isdbt:
                interval.set<FrontendGuardInterval::isdbt>(
                        static_cast<FrontendIsdbtGuardInterval>(s.interval().isdbt()));
                break;
            case HidlFrontendGuardInterval::hidl_discriminator::dtmb:
                interval.set<FrontendGuardInterval::dtmb>(
                        static_cast<FrontendDtmbGuardInterval>(s.interval().dtmb()));
                break;
            }
            status.set<FrontendStatus::interval>(interval);
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::transmissionMode: {
            FrontendTransmissionMode transmissionMode;
            switch (s.transmissionMode().getDiscriminator()) {
            case HidlFrontendTransmissionMode::hidl_discriminator::dvbt:
                transmissionMode.set<FrontendTransmissionMode::dvbt>(
                        static_cast<FrontendDvbtTransmissionMode>(s.transmissionMode().dvbt()));
                break;
            case HidlFrontendTransmissionMode::hidl_discriminator::isdbt:
                transmissionMode.set<FrontendTransmissionMode::isdbt>(
                        static_cast<FrontendIsdbtMode>(s.transmissionMode().isdbt()));
                break;
            case HidlFrontendTransmissionMode::hidl_discriminator::dtmb:
                transmissionMode.set<FrontendTransmissionMode::dtmb>(
                        static_cast<FrontendDtmbTransmissionMode>(s.transmissionMode().dtmb()));
                break;
            }
            status.set<FrontendStatus::transmissionMode>(transmissionMode);
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::uec: {
            status.set<FrontendStatus::uec>(static_cast<int32_t>(s.uec()));
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::systemId: {
            status.set<FrontendStatus::systemId>(static_cast<int32_t>(s.systemId()));
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::interleaving: {
            vector<FrontendInterleaveMode> aidlInter;
            for (auto i : s.interleaving()) {
                FrontendInterleaveMode leaveMode;
                switch (i.getDiscriminator()) {
                case HidlFrontendInterleaveMode::hidl_discriminator::atsc3:
                    leaveMode.set<FrontendInterleaveMode::atsc3>(
                            static_cast<FrontendAtsc3TimeInterleaveMode>(i.atsc3()));
                    break;
                case HidlFrontendInterleaveMode::hidl_discriminator::dvbc:
                    leaveMode.set<FrontendInterleaveMode::dvbc>(
                            static_cast<FrontendCableTimeInterleaveMode>(i.dvbc()));
                    break;
                case HidlFrontendInterleaveMode::hidl_discriminator::dtmb:
                    leaveMode.set<FrontendInterleaveMode::dtmb>(
                            static_cast<FrontendDtmbTimeInterleaveMode>(i.dtmb()));
                    break;
                }
                aidlInter.push_back(leaveMode);
            }
            status.set<FrontendStatus::interleaving>(aidlInter);
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::isdbtSegment: {
            const vector<uint8_t>& seg = s.isdbtSegment();
            vector<int32_t> i(seg.begin(), seg.end());
            status.set<FrontendStatus::isdbtSegment>(i);
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::tsDataRate: {
            vector<int32_t> ts(s.tsDataRate().begin(), s.tsDataRate().end());
            status.set<FrontendStatus::tsDataRate>(ts);
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::rollOff: {
            FrontendRollOff rollOff;
            switch (s.rollOff().getDiscriminator()) {
            case HidlFrontendRollOff::hidl_discriminator::dvbs:
                rollOff.set<FrontendRollOff::dvbs>(
                        static_cast<FrontendDvbsRolloff>(s.rollOff().dvbs()));
                break;
            case HidlFrontendRollOff::hidl_discriminator::isdbs:
                rollOff.set<FrontendRollOff::isdbs>(
                        static_cast<FrontendIsdbsRolloff>(s.rollOff().isdbs()));
                break;
            case HidlFrontendRollOff::hidl_discriminator::isdbs3:
                rollOff.set<FrontendRollOff::isdbs3>(
                        static_cast<FrontendIsdbs3Rolloff>(s.rollOff().isdbs3()));
                break;
            }
            status.set<FrontendStatus::rollOff>(rollOff);
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::isMiso: {
            status.set<FrontendStatus::isMiso>(s.isMiso());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::isLinear: {
            status.set<FrontendStatus::isLinear>(s.isLinear());
            aidlStatus.push_back(status);
            break;
        }
        case HidlFrontendStatusExt1_1::hidl_discriminator::isShortFrames: {
            status.set<FrontendStatus::isShortFrames>(s.isShortFrames());
            aidlStatus.push_back(status);
            break;
        }
        }
    }
}

hidl_vec<HidlFrontendAtsc3PlpSettings> TunerHidlFrontend::getAtsc3PlpSettings(
        const FrontendAtsc3Settings& settings) {
    int len = settings.plpSettings.size();
    hidl_vec<HidlFrontendAtsc3PlpSettings> plps = hidl_vec<HidlFrontendAtsc3PlpSettings>(len);
    // parse PLP settings
    for (int i = 0; i < len; i++) {
        uint8_t plpId = static_cast<uint8_t>(settings.plpSettings[i].plpId);
        HidlFrontendAtsc3Modulation modulation =
                static_cast<HidlFrontendAtsc3Modulation>(settings.plpSettings[i].modulation);
        HidlFrontendAtsc3TimeInterleaveMode interleaveMode =
                static_cast<HidlFrontendAtsc3TimeInterleaveMode>(
                        settings.plpSettings[i].interleaveMode);
        HidlFrontendAtsc3CodeRate codeRate =
                static_cast<HidlFrontendAtsc3CodeRate>(settings.plpSettings[i].codeRate);
        HidlFrontendAtsc3Fec fec = static_cast<HidlFrontendAtsc3Fec>(settings.plpSettings[i].fec);
        HidlFrontendAtsc3PlpSettings frontendAtsc3PlpSettings{
                .plpId = plpId,
                .modulation = modulation,
                .interleaveMode = interleaveMode,
                .codeRate = codeRate,
                .fec = fec,
        };
        plps[i] = frontendAtsc3PlpSettings;
    }
    return plps;
}

HidlFrontendDvbsCodeRate TunerHidlFrontend::getDvbsCodeRate(const FrontendDvbsCodeRate& codeRate) {
    HidlFrontendInnerFec innerFec = static_cast<HidlFrontendInnerFec>(codeRate.fec);
    bool isLinear = codeRate.isLinear;
    bool isShortFrames = codeRate.isShortFrames;
    uint32_t bitsPer1000Symbol = static_cast<uint32_t>(codeRate.bitsPer1000Symbol);
    HidlFrontendDvbsCodeRate coderate{
            .fec = innerFec,
            .isLinear = isLinear,
            .isShortFrames = isShortFrames,
            .bitsPer1000Symbol = bitsPer1000Symbol,
    };
    return coderate;
}

void TunerHidlFrontend::getHidlFrontendSettings(const FrontendSettings& aidlSettings,
                                                HidlFrontendSettings& settings,
                                                HidlFrontendSettingsExt1_1& settingsExt) {
    switch (aidlSettings.getTag()) {
    case FrontendSettings::analog: {
        const FrontendAnalogSettings& analog = aidlSettings.get<FrontendSettings::analog>();
        settings.analog({
                .frequency = static_cast<uint32_t>(analog.frequency),
                .type = static_cast<HidlFrontendAnalogType>(analog.type),
                .sifStandard = static_cast<HidlFrontendAnalogSifStandard>(analog.sifStandard),
        });
        settingsExt.settingExt.analog({
                .aftFlag = static_cast<HidlFrontendAnalogAftFlag>(analog.aftFlag),
        });
        settingsExt.endFrequency = static_cast<uint32_t>(analog.endFrequency);
        settingsExt.inversion = static_cast<HidlFrontendSpectralInversion>(analog.inversion);
        break;
    }
    case FrontendSettings::atsc: {
        const FrontendAtscSettings& atsc = aidlSettings.get<FrontendSettings::atsc>();
        settings.atsc({
                .frequency = static_cast<uint32_t>(atsc.frequency),
                .modulation = static_cast<HidlFrontendAtscModulation>(atsc.modulation),
        });
        settingsExt.endFrequency = static_cast<uint32_t>(atsc.endFrequency);
        settingsExt.inversion = static_cast<HidlFrontendSpectralInversion>(atsc.inversion);
        settingsExt.settingExt.noinit();
        break;
    }
    case FrontendSettings::atsc3: {
        const FrontendAtsc3Settings& atsc3 = aidlSettings.get<FrontendSettings::atsc3>();
        settings.atsc3({
                .frequency = static_cast<uint32_t>(atsc3.frequency),
                .bandwidth = static_cast<HidlFrontendAtsc3Bandwidth>(atsc3.bandwidth),
                .demodOutputFormat =
                        static_cast<HidlFrontendAtsc3DemodOutputFormat>(atsc3.demodOutputFormat),
                .plpSettings = getAtsc3PlpSettings(atsc3),
        });
        settingsExt.endFrequency = static_cast<uint32_t>(atsc3.endFrequency);
        settingsExt.inversion = static_cast<HidlFrontendSpectralInversion>(atsc3.inversion);
        settingsExt.settingExt.noinit();
        break;
    }
    case FrontendSettings::dvbc: {
        const FrontendDvbcSettings& dvbc = aidlSettings.get<FrontendSettings::dvbc>();
        settings.dvbc({
                .frequency = static_cast<uint32_t>(dvbc.frequency),
                .modulation = static_cast<HidlFrontendDvbcModulation>(dvbc.modulation),
                .fec = static_cast<HidlFrontendInnerFec>(dvbc.fec),
                .symbolRate = static_cast<uint32_t>(dvbc.symbolRate),
                .outerFec = static_cast<HidlFrontendDvbcOuterFec>(dvbc.outerFec),
                .annex = static_cast<HidlFrontendDvbcAnnex>(dvbc.annex),
                .spectralInversion = static_cast<HidlFrontendDvbcSpectralInversion>(dvbc.inversion),
        });
        settingsExt.settingExt.dvbc({
                .interleaveMode =
                        static_cast<HidlFrontendCableTimeInterleaveMode>(dvbc.interleaveMode),
                .bandwidth = static_cast<HidlFrontendDvbcBandwidth>(dvbc.bandwidth),
        });
        settingsExt.endFrequency = static_cast<uint32_t>(dvbc.endFrequency);
        settingsExt.inversion = static_cast<HidlFrontendSpectralInversion>(dvbc.inversion);
        break;
    }
    case FrontendSettings::dvbs: {
        const FrontendDvbsSettings& dvbs = aidlSettings.get<FrontendSettings::dvbs>();
        settings.dvbs({
                .frequency = static_cast<uint32_t>(dvbs.frequency),
                .modulation = static_cast<HidlFrontendDvbsModulation>(dvbs.modulation),
                .coderate = getDvbsCodeRate(dvbs.coderate),
                .symbolRate = static_cast<uint32_t>(dvbs.symbolRate),
                .rolloff = static_cast<HidlFrontendDvbsRolloff>(dvbs.rolloff),
                .pilot = static_cast<HidlFrontendDvbsPilot>(dvbs.pilot),
                .inputStreamId = static_cast<uint32_t>(dvbs.inputStreamId),
                .standard = static_cast<HidlFrontendDvbsStandard>(dvbs.standard),
                .vcmMode = static_cast<HidlFrontendDvbsVcmMode>(dvbs.vcmMode),
        });
        settingsExt.settingExt.dvbs({
                .scanType = static_cast<HidlFrontendDvbsScanType>(dvbs.scanType),
                .isDiseqcRxMessage = dvbs.isDiseqcRxMessage,
        });
        settingsExt.endFrequency = static_cast<uint32_t>(dvbs.endFrequency);
        settingsExt.inversion = static_cast<HidlFrontendSpectralInversion>(dvbs.inversion);
        break;
    }
    case FrontendSettings::dvbt: {
        const FrontendDvbtSettings& dvbt = aidlSettings.get<FrontendSettings::dvbt>();
        settings.dvbt({
                .frequency = static_cast<uint32_t>(dvbt.frequency),
                .transmissionMode =
                        static_cast<HidlFrontendDvbtTransmissionMode>(dvbt.transmissionMode),
                .bandwidth = static_cast<HidlFrontendDvbtBandwidth>(dvbt.bandwidth),
                .constellation = static_cast<HidlFrontendDvbtConstellation>(dvbt.constellation),
                .hierarchy = static_cast<HidlFrontendDvbtHierarchy>(dvbt.hierarchy),
                .hpCoderate = static_cast<HidlFrontendDvbtCoderate>(dvbt.hpCoderate),
                .lpCoderate = static_cast<HidlFrontendDvbtCoderate>(dvbt.lpCoderate),
                .guardInterval = static_cast<HidlFrontendDvbtGuardInterval>(dvbt.guardInterval),
                .isHighPriority = dvbt.isHighPriority,
                .standard = static_cast<HidlFrontendDvbtStandard>(dvbt.standard),
                .isMiso = dvbt.isMiso,
                .plpMode = static_cast<HidlFrontendDvbtPlpMode>(dvbt.plpMode),
                .plpId = static_cast<uint8_t>(dvbt.plpId),
                .plpGroupId = static_cast<uint8_t>(dvbt.plpGroupId),
        });
        settingsExt.settingExt.dvbt({
                .constellation = static_cast<
                        ::android::hardware::tv::tuner::V1_1::FrontendDvbtConstellation>(
                        dvbt.constellation),
                .transmissionMode = static_cast<
                        ::android::hardware::tv::tuner::V1_1::FrontendDvbtTransmissionMode>(
                        dvbt.transmissionMode),
        });
        settingsExt.endFrequency = static_cast<uint32_t>(dvbt.endFrequency);
        settingsExt.inversion = static_cast<HidlFrontendSpectralInversion>(dvbt.inversion);
        break;
    }
    case FrontendSettings::isdbs: {
        const FrontendIsdbsSettings& isdbs = aidlSettings.get<FrontendSettings::isdbs>();
        settings.isdbs({
                .frequency = static_cast<uint32_t>(isdbs.frequency),
                .streamId = static_cast<uint16_t>(isdbs.streamId),
                .streamIdType = static_cast<HidlFrontendIsdbsStreamIdType>(isdbs.streamIdType),
                .modulation = static_cast<HidlFrontendIsdbsModulation>(isdbs.modulation),
                .coderate = static_cast<HidlFrontendIsdbsCoderate>(isdbs.coderate),
                .symbolRate = static_cast<uint32_t>(isdbs.symbolRate),
                .rolloff = static_cast<HidlFrontendIsdbsRolloff>(isdbs.rolloff),
        });
        settingsExt.endFrequency = static_cast<uint32_t>(isdbs.endFrequency);
        settingsExt.settingExt.noinit();
        break;
    }
    case FrontendSettings::isdbs3: {
        const FrontendIsdbs3Settings& isdbs3 = aidlSettings.get<FrontendSettings::isdbs3>();
        settings.isdbs3({
                .frequency = static_cast<uint32_t>(isdbs3.frequency),
                .streamId = static_cast<uint16_t>(isdbs3.streamId),
                .streamIdType = static_cast<HidlFrontendIsdbsStreamIdType>(isdbs3.streamIdType),
                .modulation = static_cast<HidlFrontendIsdbs3Modulation>(isdbs3.modulation),
                .coderate = static_cast<HidlFrontendIsdbs3Coderate>(isdbs3.coderate),
                .symbolRate = static_cast<uint32_t>(isdbs3.symbolRate),
                .rolloff = static_cast<HidlFrontendIsdbs3Rolloff>(isdbs3.rolloff),
        });
        settingsExt.endFrequency = static_cast<uint32_t>(isdbs3.endFrequency);
        settingsExt.settingExt.noinit();
        break;
    }
    case FrontendSettings::isdbt: {
        const FrontendIsdbtSettings& isdbt = aidlSettings.get<FrontendSettings::isdbt>();
        HidlFrontendIsdbtModulation modulation = HidlFrontendIsdbtModulation::UNDEFINED;
        HidlFrontendIsdbtCoderate coderate = HidlFrontendIsdbtCoderate::UNDEFINED;
        if (isdbt.layerSettings.size() > 0) {
            modulation =
                    static_cast<HidlFrontendIsdbtModulation>(isdbt.layerSettings[0].modulation);
            coderate = static_cast<HidlFrontendIsdbtCoderate>(isdbt.layerSettings[0].coderate);
        }
        settings.isdbt({
                .frequency = static_cast<uint32_t>(isdbt.frequency),
                .modulation = modulation,
                .bandwidth = static_cast<HidlFrontendIsdbtBandwidth>(isdbt.bandwidth),
                .mode = static_cast<HidlFrontendIsdbtMode>(isdbt.mode),
                .coderate = coderate,
                .guardInterval = static_cast<HidlFrontendIsdbtGuardInterval>(isdbt.guardInterval),
                .serviceAreaId = static_cast<uint32_t>(isdbt.serviceAreaId),
        });
        settingsExt.endFrequency = static_cast<uint32_t>(isdbt.endFrequency);
        settingsExt.inversion = static_cast<HidlFrontendSpectralInversion>(isdbt.inversion);
        settingsExt.settingExt.noinit();
        break;
    }
    case FrontendSettings::dtmb: {
        const FrontendDtmbSettings& dtmb = aidlSettings.get<FrontendSettings::dtmb>();
        settingsExt.settingExt.dtmb({
                .frequency = static_cast<uint32_t>(dtmb.frequency),
                .transmissionMode =
                        static_cast<HidlFrontendDtmbTransmissionMode>(dtmb.transmissionMode),
                .bandwidth = static_cast<HidlFrontendDtmbBandwidth>(dtmb.bandwidth),
                .modulation = static_cast<HidlFrontendDtmbModulation>(dtmb.modulation),
                .codeRate = static_cast<HidlFrontendDtmbCodeRate>(dtmb.codeRate),
                .guardInterval = static_cast<HidlFrontendDtmbGuardInterval>(dtmb.guardInterval),
                .interleaveMode =
                        static_cast<HidlFrontendDtmbTimeInterleaveMode>(dtmb.interleaveMode),
        });
        settingsExt.endFrequency = static_cast<uint32_t>(dtmb.endFrequency);
        settingsExt.inversion = static_cast<HidlFrontendSpectralInversion>(dtmb.inversion);
        break;
    }
    default:
        break;
    }
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
