/**
 * Copyright 2020, The Android Open Source Project
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

#define LOG_TAG "TunerFrontend"

#include "TunerFrontend.h"
#include "TunerLnb.h"

using ::aidl::android::media::tv::tuner::TunerFrontendAtsc3PlpSettings;
using ::aidl::android::media::tv::tuner::TunerFrontendScanAtsc3PlpInfo;
using ::aidl::android::media::tv::tuner::TunerFrontendStatusAtsc3PlpInfo;
using ::aidl::android::media::tv::tuner::TunerFrontendUnionSettings;
using ::android::hardware::tv::tuner::V1_0::FrontendAnalogSifStandard;
using ::android::hardware::tv::tuner::V1_0::FrontendAnalogType;
using ::android::hardware::tv::tuner::V1_0::FrontendAtscModulation;
using ::android::hardware::tv::tuner::V1_0::FrontendAtsc3Bandwidth;
using ::android::hardware::tv::tuner::V1_0::FrontendAtsc3CodeRate;
using ::android::hardware::tv::tuner::V1_0::FrontendAtsc3DemodOutputFormat;
using ::android::hardware::tv::tuner::V1_0::FrontendAtsc3Fec;
using ::android::hardware::tv::tuner::V1_0::FrontendAtsc3Modulation;
using ::android::hardware::tv::tuner::V1_0::FrontendAtsc3TimeInterleaveMode;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbcAnnex;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbcModulation;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbcOuterFec;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbcSpectralInversion;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbsModulation;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbsPilot;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbsRolloff;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbsSettings;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbsStandard;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbsVcmMode;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbtBandwidth;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbtCoderate;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbtConstellation;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbtGuardInterval;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbtHierarchy;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbtPlpMode;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbtSettings;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbtStandard;
using ::android::hardware::tv::tuner::V1_0::FrontendDvbtTransmissionMode;
using ::android::hardware::tv::tuner::V1_0::FrontendInnerFec;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbs3Coderate;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbs3Modulation;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbs3Rolloff;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbs3Settings;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbsCoderate;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbsModulation;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbsRolloff;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbsSettings;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbsStreamIdType;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbtBandwidth;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbtCoderate;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbtGuardInterval;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbtMode;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbtModulation;
using ::android::hardware::tv::tuner::V1_0::FrontendIsdbtSettings;
using ::android::hardware::tv::tuner::V1_0::FrontendModulationStatus;
using ::android::hardware::tv::tuner::V1_0::FrontendScanAtsc3PlpInfo;
using ::android::hardware::tv::tuner::V1_0::FrontendScanType;
using ::android::hardware::tv::tuner::V1_0::FrontendStatusType;
using ::android::hardware::tv::tuner::V1_0::Result;
using ::android::hardware::tv::tuner::V1_1::FrontendAnalogAftFlag;
using ::android::hardware::tv::tuner::V1_1::FrontendBandwidth;
using ::android::hardware::tv::tuner::V1_1::FrontendCableTimeInterleaveMode;
using ::android::hardware::tv::tuner::V1_1::FrontendDvbcBandwidth;
using ::android::hardware::tv::tuner::V1_1::FrontendDtmbBandwidth;
using ::android::hardware::tv::tuner::V1_1::FrontendDtmbCodeRate;
using ::android::hardware::tv::tuner::V1_1::FrontendDtmbGuardInterval;
using ::android::hardware::tv::tuner::V1_1::FrontendDtmbModulation;
using ::android::hardware::tv::tuner::V1_1::FrontendDtmbTimeInterleaveMode;
using ::android::hardware::tv::tuner::V1_1::FrontendDtmbTransmissionMode;
using ::android::hardware::tv::tuner::V1_1::FrontendDvbsScanType;
using ::android::hardware::tv::tuner::V1_1::FrontendGuardInterval;
using ::android::hardware::tv::tuner::V1_1::FrontendInterleaveMode;
using ::android::hardware::tv::tuner::V1_1::FrontendModulation;
using ::android::hardware::tv::tuner::V1_1::FrontendRollOff;
using ::android::hardware::tv::tuner::V1_1::FrontendTransmissionMode;
using ::android::hardware::tv::tuner::V1_1::FrontendSpectralInversion;
using ::android::hardware::tv::tuner::V1_1::FrontendStatusTypeExt1_1;

namespace android {

TunerFrontend::TunerFrontend(sp<IFrontend> frontend, int id) {
    mFrontend = frontend;
    mFrontend_1_1 = ::android::hardware::tv::tuner::V1_1::IFrontend::castFrom(mFrontend);
    mId = id;
}

TunerFrontend::~TunerFrontend() {
    mFrontend = NULL;
    mFrontend_1_1 = NULL;
    mId = -1;
}

Status TunerFrontend::setCallback(
        const shared_ptr<ITunerFrontendCallback>& tunerFrontendCallback) {
    if (mFrontend == NULL) {
        ALOGE("IFrontend is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (tunerFrontendCallback == NULL) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    sp<IFrontendCallback> frontendCallback = new FrontendCallback(tunerFrontendCallback);
    Result status = mFrontend->setCallback(frontendCallback);
    if (status == Result::SUCCESS) {
        return Status::ok();
    }

    return Status::fromServiceSpecificError(static_cast<int32_t>(status));
}

Status TunerFrontend::tune(const TunerFrontendSettings& settings) {
    if (mFrontend == NULL) {
        ALOGE("IFrontend is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status;
    FrontendSettings frontendSettings = getHidlFrontendSettings(settings);
    if (settings.isExtended) {
        if (mFrontend_1_1 == NULL) {
            ALOGE("IFrontend_1_1 is not initialized");
            return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
        }
        FrontendSettingsExt1_1 frontendSettingsExt = getHidlFrontendSettingsExt(settings);
        status = mFrontend_1_1->tune_1_1(frontendSettings, frontendSettingsExt);
    } else {
        status = mFrontend->tune(frontendSettings);
    }

    if (status == Result::SUCCESS) {
        return Status::ok();
    }

    return Status::fromServiceSpecificError(static_cast<int32_t>(status));
}

Status TunerFrontend::stopTune() {
    if (mFrontend == NULL) {
        ALOGD("IFrontend is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status = mFrontend->stopTune();
    if (status == Result::SUCCESS) {
        return Status::ok();
    }

    return Status::fromServiceSpecificError(static_cast<int32_t>(status));
}

Status TunerFrontend::scan(const TunerFrontendSettings& settings, int frontendScanType) {
    if (mFrontend == NULL) {
        ALOGD("IFrontend is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status;
    FrontendSettings frontendSettings = getHidlFrontendSettings(settings);
    if (settings.isExtended) {
        if (mFrontend_1_1 == NULL) {
            ALOGE("IFrontend_1_1 is not initialized");
            return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
        }
        FrontendSettingsExt1_1 frontendSettingsExt = getHidlFrontendSettingsExt(settings);
        status = mFrontend_1_1->scan_1_1(frontendSettings,
                static_cast<FrontendScanType>(frontendScanType), frontendSettingsExt);
    } else {
        status = mFrontend->scan(
                frontendSettings, static_cast<FrontendScanType>(frontendScanType));
    }

    if (status == Result::SUCCESS) {
        return Status::ok();
    }

    return Status::fromServiceSpecificError(static_cast<int32_t>(status));
}

Status TunerFrontend::stopScan() {
    if (mFrontend == NULL) {
        ALOGD("IFrontend is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status = mFrontend->stopScan();
    if (status == Result::SUCCESS) {
        return Status::ok();
    }

    return Status::fromServiceSpecificError(static_cast<int32_t>(status));
}

Status TunerFrontend::setLnb(const shared_ptr<ITunerLnb>& lnb) {
    if (mFrontend == NULL) {
        ALOGD("IFrontend is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status = mFrontend->setLnb(static_cast<TunerLnb*>(lnb.get())->getId());
    if (status == Result::SUCCESS) {
        return Status::ok();
    }

    return Status::fromServiceSpecificError(static_cast<int32_t>(status));
}

Status TunerFrontend::setLna(bool bEnable) {
    if (mFrontend == NULL) {
        ALOGD("IFrontend is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status = mFrontend->setLna(bEnable);
    if (status == Result::SUCCESS) {
        return Status::ok();
    }

    return Status::fromServiceSpecificError(static_cast<int32_t>(status));
}

Status TunerFrontend::linkCiCamToFrontend(int ciCamId, int32_t* _aidl_return) {
    if (mFrontend_1_1 == NULL) {
        ALOGD("IFrontend_1_1 is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    int ltsId;
    Result status;
    mFrontend_1_1->linkCiCam(static_cast<uint32_t>(ciCamId),
            [&](Result r, uint32_t id) {
                status = r;
                ltsId = id;
            });

    if (status == Result::SUCCESS) {
        *_aidl_return = ltsId;
        return Status::ok();
    }

    return Status::fromServiceSpecificError(static_cast<int32_t>(status));
}

Status TunerFrontend::unlinkCiCamToFrontend(int ciCamId) {
    if (mFrontend_1_1 == NULL) {
        ALOGD("IFrontend_1_1 is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status = mFrontend_1_1->unlinkCiCam(ciCamId);
    if (status == Result::SUCCESS) {
        return Status::ok();
    }

    return Status::fromServiceSpecificError(static_cast<int32_t>(status));
}

Status TunerFrontend::close() {
    if (mFrontend == NULL) {
        ALOGD("IFrontend is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status = mFrontend->close();
    mFrontend = NULL;
    mFrontend_1_1 = NULL;

    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return Status::ok();
}

Status TunerFrontend::getStatus(const vector<int32_t>& statusTypes,
        vector<TunerFrontendStatus>* _aidl_return) {
    if (mFrontend == NULL) {
        ALOGD("IFrontend is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res;
    vector<FrontendStatus> status;
    vector<FrontendStatusType> types;
    for (auto s : statusTypes) {
        types.push_back(static_cast<FrontendStatusType>(s));
    }

    mFrontend->getStatus(types, [&](Result r, const hidl_vec<FrontendStatus>& s) {
        res = r;
        status = s;
    });
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    getAidlFrontendStatus(status, *_aidl_return);
    return Status::ok();
}

Status TunerFrontend::getStatusExtended_1_1(const vector<int32_t>& statusTypes,
        vector<TunerFrontendStatus>* _aidl_return) {
    if (mFrontend_1_1 == NULL) {
        ALOGD("IFrontend_1_1 is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res;
    vector<FrontendStatusExt1_1> status;
    vector<FrontendStatusTypeExt1_1> types;
    for (auto s : statusTypes) {
        types.push_back(static_cast<FrontendStatusTypeExt1_1>(s));
    }

    mFrontend_1_1->getStatusExt1_1(types, [&](Result r, const hidl_vec<FrontendStatusExt1_1>& s) {
        res = r;
        status = s;
    });
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    getAidlFrontendStatusExt(status, *_aidl_return);
    return Status::ok();
}

Status TunerFrontend::getFrontendId(int* _aidl_return) {
    *_aidl_return = mId;
    return Status::ok();
}

/////////////// FrontendCallback ///////////////////////

Return<void> TunerFrontend::FrontendCallback::onEvent(FrontendEventType frontendEventType) {
    ALOGD("FrontendCallback::onEvent, type=%d", frontendEventType);
    mTunerFrontendCallback->onEvent((int)frontendEventType);
    return Void();
}

Return<void> TunerFrontend::FrontendCallback::onScanMessage(
        FrontendScanMessageType type, const FrontendScanMessage& message) {
    ALOGD("FrontendCallback::onScanMessage, type=%d", type);
    TunerFrontendScanMessage scanMessage;
    switch(type) {
        case FrontendScanMessageType::LOCKED: {
            scanMessage.set<TunerFrontendScanMessage::isLocked>(message.isLocked());
            break;
        }
        case FrontendScanMessageType::END: {
            scanMessage.set<TunerFrontendScanMessage::isEnd>(message.isEnd());
            break;
        }
        case FrontendScanMessageType::PROGRESS_PERCENT: {
            scanMessage.set<TunerFrontendScanMessage::progressPercent>(message.progressPercent());
            break;
        }
        case FrontendScanMessageType::FREQUENCY: {
            auto f = message.frequencies();
            vector<int> frequencies(begin(f), end(f));
            scanMessage.set<TunerFrontendScanMessage::frequencies>(frequencies);
            break;
        }
        case FrontendScanMessageType::SYMBOL_RATE: {
            auto s = message.symbolRates();
            vector<int> symbolRates(begin(s), end(s));
            scanMessage.set<TunerFrontendScanMessage::symbolRates>(symbolRates);
            break;
        }
        case FrontendScanMessageType::HIERARCHY: {
            scanMessage.set<TunerFrontendScanMessage::hierarchy>((int)message.hierarchy());
            break;
        }
        case FrontendScanMessageType::ANALOG_TYPE: {
            scanMessage.set<TunerFrontendScanMessage::analogType>((int)message.analogType());
            break;
        }
        case FrontendScanMessageType::PLP_IDS: {
            auto p = message.plpIds();
            vector<uint8_t> plpIds(begin(p), end(p));
            scanMessage.set<TunerFrontendScanMessage::plpIds>(plpIds);
            break;
        }
        case FrontendScanMessageType::GROUP_IDS: {
            auto g = message.groupIds();
            vector<uint8_t> groupIds(begin(g), end(g));
            scanMessage.set<TunerFrontendScanMessage::groupIds>(groupIds);
            break;
        }
        case FrontendScanMessageType::INPUT_STREAM_IDS: {
            auto i = message.inputStreamIds();
            vector<char16_t> streamIds(begin(i), end(i));
            scanMessage.set<TunerFrontendScanMessage::inputStreamIds>(streamIds);
            break;
        }
        case FrontendScanMessageType::STANDARD: {
            FrontendScanMessage::Standard std = message.std();
            int standard;
            if (std.getDiscriminator() == FrontendScanMessage::Standard::hidl_discriminator::sStd) {
                standard = (int) std.sStd();
            } else if (std.getDiscriminator() ==
                    FrontendScanMessage::Standard::hidl_discriminator::tStd) {
                standard = (int) std.tStd();
            } else if (std.getDiscriminator() ==
                    FrontendScanMessage::Standard::hidl_discriminator::sifStd) {
                standard = (int) std.sifStd();
            }
            scanMessage.set<TunerFrontendScanMessage::std>(standard);
            break;
        }
        case FrontendScanMessageType::ATSC3_PLP_INFO: {
            vector<FrontendScanAtsc3PlpInfo> plpInfos = message.atsc3PlpInfos();
            vector<TunerFrontendScanAtsc3PlpInfo> tunerPlpInfos;
            for (int i = 0; i < plpInfos.size(); i++) {
                auto info = plpInfos[i];
                int8_t plpId = (int8_t) info.plpId;
                bool lls = (bool) info.bLlsFlag;
                TunerFrontendScanAtsc3PlpInfo plpInfo{
                    .plpId = plpId,
                    .llsFlag = lls,
                };
                tunerPlpInfos.push_back(plpInfo);
            }
            scanMessage.set<TunerFrontendScanMessage::atsc3PlpInfos>(tunerPlpInfos);
            break;
        }
        default:
            break;
    }
    mTunerFrontendCallback->onScanMessage((int)type, scanMessage);
    return Void();
}

Return<void> TunerFrontend::FrontendCallback::onScanMessageExt1_1(
        FrontendScanMessageTypeExt1_1 type, const FrontendScanMessageExt1_1& message) {
    ALOGD("onScanMessageExt1_1::onScanMessage, type=%d", type);
    TunerFrontendScanMessage scanMessage;
    switch(type) {
        case FrontendScanMessageTypeExt1_1::MODULATION: {
            FrontendModulation m = message.modulation();
            int modulation;
            switch (m.getDiscriminator()) {
                case FrontendModulation::hidl_discriminator::dvbc:
                    modulation = (int) m.dvbc();
                    break;
                case FrontendModulation::hidl_discriminator::dvbt:
                    modulation = (int) m.dvbt();
                    break;
                case FrontendModulation::hidl_discriminator::dvbs:
                    modulation = (int) m.dvbs();
                    break;
                case FrontendModulation::hidl_discriminator::isdbs:
                    modulation = (int) m.isdbs();
                    break;
                case FrontendModulation::hidl_discriminator::isdbs3:
                    modulation = (int) m.isdbs3();
                    break;
                case FrontendModulation::hidl_discriminator::isdbt:
                    modulation = (int) m.isdbt();
                    break;
                case FrontendModulation::hidl_discriminator::atsc:
                    modulation = (int) m.atsc();
                    break;
                case FrontendModulation::hidl_discriminator::atsc3:
                    modulation = (int) m.atsc3();
                    break;
                case FrontendModulation::hidl_discriminator::dtmb:
                    modulation = (int) m.dtmb();
                    break;
            }
            scanMessage.set<TunerFrontendScanMessage::modulation>(modulation);
            break;
        }
        case FrontendScanMessageTypeExt1_1::DVBC_ANNEX: {
            scanMessage.set<TunerFrontendScanMessage::annex>((int)message.annex());
            break;
        }
        case FrontendScanMessageTypeExt1_1::HIGH_PRIORITY: {
            scanMessage.set<TunerFrontendScanMessage::isHighPriority>(message.isHighPriority());
            break;
        }
        default:
            break;
    }
    mTunerFrontendCallback->onScanMessage((int)type, scanMessage);
    return Void();
}

/////////////// TunerFrontend Helper Methods ///////////////////////

void TunerFrontend::getAidlFrontendStatus(
        vector<FrontendStatus>& hidlStatus, vector<TunerFrontendStatus>& aidlStatus) {
    for (FrontendStatus s : hidlStatus) {
        TunerFrontendStatus status;
        switch (s.getDiscriminator()) {
            case FrontendStatus::hidl_discriminator::isDemodLocked: {
                status.set<TunerFrontendStatus::isDemodLocked>(s.isDemodLocked());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::snr: {
                status.set<TunerFrontendStatus::snr>((int)s.snr());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::ber: {
                status.set<TunerFrontendStatus::ber>((int)s.ber());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::per: {
                status.set<TunerFrontendStatus::per>((int)s.per());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::preBer: {
                status.set<TunerFrontendStatus::preBer>((int)s.preBer());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::signalQuality: {
                status.set<TunerFrontendStatus::signalQuality>((int)s.signalQuality());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::signalStrength: {
                status.set<TunerFrontendStatus::signalStrength>((int)s.signalStrength());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::symbolRate: {
                status.set<TunerFrontendStatus::symbolRate>((int)s.symbolRate());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::innerFec: {
                status.set<TunerFrontendStatus::innerFec>((long)s.innerFec());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::modulation: {
                switch (s.modulation().getDiscriminator()) {
                    case FrontendModulationStatus::hidl_discriminator::dvbc:
                        status.set<TunerFrontendStatus::modulation>((int)s.modulation().dvbc());
                        aidlStatus.push_back(status);
                        break;
                    case FrontendModulationStatus::hidl_discriminator::dvbs:
                        status.set<TunerFrontendStatus::modulation>((int)s.modulation().dvbs());
                        aidlStatus.push_back(status);
                        break;
                    case FrontendModulationStatus::hidl_discriminator::isdbs:
                        status.set<TunerFrontendStatus::modulation>((int)s.modulation().isdbs());
                        aidlStatus.push_back(status);
                        break;
                    case FrontendModulationStatus::hidl_discriminator::isdbs3:
                        status.set<TunerFrontendStatus::modulation>((int)s.modulation().isdbs3());
                        aidlStatus.push_back(status);
                        break;
                    case FrontendModulationStatus::hidl_discriminator::isdbt:
                        status.set<TunerFrontendStatus::modulation>((int)s.modulation().isdbt());
                        aidlStatus.push_back(status);
                        break;
                }
                break;
            }
            case FrontendStatus::hidl_discriminator::inversion: {
                status.set<TunerFrontendStatus::inversion>((int)s.inversion());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::lnbVoltage: {
                status.set<TunerFrontendStatus::lnbVoltage>((int)s.lnbVoltage());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::plpId: {
                status.set<TunerFrontendStatus::plpId>((int8_t)s.plpId());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::isEWBS: {
                status.set<TunerFrontendStatus::isEWBS>(s.isEWBS());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::agc: {
                status.set<TunerFrontendStatus::agc>((int8_t)s.agc());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::isLnaOn: {
                status.set<TunerFrontendStatus::isLnaOn>(s.isLnaOn());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::isLayerError: {
                vector<bool> e(s.isLayerError().begin(), s.isLayerError().end());
                status.set<TunerFrontendStatus::isLayerError>(e);
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::mer: {
                status.set<TunerFrontendStatus::mer>((int)s.mer());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::freqOffset: {
                status.set<TunerFrontendStatus::freqOffset>((int)s.freqOffset());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::hierarchy: {
                status.set<TunerFrontendStatus::hierarchy>((int)s.hierarchy());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::isRfLocked: {
                status.set<TunerFrontendStatus::isRfLocked>(s.isRfLocked());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatus::hidl_discriminator::plpInfo: {
                vector<TunerFrontendStatusAtsc3PlpInfo> info;
                for (auto i : s.plpInfo()) {
                    info.push_back({
                        .plpId = (int8_t)i.plpId,
                        .isLocked = i.isLocked,
                        .uec = (int)i.uec,
                    });
                }
                status.set<TunerFrontendStatus::plpInfo>(info);
                aidlStatus.push_back(status);
                break;
            }
        }
    }
}

void TunerFrontend::getAidlFrontendStatusExt(
        vector<FrontendStatusExt1_1>& hidlStatus, vector<TunerFrontendStatus>& aidlStatus) {
    for (FrontendStatusExt1_1 s : hidlStatus) {
        TunerFrontendStatus status;
        switch (s.getDiscriminator()) {
            case FrontendStatusExt1_1::hidl_discriminator::modulations: {
                vector<int> aidlMod;
                for (auto m : s.modulations()) {
                    switch (m.getDiscriminator()) {
                        case FrontendModulation::hidl_discriminator::dvbc:
                            aidlMod.push_back((int)m.dvbc());
                            break;
                        case FrontendModulation::hidl_discriminator::dvbs:
                            aidlMod.push_back((int)m.dvbs());
                            break;
                        case FrontendModulation::hidl_discriminator::dvbt:
                            aidlMod.push_back((int)m.dvbt());
                            break;
                        case FrontendModulation::hidl_discriminator::isdbs:
                            aidlMod.push_back((int)m.isdbs());
                            break;
                        case FrontendModulation::hidl_discriminator::isdbs3:
                            aidlMod.push_back((int)m.isdbs3());
                            break;
                        case FrontendModulation::hidl_discriminator::isdbt:
                            aidlMod.push_back((int)m.isdbt());
                            break;
                        case FrontendModulation::hidl_discriminator::atsc:
                            aidlMod.push_back((int)m.atsc());
                            break;
                        case FrontendModulation::hidl_discriminator::atsc3:
                            aidlMod.push_back((int)m.atsc3());
                            break;
                        case FrontendModulation::hidl_discriminator::dtmb:
                            aidlMod.push_back((int)m.dtmb());
                            break;
                    }
                }
                status.set<TunerFrontendStatus::modulations>(aidlMod);
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::bers: {
                vector<int> b(s.bers().begin(), s.bers().end());
                status.set<TunerFrontendStatus::bers>(b);
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::codeRates: {
                vector<int64_t> codeRates;
                for (auto c : s.codeRates()) {
                    codeRates.push_back((long)c);
                }
                status.set<TunerFrontendStatus::codeRates>(codeRates);
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::bandwidth: {
                switch (s.bandwidth().getDiscriminator()) {
                    case FrontendBandwidth::hidl_discriminator::atsc3:
                        status.set<TunerFrontendStatus::bandwidth>((int)s.bandwidth().atsc3());
                        break;
                    case FrontendBandwidth::hidl_discriminator::dvbc:
                        status.set<TunerFrontendStatus::bandwidth>((int)s.bandwidth().dvbc());
                        break;
                    case FrontendBandwidth::hidl_discriminator::dvbt:
                        status.set<TunerFrontendStatus::bandwidth>((int)s.bandwidth().dvbt());
                        break;
                    case FrontendBandwidth::hidl_discriminator::isdbt:
                        status.set<TunerFrontendStatus::bandwidth>((int)s.bandwidth().isdbt());
                        break;
                    case FrontendBandwidth::hidl_discriminator::dtmb:
                        status.set<TunerFrontendStatus::bandwidth>((int)s.bandwidth().dtmb());
                        break;
                }
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::interval: {
                switch (s.interval().getDiscriminator()) {
                    case FrontendGuardInterval::hidl_discriminator::dvbt:
                        status.set<TunerFrontendStatus::interval>((int)s.interval().dvbt());
                        break;
                    case FrontendGuardInterval::hidl_discriminator::isdbt:
                        status.set<TunerFrontendStatus::interval>((int)s.interval().isdbt());
                        break;
                    case FrontendGuardInterval::hidl_discriminator::dtmb:
                        status.set<TunerFrontendStatus::interval>((int)s.interval().dtmb());
                        break;
                }
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::transmissionMode: {
                switch (s.transmissionMode().getDiscriminator()) {
                    case FrontendTransmissionMode::hidl_discriminator::dvbt:
                        status.set<TunerFrontendStatus::transmissionMode>(
                                (int)s.transmissionMode().dvbt());
                        break;
                    case FrontendTransmissionMode::hidl_discriminator::isdbt:
                        status.set<TunerFrontendStatus::transmissionMode>(
                                (int)s.transmissionMode().isdbt());
                        break;
                    case FrontendTransmissionMode::hidl_discriminator::dtmb:
                        status.set<TunerFrontendStatus::transmissionMode>(
                                (int)s.transmissionMode().dtmb());
                        break;
                }
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::uec: {
                status.set<TunerFrontendStatus::uec>((int)s.uec());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::systemId: {
                status.set<TunerFrontendStatus::systemId>((char16_t)s.systemId());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::interleaving: {
                vector<int> aidlInter;
                for (auto i : s.interleaving()) {
                    switch (i.getDiscriminator()) {
                        case FrontendInterleaveMode::hidl_discriminator::atsc3:
                            aidlInter.push_back((int)i.atsc3());
                            break;
                        case FrontendInterleaveMode::hidl_discriminator::dvbc:
                            aidlInter.push_back((int)i.dvbc());
                            break;
                        case FrontendInterleaveMode::hidl_discriminator::dtmb:
                            aidlInter.push_back((int)i.dtmb());
                            break;
                    }
                }
                status.set<TunerFrontendStatus::interleaving>(aidlInter);
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::isdbtSegment: {
                auto seg = s.isdbtSegment();
                vector<uint8_t> i(seg.begin(), seg.end());
                status.set<TunerFrontendStatus::isdbtSegment>(i);
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::tsDataRate: {
                vector<int> ts(s.tsDataRate().begin(), s.tsDataRate().end());
                status.set<TunerFrontendStatus::tsDataRate>(ts);
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::rollOff: {
                switch (s.rollOff().getDiscriminator()) {
                    case FrontendRollOff::hidl_discriminator::dvbs:
                        status.set<TunerFrontendStatus::rollOff>((int)s.rollOff().dvbs());
                        break;
                    case FrontendRollOff::hidl_discriminator::isdbs:
                        status.set<TunerFrontendStatus::rollOff>((int)s.rollOff().isdbs());
                        break;
                    case FrontendRollOff::hidl_discriminator::isdbs3:
                        status.set<TunerFrontendStatus::rollOff>((int)s.rollOff().isdbs3());
                        break;
                }
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::isMiso: {
                status.set<TunerFrontendStatus::isMiso>(s.isMiso());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::isLinear: {
                status.set<TunerFrontendStatus::isLinear>(s.isLinear());
                aidlStatus.push_back(status);
                break;
            }
            case FrontendStatusExt1_1::hidl_discriminator::isShortFrames: {
                status.set<TunerFrontendStatus::isShortFrames>(s.isShortFrames());
                aidlStatus.push_back(status);
                break;
            }
        }
    }
}

hidl_vec<FrontendAtsc3PlpSettings> TunerFrontend::getAtsc3PlpSettings(
        const TunerFrontendAtsc3Settings& settings) {
    int len = settings.plpSettings.size();
    hidl_vec<FrontendAtsc3PlpSettings> plps = hidl_vec<FrontendAtsc3PlpSettings>(len);
    // parse PLP settings
    for (int i = 0; i < len; i++) {
        uint8_t plpId = static_cast<uint8_t>(settings.plpSettings[i].plpId);
        FrontendAtsc3Modulation modulation =
                static_cast<FrontendAtsc3Modulation>(settings.plpSettings[i].modulation);
        FrontendAtsc3TimeInterleaveMode interleaveMode =
                static_cast<FrontendAtsc3TimeInterleaveMode>(
                        settings.plpSettings[i].interleaveMode);
        FrontendAtsc3CodeRate codeRate =
                static_cast<FrontendAtsc3CodeRate>(settings.plpSettings[i].codeRate);
        FrontendAtsc3Fec fec =
                static_cast<FrontendAtsc3Fec>(settings.plpSettings[i].fec);
        FrontendAtsc3PlpSettings frontendAtsc3PlpSettings {
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

FrontendDvbsCodeRate TunerFrontend::getDvbsCodeRate(const TunerFrontendDvbsCodeRate& codeRate) {
    FrontendInnerFec innerFec = static_cast<FrontendInnerFec>(codeRate.fec);
    bool isLinear = codeRate.isLinear;
    bool isShortFrames = codeRate.isShortFrames;
    uint32_t bitsPer1000Symbol = static_cast<uint32_t>(codeRate.bitsPer1000Symbol);
    FrontendDvbsCodeRate coderate {
            .fec = innerFec,
            .isLinear = isLinear,
            .isShortFrames = isShortFrames,
            .bitsPer1000Symbol = bitsPer1000Symbol,
    };
    return coderate;
}

FrontendSettings TunerFrontend::getHidlFrontendSettings(const TunerFrontendSettings& aidlSettings) {
    auto settings = aidlSettings.settings;
    FrontendSettings frontendSettings;

    switch (settings.getTag()) {
        case TunerFrontendUnionSettings::analog: {
            auto analog = settings.get<TunerFrontendUnionSettings::analog>();
            frontendSettings.analog({
                .frequency = static_cast<uint32_t>(analog.frequency),
                .type = static_cast<FrontendAnalogType>(analog.signalType),
                .sifStandard = static_cast<FrontendAnalogSifStandard>(analog.sifStandard),
            });
            break;
        }
        case TunerFrontendUnionSettings::atsc: {
            auto atsc = settings.get<TunerFrontendUnionSettings::atsc>();
            frontendSettings.atsc({
                .frequency = static_cast<uint32_t>(atsc.frequency),
                .modulation = static_cast<FrontendAtscModulation>(atsc.modulation),
            });
            break;
        }
        case TunerFrontendUnionSettings::atsc3: {
            auto atsc3 = settings.get<TunerFrontendUnionSettings::atsc3>();
            frontendSettings.atsc3({
                .frequency = static_cast<uint32_t>(atsc3.frequency),
                .bandwidth = static_cast<FrontendAtsc3Bandwidth>(atsc3.bandwidth),
                .demodOutputFormat = static_cast<FrontendAtsc3DemodOutputFormat>(
                        atsc3.demodOutputFormat),
                .plpSettings = getAtsc3PlpSettings(atsc3),
            });
            break;
        }
        case TunerFrontendUnionSettings::cable: {
            auto dvbc = settings.get<TunerFrontendUnionSettings::cable>();
            frontendSettings.dvbc({
                .frequency = static_cast<uint32_t>(dvbc.frequency),
                .modulation = static_cast<FrontendDvbcModulation>(dvbc.modulation),
                .fec = static_cast<FrontendInnerFec>(dvbc.innerFec),
                .symbolRate = static_cast<uint32_t>(dvbc.symbolRate),
                .outerFec = static_cast<FrontendDvbcOuterFec>(dvbc.outerFec),
                .annex = static_cast<FrontendDvbcAnnex>(dvbc.annex),
                .spectralInversion = static_cast<FrontendDvbcSpectralInversion>(
                        dvbc.spectralInversion),
            });
            break;
        }
        case TunerFrontendUnionSettings::dvbs: {
            auto dvbs = settings.get<TunerFrontendUnionSettings::dvbs>();
            frontendSettings.dvbs({
                .frequency = static_cast<uint32_t>(dvbs.frequency),
                .modulation = static_cast<FrontendDvbsModulation>(dvbs.modulation),
                .coderate = getDvbsCodeRate(dvbs.codeRate),
                .symbolRate = static_cast<uint32_t>(dvbs.symbolRate),
                .rolloff = static_cast<FrontendDvbsRolloff>(dvbs.rolloff),
                .pilot = static_cast<FrontendDvbsPilot>(dvbs.pilot),
                .inputStreamId = static_cast<uint32_t>(dvbs.inputStreamId),
                .standard = static_cast<FrontendDvbsStandard>(dvbs.standard),
                .vcmMode = static_cast<FrontendDvbsVcmMode>(dvbs.vcm),
            });
            break;
        }
        case TunerFrontendUnionSettings::dvbt: {
            auto dvbt = settings.get<TunerFrontendUnionSettings::dvbt>();
            frontendSettings.dvbt({
                .frequency = static_cast<uint32_t>(dvbt.frequency),
                .transmissionMode = static_cast<FrontendDvbtTransmissionMode>(
                        dvbt.transmissionMode),
                .bandwidth = static_cast<FrontendDvbtBandwidth>(dvbt.bandwidth),
                .constellation = static_cast<FrontendDvbtConstellation>(dvbt.constellation),
                .hierarchy = static_cast<FrontendDvbtHierarchy>(dvbt.hierarchy),
                .hpCoderate = static_cast<FrontendDvbtCoderate>(dvbt.hpCodeRate),
                .lpCoderate = static_cast<FrontendDvbtCoderate>(dvbt.lpCodeRate),
                .guardInterval = static_cast<FrontendDvbtGuardInterval>(dvbt.guardInterval),
                .isHighPriority = dvbt.isHighPriority,
                .standard = static_cast<FrontendDvbtStandard>(dvbt.standard),
                .isMiso = dvbt.isMiso,
                .plpMode = static_cast<FrontendDvbtPlpMode>(dvbt.plpMode),
                .plpId = static_cast<uint8_t>(dvbt.plpId),
                .plpGroupId = static_cast<uint8_t>(dvbt.plpGroupId),
            });
            break;
        }
        case TunerFrontendUnionSettings::isdbs: {
            auto isdbs = settings.get<TunerFrontendUnionSettings::isdbs>();
            frontendSettings.isdbs({
                .frequency = static_cast<uint32_t>(isdbs.frequency),
                .streamId = static_cast<uint16_t>(isdbs.streamId),
                .streamIdType = static_cast<FrontendIsdbsStreamIdType>(isdbs.streamIdType),
                .modulation = static_cast<FrontendIsdbsModulation>(isdbs.modulation),
                .coderate = static_cast<FrontendIsdbsCoderate>(isdbs.codeRate),
                .symbolRate = static_cast<uint32_t>(isdbs.symbolRate),
                .rolloff = static_cast<FrontendIsdbsRolloff>(isdbs.rolloff),
            });
            break;
        }
        case TunerFrontendUnionSettings::isdbs3: {
            auto isdbs3 = settings.get<TunerFrontendUnionSettings::isdbs3>();
            frontendSettings.isdbs3({
                .frequency = static_cast<uint32_t>(isdbs3.frequency),
                .streamId = static_cast<uint16_t>(isdbs3.streamId),
                .streamIdType = static_cast<FrontendIsdbsStreamIdType>(isdbs3.streamIdType),
                .modulation = static_cast<FrontendIsdbs3Modulation>(isdbs3.modulation),
                .coderate = static_cast<FrontendIsdbs3Coderate>(isdbs3.codeRate),
                .symbolRate = static_cast<uint32_t>(isdbs3.symbolRate),
                .rolloff = static_cast<FrontendIsdbs3Rolloff>(isdbs3.rolloff),
            });
            break;
        }
        case TunerFrontendUnionSettings::isdbt: {
            auto isdbt = settings.get<TunerFrontendUnionSettings::isdbt>();
            frontendSettings.isdbt({
                .frequency = static_cast<uint32_t>(isdbt.frequency),
                .modulation = static_cast<FrontendIsdbtModulation>(isdbt.modulation),
                .bandwidth = static_cast<FrontendIsdbtBandwidth>(isdbt.bandwidth),
                .mode = static_cast<FrontendIsdbtMode>(isdbt.mode),
                .coderate = static_cast<FrontendIsdbtCoderate>(isdbt.codeRate),
                .guardInterval = static_cast<FrontendIsdbtGuardInterval>(isdbt.guardInterval),
                .serviceAreaId = static_cast<uint32_t>(isdbt.serviceAreaId),
            });
            break;
        }
        default:
            break;
    }

    return frontendSettings;
}

FrontendSettingsExt1_1 TunerFrontend::getHidlFrontendSettingsExt(
        const TunerFrontendSettings& aidlSettings) {
    FrontendSettingsExt1_1 frontendSettingsExt{
        .endFrequency = static_cast<uint32_t>(aidlSettings.endFrequency),
        .inversion = static_cast<FrontendSpectralInversion>(aidlSettings.inversion),
    };

    auto settings = aidlSettings.settings;
    switch (settings.getTag()) {
        case TunerFrontendUnionSettings::analog: {
            auto analog = settings.get<TunerFrontendUnionSettings::analog>();
            if (analog.isExtended) {
                frontendSettingsExt.settingExt.analog({
                    .aftFlag = static_cast<FrontendAnalogAftFlag>(analog.aftFlag),
                });
            } else {
                frontendSettingsExt.settingExt.noinit();
            }
            break;
        }
        case TunerFrontendUnionSettings::cable: {
            auto dvbc = settings.get<TunerFrontendUnionSettings::cable>();
            if (dvbc.isExtended) {
                frontendSettingsExt.settingExt.dvbc({
                    .interleaveMode = static_cast<FrontendCableTimeInterleaveMode>(
                            dvbc.interleaveMode),
                    .bandwidth = static_cast<FrontendDvbcBandwidth>(
                            dvbc.bandwidth),
                });
            } else {
                frontendSettingsExt.settingExt.noinit();
            }
            break;
        }
        case TunerFrontendUnionSettings::dvbs: {
            auto dvbs = settings.get<TunerFrontendUnionSettings::dvbs>();
            if (dvbs.isExtended) {
                frontendSettingsExt.settingExt.dvbs({
                    .scanType = static_cast<FrontendDvbsScanType>(dvbs.scanType),
                    .isDiseqcRxMessage = dvbs.isDiseqcRxMessage,
                });
            } else {
                frontendSettingsExt.settingExt.noinit();
            }
            break;
        }
        case TunerFrontendUnionSettings::dvbt: {
            auto dvbt = settings.get<TunerFrontendUnionSettings::dvbt>();
            if (dvbt.isExtended) {
                frontendSettingsExt.settingExt.dvbt({
                    .constellation =
                            static_cast<hardware::tv::tuner::V1_1::FrontendDvbtConstellation>(
                                    dvbt.constellation),
                    .transmissionMode =
                            static_cast<hardware::tv::tuner::V1_1::FrontendDvbtTransmissionMode>(
                                    dvbt.transmissionMode),
                });
            } else {
                frontendSettingsExt.settingExt.noinit();
            }
            break;
        }
        case TunerFrontendUnionSettings::dtmb: {
            auto dtmb = settings.get<TunerFrontendUnionSettings::dtmb>();
            frontendSettingsExt.settingExt.dtmb({
                .frequency = static_cast<uint32_t>(dtmb.frequency),
                .transmissionMode = static_cast<FrontendDtmbTransmissionMode>(
                        dtmb.transmissionMode),
                .bandwidth = static_cast<FrontendDtmbBandwidth>(dtmb.bandwidth),
                .modulation = static_cast<FrontendDtmbModulation>(dtmb.modulation),
                .codeRate = static_cast<FrontendDtmbCodeRate>(dtmb.codeRate),
                .guardInterval = static_cast<FrontendDtmbGuardInterval>(dtmb.guardInterval),
                .interleaveMode = static_cast<FrontendDtmbTimeInterleaveMode>(dtmb.interleaveMode),
            });
            break;
        }
        default:
            frontendSettingsExt.settingExt.noinit();
            break;
    }

    return frontendSettingsExt;
}
}  // namespace android
