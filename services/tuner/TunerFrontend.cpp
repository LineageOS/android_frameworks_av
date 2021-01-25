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

using ::aidl::android::media::tv::tuner::TunerFrontendAtsc3PlpSettings;
using ::aidl::android::media::tv::tuner::TunerFrontendScanAtsc3PlpInfo;
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
using ::android::hardware::tv::tuner::V1_0::FrontendScanAtsc3PlpInfo;
using ::android::hardware::tv::tuner::V1_0::FrontendScanType;
using ::android::hardware::tv::tuner::V1_0::FrontendSettings;;
using ::android::hardware::tv::tuner::V1_0::Result;
using ::android::hardware::tv::tuner::V1_1::FrontendModulation;

namespace android {

TunerFrontend::TunerFrontend(sp<IFrontend> frontend, int id) {
    mFrontend = frontend;
    mFrontend_1_1 = ::android::hardware::tv::tuner::V1_1::IFrontend::castFrom(mFrontend);
    mId = id;
}

TunerFrontend::~TunerFrontend() {
    mFrontend = NULL;
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

Status TunerFrontend::tune(const TunerFrontendSettings& /*settings*/) {
    return Status::ok();
}

Status TunerFrontend::stopTune() {
    return Status::ok();
}

Status TunerFrontend::scan(const TunerFrontendSettings& settings, int frontendScanType) {
    if (mFrontend == NULL) {
        ALOGD("IFrontend is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    // TODO: extend TunerFrontendSettings to use 1.1 types
    FrontendSettings frontendSettings;
    switch (settings.getTag()) {
        case TunerFrontendSettings::analog:
            frontendSettings.analog({
                .frequency = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::analog>().frequency),
                .type = static_cast<FrontendAnalogType>(
                        settings.get<TunerFrontendSettings::analog>().signalType),
                .sifStandard = static_cast<FrontendAnalogSifStandard>(
                        settings.get<TunerFrontendSettings::analog>().sifStandard),
            });
            break;
        case TunerFrontendSettings::atsc:
            frontendSettings.atsc({
                .frequency = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::atsc>().frequency),
                .modulation = static_cast<FrontendAtscModulation>(
                        settings.get<TunerFrontendSettings::atsc>().modulation),
            });
            break;
        case TunerFrontendSettings::atsc3:
            frontendSettings.atsc3({
                .frequency = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::atsc3>().frequency),
                .bandwidth = static_cast<FrontendAtsc3Bandwidth>(
                        settings.get<TunerFrontendSettings::atsc3>().bandwidth),
                .demodOutputFormat = static_cast<FrontendAtsc3DemodOutputFormat>(
                        settings.get<TunerFrontendSettings::atsc3>().demodOutputFormat),
                .plpSettings = getAtsc3PlpSettings(settings.get<TunerFrontendSettings::atsc3>()),
            });
            break;
        case TunerFrontendSettings::cable:
            frontendSettings.dvbc({
                .frequency = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::cable>().frequency),
                .modulation = static_cast<FrontendDvbcModulation>(
                        settings.get<TunerFrontendSettings::cable>().modulation),
                .fec = static_cast<FrontendInnerFec>(
                        settings.get<TunerFrontendSettings::cable>().innerFec),
                .symbolRate = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::cable>().symbolRate),
                .outerFec = static_cast<FrontendDvbcOuterFec>(
                        settings.get<TunerFrontendSettings::cable>().outerFec),
                .annex = static_cast<FrontendDvbcAnnex>(
                        settings.get<TunerFrontendSettings::cable>().annex),
                .spectralInversion = static_cast<FrontendDvbcSpectralInversion>(
                        settings.get<TunerFrontendSettings::cable>().spectralInversion),
            });
            break;
        case TunerFrontendSettings::dvbs:
            frontendSettings.dvbs({
                .frequency = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::dvbs>().frequency),
                .modulation = static_cast<FrontendDvbsModulation>(
                        settings.get<TunerFrontendSettings::dvbs>().modulation),
                .coderate = getDvbsCodeRate(
                        settings.get<TunerFrontendSettings::dvbs>().codeRate),
                .symbolRate = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::dvbs>().symbolRate),
                .rolloff = static_cast<FrontendDvbsRolloff>(
                        settings.get<TunerFrontendSettings::dvbs>().rolloff),
                .pilot = static_cast<FrontendDvbsPilot>(
                        settings.get<TunerFrontendSettings::dvbs>().pilot),
                .inputStreamId = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::dvbs>().inputStreamId),
                .standard = static_cast<FrontendDvbsStandard>(
                        settings.get<TunerFrontendSettings::dvbs>().standard),
                .vcmMode = static_cast<FrontendDvbsVcmMode>(
                        settings.get<TunerFrontendSettings::dvbs>().vcm),
            });
            break;
        case TunerFrontendSettings::dvbt:
            frontendSettings.dvbt({
                .frequency = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::dvbt>().frequency),
                .transmissionMode = static_cast<FrontendDvbtTransmissionMode>(
                        settings.get<TunerFrontendSettings::dvbt>().transmissionMode),
                .bandwidth = static_cast<FrontendDvbtBandwidth>(
                        settings.get<TunerFrontendSettings::dvbt>().bandwidth),
                .constellation = static_cast<FrontendDvbtConstellation>(
                        settings.get<TunerFrontendSettings::dvbt>().constellation),
                .hierarchy = static_cast<FrontendDvbtHierarchy>(
                        settings.get<TunerFrontendSettings::dvbt>().hierarchy),
                .hpCoderate = static_cast<FrontendDvbtCoderate>(
                        settings.get<TunerFrontendSettings::dvbt>().hpCodeRate),
                .lpCoderate = static_cast<FrontendDvbtCoderate>(
                        settings.get<TunerFrontendSettings::dvbt>().lpCodeRate),
                .guardInterval = static_cast<FrontendDvbtGuardInterval>(
                        settings.get<TunerFrontendSettings::dvbt>().guardInterval),
                .isHighPriority = settings.get<TunerFrontendSettings::dvbt>().isHighPriority,
                .standard = static_cast<FrontendDvbtStandard>(
                        settings.get<TunerFrontendSettings::dvbt>().standard),
                .isMiso = settings.get<TunerFrontendSettings::dvbt>().isMiso,
                .plpMode = static_cast<FrontendDvbtPlpMode>(
                        settings.get<TunerFrontendSettings::dvbt>().plpMode),
                .plpId = static_cast<uint8_t>(
                        settings.get<TunerFrontendSettings::dvbt>().plpId),
                .plpGroupId = static_cast<uint8_t>(
                        settings.get<TunerFrontendSettings::dvbt>().plpGroupId),
            });
            break;
        case TunerFrontendSettings::isdbs:
            frontendSettings.isdbs({
                .frequency = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::isdbs>().frequency),
                .streamId = static_cast<uint16_t>(
                        settings.get<TunerFrontendSettings::isdbs>().streamId),
                .streamIdType = static_cast<FrontendIsdbsStreamIdType>(
                        settings.get<TunerFrontendSettings::isdbs>().streamIdType),
                .modulation = static_cast<FrontendIsdbsModulation>(
                        settings.get<TunerFrontendSettings::isdbs>().modulation),
                .coderate = static_cast<FrontendIsdbsCoderate>(
                        settings.get<TunerFrontendSettings::isdbs>().codeRate),
                .symbolRate = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::isdbs>().symbolRate),
                .rolloff = static_cast<FrontendIsdbsRolloff>(
                        settings.get<TunerFrontendSettings::isdbs>().rolloff),
            });
            break;
        case TunerFrontendSettings::isdbs3:
            frontendSettings.isdbs3({
                .frequency = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::isdbs3>().frequency),
                .streamId = static_cast<uint16_t>(
                        settings.get<TunerFrontendSettings::isdbs3>().streamId),
                .streamIdType = static_cast<FrontendIsdbsStreamIdType>(
                        settings.get<TunerFrontendSettings::isdbs3>().streamIdType),
                .modulation = static_cast<FrontendIsdbs3Modulation>(
                        settings.get<TunerFrontendSettings::isdbs3>().modulation),
                .coderate = static_cast<FrontendIsdbs3Coderate>(
                        settings.get<TunerFrontendSettings::isdbs3>().codeRate),
                .symbolRate = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::isdbs3>().symbolRate),
                .rolloff = static_cast<FrontendIsdbs3Rolloff>(
                        settings.get<TunerFrontendSettings::isdbs3>().rolloff),
            });
            break;
        case TunerFrontendSettings::isdbt:
            frontendSettings.isdbt({
                .frequency = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::isdbt>().frequency),
                .modulation = static_cast<FrontendIsdbtModulation>(
                        settings.get<TunerFrontendSettings::isdbt>().modulation),
                .bandwidth = static_cast<FrontendIsdbtBandwidth>(
                        settings.get<TunerFrontendSettings::isdbt>().bandwidth),
                .mode = static_cast<FrontendIsdbtMode>(
                        settings.get<TunerFrontendSettings::isdbt>().mode),
                .coderate = static_cast<FrontendIsdbtCoderate>(
                        settings.get<TunerFrontendSettings::isdbt>().codeRate),
                .guardInterval = static_cast<FrontendIsdbtGuardInterval>(
                        settings.get<TunerFrontendSettings::isdbt>().guardInterval),
                .serviceAreaId = static_cast<uint32_t>(
                        settings.get<TunerFrontendSettings::isdbt>().serviceAreaId),
            });
            break;
        default:
            break;
    }
    Result status = mFrontend->scan(
            frontendSettings, static_cast<FrontendScanType>(frontendScanType));
    if (status == Result::SUCCESS) {
        return Status::ok();
    }

    return Status::fromServiceSpecificError(static_cast<int32_t>(status));
}

Status TunerFrontend::stopScan() {
    return Status::ok();
}

Status TunerFrontend::setLnb(int /*lnbHandle*/) {
    return Status::ok();
}

Status TunerFrontend::setLna(bool /*bEnable*/) {
    return Status::ok();
}

Status TunerFrontend::close() {
    return Status::ok();
}

Status TunerFrontend::getStatus(const vector<int32_t>& /*statusTypes*/,
        vector<TunerFrontendStatus>* /*_aidl_return*/) {
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
                int plpId = (int) info.plpId;
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
            if (m.getDiscriminator() == FrontendModulation::hidl_discriminator::dvbc) {
                modulation = (int) m.dvbc();
            } else if (m.getDiscriminator() == FrontendModulation::hidl_discriminator::dvbt) {
                modulation = (int) m.dvbt();
            } else if (m.getDiscriminator() == FrontendModulation::hidl_discriminator::dvbs) {
                modulation = (int) m.dvbs();
            } else if (m.getDiscriminator() == FrontendModulation::hidl_discriminator::isdbs) {
                modulation = (int) m.isdbs();
            } else if (m.getDiscriminator() == FrontendModulation::hidl_discriminator::isdbs3) {
                modulation = (int) m.isdbs3();
            } else if (m.getDiscriminator() == FrontendModulation::hidl_discriminator::isdbt) {
                modulation = (int) m.isdbt();
            } else if (m.getDiscriminator() == FrontendModulation::hidl_discriminator::atsc) {
                modulation = (int) m.atsc();
            } else if (m.getDiscriminator() == FrontendModulation::hidl_discriminator::atsc3) {
                modulation = (int) m.atsc3();
            } else if (m.getDiscriminator() == FrontendModulation::hidl_discriminator::dtmb) {
                modulation = (int) m.dtmb();
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
}  // namespace android
