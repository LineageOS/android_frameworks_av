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

#define LOG_TAG "TunerFilter"

#include "TunerFilter.h"

using ::aidl::android::media::tv::tuner::TunerFilterSectionCondition;

using ::android::hardware::hidl_handle;
using ::android::hardware::tv::tuner::V1_0::DemuxAlpLengthType;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterMainType;
using ::android::hardware::tv::tuner::V1_0::DemuxIpAddress;
using ::android::hardware::tv::tuner::V1_0::DemuxMmtpFilterType;
using ::android::hardware::tv::tuner::V1_0::DemuxMmtpPid;
using ::android::hardware::tv::tuner::V1_0::DemuxRecordScIndexType;
using ::android::hardware::tv::tuner::V1_0::DemuxStreamId;
using ::android::hardware::tv::tuner::V1_0::DemuxTsFilterType;
using ::android::hardware::tv::tuner::V1_0::Result;
using ::android::hardware::tv::tuner::V1_1::AudioStreamType;
using ::android::hardware::tv::tuner::V1_1::Constant;
using ::android::hardware::tv::tuner::V1_1::VideoStreamType;

namespace android {

using namespace std;

TunerFilter::TunerFilter(
        sp<IFilter> filter, int mainType, int subType) {
    mFilter = filter;
    mFilter_1_1 = ::android::hardware::tv::tuner::V1_1::IFilter::castFrom(filter);
    mMainType = mainType;
    mSubType = subType;
}

TunerFilter::~TunerFilter() {
    mFilter = nullptr;
    mFilter_1_1 = nullptr;
}

Status TunerFilter::getQueueDesc(AidlMQDesc* _aidl_return) {
    if (mFilter == NULL) {
        ALOGE("IFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    MQDesc filterMQDesc;
    Result res;
    mFilter->getQueueDesc([&](Result r, const MQDesc& desc) {
        filterMQDesc = desc;
        res = r;
    });
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    AidlMQDesc aidlMQDesc;
    unsafeHidlToAidlMQDescriptor<uint8_t, int8_t, SynchronizedReadWrite>(
                filterMQDesc,  &aidlMQDesc);
    *_aidl_return = move(aidlMQDesc);
    return Status::ok();
}

Status TunerFilter::getId(int32_t* _aidl_return) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res;
    mFilter->getId([&](Result r, uint32_t filterId) {
        res = r;
        mId = filterId;
    });
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    *_aidl_return = mId;
    return Status::ok();
}

Status TunerFilter::getId64Bit(int64_t* _aidl_return) {
    if (mFilter_1_1 == nullptr) {
        ALOGE("IFilter_1_1 is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res;
    mFilter_1_1->getId64Bit([&](Result r, uint64_t filterId) {
        res = r;
        mId64Bit = filterId;
    });
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    *_aidl_return = mId64Bit;
    return Status::ok();
}

Status TunerFilter::configure(const TunerFilterConfiguration& config) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    DemuxFilterSettings settings;
    switch (config.getTag()) {
        case TunerFilterConfiguration::ts: {
            getHidlTsSettings(config, settings);
            break;
        }
        case TunerFilterConfiguration::mmtp: {
            getHidlMmtpSettings(config, settings);
            break;
        }
        case TunerFilterConfiguration::ip: {
            getHidlIpSettings(config, settings);
            break;
        }
        case TunerFilterConfiguration::tlv: {
            getHidlTlvSettings(config, settings);
            break;
        }
        case TunerFilterConfiguration::alp: {
            getHidlAlpSettings(config, settings);
            break;
        }
    }

    Result res = mFilter->configure(settings);
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerFilter::configureMonitorEvent(int monitorEventType) {
    if (mFilter_1_1 == nullptr) {
        ALOGE("IFilter_1_1 is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mFilter_1_1->configureMonitorEvent(monitorEventType);
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerFilter::configureIpFilterContextId(int cid) {
    if (mFilter_1_1 == nullptr) {
        ALOGE("IFilter_1_1 is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mFilter_1_1->configureIpCid(cid);
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerFilter::configureAvStreamType(int avStreamType) {
    if (mFilter_1_1 == nullptr) {
        ALOGE("IFilter_1_1 is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    AvStreamType type;
    if (!getHidlAvStreamType(avStreamType, type)) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::INVALID_STATE));
    }

    Result res = mFilter_1_1->configureAvStreamType(type);
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerFilter::setDataSource(const shared_ptr<ITunerFilter>& filter) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    ITunerFilter* tunerFilter = filter.get();
    sp<IFilter> hidlFilter = static_cast<TunerFilter*>(tunerFilter)->getHalFilter();
    Result res = mFilter->setDataSource(hidlFilter);
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

void TunerFilter::getHidlTsSettings(
        const TunerFilterConfiguration& config, DemuxFilterSettings& settings) {
    auto tsConf = config.get<TunerFilterConfiguration::ts>();
    DemuxTsFilterSettings ts{
        .tpid = static_cast<uint16_t>(tsConf.tpid),
    };

    TunerFilterSettings tunerSettings = tsConf.filterSettings;
    switch (tunerSettings.getTag()) {
        case TunerFilterSettings::av: {
            ts.filterSettings.av(getAvSettings(tunerSettings));
            break;
        }
        case TunerFilterSettings::section: {
            ts.filterSettings.section(getSectionSettings(tunerSettings));
            break;
        }
        case TunerFilterSettings::pesData: {
            ts.filterSettings.pesData(getPesDataSettings(tunerSettings));
            break;
        }
        case TunerFilterSettings::record: {
            ts.filterSettings.record(getRecordSettings(tunerSettings));
            break;
        }
        default: {
            ts.filterSettings.noinit();
            break;
        }
    }
    settings.ts(ts);
}

void TunerFilter::getHidlMmtpSettings(
        const TunerFilterConfiguration& config, DemuxFilterSettings& settings) {
    auto mmtpConf = config.get<TunerFilterConfiguration::mmtp>();
    DemuxMmtpFilterSettings mmtp{
        .mmtpPid = static_cast<DemuxMmtpPid>(mmtpConf.mmtpPid),
    };

    TunerFilterSettings tunerSettings = mmtpConf.filterSettings;
    switch (tunerSettings.getTag()) {
        case TunerFilterSettings::av: {
            mmtp.filterSettings.av(getAvSettings(tunerSettings));
            break;
        }
        case TunerFilterSettings::section: {
            mmtp.filterSettings.section(getSectionSettings(tunerSettings));
            break;
        }
        case TunerFilterSettings::pesData: {
            mmtp.filterSettings.pesData(getPesDataSettings(tunerSettings));
            break;
        }
        case TunerFilterSettings::record: {
            mmtp.filterSettings.record(getRecordSettings(tunerSettings));
            break;
        }
        case TunerFilterSettings::download: {
            mmtp.filterSettings.download(getDownloadSettings(tunerSettings));
            break;
        }
        default: {
            mmtp.filterSettings.noinit();
            break;
        }
    }
    settings.mmtp(mmtp);
}

void TunerFilter::getHidlIpSettings(
        const TunerFilterConfiguration& config, DemuxFilterSettings& settings) {
    auto ipConf = config.get<TunerFilterConfiguration::ip>();
    DemuxIpAddress ipAddr{
        .srcPort = static_cast<uint16_t>(ipConf.ipAddr.srcPort),
        .dstPort = static_cast<uint16_t>(ipConf.ipAddr.dstPort),
    };

    ipConf.ipAddr.srcIpAddress.isIpV6
            ? ipAddr.srcIpAddress.v6(getIpV6Address(ipConf.ipAddr.srcIpAddress))
            : ipAddr.srcIpAddress.v4(getIpV4Address(ipConf.ipAddr.srcIpAddress));
    ipConf.ipAddr.dstIpAddress.isIpV6
            ? ipAddr.dstIpAddress.v6(getIpV6Address(ipConf.ipAddr.dstIpAddress))
            : ipAddr.dstIpAddress.v4(getIpV4Address(ipConf.ipAddr.dstIpAddress));
    DemuxIpFilterSettings ip{
        .ipAddr = ipAddr,
    };

    TunerFilterSettings tunerSettings = ipConf.filterSettings;
    switch (tunerSettings.getTag()) {
        case TunerFilterSettings::section: {
            ip.filterSettings.section(getSectionSettings(tunerSettings));
            break;
        }
        case TunerFilterSettings::isPassthrough: {
            ip.filterSettings.bPassthrough(tunerSettings.get<TunerFilterSettings::isPassthrough>());
            break;
        }
        default: {
            ip.filterSettings.noinit();
            break;
        }
    }
    settings.ip(ip);
}

hidl_array<uint8_t, IP_V6_LENGTH> TunerFilter::getIpV6Address(TunerDemuxIpAddress addr) {
    hidl_array<uint8_t, IP_V6_LENGTH> ip;
    if (addr.addr.size() != IP_V6_LENGTH) {
        return ip;
    }
    copy(addr.addr.begin(), addr.addr.end(), ip.data());
    return ip;
}

hidl_array<uint8_t, IP_V4_LENGTH> TunerFilter::getIpV4Address(TunerDemuxIpAddress addr) {
    hidl_array<uint8_t, IP_V4_LENGTH> ip;
    if (addr.addr.size() != IP_V4_LENGTH) {
        return ip;
    }
    copy(addr.addr.begin(), addr.addr.end(), ip.data());
    return ip;
}

void TunerFilter::getHidlTlvSettings(
        const TunerFilterConfiguration& config, DemuxFilterSettings& settings) {
    auto tlvConf = config.get<TunerFilterConfiguration::tlv>();
    DemuxTlvFilterSettings tlv{
        .packetType = static_cast<uint8_t>(tlvConf.packetType),
        .isCompressedIpPacket = tlvConf.isCompressedIpPacket,
    };

    TunerFilterSettings tunerSettings = tlvConf.filterSettings;
    switch (tunerSettings.getTag()) {
        case TunerFilterSettings::section: {
            tlv.filterSettings.section(getSectionSettings(tunerSettings));
            break;
        }
        case TunerFilterSettings::isPassthrough: {
            tlv.filterSettings.bPassthrough(
                    tunerSettings.get<TunerFilterSettings::isPassthrough>());
            break;
        }
        default: {
            tlv.filterSettings.noinit();
            break;
        }
    }
    settings.tlv(tlv);
}

void TunerFilter::getHidlAlpSettings(
        const TunerFilterConfiguration& config, DemuxFilterSettings& settings) {
    auto alpConf = config.get<TunerFilterConfiguration::alp>();
    DemuxAlpFilterSettings alp{
        .packetType = static_cast<uint8_t>(alpConf.packetType),
        .lengthType = static_cast<DemuxAlpLengthType>(alpConf.lengthType),
    };

    TunerFilterSettings tunerSettings = alpConf.filterSettings;
    switch (tunerSettings.getTag()) {
        case TunerFilterSettings::section: {
            alp.filterSettings.section(getSectionSettings(tunerSettings));
            break;
        }
        default: {
            alp.filterSettings.noinit();
            break;
        }
    }
    settings.alp(alp);
}

DemuxFilterAvSettings TunerFilter::getAvSettings(const TunerFilterSettings& settings) {
    DemuxFilterAvSettings av {
        .isPassthrough = settings.get<TunerFilterSettings::av>().isPassthrough,
    };
    return av;
}

DemuxFilterSectionSettings TunerFilter::getSectionSettings(const TunerFilterSettings& settings) {
    auto s = settings.get<TunerFilterSettings::section>();
    DemuxFilterSectionSettings section{
        .isCheckCrc = s.isCheckCrc,
        .isRepeat = s.isRepeat,
        .isRaw = s.isRaw,
    };

    switch (s.condition.getTag()) {
        case TunerFilterSectionCondition::sectionBits: {
            auto sectionBits = s.condition.get<TunerFilterSectionCondition::sectionBits>();
            vector<uint8_t> filter(sectionBits.filter.begin(), sectionBits.filter.end());
            vector<uint8_t> mask(sectionBits.mask.begin(), sectionBits.mask.end());
            vector<uint8_t> mode(sectionBits.mode.begin(), sectionBits.mode.end());
            section.condition.sectionBits({
                .filter = filter,
                .mask = mask,
                .mode = mode,
            });
            break;
        }
        case TunerFilterSectionCondition::tableInfo: {
            auto tableInfo = s.condition.get<TunerFilterSectionCondition::tableInfo>();
            section.condition.tableInfo({
                .tableId = static_cast<uint16_t>(tableInfo.tableId),
                .version = static_cast<uint16_t>(tableInfo.version),
            });
            break;
        }
        default: {
            break;
        }
    }
    return section;
}

DemuxFilterPesDataSettings TunerFilter::getPesDataSettings(const TunerFilterSettings& settings) {
    DemuxFilterPesDataSettings pes{
        .streamId = static_cast<DemuxStreamId>(
                settings.get<TunerFilterSettings::pesData>().streamId),
        .isRaw = settings.get<TunerFilterSettings::pesData>().isRaw,
    };
    return pes;
}

DemuxFilterRecordSettings TunerFilter::getRecordSettings(const TunerFilterSettings& settings) {
    auto r = settings.get<TunerFilterSettings::record>();
    DemuxFilterRecordSettings record{
        .tsIndexMask = static_cast<uint32_t>(r.tsIndexMask),
        .scIndexType = static_cast<DemuxRecordScIndexType>(r.scIndexType),
    };

    switch (r.scIndexMask.getTag()) {
        case TunerFilterScIndexMask::sc: {
            record.scIndexMask.sc(static_cast<uint32_t>(
                    r.scIndexMask.get<TunerFilterScIndexMask::sc>()));
            break;
        }
        case TunerFilterScIndexMask::scHevc: {
            record.scIndexMask.scHevc(static_cast<uint32_t>(
                    r.scIndexMask.get<TunerFilterScIndexMask::scHevc>()));
            break;
        }
    }
    return record;
}

DemuxFilterDownloadSettings TunerFilter::getDownloadSettings(const TunerFilterSettings& settings) {
    DemuxFilterDownloadSettings download {
        .downloadId = static_cast<uint32_t>(
                settings.get<TunerFilterSettings::download>().downloadId),
    };
    return download;
}

Status TunerFilter::getAvSharedHandleInfo(TunerFilterSharedHandleInfo* _aidl_return) {
    if (mFilter_1_1 == nullptr) {
        ALOGE("IFilter_1_1 is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res;
    mFilter_1_1->getAvSharedHandle([&](Result r, hidl_handle avMemory, uint64_t avMemSize) {
        res = r;
        if (res == Result::SUCCESS) {
            TunerFilterSharedHandleInfo info{
                .handle = dupToAidl(avMemory),
                .size = static_cast<int64_t>(avMemSize),
            };
            *_aidl_return = move(info);
        } else {
            _aidl_return = NULL;
        }
    });

    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerFilter::releaseAvHandle(
        const ::aidl::android::hardware::common::NativeHandle& handle, int64_t avDataId) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mFilter->releaseAvHandle(hidl_handle(makeFromAidl(handle)), avDataId);
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerFilter::start() {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }
    Result res = mFilter->start();
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerFilter::stop() {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }
    Result res = mFilter->stop();
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerFilter::flush() {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }
    Result res = mFilter->flush();
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerFilter::close() {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }
    Result res = mFilter->close();
    mFilter = NULL;
    mFilter_1_1 = NULL;

    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

sp<IFilter> TunerFilter::getHalFilter() {
    return mFilter;
}

bool TunerFilter::isAudioFilter() {
    return (mMainType == (int)DemuxFilterMainType::TS
                    && mSubType == (int)DemuxTsFilterType::AUDIO)
            || (mMainType == (int)DemuxFilterMainType::MMTP
                    && mSubType == (int)DemuxMmtpFilterType::AUDIO);
}

bool TunerFilter::isVideoFilter() {
    return (mMainType == (int)DemuxFilterMainType::TS
                    && mSubType == (int)DemuxTsFilterType::VIDEO)
            || (mMainType == (int)DemuxFilterMainType::MMTP
                    && mSubType == (int)DemuxMmtpFilterType::VIDEO);
}

bool TunerFilter::getHidlAvStreamType(int avStreamType, AvStreamType& type) {
    if (isAudioFilter()) {
        type.audio(static_cast<AudioStreamType>(avStreamType));
        return true;
    }

    if (isVideoFilter()) {
        type.video(static_cast<VideoStreamType>(avStreamType));
        return true;
    }

    return false;
}

/////////////// FilterCallback ///////////////////////

Return<void> TunerFilter::FilterCallback::onFilterStatus(DemuxFilterStatus status) {
    if (mTunerFilterCallback != NULL) {
        mTunerFilterCallback->onFilterStatus((int)status);
    }
    return Void();
}

Return<void> TunerFilter::FilterCallback::onFilterEvent(const DemuxFilterEvent& filterEvent) {
    vector<DemuxFilterEventExt::Event> emptyEventsExt;
    DemuxFilterEventExt emptyFilterEventExt {
            .events = emptyEventsExt,
    };
    onFilterEvent_1_1(filterEvent, emptyFilterEventExt);
    return Void();
}

Return<void> TunerFilter::FilterCallback::onFilterEvent_1_1(const DemuxFilterEvent& filterEvent,
        const DemuxFilterEventExt& filterEventExt) {
    if (mTunerFilterCallback != NULL) {
        vector<DemuxFilterEvent::Event> events = filterEvent.events;
        vector<DemuxFilterEventExt::Event> eventsExt = filterEventExt.events;
        vector<TunerFilterEvent> tunerEvent;

        getAidlFilterEvent(events, eventsExt, tunerEvent);
        mTunerFilterCallback->onFilterEvent(tunerEvent);
    }
    return Void();
}

/////////////// FilterCallback Helper Methods ///////////////////////

void TunerFilter::FilterCallback::getAidlFilterEvent(vector<DemuxFilterEvent::Event>& events,
        vector<DemuxFilterEventExt::Event>& eventsExt,
        vector<TunerFilterEvent>& tunerEvent) {
    if (events.empty() && !eventsExt.empty()) {
        auto eventExt = eventsExt[0];
        switch (eventExt.getDiscriminator()) {
            case DemuxFilterEventExt::Event::hidl_discriminator::monitorEvent: {
                getMonitorEvent(eventsExt, tunerEvent);
                return;
            }
            case DemuxFilterEventExt::Event::hidl_discriminator::startId: {
                getRestartEvent(eventsExt, tunerEvent);
                return;
            }
            default: {
                break;
            }
        }
        return;
    }

    if (!events.empty()) {
        auto event = events[0];
        switch (event.getDiscriminator()) {
            case DemuxFilterEvent::Event::hidl_discriminator::media: {
                getMediaEvent(events, tunerEvent);
                break;
            }
            case DemuxFilterEvent::Event::hidl_discriminator::section: {
                getSectionEvent(events, tunerEvent);
                break;
            }
            case DemuxFilterEvent::Event::hidl_discriminator::pes: {
                getPesEvent(events, tunerEvent);
                break;
            }
            case DemuxFilterEvent::Event::hidl_discriminator::tsRecord: {
                getTsRecordEvent(events, eventsExt, tunerEvent);
                break;
            }
            case DemuxFilterEvent::Event::hidl_discriminator::mmtpRecord: {
                getMmtpRecordEvent(events, eventsExt, tunerEvent);
                break;
            }
            case DemuxFilterEvent::Event::hidl_discriminator::download: {
                getDownloadEvent(events, tunerEvent);
                break;
            }
            case DemuxFilterEvent::Event::hidl_discriminator::ipPayload: {
                getIpPayloadEvent(events, tunerEvent);
                break;
            }
            case DemuxFilterEvent::Event::hidl_discriminator::temi: {
                getTemiEvent(events, tunerEvent);
                break;
            }
            default: {
                break;
            }
        }
    }
}

void TunerFilter::FilterCallback::getMediaEvent(
        vector<DemuxFilterEvent::Event>& events, vector<TunerFilterEvent>& res) {
    for (DemuxFilterEvent::Event e : events) {
        DemuxFilterMediaEvent mediaEvent = e.media();
        TunerFilterMediaEvent tunerMedia;

        tunerMedia.streamId = static_cast<char16_t>(mediaEvent.streamId);
        tunerMedia.isPtsPresent = mediaEvent.isPtsPresent;
        tunerMedia.pts = static_cast<long>(mediaEvent.pts);
        tunerMedia.dataLength = static_cast<int>(mediaEvent.dataLength);
        tunerMedia.offset = static_cast<int>(mediaEvent.offset);
        tunerMedia.isSecureMemory = mediaEvent.isSecureMemory;
        tunerMedia.avDataId = static_cast<long>(mediaEvent.avDataId);
        tunerMedia.mpuSequenceNumber = static_cast<int>(mediaEvent.mpuSequenceNumber);
        tunerMedia.isPesPrivateData = mediaEvent.isPesPrivateData;

        if (mediaEvent.extraMetaData.getDiscriminator() ==
                DemuxFilterMediaEvent::ExtraMetaData::hidl_discriminator::audio) {
            tunerMedia.isAudioExtraMetaData = true;
            tunerMedia.audio = {
                .adFade = static_cast<int8_t>(
                        mediaEvent.extraMetaData.audio().adFade),
                .adPan = static_cast<int8_t>(
                        mediaEvent.extraMetaData.audio().adPan),
                .versionTextTag = static_cast<int8_t>(
                        mediaEvent.extraMetaData.audio().versionTextTag),
                .adGainCenter = static_cast<int8_t>(
                        mediaEvent.extraMetaData.audio().adGainCenter),
                .adGainFront = static_cast<int8_t>(
                        mediaEvent.extraMetaData.audio().adGainFront),
                .adGainSurround = static_cast<int8_t>(
                        mediaEvent.extraMetaData.audio().adGainSurround),
            };
        } else {
            tunerMedia.isAudioExtraMetaData = false;
        }

        if (mediaEvent.avMemory.getNativeHandle() != nullptr) {
            tunerMedia.avMemory = dupToAidl(mediaEvent.avMemory.getNativeHandle());
        }

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::media>(move(tunerMedia));
        res.push_back(move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getSectionEvent(
        vector<DemuxFilterEvent::Event>& events, vector<TunerFilterEvent>& res) {
    for (DemuxFilterEvent::Event e : events) {
        DemuxFilterSectionEvent sectionEvent = e.section();
        TunerFilterSectionEvent tunerSection;

        tunerSection.tableId = static_cast<char16_t>(sectionEvent.tableId);
        tunerSection.version = static_cast<char16_t>(sectionEvent.version);
        tunerSection.sectionNum = static_cast<char16_t>(sectionEvent.sectionNum);
        tunerSection.dataLength = static_cast<char16_t>(sectionEvent.dataLength);

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::section>(move(tunerSection));
        res.push_back(move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getPesEvent(
        vector<DemuxFilterEvent::Event>& events, vector<TunerFilterEvent>& res) {
    for (DemuxFilterEvent::Event e : events) {
        DemuxFilterPesEvent pesEvent = e.pes();
        TunerFilterPesEvent tunerPes;

        tunerPes.streamId = static_cast<char16_t>(pesEvent.streamId);
        tunerPes.dataLength = static_cast<char16_t>(pesEvent.dataLength);
        tunerPes.mpuSequenceNumber = static_cast<int>(pesEvent.mpuSequenceNumber);

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::pes>(move(tunerPes));
        res.push_back(move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getTsRecordEvent(vector<DemuxFilterEvent::Event>& events,
        vector<DemuxFilterEventExt::Event>& eventsExt, vector<TunerFilterEvent>& res) {
    for (int i = 0; i < events.size(); i++) {
        TunerFilterTsRecordEvent tunerTsRecord;
        DemuxFilterTsRecordEvent tsRecordEvent = events[i].tsRecord();

        TunerFilterScIndexMask scIndexMask;
        if (tsRecordEvent.scIndexMask.getDiscriminator()
                == DemuxFilterTsRecordEvent::ScIndexMask::hidl_discriminator::sc) {
            scIndexMask.set<TunerFilterScIndexMask::sc>(
                    static_cast<int>(tsRecordEvent.scIndexMask.sc()));
        } else if (tsRecordEvent.scIndexMask.getDiscriminator()
                == DemuxFilterTsRecordEvent::ScIndexMask::hidl_discriminator::scHevc) {
            scIndexMask.set<TunerFilterScIndexMask::scHevc>(
                    static_cast<int>(tsRecordEvent.scIndexMask.scHevc()));
        }

        if (tsRecordEvent.pid.getDiscriminator() == DemuxPid::hidl_discriminator::tPid) {
            tunerTsRecord.pid = static_cast<char16_t>(tsRecordEvent.pid.tPid());
        } else {
            tunerTsRecord.pid = static_cast<char16_t>(Constant::INVALID_TS_PID);
        }

        tunerTsRecord.scIndexMask = scIndexMask;
        tunerTsRecord.tsIndexMask = static_cast<int>(tsRecordEvent.tsIndexMask);
        tunerTsRecord.byteNumber = static_cast<long>(tsRecordEvent.byteNumber);

        if (eventsExt.size() > i && eventsExt[i].getDiscriminator() ==
                    DemuxFilterEventExt::Event::hidl_discriminator::tsRecord) {
            tunerTsRecord.isExtended = true;
            tunerTsRecord.pts = static_cast<long>(eventsExt[i].tsRecord().pts);
            tunerTsRecord.firstMbInSlice = static_cast<int>(eventsExt[i].tsRecord().firstMbInSlice);
        } else {
            tunerTsRecord.isExtended = false;
        }

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::tsRecord>(move(tunerTsRecord));
        res.push_back(move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getMmtpRecordEvent(vector<DemuxFilterEvent::Event>& events,
        vector<DemuxFilterEventExt::Event>& eventsExt, vector<TunerFilterEvent>& res) {
    for (int i = 0; i < events.size(); i++) {
        TunerFilterMmtpRecordEvent tunerMmtpRecord;
        DemuxFilterMmtpRecordEvent mmtpRecordEvent = events[i].mmtpRecord();

        tunerMmtpRecord.scHevcIndexMask = static_cast<int>(mmtpRecordEvent.scHevcIndexMask);
        tunerMmtpRecord.byteNumber = static_cast<long>(mmtpRecordEvent.byteNumber);

        if (eventsExt.size() > i && eventsExt[i].getDiscriminator() ==
                    DemuxFilterEventExt::Event::hidl_discriminator::mmtpRecord) {
            tunerMmtpRecord.isExtended = true;
            tunerMmtpRecord.pts = static_cast<long>(eventsExt[i].mmtpRecord().pts);
            tunerMmtpRecord.mpuSequenceNumber =
                    static_cast<int>(eventsExt[i].mmtpRecord().mpuSequenceNumber);
            tunerMmtpRecord.firstMbInSlice =
                    static_cast<int>(eventsExt[i].mmtpRecord().firstMbInSlice);
            tunerMmtpRecord.tsIndexMask = static_cast<int>(eventsExt[i].mmtpRecord().tsIndexMask);
        } else {
            tunerMmtpRecord.isExtended = false;
        }

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::mmtpRecord>(move(tunerMmtpRecord));
        res.push_back(move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getDownloadEvent(
        vector<DemuxFilterEvent::Event>& events, vector<TunerFilterEvent>& res) {
    for (DemuxFilterEvent::Event e : events) {
        DemuxFilterDownloadEvent downloadEvent = e.download();
        TunerFilterDownloadEvent tunerDownload;

        tunerDownload.itemId = static_cast<int>(downloadEvent.itemId);
        tunerDownload.itemFragmentIndex = static_cast<int>(downloadEvent.itemFragmentIndex);
        tunerDownload.mpuSequenceNumber = static_cast<int>(downloadEvent.mpuSequenceNumber);
        tunerDownload.lastItemFragmentIndex = static_cast<int>(downloadEvent.lastItemFragmentIndex);
        tunerDownload.dataLength = static_cast<char16_t>(downloadEvent.dataLength);

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::download>(move(tunerDownload));
        res.push_back(move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getIpPayloadEvent(
        vector<DemuxFilterEvent::Event>& events, vector<TunerFilterEvent>& res) {
    for (DemuxFilterEvent::Event e : events) {
        DemuxFilterIpPayloadEvent ipPayloadEvent = e.ipPayload();
        TunerFilterIpPayloadEvent tunerIpPayload;

        tunerIpPayload.dataLength = static_cast<char16_t>(ipPayloadEvent.dataLength);

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::ipPayload>(move(tunerIpPayload));
        res.push_back(move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getTemiEvent(
        vector<DemuxFilterEvent::Event>& events, vector<TunerFilterEvent>& res) {
    for (DemuxFilterEvent::Event e : events) {
        DemuxFilterTemiEvent temiEvent = e.temi();
        TunerFilterTemiEvent tunerTemi;

        tunerTemi.pts = static_cast<long>(temiEvent.pts);
        tunerTemi.descrTag = static_cast<int8_t>(temiEvent.descrTag);
        vector<uint8_t> descrData = temiEvent.descrData;
        tunerTemi.descrData.resize(descrData.size());
        copy(descrData.begin(), descrData.end(), tunerTemi.descrData.begin());

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::temi>(move(tunerTemi));
        res.push_back(move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getMonitorEvent(
        vector<DemuxFilterEventExt::Event>& eventsExt, vector<TunerFilterEvent>& res) {
    DemuxFilterMonitorEvent monitorEvent = eventsExt[0].monitorEvent();
    TunerFilterMonitorEvent tunerMonitor;

    switch (monitorEvent.getDiscriminator()) {
        case DemuxFilterMonitorEvent::hidl_discriminator::scramblingStatus: {
            tunerMonitor.set<TunerFilterMonitorEvent::scramblingStatus>(
                    static_cast<int>(monitorEvent.scramblingStatus()));
            break;
        }
        case DemuxFilterMonitorEvent::hidl_discriminator::cid: {
            tunerMonitor.set<TunerFilterMonitorEvent::cid>(static_cast<int>(monitorEvent.cid()));
            break;
        }
    }

    TunerFilterEvent tunerEvent;
    tunerEvent.set<TunerFilterEvent::monitor>(move(tunerMonitor));
    res.push_back(move(tunerEvent));
}

void TunerFilter::FilterCallback::getRestartEvent(
        vector<DemuxFilterEventExt::Event>& eventsExt, vector<TunerFilterEvent>& res) {
    TunerFilterEvent tunerEvent;
    tunerEvent.set<TunerFilterEvent::startId>(static_cast<int>(eventsExt[0].startId()));
    res.push_back(move(tunerEvent));
}
}  // namespace android
