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

using ::android::hardware::hidl_handle;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterMainType;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxMmtpFilterType;
using ::android::hardware::tv::tuner::V1_0::DemuxTsFilterSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxTsFilterType;
using ::android::hardware::tv::tuner::V1_0::Result;
using ::android::hardware::tv::tuner::V1_1::Constant;

namespace android {

TunerFilter::TunerFilter(
        sp<IFilter> filter, sp<IFilterCallback> callback) {
    mFilter = filter;
    mFilter_1_1 = ::android::hardware::tv::tuner::V1_1::IFilter::castFrom(filter);
    mFilterCallback = callback;
}

TunerFilter::~TunerFilter() {
    mFilter = nullptr;
    mFilter_1_1 = nullptr;
    mFilterCallback = nullptr;
}

DemuxFilterAvSettings TunerFilter::getAvSettings(const TunerFilterSettings& settings) {
    DemuxFilterAvSettings av {
        .isPassthrough = settings.get<TunerFilterSettings::av>().isPassthrough,
    };
    return av;
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

    // TODO: more filter types.
    TunerFilterSettings tunerSettings;
    DemuxFilterSettings halSettings;
    switch (config.getTag()) {
        case TunerFilterConfiguration::ts: {
            uint16_t tpid = static_cast<uint16_t>(config.get<TunerFilterConfiguration::ts>().tpid);
            tunerSettings = config.get<TunerFilterConfiguration::ts>().filterSettings;
            DemuxTsFilterSettings ts {
                .tpid = tpid,
            };

            switch (tunerSettings.getTag()) {
                case TunerFilterSettings::av: {
                    ts.filterSettings.av(getAvSettings(tunerSettings));
                    break;
                }
            }
            halSettings.ts(ts);
            break;
        }
    }
    Result res = mFilter->configure(halSettings);
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
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
                .handle = dupToAidl(hidl_handle(avMemory.getNativeHandle())),
                .size = static_cast<int64_t>(avMemSize),
            };
            *_aidl_return = std::move(info);
        } else {
            _aidl_return = NULL;
        }
    });

    return Status::fromServiceSpecificError(static_cast<int32_t>(res));
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
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

sp<IFilter> TunerFilter::getHalFilter() {
    return mFilter;
}

/////////////// FilterCallback ///////////////////////

Return<void> TunerFilter::FilterCallback::onFilterStatus(DemuxFilterStatus status) {
    if (mTunerFilterCallback != NULL) {
        mTunerFilterCallback->onFilterStatus((int)status);
    }
    return Void();
}

Return<void> TunerFilter::FilterCallback::onFilterEvent(const DemuxFilterEvent& filterEvent) {
    std::vector<DemuxFilterEventExt::Event> emptyEventsExt;
    DemuxFilterEventExt emptyFilterEventExt {
            .events = emptyEventsExt,
    };
    onFilterEvent_1_1(filterEvent, emptyFilterEventExt);
    return Void();
}

Return<void> TunerFilter::FilterCallback::onFilterEvent_1_1(const DemuxFilterEvent& filterEvent,
        const DemuxFilterEventExt& filterEventExt) {
    if (mTunerFilterCallback != NULL) {
        std::vector<DemuxFilterEvent::Event> events = filterEvent.events;
        std::vector<DemuxFilterEventExt::Event> eventsExt = filterEventExt.events;
        std::vector<TunerFilterEvent> tunerEvent;

        getAidlFilterEvent(events, eventsExt, tunerEvent);
        mTunerFilterCallback->onFilterEvent(tunerEvent);
    }
    return Void();
}

/////////////// FilterCallback Helper Methods ///////////////////////

void TunerFilter::FilterCallback::getAidlFilterEvent(std::vector<DemuxFilterEvent::Event>& events,
        std::vector<DemuxFilterEventExt::Event>& eventsExt,
        std::vector<TunerFilterEvent>& tunerEvent) {
    if (events.empty() && !eventsExt.empty()) {
        auto eventExt = eventsExt[0];
        switch (eventExt.getDiscriminator()) {
            case DemuxFilterEventExt::Event::hidl_discriminator::monitorEvent: {
                getMonitorEvent(eventsExt, tunerEvent);
                break;
            }
            case DemuxFilterEventExt::Event::hidl_discriminator::startId: {
                getRestartEvent(eventsExt, tunerEvent);
                break;
            }
            default: {
                break;
            }
        }
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
        std::vector<DemuxFilterEvent::Event>& events, std::vector<TunerFilterEvent>& res) {
    for (DemuxFilterEvent::Event e : events) {
        DemuxFilterMediaEvent mediaEvent = e.media();
        TunerFilterMediaEvent tunerMedia;

        tunerMedia.streamId = static_cast<int>(mediaEvent.streamId);
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
        tunerEvent.set<TunerFilterEvent::media>(std::move(tunerMedia));
        res.push_back(std::move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getSectionEvent(
        std::vector<DemuxFilterEvent::Event>& events, std::vector<TunerFilterEvent>& res) {
    for (DemuxFilterEvent::Event e : events) {
        DemuxFilterSectionEvent sectionEvent = e.section();
        TunerFilterSectionEvent tunerSection;

        tunerSection.tableId = static_cast<char>(sectionEvent.tableId);
        tunerSection.version = static_cast<char>(sectionEvent.version);
        tunerSection.sectionNum = static_cast<char>(sectionEvent.sectionNum);
        tunerSection.dataLength = static_cast<char>(sectionEvent.dataLength);

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::section>(std::move(tunerSection));
        res.push_back(std::move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getPesEvent(
        std::vector<DemuxFilterEvent::Event>& events, std::vector<TunerFilterEvent>& res) {
    for (DemuxFilterEvent::Event e : events) {
        DemuxFilterPesEvent pesEvent = e.pes();
        TunerFilterPesEvent tunerPes;

        tunerPes.streamId = static_cast<char>(pesEvent.streamId);
        tunerPes.dataLength = static_cast<int>(pesEvent.dataLength);
        tunerPes.mpuSequenceNumber = static_cast<int>(pesEvent.mpuSequenceNumber);

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::pes>(std::move(tunerPes));
        res.push_back(std::move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getTsRecordEvent(std::vector<DemuxFilterEvent::Event>& events,
        std::vector<DemuxFilterEventExt::Event>& eventsExt, std::vector<TunerFilterEvent>& res) {
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
            tunerTsRecord.pid = static_cast<char>(tsRecordEvent.pid.tPid());
        } else {
            tunerTsRecord.pid = static_cast<char>(Constant::INVALID_TS_PID);
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
        tunerEvent.set<TunerFilterEvent::tsRecord>(std::move(tunerTsRecord));
        res.push_back(std::move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getMmtpRecordEvent(std::vector<DemuxFilterEvent::Event>& events,
        std::vector<DemuxFilterEventExt::Event>& eventsExt, std::vector<TunerFilterEvent>& res) {
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
        tunerEvent.set<TunerFilterEvent::mmtpRecord>(std::move(tunerMmtpRecord));
        res.push_back(std::move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getDownloadEvent(
        std::vector<DemuxFilterEvent::Event>& events, std::vector<TunerFilterEvent>& res) {
    for (DemuxFilterEvent::Event e : events) {
        DemuxFilterDownloadEvent downloadEvent = e.download();
        TunerFilterDownloadEvent tunerDownload;

        tunerDownload.itemId = static_cast<int>(downloadEvent.itemId);
        tunerDownload.itemFragmentIndex = static_cast<int>(downloadEvent.itemFragmentIndex);
        tunerDownload.mpuSequenceNumber = static_cast<int>(downloadEvent.mpuSequenceNumber);
        tunerDownload.lastItemFragmentIndex = static_cast<int>(downloadEvent.lastItemFragmentIndex);
        tunerDownload.dataLength = static_cast<char>(downloadEvent.dataLength);

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::download>(std::move(tunerDownload));
        res.push_back(std::move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getIpPayloadEvent(
        std::vector<DemuxFilterEvent::Event>& events, std::vector<TunerFilterEvent>& res) {
    for (DemuxFilterEvent::Event e : events) {
        DemuxFilterIpPayloadEvent ipPayloadEvent = e.ipPayload();
        TunerFilterIpPayloadEvent tunerIpPayload;

        tunerIpPayload.dataLength = static_cast<char>(ipPayloadEvent.dataLength);

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::ipPayload>(std::move(tunerIpPayload));
        res.push_back(std::move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getTemiEvent(
        std::vector<DemuxFilterEvent::Event>& events, std::vector<TunerFilterEvent>& res) {
    for (DemuxFilterEvent::Event e : events) {
        DemuxFilterTemiEvent temiEvent = e.temi();
        TunerFilterTemiEvent tunerTemi;

        tunerTemi.pts = static_cast<long>(temiEvent.pts);
        tunerTemi.descrTag = static_cast<int8_t>(temiEvent.descrTag);
        std::vector<uint8_t> descrData = temiEvent.descrData;
        tunerTemi.descrData.resize(descrData.size());
        copy(descrData.begin(), descrData.end(), tunerTemi.descrData.begin());

        TunerFilterEvent tunerEvent;
        tunerEvent.set<TunerFilterEvent::temi>(std::move(tunerTemi));
        res.push_back(std::move(tunerEvent));
    }
}

void TunerFilter::FilterCallback::getMonitorEvent(
        std::vector<DemuxFilterEventExt::Event>& eventsExt, std::vector<TunerFilterEvent>& res) {
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
        default: {
            break;
        }
    }

    TunerFilterEvent tunerEvent;
    tunerEvent.set<TunerFilterEvent::monitor>(std::move(tunerMonitor));
    res.push_back(std::move(tunerEvent));
}

void TunerFilter::FilterCallback::getRestartEvent(
        std::vector<DemuxFilterEventExt::Event>& eventsExt, std::vector<TunerFilterEvent>& res) {
    TunerFilterEvent tunerEvent;
    tunerEvent.set<TunerFilterEvent::startId>(static_cast<int>(eventsExt[0].startId()));
    res.push_back(std::move(tunerEvent));
}
}  // namespace android
