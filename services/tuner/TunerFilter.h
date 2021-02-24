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

#ifndef ANDROID_MEDIA_TUNERFILTER_H
#define ANDROID_MEDIA_TUNERFILTER_H

#include <aidl/android/media/tv/tuner/BnTunerFilter.h>
#include <aidl/android/media/tv/tuner/ITunerFilterCallback.h>
#include <aidlcommonsupport/NativeHandle.h>
#include <android/hardware/tv/tuner/1.0/ITuner.h>
#include <android/hardware/tv/tuner/1.1/IFilter.h>
#include <android/hardware/tv/tuner/1.1/IFilterCallback.h>
#include <android/hardware/tv/tuner/1.1/types.h>
#include <media/stagefright/foundation/ADebug.h>
#include <fmq/ConvertMQDescriptors.h>
#include <fmq/MessageQueue.h>

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::hardware::common::fmq::MQDescriptor;
using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::aidl::android::media::tv::tuner::BnTunerFilter;
using ::aidl::android::media::tv::tuner::ITunerFilterCallback;
using ::aidl::android::media::tv::tuner::TunerDemuxIpAddress;
using ::aidl::android::media::tv::tuner::TunerFilterConfiguration;
using ::aidl::android::media::tv::tuner::TunerFilterDownloadEvent;
using ::aidl::android::media::tv::tuner::TunerFilterIpPayloadEvent;
using ::aidl::android::media::tv::tuner::TunerFilterEvent;
using ::aidl::android::media::tv::tuner::TunerFilterMediaEvent;
using ::aidl::android::media::tv::tuner::TunerFilterMmtpRecordEvent;
using ::aidl::android::media::tv::tuner::TunerFilterMonitorEvent;
using ::aidl::android::media::tv::tuner::TunerFilterPesEvent;
using ::aidl::android::media::tv::tuner::TunerFilterScIndexMask;
using ::aidl::android::media::tv::tuner::TunerFilterSectionEvent;
using ::aidl::android::media::tv::tuner::TunerFilterSharedHandleInfo;
using ::aidl::android::media::tv::tuner::TunerFilterSettings;
using ::aidl::android::media::tv::tuner::TunerFilterTemiEvent;
using ::aidl::android::media::tv::tuner::TunerFilterTsRecordEvent;
using ::android::hardware::MQDescriptorSync;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::hidl_array;
using ::android::hardware::tv::tuner::V1_0::DemuxAlpFilterSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterAvSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterDownloadEvent;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterDownloadSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterIpPayloadEvent;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterEvent;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterMediaEvent;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterMmtpRecordEvent;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterPesDataSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterPesEvent;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterRecordSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterSectionEvent;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterSectionSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterStatus;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterTemiEvent;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterTsRecordEvent;
using ::android::hardware::tv::tuner::V1_0::DemuxIpFilterSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxMmtpFilterSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxTlvFilterSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxTsFilterSettings;
using ::android::hardware::tv::tuner::V1_0::DemuxPid;
using ::android::hardware::tv::tuner::V1_0::IFilter;
using ::android::hardware::tv::tuner::V1_1::AvStreamType;
using ::android::hardware::tv::tuner::V1_1::DemuxFilterEventExt;
using ::android::hardware::tv::tuner::V1_1::DemuxFilterMonitorEvent;
using ::android::hardware::tv::tuner::V1_1::DemuxFilterTsRecordEventExt;
using ::android::hardware::tv::tuner::V1_1::IFilterCallback;

namespace android {

using MQDesc = MQDescriptorSync<uint8_t>;
using AidlMQDesc = MQDescriptor<int8_t, SynchronizedReadWrite>;

const static int IP_V4_LENGTH = 4;
const static int IP_V6_LENGTH = 16;

class TunerFilter : public BnTunerFilter {

public:
    TunerFilter(sp<IFilter> filter, int mainType, int subTyp);
    virtual ~TunerFilter();
    Status getId(int32_t* _aidl_return) override;
    Status getId64Bit(int64_t* _aidl_return) override;
    Status getQueueDesc(AidlMQDesc* _aidl_return) override;
    Status configure(const TunerFilterConfiguration& config) override;
    Status configureMonitorEvent(int monitorEventType) override;
    Status configureIpFilterContextId(int cid) override;
    Status configureAvStreamType(int avStreamType) override;
    Status getAvSharedHandleInfo(TunerFilterSharedHandleInfo* _aidl_return) override;
    Status releaseAvHandle(const ::aidl::android::hardware::common::NativeHandle& handle,
            int64_t avDataId) override;
    Status setDataSource(const std::shared_ptr<ITunerFilter>& filter) override;
    Status start() override;
    Status stop() override;
    Status flush() override;
    Status close() override;
    sp<IFilter> getHalFilter();

    struct FilterCallback : public IFilterCallback {
        FilterCallback(const std::shared_ptr<ITunerFilterCallback> tunerFilterCallback)
                : mTunerFilterCallback(tunerFilterCallback) {};

        virtual Return<void> onFilterEvent(const DemuxFilterEvent& filterEvent);
        virtual Return<void> onFilterEvent_1_1(const DemuxFilterEvent& filterEvent,
                const DemuxFilterEventExt& filterEventExt);
        virtual Return<void> onFilterStatus(DemuxFilterStatus status);

        void getAidlFilterEvent(std::vector<DemuxFilterEvent::Event>& events,
                std::vector<DemuxFilterEventExt::Event>& eventsExt,
                std::vector<TunerFilterEvent>& tunerEvent);

        void getMediaEvent(
                std::vector<DemuxFilterEvent::Event>& events, std::vector<TunerFilterEvent>& res);
        void getSectionEvent(
                std::vector<DemuxFilterEvent::Event>& events, std::vector<TunerFilterEvent>& res);
        void getPesEvent(
                std::vector<DemuxFilterEvent::Event>& events, std::vector<TunerFilterEvent>& res);
        void getTsRecordEvent(
                std::vector<DemuxFilterEvent::Event>& events,
                std::vector<DemuxFilterEventExt::Event>& eventsExt,
                std::vector<TunerFilterEvent>& res);
        void getMmtpRecordEvent(
                std::vector<DemuxFilterEvent::Event>& events,
                std::vector<DemuxFilterEventExt::Event>& eventsExt,
                std::vector<TunerFilterEvent>& res);
        void getDownloadEvent(
                std::vector<DemuxFilterEvent::Event>& events, std::vector<TunerFilterEvent>& res);
        void getIpPayloadEvent(
                std::vector<DemuxFilterEvent::Event>& events, std::vector<TunerFilterEvent>& res);
        void getTemiEvent(
                std::vector<DemuxFilterEvent::Event>& events, std::vector<TunerFilterEvent>& res);
        void getMonitorEvent(
                std::vector<DemuxFilterEventExt::Event>& eventsExt,
                std::vector<TunerFilterEvent>& res);
        void getRestartEvent(
                std::vector<DemuxFilterEventExt::Event>& eventsExt,
                std::vector<TunerFilterEvent>& res);

        std::shared_ptr<ITunerFilterCallback> mTunerFilterCallback;
    };

private:
    DemuxFilterAvSettings getAvSettings(const TunerFilterSettings& settings);
    DemuxFilterSectionSettings getSectionSettings(const TunerFilterSettings& settings);
    DemuxFilterPesDataSettings getPesDataSettings(const TunerFilterSettings& settings);
    DemuxFilterRecordSettings getRecordSettings(const TunerFilterSettings& settings);
    DemuxFilterDownloadSettings getDownloadSettings(const TunerFilterSettings& settings);

    bool isAudioFilter();
    bool isVideoFilter();
    bool getHidlAvStreamType(int avStreamType, AvStreamType& type);

    void getHidlTsSettings(
        const TunerFilterConfiguration& config, DemuxFilterSettings& settings);
    void getHidlMmtpSettings(
        const TunerFilterConfiguration& config, DemuxFilterSettings& settings);
    void getHidlIpSettings(
        const TunerFilterConfiguration& config, DemuxFilterSettings& settings);
    void getHidlTlvSettings(
        const TunerFilterConfiguration& config, DemuxFilterSettings& settings);
    void getHidlAlpSettings(
        const TunerFilterConfiguration& config, DemuxFilterSettings& settings);

    hidl_array<uint8_t, IP_V4_LENGTH> getIpV4Address(TunerDemuxIpAddress addr);
    hidl_array<uint8_t, IP_V6_LENGTH> getIpV6Address(TunerDemuxIpAddress addr);

    sp<IFilter> mFilter;
    sp<::android::hardware::tv::tuner::V1_1::IFilter> mFilter_1_1;
    int32_t mId;
    int64_t mId64Bit;
    int mMainType;
    int mSubType;
};

} // namespace android

#endif // ANDROID_MEDIA_TUNERFILTER_H
