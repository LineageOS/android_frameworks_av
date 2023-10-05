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

#ifndef ANDROID_MEDIA_TUNERHIDLFILTER_H
#define ANDROID_MEDIA_TUNERHIDLFILTER_H

#include <aidl/android/hardware/tv/tuner/AvStreamType.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterAvSettings.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterDownloadSettings.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterEvent.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterPesDataSettings.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterRecordSettings.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterSectionSettings.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterSettings.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterStatus.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterType.h>
#include <aidl/android/media/tv/tuner/BnTunerFilter.h>
#include <aidl/android/media/tv/tuner/ITunerFilterCallback.h>
#include <android/hardware/tv/tuner/1.0/ITuner.h>
#include <android/hardware/tv/tuner/1.1/IFilter.h>
#include <android/hardware/tv/tuner/1.1/IFilterCallback.h>
#include <android/hardware/tv/tuner/1.1/types.h>
#include <fmq/MessageQueue.h>
#include <utils/Mutex.h>

#include <map>

using ::aidl::android::hardware::common::NativeHandle;
using ::aidl::android::hardware::common::fmq::MQDescriptor;
using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::aidl::android::hardware::tv::tuner::AvStreamType;
using ::aidl::android::hardware::tv::tuner::DemuxFilterAvSettings;
using ::aidl::android::hardware::tv::tuner::DemuxFilterDownloadSettings;
using ::aidl::android::hardware::tv::tuner::DemuxFilterEvent;
using ::aidl::android::hardware::tv::tuner::DemuxFilterPesDataSettings;
using ::aidl::android::hardware::tv::tuner::DemuxFilterRecordSettings;
using ::aidl::android::hardware::tv::tuner::DemuxFilterSectionSettings;
using ::aidl::android::hardware::tv::tuner::DemuxFilterSettings;
using ::aidl::android::hardware::tv::tuner::DemuxFilterStatus;
using ::aidl::android::hardware::tv::tuner::DemuxFilterType;
using ::aidl::android::hardware::tv::tuner::DemuxIpAddressIpAddress;
using ::aidl::android::hardware::tv::tuner::FilterDelayHint;
using ::aidl::android::media::tv::tuner::BnTunerFilter;
using ::aidl::android::media::tv::tuner::ITunerFilterCallback;
using ::android::Mutex;
using ::android::sp;
using ::android::hardware::hidl_array;
using ::android::hardware::MQDescriptorSync;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::std::shared_ptr;
using ::std::string;
using ::std::vector;

using HidlAvStreamType = ::android::hardware::tv::tuner::V1_1::AvStreamType;
using HidlDemuxAlpFilterSettings = ::android::hardware::tv::tuner::V1_0::DemuxAlpFilterSettings;
using HidlDemuxFilterAvSettings = ::android::hardware::tv::tuner::V1_0::DemuxFilterAvSettings;
using HidlDemuxFilterDownloadEvent = ::android::hardware::tv::tuner::V1_0::DemuxFilterDownloadEvent;
using HidlDemuxFilterDownloadSettings =
        ::android::hardware::tv::tuner::V1_0::DemuxFilterDownloadSettings;
using HidlDemuxFilterIpPayloadEvent =
        ::android::hardware::tv::tuner::V1_0::DemuxFilterIpPayloadEvent;
using HidlDemuxFilterEvent = ::android::hardware::tv::tuner::V1_0::DemuxFilterEvent;
using HidlDemuxFilterMediaEvent = ::android::hardware::tv::tuner::V1_0::DemuxFilterMediaEvent;
using HidlDemuxFilterMmtpRecordEvent =
        ::android::hardware::tv::tuner::V1_0::DemuxFilterMmtpRecordEvent;
using HidlDemuxFilterPesDataSettings =
        ::android::hardware::tv::tuner::V1_0::DemuxFilterPesDataSettings;
using HidlDemuxFilterPesEvent = ::android::hardware::tv::tuner::V1_0::DemuxFilterPesEvent;
using HidlDemuxFilterRecordSettings =
        ::android::hardware::tv::tuner::V1_0::DemuxFilterRecordSettings;
using HidlDemuxFilterSectionEvent = ::android::hardware::tv::tuner::V1_0::DemuxFilterSectionEvent;
using HidlDemuxFilterSectionSettings =
        ::android::hardware::tv::tuner::V1_0::DemuxFilterSectionSettings;
using HidlDemuxFilterSettings = ::android::hardware::tv::tuner::V1_0::DemuxFilterSettings;
using HidlDemuxFilterStatus = ::android::hardware::tv::tuner::V1_0::DemuxFilterStatus;
using HidlDemuxFilterTemiEvent = ::android::hardware::tv::tuner::V1_0::DemuxFilterTemiEvent;
using HidlDemuxFilterTsRecordEvent = ::android::hardware::tv::tuner::V1_0::DemuxFilterTsRecordEvent;
using HidlDemuxIpFilterSettings = ::android::hardware::tv::tuner::V1_0::DemuxIpFilterSettings;
using HidlDemuxMmtpFilterSettings = ::android::hardware::tv::tuner::V1_0::DemuxMmtpFilterSettings;
using HidlDemuxTlvFilterSettings = ::android::hardware::tv::tuner::V1_0::DemuxTlvFilterSettings;
using HidlDemuxTsFilterSettings = ::android::hardware::tv::tuner::V1_0::DemuxTsFilterSettings;
using HidlDemuxPid = ::android::hardware::tv::tuner::V1_0::DemuxPid;
using HidlIFilter = ::android::hardware::tv::tuner::V1_0::IFilter;
using HidlDvStreamType = ::android::hardware::tv::tuner::V1_1::AvStreamType;
using HidlDemuxFilterEventExt = ::android::hardware::tv::tuner::V1_1::DemuxFilterEventExt;
using HidlDemuxFilterMonitorEvent = ::android::hardware::tv::tuner::V1_1::DemuxFilterMonitorEvent;
using HidlDemuxFilterTsRecordEventExt =
        ::android::hardware::tv::tuner::V1_1::DemuxFilterTsRecordEventExt;
using HidlIFilterCallback = ::android::hardware::tv::tuner::V1_1::IFilterCallback;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

using MQDesc = MQDescriptorSync<uint8_t>;
using AidlMQDesc = MQDescriptor<int8_t, SynchronizedReadWrite>;

const static int IP_V4_LENGTH = 4;
const static int IP_V6_LENGTH = 16;

class TunerHidlService;

class TunerHidlFilter : public BnTunerFilter {
public:
    class FilterCallback : public HidlIFilterCallback {
    public:
        FilterCallback(const shared_ptr<ITunerFilterCallback> tunerFilterCallback)
              : mTunerFilterCallback(tunerFilterCallback){};

        virtual Return<void> onFilterEvent(const HidlDemuxFilterEvent& filterEvent);
        virtual Return<void> onFilterEvent_1_1(const HidlDemuxFilterEvent& filterEvent,
                                               const HidlDemuxFilterEventExt& filterEventExt);
        virtual Return<void> onFilterStatus(HidlDemuxFilterStatus status);

        void sendSharedFilterStatus(int32_t status);
        void attachSharedFilterCallback(const shared_ptr<ITunerFilterCallback>& in_cb);
        void detachSharedFilterCallback();
        void detachCallbacks();

    private:
        void getAidlFilterEvent(const vector<HidlDemuxFilterEvent::Event>& events,
                                const vector<HidlDemuxFilterEventExt::Event>& eventsExt,
                                vector<DemuxFilterEvent>& aidlEvents);

        void getMediaEvent(const vector<HidlDemuxFilterEvent::Event>& events,
                           vector<DemuxFilterEvent>& res);
        void getSectionEvent(const vector<HidlDemuxFilterEvent::Event>& events,
                             vector<DemuxFilterEvent>& res);
        void getPesEvent(const vector<HidlDemuxFilterEvent::Event>& events,
                         vector<DemuxFilterEvent>& res);
        void getTsRecordEvent(const vector<HidlDemuxFilterEvent::Event>& events,
                              const vector<HidlDemuxFilterEventExt::Event>& eventsExt,
                              vector<DemuxFilterEvent>& res);
        void getMmtpRecordEvent(const vector<HidlDemuxFilterEvent::Event>& events,
                                const vector<HidlDemuxFilterEventExt::Event>& eventsExt,
                                vector<DemuxFilterEvent>& res);
        void getDownloadEvent(const vector<HidlDemuxFilterEvent::Event>& events,
                              vector<DemuxFilterEvent>& res);
        void getIpPayloadEvent(const vector<HidlDemuxFilterEvent::Event>& events,
                               vector<DemuxFilterEvent>& res);
        void getTemiEvent(const vector<HidlDemuxFilterEvent::Event>& events,
                          vector<DemuxFilterEvent>& res);
        void getMonitorEvent(const vector<HidlDemuxFilterEventExt::Event>& eventsExt,
                             vector<DemuxFilterEvent>& res);
        void getRestartEvent(const vector<HidlDemuxFilterEventExt::Event>& eventsExt,
                             vector<DemuxFilterEvent>& res);

    private:
        shared_ptr<ITunerFilterCallback> mTunerFilterCallback;
        shared_ptr<ITunerFilterCallback> mOriginalCallback;
        Mutex mCallbackLock;
    };

    TunerHidlFilter(const sp<HidlIFilter> filter, const sp<FilterCallback> cb,
                    const DemuxFilterType type, const shared_ptr<TunerHidlService> tuner);
    virtual ~TunerHidlFilter();

    ::ndk::ScopedAStatus getId(int32_t* _aidl_return) override;
    ::ndk::ScopedAStatus getId64Bit(int64_t* _aidl_return) override;
    ::ndk::ScopedAStatus getQueueDesc(AidlMQDesc* _aidl_return) override;
    ::ndk::ScopedAStatus configure(const DemuxFilterSettings& in_settings) override;
    ::ndk::ScopedAStatus configureMonitorEvent(int32_t in_monitorEventTypes) override;
    ::ndk::ScopedAStatus configureIpFilterContextId(int32_t in_cid) override;
    ::ndk::ScopedAStatus configureAvStreamType(const AvStreamType& in_avStreamType) override;
    ::ndk::ScopedAStatus getAvSharedHandle(NativeHandle* out_avMemory,
                                           int64_t* _aidl_return) override;
    ::ndk::ScopedAStatus releaseAvHandle(const NativeHandle& in_handle,
                                         int64_t in_avDataId) override;
    ::ndk::ScopedAStatus setDataSource(const shared_ptr<ITunerFilter>& in_filter) override;
    ::ndk::ScopedAStatus start() override;
    ::ndk::ScopedAStatus stop() override;
    ::ndk::ScopedAStatus flush() override;
    ::ndk::ScopedAStatus close() override;
    ::ndk::ScopedAStatus acquireSharedFilterToken(string* _aidl_return) override;
    ::ndk::ScopedAStatus freeSharedFilterToken(const string& in_filterToken) override;
    ::ndk::ScopedAStatus getFilterType(DemuxFilterType* _aidl_return) override;
    ::ndk::ScopedAStatus setDelayHint(const FilterDelayHint& in_hint) override;

    bool isSharedFilterAllowed(int32_t pid);
    void attachSharedFilterCallback(const shared_ptr<ITunerFilterCallback>& in_cb);
    sp<HidlIFilter> getHalFilter();

private:
    bool isAudioFilter();
    bool isVideoFilter();

    HidlDemuxFilterAvSettings getHidlAvSettings(const DemuxFilterAvSettings& settings);
    HidlDemuxFilterSectionSettings getHidlSectionSettings(
            const DemuxFilterSectionSettings& settings);
    HidlDemuxFilterPesDataSettings getHidlPesDataSettings(
            const DemuxFilterPesDataSettings& settings);
    HidlDemuxFilterRecordSettings getHidlRecordSettings(const DemuxFilterRecordSettings& settings);
    HidlDemuxFilterDownloadSettings getHidlDownloadSettings(
            const DemuxFilterDownloadSettings& settings);
    bool getHidlAvStreamType(const AvStreamType avStreamType, HidlAvStreamType& type);
    void getHidlTsSettings(const DemuxFilterSettings& settings,
                           HidlDemuxFilterSettings& hidlSettings);
    void getHidlMmtpSettings(const DemuxFilterSettings& settings,
                             HidlDemuxFilterSettings& hidlSettings);
    void getHidlIpSettings(const DemuxFilterSettings& settings,
                           HidlDemuxFilterSettings& hidlSettings);
    void getHidlTlvSettings(const DemuxFilterSettings& settings,
                            HidlDemuxFilterSettings& hidlSettings);
    void getHidlAlpSettings(const DemuxFilterSettings& settings,
                            HidlDemuxFilterSettings& hidlSettings);

    hidl_array<uint8_t, IP_V4_LENGTH> getIpV4Address(const DemuxIpAddressIpAddress& addr);
    hidl_array<uint8_t, IP_V6_LENGTH> getIpV6Address(const DemuxIpAddressIpAddress& addr);

    sp<HidlIFilter> mFilter;
    sp<::android::hardware::tv::tuner::V1_1::IFilter> mFilter_1_1;
    int32_t mId;
    int64_t mId64Bit;
    DemuxFilterType mType;
    bool mStarted;
    bool mShared;
    int32_t mClientPid;
    sp<FilterCallback> mFilterCallback;
    Mutex mLock;
    shared_ptr<TunerHidlService> mTunerService;
};

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl

#endif  // ANDROID_MEDIA_TUNERHIDLFILTER_H
