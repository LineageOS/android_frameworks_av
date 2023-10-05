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

#include <aidl/android/hardware/tv/tuner/AvStreamType.h>
#include <aidl/android/hardware/tv/tuner/BnFilterCallback.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterEvent.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterSettings.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterStatus.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterType.h>
#include <aidl/android/hardware/tv/tuner/FilterDelayHint.h>
#include <aidl/android/hardware/tv/tuner/IFilter.h>
#include <aidl/android/media/tv/tuner/BnTunerFilter.h>
#include <aidl/android/media/tv/tuner/ITunerFilterCallback.h>
#include <utils/Mutex.h>

using ::aidl::android::hardware::common::NativeHandle;
using ::aidl::android::hardware::common::fmq::MQDescriptor;
using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::aidl::android::hardware::tv::tuner::AvStreamType;
using ::aidl::android::hardware::tv::tuner::BnFilterCallback;
using ::aidl::android::hardware::tv::tuner::DemuxFilterEvent;
using ::aidl::android::hardware::tv::tuner::DemuxFilterSettings;
using ::aidl::android::hardware::tv::tuner::DemuxFilterStatus;
using ::aidl::android::hardware::tv::tuner::DemuxFilterType;
using ::aidl::android::hardware::tv::tuner::FilterDelayHint;
using ::aidl::android::hardware::tv::tuner::IFilter;
using ::aidl::android::media::tv::tuner::BnTunerFilter;
using ::android::Mutex;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

using AidlMQDesc = MQDescriptor<int8_t, SynchronizedReadWrite>;

class TunerService;

class TunerFilter : public BnTunerFilter {
public:
    class FilterCallback : public BnFilterCallback {
    public:
        FilterCallback(const shared_ptr<ITunerFilterCallback>& tunerFilterCallback)
              : mTunerFilterCallback(tunerFilterCallback), mOriginalCallback(nullptr){};

        ::ndk::ScopedAStatus onFilterEvent(const vector<DemuxFilterEvent>& events) override;
        ::ndk::ScopedAStatus onFilterStatus(DemuxFilterStatus status) override;

        void sendSharedFilterStatus(int32_t status);
        void attachSharedFilterCallback(const shared_ptr<ITunerFilterCallback>& in_cb);
        void detachSharedFilterCallback();
        void detachCallbacks();

    private:
        shared_ptr<ITunerFilterCallback> mTunerFilterCallback;
        shared_ptr<ITunerFilterCallback> mOriginalCallback;
        Mutex mCallbackLock;
    };

    TunerFilter(const shared_ptr<IFilter> filter, const shared_ptr<FilterCallback> cb,
                const DemuxFilterType type, const shared_ptr<TunerService> tuner);
    virtual ~TunerFilter();

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
    shared_ptr<IFilter> getHalFilter();

private:
    shared_ptr<IFilter> mFilter;
    int32_t mId;
    int64_t mId64Bit;
    DemuxFilterType mType;
    bool mStarted;
    bool mShared;
    int32_t mClientPid;
    shared_ptr<FilterCallback> mFilterCallback;
    Mutex mLock;
    shared_ptr<TunerService> mTunerService;
};

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl

#endif // ANDROID_MEDIA_TUNERFILTER_H
