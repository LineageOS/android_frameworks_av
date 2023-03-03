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

#define LOG_TAG "TunerHidlFilter"

#include "TunerHidlFilter.h"

#include <aidl/android/hardware/tv/tuner/Constant.h>
#include <aidl/android/hardware/tv/tuner/DemuxScIndex.h>
#include <aidl/android/hardware/tv/tuner/Result.h>
#include <aidlcommonsupport/NativeHandle.h>
#include <binder/IPCThreadState.h>
#include <fmq/ConvertMQDescriptors.h>

#include "TunerHelper.h"
#include "TunerHidlService.h"

using ::aidl::android::hardware::tv::tuner::AudioExtraMetaData;
using ::aidl::android::hardware::tv::tuner::AudioStreamType;
using ::aidl::android::hardware::tv::tuner::Constant;
using ::aidl::android::hardware::tv::tuner::DemuxAlpFilterSettings;
using ::aidl::android::hardware::tv::tuner::DemuxAlpFilterSettingsFilterSettings;
using ::aidl::android::hardware::tv::tuner::DemuxFilterDownloadEvent;
using ::aidl::android::hardware::tv::tuner::DemuxFilterIpPayloadEvent;
using ::aidl::android::hardware::tv::tuner::DemuxFilterMainType;
using ::aidl::android::hardware::tv::tuner::DemuxFilterMediaEvent;
using ::aidl::android::hardware::tv::tuner::DemuxFilterMediaEventExtraMetaData;
using ::aidl::android::hardware::tv::tuner::DemuxFilterMmtpRecordEvent;
using ::aidl::android::hardware::tv::tuner::DemuxFilterMonitorEvent;
using ::aidl::android::hardware::tv::tuner::DemuxFilterPesEvent;
using ::aidl::android::hardware::tv::tuner::DemuxFilterScIndexMask;
using ::aidl::android::hardware::tv::tuner::DemuxFilterSectionBits;
using ::aidl::android::hardware::tv::tuner::DemuxFilterSectionEvent;
using ::aidl::android::hardware::tv::tuner::DemuxFilterSectionSettingsCondition;
using ::aidl::android::hardware::tv::tuner::DemuxFilterSectionSettingsConditionTableInfo;
using ::aidl::android::hardware::tv::tuner::DemuxFilterSubType;
using ::aidl::android::hardware::tv::tuner::DemuxFilterTemiEvent;
using ::aidl::android::hardware::tv::tuner::DemuxFilterTsRecordEvent;
using ::aidl::android::hardware::tv::tuner::DemuxIpAddress;
using ::aidl::android::hardware::tv::tuner::DemuxIpAddressIpAddress;
using ::aidl::android::hardware::tv::tuner::DemuxIpFilterSettings;
using ::aidl::android::hardware::tv::tuner::DemuxIpFilterSettingsFilterSettings;
using ::aidl::android::hardware::tv::tuner::DemuxMmtpFilterSettings;
using ::aidl::android::hardware::tv::tuner::DemuxMmtpFilterSettingsFilterSettings;
using ::aidl::android::hardware::tv::tuner::DemuxMmtpFilterType;
using ::aidl::android::hardware::tv::tuner::DemuxPid;
using ::aidl::android::hardware::tv::tuner::DemuxScIndex;
using ::aidl::android::hardware::tv::tuner::DemuxTlvFilterSettings;
using ::aidl::android::hardware::tv::tuner::DemuxTlvFilterSettingsFilterSettings;
using ::aidl::android::hardware::tv::tuner::DemuxTsFilterSettings;
using ::aidl::android::hardware::tv::tuner::DemuxTsFilterSettingsFilterSettings;
using ::aidl::android::hardware::tv::tuner::DemuxTsFilterType;
using ::aidl::android::hardware::tv::tuner::Result;
using ::aidl::android::hardware::tv::tuner::ScramblingStatus;
using ::android::dupToAidl;
using ::android::IPCThreadState;
using ::android::makeFromAidl;
using ::android::unsafeHidlToAidlMQDescriptor;
using ::android::hardware::hidl_handle;

using HidlDemuxAlpLengthType = ::android::hardware::tv::tuner::V1_0::DemuxAlpLengthType;
using HidlDemuxFilterMainType = ::android::hardware::tv::tuner::V1_0::DemuxFilterMainType;
using HidlDemuxIpAddress = ::android::hardware::tv::tuner::V1_0::DemuxIpAddress;
using HidlDemuxMmtpFilterType = ::android::hardware::tv::tuner::V1_0::DemuxMmtpFilterType;
using HidlDemuxMmtpPid = ::android::hardware::tv::tuner::V1_0::DemuxMmtpPid;
using HidlDemuxRecordScIndexType = ::android::hardware::tv::tuner::V1_0::DemuxRecordScIndexType;
using HidlDemuxStreamId = ::android::hardware::tv::tuner::V1_0::DemuxStreamId;
using HidlDemuxTsFilterType = ::android::hardware::tv::tuner::V1_0::DemuxTsFilterType;
using HidlResult = ::android::hardware::tv::tuner::V1_0::Result;
using HidlAudioStreamType = ::android::hardware::tv::tuner::V1_1::AudioStreamType;
using HidlConstant = ::android::hardware::tv::tuner::V1_1::Constant;
using HidlVideoStreamType = ::android::hardware::tv::tuner::V1_1::VideoStreamType;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerHidlFilter::TunerHidlFilter(sp<HidlIFilter> filter, sp<FilterCallback> cb,
                                 DemuxFilterType type)
      : mFilter(filter),
        mType(type),
        mStarted(false),
        mShared(false),
        mClientPid(-1),
        mFilterCallback(cb) {
    mFilter_1_1 = ::android::hardware::tv::tuner::V1_1::IFilter::castFrom(filter);
}

TunerHidlFilter::~TunerHidlFilter() {
    Mutex::Autolock _l(mLock);
    mFilter = nullptr;
    mFilter_1_1 = nullptr;
}

::ndk::ScopedAStatus TunerHidlFilter::getQueueDesc(AidlMQDesc* _aidl_return) {
    Mutex::Autolock _l(mLock);
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        IPCThreadState* ipc = IPCThreadState::self();
        int32_t callingPid = ipc->getCallingPid();
        if (callingPid == mClientPid) {
            ALOGD("%s is called in wrong process", __FUNCTION__);
            return ::ndk::ScopedAStatus::fromServiceSpecificError(
                    static_cast<int32_t>(Result::INVALID_STATE));
        }
    }

    MQDesc filterMQDesc;
    HidlResult res;
    mFilter->getQueueDesc([&](HidlResult r, const MQDesc& desc) {
        filterMQDesc = desc;
        res = r;
    });
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    AidlMQDesc aidlMQDesc;
    unsafeHidlToAidlMQDescriptor<uint8_t, int8_t, SynchronizedReadWrite>(filterMQDesc, &aidlMQDesc);
    *_aidl_return = std::move(aidlMQDesc);

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::getId(int32_t* _aidl_return) {
    Mutex::Autolock _l(mLock);
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    HidlResult res;
    mFilter->getId([&](HidlResult r, uint32_t filterId) {
        res = r;
        mId = filterId;
    });
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    *_aidl_return = mId;

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::getId64Bit(int64_t* _aidl_return) {
    Mutex::Autolock _l(mLock);
    if (mFilter_1_1 == nullptr) {
        ALOGE("IFilter_1_1 is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    HidlResult res;
    mFilter_1_1->getId64Bit([&](HidlResult r, uint64_t filterId) {
        res = r;
        mId64Bit = filterId;
    });
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    *_aidl_return = mId64Bit;

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::configure(const DemuxFilterSettings& in_settings) {
    Mutex::Autolock _l(mLock);
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    HidlDemuxFilterSettings settings;
    switch (in_settings.getTag()) {
    case DemuxFilterSettings::ts: {
        getHidlTsSettings(in_settings, settings);
        break;
    }
    case DemuxFilterSettings::mmtp: {
        getHidlMmtpSettings(in_settings, settings);
        break;
    }
    case DemuxFilterSettings::ip: {
        getHidlIpSettings(in_settings, settings);
        break;
    }
    case DemuxFilterSettings::tlv: {
        getHidlTlvSettings(in_settings, settings);
        break;
    }
    case DemuxFilterSettings::alp: {
        getHidlAlpSettings(in_settings, settings);
        break;
    }
    }

    HidlResult res = mFilter->configure(settings);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::configureMonitorEvent(int32_t monitorEventType) {
    Mutex::Autolock _l(mLock);
    if (mFilter_1_1 == nullptr) {
        ALOGE("IFilter_1_1 is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    HidlResult res = mFilter_1_1->configureMonitorEvent(monitorEventType);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::configureIpFilterContextId(int32_t cid) {
    Mutex::Autolock _l(mLock);
    if (mFilter_1_1 == nullptr) {
        ALOGE("IFilter_1_1 is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    HidlResult res = mFilter_1_1->configureIpCid(cid);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::configureAvStreamType(const AvStreamType& in_avStreamType) {
    Mutex::Autolock _l(mLock);
    if (mFilter_1_1 == nullptr) {
        ALOGE("IFilter_1_1 is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    HidlAvStreamType type;
    if (!getHidlAvStreamType(in_avStreamType, type)) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    HidlResult res = mFilter_1_1->configureAvStreamType(type);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::setDataSource(const shared_ptr<ITunerFilter>& filter) {
    Mutex::Autolock _l(mLock);
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (filter == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    sp<HidlIFilter> hidlFilter = static_cast<TunerHidlFilter*>(filter.get())->getHalFilter();
    HidlResult res = mFilter->setDataSource(hidlFilter);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::getAvSharedHandle(NativeHandle* out_avMemory,
                                                        int64_t* _aidl_return) {
    Mutex::Autolock _l(mLock);
    if (mFilter_1_1 == nullptr) {
        ALOGE("IFilter_1_1 is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    HidlResult res;
    mFilter_1_1->getAvSharedHandle([&](HidlResult r, hidl_handle avMemory, uint64_t avMemSize) {
        res = r;
        if (res == HidlResult::SUCCESS) {
            *out_avMemory = dupToAidl(avMemory);
            *_aidl_return = static_cast<int64_t>(avMemSize);
        }
    });

    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::releaseAvHandle(const NativeHandle& in_handle,
                                                      int64_t in_avDataId) {
    Mutex::Autolock _l(mLock);
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    hidl_handle handle;
    handle.setTo(makeFromAidl(in_handle), true);
    HidlResult res = mFilter->releaseAvHandle(handle, in_avDataId);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    // Call to HAL to make sure the transport FD was able to be closed by binder.
    // This is a tricky workaround for a problem in Binder.
    // TODO:[b/192048842] When that problem is fixed we may be able to remove or change this code.
    mFilter->getId([&](HidlResult /* r */, uint32_t /* filterId*/){});

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::start() {
    Mutex::Autolock _l(mLock);
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        IPCThreadState* ipc = IPCThreadState::self();
        int32_t callingPid = ipc->getCallingPid();
        if (callingPid == mClientPid) {
            ALOGD("%s is called in wrong process", __FUNCTION__);
            return ::ndk::ScopedAStatus::fromServiceSpecificError(
                    static_cast<int32_t>(Result::INVALID_STATE));
        }
    }

    HidlResult res = mFilter->start();
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    mStarted = true;

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::stop() {
    Mutex::Autolock _l(mLock);
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        IPCThreadState* ipc = IPCThreadState::self();
        int32_t callingPid = ipc->getCallingPid();
        if (callingPid == mClientPid) {
            ALOGD("%s is called in wrong process", __FUNCTION__);
            return ::ndk::ScopedAStatus::fromServiceSpecificError(
                    static_cast<int32_t>(Result::INVALID_STATE));
        }
    }

    HidlResult res = mFilter->stop();
    mStarted = false;
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::flush() {
    Mutex::Autolock _l(mLock);
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        IPCThreadState* ipc = IPCThreadState::self();
        int32_t callingPid = ipc->getCallingPid();
        if (callingPid == mClientPid) {
            ALOGD("%s is called in wrong process", __FUNCTION__);
            return ::ndk::ScopedAStatus::fromServiceSpecificError(
                    static_cast<int32_t>(Result::INVALID_STATE));
        }
    }

    HidlResult res = mFilter->flush();
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::close() {
    Mutex::Autolock _l(mLock);
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared) {
        IPCThreadState* ipc = IPCThreadState::self();
        int32_t callingPid = ipc->getCallingPid();
        if (callingPid == mClientPid) {
            if (mFilterCallback != nullptr) {
                mFilterCallback->sendSharedFilterStatus(STATUS_INACCESSIBLE);
                mFilterCallback->detachSharedFilterCallback();
            }
            TunerHidlService::getTunerService()->removeSharedFilter(this->ref<TunerHidlFilter>());
        } else {
            // Calling from shared process, do not really close this filter.
            if (mFilterCallback != nullptr) {
                mFilterCallback->detachSharedFilterCallback();
            }
            mStarted = false;
            return ::ndk::ScopedAStatus::ok();
        }
    }

    if (mFilterCallback != nullptr) {
        mFilterCallback->detachCallbacks();
    }
    HidlResult res = mFilter->close();
    mFilter = nullptr;
    mFilter_1_1 = nullptr;
    mStarted = false;
    mShared = false;
    mClientPid = -1;

    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::acquireSharedFilterToken(string* _aidl_return) {
    Mutex::Autolock _l(mLock);
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (mShared || mStarted) {
        ALOGD("create SharedFilter in wrong state");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    IPCThreadState* ipc = IPCThreadState::self();
    mClientPid = ipc->getCallingPid();
    string token =
            TunerHidlService::getTunerService()->addFilterToShared(this->ref<TunerHidlFilter>());
    _aidl_return->assign(token);
    mShared = true;

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::freeSharedFilterToken(const string& /* in_filterToken */) {
    Mutex::Autolock _l(mLock);
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (!mShared) {
        // The filter is not shared or the shared filter has been closed.
        return ::ndk::ScopedAStatus::ok();
    }

    if (mFilterCallback != nullptr) {
        mFilterCallback->sendSharedFilterStatus(STATUS_INACCESSIBLE);
        mFilterCallback->detachSharedFilterCallback();
    }

    TunerHidlService::getTunerService()->removeSharedFilter(this->ref<TunerHidlFilter>());
    mShared = false;

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::getFilterType(DemuxFilterType* _aidl_return) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    *_aidl_return = mType;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlFilter::setDelayHint(const FilterDelayHint&) {
    // setDelayHint is not supported in HIDL HAL
    return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
}

bool TunerHidlFilter::isSharedFilterAllowed(int callingPid) {
    return mShared && mClientPid != callingPid;
}

void TunerHidlFilter::attachSharedFilterCallback(const shared_ptr<ITunerFilterCallback>& in_cb) {
    if (mFilterCallback != nullptr) {
        mFilterCallback->attachSharedFilterCallback(in_cb);
    }
}

sp<HidlIFilter> TunerHidlFilter::getHalFilter() {
    return mFilter;
}

bool TunerHidlFilter::getHidlAvStreamType(const AvStreamType avStreamType, HidlAvStreamType& type) {
    if (isAudioFilter()) {
        AudioStreamType audio = avStreamType.get<AvStreamType::audio>();
        if (static_cast<int32_t>(audio) > static_cast<int32_t>(HidlAudioStreamType::DRA)) {
            return false;
        }
        type.audio(static_cast<HidlAudioStreamType>(audio));
        return true;
    }

    if (isVideoFilter()) {
        type.video(static_cast<HidlVideoStreamType>(avStreamType.get<AvStreamType::video>()));
        return true;
    }

    return false;
}

bool TunerHidlFilter::isAudioFilter() {
    return (mType.mainType == DemuxFilterMainType::TS &&
            mType.subType.get<DemuxFilterSubType::tsFilterType>() == DemuxTsFilterType::AUDIO) ||
           (mType.mainType == DemuxFilterMainType::MMTP &&
            mType.subType.get<DemuxFilterSubType::mmtpFilterType>() == DemuxMmtpFilterType::AUDIO);
}

bool TunerHidlFilter::isVideoFilter() {
    return (mType.mainType == DemuxFilterMainType::TS &&
            mType.subType.get<DemuxFilterSubType::tsFilterType>() == DemuxTsFilterType::VIDEO) ||
           (mType.mainType == DemuxFilterMainType::MMTP &&
            mType.subType.get<DemuxFilterSubType::mmtpFilterType>() == DemuxMmtpFilterType::VIDEO);
}

void TunerHidlFilter::getHidlTsSettings(const DemuxFilterSettings& settings,
                                        HidlDemuxFilterSettings& hidlSettings) {
    const DemuxTsFilterSettings& tsConf = settings.get<DemuxFilterSettings::ts>();
    HidlDemuxTsFilterSettings ts{
            .tpid = static_cast<uint16_t>(tsConf.tpid),
    };

    switch (tsConf.filterSettings.getTag()) {
    case DemuxTsFilterSettingsFilterSettings::av: {
        ts.filterSettings.av(getHidlAvSettings(
                tsConf.filterSettings.get<DemuxTsFilterSettingsFilterSettings::av>()));
        break;
    }
    case DemuxTsFilterSettingsFilterSettings::section: {
        ts.filterSettings.section(getHidlSectionSettings(
                tsConf.filterSettings.get<DemuxTsFilterSettingsFilterSettings::section>()));
        break;
    }
    case DemuxTsFilterSettingsFilterSettings::pesData: {
        ts.filterSettings.pesData(getHidlPesDataSettings(
                tsConf.filterSettings.get<DemuxTsFilterSettingsFilterSettings::pesData>()));
        break;
    }
    case DemuxTsFilterSettingsFilterSettings::record: {
        ts.filterSettings.record(getHidlRecordSettings(
                tsConf.filterSettings.get<DemuxTsFilterSettingsFilterSettings::record>()));
        break;
    }
    default: {
        ts.filterSettings.noinit();
        break;
    }
    }
    hidlSettings.ts(ts);
}

void TunerHidlFilter::getHidlMmtpSettings(const DemuxFilterSettings& settings,
                                          HidlDemuxFilterSettings& hidlSettings) {
    const DemuxMmtpFilterSettings& mmtpConf = settings.get<DemuxFilterSettings::mmtp>();
    HidlDemuxMmtpFilterSettings mmtp{
            .mmtpPid = static_cast<HidlDemuxMmtpPid>(mmtpConf.mmtpPid),
    };

    switch (mmtpConf.filterSettings.getTag()) {
    case DemuxMmtpFilterSettingsFilterSettings::av: {
        mmtp.filterSettings.av(getHidlAvSettings(
                mmtpConf.filterSettings.get<DemuxMmtpFilterSettingsFilterSettings::av>()));
        break;
    }
    case DemuxMmtpFilterSettingsFilterSettings::section: {
        mmtp.filterSettings.section(getHidlSectionSettings(
                mmtpConf.filterSettings.get<DemuxMmtpFilterSettingsFilterSettings::section>()));
        break;
    }
    case DemuxMmtpFilterSettingsFilterSettings::pesData: {
        mmtp.filterSettings.pesData(getHidlPesDataSettings(
                mmtpConf.filterSettings.get<DemuxMmtpFilterSettingsFilterSettings::pesData>()));
        break;
    }
    case DemuxMmtpFilterSettingsFilterSettings::record: {
        mmtp.filterSettings.record(getHidlRecordSettings(
                mmtpConf.filterSettings.get<DemuxMmtpFilterSettingsFilterSettings::record>()));
        break;
    }
    case DemuxMmtpFilterSettingsFilterSettings::download: {
        mmtp.filterSettings.download(getHidlDownloadSettings(
                mmtpConf.filterSettings.get<DemuxMmtpFilterSettingsFilterSettings::download>()));
        break;
    }
    default: {
        mmtp.filterSettings.noinit();
        break;
    }
    }
    hidlSettings.mmtp(mmtp);
}

void TunerHidlFilter::getHidlIpSettings(const DemuxFilterSettings& settings,
                                        HidlDemuxFilterSettings& hidlSettings) {
    const DemuxIpFilterSettings& ipConf = settings.get<DemuxFilterSettings::ip>();
    HidlDemuxIpAddress ipAddr{
            .srcPort = static_cast<uint16_t>(ipConf.ipAddr.srcPort),
            .dstPort = static_cast<uint16_t>(ipConf.ipAddr.dstPort),
    };

    ipConf.ipAddr.srcIpAddress.getTag() == DemuxIpAddressIpAddress::v6
            ? ipAddr.srcIpAddress.v6(getIpV6Address(ipConf.ipAddr.srcIpAddress))
            : ipAddr.srcIpAddress.v4(getIpV4Address(ipConf.ipAddr.srcIpAddress));
    ipConf.ipAddr.dstIpAddress.getTag() == DemuxIpAddressIpAddress::v6
            ? ipAddr.dstIpAddress.v6(getIpV6Address(ipConf.ipAddr.dstIpAddress))
            : ipAddr.dstIpAddress.v4(getIpV4Address(ipConf.ipAddr.dstIpAddress));

    HidlDemuxIpFilterSettings ip;
    ip.ipAddr = ipAddr;

    switch (ipConf.filterSettings.getTag()) {
    case DemuxIpFilterSettingsFilterSettings::section: {
        ip.filterSettings.section(getHidlSectionSettings(
                ipConf.filterSettings.get<DemuxIpFilterSettingsFilterSettings::section>()));
        break;
    }
    case DemuxIpFilterSettingsFilterSettings::bPassthrough: {
        ip.filterSettings.bPassthrough(
                ipConf.filterSettings.get<DemuxIpFilterSettingsFilterSettings::bPassthrough>());
        break;
    }
    default: {
        ip.filterSettings.noinit();
        break;
    }
    }
    hidlSettings.ip(ip);
}

hidl_array<uint8_t, IP_V6_LENGTH> TunerHidlFilter::getIpV6Address(
        const DemuxIpAddressIpAddress& addr) {
    hidl_array<uint8_t, IP_V6_LENGTH> ip;
    if (addr.get<DemuxIpAddressIpAddress::v6>().size() != IP_V6_LENGTH) {
        return ip;
    }
    copy(addr.get<DemuxIpAddressIpAddress::v6>().begin(),
         addr.get<DemuxIpAddressIpAddress::v6>().end(), ip.data());
    return ip;
}

hidl_array<uint8_t, IP_V4_LENGTH> TunerHidlFilter::getIpV4Address(
        const DemuxIpAddressIpAddress& addr) {
    hidl_array<uint8_t, IP_V4_LENGTH> ip;
    if (addr.get<DemuxIpAddressIpAddress::v4>().size() != IP_V4_LENGTH) {
        return ip;
    }
    copy(addr.get<DemuxIpAddressIpAddress::v4>().begin(),
         addr.get<DemuxIpAddressIpAddress::v4>().end(), ip.data());
    return ip;
}

void TunerHidlFilter::getHidlTlvSettings(const DemuxFilterSettings& settings,
                                         HidlDemuxFilterSettings& hidlSettings) {
    const DemuxTlvFilterSettings& tlvConf = settings.get<DemuxFilterSettings::tlv>();
    HidlDemuxTlvFilterSettings tlv{
            .packetType = static_cast<uint8_t>(tlvConf.packetType),
            .isCompressedIpPacket = tlvConf.isCompressedIpPacket,
    };

    switch (tlvConf.filterSettings.getTag()) {
    case DemuxTlvFilterSettingsFilterSettings::section: {
        tlv.filterSettings.section(getHidlSectionSettings(
                tlvConf.filterSettings.get<DemuxTlvFilterSettingsFilterSettings::section>()));
        break;
    }
    case DemuxTlvFilterSettingsFilterSettings::bPassthrough: {
        tlv.filterSettings.bPassthrough(
                tlvConf.filterSettings.get<DemuxTlvFilterSettingsFilterSettings::bPassthrough>());
        break;
    }
    default: {
        tlv.filterSettings.noinit();
        break;
    }
    }
    hidlSettings.tlv(tlv);
}

void TunerHidlFilter::getHidlAlpSettings(const DemuxFilterSettings& settings,
                                         HidlDemuxFilterSettings& hidlSettings) {
    const DemuxAlpFilterSettings& alpConf = settings.get<DemuxFilterSettings::alp>();
    HidlDemuxAlpFilterSettings alp{
            .packetType = static_cast<uint8_t>(alpConf.packetType),
            .lengthType = static_cast<HidlDemuxAlpLengthType>(alpConf.lengthType),
    };

    switch (alpConf.filterSettings.getTag()) {
    case DemuxAlpFilterSettingsFilterSettings::section: {
        alp.filterSettings.section(getHidlSectionSettings(
                alpConf.filterSettings.get<DemuxAlpFilterSettingsFilterSettings::section>()));
        break;
    }
    default: {
        alp.filterSettings.noinit();
        break;
    }
    }
    hidlSettings.alp(alp);
}

HidlDemuxFilterAvSettings TunerHidlFilter::getHidlAvSettings(
        const DemuxFilterAvSettings& settings) {
    HidlDemuxFilterAvSettings av{
            .isPassthrough = settings.isPassthrough,
    };
    return av;
}

HidlDemuxFilterSectionSettings TunerHidlFilter::getHidlSectionSettings(
        const DemuxFilterSectionSettings& settings) {
    HidlDemuxFilterSectionSettings section{
            .isCheckCrc = settings.isCheckCrc,
            .isRepeat = settings.isRepeat,
            .isRaw = settings.isRaw,
    };

    switch (settings.condition.getTag()) {
    case DemuxFilterSectionSettingsCondition::sectionBits: {
        const DemuxFilterSectionBits& sectionBits =
                settings.condition.get<DemuxFilterSectionSettingsCondition::sectionBits>();
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
    case DemuxFilterSectionSettingsCondition::tableInfo: {
        const DemuxFilterSectionSettingsConditionTableInfo& tableInfo =
                settings.condition.get<DemuxFilterSectionSettingsCondition::tableInfo>();
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

HidlDemuxFilterPesDataSettings TunerHidlFilter::getHidlPesDataSettings(
        const DemuxFilterPesDataSettings& settings) {
    HidlDemuxFilterPesDataSettings pes{
            .streamId = static_cast<HidlDemuxStreamId>(settings.streamId),
            .isRaw = settings.isRaw,
    };
    return pes;
}

HidlDemuxFilterRecordSettings TunerHidlFilter::getHidlRecordSettings(
        const DemuxFilterRecordSettings& settings) {
    HidlDemuxFilterRecordSettings record{
            .tsIndexMask = static_cast<uint32_t>(settings.tsIndexMask),
    };

    switch (settings.scIndexMask.getTag()) {
    case DemuxFilterScIndexMask::scIndex: {
        record.scIndexType = static_cast<HidlDemuxRecordScIndexType>(settings.scIndexType);
        record.scIndexMask.sc(
                static_cast<uint32_t>(settings.scIndexMask.get<DemuxFilterScIndexMask::scIndex>()));
        break;
    }
    case DemuxFilterScIndexMask::scAvc: {
        record.scIndexType = HidlDemuxRecordScIndexType::SC;
        uint32_t index =
                static_cast<uint32_t>(settings.scIndexMask.get<DemuxFilterScIndexMask::scAvc>());
        // HIDL HAL starting from 1 << 4; AIDL starting from 1 << 0.
        index = index << 4;
        record.scIndexMask.sc(index);
        break;
    }
    case DemuxFilterScIndexMask::scHevc: {
        record.scIndexType = static_cast<HidlDemuxRecordScIndexType>(settings.scIndexType);
        record.scIndexMask.scHevc(
                static_cast<uint32_t>(settings.scIndexMask.get<DemuxFilterScIndexMask::scHevc>()));
        break;
    }
    }
    return record;
}

HidlDemuxFilterDownloadSettings TunerHidlFilter::getHidlDownloadSettings(
        const DemuxFilterDownloadSettings& settings) {
    HidlDemuxFilterDownloadSettings download{
            .downloadId = static_cast<uint32_t>(settings.downloadId),
    };
    return download;
}

/////////////// FilterCallback ///////////////////////
Return<void> TunerHidlFilter::FilterCallback::onFilterStatus(HidlDemuxFilterStatus status) {
    Mutex::Autolock _l(mCallbackLock);
    if (mTunerFilterCallback != nullptr) {
        mTunerFilterCallback->onFilterStatus(static_cast<DemuxFilterStatus>(status));
    }
    return Void();
}

Return<void> TunerHidlFilter::FilterCallback::onFilterEvent(
        const HidlDemuxFilterEvent& filterEvent) {
    vector<HidlDemuxFilterEventExt::Event> emptyEventsExt;
    HidlDemuxFilterEventExt emptyFilterEventExt{
            .events = emptyEventsExt,
    };
    onFilterEvent_1_1(filterEvent, emptyFilterEventExt);
    return Void();
}

Return<void> TunerHidlFilter::FilterCallback::onFilterEvent_1_1(
        const HidlDemuxFilterEvent& filterEvent, const HidlDemuxFilterEventExt& filterEventExt) {
    Mutex::Autolock _l(mCallbackLock);
    if (mTunerFilterCallback != nullptr) {
        vector<HidlDemuxFilterEvent::Event> events = filterEvent.events;
        vector<HidlDemuxFilterEventExt::Event> eventsExt = filterEventExt.events;
        vector<DemuxFilterEvent> tunerEvents;

        getAidlFilterEvent(events, eventsExt, tunerEvents);
        mTunerFilterCallback->onFilterEvent(tunerEvents);
    }
    return Void();
}

void TunerHidlFilter::FilterCallback::sendSharedFilterStatus(int32_t status) {
    Mutex::Autolock _l(mCallbackLock);
    if (mTunerFilterCallback != nullptr && mOriginalCallback != nullptr) {
        mTunerFilterCallback->onFilterStatus(static_cast<DemuxFilterStatus>(status));
    }
}

void TunerHidlFilter::FilterCallback::attachSharedFilterCallback(
        const shared_ptr<ITunerFilterCallback>& in_cb) {
    Mutex::Autolock _l(mCallbackLock);
    mOriginalCallback = mTunerFilterCallback;
    mTunerFilterCallback = in_cb;
}

void TunerHidlFilter::FilterCallback::detachSharedFilterCallback() {
    Mutex::Autolock _l(mCallbackLock);
    if (mTunerFilterCallback != nullptr && mOriginalCallback != nullptr) {
        mTunerFilterCallback = mOriginalCallback;
        mOriginalCallback = nullptr;
    }
}

void TunerHidlFilter::FilterCallback::detachCallbacks() {
    Mutex::Autolock _l(mCallbackLock);
    mOriginalCallback = nullptr;
    mTunerFilterCallback = nullptr;
}

/////////////// FilterCallback Helper Methods ///////////////////////
void TunerHidlFilter::FilterCallback::getAidlFilterEvent(
        const vector<HidlDemuxFilterEvent::Event>& events,
        const vector<HidlDemuxFilterEventExt::Event>& eventsExt,
        vector<DemuxFilterEvent>& aidlEvents) {
    if (events.empty() && !eventsExt.empty()) {
        switch (eventsExt[0].getDiscriminator()) {
        case HidlDemuxFilterEventExt::Event::hidl_discriminator::monitorEvent: {
            getMonitorEvent(eventsExt, aidlEvents);
            break;
        }
        case HidlDemuxFilterEventExt::Event::hidl_discriminator::startId: {
            getRestartEvent(eventsExt, aidlEvents);
            break;
        }
        default: {
            break;
        }
        }
    }

    if (!events.empty()) {
        switch (events[0].getDiscriminator()) {
        case HidlDemuxFilterEvent::Event::hidl_discriminator::media: {
            getMediaEvent(events, aidlEvents);
            break;
        }
        case HidlDemuxFilterEvent::Event::hidl_discriminator::section: {
            getSectionEvent(events, aidlEvents);
            break;
        }
        case HidlDemuxFilterEvent::Event::hidl_discriminator::pes: {
            getPesEvent(events, aidlEvents);
            break;
        }
        case HidlDemuxFilterEvent::Event::hidl_discriminator::tsRecord: {
            getTsRecordEvent(events, eventsExt, aidlEvents);
            break;
        }
        case HidlDemuxFilterEvent::Event::hidl_discriminator::mmtpRecord: {
            getMmtpRecordEvent(events, eventsExt, aidlEvents);
            break;
        }
        case HidlDemuxFilterEvent::Event::hidl_discriminator::download: {
            getDownloadEvent(events, aidlEvents);
            break;
        }
        case HidlDemuxFilterEvent::Event::hidl_discriminator::ipPayload: {
            getIpPayloadEvent(events, aidlEvents);
            break;
        }
        case HidlDemuxFilterEvent::Event::hidl_discriminator::temi: {
            getTemiEvent(events, aidlEvents);
            break;
        }
        default: {
            break;
        }
        }
    }
}

void TunerHidlFilter::FilterCallback::getMediaEvent(
        const vector<HidlDemuxFilterEvent::Event>& events, vector<DemuxFilterEvent>& res) {
    for (int i = 0; i < events.size(); i++) {
        const HidlDemuxFilterMediaEvent& mediaEvent = events[i].media();
        DemuxFilterMediaEvent media;

        media.streamId = static_cast<int32_t>(mediaEvent.streamId);
        media.isPtsPresent = mediaEvent.isPtsPresent;
        media.pts = static_cast<int64_t>(mediaEvent.pts);
        media.isDtsPresent = false;
        media.dts = static_cast<int64_t>(-1);
        media.dataLength = static_cast<int64_t>(mediaEvent.dataLength);
        media.offset = static_cast<int64_t>(mediaEvent.offset);
        media.isSecureMemory = mediaEvent.isSecureMemory;
        media.avDataId = static_cast<int64_t>(mediaEvent.avDataId);
        media.mpuSequenceNumber = static_cast<int32_t>(mediaEvent.mpuSequenceNumber);
        media.isPesPrivateData = mediaEvent.isPesPrivateData;
        media.scIndexMask.set<DemuxFilterScIndexMask::scIndex>(
                static_cast<int32_t>(DemuxScIndex::UNDEFINED));

        if (mediaEvent.extraMetaData.getDiscriminator() ==
            HidlDemuxFilterMediaEvent::ExtraMetaData::hidl_discriminator::audio) {
            AudioExtraMetaData audio;
            audio.adFade = static_cast<int8_t>(mediaEvent.extraMetaData.audio().adFade);
            audio.adPan = static_cast<int8_t>(mediaEvent.extraMetaData.audio().adPan);
            audio.versionTextTag =
                    static_cast<int16_t>(mediaEvent.extraMetaData.audio().versionTextTag);
            audio.adGainCenter = static_cast<int8_t>(mediaEvent.extraMetaData.audio().adGainCenter);
            audio.adGainFront = static_cast<int8_t>(mediaEvent.extraMetaData.audio().adGainFront);
            audio.adGainSurround =
                    static_cast<int8_t>(mediaEvent.extraMetaData.audio().adGainSurround);
            media.extraMetaData.set<DemuxFilterMediaEventExtraMetaData::audio>(audio);
        } else {
            media.extraMetaData.set<DemuxFilterMediaEventExtraMetaData::noinit>(true);
        }

        if (mediaEvent.avMemory.getNativeHandle() != nullptr) {
            media.avMemory = dupToAidl(mediaEvent.avMemory.getNativeHandle());
        }

        DemuxFilterEvent filterEvent;
        filterEvent.set<DemuxFilterEvent::media>(std::move(media));
        res.push_back(std::move(filterEvent));
    }
}

void TunerHidlFilter::FilterCallback::getSectionEvent(
        const vector<HidlDemuxFilterEvent::Event>& events, vector<DemuxFilterEvent>& res) {
    for (int i = 0; i < events.size(); i++) {
        const HidlDemuxFilterSectionEvent& sectionEvent = events[i].section();
        DemuxFilterSectionEvent section;

        section.tableId = static_cast<int32_t>(sectionEvent.tableId);
        section.version = static_cast<int32_t>(sectionEvent.version);
        section.sectionNum = static_cast<int32_t>(sectionEvent.sectionNum);
        section.dataLength = static_cast<int64_t>(sectionEvent.dataLength);

        DemuxFilterEvent filterEvent;
        filterEvent.set<DemuxFilterEvent::section>(std::move(section));
        res.push_back(std::move(filterEvent));
    }
}

void TunerHidlFilter::FilterCallback::getPesEvent(const vector<HidlDemuxFilterEvent::Event>& events,
                                                  vector<DemuxFilterEvent>& res) {
    for (int i = 0; i < events.size(); i++) {
        const HidlDemuxFilterPesEvent& pesEvent = events[i].pes();
        DemuxFilterPesEvent pes;

        pes.streamId = static_cast<int32_t>(pesEvent.streamId);
        pes.dataLength = static_cast<int32_t>(pesEvent.dataLength);
        pes.mpuSequenceNumber = static_cast<int32_t>(pesEvent.mpuSequenceNumber);

        DemuxFilterEvent filterEvent;
        filterEvent.set<DemuxFilterEvent::pes>(std::move(pes));
        res.push_back(std::move(filterEvent));
    }
}

void TunerHidlFilter::FilterCallback::getTsRecordEvent(
        const vector<HidlDemuxFilterEvent::Event>& events,
        const vector<HidlDemuxFilterEventExt::Event>& eventsExt, vector<DemuxFilterEvent>& res) {
    for (int i = 0; i < events.size(); i++) {
        DemuxFilterTsRecordEvent tsRecord;
        const HidlDemuxFilterTsRecordEvent& tsRecordEvent = events[i].tsRecord();

        DemuxFilterScIndexMask scIndexMask;
        if (tsRecordEvent.scIndexMask.getDiscriminator() ==
            HidlDemuxFilterTsRecordEvent::ScIndexMask::hidl_discriminator::sc) {
            int32_t hidlScIndex = static_cast<int32_t>(tsRecordEvent.scIndexMask.sc());
            if (hidlScIndex <= static_cast<int32_t>(DemuxScIndex::SEQUENCE)) {
                scIndexMask.set<DemuxFilterScIndexMask::scIndex>(hidlScIndex);
            } else {
                // HIDL HAL starting from 1 << 4; AIDL starting from 1 << 0.
                scIndexMask.set<DemuxFilterScIndexMask::scAvc>(hidlScIndex >> 4);
            }
        } else if (tsRecordEvent.scIndexMask.getDiscriminator() ==
                   HidlDemuxFilterTsRecordEvent::ScIndexMask::hidl_discriminator::scHevc) {
            scIndexMask.set<DemuxFilterScIndexMask::scHevc>(
                    static_cast<int32_t>(tsRecordEvent.scIndexMask.scHevc()));
        }

        if (tsRecordEvent.pid.getDiscriminator() == HidlDemuxPid::hidl_discriminator::tPid) {
            DemuxPid pid;
            pid.set<DemuxPid::tPid>(static_cast<int32_t>(tsRecordEvent.pid.tPid()));
            tsRecord.pid = pid;
        } else {
            DemuxPid pid;
            pid.set<DemuxPid::tPid>(static_cast<int32_t>(Constant::INVALID_TS_PID));
            tsRecord.pid = pid;
        }

        tsRecord.scIndexMask = scIndexMask;
        tsRecord.tsIndexMask = static_cast<int32_t>(tsRecordEvent.tsIndexMask);
        tsRecord.byteNumber = static_cast<int64_t>(tsRecordEvent.byteNumber);

        if (eventsExt.size() > i &&
            eventsExt[i].getDiscriminator() ==
                    HidlDemuxFilterEventExt::Event::hidl_discriminator::tsRecord) {
            tsRecord.pts = static_cast<int64_t>(eventsExt[i].tsRecord().pts);
            tsRecord.firstMbInSlice = static_cast<int32_t>(eventsExt[i].tsRecord().firstMbInSlice);
        }

        DemuxFilterEvent filterEvent;
        filterEvent.set<DemuxFilterEvent::tsRecord>(std::move(tsRecord));
        res.push_back(std::move(filterEvent));
    }
}

void TunerHidlFilter::FilterCallback::getMmtpRecordEvent(
        const vector<HidlDemuxFilterEvent::Event>& events,
        const vector<HidlDemuxFilterEventExt::Event>& eventsExt, vector<DemuxFilterEvent>& res) {
    for (int i = 0; i < events.size(); i++) {
        DemuxFilterMmtpRecordEvent mmtpRecord;
        const HidlDemuxFilterMmtpRecordEvent& mmtpRecordEvent = events[i].mmtpRecord();

        mmtpRecord.scHevcIndexMask = static_cast<int32_t>(mmtpRecordEvent.scHevcIndexMask);
        mmtpRecord.byteNumber = static_cast<int64_t>(mmtpRecordEvent.byteNumber);

        if (eventsExt.size() > i &&
            eventsExt[i].getDiscriminator() ==
                    HidlDemuxFilterEventExt::Event::hidl_discriminator::mmtpRecord) {
            mmtpRecord.pts = static_cast<int64_t>(eventsExt[i].mmtpRecord().pts);
            mmtpRecord.mpuSequenceNumber =
                    static_cast<int32_t>(eventsExt[i].mmtpRecord().mpuSequenceNumber);
            mmtpRecord.firstMbInSlice =
                    static_cast<int32_t>(eventsExt[i].mmtpRecord().firstMbInSlice);
            mmtpRecord.tsIndexMask = static_cast<int32_t>(eventsExt[i].mmtpRecord().tsIndexMask);
        }

        DemuxFilterEvent filterEvent;
        filterEvent.set<DemuxFilterEvent::mmtpRecord>(std::move(mmtpRecord));
        res.push_back(std::move(filterEvent));
    }
}

void TunerHidlFilter::FilterCallback::getDownloadEvent(
        const vector<HidlDemuxFilterEvent::Event>& events, vector<DemuxFilterEvent>& res) {
    for (int i = 0; i < events.size(); i++) {
        const HidlDemuxFilterDownloadEvent& downloadEvent = events[i].download();
        DemuxFilterDownloadEvent download;

        download.itemId = static_cast<int32_t>(downloadEvent.itemId);
        download.downloadId = -1;
        download.itemFragmentIndex = static_cast<int32_t>(downloadEvent.itemFragmentIndex);
        download.mpuSequenceNumber = static_cast<int32_t>(downloadEvent.mpuSequenceNumber);
        download.lastItemFragmentIndex = static_cast<int32_t>(downloadEvent.lastItemFragmentIndex);
        download.dataLength = static_cast<int32_t>(downloadEvent.dataLength);

        DemuxFilterEvent filterEvent;
        filterEvent.set<DemuxFilterEvent::download>(std::move(download));
        res.push_back(std::move(filterEvent));
    }
}

void TunerHidlFilter::FilterCallback::getIpPayloadEvent(
        const vector<HidlDemuxFilterEvent::Event>& events, vector<DemuxFilterEvent>& res) {
    for (int i = 0; i < events.size(); i++) {
        const HidlDemuxFilterIpPayloadEvent& ipPayloadEvent = events[i].ipPayload();
        DemuxFilterIpPayloadEvent ipPayload;

        ipPayload.dataLength = static_cast<int32_t>(ipPayloadEvent.dataLength);

        DemuxFilterEvent filterEvent;
        filterEvent.set<DemuxFilterEvent::ipPayload>(std::move(ipPayload));
        res.push_back(std::move(filterEvent));
    }
}

void TunerHidlFilter::FilterCallback::getTemiEvent(
        const vector<HidlDemuxFilterEvent::Event>& events, vector<DemuxFilterEvent>& res) {
    for (int i = 0; i < events.size(); i++) {
        const HidlDemuxFilterTemiEvent& temiEvent = events[i].temi();
        DemuxFilterTemiEvent temi;

        temi.pts = static_cast<int64_t>(temiEvent.pts);
        temi.descrTag = static_cast<int8_t>(temiEvent.descrTag);
        vector<uint8_t> descrData = temiEvent.descrData;
        temi.descrData.resize(descrData.size());
        copy(descrData.begin(), descrData.end(), temi.descrData.begin());

        DemuxFilterEvent filterEvent;
        filterEvent.set<DemuxFilterEvent::temi>(std::move(temi));
        res.push_back(std::move(filterEvent));
    }
}

void TunerHidlFilter::FilterCallback::getMonitorEvent(
        const vector<HidlDemuxFilterEventExt::Event>& eventsExt, vector<DemuxFilterEvent>& res) {
    HidlDemuxFilterMonitorEvent monitorEvent = eventsExt[0].monitorEvent();
    DemuxFilterMonitorEvent monitor;

    switch (monitorEvent.getDiscriminator()) {
    case HidlDemuxFilterMonitorEvent::hidl_discriminator::scramblingStatus: {
        monitor.set<DemuxFilterMonitorEvent::scramblingStatus>(
                static_cast<ScramblingStatus>(monitorEvent.scramblingStatus()));
        break;
    }
    case HidlDemuxFilterMonitorEvent::hidl_discriminator::cid: {
        monitor.set<DemuxFilterMonitorEvent::cid>(static_cast<int32_t>(monitorEvent.cid()));
        break;
    }
    }

    DemuxFilterEvent filterEvent;
    filterEvent.set<DemuxFilterEvent::monitorEvent>(std::move(monitor));
    res.push_back(std::move(filterEvent));
}

void TunerHidlFilter::FilterCallback::getRestartEvent(
        const vector<HidlDemuxFilterEventExt::Event>& eventsExt, vector<DemuxFilterEvent>& res) {
    DemuxFilterEvent filterEvent;
    filterEvent.set<DemuxFilterEvent::startId>(static_cast<int32_t>(eventsExt[0].startId()));
    res.push_back(std::move(filterEvent));
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
