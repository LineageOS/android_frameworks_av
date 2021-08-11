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

#include <aidl/android/hardware/tv/tuner/Result.h>

using ::aidl::android::hardware::tv::tuner::Result;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

using namespace std;

TunerFilter::TunerFilter(shared_ptr<IFilter> filter, DemuxFilterType type)
      : mFilter(filter), mType(type) {}

TunerFilter::~TunerFilter() {
    mFilter = nullptr;
}

::ndk::ScopedAStatus TunerFilter::getQueueDesc(AidlMQDesc* _aidl_return) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mFilter->getQueueDesc(_aidl_return);
}

::ndk::ScopedAStatus TunerFilter::getId(int32_t* _aidl_return) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    auto status = mFilter->getId(&mId);
    if (status.isOk()) {
        *_aidl_return = mId;
    }
    return status;
}

::ndk::ScopedAStatus TunerFilter::getId64Bit(int64_t* _aidl_return) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    auto status = mFilter->getId64Bit(&mId64Bit);
    if (status.isOk()) {
        *_aidl_return = mId64Bit;
    }
    return status;
}

::ndk::ScopedAStatus TunerFilter::configure(const DemuxFilterSettings& in_settings) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mFilter->configure(in_settings);
}

::ndk::ScopedAStatus TunerFilter::configureMonitorEvent(int32_t monitorEventType) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mFilter->configureMonitorEvent(monitorEventType);
}

::ndk::ScopedAStatus TunerFilter::configureIpFilterContextId(int32_t cid) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mFilter->configureIpCid(cid);
}

::ndk::ScopedAStatus TunerFilter::configureAvStreamType(const AvStreamType& in_avStreamType) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mFilter->configureAvStreamType(in_avStreamType);
}

::ndk::ScopedAStatus TunerFilter::setDataSource(const shared_ptr<ITunerFilter>& filter) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (filter == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    shared_ptr<IFilter> halFilter = static_cast<TunerFilter*>(filter.get())->getHalFilter();
    return mFilter->setDataSource(halFilter);
}

::ndk::ScopedAStatus TunerFilter::getAvSharedHandle(NativeHandle* out_avMemory,
                                                    int64_t* _aidl_return) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mFilter->getAvSharedHandle(out_avMemory, _aidl_return);
}

::ndk::ScopedAStatus TunerFilter::releaseAvHandle(const NativeHandle& in_handle,
                                                  int64_t in_avDataId) {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mFilter->releaseAvHandle(in_handle, in_avDataId);
}

::ndk::ScopedAStatus TunerFilter::start() {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mFilter->start();
}

::ndk::ScopedAStatus TunerFilter::stop() {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mFilter->stop();
}

::ndk::ScopedAStatus TunerFilter::flush() {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mFilter->flush();
}

::ndk::ScopedAStatus TunerFilter::close() {
    if (mFilter == nullptr) {
        ALOGE("IFilter is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }
    auto res = mFilter->close();
    mFilter = nullptr;

    return res;
}

shared_ptr<IFilter> TunerFilter::getHalFilter() {
    return mFilter;
}

/////////////// FilterCallback ///////////////////////
::ndk::ScopedAStatus TunerFilter::FilterCallback::onFilterStatus(DemuxFilterStatus status) {
    if (mTunerFilterCallback != nullptr) {
        mTunerFilterCallback->onFilterStatus(status);
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerFilter::FilterCallback::onFilterEvent(
        const vector<DemuxFilterEvent>& events) {
    if (mTunerFilterCallback != nullptr) {
        mTunerFilterCallback->onFilterEvent(events);
    }
    return ::ndk::ScopedAStatus::ok();
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
