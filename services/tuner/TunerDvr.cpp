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

#define LOG_TAG "TunerDvr"

#include <fmq/ConvertMQDescriptors.h>
#include "TunerDvr.h"
#include "TunerFilter.h"

using ::android::hardware::tv::tuner::V1_0::DataFormat;
using ::android::hardware::tv::tuner::V1_0::Result;

namespace android {

TunerDvr::TunerDvr(sp<IDvr> dvr, int type) {
    mDvr = dvr;
    mType = static_cast<DvrType>(type);
}

TunerDvr::~TunerDvr() {
    mDvr = NULL;
}

Status TunerDvr::getQueueDesc(AidlMQDesc* _aidl_return) {
    if (mDvr == NULL) {
        ALOGE("IDvr is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    MQDesc dvrMQDesc;
    Result res;
    mDvr->getQueueDesc([&](Result r, const MQDesc& desc) {
        dvrMQDesc = desc;
        res = r;
    });
    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    AidlMQDesc aidlMQDesc;
    unsafeHidlToAidlMQDescriptor<uint8_t, int8_t, SynchronizedReadWrite>(
                dvrMQDesc,  &aidlMQDesc);
    *_aidl_return = move(aidlMQDesc);
    return Status::ok();
}

Status TunerDvr::configure(const TunerDvrSettings& settings) {
    if (mDvr == NULL) {
        ALOGE("IDvr is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mDvr->configure(getHidlDvrSettingsFromAidl(settings));
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDvr::attachFilter(const shared_ptr<ITunerFilter>& filter) {
    if (mDvr == NULL) {
        ALOGE("IDvr is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    ITunerFilter* tunerFilter = filter.get();
    sp<IFilter> hidlFilter = static_cast<TunerFilter*>(tunerFilter)->getHalFilter();
    if (hidlFilter == NULL) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    Result res = mDvr->attachFilter(hidlFilter);
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDvr::detachFilter(const shared_ptr<ITunerFilter>& filter) {
    if (mDvr == NULL) {
        ALOGE("IDvr is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    ITunerFilter* tunerFilter = filter.get();
    sp<IFilter> hidlFilter = static_cast<TunerFilter*>(tunerFilter)->getHalFilter();
    if (hidlFilter == NULL) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    Result res = mDvr->detachFilter(hidlFilter);
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDvr::start() {
    if (mDvr == NULL) {
        ALOGE("IDvr is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mDvr->start();
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDvr::stop() {
    if (mDvr == NULL) {
        ALOGE("IDvr is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mDvr->stop();
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDvr::flush() {
    if (mDvr == NULL) {
        ALOGE("IDvr is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mDvr->flush();
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDvr::close() {
    if (mDvr == NULL) {
        ALOGE("IDvr is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mDvr->close();
    mDvr = NULL;

    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

DvrSettings TunerDvr::getHidlDvrSettingsFromAidl(TunerDvrSettings settings) {
    DvrSettings s;
    switch (mType) {
        case DvrType::PLAYBACK: {
            s.playback({
                .statusMask = static_cast<uint8_t>(settings.statusMask),
                .lowThreshold = static_cast<uint32_t>(settings.lowThreshold),
                .highThreshold = static_cast<uint32_t>(settings.highThreshold),
                .dataFormat = static_cast<DataFormat>(settings.dataFormat),
                .packetSize = static_cast<uint8_t>(settings.packetSize),
            });
            return s;
        }
        case DvrType::RECORD: {
            s.record({
                .statusMask = static_cast<uint8_t>(settings.statusMask),
                .lowThreshold = static_cast<uint32_t>(settings.lowThreshold),
                .highThreshold = static_cast<uint32_t>(settings.highThreshold),
                .dataFormat = static_cast<DataFormat>(settings.dataFormat),
                .packetSize = static_cast<uint8_t>(settings.packetSize),
            });
            return s;
        }
        default:
            break;
    }
    return s;
}

/////////////// IDvrCallback ///////////////////////

Return<void> TunerDvr::DvrCallback::onRecordStatus(const RecordStatus status) {
    if (mTunerDvrCallback != NULL) {
        mTunerDvrCallback->onRecordStatus(static_cast<int>(status));
    }
    return Void();
}

Return<void> TunerDvr::DvrCallback::onPlaybackStatus(const PlaybackStatus status) {
    if (mTunerDvrCallback != NULL) {
        mTunerDvrCallback->onPlaybackStatus(static_cast<int>(status));
    }
    return Void();
}
}  // namespace android
