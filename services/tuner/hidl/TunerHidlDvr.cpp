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

#define LOG_TAG "TunerHidlDvr"

#include "TunerHidlDvr.h"

#include <aidl/android/hardware/tv/tuner/DataFormat.h>
#include <aidl/android/hardware/tv/tuner/PlaybackStatus.h>
#include <aidl/android/hardware/tv/tuner/RecordStatus.h>
#include <aidl/android/hardware/tv/tuner/Result.h>
#include <fmq/ConvertMQDescriptors.h>

using ::aidl::android::hardware::tv::tuner::DataFormat;
using ::aidl::android::hardware::tv::tuner::PlaybackStatus;
using ::aidl::android::hardware::tv::tuner::RecordStatus;
using ::aidl::android::hardware::tv::tuner::Result;
using ::android::unsafeHidlToAidlMQDescriptor;
using ::android::hardware::MessageQueue;
using ::android::hardware::MQDescriptorSync;

using HidlDataFormat = ::android::hardware::tv::tuner::V1_0::DataFormat;
using HidlResult = ::android::hardware::tv::tuner::V1_0::Result;
using MQDesc = MQDescriptorSync<uint8_t>;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerHidlDvr::TunerHidlDvr(sp<HidlIDvr> dvr, DvrType type) {
    mDvr = dvr;
    mType = type;
}

TunerHidlDvr::~TunerHidlDvr() {
    mDvr = nullptr;
}

::ndk::ScopedAStatus TunerHidlDvr::getQueueDesc(AidlMQDesc* _aidl_return) {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    MQDesc dvrMQDesc;
    HidlResult res;
    mDvr->getQueueDesc([&](HidlResult r, const MQDesc& desc) {
        dvrMQDesc = desc;
        res = r;
    });
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }

    AidlMQDesc aidlMQDesc;
    unsafeHidlToAidlMQDescriptor<uint8_t, int8_t, SynchronizedReadWrite>(dvrMQDesc, &aidlMQDesc);
    *_aidl_return = std::move(aidlMQDesc);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDvr::configure(const DvrSettings& in_settings) {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    HidlResult res = mDvr->configure(getHidlDvrSettings(in_settings));
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDvr::attachFilter(const shared_ptr<ITunerFilter>& in_filter) {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (in_filter == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    sp<HidlIFilter> hidlFilter = static_cast<TunerHidlFilter*>(in_filter.get())->getHalFilter();
    if (hidlFilter == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    HidlResult res = mDvr->attachFilter(hidlFilter);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDvr::detachFilter(const shared_ptr<ITunerFilter>& in_filter) {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (in_filter == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    sp<HidlIFilter> halFilter = (static_cast<TunerHidlFilter*>(in_filter.get()))->getHalFilter();
    if (halFilter == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    HidlResult res = mDvr->detachFilter(halFilter);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDvr::start() {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    HidlResult res = mDvr->start();
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDvr::stop() {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    HidlResult res = mDvr->stop();
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDvr::flush() {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    HidlResult res = mDvr->flush();
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDvr::close() {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    HidlResult res = mDvr->close();
    mDvr = nullptr;

    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

HidlDvrSettings TunerHidlDvr::getHidlDvrSettings(const DvrSettings& settings) {
    HidlDvrSettings s;
    switch (mType) {
    case DvrType::PLAYBACK: {
        s.playback({
                .statusMask =
                        static_cast<uint8_t>(settings.get<DvrSettings::playback>().statusMask),
                .lowThreshold =
                        static_cast<uint32_t>(settings.get<DvrSettings::playback>().lowThreshold),
                .highThreshold =
                        static_cast<uint32_t>(settings.get<DvrSettings::playback>().highThreshold),
                .dataFormat = static_cast<HidlDataFormat>(
                        settings.get<DvrSettings::playback>().dataFormat),
                .packetSize =
                        static_cast<uint8_t>(settings.get<DvrSettings::playback>().packetSize),
        });
        return s;
    }
    case DvrType::RECORD: {
        s.record({
                .statusMask = static_cast<uint8_t>(settings.get<DvrSettings::record>().statusMask),
                .lowThreshold =
                        static_cast<uint32_t>(settings.get<DvrSettings::record>().lowThreshold),
                .highThreshold =
                        static_cast<uint32_t>(settings.get<DvrSettings::record>().highThreshold),
                .dataFormat =
                        static_cast<HidlDataFormat>(settings.get<DvrSettings::record>().dataFormat),
                .packetSize = static_cast<uint8_t>(settings.get<DvrSettings::record>().packetSize),
        });
        return s;
    }
    default:
        break;
    }
    return s;
}

/////////////// IDvrCallback ///////////////////////
Return<void> TunerHidlDvr::DvrCallback::onRecordStatus(const HidlRecordStatus status) {
    if (mTunerDvrCallback != nullptr) {
        mTunerDvrCallback->onRecordStatus(static_cast<RecordStatus>(status));
    }
    return Void();
}

Return<void> TunerHidlDvr::DvrCallback::onPlaybackStatus(const HidlPlaybackStatus status) {
    if (mTunerDvrCallback != nullptr) {
        mTunerDvrCallback->onPlaybackStatus(static_cast<PlaybackStatus>(status));
    }
    return Void();
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
