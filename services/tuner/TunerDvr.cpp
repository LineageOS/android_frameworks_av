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

#include "TunerDvr.h"

#include <aidl/android/hardware/tv/tuner/Result.h>
#include <utils/Log.h>

#include "TunerFilter.h"

using ::aidl::android::hardware::tv::tuner::Result;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerDvr::TunerDvr(shared_ptr<IDvr> dvr, DvrType type) {
    mDvr = dvr;
    mType = type;
}

TunerDvr::~TunerDvr() {
    mDvr = nullptr;
}

::ndk::ScopedAStatus TunerDvr::getQueueDesc(AidlMQDesc* _aidl_return) {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mDvr->getQueueDesc(_aidl_return);
}

::ndk::ScopedAStatus TunerDvr::configure(const DvrSettings& in_settings) {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mDvr->configure(in_settings);
}

::ndk::ScopedAStatus TunerDvr::attachFilter(const shared_ptr<ITunerFilter>& in_filter) {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (in_filter == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    shared_ptr<IFilter> halFilter = (static_cast<TunerFilter*>(in_filter.get()))->getHalFilter();
    if (halFilter == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    return mDvr->attachFilter(halFilter);
}

::ndk::ScopedAStatus TunerDvr::detachFilter(const shared_ptr<ITunerFilter>& in_filter) {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (in_filter == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    shared_ptr<IFilter> halFilter = (static_cast<TunerFilter*>(in_filter.get()))->getHalFilter();
    if (halFilter == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    return mDvr->detachFilter(halFilter);
}

::ndk::ScopedAStatus TunerDvr::start() {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mDvr->start();
}

::ndk::ScopedAStatus TunerDvr::stop() {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mDvr->stop();
}

::ndk::ScopedAStatus TunerDvr::flush() {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return mDvr->flush();
}

::ndk::ScopedAStatus TunerDvr::close() {
    if (mDvr == nullptr) {
        ALOGE("IDvr is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    auto status = mDvr->close();
    mDvr = nullptr;

    return status;
}

/////////////// IDvrCallback ///////////////////////
::ndk::ScopedAStatus TunerDvr::DvrCallback::onRecordStatus(const RecordStatus status) {
    if (mTunerDvrCallback != nullptr) {
        mTunerDvrCallback->onRecordStatus(status);
    }
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerDvr::DvrCallback::onPlaybackStatus(const PlaybackStatus status) {
    if (mTunerDvrCallback != nullptr) {
        mTunerDvrCallback->onPlaybackStatus(status);
    }
    return ndk::ScopedAStatus::ok();
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
