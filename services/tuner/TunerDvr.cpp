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
    if (!isClosed) {
        close();
    }
    mDvr = nullptr;
}

::ndk::ScopedAStatus TunerDvr::getQueueDesc(AidlMQDesc* _aidl_return) {
    return mDvr->getQueueDesc(_aidl_return);
}

::ndk::ScopedAStatus TunerDvr::configure(const DvrSettings& in_settings) {
    return mDvr->configure(in_settings);
}

::ndk::ScopedAStatus TunerDvr::attachFilter(const shared_ptr<ITunerFilter>& in_filter) {
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
    return mDvr->start();
}

::ndk::ScopedAStatus TunerDvr::stop() {
    return mDvr->stop();
}

::ndk::ScopedAStatus TunerDvr::flush() {
    return mDvr->flush();
}

::ndk::ScopedAStatus TunerDvr::close() {
    isClosed = true;
    return mDvr->close();
}

::ndk::ScopedAStatus TunerDvr::setStatusCheckIntervalHint(const int64_t milliseconds) {
    if (milliseconds < 0L) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    ::ndk::ScopedAStatus s = mDvr->setStatusCheckIntervalHint(milliseconds);
    if (s.getStatus() == STATUS_UNKNOWN_TRANSACTION) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    return s;
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
