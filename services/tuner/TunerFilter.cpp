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
#include <binder/IPCThreadState.h>

#include "TunerHelper.h"
#include "TunerService.h"

using ::aidl::android::hardware::tv::tuner::Result;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

using ::android::IPCThreadState;

using namespace std;

TunerFilter::TunerFilter(const shared_ptr<IFilter> filter, const shared_ptr<FilterCallback> cb,
                         const DemuxFilterType type, const shared_ptr<TunerService> tuner)
      : mFilter(filter),
        mType(type),
        mStarted(false),
        mShared(false),
        mClientPid(-1),
        mFilterCallback(cb),
        mTunerService(tuner) {}

TunerFilter::~TunerFilter() {
    if (!isClosed) {
        close();
    }
    freeSharedFilterToken("");
    {
        Mutex::Autolock _l(mLock);
        mFilter = nullptr;
        mTunerService = nullptr;
    }
}

::ndk::ScopedAStatus TunerFilter::getQueueDesc(AidlMQDesc* _aidl_return) {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        IPCThreadState* ipc = IPCThreadState::self();
        int32_t callingPid = ipc->getCallingPid();
        if (callingPid == mClientPid) {
            ALOGD("%s is called in wrong process", __FUNCTION__);
            return ::ndk::ScopedAStatus::fromServiceSpecificError(
                    static_cast<int32_t>(Result::INVALID_STATE));
        }
    }

    return mFilter->getQueueDesc(_aidl_return);
}

::ndk::ScopedAStatus TunerFilter::getId(int32_t* _aidl_return) {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    auto status = mFilter->getId(&mId);
    if (status.isOk()) {
        *_aidl_return = mId;
    }
    return status;
}

::ndk::ScopedAStatus TunerFilter::getId64Bit(int64_t* _aidl_return) {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    auto status = mFilter->getId64Bit(&mId64Bit);
    if (status.isOk()) {
        *_aidl_return = mId64Bit;
    }
    return status;
}

::ndk::ScopedAStatus TunerFilter::configure(const DemuxFilterSettings& in_settings) {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    return mFilter->configure(in_settings);
}

::ndk::ScopedAStatus TunerFilter::configureMonitorEvent(int32_t monitorEventType) {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    return mFilter->configureMonitorEvent(monitorEventType);
}

::ndk::ScopedAStatus TunerFilter::configureIpFilterContextId(int32_t cid) {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    return mFilter->configureIpCid(cid);
}

::ndk::ScopedAStatus TunerFilter::configureAvStreamType(const AvStreamType& in_avStreamType) {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    return mFilter->configureAvStreamType(in_avStreamType);
}

::ndk::ScopedAStatus TunerFilter::setDataSource(const shared_ptr<ITunerFilter>& filter) {
    Mutex::Autolock _l(mLock);
    if (filter == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    shared_ptr<IFilter> halFilter = static_cast<TunerFilter*>(filter.get())->getHalFilter();
    return mFilter->setDataSource(halFilter);
}

::ndk::ScopedAStatus TunerFilter::getAvSharedHandle(NativeHandle* out_avMemory,
                                                    int64_t* _aidl_return) {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    return mFilter->getAvSharedHandle(out_avMemory, _aidl_return);
}

::ndk::ScopedAStatus TunerFilter::releaseAvHandle(const NativeHandle& in_handle,
                                                  int64_t in_avDataId) {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        ALOGD("%s is called on a shared filter", __FUNCTION__);
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    return mFilter->releaseAvHandle(in_handle, in_avDataId);
}

::ndk::ScopedAStatus TunerFilter::start() {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        IPCThreadState* ipc = IPCThreadState::self();
        int32_t callingPid = ipc->getCallingPid();
        if (callingPid == mClientPid) {
            ALOGD("%s is called in wrong process", __FUNCTION__);
            return ::ndk::ScopedAStatus::fromServiceSpecificError(
                    static_cast<int32_t>(Result::INVALID_STATE));
        }
    }

    auto res = mFilter->start();
    if (res.isOk()) {
        mStarted = true;
    }
    return res;
}

::ndk::ScopedAStatus TunerFilter::stop() {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        IPCThreadState* ipc = IPCThreadState::self();
        int32_t callingPid = ipc->getCallingPid();
        if (callingPid == mClientPid) {
            ALOGD("%s is called in wrong process", __FUNCTION__);
            return ::ndk::ScopedAStatus::fromServiceSpecificError(
                    static_cast<int32_t>(Result::INVALID_STATE));
        }
    }

    auto res = mFilter->stop();
    mStarted = false;

    return res;
}

::ndk::ScopedAStatus TunerFilter::flush() {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        IPCThreadState* ipc = IPCThreadState::self();
        int32_t callingPid = ipc->getCallingPid();
        if (callingPid == mClientPid) {
            ALOGD("%s is called in wrong process", __FUNCTION__);
            return ::ndk::ScopedAStatus::fromServiceSpecificError(
                    static_cast<int32_t>(Result::INVALID_STATE));
        }
    }

    return mFilter->flush();
}

::ndk::ScopedAStatus TunerFilter::close() {
    Mutex::Autolock _l(mLock);
    if (mShared) {
        IPCThreadState* ipc = IPCThreadState::self();
        int32_t callingPid = ipc->getCallingPid();
        if (callingPid == mClientPid) {
            if (mFilterCallback != nullptr) {
                mFilterCallback->sendSharedFilterStatus(STATUS_INACCESSIBLE);
                mFilterCallback->detachSharedFilterCallback();
            }
            mTunerService->removeSharedFilter(this->ref<TunerFilter>());
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
    auto res = mFilter->close();
    mStarted = false;
    mShared = false;
    mClientPid = -1;
    isClosed = true;

    return res;
}

::ndk::ScopedAStatus TunerFilter::acquireSharedFilterToken(string* _aidl_return) {
    Mutex::Autolock _l(mLock);
    if (mShared || mStarted) {
        ALOGD("create SharedFilter in wrong state");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_STATE));
    }

    IPCThreadState* ipc = IPCThreadState::self();
    mClientPid = ipc->getCallingPid();
    string token = mTunerService->addFilterToShared(this->ref<TunerFilter>());
    _aidl_return->assign(token);
    mShared = true;

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerFilter::freeSharedFilterToken(const string& /* in_filterToken */) {
    Mutex::Autolock _l(mLock);
    if (!mShared) {
        // The filter is not shared or the shared filter has been closed.
        return ::ndk::ScopedAStatus::ok();
    }

    if (mFilterCallback != nullptr) {
        mFilterCallback->sendSharedFilterStatus(STATUS_INACCESSIBLE);
        mFilterCallback->detachSharedFilterCallback();
    }

    mTunerService->removeSharedFilter(this->ref<TunerFilter>());
    mShared = false;

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerFilter::getFilterType(DemuxFilterType* _aidl_return) {
    Mutex::Autolock _l(mLock);
    *_aidl_return = mType;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerFilter::setDelayHint(const FilterDelayHint& in_hint) {
    Mutex::Autolock _l(mLock);
    return mFilter->setDelayHint(in_hint);
}

bool TunerFilter::isSharedFilterAllowed(int callingPid) {
    return mShared && mClientPid != callingPid;
}

void TunerFilter::attachSharedFilterCallback(const shared_ptr<ITunerFilterCallback>& in_cb) {
    if (mFilterCallback != nullptr) {
        mFilterCallback->attachSharedFilterCallback(in_cb);
    }
}

shared_ptr<IFilter> TunerFilter::getHalFilter() {
    return mFilter;
}

/////////////// FilterCallback ///////////////////////
::ndk::ScopedAStatus TunerFilter::FilterCallback::onFilterStatus(DemuxFilterStatus status) {
    Mutex::Autolock _l(mCallbackLock);
    if (mTunerFilterCallback != nullptr) {
        mTunerFilterCallback->onFilterStatus(status);
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerFilter::FilterCallback::onFilterEvent(
        const vector<DemuxFilterEvent>& events) {
    Mutex::Autolock _l(mCallbackLock);
    if (mTunerFilterCallback != nullptr) {
        mTunerFilterCallback->onFilterEvent(events);
    }
    return ::ndk::ScopedAStatus::ok();
}

void TunerFilter::FilterCallback::sendSharedFilterStatus(int32_t status) {
    Mutex::Autolock _l(mCallbackLock);
    if (mTunerFilterCallback != nullptr && mOriginalCallback != nullptr) {
        mTunerFilterCallback->onFilterStatus(static_cast<DemuxFilterStatus>(status));
    }
}

void TunerFilter::FilterCallback::attachSharedFilterCallback(
        const shared_ptr<ITunerFilterCallback>& in_cb) {
    Mutex::Autolock _l(mCallbackLock);
    mOriginalCallback = mTunerFilterCallback;
    mTunerFilterCallback = in_cb;
}

void TunerFilter::FilterCallback::detachSharedFilterCallback() {
    Mutex::Autolock _l(mCallbackLock);
    if (mTunerFilterCallback != nullptr && mOriginalCallback != nullptr) {
        mTunerFilterCallback = mOriginalCallback;
        mOriginalCallback = nullptr;
    }
}

void TunerFilter::FilterCallback::detachCallbacks() {
    Mutex::Autolock _l(mCallbackLock);
    mOriginalCallback = nullptr;
    mTunerFilterCallback = nullptr;
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
