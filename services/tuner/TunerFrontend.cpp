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

//#define LOG_NDEBUG 0
#define LOG_TAG "TunerFrontend"

#include "TunerFrontend.h"

#include <aidl/android/hardware/tv/tuner/Result.h>

#include "TunerLnb.h"

using ::aidl::android::hardware::tv::tuner::Result;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerFrontend::TunerFrontend(shared_ptr<IFrontend> frontend, int id) {
    mFrontend = frontend;
    mId = id;
}

TunerFrontend::~TunerFrontend() {
    if (!isClosed) {
        close();
    }
    mFrontend = nullptr;
    mId = -1;
}

::ndk::ScopedAStatus TunerFrontend::setCallback(
        const shared_ptr<ITunerFrontendCallback>& tunerFrontendCallback) {
    if (tunerFrontendCallback == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    shared_ptr<IFrontendCallback> frontendCallback =
            ::ndk::SharedRefBase::make<FrontendCallback>(tunerFrontendCallback);
    return mFrontend->setCallback(frontendCallback);
}

::ndk::ScopedAStatus TunerFrontend::tune(const FrontendSettings& settings) {
    return mFrontend->tune(settings);
}

::ndk::ScopedAStatus TunerFrontend::stopTune() {
    return mFrontend->stopTune();
}

::ndk::ScopedAStatus TunerFrontend::scan(const FrontendSettings& settings,
                                         FrontendScanType frontendScanType) {
    return mFrontend->scan(settings, frontendScanType);
}

::ndk::ScopedAStatus TunerFrontend::stopScan() {
    return mFrontend->stopScan();
}

::ndk::ScopedAStatus TunerFrontend::setLnb(const shared_ptr<ITunerLnb>& lnb) {
    if (lnb == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    return mFrontend->setLnb(static_cast<TunerLnb*>(lnb.get())->getId());
}

::ndk::ScopedAStatus TunerFrontend::linkCiCamToFrontend(int32_t ciCamId, int32_t* _aidl_return) {
    return mFrontend->linkCiCam(ciCamId, _aidl_return);
}

::ndk::ScopedAStatus TunerFrontend::unlinkCiCamToFrontend(int32_t ciCamId) {
    return mFrontend->unlinkCiCam(ciCamId);
}

::ndk::ScopedAStatus TunerFrontend::close() {
    isClosed = true;
    return mFrontend->close();
}

::ndk::ScopedAStatus TunerFrontend::getStatus(const vector<FrontendStatusType>& in_statusTypes,
                                              vector<FrontendStatus>* _aidl_return) {
    return mFrontend->getStatus(in_statusTypes, _aidl_return);
}

::ndk::ScopedAStatus TunerFrontend::getFrontendId(int32_t* _aidl_return) {
    *_aidl_return = mId;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerFrontend::getHardwareInfo(std::string* _aidl_return) {
    return mFrontend->getHardwareInfo(_aidl_return);
}

::ndk::ScopedAStatus TunerFrontend::removeOutputPid(int32_t in_pid) {
    return mFrontend->removeOutputPid(in_pid);
}

::ndk::ScopedAStatus TunerFrontend::getFrontendStatusReadiness(
        const std::vector<FrontendStatusType>& in_statusTypes,
        std::vector<FrontendStatusReadiness>* _aidl_return) {
    return mFrontend->getFrontendStatusReadiness(in_statusTypes, _aidl_return);
}

/////////////// FrontendCallback ///////////////////////
::ndk::ScopedAStatus TunerFrontend::FrontendCallback::onEvent(FrontendEventType frontendEventType) {
    ALOGV("FrontendCallback::onEvent, type=%d", frontendEventType);
    if (mTunerFrontendCallback != nullptr) {
        mTunerFrontendCallback->onEvent(frontendEventType);
    }
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerFrontend::FrontendCallback::onScanMessage(
        FrontendScanMessageType type, const FrontendScanMessage& message) {
    ALOGV("FrontendCallback::onScanMessage, type=%d", type);
    if (mTunerFrontendCallback != nullptr) {
        mTunerFrontendCallback->onScanMessage(type, message);
    }
    return ndk::ScopedAStatus::ok();
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
