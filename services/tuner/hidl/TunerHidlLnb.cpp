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

#define LOG_TAG "TunerHidlLnb"

#include "TunerHidlLnb.h"

#include <aidl/android/hardware/tv/tuner/Result.h>

using ::aidl::android::hardware::tv::tuner::Result;
using HidlLnbPosition = ::android::hardware::tv::tuner::V1_0::LnbPosition;
using HidlLnbTone = ::android::hardware::tv::tuner::V1_0::LnbTone;
using HidlLnbVoltage = ::android::hardware::tv::tuner::V1_0::LnbVoltage;
using HidlResult = ::android::hardware::tv::tuner::V1_0::Result;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerHidlLnb::TunerHidlLnb(sp<HidlILnb> lnb, int id) {
    mLnb = lnb;
    mId = id;
}

TunerHidlLnb::~TunerHidlLnb() {
    mLnb = nullptr;
    mId = -1;
}

::ndk::ScopedAStatus TunerHidlLnb::setCallback(
        const shared_ptr<ITunerLnbCallback>& in_tunerLnbCallback) {
    if (mLnb == nullptr) {
        ALOGE("ILnb is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (in_tunerLnbCallback == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    sp<HidlILnbCallback> lnbCallback = new LnbCallback(in_tunerLnbCallback);
    HidlResult status = mLnb->setCallback(lnbCallback);
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlLnb::setVoltage(LnbVoltage in_voltage) {
    if (mLnb == nullptr) {
        ALOGE("ILnb is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    HidlResult status = mLnb->setVoltage(static_cast<HidlLnbVoltage>(in_voltage));
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlLnb::setTone(LnbTone in_tone) {
    if (mLnb == nullptr) {
        ALOGE("ILnb is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    HidlResult status = mLnb->setTone(static_cast<HidlLnbTone>(in_tone));
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlLnb::setSatellitePosition(LnbPosition in_position) {
    if (mLnb == nullptr) {
        ALOGE("ILnb is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    HidlResult status = mLnb->setSatellitePosition(static_cast<HidlLnbPosition>(in_position));
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlLnb::sendDiseqcMessage(const vector<uint8_t>& in_diseqcMessage) {
    if (mLnb == nullptr) {
        ALOGE("ILnb is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    HidlResult status = mLnb->sendDiseqcMessage(in_diseqcMessage);
    if (status != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlLnb::close() {
    if (mLnb == nullptr) {
        ALOGE("ILnb is not initialized");
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::UNAVAILABLE));
    }

    HidlResult res = mLnb->close();
    mLnb = nullptr;

    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

/////////////// ILnbCallback ///////////////////////
Return<void> TunerHidlLnb::LnbCallback::onEvent(const HidlLnbEventType lnbEventType) {
    if (mTunerLnbCallback != nullptr) {
        mTunerLnbCallback->onEvent(static_cast<LnbEventType>(lnbEventType));
    }
    return Void();
}

Return<void> TunerHidlLnb::LnbCallback::onDiseqcMessage(const hidl_vec<uint8_t>& diseqcMessage) {
    if (mTunerLnbCallback != nullptr) {
        vector<uint8_t> msg(begin(diseqcMessage), end(diseqcMessage));
        mTunerLnbCallback->onDiseqcMessage(msg);
    }
    return Void();
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
