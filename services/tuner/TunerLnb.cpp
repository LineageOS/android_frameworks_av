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

#define LOG_TAG "TunerLnb"

#include "TunerLnb.h"

#include <aidl/android/hardware/tv/tuner/ILnbCallback.h>
#include <aidl/android/hardware/tv/tuner/Result.h>

using ::aidl::android::hardware::tv::tuner::ILnbCallback;
using ::aidl::android::hardware::tv::tuner::Result;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerLnb::TunerLnb(shared_ptr<ILnb> lnb, int id) {
    mLnb = lnb;
    mId = id;
}

TunerLnb::~TunerLnb() {
    close();
    mLnb = nullptr;
    mId = -1;
}

::ndk::ScopedAStatus TunerLnb::setCallback(
        const shared_ptr<ITunerLnbCallback>& in_tunerLnbCallback) {
    if (in_tunerLnbCallback == nullptr) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(
                static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    shared_ptr<ILnbCallback> lnbCallback =
            ::ndk::SharedRefBase::make<LnbCallback>(in_tunerLnbCallback);
    return mLnb->setCallback(lnbCallback);
}

::ndk::ScopedAStatus TunerLnb::setVoltage(LnbVoltage in_voltage) {
    return mLnb->setVoltage(in_voltage);
}

::ndk::ScopedAStatus TunerLnb::setTone(LnbTone in_tone) {
    return mLnb->setTone(in_tone);
}

::ndk::ScopedAStatus TunerLnb::setSatellitePosition(LnbPosition in_position) {
    return mLnb->setSatellitePosition(in_position);
}

::ndk::ScopedAStatus TunerLnb::sendDiseqcMessage(const vector<uint8_t>& in_diseqcMessage) {
    return mLnb->sendDiseqcMessage(in_diseqcMessage);
}

::ndk::ScopedAStatus TunerLnb::close() {
    return mLnb->close();
}

/////////////// ILnbCallback ///////////////////////
::ndk::ScopedAStatus TunerLnb::LnbCallback::onEvent(const LnbEventType lnbEventType) {
    if (mTunerLnbCallback != nullptr) {
        mTunerLnbCallback->onEvent(lnbEventType);
    }
    return ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerLnb::LnbCallback::onDiseqcMessage(const vector<uint8_t>& diseqcMessage) {
    if (mTunerLnbCallback != nullptr) {
        mTunerLnbCallback->onDiseqcMessage(diseqcMessage);
    }
    return ndk::ScopedAStatus::ok();
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
