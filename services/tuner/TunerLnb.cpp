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

using ::android::hardware::tv::tuner::V1_0::LnbPosition;
using ::android::hardware::tv::tuner::V1_0::LnbTone;
using ::android::hardware::tv::tuner::V1_0::LnbVoltage;
using ::android::hardware::tv::tuner::V1_0::Result;

namespace android {

TunerLnb::TunerLnb(sp<ILnb> lnb, int id) {
    mLnb = lnb;
    mId = id;
}

TunerLnb::~TunerLnb() {
    mLnb = NULL;
    mId = -1;
}

Status TunerLnb::setCallback(
        const shared_ptr<ITunerLnbCallback>& tunerLnbCallback) {
    if (mLnb == NULL) {
        ALOGE("ILnb is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    if (tunerLnbCallback == NULL) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::INVALID_ARGUMENT));
    }

    sp<ILnbCallback> lnbCallback = new LnbCallback(tunerLnbCallback);
    Result status = mLnb->setCallback(lnbCallback);
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return Status::ok();
}

Status TunerLnb::setVoltage(int voltage) {
    if (mLnb == NULL) {
        ALOGE("ILnb is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status = mLnb->setVoltage(static_cast<LnbVoltage>(voltage));
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return Status::ok();
}

Status TunerLnb::setTone(int tone) {
    if (mLnb == NULL) {
        ALOGE("ILnb is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status = mLnb->setTone(static_cast<LnbTone>(tone));
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return Status::ok();
}

Status TunerLnb::setSatellitePosition(int position) {
    if (mLnb == NULL) {
        ALOGE("ILnb is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status = mLnb->setSatellitePosition(static_cast<LnbPosition>(position));
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return Status::ok();
}

Status TunerLnb::sendDiseqcMessage(const vector<uint8_t>& diseqcMessage) {
    if (mLnb == NULL) {
        ALOGE("ILnb is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result status = mLnb->sendDiseqcMessage(diseqcMessage);
    if (status != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(status));
    }
    return Status::ok();
}

Status TunerLnb::close() {
    if (mLnb == NULL) {
        ALOGE("ILnb is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mLnb->close();
    mLnb = NULL;

    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

/////////////// ILnbCallback ///////////////////////

Return<void> TunerLnb::LnbCallback::onEvent(const LnbEventType lnbEventType) {
    if (mTunerLnbCallback != NULL) {
        mTunerLnbCallback->onEvent((int)lnbEventType);
    }
    return Void();
}

Return<void> TunerLnb::LnbCallback::onDiseqcMessage(const hidl_vec<uint8_t>& diseqcMessage) {
    if (mTunerLnbCallback != NULL && diseqcMessage != NULL) {
        vector<uint8_t> msg(begin(diseqcMessage), end(diseqcMessage));
        mTunerLnbCallback->onDiseqcMessage(msg);
    }
    return Void();
}
}  // namespace android
