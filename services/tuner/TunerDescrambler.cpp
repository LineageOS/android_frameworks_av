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

#define LOG_TAG "TunerDescrambler"

#include "TunerFilter.h"
#include "TunerDemux.h"
#include "TunerDescrambler.h"

using ::android::hardware::tv::tuner::V1_0::Result;

using namespace std;

namespace android {

TunerDescrambler::TunerDescrambler(sp<IDescrambler> descrambler) {
    mDescrambler = descrambler;
}

TunerDescrambler::~TunerDescrambler() {
    mDescrambler = nullptr;
}

Status TunerDescrambler::setDemuxSource(const std::shared_ptr<ITunerDemux>& demux) {
    if (mDescrambler == nullptr) {
        ALOGE("IDescrambler is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mDescrambler->setDemuxSource(static_cast<TunerDemux*>(demux.get())->getId());
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDescrambler::setKeyToken(const vector<uint8_t>& keyToken) {
    if (mDescrambler == nullptr) {
        ALOGE("IDescrambler is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mDescrambler->setKeyToken(keyToken);
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDescrambler::addPid(const TunerDemuxPid& pid,
        const shared_ptr<ITunerFilter>& optionalSourceFilter) {
    if (mDescrambler == nullptr) {
        ALOGE("IDescrambler is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    sp<IFilter> halFilter = (optionalSourceFilter == NULL)
            ? NULL : static_cast<TunerFilter*>(optionalSourceFilter.get())->getHalFilter();
    Result res = mDescrambler->addPid(getHidlDemuxPid(pid), halFilter);
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDescrambler::removePid(const TunerDemuxPid& pid,
        const shared_ptr<ITunerFilter>& optionalSourceFilter) {
    if (mDescrambler == nullptr) {
        ALOGE("IDescrambler is not initialized");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    sp<IFilter> halFilter = (optionalSourceFilter == NULL)
            ? NULL : static_cast<TunerFilter*>(optionalSourceFilter.get())->getHalFilter();
    Result res = mDescrambler->removePid(getHidlDemuxPid(pid), halFilter);
    if (res != Result::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

Status TunerDescrambler::close() {
    if (mDescrambler == nullptr) {
        ALOGE("IDescrambler is not initialized.");
        return Status::fromServiceSpecificError(static_cast<int32_t>(Result::UNAVAILABLE));
    }

    Result res = mDescrambler->close();
    mDescrambler = NULL;

    if (res != Result::SUCCESS) {
        return Status::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return Status::ok();
}

DemuxPid TunerDescrambler::getHidlDemuxPid(const TunerDemuxPid& pid) {
    DemuxPid hidlPid;
    switch (pid.getTag()) {
        case TunerDemuxPid::tPid: {
            hidlPid.tPid((uint16_t)pid.get<TunerDemuxPid::tPid>());
            break;
        }
        case TunerDemuxPid::mmtpPid: {
            hidlPid.mmtpPid((uint16_t)pid.get<TunerDemuxPid::mmtpPid>());
            break;
        }
    }
    return hidlPid;
}
}  // namespace android
