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

#define LOG_TAG "TunerHidlDescrambler"

#include "TunerHidlDescrambler.h"

#include <aidl/android/hardware/tv/tuner/Result.h>

#include "TunerHidlDemux.h"
#include "TunerHidlFilter.h"

using ::aidl::android::hardware::tv::tuner::Result;

using HidlResult = ::android::hardware::tv::tuner::V1_0::Result;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerHidlDescrambler::TunerHidlDescrambler(sp<HidlIDescrambler> descrambler) {
    mDescrambler = descrambler;
}

TunerHidlDescrambler::~TunerHidlDescrambler() {
    mDescrambler = nullptr;
}

::ndk::ScopedAStatus TunerHidlDescrambler::setDemuxSource(
        const shared_ptr<ITunerDemux>& in_tunerDemux) {
    HidlResult res = mDescrambler->setDemuxSource(
            static_cast<TunerHidlDemux*>(in_tunerDemux.get())->getId());
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDescrambler::setKeyToken(const vector<uint8_t>& in_keyToken) {
    HidlResult res = mDescrambler->setKeyToken(in_keyToken);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDescrambler::addPid(
        const DemuxPid& in_pid, const shared_ptr<ITunerFilter>& in_optionalSourceFilter) {
    sp<HidlIFilter> halFilter =
            (in_optionalSourceFilter == nullptr)
                    ? nullptr
                    : static_cast<TunerHidlFilter*>(in_optionalSourceFilter.get())->getHalFilter();
    HidlResult res = mDescrambler->addPid(getHidlDemuxPid(in_pid), halFilter);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDescrambler::removePid(
        const DemuxPid& in_pid, const shared_ptr<ITunerFilter>& in_optionalSourceFilter) {
    sp<HidlIFilter> halFilter =
            (in_optionalSourceFilter == nullptr)
                    ? nullptr
                    : static_cast<TunerHidlFilter*>(in_optionalSourceFilter.get())->getHalFilter();
    HidlResult res = mDescrambler->removePid(getHidlDemuxPid(in_pid), halFilter);
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus TunerHidlDescrambler::close() {
    HidlResult res = mDescrambler->close();
    if (res != HidlResult::SUCCESS) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(res));
    }
    return ::ndk::ScopedAStatus::ok();
}

HidlDemuxPid TunerHidlDescrambler::getHidlDemuxPid(const DemuxPid& pid) {
    HidlDemuxPid hidlPid;
    switch (pid.getTag()) {
    case DemuxPid::tPid: {
        hidlPid.tPid((uint16_t)pid.get<DemuxPid::Tag::tPid>());
        break;
    }
    case DemuxPid::mmtpPid: {
        hidlPid.mmtpPid((uint16_t)pid.get<DemuxPid::Tag::mmtpPid>());
        break;
    }
    }
    return hidlPid;
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
