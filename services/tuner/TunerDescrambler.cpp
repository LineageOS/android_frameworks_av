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

#include "TunerDescrambler.h"

#include <aidl/android/hardware/tv/tuner/IFilter.h>
#include <aidl/android/hardware/tv/tuner/Result.h>
#include <utils/Log.h>

#include "TunerDemux.h"
#include "TunerFilter.h"

using ::aidl::android::hardware::tv::tuner::IFilter;
using ::aidl::android::hardware::tv::tuner::Result;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

TunerDescrambler::TunerDescrambler(shared_ptr<IDescrambler> descrambler) {
    mDescrambler = descrambler;
}

TunerDescrambler::~TunerDescrambler() {
    if (!isClosed) {
        close();
    }
    mDescrambler = nullptr;
}

::ndk::ScopedAStatus TunerDescrambler::setDemuxSource(
        const shared_ptr<ITunerDemux>& in_tunerDemux) {
    return mDescrambler->setDemuxSource((static_cast<TunerDemux*>(in_tunerDemux.get()))->getId());
}

::ndk::ScopedAStatus TunerDescrambler::setKeyToken(const vector<uint8_t>& in_keyToken) {
    return mDescrambler->setKeyToken(in_keyToken);
}

::ndk::ScopedAStatus TunerDescrambler::addPid(
        const DemuxPid& in_pid, const shared_ptr<ITunerFilter>& in_optionalSourceFilter) {
    shared_ptr<IFilter> halFilter =
            (in_optionalSourceFilter == nullptr)
                    ? nullptr
                    : static_cast<TunerFilter*>(in_optionalSourceFilter.get())->getHalFilter();

    return mDescrambler->addPid(in_pid, halFilter);
}

::ndk::ScopedAStatus TunerDescrambler::removePid(
        const DemuxPid& in_pid, const shared_ptr<ITunerFilter>& in_optionalSourceFilter) {
    shared_ptr<IFilter> halFilter =
            (in_optionalSourceFilter == nullptr)
                    ? nullptr
                    : static_cast<TunerFilter*>(in_optionalSourceFilter.get())->getHalFilter();

    return mDescrambler->removePid(in_pid, halFilter);
}

::ndk::ScopedAStatus TunerDescrambler::close() {
    isClosed = true;
    return mDescrambler->close();
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
