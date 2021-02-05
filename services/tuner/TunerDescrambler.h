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

#ifndef ANDROID_MEDIA_TUNERDESCRAMBLER_H
#define ANDROID_MEDIA_TUNERDESCRAMBLER_H

#include <aidl/android/media/tv/tuner/BnTunerDescrambler.h>
#include <android/hardware/tv/tuner/1.0/ITuner.h>

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::tv::tuner::BnTunerDescrambler;
using ::aidl::android::media::tv::tuner::ITunerDemux;
using ::aidl::android::media::tv::tuner::ITunerFilter;
using ::aidl::android::media::tv::tuner::TunerDemuxPid;
using ::android::hardware::tv::tuner::V1_0::DemuxPid;
using ::android::hardware::tv::tuner::V1_0::IDescrambler;

namespace android {

class TunerDescrambler : public BnTunerDescrambler {

public:
    TunerDescrambler(sp<IDescrambler> descrambler);
    virtual ~TunerDescrambler();
    Status setDemuxSource(const shared_ptr<ITunerDemux>& demux) override;
    Status setKeyToken(const vector<uint8_t>& keyToken) override;
    Status addPid(const TunerDemuxPid& pid,
            const shared_ptr<ITunerFilter>& optionalSourceFilter) override;
    Status removePid(const TunerDemuxPid& pid,
            const shared_ptr<ITunerFilter>& optionalSourceFilter) override;
    Status close() override;

private:
    DemuxPid getHidlDemuxPid(const TunerDemuxPid& pid);

    sp<IDescrambler> mDescrambler;
};

} // namespace android

#endif // ANDROID_MEDIA_TUNERDESCRAMBLER_H
