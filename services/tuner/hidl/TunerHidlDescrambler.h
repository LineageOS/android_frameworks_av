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

#ifndef ANDROID_MEDIA_TUNERHIDLDESCRAMBLER_H
#define ANDROID_MEDIA_TUNERHIDLDESCRAMBLER_H

#include <aidl/android/hardware/tv/tuner/IDescrambler.h>
#include <aidl/android/media/tv/tuner/BnTunerDescrambler.h>
#include <android/hardware/tv/tuner/1.0/IDescrambler.h>
#include <android/hardware/tv/tuner/1.0/ITuner.h>

using ::aidl::android::hardware::tv::tuner::DemuxPid;
using ::android::sp;
using ::android::hardware::Return;
using ::android::hardware::Void;

using HidlDemuxPid = ::android::hardware::tv::tuner::V1_0::DemuxPid;
using HidlIDescrambler = ::android::hardware::tv::tuner::V1_0::IDescrambler;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

class TunerHidlDescrambler : public BnTunerDescrambler {
public:
    TunerHidlDescrambler(sp<HidlIDescrambler> descrambler);
    virtual ~TunerHidlDescrambler();

    ::ndk::ScopedAStatus setDemuxSource(const std::shared_ptr<ITunerDemux>& in_tunerDemux) override;
    ::ndk::ScopedAStatus setKeyToken(const std::vector<uint8_t>& in_keyToken) override;
    ::ndk::ScopedAStatus addPid(
            const DemuxPid& in_pid,
            const std::shared_ptr<ITunerFilter>& in_optionalSourceFilter) override;
    ::ndk::ScopedAStatus removePid(
            const DemuxPid& in_pid,
            const std::shared_ptr<ITunerFilter>& in_optionalSourceFilter) override;
    ::ndk::ScopedAStatus close() override;

private:
    HidlDemuxPid getHidlDemuxPid(const DemuxPid& pid);

    sp<HidlIDescrambler> mDescrambler;
};

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl

#endif  // ANDROID_MEDIA_TUNERHIDLDESCRAMBLER_H
