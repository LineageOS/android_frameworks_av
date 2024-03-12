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

#include <aidl/android/hardware/tv/tuner/IDescrambler.h>
#include <aidl/android/media/tv/tuner/BnTunerDescrambler.h>

using ::aidl::android::hardware::tv::tuner::DemuxPid;
using ::aidl::android::hardware::tv::tuner::IDescrambler;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

class TunerDescrambler : public BnTunerDescrambler {

public:
    TunerDescrambler(shared_ptr<IDescrambler> descrambler);
    virtual ~TunerDescrambler();

    ::ndk::ScopedAStatus setDemuxSource(const shared_ptr<ITunerDemux>& in_tunerDemux) override;
    ::ndk::ScopedAStatus setKeyToken(const vector<uint8_t>& in_keyToken) override;
    ::ndk::ScopedAStatus addPid(const DemuxPid& in_pid,
                                const shared_ptr<ITunerFilter>& in_optionalSourceFilter) override;
    ::ndk::ScopedAStatus removePid(
            const DemuxPid& in_pid,
            const shared_ptr<ITunerFilter>& in_optionalSourceFilter) override;
    ::ndk::ScopedAStatus close() override;

private:
    shared_ptr<IDescrambler> mDescrambler;
    bool isClosed = false;
};

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl

#endif // ANDROID_MEDIA_TUNERDESCRAMBLER_H
