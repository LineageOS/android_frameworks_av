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

#ifndef ANDROID_MEDIA_TUNERFLNB_H
#define ANDROID_MEDIA_TUNERFLNB_H

#include <aidl/android/media/tv/tuner/BnTunerLnb.h>
#include <android/hardware/tv/tuner/1.0/ILnb.h>
#include <android/hardware/tv/tuner/1.0/ILnbCallback.h>
#include <media/stagefright/foundation/ADebug.h>
#include <utils/Log.h>

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::tv::tuner::BnTunerLnb;
using ::aidl::android::media::tv::tuner::ITunerLnbCallback;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::hidl_vec;
using ::android::hardware::tv::tuner::V1_0::ILnb;
using ::android::hardware::tv::tuner::V1_0::ILnbCallback;
using ::android::hardware::tv::tuner::V1_0::LnbEventType;

using namespace std;

namespace android {

class TunerLnb : public BnTunerLnb {

public:
    TunerLnb(sp<ILnb> lnb, int id);
    virtual ~TunerLnb();
    Status setCallback(const shared_ptr<ITunerLnbCallback>& tunerLnbCallback) override;
    Status setVoltage(int voltage) override;
    Status setTone(int tone) override;
    Status setSatellitePosition(int position) override;
    Status sendDiseqcMessage(const vector<uint8_t>& diseqcMessage) override;
    Status close() override;

    int getId() { return mId; }

    struct LnbCallback : public ILnbCallback {
        LnbCallback(const shared_ptr<ITunerLnbCallback> tunerLnbCallback)
                : mTunerLnbCallback(tunerLnbCallback) {};

        virtual Return<void> onEvent(const LnbEventType lnbEventType);
        virtual Return<void> onDiseqcMessage(const hidl_vec<uint8_t>& diseqcMessage);

        shared_ptr<ITunerLnbCallback> mTunerLnbCallback;
    };

private:
    int mId;
    sp<ILnb> mLnb;
};

} // namespace android

#endif // ANDROID_MEDIA_TUNERFLNB_H
