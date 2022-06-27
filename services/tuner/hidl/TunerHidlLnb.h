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

#ifndef ANDROID_MEDIA_TUNERHIDLLNB_H
#define ANDROID_MEDIA_TUNERHIDLLNB_H

#include <aidl/android/hardware/tv/tuner/ILnb.h>
#include <aidl/android/media/tv/tuner/BnTunerLnb.h>
#include <android/hardware/tv/tuner/1.0/ILnb.h>
#include <android/hardware/tv/tuner/1.0/ILnbCallback.h>
#include <utils/Log.h>

using ::aidl::android::hardware::tv::tuner::LnbEventType;
using ::aidl::android::hardware::tv::tuner::LnbPosition;
using ::aidl::android::hardware::tv::tuner::LnbTone;
using ::aidl::android::hardware::tv::tuner::LnbVoltage;
using ::android::sp;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::std::shared_ptr;
using ::std::vector;

using HidlILnb = ::android::hardware::tv::tuner::V1_0::ILnb;
using HidlILnbCallback = ::android::hardware::tv::tuner::V1_0::ILnbCallback;
using HidlLnbEventType = ::android::hardware::tv::tuner::V1_0::LnbEventType;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

class TunerHidlLnb : public BnTunerLnb {
public:
    TunerHidlLnb(sp<HidlILnb> lnb, int id);
    virtual ~TunerHidlLnb();

    ::ndk::ScopedAStatus setCallback(
            const shared_ptr<ITunerLnbCallback>& in_tunerLnbCallback) override;
    ::ndk::ScopedAStatus setVoltage(LnbVoltage in_voltage) override;
    ::ndk::ScopedAStatus setTone(LnbTone in_tone) override;
    ::ndk::ScopedAStatus setSatellitePosition(LnbPosition in_position) override;
    ::ndk::ScopedAStatus sendDiseqcMessage(const vector<uint8_t>& in_diseqcMessage) override;
    ::ndk::ScopedAStatus close() override;

    int getId() { return mId; }

    struct LnbCallback : public HidlILnbCallback {
        LnbCallback(const shared_ptr<ITunerLnbCallback> tunerLnbCallback)
              : mTunerLnbCallback(tunerLnbCallback){};

        virtual Return<void> onEvent(const HidlLnbEventType lnbEventType);
        virtual Return<void> onDiseqcMessage(const hidl_vec<uint8_t>& diseqcMessage);

        shared_ptr<ITunerLnbCallback> mTunerLnbCallback;
    };

private:
    int mId;
    sp<HidlILnb> mLnb;
};

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl

#endif  // ANDROID_MEDIA_TUNERHIDLLNB_H
