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

#ifndef ANDROID_MEDIA_TUNERHIDLDVR_H
#define ANDROID_MEDIA_TUNERHIDLDVR_H

#include <aidl/android/hardware/tv/tuner/DvrSettings.h>
#include <aidl/android/hardware/tv/tuner/DvrType.h>
#include <aidl/android/media/tv/tuner/BnTunerDvr.h>
#include <aidl/android/media/tv/tuner/ITunerDvrCallback.h>
#include <android/hardware/tv/tuner/1.0/IDvr.h>
#include <android/hardware/tv/tuner/1.0/IDvrCallback.h>

#include "TunerHidlFilter.h"

using ::aidl::android::hardware::common::fmq::MQDescriptor;
using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::aidl::android::hardware::tv::tuner::DvrSettings;
using ::aidl::android::hardware::tv::tuner::DvrType;
using ::android::sp;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::std::shared_ptr;
using ::std::vector;

using HidlDvrSettings = ::android::hardware::tv::tuner::V1_0::DvrSettings;
using HidlIDvr = ::android::hardware::tv::tuner::V1_0::IDvr;
using HidlIDvrCallback = ::android::hardware::tv::tuner::V1_0::IDvrCallback;
using HidlPlaybackStatus = ::android::hardware::tv::tuner::V1_0::PlaybackStatus;
using HidlRecordStatus = ::android::hardware::tv::tuner::V1_0::RecordStatus;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

using AidlMQDesc = MQDescriptor<int8_t, SynchronizedReadWrite>;

class TunerHidlDvr : public BnTunerDvr {
public:
    TunerHidlDvr(sp<HidlIDvr> dvr, DvrType type);
    ~TunerHidlDvr();

    ::ndk::ScopedAStatus getQueueDesc(AidlMQDesc* _aidl_return) override;
    ::ndk::ScopedAStatus configure(const DvrSettings& in_settings) override;
    ::ndk::ScopedAStatus attachFilter(const shared_ptr<ITunerFilter>& in_filter) override;
    ::ndk::ScopedAStatus detachFilter(const shared_ptr<ITunerFilter>& in_filter) override;
    ::ndk::ScopedAStatus start() override;
    ::ndk::ScopedAStatus stop() override;
    ::ndk::ScopedAStatus flush() override;
    ::ndk::ScopedAStatus close() override;
    ::ndk::ScopedAStatus setStatusCheckIntervalHint(int64_t in_milliseconds) override;

    struct DvrCallback : public HidlIDvrCallback {
        DvrCallback(const shared_ptr<ITunerDvrCallback> tunerDvrCallback)
              : mTunerDvrCallback(tunerDvrCallback){};

        virtual Return<void> onRecordStatus(const HidlRecordStatus status);
        virtual Return<void> onPlaybackStatus(const HidlPlaybackStatus status);

    private:
        shared_ptr<ITunerDvrCallback> mTunerDvrCallback;
    };

private:
    HidlDvrSettings getHidlDvrSettings(const DvrSettings& settings);

    sp<HidlIDvr> mDvr;
    DvrType mType;
};

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl

#endif  // ANDROID_MEDIA_TUNERHIDLDVR_H
