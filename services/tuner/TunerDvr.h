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

#ifndef ANDROID_MEDIA_TUNERDVR_H
#define ANDROID_MEDIA_TUNERDVR_H

#include <aidl/android/media/tv/tuner/BnTunerDvr.h>
#include <aidl/android/media/tv/tuner/ITunerDvrCallback.h>
#include <android/hardware/tv/tuner/1.0/ITuner.h>
#include <fmq/MessageQueue.h>

#include <TunerFilter.h>

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::hardware::common::fmq::GrantorDescriptor;
using ::aidl::android::hardware::common::fmq::MQDescriptor;
using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::aidl::android::media::tv::tuner::BnTunerDvr;
using ::aidl::android::media::tv::tuner::ITunerDvrCallback;
using ::aidl::android::media::tv::tuner::ITunerFilter;
using ::aidl::android::media::tv::tuner::TunerDvrSettings;

using ::android::hardware::MQDescriptorSync;
using ::android::hardware::MessageQueue;
using ::android::hardware::Return;
using ::android::hardware::Void;

using ::android::hardware::tv::tuner::V1_0::DvrSettings;
using ::android::hardware::tv::tuner::V1_0::DvrType;
using ::android::hardware::tv::tuner::V1_0::IDvr;
using ::android::hardware::tv::tuner::V1_0::IDvrCallback;
using ::android::hardware::tv::tuner::V1_0::PlaybackStatus;
using ::android::hardware::tv::tuner::V1_0::RecordStatus;

using namespace std;

namespace android {

using MQDesc = MQDescriptorSync<uint8_t>;
using AidlMQDesc = MQDescriptor<int8_t, SynchronizedReadWrite>;

class TunerDvr : public BnTunerDvr {

public:
    TunerDvr(sp<IDvr> dvr, int type);
    ~TunerDvr();

    Status getQueueDesc(AidlMQDesc* _aidl_return) override;

    Status configure(const TunerDvrSettings& settings) override;

    Status attachFilter(const shared_ptr<ITunerFilter>& filter) override;

    Status detachFilter(const shared_ptr<ITunerFilter>& filter) override;

    Status start() override;

    Status stop() override;

    Status flush() override;

    Status close() override;

    struct DvrCallback : public IDvrCallback {
        DvrCallback(const shared_ptr<ITunerDvrCallback> tunerDvrCallback)
                : mTunerDvrCallback(tunerDvrCallback) {};

        virtual Return<void> onRecordStatus(const RecordStatus status);
        virtual Return<void> onPlaybackStatus(const PlaybackStatus status);

        private:
            shared_ptr<ITunerDvrCallback> mTunerDvrCallback;
    };

private:
    DvrSettings getHidlDvrSettingsFromAidl(TunerDvrSettings settings);

    sp<IDvr> mDvr;
    DvrType mType;
};

} // namespace android

#endif // ANDROID_MEDIA_TUNERDVR_H
