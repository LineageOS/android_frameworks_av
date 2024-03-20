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

#include <aidl/android/hardware/tv/tuner/BnDvrCallback.h>
#include <aidl/android/hardware/tv/tuner/DvrSettings.h>
#include <aidl/android/hardware/tv/tuner/DvrType.h>
#include <aidl/android/hardware/tv/tuner/IDvr.h>
#include <aidl/android/hardware/tv/tuner/PlaybackStatus.h>
#include <aidl/android/hardware/tv/tuner/RecordStatus.h>
#include <aidl/android/media/tv/tuner/BnTunerDvr.h>
#include <aidl/android/media/tv/tuner/ITunerDvrCallback.h>

#include "TunerFilter.h"

using ::aidl::android::hardware::common::fmq::MQDescriptor;
using ::aidl::android::hardware::common::fmq::SynchronizedReadWrite;
using ::aidl::android::hardware::tv::tuner::BnDvrCallback;
using ::aidl::android::hardware::tv::tuner::DvrSettings;
using ::aidl::android::hardware::tv::tuner::DvrType;
using ::aidl::android::hardware::tv::tuner::IDvr;
using ::aidl::android::hardware::tv::tuner::PlaybackStatus;
using ::aidl::android::hardware::tv::tuner::RecordStatus;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

using AidlMQDesc = MQDescriptor<int8_t, SynchronizedReadWrite>;

class TunerDvr : public BnTunerDvr {

public:
    TunerDvr(shared_ptr<IDvr> dvr, DvrType type);
    ~TunerDvr();

    ::ndk::ScopedAStatus getQueueDesc(AidlMQDesc* _aidl_return) override;
    ::ndk::ScopedAStatus configure(const DvrSettings& in_settings) override;
    ::ndk::ScopedAStatus attachFilter(const shared_ptr<ITunerFilter>& in_filter) override;
    ::ndk::ScopedAStatus detachFilter(const shared_ptr<ITunerFilter>& in_filter) override;
    ::ndk::ScopedAStatus start() override;
    ::ndk::ScopedAStatus stop() override;
    ::ndk::ScopedAStatus flush() override;
    ::ndk::ScopedAStatus close() override;
    ::ndk::ScopedAStatus setStatusCheckIntervalHint(int64_t in_milliseconds) override;

    struct DvrCallback : public BnDvrCallback {
        DvrCallback(const shared_ptr<ITunerDvrCallback> tunerDvrCallback)
              : mTunerDvrCallback(tunerDvrCallback){};

        ::ndk::ScopedAStatus onRecordStatus(const RecordStatus status) override;
        ::ndk::ScopedAStatus onPlaybackStatus(const PlaybackStatus status) override;

    private:
        shared_ptr<ITunerDvrCallback> mTunerDvrCallback;
    };

private:
    shared_ptr<IDvr> mDvr;
    DvrType mType;
    bool isClosed = false;
};

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl

#endif // ANDROID_MEDIA_TUNERDVR_H
