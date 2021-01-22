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

#ifndef ANDROID_MEDIA_TUNERFILTER_H
#define ANDROID_MEDIA_TUNERFILTER_H

#include <aidl/android/media/tv/tuner/BnTunerFilter.h>
#include <aidl/android/media/tv/tuner/ITunerFilterCallback.h>
#include <android/hardware/tv/tuner/1.0/ITuner.h>
#include <media/stagefright/foundation/ADebug.h>

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::tv::tuner::BnTunerFilter;
using ::aidl::android::media::tv::tuner::ITunerFilterCallback;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterEvent;
using ::android::hardware::tv::tuner::V1_0::DemuxFilterStatus;
using ::android::hardware::tv::tuner::V1_0::IFilter;
using ::android::hardware::tv::tuner::V1_0::IFilterCallback;


namespace android {

class TunerFilter : public BnTunerFilter {

public:
    TunerFilter(sp<IFilter> filter, sp<IFilterCallback> callback);
    virtual ~TunerFilter();
    Status getId(int32_t* _aidl_return) override;

    struct FilterCallback : public IFilterCallback {
        FilterCallback(const std::shared_ptr<ITunerFilterCallback> tunerFilterCallback)
                : mTunerFilterCallback(tunerFilterCallback) {};

        virtual Return<void> onFilterEvent(const DemuxFilterEvent& filterEvent);
        virtual Return<void> onFilterStatus(DemuxFilterStatus status);

        std::shared_ptr<ITunerFilterCallback> mTunerFilterCallback;
    };

private:
    sp<IFilter> mFilter;
    sp<IFilterCallback> mFilterCallback;
    int32_t mId;
};

} // namespace android

#endif // ANDROID_MEDIA_TUNERFILTER_H
