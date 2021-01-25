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

#ifndef ANDROID_MEDIA_TUNERDEMUX_H
#define ANDROID_MEDIA_TUNERDEMUX_H

#include <aidl/android/media/tv/tuner/BnTunerDemux.h>
#include <android/hardware/tv/tuner/1.0/ITuner.h>

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::tv::tuner::BnTunerDemux;
using ::aidl::android::media::tv::tuner::ITunerFilter;
using ::aidl::android::media::tv::tuner::ITunerFilterCallback;
using ::aidl::android::media::tv::tuner::ITunerFrontend;
using ::android::hardware::tv::tuner::V1_0::IDemux;


namespace android {

class TunerDemux : public BnTunerDemux {

public:
    TunerDemux(sp<IDemux> demux, int demuxId);
    virtual ~TunerDemux();
    Status setFrontendDataSource(const std::shared_ptr<ITunerFrontend>& frontend) override;
    Status openFilter(
        int mainType, int subtype, int bufferSize, const std::shared_ptr<ITunerFilterCallback>& cb,
        std::shared_ptr<ITunerFilter>* _aidl_return);

private:
    sp<IDemux> mDemux;
    int mDemuxId;
};

} // namespace android

#endif // ANDROID_MEDIA_TUNERDEMUX_H
