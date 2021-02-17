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

#ifndef ANDROID_MEDIA_TUNERFTIMEFILTER_H
#define ANDROID_MEDIA_TUNERFTIMEFILTER_H

#include <aidl/android/media/tv/tuner/BnTunerTimeFilter.h>
#include <android/hardware/tv/tuner/1.0/ITimeFilter.h>
#include <android/hardware/tv/tuner/1.1/types.h>
#include <media/stagefright/foundation/ADebug.h>
#include <utils/Log.h>

using Status = ::ndk::ScopedAStatus;
using ::aidl::android::media::tv::tuner::BnTunerTimeFilter;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::hidl_vec;
using ::android::hardware::tv::tuner::V1_0::ITimeFilter;

using namespace std;

namespace android {

class TunerTimeFilter : public BnTunerTimeFilter {

public:
    TunerTimeFilter(sp<ITimeFilter> timeFilter);
    virtual ~TunerTimeFilter();
    Status setTimeStamp(int64_t timeStamp) override;
    Status clearTimeStamp() override;
    Status getSourceTime(int64_t* _aidl_return) override;
    Status getTimeStamp(int64_t* _aidl_return) override;
    Status close() override;

private:
    sp<ITimeFilter> mTimeFilter;
};

} // namespace android

#endif // ANDROID_MEDIA_TUNERFTIMEFILTER_H
