/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_MEDIA_TUNERDVRHELPER_H
#define ANDROID_MEDIA_TUNERDVRHELPER_H

#include <aidl/android/media/tv/tunerresourcemanager/TunerDemuxInfo.h>
#include <aidl/android/media/tv/tunerresourcemanager/TunerFrontendInfo.h>
#include <utils/String16.h>

using ::aidl::android::media::tv::tunerresourcemanager::TunerDemuxInfo;
using ::aidl::android::media::tv::tunerresourcemanager::TunerFrontendInfo;
using ::android::String16;

using namespace std;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

const static int TUNER_HAL_VERSION_UNKNOWN = 0;
const static int TUNER_HAL_VERSION_1_0 = 1 << 16;
const static int TUNER_HAL_VERSION_1_1 = (1 << 16) | 1;
const static int TUNER_HAL_VERSION_2_0 = 2 << 16;

// Keep syncing with ShareFilter.java
const static int STATUS_INACCESSIBLE = 1 << 7;

const static String16 sSharedFilterPermission("android.permission.ACCESS_TV_SHARED_FILTER");

typedef enum {
    FRONTEND,
    DEMUX,
    DESCRAMBLER,
    LNB
} TunerResourceType;

class TunerHelper {
public:
    static bool checkTunerFeature();

    // TODO: update Demux, Descrambler.
    static void updateTunerResources(const vector<TunerFrontendInfo>& feInfos,
                                     const vector<int32_t>& lnbHandles);

    static void updateTunerResources(const vector<TunerFrontendInfo>& feInfos,
                                     const vector<TunerDemuxInfo>& demuxInfos,
                                     const vector<int32_t>& lnbHandles);
    // TODO: create a map between resource id and handles.
    static int getResourceIdFromHandle(int resourceHandle, int type);
    static int getResourceHandleFromId(int id, int resourceType);

private:
    static int32_t sResourceRequestCount;
};

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl

#endif  // ANDROID_MEDIA_TUNERDVRHELPER_H
