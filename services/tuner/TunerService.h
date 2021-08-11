/**
 * Copyright (c) 2021, The Android Open Source Project
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

#ifndef ANDROID_MEDIA_TUNERSERVICE_H
#define ANDROID_MEDIA_TUNERSERVICE_H

#include <aidl/android/hardware/tv/tuner/BnFilterCallback.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterEvent.h>
#include <aidl/android/hardware/tv/tuner/DemuxFilterStatus.h>
#include <aidl/android/hardware/tv/tuner/ITuner.h>
#include <aidl/android/media/tv/tuner/BnTunerService.h>
#include <aidl/android/media/tv/tunerresourcemanager/ITunerResourceManager.h>

using ::aidl::android::hardware::tv::tuner::BnFilterCallback;
using ::aidl::android::hardware::tv::tuner::DemuxCapabilities;
using ::aidl::android::hardware::tv::tuner::DemuxFilterEvent;
using ::aidl::android::hardware::tv::tuner::DemuxFilterStatus;
using ::aidl::android::hardware::tv::tuner::FrontendInfo;
using ::aidl::android::hardware::tv::tuner::ITuner;
using ::aidl::android::media::tv::tunerresourcemanager::ITunerResourceManager;

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
// System Feature defined in PackageManager
static const ::android::String16 FEATURE_TUNER(::android::String16("android.hardware.tv.tuner"));

typedef enum {
    FRONTEND,
    LNB,
    DEMUX,
    DESCRAMBLER,
} TunerResourceType;

struct FilterCallback : public BnFilterCallback {
    ~FilterCallback() {}
    virtual ::ndk::ScopedAStatus onFilterEvent(
            const vector<DemuxFilterEvent>& /* events */) override {
        return ::ndk::ScopedAStatus::ok();
    }

    virtual ::ndk::ScopedAStatus onFilterStatus(const DemuxFilterStatus /*status*/) override {
        return ::ndk::ScopedAStatus::ok();
    }
};

class TunerService : public BnTunerService {
public:
    static char const *getServiceName() { return "media.tuner"; }
    static binder_status_t instantiate();
    TunerService();
    virtual ~TunerService();

    ::ndk::ScopedAStatus getFrontendIds(vector<int32_t>* out_ids) override;
    ::ndk::ScopedAStatus getFrontendInfo(int32_t in_frontendHandle,
                                         FrontendInfo* _aidl_return) override;
    ::ndk::ScopedAStatus openFrontend(int32_t in_frontendHandle,
                                      shared_ptr<ITunerFrontend>* _aidl_return) override;
    ::ndk::ScopedAStatus openLnb(int32_t in_lnbHandle,
                                 shared_ptr<ITunerLnb>* _aidl_return) override;
    ::ndk::ScopedAStatus openLnbByName(const string& in_lnbName,
                                       shared_ptr<ITunerLnb>* _aidl_return) override;
    ::ndk::ScopedAStatus openDemux(int32_t in_demuxHandle,
                                   shared_ptr<ITunerDemux>* _aidl_return) override;
    ::ndk::ScopedAStatus getDemuxCaps(DemuxCapabilities* _aidl_return) override;
    ::ndk::ScopedAStatus openDescrambler(int32_t in_descramblerHandle,
                                         shared_ptr<ITunerDescrambler>* _aidl_return) override;
    ::ndk::ScopedAStatus getTunerHalVersion(int32_t* _aidl_return) override;

    // TODO: create a map between resource id and handles.
    static int getResourceIdFromHandle(int resourceHandle, int /*type*/) {
        return (resourceHandle & 0x00ff0000) >> 16;
    }

    int getResourceHandleFromId(int id, int resourceType) {
        // TODO: build up randomly generated id to handle mapping
        return (resourceType & 0x000000ff) << 24
                | (id << 16)
                | (mResourceRequestCount++ & 0xffff);
    }

private:
    bool hasITuner();
    void updateTunerResources();
    void updateFrontendResources();
    void updateLnbResources();
    vector<int32_t> getLnbHandles();

    shared_ptr<ITuner> mTuner;
    shared_ptr<ITunerResourceManager> mTunerResourceManager;
    int mResourceRequestCount = 0;
    int mTunerVersion = TUNER_HAL_VERSION_UNKNOWN;
};

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl

#endif // ANDROID_MEDIA_TUNERSERVICE_H
