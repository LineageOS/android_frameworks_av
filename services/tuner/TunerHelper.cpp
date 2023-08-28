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

#include "TunerHelper.h"

#include <aidl/android/media/tv/tunerresourcemanager/ITunerResourceManager.h>
#include <android/binder_manager.h>
#include <android/content/pm/IPackageManagerNative.h>
#include <binder/IServiceManager.h>
#include <utils/Log.h>

using ::aidl::android::media::tv::tunerresourcemanager::ITunerResourceManager;
using ::android::defaultServiceManager;
using ::android::IBinder;
using ::android::interface_cast;
using ::android::IServiceManager;
using ::android::sp;
using ::android::binder::Status;
using ::android::content::pm::IPackageManagerNative;

namespace aidl {
namespace android {
namespace media {
namespace tv {
namespace tuner {

// System Feature defined in PackageManager
static const ::android::String16 FEATURE_TUNER(::android::String16("android.hardware.tv.tuner"));

int32_t TunerHelper::sResourceRequestCount = 0;

bool TunerHelper::checkTunerFeature() {
    sp<IServiceManager> serviceMgr = defaultServiceManager();
    sp<IPackageManagerNative> packageMgr;
    if (serviceMgr.get() == nullptr) {
        ALOGE("%s: Cannot find service manager", __func__);
        return false;
    }

    sp<IBinder> binder = serviceMgr->waitForService(String16("package_native"));
    packageMgr = interface_cast<IPackageManagerNative>(binder);
    if (packageMgr != nullptr) {
        bool hasFeature = false;
        Status status = packageMgr->hasSystemFeature(FEATURE_TUNER, 0, &hasFeature);
        if (!status.isOk()) {
            ALOGE("%s: hasSystemFeature failed: %s", __func__, status.exceptionMessage().c_str());
            return false;
        }
        if (!hasFeature) {
            ALOGD("Current device does not support tuner feaure.");
            return false;
        }
    } else {
        ALOGD("%s: Cannot find package manager.", __func__);
        return false;
    }

    return true;
}

// TODO: update Demux, Descrambler.
void TunerHelper::updateTunerResources(const vector<TunerFrontendInfo>& feInfos,
                                       const vector<int32_t>& lnbHandles) {
    ::ndk::SpAIBinder binder(AServiceManager_waitForService("tv_tuner_resource_mgr"));
    shared_ptr<ITunerResourceManager> tunerRM = ITunerResourceManager::fromBinder(binder);
    if (tunerRM == nullptr) {
        return;
    }

    tunerRM->setFrontendInfoList(feInfos);
    tunerRM->setLnbInfoList(lnbHandles);
}
void TunerHelper::updateTunerResources(const vector<TunerFrontendInfo>& feInfos,
                                       const vector<TunerDemuxInfo>& demuxInfos,
                                       const vector<int32_t>& lnbHandles) {
    ::ndk::SpAIBinder binder(AServiceManager_waitForService("tv_tuner_resource_mgr"));
    shared_ptr<ITunerResourceManager> tunerRM = ITunerResourceManager::fromBinder(binder);
    if (tunerRM == nullptr) {
        return;
    }

    updateTunerResources(feInfos, lnbHandles);

    // for Tuner 2.0 and below, Demux resource is not really managed under TRM
    if (demuxInfos.size() > 0) {
        tunerRM->setDemuxInfoList(demuxInfos);
    }
}

// TODO: create a map between resource id and handles.
int TunerHelper::getResourceIdFromHandle(int resourceHandle, int /*type*/) {
    return (resourceHandle & 0x00ff0000) >> 16;
}

int TunerHelper::getResourceHandleFromId(int id, int resourceType) {
    // TODO: build up randomly generated id to handle mapping
    return (resourceType & 0x000000ff) << 24 | (id << 16) | (sResourceRequestCount++ & 0xffff);
}

}  // namespace tuner
}  // namespace tv
}  // namespace media
}  // namespace android
}  // namespace aidl
