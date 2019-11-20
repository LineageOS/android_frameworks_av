/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef ANDROID_SERVERS_CAMERA_PHOTOGRAPHY_CAMERAOFFLINESESSIONCLIENT_H
#define ANDROID_SERVERS_CAMERA_PHOTOGRAPHY_CAMERAOFFLINESESSIONCLIENT_H

#include <android/hardware/camera2/BnCameraOfflineSession.h>
#include <android/hardware/camera2/ICameraDeviceCallbacks.h>
#include "CameraService.h"
#include "CompositeStream.h"

namespace android {

using android::hardware::camera2::ICameraDeviceCallbacks;
using camera3::CompositeStream;

// Client for offline session. Note that offline session client does not affect camera service's
// client arbitration logic. It is camera HAL's decision to decide whether a normal camera
// client is conflicting with existing offline client(s).
// The other distinctive difference between offline clients and normal clients is that normal
// clients are created through ICameraService binder calls, while the offline session client
// is created through ICameraDeviceUser::switchToOffline call.
class CameraOfflineSessionClient :
        public CameraService::BasicClient,
        public hardware::camera2::BnCameraOfflineSession
        // public camera2::FrameProcessorBase::FilteredListener?
{
public:
    CameraOfflineSessionClient(
            const sp<CameraService>& cameraService,
            sp<CameraOfflineSessionBase> session,
            const KeyedVector<sp<IBinder>, sp<CompositeStream>>& offlineCompositeStreamMap,
            const sp<ICameraDeviceCallbacks>& remoteCallback,
            const String16& clientPackageName,
            const std::unique_ptr<String16>& clientFeatureId,
            const String8& cameraIdStr, int cameraFacing,
            int clientPid, uid_t clientUid, int servicePid) :
            CameraService::BasicClient(
                    cameraService,
                    IInterface::asBinder(remoteCallback),
                    clientPackageName, clientFeatureId,
                    cameraIdStr, cameraFacing, clientPid, clientUid, servicePid),
            mRemoteCallback(remoteCallback), mOfflineSession(session),
            mCompositeStreamMap(offlineCompositeStreamMap) {}

    virtual ~CameraOfflineSessionClient() {}

    virtual sp<IBinder> asBinderWrapper() override {
        return IInterface::asBinder(this);
    }

    virtual binder::Status disconnect() override;

    virtual status_t dump(int /*fd*/, const Vector<String16>& /*args*/) override;

    virtual status_t dumpClient(int /*fd*/, const Vector<String16>& /*args*/) override;

    virtual void notifyError(int32_t /*errorCode*/,
            const CaptureResultExtras& /*resultExtras*/) override;

    virtual status_t initialize(sp<CameraProviderManager> /*manager*/,
            const String8& /*monitorTags*/) override;

    // permissions management
    virtual status_t startCameraOps() override;
    virtual status_t finishCameraOps() override;

    // TODO: Those will be introduced when we implement FilteredListener and the device
    // callbacks respectively. Just adding for now.
    void onResultAvailable(const CaptureResult& result);
    void notifyShutter(const CaptureResultExtras& resultExtras, nsecs_t timestamp);

private:

    const sp<hardware::camera2::ICameraDeviceCallbacks>& getRemoteCallback() {
        return mRemoteCallback;
    }

    sp<hardware::camera2::ICameraDeviceCallbacks> mRemoteCallback;

    sp<CameraOfflineSessionBase> mOfflineSession;

    // Offline composite streams
    KeyedVector<sp<IBinder>, sp<CompositeStream>> mCompositeStreamMap;
};

} // namespace android

#endif // ANDROID_SERVERS_CAMERA_PHOTOGRAPHY_CAMERAOFFLINESESSIONCLIENT_H
