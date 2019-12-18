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

namespace android {

using android::hardware::camera2::ICameraDeviceCallbacks;

class CameraOfflineSessionClient :
        public CameraService::OfflineClient,
        public hardware::camera2::BnCameraOfflineSession
        // public camera2::FrameProcessorBase::FilteredListener?
{
public:
    CameraOfflineSessionClient(
            const sp<CameraService>& cameraService,
            sp<CameraOfflineSessionBase> session,
            const sp<ICameraDeviceCallbacks>& remoteCallback,
            const String16& clientPackageName,
            const String8& cameraIdStr,
            int clientPid, uid_t clientUid, int servicePid) :
                    CameraService::OfflineClient(cameraService, clientPackageName,
                            cameraIdStr, clientPid, clientUid, servicePid),
                            mRemoteCallback(remoteCallback), mOfflineSession(session) {}

    ~CameraOfflineSessionClient() {}

    virtual binder::Status disconnect() override { return binder::Status::ok(); }

    virtual status_t dump(int /*fd*/, const Vector<String16>& /*args*/) override {
        return OK;
    }

    // Block the client form using the camera
    virtual void block() override {};

    // Return the package name for this client
    virtual String16 getPackageName() const override { String16 ret; return ret; };

    // Notify client about a fatal error
    // TODO: maybe let impl notify within block?
    virtual void notifyError(int32_t /*errorCode*/,
            const CaptureResultExtras& /*resultExtras*/) override {}

    // Get the UID of the application client using this
    virtual uid_t getClientUid() const override { return 0; }

    // Get the PID of the application client using this
    virtual int getClientPid() const override { return 0; }

    status_t initialize() {
        // TODO: Talk to camera service to add the offline session client book keeping
        return OK;
    }
private:
    sp<CameraOfflineSessionBase> mSession;

    sp<hardware::camera2::ICameraDeviceCallbacks> mRemoteCallback;
    // This class is responsible to convert HAL callbacks to AIDL callbacks

    sp<CameraOfflineSessionBase> mOfflineSession;
};

} // namespace android

#endif // ANDROID_SERVERS_CAMERA_PHOTOGRAPHY_CAMERAOFFLINESESSIONCLIENT_H
