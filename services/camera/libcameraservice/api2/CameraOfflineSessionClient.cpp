/*
 * Copyright (C) 2009 The Android Open Source Project
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

#define LOG_TAG "CameraOfflineClient"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include "CameraOfflineSessionClient.h"
#include <utils/Trace.h>

namespace android {

using binder::Status;

status_t CameraOfflineSessionClient::initialize(sp<CameraProviderManager>, const String8&) {
    return OK;
}

status_t CameraOfflineSessionClient::dump(int /*fd*/, const Vector<String16>& /*args*/) {
    return OK;
}

status_t CameraOfflineSessionClient::dumpClient(int /*fd*/, const Vector<String16>& /*args*/) {
    return OK;
}

binder::Status CameraOfflineSessionClient::disconnect() {
    binder::Status res = Status::ok();
    if (mDisconnected) {
        return res;
    }
    mDisconnected = true;

    sCameraService->removeByClient(this);
    sCameraService->logDisconnectedOffline(mCameraIdStr, mClientPid, String8(mClientPackageName));

    sp<IBinder> remote = getRemote();
    if (remote != nullptr) {
        remote->unlinkToDeath(sCameraService);
    }

    finishCameraOps();
    ALOGI("%s: Disconnected client for offline camera %s for PID %d", __FUNCTION__,
            mCameraIdStr.string(), mClientPid);

    // client shouldn't be able to call into us anymore
    mClientPid = 0;

    for (size_t i = 0; i < mCompositeStreamMap.size(); i++) {
        auto ret = mCompositeStreamMap.valueAt(i)->deleteInternalStreams();
        if (ret != OK) {
            ALOGE("%s: Failed removing composite stream  %s (%d)", __FUNCTION__,
                    strerror(-ret), ret);
        }
    }
    mCompositeStreamMap.clear();

    return res;
}

void CameraOfflineSessionClient::notifyError(int32_t errorCode,
        const CaptureResultExtras& resultExtras) {
    // Thread safe. Don't bother locking.
    sp<hardware::camera2::ICameraDeviceCallbacks> remoteCb = getRemoteCallback();
    //
    // Composites can have multiple internal streams. Error notifications coming from such internal
    // streams may need to remain within camera service.
    bool skipClientNotification = false;
    for (size_t i = 0; i < mCompositeStreamMap.size(); i++) {
        skipClientNotification |= mCompositeStreamMap.valueAt(i)->onError(errorCode, resultExtras);
    }

    if ((remoteCb != 0) && (!skipClientNotification)) {
        remoteCb->onDeviceError(errorCode, resultExtras);
    }
}

status_t CameraOfflineSessionClient::startCameraOps() {
    ATRACE_CALL();
    {
        ALOGV("%s: Start camera ops, package name = %s, client UID = %d",
              __FUNCTION__, String8(mClientPackageName).string(), mClientUid);
    }

    if (mAppOpsManager != nullptr) {
        // Notify app ops that the camera is not available
        mOpsCallback = new OpsCallback(this);
        int32_t res;
        // TODO : possibly change this to OP_OFFLINE_CAMERA_SESSION
        mAppOpsManager->startWatchingMode(AppOpsManager::OP_CAMERA,
                mClientPackageName, mOpsCallback);
        // TODO : possibly change this to OP_OFFLINE_CAMERA_SESSION
        res = mAppOpsManager->startOpNoThrow(AppOpsManager::OP_CAMERA,
                mClientUid, mClientPackageName, /*startIfModeDefault*/ false);

        if (res == AppOpsManager::MODE_ERRORED) {
            ALOGI("Offline Camera %s: Access for \"%s\" has been revoked",
                    mCameraIdStr.string(), String8(mClientPackageName).string());
            return PERMISSION_DENIED;
        }

        if (res == AppOpsManager::MODE_IGNORED) {
            ALOGI("Offline Camera %s: Access for \"%s\" has been restricted",
                    mCameraIdStr.string(), String8(mClientPackageName).string());
            // Return the same error as for device policy manager rejection
            return -EACCES;
        }
    }

    mOpsActive = true;

    // Transition device state to OPEN
    sCameraService->mUidPolicy->registerMonitorUid(mClientUid);

    return OK;
}

status_t CameraOfflineSessionClient::finishCameraOps() {
    ATRACE_CALL();

    // Check if startCameraOps succeeded, and if so, finish the camera op
    if (mOpsActive) {
        // Notify app ops that the camera is available again
        if (mAppOpsManager != nullptr) {
        // TODO : possibly change this to OP_OFFLINE_CAMERA_SESSION
            mAppOpsManager->finishOp(AppOpsManager::OP_CAMERA, mClientUid,
                    mClientPackageName);
            mOpsActive = false;
        }
    }
    // Always stop watching, even if no camera op is active
    if (mOpsCallback != nullptr && mAppOpsManager != nullptr) {
        mAppOpsManager->stopWatchingMode(mOpsCallback);
    }
    mOpsCallback.clear();

    sCameraService->mUidPolicy->unregisterMonitorUid(mClientUid);

    return OK;
}

void CameraOfflineSessionClient::onResultAvailable(const CaptureResult& result) {
    ATRACE_CALL();
    ALOGV("%s", __FUNCTION__);

    // Thread-safe. No lock necessary.
    sp<hardware::camera2::ICameraDeviceCallbacks> remoteCb = mRemoteCallback;
    if (remoteCb != NULL) {
        remoteCb->onResultReceived(result.mMetadata, result.mResultExtras,
                result.mPhysicalMetadatas);
    }

    for (size_t i = 0; i < mCompositeStreamMap.size(); i++) {
        mCompositeStreamMap.valueAt(i)->onResultAvailable(result);
    }
}

void CameraOfflineSessionClient::notifyShutter(const CaptureResultExtras& resultExtras,
        nsecs_t timestamp) {
    // Thread safe. Don't bother locking.
    sp<hardware::camera2::ICameraDeviceCallbacks> remoteCb = getRemoteCallback();
    if (remoteCb != 0) {
        remoteCb->onCaptureStarted(resultExtras, timestamp);
    }

    for (size_t i = 0; i < mCompositeStreamMap.size(); i++) {
        mCompositeStreamMap.valueAt(i)->onShutter(resultExtras, timestamp);
    }
}

// ----------------------------------------------------------------------------
}; // namespace android
