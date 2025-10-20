/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <vector>
#include <inttypes.h>
#include "ACameraDevice.h"
#include "ACameraMetadata.h"
#include "ACaptureRequest.h"
#include "ACameraCaptureSession.h"

namespace android {
namespace acam {

template<class T>
camera_status_t
CameraDevice::captureLocked(
        sp<ACameraCaptureSession> session,
        /*optional*/T* cbs,
        int numRequests, ACaptureRequest** requests,
        /*optional*/int* captureSequenceId) {
    return submitRequestsLocked(
            session, cbs, numRequests, requests, captureSequenceId, /*isRepeating*/false);
}

template<class T>
camera_status_t
CameraDevice::setRepeatingRequestsLocked(
        sp<ACameraCaptureSession> session,
        /*optional*/T* cbs,
        int numRequests, ACaptureRequest** requests,
        /*optional*/int* captureSequenceId) {
    return submitRequestsLocked(
            session, cbs, numRequests, requests, captureSequenceId, /*isRepeating*/true);
}

template<class T>
camera_status_t CameraDevice::submitRequestsLocked(
        sp<ACameraCaptureSession> session,
        /*optional*/T* cbs,
        int numRequests, ACaptureRequest** requests,
        /*optional*/int* captureSequenceId,
        bool isRepeating) {
    camera_status_t ret = checkCameraClosedOrErrorLocked();
    if (ret != ACAMERA_OK) {
        ALOGE("Camera %s submit capture request failed! ret %d", getId(), ret);
        return ret;
    }

    // Form two vectors of capture request, one for internal tracking
    std::vector<hardware::camera2::CaptureRequest> requestList;
    Vector<sp<CaptureRequest> > requestsV;
    requestsV.setCapacity(numRequests);
    // Check if we have a ZSL capture request.
    // Capture sequences with ZSL enabled may return frame numbers that
    // appear out of order relative to regular & repeating requests.
    // The callbacks for such ZSL capture sequences may need to be kept
    // for longer compared to regular/non-ZSL requests.
    bool isZsl = false;
    for (int i = 0; i < numRequests; i++) {
        sp<CaptureRequest> req;
        bool zslRequest = false;
        ret = allocateCaptureRequest(requests[i], req, &zslRequest);
        if (ret != ACAMERA_OK) {
            ALOGE("Convert capture request to internal format failure! ret %d", ret);
            return ret;
        }
        if (req->mSurfaceList.empty()) {
            ALOGE("Capture request without output target cannot be submitted!");
            return ACAMERA_ERROR_INVALID_PARAMETER;
        }
        requestList.push_back(*(req.get()));
        requestsV.push_back(req);
        isZsl |= zslRequest;
    }

    if (isRepeating) {
        ret = stopRepeatingLocked();
        if (ret != ACAMERA_OK) {
            ALOGE("Camera %s stop repeating failed! ret %d", getId(), ret);
            return ret;
        }
    }

    binder::Status remoteRet;
    hardware::camera2::utils::SubmitInfo info;
    remoteRet = mRemote->submitRequestList(requestList, isRepeating, &info);
    int sequenceId = info.mRequestId;
    int64_t lastFrameNumber = info.mLastFrameNumber;
    if (sequenceId < 0) {
        ALOGE("Camera %s submit request remote failure: ret %d", getId(), sequenceId);
        return ACAMERA_ERROR_UNKNOWN;
    }

    CallbackHolder cbHolder(session, requestsV, isRepeating, cbs);
    mSequenceCallbackMap.insert(std::make_pair(sequenceId, cbHolder));

    if (isRepeating) {
        // stopRepeating above should have cleanup repeating sequence id
        if (mRepeatingSequenceId != REQUEST_ID_NONE) {
            setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_DEVICE);
            return ACAMERA_ERROR_CAMERA_DEVICE;
        }
        mRepeatingSequenceId = sequenceId;
    } else {
        RequestLastFrameNumberHolder holder(lastFrameNumber);
        holder.isZsl = isZsl;
        mSequenceLastFrameNumberMap.insert(std::make_pair(sequenceId, holder));
    }

    if (mIdle) {
        sp<AMessage> msg = new AMessage(kWhatSessionStateCb, mHandler);
        msg->setPointer(kContextKey, session->mUserSessionCallback.context);
        msg->setObject(kSessionSpKey, session);
        msg->setPointer(kCallbackFpKey, (void*) session->mUserSessionCallback.onActive);
        postSessionMsgAndCleanup(msg);
    }
    mIdle = false;
    mBusySession = session;

    if (captureSequenceId) {
        *captureSequenceId = sequenceId;
    }
    return ACAMERA_OK;
}

template<class T>
camera_status_t CameraDevice::startStreamingLocked(ACameraCaptureSession* session,
        /*optional*/T* callbacks, int numOutputWindows,
        ANativeWindow** windows, /*optional*/int* captureSequenceId) {
    camera_status_t ret = checkCameraClosedOrErrorLocked();
    if (ret != ACAMERA_OK) {
        ALOGE("%s: camera is in closed or error state %d", __FUNCTION__, ret);
        return ret;
    }
    CameraMetadata rawPreviewRequest;
    binder::Status remoteRet = mRemote->createDefaultRequest(TEMPLATE_PREVIEW, &rawPreviewRequest);
    if (!remoteRet.isOk()) {
        ALOGE("%s: Create capture request failed: %s", __FUNCTION__, remoteRet.toString8().c_str());
        return ACAMERA_ERROR_UNKNOWN;
    }
    // ToDo: Check if the memory allocation can be freed automatically using either default_delete
    // or ScopedAResource.
    mPreviewRequest = new ACaptureRequest();
    mPreviewRequest->settings = new ACameraMetadata(rawPreviewRequest.release(),
            ACameraMetadata::ACM_REQUEST);
    mPreviewRequest->targets  = new ACameraOutputTargets();
    for (int i = 0; i < numOutputWindows ; i++) {
        ACameraOutputTarget* outputTarget = nullptr;
        ret = ACameraOutputTarget_create(windows[i], &outputTarget);
        if (ret != ACAMERA_OK) {
            ALOGE("%s: error while ACameraOutputTarget_create %d", __FUNCTION__, ret);
            return ret;
        }
        ret = ACaptureRequest_addTarget(mPreviewRequest, outputTarget);
        if (ret != ACAMERA_OK) {
            ALOGE("%s: error while ACaptureRequest_addTarget %d", __FUNCTION__, ret);
            return ret;
        }
        mPreviewRequestOutputs.push_back(outputTarget);
    }

    sp<CaptureRequest> req;
    ret = allocateCaptureRequest(mPreviewRequest, req);
    if (ret != ACAMERA_OK) {
        ALOGE("Convert capture request to internal format failure! ret %d", ret);
        return ret;
    }
    if (req->mSurfaceList.empty()) {
        ALOGE("Capture request without output target cannot be submitted!");
        return ACAMERA_ERROR_INVALID_PARAMETER;
    }

    // In shared session mode, if there are other active clients streaming then
    // stoprepeating does not actually send request to HAL to cancel the request.
    // Cameraservice will use this call to remove this client surfaces provided in its
    // previous streaming request. If this is the only client for the shared camera device
    // then camerservice will ask HAL to cancel the previous repeating request.
    ret = stopRepeatingLocked();
    if (ret != ACAMERA_OK) {
        ALOGE("Camera %s stop repeating failed! ret %d", getId(), ret);
        return ret;
    }

    hardware::camera2::utils::SubmitInfo info;
    std::vector<int> streamIds(req->mStreamIdxList.begin(), req->mStreamIdxList.end());
    std::vector<int> surfaceIds(req->mSurfaceIdxList.begin(), req->mSurfaceIdxList.end());
    remoteRet = mRemote->startStreaming(streamIds, surfaceIds, &info);
    int sequenceId = info.mRequestId;
    if (sequenceId < 0) {
        ALOGE("Camera %s start streaming remote failure: ret %d", getId(), sequenceId);
        return ACAMERA_ERROR_UNKNOWN;
    }

    Vector<sp<CaptureRequest> > requestsV;
    requestsV.push_back(req);
    CallbackHolder cbHolder(session, requestsV, true, callbacks);
    mSequenceCallbackMap.insert(std::make_pair(sequenceId, cbHolder));

    // stopRepeating above should have cleanup repeating sequence id
    if (mRepeatingSequenceId != REQUEST_ID_NONE) {
        setCameraDeviceErrorLocked(ACAMERA_ERROR_CAMERA_DEVICE);
        return ACAMERA_ERROR_CAMERA_DEVICE;
    }
    mRepeatingSequenceId = sequenceId;

    if (mIdle) {
        sp<AMessage> msg = new AMessage(kWhatSessionStateCb, mHandler);
        msg->setPointer(kContextKey, session->mUserSessionCallback.context);
        msg->setObject(kSessionSpKey, session);
        msg->setPointer(kCallbackFpKey, (void*) session->mUserSessionCallback.onActive);
        postSessionMsgAndCleanup(msg);
    }
    mIdle = false;
    mBusySession = session;

    if (captureSequenceId) {
        *captureSequenceId = sequenceId;
    }
    return ACAMERA_OK;
}

} // namespace acam
} // namespace android
