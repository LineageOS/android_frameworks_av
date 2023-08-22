/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define LOG_TAG "CameraFlashlight"
#define ATRACE_TAG ATRACE_TAG_CAMERA
// #define LOG_NDEBUG 0

#include <utils/Log.h>
#include <utils/Trace.h>
#include <cutils/properties.h>

#include "camera/CameraMetadata.h"
#include "CameraFlashlight.h"
#include "gui/IGraphicBufferConsumer.h"
#include "gui/BufferQueue.h"
#include "camera/camera2/CaptureRequest.h"
#include "device3/Camera3Device.h"


namespace android {

/////////////////////////////////////////////////////////////////////
// CameraFlashlight implementation begins
// used by camera service to control flashflight.
/////////////////////////////////////////////////////////////////////

CameraFlashlight::CameraFlashlight(sp<CameraProviderManager> providerManager,
        CameraProviderManager::StatusListener* callbacks) :
        mProviderManager(providerManager),
        mCallbacks(callbacks),
        mFlashlightMapInitialized(false) {
}

CameraFlashlight::~CameraFlashlight() {
}

status_t CameraFlashlight::createFlashlightControl(const std::string& cameraId) {
    ALOGV("%s: creating a flash light control for camera %s", __FUNCTION__,
            cameraId.c_str());
    if (mFlashControl != NULL) {
        return INVALID_OPERATION;
    }

    if (mProviderManager->supportSetTorchMode(cameraId)) {
        mFlashControl = new ProviderFlashControl(mProviderManager);
    } else {
        ALOGE("Flashlight control not supported by this device!");
        return NO_INIT;
    }

    return OK;
}

status_t CameraFlashlight::setTorchMode(const std::string& cameraId, bool enabled) {
    if (!mFlashlightMapInitialized) {
        ALOGE("%s: findFlashUnits() must be called before this method.",
               __FUNCTION__);
        return NO_INIT;
    }

    ALOGV("%s: set torch mode of camera %s to %d", __FUNCTION__,
            cameraId.c_str(), enabled);

    status_t res = OK;
    Mutex::Autolock l(mLock);

    if (mOpenedCameraIds.indexOf(cameraId) != NAME_NOT_FOUND) {
        // This case is needed to avoid state corruption during the following call sequence:
        // CameraService::setTorchMode for camera ID 0 begins, does torch status checks
        // CameraService::connect for camera ID 0 begins, calls prepareDeviceOpen, ends
        // CameraService::setTorchMode for camera ID 0 continues, calls
        //        CameraFlashlight::setTorchMode

        // TODO: Move torch status checks and state updates behind this CameraFlashlight lock
        // to avoid other similar race conditions.
        ALOGE("%s: Camera device %s is in use, cannot set torch mode.",
                __FUNCTION__, cameraId.c_str());
        return -EBUSY;
    }

    if (mFlashControl == NULL) {
        res = createFlashlightControl(cameraId);
        if (res) {
            return res;
        }
        res =  mFlashControl->setTorchMode(cameraId, enabled);
        return res;
    }

    // if flash control already exists, turning on torch mode may fail if it's
    // tied to another camera device for module v2.3 and below.
    res = mFlashControl->setTorchMode(cameraId, enabled);
    if (res == BAD_INDEX) {
        // flash control is tied to another camera device, need to close it and
        // try again.
        mFlashControl.clear();
        res = createFlashlightControl(cameraId);
        if (res) {
            return res;
        }
        res = mFlashControl->setTorchMode(cameraId, enabled);
    }

    return res;
}

status_t CameraFlashlight::turnOnTorchWithStrengthLevel(const std::string& cameraId,
            int32_t torchStrength) {
    if (!mFlashlightMapInitialized) {
        ALOGE("%s: findFlashUnits() must be called before this method.",
               __FUNCTION__);
        return NO_INIT;
    }

    ALOGV("%s: set torch strength of camera %s to %d", __FUNCTION__,
            cameraId.c_str(), torchStrength);
    status_t res = OK;
    Mutex::Autolock l(mLock);

    if (mOpenedCameraIds.indexOf(cameraId) != NAME_NOT_FOUND) {
        ALOGE("%s: Camera device %s is in use, cannot be turned ON.",
                __FUNCTION__, cameraId.c_str());
        return -EBUSY;
    }

    if (mFlashControl == NULL) {
        res = createFlashlightControl(cameraId);
        if (res) {
            return res;
        }
    }

    res = mFlashControl->turnOnTorchWithStrengthLevel(cameraId, torchStrength);
    return res;
}


status_t CameraFlashlight::getTorchStrengthLevel(const std::string& cameraId,
            int32_t* torchStrength) {
    status_t res = OK;
    if (!mFlashlightMapInitialized) {
        ALOGE("%s: findFlashUnits() must be called before this method.",
            __FUNCTION__);
        return false;
    }

    Mutex::Autolock l(mLock);

    if (mFlashControl == NULL) {
        res = createFlashlightControl(cameraId);
        if (res) {
            return res;
        }
    }

    res = mFlashControl->getTorchStrengthLevel(cameraId, torchStrength);
    return res;
}

status_t CameraFlashlight::findFlashUnits() {
    Mutex::Autolock l(mLock);
    status_t res;

    std::vector<std::string> cameraIds;
    std::vector<std::string> ids = mProviderManager->getCameraDeviceIds();
    int numberOfCameras = static_cast<int>(ids.size());
    cameraIds.resize(numberOfCameras);
    // No module, must be provider
    for (size_t i = 0; i < cameraIds.size(); i++) {
        cameraIds[i] = ids[i];
    }

    mFlashControl.clear();

    for (auto &id : cameraIds) {
        ssize_t index = mHasFlashlightMap.indexOfKey(id);
        if (0 <= index) {
            continue;
        }

        bool hasFlash = false;
        res = createFlashlightControl(id);
        if (res) {
            ALOGE("%s: failed to create flash control for %s", __FUNCTION__,
                    id.c_str());
        } else {
            res = mFlashControl->hasFlashUnit(id, &hasFlash);
            if (res == -EUSERS || res == -EBUSY) {
                ALOGE("%s: failed to check if camera %s has a flash unit. Some "
                        "camera devices may be opened", __FUNCTION__,
                        id.c_str());
                return res;
            } else if (res) {
                ALOGE("%s: failed to check if camera %s has a flash unit. %s"
                        " (%d)", __FUNCTION__, id.c_str(), strerror(-res),
                        res);
            }

            mFlashControl.clear();
        }
        mHasFlashlightMap.add(id, hasFlash);
    }

    mFlashlightMapInitialized = true;
    return OK;
}

bool CameraFlashlight::hasFlashUnit(const std::string& cameraId) {
    Mutex::Autolock l(mLock);
    return hasFlashUnitLocked(cameraId);
}

bool CameraFlashlight::hasFlashUnitLocked(const std::string& cameraId) {
    if (!mFlashlightMapInitialized) {
        ALOGE("%s: findFlashUnits() must be called before this method.",
               __FUNCTION__);
        return false;
    }

    ssize_t index = mHasFlashlightMap.indexOfKey(cameraId);
    if (index == NAME_NOT_FOUND) {
        // Might be external camera
        ALOGW("%s: camera %s not present when findFlashUnits() was called",
                __FUNCTION__, cameraId.c_str());
        return false;
    }

    return mHasFlashlightMap.valueAt(index);
}

bool CameraFlashlight::isBackwardCompatibleMode(const std::string& cameraId) {
    bool backwardCompatibleMode = false;
    if (mProviderManager != nullptr &&
            !mProviderManager->supportSetTorchMode(cameraId)) {
        backwardCompatibleMode = true;
    }
    return backwardCompatibleMode;
}

status_t CameraFlashlight::prepareDeviceOpen(const std::string& cameraId) {
    ALOGV("%s: prepare for device open", __FUNCTION__);

    Mutex::Autolock l(mLock);
    if (!mFlashlightMapInitialized) {
        ALOGE("%s: findFlashUnits() must be called before this method.",
               __FUNCTION__);
        return NO_INIT;
    }

    if (isBackwardCompatibleMode(cameraId)) {
        // framework is going to open a camera device, all flash light control
        // should be closed for backward compatible support.
        mFlashControl.clear();

        if (mOpenedCameraIds.size() == 0) {
            // notify torch unavailable for all cameras with a flash
            std::vector<std::string> ids = mProviderManager->getCameraDeviceIds();
            int numCameras = static_cast<int>(ids.size());
            for (int i = 0; i < numCameras; i++) {
                if (hasFlashUnitLocked(ids[i])) {
                    mCallbacks->onTorchStatusChanged(
                            ids[i], TorchModeStatus::NOT_AVAILABLE);
                }
            }
        }

        // close flash control that may be opened by calling hasFlashUnitLocked.
        mFlashControl.clear();
    }

    if (mOpenedCameraIds.indexOf(cameraId) == NAME_NOT_FOUND) {
        mOpenedCameraIds.add(cameraId);
    }

    return OK;
}

status_t CameraFlashlight::deviceClosed(const std::string& cameraId) {
    ALOGV("%s: device %s is closed", __FUNCTION__, cameraId.c_str());

    Mutex::Autolock l(mLock);
    if (!mFlashlightMapInitialized) {
        ALOGE("%s: findFlashUnits() must be called before this method.",
               __FUNCTION__);
        return NO_INIT;
    }

    ssize_t index = mOpenedCameraIds.indexOf(cameraId);
    if (index == NAME_NOT_FOUND) {
        ALOGE("%s: couldn't find camera %s in the opened list", __FUNCTION__,
                cameraId.c_str());
    } else {
        mOpenedCameraIds.removeAt(index);
    }

    // Cannot do anything until all cameras are closed.
    if (mOpenedCameraIds.size() != 0)
        return OK;

    if (isBackwardCompatibleMode(cameraId)) {
        // notify torch available for all cameras with a flash
        std::vector<std::string> ids = mProviderManager->getCameraDeviceIds();
        int numCameras = static_cast<int>(ids.size());
        for (int i = 0; i < numCameras; i++) {
            if (hasFlashUnitLocked(ids[i])) {
                mCallbacks->onTorchStatusChanged(
                        ids[i], TorchModeStatus::AVAILABLE_OFF);
            }
        }
    }

    return OK;
}
// CameraFlashlight implementation ends


FlashControlBase::~FlashControlBase() {
}

/////////////////////////////////////////////////////////////////////
// ModuleFlashControl implementation begins
// Flash control for camera module v2.4 and above.
/////////////////////////////////////////////////////////////////////
ProviderFlashControl::ProviderFlashControl(sp<CameraProviderManager> providerManager) :
        mProviderManager(providerManager) {
}

ProviderFlashControl::~ProviderFlashControl() {
}

status_t ProviderFlashControl::hasFlashUnit(const std::string& cameraId, bool *hasFlash) {
    if (!hasFlash) {
        return BAD_VALUE;
    }
    *hasFlash = mProviderManager->hasFlashUnit(cameraId);
    return OK;
}

status_t ProviderFlashControl::setTorchMode(const std::string& cameraId, bool enabled) {
    ALOGV("%s: set camera %s torch mode to %d", __FUNCTION__,
            cameraId.c_str(), enabled);

    return mProviderManager->setTorchMode(cameraId, enabled);
}

status_t ProviderFlashControl::turnOnTorchWithStrengthLevel(const std::string& cameraId,
            int32_t torchStrength) {
    ALOGV("%s: change torch strength level of camera %s to %d", __FUNCTION__,
            cameraId.c_str(), torchStrength);

    return mProviderManager->turnOnTorchWithStrengthLevel(cameraId, torchStrength);
}

status_t ProviderFlashControl::getTorchStrengthLevel(const std::string& cameraId,
            int32_t* torchStrength) {
    ALOGV("%s: get torch strength level of camera %s", __FUNCTION__,
            cameraId.c_str());

    return mProviderManager->getTorchStrengthLevel(cameraId, torchStrength);
}
// ProviderFlashControl implementation ends

}
