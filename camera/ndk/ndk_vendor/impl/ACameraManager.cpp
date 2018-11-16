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

//#define LOG_NDEBUG 0
#define LOG_TAG "ACameraManagerVendor"

#include <memory>
#include "ndk_vendor/impl/ACameraManager.h"
#include "ACameraMetadata.h"
#include "ndk_vendor/impl/ACameraDevice.h"
#include "utils.h"

#include <utils/Vector.h>
#include <cutils/properties.h>
#include <stdlib.h>

#include <VendorTagDescriptor.h>

using namespace android::acam;

namespace android {
namespace acam {

using CameraStatusAndId = frameworks::cameraservice::service::V2_0::CameraStatusAndId;

// Static member definitions
const char* CameraManagerGlobal::kCameraIdKey   = "CameraId";
const char* CameraManagerGlobal::kCallbackFpKey = "CallbackFp";
const char* CameraManagerGlobal::kContextKey    = "CallbackContext";
Mutex                CameraManagerGlobal::sLock;
CameraManagerGlobal* CameraManagerGlobal::sInstance = nullptr;

CameraManagerGlobal&
CameraManagerGlobal::getInstance() {
    Mutex::Autolock _l(sLock);
    CameraManagerGlobal* instance = sInstance;
    if (instance == nullptr) {
        instance = new CameraManagerGlobal();
        sInstance = instance;
    }
    return *instance;
}

CameraManagerGlobal::~CameraManagerGlobal() {
    // clear sInstance so next getInstance call knows to create a new one
    Mutex::Autolock _sl(sLock);
    sInstance = nullptr;
    Mutex::Autolock _l(mLock);
    if (mCameraService != nullptr) {
        mCameraService->unlinkToDeath(mDeathNotifier);
        mCameraService->removeListener(mCameraServiceListener);
    }
    mDeathNotifier.clear();
    if (mCbLooper != nullptr) {
        mCbLooper->unregisterHandler(mHandler->id());
        mCbLooper->stop();
    }
    mCbLooper.clear();
    mHandler.clear();
    mCameraServiceListener.clear();
    mCameraService.clear();
}

static bool isCameraServiceDisabled() {
    char value[PROPERTY_VALUE_MAX];
    property_get("config.disable_cameraservice", value, "0");
    return (strncmp(value, "0", 2) != 0 && strncasecmp(value, "false", 6) != 0);
}

// TODO: Add back when vendor tags are supported for libcamera2ndk_vendor when
//       the HIDL interface supports querying by vendor id.

sp<ICameraService> CameraManagerGlobal::getCameraService() {
    Mutex::Autolock _l(mLock);
    if (mCameraService.get() == nullptr) {
        if (isCameraServiceDisabled()) {
            return mCameraService;
        }

        sp<ICameraService> cameraServiceBinder;
        do {
            cameraServiceBinder = ICameraService::getService();
            if (cameraServiceBinder != nullptr) {
                break;
            }
            ALOGW("CameraService not published, waiting...");
            usleep(kCameraServicePollDelay);
        } while(true);
        if (mDeathNotifier == nullptr) {
            mDeathNotifier = new DeathNotifier(this);
        }
        cameraServiceBinder->linkToDeath(mDeathNotifier, 0);
        mCameraService = cameraServiceBinder;

        // Setup looper thread to perfrom availiability callbacks
        if (mCbLooper == nullptr) {
            mCbLooper = new ALooper;
            mCbLooper->setName("C2N-mgr-looper");
            status_t err = mCbLooper->start(
                    /*runOnCallingThread*/false,
                    /*canCallJava*/       true,
                    PRIORITY_DEFAULT);
            if (err != OK) {
                ALOGE("%s: Unable to start camera service listener looper: %s (%d)",
                        __FUNCTION__, strerror(-err), err);
                mCbLooper.clear();
                return nullptr;
            }
            if (mHandler == nullptr) {
                mHandler = new CallbackHandler();
            }
            mCbLooper->registerHandler(mHandler);
        }

        // register ICameraServiceListener
        if (mCameraServiceListener == nullptr) {
            mCameraServiceListener = new CameraServiceListener(this);
        }
        hidl_vec<CameraStatusAndId> cameraStatuses{};
        Status status = Status::NO_ERROR;
        auto remoteRet = mCameraService->addListener(mCameraServiceListener,
                                                     [&status, &cameraStatuses](Status s,
                                                                                auto &retStatuses) {
                                                         status = s;
                                                         cameraStatuses = retStatuses;
                                                     });
        if (!remoteRet.isOk() || status != Status::NO_ERROR) {
            ALOGE("Failed to add listener to camera service %s", remoteRet.description().c_str());
        }
        for (auto& c : cameraStatuses) {
            onStatusChangedLocked(c);
        }
    }
    return mCameraService;
}

void CameraManagerGlobal::DeathNotifier::serviceDied(uint64_t cookie, const wp<IBase> &who) {
    (void) cookie;
    (void) who;
    ALOGE("Camera service binderDied!");
    sp<CameraManagerGlobal> cm = mCameraManager.promote();
    if (cm != nullptr) {
        AutoMutex lock(cm->mLock);
        for (auto& pair : cm->mDeviceStatusMap) {
            CameraStatusAndId cameraStatusAndId;
            cameraStatusAndId.cameraId = pair.first;
            cameraStatusAndId.deviceStatus = pair.second;
            cm->onStatusChangedLocked(cameraStatusAndId);
        }
        cm->mCameraService.clear();
        // TODO: consider adding re-connect call here?
    }
}

void CameraManagerGlobal::registerAvailabilityCallback(
        const ACameraManager_AvailabilityCallbacks *callback) {
    Mutex::Autolock _l(mLock);
    Callback cb(callback);
    auto pair = mCallbacks.insert(cb);
    // Send initial callbacks if callback is newly registered
    if (pair.second) {
        for (auto& pair : mDeviceStatusMap) {
            const hidl_string& cameraId = pair.first;
            CameraDeviceStatus status = pair.second;

            sp<AMessage> msg = new AMessage(kWhatSendSingleCallback, mHandler);
            ACameraManager_AvailabilityCallback cb = isStatusAvailable(status) ?
                    callback->onCameraAvailable : callback->onCameraUnavailable;
            msg->setPointer(kCallbackFpKey, (void *) cb);
            msg->setPointer(kContextKey, callback->context);
            msg->setString(kCameraIdKey, AString(cameraId.c_str()));
            msg->post();
        }
    }
}

void CameraManagerGlobal::unregisterAvailabilityCallback(
        const ACameraManager_AvailabilityCallbacks *callback) {
    Mutex::Autolock _l(mLock);
    Callback cb(callback);
    mCallbacks.erase(cb);
}

void CameraManagerGlobal::getCameraIdList(std::vector<hidl_string>* cameraIds) {
    // Ensure that we have initialized/refreshed the list of available devices
    auto cs = getCameraService();
    Mutex::Autolock _l(mLock);

    for(auto& deviceStatus : mDeviceStatusMap) {
        if (deviceStatus.second == CameraDeviceStatus::STATUS_NOT_PRESENT ||
                deviceStatus.second == CameraDeviceStatus::STATUS_ENUMERATING) {
            continue;
        }
        cameraIds->push_back(deviceStatus.first);
    }
}

bool CameraManagerGlobal::validStatus(CameraDeviceStatus status) {
    switch (status) {
        case CameraDeviceStatus::STATUS_NOT_PRESENT:
        case CameraDeviceStatus::STATUS_PRESENT:
        case CameraDeviceStatus::STATUS_ENUMERATING:
        case CameraDeviceStatus::STATUS_NOT_AVAILABLE:
            return true;
        default:
            return false;
    }
}

bool CameraManagerGlobal::isStatusAvailable(CameraDeviceStatus status) {
    switch (status) {
        case CameraDeviceStatus::STATUS_PRESENT:
            return true;
        default:
            return false;
    }
}

void CameraManagerGlobal::CallbackHandler::onMessageReceived(
        const sp<AMessage> &msg) {
    switch (msg->what()) {
        case kWhatSendSingleCallback:
        {
            ACameraManager_AvailabilityCallback cb;
            void* context;
            AString cameraId;
            bool found = msg->findPointer(kCallbackFpKey, (void**) &cb);
            if (!found) {
                ALOGE("%s: Cannot find camera callback fp!", __FUNCTION__);
                return;
            }
            found = msg->findPointer(kContextKey, &context);
            if (!found) {
                ALOGE("%s: Cannot find callback context!", __FUNCTION__);
                return;
            }
            found = msg->findString(kCameraIdKey, &cameraId);
            if (!found) {
                ALOGE("%s: Cannot find camera ID!", __FUNCTION__);
                return;
            }
            (*cb)(context, cameraId.c_str());
            break;
        }
        default:
            ALOGE("%s: unknown message type %d", __FUNCTION__, msg->what());
            break;
    }
}

hardware::Return<void> CameraManagerGlobal::CameraServiceListener::onStatusChanged(
        const CameraStatusAndId &statusAndId) {
    sp<CameraManagerGlobal> cm = mCameraManager.promote();
    if (cm != nullptr) {
        cm->onStatusChanged(statusAndId);
    } else {
        ALOGE("Cannot deliver status change. Global camera manager died");
    }
    return Void();
}

void CameraManagerGlobal::onStatusChanged(
        const CameraStatusAndId &statusAndId) {
    Mutex::Autolock _l(mLock);
    onStatusChangedLocked(statusAndId);
}

void CameraManagerGlobal::onStatusChangedLocked(
        const CameraStatusAndId &statusAndId) {
    hidl_string cameraId = statusAndId.cameraId;
    CameraDeviceStatus status = statusAndId.deviceStatus;
    if (!validStatus(status)) {
        ALOGE("%s: Invalid status %d", __FUNCTION__, status);
        return;
    }

    bool firstStatus = (mDeviceStatusMap.count(cameraId) == 0);
    CameraDeviceStatus oldStatus = firstStatus ?
            status : // first status
            mDeviceStatusMap[cameraId];

    if (!firstStatus &&
            isStatusAvailable(status) == isStatusAvailable(oldStatus)) {
        // No status update. No need to send callback
        return;
    }

    // Iterate through all registered callbacks
    mDeviceStatusMap[cameraId] = status;
    for (auto cb : mCallbacks) {
        sp<AMessage> msg = new AMessage(kWhatSendSingleCallback, mHandler);
        ACameraManager_AvailabilityCallback cbFp = isStatusAvailable(status) ?
                cb.mAvailable : cb.mUnavailable;
        msg->setPointer(kCallbackFpKey, (void *) cbFp);
        msg->setPointer(kContextKey, cb.mContext);
        msg->setString(kCameraIdKey, AString(cameraId.c_str()));
        msg->post();
    }
    if (status == CameraDeviceStatus::STATUS_NOT_PRESENT) {
        mDeviceStatusMap.erase(cameraId);
    }
}

} // namespace acam
} // namespace android

/**
 * ACameraManger Implementation
 */
camera_status_t
ACameraManager::getCameraIdList(ACameraIdList** cameraIdList) {
    Mutex::Autolock _l(mLock);

    std::vector<hidl_string> idList;
    CameraManagerGlobal::getInstance().getCameraIdList(&idList);

    int numCameras = idList.size();
    ACameraIdList *out = new ACameraIdList;
    if (!out) {
        ALOGE("Allocate memory for ACameraIdList failed!");
        return ACAMERA_ERROR_NOT_ENOUGH_MEMORY;
    }
    out->numCameras = numCameras;
    out->cameraIds = new const char*[numCameras];
    if (!out->cameraIds) {
        ALOGE("Allocate memory for ACameraIdList failed!");
        deleteCameraIdList(out);
        return ACAMERA_ERROR_NOT_ENOUGH_MEMORY;
    }
    for (int i = 0; i < numCameras; i++) {
        const char* src = idList[i].c_str();
        size_t dstSize = strlen(src) + 1;
        char* dst = new char[dstSize];
        if (!dst) {
            ALOGE("Allocate memory for ACameraIdList failed!");
            deleteCameraIdList(out);
            return ACAMERA_ERROR_NOT_ENOUGH_MEMORY;
        }
        strlcpy(dst, src, dstSize);
        out->cameraIds[i] = dst;
    }
    *cameraIdList = out;
    return ACAMERA_OK;
}

void
ACameraManager::deleteCameraIdList(ACameraIdList* cameraIdList) {
    if (cameraIdList != nullptr) {
        if (cameraIdList->cameraIds != nullptr) {
            for (int i = 0; i < cameraIdList->numCameras; i ++) {
                if (cameraIdList->cameraIds[i] != nullptr) {
                    delete[] cameraIdList->cameraIds[i];
                }
            }
            delete[] cameraIdList->cameraIds;
        }
        delete cameraIdList;
    }
}

camera_status_t ACameraManager::getCameraCharacteristics(
        const char *cameraIdStr, sp<ACameraMetadata> *characteristics) {
    Mutex::Autolock _l(mLock);

    sp<ICameraService> cs = CameraManagerGlobal::getInstance().getCameraService();
    if (cs == nullptr) {
        ALOGE("%s: Cannot reach camera service!", __FUNCTION__);
        return ACAMERA_ERROR_CAMERA_DISCONNECTED;
    }
    CameraMetadata rawMetadata;
    Status status = Status::NO_ERROR;
    auto serviceRet =
        cs->getCameraCharacteristics(cameraIdStr,
                                     [&status, &rawMetadata] (auto s ,
                                                              const hidl_vec<uint8_t> &metadata) {
                                          status = s;
                                          if (status == Status::NO_ERROR) {
                                              utils::convertFromHidlCloned(metadata, &rawMetadata);
                                          }
                                     });
    if (!serviceRet.isOk() || status != Status::NO_ERROR) {
        ALOGE("Get camera characteristics from camera service failed");
        return ACAMERA_ERROR_UNKNOWN; // should not reach here
    }

    *characteristics = new ACameraMetadata(
            rawMetadata.release(), ACameraMetadata::ACM_CHARACTERISTICS);
    return ACAMERA_OK;
}

camera_status_t
ACameraManager::openCamera(
        const char* cameraId,
        ACameraDevice_StateCallbacks* callback,
        /*out*/ACameraDevice** outDevice) {
    sp<ACameraMetadata> rawChars;
    camera_status_t ret = getCameraCharacteristics(cameraId, &rawChars);
    Mutex::Autolock _l(mLock);
    if (ret != ACAMERA_OK) {
        ALOGE("%s: cannot get camera characteristics for camera %s. err %d",
                __FUNCTION__, cameraId, ret);
        return ACAMERA_ERROR_INVALID_PARAMETER;
    }

    ACameraDevice* device = new ACameraDevice(cameraId, callback, std::move(rawChars));

    sp<ICameraService> cs = CameraManagerGlobal::getInstance().getCameraService();
    if (cs == nullptr) {
        ALOGE("%s: Cannot reach camera service!", __FUNCTION__);
        delete device;
        return ACAMERA_ERROR_CAMERA_DISCONNECTED;
    }

    sp<ICameraDeviceCallback> callbacks = device->getServiceCallback();
    sp<ICameraDeviceUser> deviceRemote;

    // No way to get package name from native.
    // Send a zero length package name and let camera service figure it out from UID
    Status status = Status::NO_ERROR;
    auto serviceRet = cs->connectDevice(
            callbacks, cameraId, [&status, &deviceRemote](auto s, auto &device) {
                                     status = s;
                                     deviceRemote = device;
                                 });

    if (!serviceRet.isOk() || status != Status::NO_ERROR) {
        ALOGE("%s: connect camera device failed", __FUNCTION__);
        // TODO: Convert serviceRet to camera_status_t
        delete device;
        return ACAMERA_ERROR_UNKNOWN;
    }
    if (deviceRemote == nullptr) {
        ALOGE("%s: connect camera device failed! remote device is null", __FUNCTION__);
        delete device;
        return ACAMERA_ERROR_CAMERA_DISCONNECTED;
    }
    device->setRemoteDevice(deviceRemote);
    device->setDeviceMetadataQueues();
    *outDevice = device;
    return ACAMERA_OK;
}

ACameraManager::~ACameraManager() {

}
