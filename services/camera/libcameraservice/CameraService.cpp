/*
 * Copyright (C) 2008 The Android Open Source Project
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

#define LOG_TAG "CameraService"
#define ATRACE_TAG ATRACE_TAG_CAMERA
//#define LOG_NDEBUG 0

#include <algorithm>
#include <climits>
#include <stdio.h>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <sys/types.h>
#include <inttypes.h>
#include <pthread.h>
#include <poll.h>

#include <android/hardware/ICamera.h>
#include <android/hardware/ICameraClient.h>

#include <android-base/macros.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <binder/ActivityManager.h>
#include <binder/AppOpsManager.h>
#include <binder/IPCThreadState.h>
#include <binder/MemoryBase.h>
#include <binder/MemoryHeapBase.h>
#include <binder/PermissionController.h>
#include <binder/IResultReceiver.h>
#include <binderthreadstate/CallerUtils.h>
#include <cutils/atomic.h>
#include <cutils/properties.h>
#include <cutils/misc.h>
#include <gui/Surface.h>
#include <hardware/hardware.h>
#include "hidl/HidlCameraService.h"
#include <hidl/HidlTransportSupport.h>
#include <hwbinder/IPCThreadState.h>
#include <memunreachable/memunreachable.h>
#include <media/AudioSystem.h>
#include <media/IMediaHTTPService.h>
#include <media/mediaplayer.h>
#include <mediautils/BatteryNotifier.h>
#include <processinfo/ProcessInfoService.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/String16.h>
#include <utils/SystemClock.h>
#include <utils/Trace.h>
#include <utils/CallStack.h>
#include <private/android_filesystem_config.h>
#include <system/camera_vendor_tags.h>
#include <system/camera_metadata.h>

#include <system/camera.h>

#include "CameraService.h"
#include "api1/Camera2Client.h"
#include "api2/CameraDeviceClient.h"
#include "utils/CameraTraces.h"
#include "utils/TagMonitor.h"
#include "utils/CameraThreadState.h"
#include "utils/CameraServiceProxyWrapper.h"

namespace {
    const char* kPermissionServiceName = "permission";
}; // namespace anonymous

namespace android {

using base::StringPrintf;
using binder::Status;
using namespace camera3;
using frameworks::cameraservice::service::V2_0::implementation::HidlCameraService;
using hardware::ICamera;
using hardware::ICameraClient;
using hardware::ICameraServiceListener;
using hardware::camera2::ICameraInjectionCallback;
using hardware::camera2::ICameraInjectionSession;
using hardware::camera2::utils::CameraIdAndSessionConfiguration;
using hardware::camera2::utils::ConcurrentCameraIdCombination;

// ----------------------------------------------------------------------------
// Logging support -- this is for debugging only
// Use "adb shell dumpsys media.camera -v 1" to change it.
volatile int32_t gLogLevel = 0;

#define LOG1(...) ALOGD_IF(gLogLevel >= 1, __VA_ARGS__);
#define LOG2(...) ALOGD_IF(gLogLevel >= 2, __VA_ARGS__);

static void setLogLevel(int level) {
    android_atomic_write(level, &gLogLevel);
}

// Convenience methods for constructing binder::Status objects for error returns

#define STATUS_ERROR(errorCode, errorString) \
    binder::Status::fromServiceSpecificError(errorCode, \
            String8::format("%s:%d: %s", __FUNCTION__, __LINE__, errorString))

#define STATUS_ERROR_FMT(errorCode, errorString, ...) \
    binder::Status::fromServiceSpecificError(errorCode, \
            String8::format("%s:%d: " errorString, __FUNCTION__, __LINE__, \
                    __VA_ARGS__))

// ----------------------------------------------------------------------------

static const String16 sDumpPermission("android.permission.DUMP");
static const String16 sManageCameraPermission("android.permission.MANAGE_CAMERA");
static const String16 sCameraPermission("android.permission.CAMERA");
static const String16 sSystemCameraPermission("android.permission.SYSTEM_CAMERA");
static const String16
        sCameraSendSystemEventsPermission("android.permission.CAMERA_SEND_SYSTEM_EVENTS");
static const String16 sCameraOpenCloseListenerPermission(
        "android.permission.CAMERA_OPEN_CLOSE_LISTENER");
static const String16
        sCameraInjectExternalCameraPermission("android.permission.CAMERA_INJECT_EXTERNAL_CAMERA");
const char *sFileName = "lastOpenSessionDumpFile";
static constexpr int32_t kSystemNativeClientScore = resource_policy::PERCEPTIBLE_APP_ADJ;
static constexpr int32_t kSystemNativeClientState =
        ActivityManager::PROCESS_STATE_PERSISTENT_UI;

const String8 CameraService::kOfflineDevice("offline-");
const String16 CameraService::kWatchAllClientsFlag("all");

// Set to keep track of logged service error events.
static std::set<String8> sServiceErrorEventSet;

CameraService::CameraService() :
        mEventLog(DEFAULT_EVENT_LOG_LENGTH),
        mNumberOfCameras(0),
        mNumberOfCamerasWithoutSystemCamera(0),
        mSoundRef(0), mInitialized(false),
        mAudioRestriction(hardware::camera2::ICameraDeviceUser::AUDIO_RESTRICTION_NONE) {
    ALOGI("CameraService started (pid=%d)", getpid());
    mServiceLockWrapper = std::make_shared<WaitableMutexWrapper>(&mServiceLock);
    mMemFd = memfd_create(sFileName, MFD_ALLOW_SEALING);
    if (mMemFd == -1) {
        ALOGE("%s: Error while creating the file: %s", __FUNCTION__, sFileName);
    }
}

// The word 'System' here does not refer to clients only on the system
// partition. They just need to have a android system uid.
static bool doesClientHaveSystemUid() {
    return (CameraThreadState::getCallingUid() < AID_APP_START);
}

void CameraService::onFirstRef()
{

    ALOGI("CameraService process starting");

    BnCameraService::onFirstRef();

    // Update battery life tracking if service is restarting
    BatteryNotifier& notifier(BatteryNotifier::getInstance());
    notifier.noteResetCamera();
    notifier.noteResetFlashlight();

    status_t res = INVALID_OPERATION;

    res = enumerateProviders();
    if (res == OK) {
        mInitialized = true;
    }

    mUidPolicy = new UidPolicy(this);
    mUidPolicy->registerSelf();
    mSensorPrivacyPolicy = new SensorPrivacyPolicy(this);
    mSensorPrivacyPolicy->registerSelf();
    mInjectionStatusListener = new InjectionStatusListener(this);
    mAppOps.setCameraAudioRestriction(mAudioRestriction);
    sp<HidlCameraService> hcs = HidlCameraService::getInstance(this);
    if (hcs->registerAsService() != android::OK) {
        ALOGE("%s: Failed to register default android.frameworks.cameraservice.service@1.0",
              __FUNCTION__);
    }

    // This needs to be last call in this function, so that it's as close to
    // ServiceManager::addService() as possible.
    CameraServiceProxyWrapper::pingCameraServiceProxy();
    ALOGI("CameraService pinged cameraservice proxy");
}

status_t CameraService::enumerateProviders() {
    status_t res;

    std::vector<std::string> deviceIds;
    std::unordered_map<std::string, std::set<std::string>> unavailPhysicalIds;
    {
        Mutex::Autolock l(mServiceLock);

        if (nullptr == mCameraProviderManager.get()) {
            mCameraProviderManager = new CameraProviderManager();
            res = mCameraProviderManager->initialize(this);
            if (res != OK) {
                ALOGE("%s: Unable to initialize camera provider manager: %s (%d)",
                        __FUNCTION__, strerror(-res), res);
                logServiceError(String8::format("Unable to initialize camera provider manager"),
                ERROR_DISCONNECTED);
                return res;
            }
        }


        // Setup vendor tags before we call get_camera_info the first time
        // because HAL might need to setup static vendor keys in get_camera_info
        // TODO: maybe put this into CameraProviderManager::initialize()?
        mCameraProviderManager->setUpVendorTags();

        if (nullptr == mFlashlight.get()) {
            mFlashlight = new CameraFlashlight(mCameraProviderManager, this);
        }

        res = mFlashlight->findFlashUnits();
        if (res != OK) {
            ALOGE("Failed to enumerate flash units: %s (%d)", strerror(-res), res);
        }

        deviceIds = mCameraProviderManager->getCameraDeviceIds(&unavailPhysicalIds);
    }


    for (auto& cameraId : deviceIds) {
        String8 id8 = String8(cameraId.c_str());
        if (getCameraState(id8) == nullptr) {
            onDeviceStatusChanged(id8, CameraDeviceStatus::PRESENT);
        }
        if (unavailPhysicalIds.count(cameraId) > 0) {
            for (const auto& physicalId : unavailPhysicalIds[cameraId]) {
                String8 physicalId8 = String8(physicalId.c_str());
                onDeviceStatusChanged(id8, physicalId8, CameraDeviceStatus::NOT_PRESENT);
            }
        }
    }

    // Derive primary rear/front cameras, and filter their charactierstics.
    // This needs to be done after all cameras are enumerated and camera ids are sorted.
    if (SessionConfigurationUtils::IS_PERF_CLASS) {
        // Assume internal cameras are advertised from the same
        // provider. If multiple providers are registered at different time,
        // and each provider contains multiple internal color cameras, the current
        // logic may filter the characteristics of more than one front/rear color
        // cameras.
        Mutex::Autolock l(mServiceLock);
        filterSPerfClassCharacteristicsLocked();
    }

    return OK;
}

void CameraService::broadcastTorchModeStatus(const String8& cameraId, TorchModeStatus status,
        SystemCameraKind systemCameraKind) {
    Mutex::Autolock lock(mStatusListenerLock);
    for (auto& i : mListenerList) {
        if (shouldSkipStatusUpdates(systemCameraKind, i->isVendorListener(), i->getListenerPid(),
                i->getListenerUid())) {
            ALOGV("Skipping torch callback for system-only camera device %s",
                    cameraId.c_str());
            continue;
        }
        i->getListener()->onTorchStatusChanged(mapToInterface(status), String16{cameraId});
    }
}

CameraService::~CameraService() {
    VendorTagDescriptor::clearGlobalVendorTagDescriptor();
    mUidPolicy->unregisterSelf();
    mSensorPrivacyPolicy->unregisterSelf();
    mInjectionStatusListener->removeListener();
}

void CameraService::onNewProviderRegistered() {
    enumerateProviders();
}

void CameraService::filterAPI1SystemCameraLocked(
        const std::vector<std::string> &normalDeviceIds) {
    mNormalDeviceIdsWithoutSystemCamera.clear();
    for (auto &deviceId : normalDeviceIds) {
        SystemCameraKind deviceKind = SystemCameraKind::PUBLIC;
        if (getSystemCameraKind(String8(deviceId.c_str()), &deviceKind) != OK) {
            ALOGE("%s: Invalid camera id %s, skipping", __FUNCTION__, deviceId.c_str());
            continue;
        }
        if (deviceKind == SystemCameraKind::SYSTEM_ONLY_CAMERA) {
            // All system camera ids will necessarily come after public camera
            // device ids as per the HAL interface contract.
            break;
        }
        mNormalDeviceIdsWithoutSystemCamera.push_back(deviceId);
    }
    ALOGV("%s: number of API1 compatible public cameras is %zu", __FUNCTION__,
              mNormalDeviceIdsWithoutSystemCamera.size());
}

status_t CameraService::getSystemCameraKind(const String8& cameraId, SystemCameraKind *kind) const {
    auto state = getCameraState(cameraId);
    if (state != nullptr) {
        *kind = state->getSystemCameraKind();
        return OK;
    }
    // Hidden physical camera ids won't have CameraState
    return mCameraProviderManager->getSystemCameraKind(cameraId.c_str(), kind);
}

void CameraService::updateCameraNumAndIds() {
    Mutex::Autolock l(mServiceLock);
    std::pair<int, int> systemAndNonSystemCameras = mCameraProviderManager->getCameraCount();
    // Excludes hidden secure cameras
    mNumberOfCameras =
            systemAndNonSystemCameras.first + systemAndNonSystemCameras.second;
    mNumberOfCamerasWithoutSystemCamera = systemAndNonSystemCameras.second;
    mNormalDeviceIds =
            mCameraProviderManager->getAPI1CompatibleCameraDeviceIds();
    filterAPI1SystemCameraLocked(mNormalDeviceIds);
}

void CameraService::filterSPerfClassCharacteristicsLocked() {
    // To claim to be S Performance primary cameras, the cameras must be
    // backward compatible. So performance class primary camera Ids must be API1
    // compatible.
    bool firstRearCameraSeen = false, firstFrontCameraSeen = false;
    for (const auto& cameraId : mNormalDeviceIdsWithoutSystemCamera) {
        int facing = -1;
        int orientation = 0;
        String8 cameraId8(cameraId.c_str());
        int portraitRotation;
        getDeviceVersion(cameraId8, /*overrideToPortrait*/false, /*out*/&portraitRotation,
                /*out*/&facing, /*out*/&orientation);
        if (facing == -1) {
            ALOGE("%s: Unable to get camera device \"%s\" facing", __FUNCTION__, cameraId.c_str());
            return;
        }

        if ((facing == hardware::CAMERA_FACING_BACK && !firstRearCameraSeen) ||
                (facing == hardware::CAMERA_FACING_FRONT && !firstFrontCameraSeen)) {
            status_t res = mCameraProviderManager->filterSmallJpegSizes(cameraId);
            if (res == OK) {
                mPerfClassPrimaryCameraIds.insert(cameraId);
            } else {
                ALOGE("%s: Failed to filter small JPEG sizes for performance class primary "
                        "camera %s: %s(%d)", __FUNCTION__, cameraId.c_str(), strerror(-res), res);
                break;
            }

            if (facing == hardware::CAMERA_FACING_BACK) {
                firstRearCameraSeen = true;
            }
            if (facing == hardware::CAMERA_FACING_FRONT) {
                firstFrontCameraSeen = true;
            }
        }

        if (firstRearCameraSeen && firstFrontCameraSeen) {
            break;
        }
    }
}

void CameraService::addStates(const String8 id) {
    std::string cameraId(id.c_str());
    CameraResourceCost cost;
    status_t res = mCameraProviderManager->getResourceCost(cameraId, &cost);
    if (res != OK) {
        ALOGE("Failed to query device resource cost: %s (%d)", strerror(-res), res);
        return;
    }
    SystemCameraKind deviceKind = SystemCameraKind::PUBLIC;
    res = mCameraProviderManager->getSystemCameraKind(cameraId, &deviceKind);
    if (res != OK) {
        ALOGE("Failed to query device kind: %s (%d)", strerror(-res), res);
        return;
    }
    std::vector<std::string> physicalCameraIds;
    mCameraProviderManager->isLogicalCamera(cameraId, &physicalCameraIds);
    std::set<String8> conflicting;
    for (size_t i = 0; i < cost.conflictingDevices.size(); i++) {
        conflicting.emplace(String8(cost.conflictingDevices[i].c_str()));
    }

    {
        Mutex::Autolock lock(mCameraStatesLock);
        mCameraStates.emplace(id, std::make_shared<CameraState>(id, cost.resourceCost,
                conflicting, deviceKind, physicalCameraIds));
    }

    if (mFlashlight->hasFlashUnit(id)) {
        Mutex::Autolock al(mTorchStatusMutex);
        mTorchStatusMap.add(id, TorchModeStatus::AVAILABLE_OFF);

        broadcastTorchModeStatus(id, TorchModeStatus::AVAILABLE_OFF, deviceKind);
    }

    updateCameraNumAndIds();
    logDeviceAdded(id, "Device added");
}

void CameraService::removeStates(const String8 id) {
    updateCameraNumAndIds();
    if (mFlashlight->hasFlashUnit(id)) {
        Mutex::Autolock al(mTorchStatusMutex);
        mTorchStatusMap.removeItem(id);
    }

    {
        Mutex::Autolock lock(mCameraStatesLock);
        mCameraStates.erase(id);
    }
}

void CameraService::onDeviceStatusChanged(const String8& id,
        CameraDeviceStatus newHalStatus) {
    ALOGI("%s: Status changed for cameraId=%s, newStatus=%d", __FUNCTION__,
            id.string(), newHalStatus);

    StatusInternal newStatus = mapToInternal(newHalStatus);

    std::shared_ptr<CameraState> state = getCameraState(id);

    if (state == nullptr) {
        if (newStatus == StatusInternal::PRESENT) {
            ALOGI("%s: Unknown camera ID %s, a new camera is added",
                    __FUNCTION__, id.string());

            // First add as absent to make sure clients are notified below
            addStates(id);

            updateStatus(newStatus, id);
        } else {
            ALOGE("%s: Bad camera ID %s", __FUNCTION__, id.string());
        }
        return;
    }

    StatusInternal oldStatus = state->getStatus();

    if (oldStatus == newStatus) {
        ALOGE("%s: State transition to the same status %#x not allowed", __FUNCTION__, newStatus);
        return;
    }

    if (newStatus == StatusInternal::NOT_PRESENT) {
        logDeviceRemoved(id, String8::format("Device status changed from %d to %d", oldStatus,
                newStatus));

        // Set the device status to NOT_PRESENT, clients will no longer be able to connect
        // to this device until the status changes
        updateStatus(StatusInternal::NOT_PRESENT, id);

        sp<BasicClient> clientToDisconnectOnline, clientToDisconnectOffline;
        {
            // Don't do this in updateStatus to avoid deadlock over mServiceLock
            Mutex::Autolock lock(mServiceLock);

            // Remove cached shim parameters
            state->setShimParams(CameraParameters());

            // Remove online as well as offline client from the list of active clients,
            // if they are present
            clientToDisconnectOnline = removeClientLocked(id);
            clientToDisconnectOffline = removeClientLocked(kOfflineDevice + id);
        }

        disconnectClient(id, clientToDisconnectOnline);
        disconnectClient(kOfflineDevice + id, clientToDisconnectOffline);

        removeStates(id);
    } else {
        if (oldStatus == StatusInternal::NOT_PRESENT) {
            logDeviceAdded(id, String8::format("Device status changed from %d to %d", oldStatus,
                    newStatus));
        }
        updateStatus(newStatus, id);
    }
}

void CameraService::onDeviceStatusChanged(const String8& id,
        const String8& physicalId,
        CameraDeviceStatus newHalStatus) {
    ALOGI("%s: Status changed for cameraId=%s, physicalCameraId=%s, newStatus=%d",
            __FUNCTION__, id.string(), physicalId.string(), newHalStatus);

    StatusInternal newStatus = mapToInternal(newHalStatus);

    std::shared_ptr<CameraState> state = getCameraState(id);

    if (state == nullptr) {
        ALOGE("%s: Physical camera id %s status change on a non-present ID %s",
                __FUNCTION__, physicalId.string(), id.string());
        return;
    }

    StatusInternal logicalCameraStatus = state->getStatus();
    if (logicalCameraStatus != StatusInternal::PRESENT &&
            logicalCameraStatus != StatusInternal::NOT_AVAILABLE) {
        ALOGE("%s: Physical camera id %s status %d change for an invalid logical camera state %d",
                __FUNCTION__, physicalId.string(), newHalStatus, logicalCameraStatus);
        return;
    }

    bool updated = false;
    if (newStatus == StatusInternal::PRESENT) {
        updated = state->removeUnavailablePhysicalId(physicalId);
    } else {
        updated = state->addUnavailablePhysicalId(physicalId);
    }

    if (updated) {
        String8 idCombo = id + " : " + physicalId;
        if (newStatus == StatusInternal::PRESENT) {
            logDeviceAdded(idCombo,
                    String8::format("Device status changed to %d", newStatus));
        } else {
            logDeviceRemoved(idCombo,
                    String8::format("Device status changed to %d", newStatus));
        }
        // Avoid calling getSystemCameraKind() with mStatusListenerLock held (b/141756275)
        SystemCameraKind deviceKind = SystemCameraKind::PUBLIC;
        if (getSystemCameraKind(id, &deviceKind) != OK) {
            ALOGE("%s: Invalid camera id %s, skipping", __FUNCTION__, id.string());
            return;
        }
        String16 id16(id), physicalId16(physicalId);
        Mutex::Autolock lock(mStatusListenerLock);
        for (auto& listener : mListenerList) {
            if (shouldSkipStatusUpdates(deviceKind, listener->isVendorListener(),
                    listener->getListenerPid(), listener->getListenerUid())) {
                ALOGV("Skipping discovery callback for system-only camera device %s",
                        id.c_str());
                continue;
            }
            listener->getListener()->onPhysicalCameraStatusChanged(mapToInterface(newStatus),
                    id16, physicalId16);
        }
    }
}

void CameraService::disconnectClient(const String8& id, sp<BasicClient> clientToDisconnect) {
    if (clientToDisconnect.get() != nullptr) {
        ALOGI("%s: Client for camera ID %s evicted due to device status change from HAL",
                __FUNCTION__, id.string());
        // Notify the client of disconnection
        clientToDisconnect->notifyError(
                hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_DISCONNECTED,
                CaptureResultExtras{});
        clientToDisconnect->disconnect();
    }
}

void CameraService::onTorchStatusChanged(const String8& cameraId,
        TorchModeStatus newStatus) {
    SystemCameraKind systemCameraKind = SystemCameraKind::PUBLIC;
    status_t res = getSystemCameraKind(cameraId, &systemCameraKind);
    if (res != OK) {
        ALOGE("%s: Could not get system camera kind for camera id %s", __FUNCTION__,
                cameraId.string());
        return;
    }
    Mutex::Autolock al(mTorchStatusMutex);
    onTorchStatusChangedLocked(cameraId, newStatus, systemCameraKind);
}


void CameraService::onTorchStatusChanged(const String8& cameraId,
        TorchModeStatus newStatus, SystemCameraKind systemCameraKind) {
    Mutex::Autolock al(mTorchStatusMutex);
    onTorchStatusChangedLocked(cameraId, newStatus, systemCameraKind);
}

void CameraService::broadcastTorchStrengthLevel(const String8& cameraId,
        int32_t newStrengthLevel) {
    Mutex::Autolock lock(mStatusListenerLock);
    for (auto& i : mListenerList) {
        i->getListener()->onTorchStrengthLevelChanged(String16{cameraId},
                newStrengthLevel);
    }
}

void CameraService::onTorchStatusChangedLocked(const String8& cameraId,
        TorchModeStatus newStatus, SystemCameraKind systemCameraKind) {
    ALOGI("%s: Torch status changed for cameraId=%s, newStatus=%d",
            __FUNCTION__, cameraId.string(), newStatus);

    TorchModeStatus status;
    status_t res = getTorchStatusLocked(cameraId, &status);
    if (res) {
        ALOGE("%s: cannot get torch status of camera %s: %s (%d)",
                __FUNCTION__, cameraId.string(), strerror(-res), res);
        return;
    }
    if (status == newStatus) {
        return;
    }

    res = setTorchStatusLocked(cameraId, newStatus);
    if (res) {
        ALOGE("%s: Failed to set the torch status to %d: %s (%d)", __FUNCTION__,
                (uint32_t)newStatus, strerror(-res), res);
        return;
    }

    {
        // Update battery life logging for flashlight
        Mutex::Autolock al(mTorchUidMapMutex);
        auto iter = mTorchUidMap.find(cameraId);
        if (iter != mTorchUidMap.end()) {
            int oldUid = iter->second.second;
            int newUid = iter->second.first;
            BatteryNotifier& notifier(BatteryNotifier::getInstance());
            if (oldUid != newUid) {
                // If the UID has changed, log the status and update current UID in mTorchUidMap
                if (status == TorchModeStatus::AVAILABLE_ON) {
                    notifier.noteFlashlightOff(cameraId, oldUid);
                }
                if (newStatus == TorchModeStatus::AVAILABLE_ON) {
                    notifier.noteFlashlightOn(cameraId, newUid);
                }
                iter->second.second = newUid;
            } else {
                // If the UID has not changed, log the status
                if (newStatus == TorchModeStatus::AVAILABLE_ON) {
                    notifier.noteFlashlightOn(cameraId, oldUid);
                } else {
                    notifier.noteFlashlightOff(cameraId, oldUid);
                }
            }
        }
    }
    broadcastTorchModeStatus(cameraId, newStatus, systemCameraKind);
}

static bool hasPermissionsForSystemCamera(int callingPid, int callingUid,
        bool logPermissionFailure = false) {
    return checkPermission(sSystemCameraPermission, callingPid, callingUid,
            logPermissionFailure) &&
            checkPermission(sCameraPermission, callingPid, callingUid);
}

Status CameraService::getNumberOfCameras(int32_t type, int32_t* numCameras) {
    ATRACE_CALL();
    Mutex::Autolock l(mServiceLock);
    bool hasSystemCameraPermissions =
            hasPermissionsForSystemCamera(CameraThreadState::getCallingPid(),
                    CameraThreadState::getCallingUid());
    switch (type) {
        case CAMERA_TYPE_BACKWARD_COMPATIBLE:
            if (hasSystemCameraPermissions) {
                *numCameras = static_cast<int>(mNormalDeviceIds.size());
            } else {
                *numCameras = static_cast<int>(mNormalDeviceIdsWithoutSystemCamera.size());
            }
            break;
        case CAMERA_TYPE_ALL:
            if (hasSystemCameraPermissions) {
                *numCameras = mNumberOfCameras;
            } else {
                *numCameras = mNumberOfCamerasWithoutSystemCamera;
            }
            break;
        default:
            ALOGW("%s: Unknown camera type %d",
                    __FUNCTION__, type);
            return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT,
                    "Unknown camera type %d", type);
    }
    return Status::ok();
}

Status CameraService::getCameraInfo(int cameraId, bool overrideToPortrait,
        CameraInfo* cameraInfo) {
    ATRACE_CALL();
    Mutex::Autolock l(mServiceLock);
    std::string cameraIdStr = cameraIdIntToStrLocked(cameraId);
    if (shouldRejectSystemCameraConnection(String8(cameraIdStr.c_str()))) {
        return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION, "Unable to retrieve camera"
                "characteristics for system only device %s: ", cameraIdStr.c_str());
    }

    if (!mInitialized) {
        logServiceError(String8::format("Camera subsystem is not available"),ERROR_DISCONNECTED);
        return STATUS_ERROR(ERROR_DISCONNECTED,
                "Camera subsystem is not available");
    }
    bool hasSystemCameraPermissions =
            hasPermissionsForSystemCamera(CameraThreadState::getCallingPid(),
                    CameraThreadState::getCallingUid());
    int cameraIdBound = mNumberOfCamerasWithoutSystemCamera;
    if (hasSystemCameraPermissions) {
        cameraIdBound = mNumberOfCameras;
    }
    if (cameraId < 0 || cameraId >= cameraIdBound) {
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT,
                "CameraId is not valid");
    }

    Status ret = Status::ok();
    int portraitRotation;
    status_t err = mCameraProviderManager->getCameraInfo(
            cameraIdStr.c_str(), overrideToPortrait, &portraitRotation, cameraInfo);
    if (err != OK) {
        ret = STATUS_ERROR_FMT(ERROR_INVALID_OPERATION,
                "Error retrieving camera info from device %d: %s (%d)", cameraId,
                strerror(-err), err);
        logServiceError(String8::format("Error retrieving camera info from device %d",cameraId),
            ERROR_INVALID_OPERATION);
    }

    return ret;
}

std::string CameraService::cameraIdIntToStrLocked(int cameraIdInt) {
    const std::vector<std::string> *deviceIds = &mNormalDeviceIdsWithoutSystemCamera;
    auto callingPid = CameraThreadState::getCallingPid();
    auto callingUid = CameraThreadState::getCallingUid();
    if (checkPermission(sSystemCameraPermission, callingPid, callingUid,
            /*logPermissionFailure*/false) || getpid() == callingPid) {
        deviceIds = &mNormalDeviceIds;
    }
    if (cameraIdInt < 0 || cameraIdInt >= static_cast<int>(deviceIds->size())) {
        ALOGE("%s: input id %d invalid: valid range  (0, %zu)",
                __FUNCTION__, cameraIdInt, deviceIds->size());
        return std::string{};
    }

    return (*deviceIds)[cameraIdInt];
}

String8 CameraService::cameraIdIntToStr(int cameraIdInt) {
    Mutex::Autolock lock(mServiceLock);
    return String8(cameraIdIntToStrLocked(cameraIdInt).c_str());
}

Status CameraService::getCameraCharacteristics(const String16& cameraId,
        int targetSdkVersion, bool overrideToPortrait, CameraMetadata* cameraInfo) {
    ATRACE_CALL();
    if (!cameraInfo) {
        ALOGE("%s: cameraInfo is NULL", __FUNCTION__);
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, "cameraInfo is NULL");
    }

    if (!mInitialized) {
        ALOGE("%s: Camera HAL couldn't be initialized", __FUNCTION__);
        logServiceError(String8::format("Camera subsystem is not available"),ERROR_DISCONNECTED);
        return STATUS_ERROR(ERROR_DISCONNECTED,
                "Camera subsystem is not available");;
    }

    if (shouldRejectSystemCameraConnection(String8(cameraId))) {
        return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION, "Unable to retrieve camera"
                "characteristics for system only device %s: ", String8(cameraId).string());
    }

    Status ret{};


    std::string cameraIdStr = String8(cameraId).string();
    bool overrideForPerfClass =
            SessionConfigurationUtils::targetPerfClassPrimaryCamera(mPerfClassPrimaryCameraIds,
                    cameraIdStr, targetSdkVersion);
    status_t res = mCameraProviderManager->getCameraCharacteristics(
            cameraIdStr, overrideForPerfClass, cameraInfo, overrideToPortrait);
    if (res != OK) {
        if (res == NAME_NOT_FOUND) {
            return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT, "Unable to retrieve camera "
                    "characteristics for unknown device %s: %s (%d)", String8(cameraId).string(),
                    strerror(-res), res);
        } else {
            logServiceError(String8::format("Unable to retrieve camera characteristics for "
            "device %s.", String8(cameraId).string()),ERROR_INVALID_OPERATION);
            return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION, "Unable to retrieve camera "
                    "characteristics for device %s: %s (%d)", String8(cameraId).string(),
                    strerror(-res), res);
        }
    }
    SystemCameraKind deviceKind = SystemCameraKind::PUBLIC;
    if (getSystemCameraKind(String8(cameraId), &deviceKind) != OK) {
        ALOGE("%s: Invalid camera id %s, skipping", __FUNCTION__, String8(cameraId).string());
        return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION, "Unable to retrieve camera kind "
                "for device %s", String8(cameraId).string());
    }
    int callingPid = CameraThreadState::getCallingPid();
    int callingUid = CameraThreadState::getCallingUid();
    std::vector<int32_t> tagsRemoved;
    // If it's not calling from cameraserver, check the permission only if
    // android.permission.CAMERA is required. If android.permission.SYSTEM_CAMERA was needed,
    // it would've already been checked in shouldRejectSystemCameraConnection.
    if ((callingPid != getpid()) &&
            (deviceKind != SystemCameraKind::SYSTEM_ONLY_CAMERA) &&
            !checkPermission(sCameraPermission, callingPid, callingUid)) {
        res = cameraInfo->removePermissionEntries(
                mCameraProviderManager->getProviderTagIdLocked(String8(cameraId).string()),
                &tagsRemoved);
        if (res != OK) {
            cameraInfo->clear();
            return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION, "Failed to remove camera"
                    " characteristics needing camera permission for device %s: %s (%d)",
                    String8(cameraId).string(), strerror(-res), res);
        }
    }

    if (!tagsRemoved.empty()) {
        res = cameraInfo->update(ANDROID_REQUEST_CHARACTERISTIC_KEYS_NEEDING_PERMISSION,
                tagsRemoved.data(), tagsRemoved.size());
        if (res != OK) {
            cameraInfo->clear();
            return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION, "Failed to insert camera "
                    "keys needing permission for device %s: %s (%d)", String8(cameraId).string(),
                    strerror(-res), res);
        }
    }

    return ret;
}

Status CameraService::getTorchStrengthLevel(const String16& cameraId,
        int32_t* torchStrength) {
    ATRACE_CALL();
    Mutex::Autolock l(mServiceLock);
    if (!mInitialized) {
        ALOGE("%s: Camera HAL couldn't be initialized.", __FUNCTION__);
        return STATUS_ERROR(ERROR_DISCONNECTED, "Camera HAL couldn't be initialized.");
    }

    if(torchStrength == NULL) {
        ALOGE("%s: strength level must not be null.", __FUNCTION__);
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, "Strength level should not be null.");
    }

    status_t res = mCameraProviderManager->getTorchStrengthLevel(String8(cameraId).string(),
        torchStrength);
    if (res != OK) {
        return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION, "Unable to retrieve torch "
            "strength level for device %s: %s (%d)", String8(cameraId).string(),
            strerror(-res), res);
    }
    ALOGI("%s: Torch strength level is: %d", __FUNCTION__, *torchStrength);
    return Status::ok();
}

String8 CameraService::getFormattedCurrentTime() {
    time_t now = time(nullptr);
    char formattedTime[64];
    strftime(formattedTime, sizeof(formattedTime), "%m-%d %H:%M:%S", localtime(&now));
    return String8(formattedTime);
}

Status CameraService::getCameraVendorTagDescriptor(
        /*out*/
        hardware::camera2::params::VendorTagDescriptor* desc) {
    ATRACE_CALL();
    if (!mInitialized) {
        ALOGE("%s: Camera HAL couldn't be initialized", __FUNCTION__);
        return STATUS_ERROR(ERROR_DISCONNECTED, "Camera subsystem not available");
    }
    sp<VendorTagDescriptor> globalDescriptor = VendorTagDescriptor::getGlobalVendorTagDescriptor();
    if (globalDescriptor != nullptr) {
        *desc = *(globalDescriptor.get());
    }
    return Status::ok();
}

Status CameraService::getCameraVendorTagCache(
        /*out*/ hardware::camera2::params::VendorTagDescriptorCache* cache) {
    ATRACE_CALL();
    if (!mInitialized) {
        ALOGE("%s: Camera HAL couldn't be initialized", __FUNCTION__);
        return STATUS_ERROR(ERROR_DISCONNECTED,
                "Camera subsystem not available");
    }
    sp<VendorTagDescriptorCache> globalCache =
            VendorTagDescriptorCache::getGlobalVendorTagCache();
    if (globalCache != nullptr) {
        *cache = *(globalCache.get());
    }
    return Status::ok();
}

void CameraService::clearCachedVariables() {
    BasicClient::BasicClient::sCameraService = nullptr;
}

std::pair<int, IPCTransport> CameraService::getDeviceVersion(const String8& cameraId,
        bool overrideToPortrait, int* portraitRotation, int* facing, int* orientation) {
    ATRACE_CALL();

    int deviceVersion = 0;

    status_t res;
    hardware::hidl_version maxVersion{0,0};
    IPCTransport transport = IPCTransport::INVALID;
    res = mCameraProviderManager->getHighestSupportedVersion(cameraId.string(),
            &maxVersion, &transport);
    if (res != OK || transport == IPCTransport::INVALID) {
        ALOGE("%s: Unable to get highest supported version for camera id %s", __FUNCTION__,
                cameraId.string());
        return std::make_pair(-1, IPCTransport::INVALID) ;
    }
    deviceVersion = HARDWARE_DEVICE_API_VERSION(maxVersion.get_major(), maxVersion.get_minor());

    hardware::CameraInfo info;
    if (facing) {
        res = mCameraProviderManager->getCameraInfo(cameraId.string(), overrideToPortrait,
                portraitRotation, &info);
        if (res != OK) {
            return std::make_pair(-1, IPCTransport::INVALID);
        }
        *facing = info.facing;
        if (orientation) {
            *orientation = info.orientation;
        }
    }

    return std::make_pair(deviceVersion, transport);
}

Status CameraService::filterGetInfoErrorCode(status_t err) {
    switch(err) {
        case NO_ERROR:
            return Status::ok();
        case BAD_VALUE:
            return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT,
                    "CameraId is not valid for HAL module");
        case NO_INIT:
            return STATUS_ERROR(ERROR_DISCONNECTED,
                    "Camera device not available");
        default:
            return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION,
                    "Camera HAL encountered error %d: %s",
                    err, strerror(-err));
    }
}

Status CameraService::makeClient(const sp<CameraService>& cameraService,
        const sp<IInterface>& cameraCb, const String16& packageName, bool systemNativeClient,
        const std::optional<String16>& featureId,  const String8& cameraId,
        int api1CameraId, int facing, int sensorOrientation, int clientPid, uid_t clientUid,
        int servicePid, std::pair<int, IPCTransport> deviceVersionAndTransport,
        apiLevel effectiveApiLevel, bool overrideForPerfClass, bool overrideToPortrait,
        bool forceSlowJpegMode, /*out*/sp<BasicClient>* client) {
    // For HIDL devices
    if (deviceVersionAndTransport.second == IPCTransport::HIDL) {
        // Create CameraClient based on device version reported by the HAL.
        int deviceVersion = deviceVersionAndTransport.first;
        switch(deviceVersion) {
            case CAMERA_DEVICE_API_VERSION_1_0:
                ALOGE("Camera using old HAL version: %d", deviceVersion);
                return STATUS_ERROR_FMT(ERROR_DEPRECATED_HAL,
                        "Camera device \"%s\" HAL version %d no longer supported",
                        cameraId.string(), deviceVersion);
                break;
            case CAMERA_DEVICE_API_VERSION_3_0:
            case CAMERA_DEVICE_API_VERSION_3_1:
            case CAMERA_DEVICE_API_VERSION_3_2:
            case CAMERA_DEVICE_API_VERSION_3_3:
            case CAMERA_DEVICE_API_VERSION_3_4:
            case CAMERA_DEVICE_API_VERSION_3_5:
            case CAMERA_DEVICE_API_VERSION_3_6:
            case CAMERA_DEVICE_API_VERSION_3_7:
                break;
            default:
                // Should not be reachable
                ALOGE("Unknown camera device HAL version: %d", deviceVersion);
                return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION,
                        "Camera device \"%s\" has unknown HAL version %d",
                        cameraId.string(), deviceVersion);
        }
    }
    if (effectiveApiLevel == API_1) { // Camera1 API route
        sp<ICameraClient> tmp = static_cast<ICameraClient*>(cameraCb.get());
        *client = new Camera2Client(cameraService, tmp, packageName, featureId,
                cameraId, api1CameraId, facing, sensorOrientation, clientPid, clientUid,
                servicePid, overrideForPerfClass, overrideToPortrait, forceSlowJpegMode);
        ALOGI("%s: Camera1 API (legacy), override to portrait %d, forceSlowJpegMode %d",
                __FUNCTION__, overrideToPortrait, forceSlowJpegMode);
    } else { // Camera2 API route
        sp<hardware::camera2::ICameraDeviceCallbacks> tmp =
                static_cast<hardware::camera2::ICameraDeviceCallbacks*>(cameraCb.get());
        *client = new CameraDeviceClient(cameraService, tmp, packageName,
                systemNativeClient, featureId, cameraId, facing, sensorOrientation,
                clientPid, clientUid, servicePid, overrideForPerfClass, overrideToPortrait);
        ALOGI("%s: Camera2 API, override to portrait %d", __FUNCTION__, overrideToPortrait);
    }
    return Status::ok();
}

String8 CameraService::toString(std::set<userid_t> intSet) {
    String8 s("");
    bool first = true;
    for (userid_t i : intSet) {
        if (first) {
            s.appendFormat("%d", i);
            first = false;
        } else {
            s.appendFormat(", %d", i);
        }
    }
    return s;
}

int32_t CameraService::mapToInterface(TorchModeStatus status) {
    int32_t serviceStatus = ICameraServiceListener::TORCH_STATUS_NOT_AVAILABLE;
    switch (status) {
        case TorchModeStatus::NOT_AVAILABLE:
            serviceStatus = ICameraServiceListener::TORCH_STATUS_NOT_AVAILABLE;
            break;
        case TorchModeStatus::AVAILABLE_OFF:
            serviceStatus = ICameraServiceListener::TORCH_STATUS_AVAILABLE_OFF;
            break;
        case TorchModeStatus::AVAILABLE_ON:
            serviceStatus = ICameraServiceListener::TORCH_STATUS_AVAILABLE_ON;
            break;
        default:
            ALOGW("Unknown new flash status: %d", status);
    }
    return serviceStatus;
}

CameraService::StatusInternal CameraService::mapToInternal(CameraDeviceStatus status) {
    StatusInternal serviceStatus = StatusInternal::NOT_PRESENT;
    switch (status) {
        case CameraDeviceStatus::NOT_PRESENT:
            serviceStatus = StatusInternal::NOT_PRESENT;
            break;
        case CameraDeviceStatus::PRESENT:
            serviceStatus = StatusInternal::PRESENT;
            break;
        case CameraDeviceStatus::ENUMERATING:
            serviceStatus = StatusInternal::ENUMERATING;
            break;
        default:
            ALOGW("Unknown new HAL device status: %d", status);
    }
    return serviceStatus;
}

int32_t CameraService::mapToInterface(StatusInternal status) {
    int32_t serviceStatus = ICameraServiceListener::STATUS_NOT_PRESENT;
    switch (status) {
        case StatusInternal::NOT_PRESENT:
            serviceStatus = ICameraServiceListener::STATUS_NOT_PRESENT;
            break;
        case StatusInternal::PRESENT:
            serviceStatus = ICameraServiceListener::STATUS_PRESENT;
            break;
        case StatusInternal::ENUMERATING:
            serviceStatus = ICameraServiceListener::STATUS_ENUMERATING;
            break;
        case StatusInternal::NOT_AVAILABLE:
            serviceStatus = ICameraServiceListener::STATUS_NOT_AVAILABLE;
            break;
        case StatusInternal::UNKNOWN:
            serviceStatus = ICameraServiceListener::STATUS_UNKNOWN;
            break;
        default:
            ALOGW("Unknown new internal device status: %d", status);
    }
    return serviceStatus;
}

Status CameraService::initializeShimMetadata(int cameraId) {
    int uid = CameraThreadState::getCallingUid();

    String16 internalPackageName("cameraserver");
    String8 id = String8::format("%d", cameraId);
    Status ret = Status::ok();
    sp<Client> tmp = nullptr;
    if (!(ret = connectHelper<ICameraClient,Client>(
            sp<ICameraClient>{nullptr}, id, cameraId,
            internalPackageName, /*systemNativeClient*/ false, {}, uid, USE_CALLING_PID,
            API_1, /*shimUpdateOnly*/ true, /*oomScoreOffset*/ 0,
            /*targetSdkVersion*/ __ANDROID_API_FUTURE__, /*overrideToPortrait*/ true,
            /*forceSlowJpegMode*/false, /*out*/ tmp)
            ).isOk()) {
        ALOGE("%s: Error initializing shim metadata: %s", __FUNCTION__, ret.toString8().string());
    }
    return ret;
}

Status CameraService::getLegacyParametersLazy(int cameraId,
        /*out*/
        CameraParameters* parameters) {

    ALOGV("%s: for cameraId: %d", __FUNCTION__, cameraId);

    Status ret = Status::ok();

    if (parameters == NULL) {
        ALOGE("%s: parameters must not be null", __FUNCTION__);
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, "Parameters must not be null");
    }

    String8 id = String8::format("%d", cameraId);

    // Check if we already have parameters
    {
        // Scope for service lock
        Mutex::Autolock lock(mServiceLock);
        auto cameraState = getCameraState(id);
        if (cameraState == nullptr) {
            ALOGE("%s: Invalid camera ID: %s", __FUNCTION__, id.string());
            return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT,
                    "Invalid camera ID: %s", id.string());
        }
        CameraParameters p = cameraState->getShimParams();
        if (!p.isEmpty()) {
            *parameters = p;
            return ret;
        }
    }

    int64_t token = CameraThreadState::clearCallingIdentity();
    ret = initializeShimMetadata(cameraId);
    CameraThreadState::restoreCallingIdentity(token);
    if (!ret.isOk()) {
        // Error already logged by callee
        return ret;
    }

    // Check for parameters again
    {
        // Scope for service lock
        Mutex::Autolock lock(mServiceLock);
        auto cameraState = getCameraState(id);
        if (cameraState == nullptr) {
            ALOGE("%s: Invalid camera ID: %s", __FUNCTION__, id.string());
            return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT,
                    "Invalid camera ID: %s", id.string());
        }
        CameraParameters p = cameraState->getShimParams();
        if (!p.isEmpty()) {
            *parameters = p;
            return ret;
        }
    }

    ALOGE("%s: Parameters were not initialized, or were empty.  Device may not be present.",
            __FUNCTION__);
    return STATUS_ERROR(ERROR_INVALID_OPERATION, "Unable to initialize legacy parameters");
}

// Can camera service trust the caller based on the calling UID?
static bool isTrustedCallingUid(uid_t uid) {
    switch (uid) {
        case AID_MEDIA:        // mediaserver
        case AID_CAMERASERVER: // cameraserver
        case AID_RADIO:        // telephony
            return true;
        default:
            return false;
    }
}

static status_t getUidForPackage(String16 packageName, int userId, /*inout*/uid_t& uid, int err) {
    PermissionController pc;
    uid = pc.getPackageUid(packageName, 0);
    if (uid <= 0) {
        ALOGE("Unknown package: '%s'", String8(packageName).string());
        dprintf(err, "Unknown package: '%s'\n", String8(packageName).string());
        return BAD_VALUE;
    }

    if (userId < 0) {
        ALOGE("Invalid user: %d", userId);
        dprintf(err, "Invalid user: %d\n", userId);
        return BAD_VALUE;
    }

    uid = multiuser_get_uid(userId, uid);
    return NO_ERROR;
}

Status CameraService::validateConnectLocked(const String8& cameraId,
        const String8& clientName8, /*inout*/int& clientUid, /*inout*/int& clientPid,
        /*out*/int& originalClientPid) const {

#ifdef __BRILLO__
    UNUSED(clientName8);
    UNUSED(clientUid);
    UNUSED(clientPid);
    UNUSED(originalClientPid);
#else
    Status allowed = validateClientPermissionsLocked(cameraId, clientName8, clientUid, clientPid,
            originalClientPid);
    if (!allowed.isOk()) {
        return allowed;
    }
#endif  // __BRILLO__

    int callingPid = CameraThreadState::getCallingPid();

    if (!mInitialized) {
        ALOGE("CameraService::connect X (PID %d) rejected (camera HAL module not loaded)",
                callingPid);
        return STATUS_ERROR_FMT(ERROR_DISCONNECTED,
                "No camera HAL module available to open camera device \"%s\"", cameraId.string());
    }

    if (getCameraState(cameraId) == nullptr) {
        ALOGE("CameraService::connect X (PID %d) rejected (invalid camera ID %s)", callingPid,
                cameraId.string());
        return STATUS_ERROR_FMT(ERROR_DISCONNECTED,
                "No camera device with ID \"%s\" available", cameraId.string());
    }

    status_t err = checkIfDeviceIsUsable(cameraId);
    if (err != NO_ERROR) {
        switch(err) {
            case -ENODEV:
            case -EBUSY:
                return STATUS_ERROR_FMT(ERROR_DISCONNECTED,
                        "No camera device with ID \"%s\" currently available", cameraId.string());
            default:
                return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION,
                        "Unknown error connecting to ID \"%s\"", cameraId.string());
        }
    }
    return Status::ok();
}

Status CameraService::validateClientPermissionsLocked(const String8& cameraId,
        const String8& clientName8, int& clientUid, int& clientPid,
        /*out*/int& originalClientPid) const {
    int callingPid = CameraThreadState::getCallingPid();
    int callingUid = CameraThreadState::getCallingUid();

    // Check if we can trust clientUid
    if (clientUid == USE_CALLING_UID) {
        clientUid = callingUid;
    } else if (!isTrustedCallingUid(callingUid)) {
        ALOGE("CameraService::connect X (calling PID %d, calling UID %d) rejected "
                "(don't trust clientUid %d)", callingPid, callingUid, clientUid);
        return STATUS_ERROR_FMT(ERROR_PERMISSION_DENIED,
                "Untrusted caller (calling PID %d, UID %d) trying to "
                "forward camera access to camera %s for client %s (PID %d, UID %d)",
                callingPid, callingUid, cameraId.string(),
                clientName8.string(), clientUid, clientPid);
    }

    // Check if we can trust clientPid
    if (clientPid == USE_CALLING_PID) {
        clientPid = callingPid;
    } else if (!isTrustedCallingUid(callingUid)) {
        ALOGE("CameraService::connect X (calling PID %d, calling UID %d) rejected "
                "(don't trust clientPid %d)", callingPid, callingUid, clientPid);
        return STATUS_ERROR_FMT(ERROR_PERMISSION_DENIED,
                "Untrusted caller (calling PID %d, UID %d) trying to "
                "forward camera access to camera %s for client %s (PID %d, UID %d)",
                callingPid, callingUid, cameraId.string(),
                clientName8.string(), clientUid, clientPid);
    }

    if (shouldRejectSystemCameraConnection(cameraId)) {
        ALOGW("Attempting to connect to system-only camera id %s, connection rejected",
                cameraId.c_str());
        return STATUS_ERROR_FMT(ERROR_DISCONNECTED, "No camera device with ID \"%s\" is"
                                "available", cameraId.string());
    }
    SystemCameraKind deviceKind = SystemCameraKind::PUBLIC;
    if (getSystemCameraKind(cameraId, &deviceKind) != OK) {
        ALOGE("%s: Invalid camera id %s, skipping", __FUNCTION__, cameraId.string());
        return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT, "No camera device with ID \"%s\""
                "found while trying to query device kind", cameraId.string());

    }

    // If it's not calling from cameraserver, check the permission if the
    // device isn't a system only camera (shouldRejectSystemCameraConnection already checks for
    // android.permission.SYSTEM_CAMERA for system only camera devices).
    if (callingPid != getpid() &&
                (deviceKind != SystemCameraKind::SYSTEM_ONLY_CAMERA) &&
                !checkPermission(sCameraPermission, clientPid, clientUid)) {
        ALOGE("Permission Denial: can't use the camera pid=%d, uid=%d", clientPid, clientUid);
        return STATUS_ERROR_FMT(ERROR_PERMISSION_DENIED,
                "Caller \"%s\" (PID %d, UID %d) cannot open camera \"%s\" without camera permission",
                clientName8.string(), clientUid, clientPid, cameraId.string());
    }

    // Make sure the UID is in an active state to use the camera
    if (!mUidPolicy->isUidActive(callingUid, String16(clientName8))) {
        int32_t procState = mUidPolicy->getProcState(callingUid);
        ALOGE("Access Denial: can't use the camera from an idle UID pid=%d, uid=%d",
            clientPid, clientUid);
        return STATUS_ERROR_FMT(ERROR_DISABLED,
                "Caller \"%s\" (PID %d, UID %d) cannot open camera \"%s\" from background ("
                "calling UID %d proc state %" PRId32 ")",
                clientName8.string(), clientUid, clientPid, cameraId.string(),
                callingUid, procState);
    }

    // If sensor privacy is enabled then prevent access to the camera
    if (mSensorPrivacyPolicy->isSensorPrivacyEnabled()) {
        ALOGE("Access Denial: cannot use the camera when sensor privacy is enabled");
        return STATUS_ERROR_FMT(ERROR_DISABLED,
                "Caller \"%s\" (PID %d, UID %d) cannot open camera \"%s\" when sensor privacy "
                "is enabled", clientName8.string(), clientUid, clientPid, cameraId.string());
    }

    // Only use passed in clientPid to check permission. Use calling PID as the client PID that's
    // connected to camera service directly.
    originalClientPid = clientPid;
    clientPid = callingPid;

    userid_t clientUserId = multiuser_get_user_id(clientUid);

    // For non-system clients : Only allow clients who are being used by the current foreground
    // device user, unless calling from our own process.
    if (!doesClientHaveSystemUid() && callingPid != getpid() &&
            (mAllowedUsers.find(clientUserId) == mAllowedUsers.end())) {
        ALOGE("CameraService::connect X (PID %d) rejected (cannot connect from "
                "device user %d, currently allowed device users: %s)", callingPid, clientUserId,
                toString(mAllowedUsers).string());
        return STATUS_ERROR_FMT(ERROR_PERMISSION_DENIED,
                "Callers from device user %d are not currently allowed to connect to camera \"%s\"",
                clientUserId, cameraId.string());
    }

    return Status::ok();
}

status_t CameraService::checkIfDeviceIsUsable(const String8& cameraId) const {
    auto cameraState = getCameraState(cameraId);
    int callingPid = CameraThreadState::getCallingPid();
    if (cameraState == nullptr) {
        ALOGE("CameraService::connect X (PID %d) rejected (invalid camera ID %s)", callingPid,
                cameraId.string());
        return -ENODEV;
    }

    StatusInternal currentStatus = cameraState->getStatus();
    if (currentStatus == StatusInternal::NOT_PRESENT) {
        ALOGE("CameraService::connect X (PID %d) rejected (camera %s is not connected)",
                callingPid, cameraId.string());
        return -ENODEV;
    } else if (currentStatus == StatusInternal::ENUMERATING) {
        ALOGE("CameraService::connect X (PID %d) rejected, (camera %s is initializing)",
                callingPid, cameraId.string());
        return -EBUSY;
    }

    return NO_ERROR;
}

void CameraService::finishConnectLocked(const sp<BasicClient>& client,
        const CameraService::DescriptorPtr& desc, int oomScoreOffset, bool systemNativeClient) {

    // Make a descriptor for the incoming client
    auto clientDescriptor =
            CameraService::CameraClientManager::makeClientDescriptor(client, desc,
                    oomScoreOffset, systemNativeClient);
    auto evicted = mActiveClientManager.addAndEvict(clientDescriptor);

    logConnected(desc->getKey(), static_cast<int>(desc->getOwnerId()),
            String8(client->getPackageName()));

    if (evicted.size() > 0) {
        // This should never happen - clients should already have been removed in disconnect
        for (auto& i : evicted) {
            ALOGE("%s: Invalid state: Client for camera %s was not removed in disconnect",
                    __FUNCTION__, i->getKey().string());
        }

        LOG_ALWAYS_FATAL("%s: Invalid state for CameraService, clients not evicted properly",
                __FUNCTION__);
    }

    // And register a death notification for the client callback. Do
    // this last to avoid Binder policy where a nested Binder
    // transaction might be pre-empted to service the client death
    // notification if the client process dies before linkToDeath is
    // invoked.
    sp<IBinder> remoteCallback = client->getRemote();
    if (remoteCallback != nullptr) {
        remoteCallback->linkToDeath(this);
    }
}

status_t CameraService::handleEvictionsLocked(const String8& cameraId, int clientPid,
        apiLevel effectiveApiLevel, const sp<IBinder>& remoteCallback, const String8& packageName,
        int oomScoreOffset, bool systemNativeClient,
        /*out*/
        sp<BasicClient>* client,
        std::shared_ptr<resource_policy::ClientDescriptor<String8, sp<BasicClient>>>* partial) {
    ATRACE_CALL();
    status_t ret = NO_ERROR;
    std::vector<DescriptorPtr> evictedClients;
    DescriptorPtr clientDescriptor;
    {
        if (effectiveApiLevel == API_1) {
            // If we are using API1, any existing client for this camera ID with the same remote
            // should be returned rather than evicted to allow MediaRecorder to work properly.

            auto current = mActiveClientManager.get(cameraId);
            if (current != nullptr) {
                auto clientSp = current->getValue();
                if (clientSp.get() != nullptr) { // should never be needed
                    if (!clientSp->canCastToApiClient(effectiveApiLevel)) {
                        ALOGW("CameraService connect called with a different"
                                " API level, evicting prior client...");
                    } else if (clientSp->getRemote() == remoteCallback) {
                        ALOGI("CameraService::connect X (PID %d) (second call from same"
                                " app binder, returning the same client)", clientPid);
                        *client = clientSp;
                        return NO_ERROR;
                    }
                }
            }
        }

        // Get current active client PIDs
        std::vector<int> ownerPids(mActiveClientManager.getAllOwners());
        ownerPids.push_back(clientPid);

        std::vector<int> priorityScores(ownerPids.size());
        std::vector<int> states(ownerPids.size());

        // Get priority scores of all active PIDs
        status_t err = ProcessInfoService::getProcessStatesScoresFromPids(
                ownerPids.size(), &ownerPids[0], /*out*/&states[0],
                /*out*/&priorityScores[0]);
        if (err != OK) {
            ALOGE("%s: Priority score query failed: %d",
                  __FUNCTION__, err);
            return err;
        }

        // Update all active clients' priorities
        std::map<int,resource_policy::ClientPriority> pidToPriorityMap;
        for (size_t i = 0; i < ownerPids.size() - 1; i++) {
            pidToPriorityMap.emplace(ownerPids[i],
                    resource_policy::ClientPriority(priorityScores[i], states[i],
                            /* isVendorClient won't get copied over*/ false,
                            /* oomScoreOffset won't get copied over*/ 0));
        }
        mActiveClientManager.updatePriorities(pidToPriorityMap);

        // Get state for the given cameraId
        auto state = getCameraState(cameraId);
        if (state == nullptr) {
            ALOGE("CameraService::connect X (PID %d) rejected (no camera device with ID %s)",
                clientPid, cameraId.string());
            // Should never get here because validateConnectLocked should have errored out
            return BAD_VALUE;
        }

        int32_t actualScore = priorityScores[priorityScores.size() - 1];
        int32_t actualState = states[states.size() - 1];

        // Make descriptor for incoming client. We store the oomScoreOffset
        // since we might need it later on new handleEvictionsLocked and
        // ProcessInfoService would not take that into account.
        clientDescriptor = CameraClientManager::makeClientDescriptor(cameraId,
                sp<BasicClient>{nullptr}, static_cast<int32_t>(state->getCost()),
                state->getConflicting(), actualScore, clientPid, actualState,
                oomScoreOffset, systemNativeClient);

        resource_policy::ClientPriority clientPriority = clientDescriptor->getPriority();

        // Find clients that would be evicted
        auto evicted = mActiveClientManager.wouldEvict(clientDescriptor);

        // If the incoming client was 'evicted,' higher priority clients have the camera in the
        // background, so we cannot do evictions
        if (std::find(evicted.begin(), evicted.end(), clientDescriptor) != evicted.end()) {
            ALOGE("CameraService::connect X (PID %d) rejected (existing client(s) with higher"
                    " priority).", clientPid);

            sp<BasicClient> clientSp = clientDescriptor->getValue();
            String8 curTime = getFormattedCurrentTime();
            auto incompatibleClients =
                    mActiveClientManager.getIncompatibleClients(clientDescriptor);

            String8 msg = String8::format("%s : DENIED connect device %s client for package %s "
                    "(PID %d, score %d state %d) due to eviction policy", curTime.string(),
                    cameraId.string(), packageName.string(), clientPid,
                    clientPriority.getScore(), clientPriority.getState());

            for (auto& i : incompatibleClients) {
                msg.appendFormat("\n   - Blocked by existing device %s client for package %s"
                        "(PID %" PRId32 ", score %" PRId32 ", state %" PRId32 ")",
                        i->getKey().string(),
                        String8{i->getValue()->getPackageName()}.string(),
                        i->getOwnerId(), i->getPriority().getScore(),
                        i->getPriority().getState());
                ALOGE("   Conflicts with: Device %s, client package %s (PID %"
                        PRId32 ", score %" PRId32 ", state %" PRId32 ")", i->getKey().string(),
                        String8{i->getValue()->getPackageName()}.string(), i->getOwnerId(),
                        i->getPriority().getScore(), i->getPriority().getState());
            }

            // Log the client's attempt
            Mutex::Autolock l(mLogLock);
            mEventLog.add(msg);

            auto current = mActiveClientManager.get(cameraId);
            if (current != nullptr) {
                return -EBUSY; // CAMERA_IN_USE
            } else {
                return -EUSERS; // MAX_CAMERAS_IN_USE
            }
        }

        for (auto& i : evicted) {
            sp<BasicClient> clientSp = i->getValue();
            if (clientSp.get() == nullptr) {
                ALOGE("%s: Invalid state: Null client in active client list.", __FUNCTION__);

                // TODO: Remove this
                LOG_ALWAYS_FATAL("%s: Invalid state for CameraService, null client in active list",
                        __FUNCTION__);
                mActiveClientManager.remove(i);
                continue;
            }

            ALOGE("CameraService::connect evicting conflicting client for camera ID %s",
                    i->getKey().string());
            evictedClients.push_back(i);

            // Log the clients evicted
            logEvent(String8::format("EVICT device %s client held by package %s (PID"
                    " %" PRId32 ", score %" PRId32 ", state %" PRId32 ")\n - Evicted by device %s client for"
                    " package %s (PID %d, score %" PRId32 ", state %" PRId32 ")",
                    i->getKey().string(), String8{clientSp->getPackageName()}.string(),
                    i->getOwnerId(), i->getPriority().getScore(),
                    i->getPriority().getState(), cameraId.string(),
                    packageName.string(), clientPid, clientPriority.getScore(),
                    clientPriority.getState()));

            // Notify the client of disconnection
            clientSp->notifyError(hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_DISCONNECTED,
                    CaptureResultExtras());
        }
    }

    // Do not hold mServiceLock while disconnecting clients, but retain the condition blocking
    // other clients from connecting in mServiceLockWrapper if held
    mServiceLock.unlock();

    // Clear caller identity temporarily so client disconnect PID checks work correctly
    int64_t token = CameraThreadState::clearCallingIdentity();

    // Destroy evicted clients
    for (auto& i : evictedClients) {
        // Disconnect is blocking, and should only have returned when HAL has cleaned up
        i->getValue()->disconnect(); // Clients will remove themselves from the active client list
    }

    CameraThreadState::restoreCallingIdentity(token);

    for (const auto& i : evictedClients) {
        ALOGV("%s: Waiting for disconnect to complete for client for device %s (PID %" PRId32 ")",
                __FUNCTION__, i->getKey().string(), i->getOwnerId());
        ret = mActiveClientManager.waitUntilRemoved(i, DEFAULT_DISCONNECT_TIMEOUT_NS);
        if (ret == TIMED_OUT) {
            ALOGE("%s: Timed out waiting for client for device %s to disconnect, "
                    "current clients:\n%s", __FUNCTION__, i->getKey().string(),
                    mActiveClientManager.toString().string());
            return -EBUSY;
        }
        if (ret != NO_ERROR) {
            ALOGE("%s: Received error waiting for client for device %s to disconnect: %s (%d), "
                    "current clients:\n%s", __FUNCTION__, i->getKey().string(), strerror(-ret),
                    ret, mActiveClientManager.toString().string());
            return ret;
        }
    }

    evictedClients.clear();

    // Once clients have been disconnected, relock
    mServiceLock.lock();

    // Check again if the device was unplugged or something while we weren't holding mServiceLock
    if ((ret = checkIfDeviceIsUsable(cameraId)) != NO_ERROR) {
        return ret;
    }

    *partial = clientDescriptor;
    return NO_ERROR;
}

Status CameraService::connect(
        const sp<ICameraClient>& cameraClient,
        int api1CameraId,
        const String16& clientPackageName,
        int clientUid,
        int clientPid,
        int targetSdkVersion,
        bool overrideToPortrait,
        bool forceSlowJpegMode,
        /*out*/
        sp<ICamera>* device) {

    ATRACE_CALL();
    Status ret = Status::ok();

    String8 id = cameraIdIntToStr(api1CameraId);
    sp<Client> client = nullptr;
    ret = connectHelper<ICameraClient,Client>(cameraClient, id, api1CameraId,
            clientPackageName,/*systemNativeClient*/ false, {}, clientUid, clientPid, API_1,
            /*shimUpdateOnly*/ false, /*oomScoreOffset*/ 0, targetSdkVersion,
            overrideToPortrait, forceSlowJpegMode, /*out*/client);

    if(!ret.isOk()) {
        logRejected(id, CameraThreadState::getCallingPid(), String8(clientPackageName),
                ret.toString8());
        return ret;
    }

    *device = client;
    return ret;
}

bool CameraService::shouldSkipStatusUpdates(SystemCameraKind systemCameraKind,
        bool isVendorListener, int clientPid, int clientUid) {
    // If the client is not a vendor client, don't add listener if
    //   a) the camera is a publicly hidden secure camera OR
    //   b) the camera is a system only camera and the client doesn't
    //      have android.permission.SYSTEM_CAMERA permissions.
    if (!isVendorListener && (systemCameraKind == SystemCameraKind::HIDDEN_SECURE_CAMERA ||
            (systemCameraKind == SystemCameraKind::SYSTEM_ONLY_CAMERA &&
            !hasPermissionsForSystemCamera(clientPid, clientUid)))) {
        return true;
    }
    return false;
}

bool CameraService::shouldRejectSystemCameraConnection(const String8& cameraId) const {
    // Rules for rejection:
    // 1) If cameraserver tries to access this camera device, accept the
    //    connection.
    // 2) The camera device is a publicly hidden secure camera device AND some
    //    non system component is trying to access it.
    // 3) if the camera device is advertised by the camera HAL as SYSTEM_ONLY
    //    and the serving thread is a non hwbinder thread, the client must have
    //    android.permission.SYSTEM_CAMERA permissions to connect.

    int cPid = CameraThreadState::getCallingPid();
    int cUid = CameraThreadState::getCallingUid();
    bool systemClient = doesClientHaveSystemUid();
    SystemCameraKind systemCameraKind = SystemCameraKind::PUBLIC;
    if (getSystemCameraKind(cameraId, &systemCameraKind) != OK) {
        // This isn't a known camera ID, so it's not a system camera
        ALOGV("%s: Unknown camera id %s, ", __FUNCTION__, cameraId.c_str());
        return false;
    }

    // (1) Cameraserver trying to connect, accept.
    if (CameraThreadState::getCallingPid() == getpid()) {
        return false;
    }
    // (2)
    if (!systemClient && systemCameraKind == SystemCameraKind::HIDDEN_SECURE_CAMERA) {
        ALOGW("Rejecting access to secure hidden camera %s", cameraId.c_str());
        return true;
    }
    // (3) Here we only check for permissions if it is a system only camera device. This is since
    //     getCameraCharacteristics() allows for calls to succeed (albeit after hiding some
    //     characteristics) even if clients don't have android.permission.CAMERA. We do not want the
    //     same behavior for system camera devices.
    if (!systemClient && systemCameraKind == SystemCameraKind::SYSTEM_ONLY_CAMERA &&
            !hasPermissionsForSystemCamera(cPid, cUid, /*logPermissionFailure*/true)) {
        ALOGW("Rejecting access to system only camera %s, inadequete permissions",
                cameraId.c_str());
        return true;
    }

    return false;
}

Status CameraService::connectDevice(
        const sp<hardware::camera2::ICameraDeviceCallbacks>& cameraCb,
        const String16& cameraId,
        const String16& clientPackageName,
        const std::optional<String16>& clientFeatureId,
        int clientUid, int oomScoreOffset, int targetSdkVersion,
        bool overrideToPortrait,
        /*out*/
        sp<hardware::camera2::ICameraDeviceUser>* device) {

    ATRACE_CALL();
    Status ret = Status::ok();
    String8 id = String8(cameraId);
    sp<CameraDeviceClient> client = nullptr;
    String16 clientPackageNameAdj = clientPackageName;
    int callingPid = CameraThreadState::getCallingPid();
    bool systemNativeClient = false;
    if (doesClientHaveSystemUid() && (clientPackageNameAdj.size() == 0)) {
        std::string systemClient =
                StringPrintf("client.pid<%d>", CameraThreadState::getCallingPid());
        clientPackageNameAdj = String16(systemClient.c_str());
        systemNativeClient = true;
    }

    if (oomScoreOffset < 0) {
        String8 msg =
                String8::format("Cannot increase the priority of a client %s pid %d for "
                        "camera id %s", String8(clientPackageNameAdj).string(), callingPid,
                        id.string());
        ALOGE("%s: %s", __FUNCTION__, msg.string());
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, msg.string());
    }

    userid_t clientUserId = multiuser_get_user_id(clientUid);
    int callingUid = CameraThreadState::getCallingUid();
    if (clientUid == USE_CALLING_UID) {
        clientUserId = multiuser_get_user_id(callingUid);
    }

    if (CameraServiceProxyWrapper::isCameraDisabled(clientUserId)) {
        String8 msg =
                String8::format("Camera disabled by device policy");
        ALOGE("%s: %s", __FUNCTION__, msg.string());
        return STATUS_ERROR(ERROR_DISABLED, msg.string());
    }

    // enforce system camera permissions
    if (oomScoreOffset > 0 &&
            !hasPermissionsForSystemCamera(callingPid, CameraThreadState::getCallingUid())) {
        String8 msg =
                String8::format("Cannot change the priority of a client %s pid %d for "
                        "camera id %s without SYSTEM_CAMERA permissions",
                        String8(clientPackageNameAdj).string(), callingPid, id.string());
        ALOGE("%s: %s", __FUNCTION__, msg.string());
        return STATUS_ERROR(ERROR_PERMISSION_DENIED, msg.string());
    }

    ret = connectHelper<hardware::camera2::ICameraDeviceCallbacks,CameraDeviceClient>(cameraCb, id,
            /*api1CameraId*/-1, clientPackageNameAdj, systemNativeClient,clientFeatureId,
            clientUid, USE_CALLING_PID, API_2, /*shimUpdateOnly*/ false, oomScoreOffset,
            targetSdkVersion, overrideToPortrait, /*forceSlowJpegMode*/false,
            /*out*/client);

    if(!ret.isOk()) {
        logRejected(id, callingPid, String8(clientPackageNameAdj), ret.toString8());
        return ret;
    }

    *device = client;
    Mutex::Autolock lock(mServiceLock);

    // Clear the previous cached logs and reposition the
    // file offset to beginning of the file to log new data.
    // If either truncate or lseek fails, close the previous file and create a new one.
    if ((ftruncate(mMemFd, 0) == -1) || (lseek(mMemFd, 0, SEEK_SET) == -1)) {
        ALOGE("%s: Error while truncating the file: %s", __FUNCTION__, sFileName);
        // Close the previous memfd.
        close(mMemFd);
        // If failure to wipe the data, then create a new file and
        // assign the new value to mMemFd.
        mMemFd = memfd_create(sFileName, MFD_ALLOW_SEALING);
        if (mMemFd == -1) {
            ALOGE("%s: Error while creating the file: %s", __FUNCTION__, sFileName);
        }
    }
    return ret;
}

String16 CameraService::getPackageNameFromUid(int clientUid) {
    String16 packageName("");

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(String16(kPermissionServiceName));
    if (binder == 0) {
        ALOGE("Cannot get permission service");
        // Return empty package name and the further interaction
        // with camera will likely fail
        return packageName;
    }

    sp<IPermissionController> permCtrl = interface_cast<IPermissionController>(binder);
    Vector<String16> packages;

    permCtrl->getPackagesForUid(clientUid, packages);

    if (packages.isEmpty()) {
        ALOGE("No packages for calling UID %d", clientUid);
        // Return empty package name and the further interaction
        // with camera will likely fail
        return packageName;
    }

    // Arbitrarily pick the first name in the list
    packageName = packages[0];

    return packageName;
}

template<class CALLBACK, class CLIENT>
Status CameraService::connectHelper(const sp<CALLBACK>& cameraCb, const String8& cameraId,
        int api1CameraId, const String16& clientPackageNameMaybe, bool systemNativeClient,
        const std::optional<String16>& clientFeatureId, int clientUid, int clientPid,
        apiLevel effectiveApiLevel, bool shimUpdateOnly, int oomScoreOffset, int targetSdkVersion,
        bool overrideToPortrait, bool forceSlowJpegMode,
        /*out*/sp<CLIENT>& device) {
    binder::Status ret = binder::Status::ok();

    bool isNonSystemNdk = false;
    String16 clientPackageName;
    if (clientPackageNameMaybe.size() <= 0) {
        // NDK calls don't come with package names, but we need one for various cases.
        // Generally, there's a 1:1 mapping between UID and package name, but shared UIDs
        // do exist. For all authentication cases, all packages under the same UID get the
        // same permissions, so picking any associated package name is sufficient. For some
        // other cases, this may give inaccurate names for clients in logs.
        isNonSystemNdk = true;
        int packageUid = (clientUid == USE_CALLING_UID) ?
            CameraThreadState::getCallingUid() : clientUid;
        clientPackageName = getPackageNameFromUid(packageUid);
    } else {
        clientPackageName = clientPackageNameMaybe;
    }

    String8 clientName8(clientPackageName);

    int originalClientPid = 0;

    int packagePid = (clientPid == USE_CALLING_PID) ?
        CameraThreadState::getCallingPid() : clientPid;
    ALOGI("CameraService::connect call (PID %d \"%s\", camera ID %s) and "
            "Camera API version %d", packagePid, clientName8.string(), cameraId.string(),
            static_cast<int>(effectiveApiLevel));

    nsecs_t openTimeNs = systemTime();

    sp<CLIENT> client = nullptr;
    int facing = -1;
    int orientation = 0;

    {
        // Acquire mServiceLock and prevent other clients from connecting
        std::unique_ptr<AutoConditionLock> lock =
                AutoConditionLock::waitAndAcquire(mServiceLockWrapper, DEFAULT_CONNECT_TIMEOUT_NS);

        if (lock == nullptr) {
            ALOGE("CameraService::connect (PID %d) rejected (too many other clients connecting)."
                    , clientPid);
            return STATUS_ERROR_FMT(ERROR_MAX_CAMERAS_IN_USE,
                    "Cannot open camera %s for \"%s\" (PID %d): Too many other clients connecting",
                    cameraId.string(), clientName8.string(), clientPid);
        }

        // Enforce client permissions and do basic validity checks
        if(!(ret = validateConnectLocked(cameraId, clientName8,
                /*inout*/clientUid, /*inout*/clientPid, /*out*/originalClientPid)).isOk()) {
            return ret;
        }

        // Check the shim parameters after acquiring lock, if they have already been updated and
        // we were doing a shim update, return immediately
        if (shimUpdateOnly) {
            auto cameraState = getCameraState(cameraId);
            if (cameraState != nullptr) {
                if (!cameraState->getShimParams().isEmpty()) return ret;
            }
        }

        status_t err;

        sp<BasicClient> clientTmp = nullptr;
        std::shared_ptr<resource_policy::ClientDescriptor<String8, sp<BasicClient>>> partial;
        if ((err = handleEvictionsLocked(cameraId, originalClientPid, effectiveApiLevel,
                IInterface::asBinder(cameraCb), clientName8, oomScoreOffset, systemNativeClient,
                /*out*/&clientTmp, /*out*/&partial)) != NO_ERROR) {
            switch (err) {
                case -ENODEV:
                    return STATUS_ERROR_FMT(ERROR_DISCONNECTED,
                            "No camera device with ID \"%s\" currently available",
                            cameraId.string());
                case -EBUSY:
                    return STATUS_ERROR_FMT(ERROR_CAMERA_IN_USE,
                            "Higher-priority client using camera, ID \"%s\" currently unavailable",
                            cameraId.string());
                case -EUSERS:
                    return STATUS_ERROR_FMT(ERROR_MAX_CAMERAS_IN_USE,
                            "Too many cameras already open, cannot open camera \"%s\"",
                            cameraId.string());
                default:
                    return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION,
                            "Unexpected error %s (%d) opening camera \"%s\"",
                            strerror(-err), err, cameraId.string());
            }
        }

        if (clientTmp.get() != nullptr) {
            // Handle special case for API1 MediaRecorder where the existing client is returned
            device = static_cast<CLIENT*>(clientTmp.get());
            return ret;
        }

        // give flashlight a chance to close devices if necessary.
        mFlashlight->prepareDeviceOpen(cameraId);

        int portraitRotation;
        auto deviceVersionAndTransport =
                getDeviceVersion(cameraId, overrideToPortrait, /*out*/&portraitRotation,
                        /*out*/&facing, /*out*/&orientation);
        if (facing == -1) {
            ALOGE("%s: Unable to get camera device \"%s\"  facing", __FUNCTION__, cameraId.string());
            return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION,
                    "Unable to get camera device \"%s\" facing", cameraId.string());
        }

        sp<BasicClient> tmp = nullptr;
        bool overrideForPerfClass = SessionConfigurationUtils::targetPerfClassPrimaryCamera(
                mPerfClassPrimaryCameraIds, cameraId.string(), targetSdkVersion);
        if(!(ret = makeClient(this, cameraCb, clientPackageName, systemNativeClient,
                clientFeatureId, cameraId, api1CameraId, facing, orientation,
                clientPid, clientUid, getpid(),
                deviceVersionAndTransport, effectiveApiLevel, overrideForPerfClass,
                overrideToPortrait, forceSlowJpegMode,
                /*out*/&tmp)).isOk()) {
            return ret;
        }
        client = static_cast<CLIENT*>(tmp.get());

        LOG_ALWAYS_FATAL_IF(client.get() == nullptr, "%s: CameraService in invalid state",
                __FUNCTION__);

        String8 monitorTags = isClientWatched(client.get()) ? mMonitorTags : String8("");
        err = client->initialize(mCameraProviderManager, monitorTags);
        if (err != OK) {
            ALOGE("%s: Could not initialize client from HAL.", __FUNCTION__);
            // Errors could be from the HAL module open call or from AppOpsManager
            switch(err) {
                case BAD_VALUE:
                    return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT,
                            "Illegal argument to HAL module for camera \"%s\"", cameraId.string());
                case -EBUSY:
                    return STATUS_ERROR_FMT(ERROR_CAMERA_IN_USE,
                            "Camera \"%s\" is already open", cameraId.string());
                case -EUSERS:
                    return STATUS_ERROR_FMT(ERROR_MAX_CAMERAS_IN_USE,
                            "Too many cameras already open, cannot open camera \"%s\"",
                            cameraId.string());
                case PERMISSION_DENIED:
                    return STATUS_ERROR_FMT(ERROR_PERMISSION_DENIED,
                            "No permission to open camera \"%s\"", cameraId.string());
                case -EACCES:
                    return STATUS_ERROR_FMT(ERROR_DISABLED,
                            "Camera \"%s\" disabled by policy", cameraId.string());
                case -ENODEV:
                default:
                    return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION,
                            "Failed to initialize camera \"%s\": %s (%d)", cameraId.string(),
                            strerror(-err), err);
            }
        }

        // Update shim paremeters for legacy clients
        if (effectiveApiLevel == API_1) {
            // Assume we have always received a Client subclass for API1
            sp<Client> shimClient = reinterpret_cast<Client*>(client.get());
            String8 rawParams = shimClient->getParameters();
            CameraParameters params(rawParams);

            auto cameraState = getCameraState(cameraId);
            if (cameraState != nullptr) {
                cameraState->setShimParams(params);
            } else {
                ALOGE("%s: Cannot update shim parameters for camera %s, no such device exists.",
                        __FUNCTION__, cameraId.string());
            }
        }

        // Enable/disable camera service watchdog
        client->setCameraServiceWatchdog(mCameraServiceWatchdogEnabled);

        // Set rotate-and-crop override behavior
        if (mOverrideRotateAndCropMode != ANDROID_SCALER_ROTATE_AND_CROP_AUTO) {
            client->setRotateAndCropOverride(mOverrideRotateAndCropMode);
        } else if (overrideToPortrait && portraitRotation != 0) {
            uint8_t rotateAndCropMode = ANDROID_SCALER_ROTATE_AND_CROP_AUTO;
            switch (portraitRotation) {
                case 90:
                    rotateAndCropMode = ANDROID_SCALER_ROTATE_AND_CROP_90;
                    break;
                case 180:
                    rotateAndCropMode = ANDROID_SCALER_ROTATE_AND_CROP_180;
                    break;
                case 270:
                    rotateAndCropMode = ANDROID_SCALER_ROTATE_AND_CROP_270;
                    break;
                default:
                    ALOGE("Unexpected portrait rotation: %d", portraitRotation);
                    break;
            }
            client->setRotateAndCropOverride(rotateAndCropMode);
        } else {
            client->setRotateAndCropOverride(
              CameraServiceProxyWrapper::getRotateAndCropOverride(
                  clientPackageName, facing, multiuser_get_user_id(clientUid)));
        }

        // Set camera muting behavior
        bool isCameraPrivacyEnabled =
                mSensorPrivacyPolicy->isCameraPrivacyEnabled();
        if (client->supportsCameraMute()) {
            client->setCameraMute(
                    mOverrideCameraMuteMode || isCameraPrivacyEnabled);
        } else if (isCameraPrivacyEnabled) {
            // no camera mute supported, but privacy is on! => disconnect
            ALOGI("Camera mute not supported for package: %s, camera id: %s",
                    String8(client->getPackageName()).string(), cameraId.string());
            // Do not hold mServiceLock while disconnecting clients, but
            // retain the condition blocking other clients from connecting
            // in mServiceLockWrapper if held.
            mServiceLock.unlock();
            // Clear caller identity temporarily so client disconnect PID
            // checks work correctly
            int64_t token = CameraThreadState::clearCallingIdentity();
            // Note AppOp to trigger the "Unblock" dialog
            client->noteAppOp();
            client->disconnect();
            CameraThreadState::restoreCallingIdentity(token);
            // Reacquire mServiceLock
            mServiceLock.lock();

            return STATUS_ERROR_FMT(ERROR_DISABLED,
                    "Camera \"%s\" disabled due to camera mute", cameraId.string());
        }

        if (shimUpdateOnly) {
            // If only updating legacy shim parameters, immediately disconnect client
            mServiceLock.unlock();
            client->disconnect();
            mServiceLock.lock();
        } else {
            // Otherwise, add client to active clients list
            finishConnectLocked(client, partial, oomScoreOffset, systemNativeClient);
        }

        client->setImageDumpMask(mImageDumpMask);
        client->setStreamUseCaseOverrides(mStreamUseCaseOverrides);
    } // lock is destroyed, allow further connect calls

    // Important: release the mutex here so the client can call back into the service from its
    // destructor (can be at the end of the call)
    device = client;

    int32_t openLatencyMs = ns2ms(systemTime() - openTimeNs);
    CameraServiceProxyWrapper::logOpen(cameraId, facing, clientPackageName,
            effectiveApiLevel, isNonSystemNdk, openLatencyMs);

    {
        Mutex::Autolock lock(mInjectionParametersLock);
        if (cameraId == mInjectionInternalCamId && mInjectionInitPending) {
            mInjectionInitPending = false;
            status_t res = NO_ERROR;
            auto clientDescriptor = mActiveClientManager.get(mInjectionInternalCamId);
            if (clientDescriptor != nullptr) {
                sp<BasicClient> clientSp = clientDescriptor->getValue();
                res = checkIfInjectionCameraIsPresent(mInjectionExternalCamId, clientSp);
                if(res != OK) {
                    return STATUS_ERROR_FMT(ERROR_DISCONNECTED,
                            "No camera device with ID \"%s\" currently available",
                            mInjectionExternalCamId.string());
                }
                res = clientSp->injectCamera(mInjectionExternalCamId, mCameraProviderManager);
                if (res != OK) {
                    mInjectionStatusListener->notifyInjectionError(mInjectionExternalCamId, res);
                }
            } else {
                ALOGE("%s: Internal camera ID = %s 's client does not exist!",
                        __FUNCTION__, mInjectionInternalCamId.string());
                res = NO_INIT;
                mInjectionStatusListener->notifyInjectionError(mInjectionExternalCamId, res);
            }
        }
    }

    return ret;
}

status_t CameraService::addOfflineClient(String8 cameraId, sp<BasicClient> offlineClient) {
    if (offlineClient.get() == nullptr) {
        return BAD_VALUE;
    }

    {
        // Acquire mServiceLock and prevent other clients from connecting
        std::unique_ptr<AutoConditionLock> lock =
                AutoConditionLock::waitAndAcquire(mServiceLockWrapper, DEFAULT_CONNECT_TIMEOUT_NS);

        if (lock == nullptr) {
            ALOGE("%s: (PID %d) rejected (too many other clients connecting)."
                    , __FUNCTION__, offlineClient->getClientPid());
            return TIMED_OUT;
        }

        auto onlineClientDesc = mActiveClientManager.get(cameraId);
        if (onlineClientDesc.get() == nullptr) {
            ALOGE("%s: No active online client using camera id: %s", __FUNCTION__,
                    cameraId.c_str());
            return BAD_VALUE;
        }

        // Offline clients do not evict or conflict with other online devices. Resource sharing
        // conflicts are handled by the camera provider which will either succeed or fail before
        // reaching this method.
        const auto& onlinePriority = onlineClientDesc->getPriority();
        auto offlineClientDesc = CameraClientManager::makeClientDescriptor(
                kOfflineDevice + onlineClientDesc->getKey(), offlineClient, /*cost*/ 0,
                /*conflictingKeys*/ std::set<String8>(), onlinePriority.getScore(),
                onlineClientDesc->getOwnerId(), onlinePriority.getState(),
                // native clients don't have offline processing support.
                /*ommScoreOffset*/ 0, /*systemNativeClient*/false);

        // Allow only one offline device per camera
        auto incompatibleClients = mActiveClientManager.getIncompatibleClients(offlineClientDesc);
        if (!incompatibleClients.empty()) {
            ALOGE("%s: Incompatible offline clients present!", __FUNCTION__);
            return BAD_VALUE;
        }

        String8 monitorTags = isClientWatched(offlineClient.get()) ? mMonitorTags : String8("");
        auto err = offlineClient->initialize(mCameraProviderManager, monitorTags);
        if (err != OK) {
            ALOGE("%s: Could not initialize offline client.", __FUNCTION__);
            return err;
        }

        auto evicted = mActiveClientManager.addAndEvict(offlineClientDesc);
        if (evicted.size() > 0) {
            for (auto& i : evicted) {
                ALOGE("%s: Invalid state: Offline client for camera %s was not removed ",
                        __FUNCTION__, i->getKey().string());
            }

            LOG_ALWAYS_FATAL("%s: Invalid state for CameraService, offline clients not evicted "
                    "properly", __FUNCTION__);

            return BAD_VALUE;
        }

        logConnectedOffline(offlineClientDesc->getKey(),
                static_cast<int>(offlineClientDesc->getOwnerId()),
                String8(offlineClient->getPackageName()));

        sp<IBinder> remoteCallback = offlineClient->getRemote();
        if (remoteCallback != nullptr) {
            remoteCallback->linkToDeath(this);
        }
    } // lock is destroyed, allow further connect calls

    return OK;
}

Status CameraService::turnOnTorchWithStrengthLevel(const String16& cameraId, int32_t torchStrength,
        const sp<IBinder>& clientBinder) {
    Mutex::Autolock lock(mServiceLock);

    ATRACE_CALL();
    if (clientBinder == nullptr) {
        ALOGE("%s: torch client binder is NULL", __FUNCTION__);
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT,
                "Torch client binder in null.");
    }

    String8 id = String8(cameraId.string());
    int uid = CameraThreadState::getCallingUid();

    if (shouldRejectSystemCameraConnection(id)) {
        return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT, "Unable to change the strength level"
                "for system only device %s: ", id.string());
    }

    // verify id is valid
    auto state = getCameraState(id);
    if (state == nullptr) {
        ALOGE("%s: camera id is invalid %s", __FUNCTION__, id.string());
        return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT,
            "Camera ID \"%s\" is a not valid camera ID", id.string());
    }

    StatusInternal cameraStatus = state->getStatus();
    if (cameraStatus != StatusInternal::NOT_AVAILABLE &&
            cameraStatus != StatusInternal::PRESENT) {
        ALOGE("%s: camera id is invalid %s, status %d", __FUNCTION__, id.string(),
            (int)cameraStatus);
        return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT,
                "Camera ID \"%s\" is a not valid camera ID", id.string());
    }

    {
        Mutex::Autolock al(mTorchStatusMutex);
        TorchModeStatus status;
        status_t err = getTorchStatusLocked(id, &status);
        if (err != OK) {
            if (err == NAME_NOT_FOUND) {
             return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT,
                    "Camera \"%s\" does not have a flash unit", id.string());
            }
            ALOGE("%s: getting current torch status failed for camera %s",
                    __FUNCTION__, id.string());
            return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION,
                    "Error changing torch strength level for camera \"%s\": %s (%d)",
                    id.string(), strerror(-err), err);
        }

        if (status == TorchModeStatus::NOT_AVAILABLE) {
            if (cameraStatus == StatusInternal::NOT_AVAILABLE) {
                ALOGE("%s: torch mode of camera %s is not available because "
                        "camera is in use.", __FUNCTION__, id.string());
                return STATUS_ERROR_FMT(ERROR_CAMERA_IN_USE,
                        "Torch for camera \"%s\" is not available due to an existing camera user",
                        id.string());
            } else {
                ALOGE("%s: torch mode of camera %s is not available due to "
                       "insufficient resources", __FUNCTION__, id.string());
                return STATUS_ERROR_FMT(ERROR_MAX_CAMERAS_IN_USE,
                        "Torch for camera \"%s\" is not available due to insufficient resources",
                        id.string());
            }
        }
    }

    {
        Mutex::Autolock al(mTorchUidMapMutex);
        updateTorchUidMapLocked(cameraId, uid);
    }
    // Check if the current torch strength level is same as the new one.
    bool shouldSkipTorchStrengthUpdates = mCameraProviderManager->shouldSkipTorchStrengthUpdate(
            id.string(), torchStrength);

    status_t err = mFlashlight->turnOnTorchWithStrengthLevel(id, torchStrength);

    if (err != OK) {
        int32_t errorCode;
        String8 msg;
        switch (err) {
            case -ENOSYS:
                msg = String8::format("Camera \"%s\" has no flashlight.",
                    id.string());
                errorCode = ERROR_ILLEGAL_ARGUMENT;
                break;
            case -EBUSY:
                msg = String8::format("Camera \"%s\" is in use",
                    id.string());
                errorCode = ERROR_CAMERA_IN_USE;
                break;
            case -EINVAL:
                msg = String8::format("Torch strength level %d is not within the "
                        "valid range.", torchStrength);
                errorCode = ERROR_ILLEGAL_ARGUMENT;
                break;
            default:
                msg = String8::format("Changing torch strength level failed.");
                errorCode = ERROR_INVALID_OPERATION;
        }
        ALOGE("%s: %s", __FUNCTION__, msg.string());
        return STATUS_ERROR(errorCode, msg.string());
    }

    {
        // update the link to client's death
        // Store the last client that turns on each camera's torch mode.
        Mutex::Autolock al(mTorchClientMapMutex);
        ssize_t index = mTorchClientMap.indexOfKey(id);
        if (index == NAME_NOT_FOUND) {
            mTorchClientMap.add(id, clientBinder);
        } else {
            mTorchClientMap.valueAt(index)->unlinkToDeath(this);
            mTorchClientMap.replaceValueAt(index, clientBinder);
        }
        clientBinder->linkToDeath(this);
    }

    int clientPid = CameraThreadState::getCallingPid();
    const char *id_cstr = id.c_str();
    ALOGI("%s: Torch strength for camera id %s changed to %d for client PID %d",
            __FUNCTION__, id_cstr, torchStrength, clientPid);
    if (!shouldSkipTorchStrengthUpdates) {
        broadcastTorchStrengthLevel(id, torchStrength);
    }
    return Status::ok();
}

Status CameraService::setTorchMode(const String16& cameraId, bool enabled,
        const sp<IBinder>& clientBinder) {
    Mutex::Autolock lock(mServiceLock);

    ATRACE_CALL();
    if (enabled && clientBinder == nullptr) {
        ALOGE("%s: torch client binder is NULL", __FUNCTION__);
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT,
                "Torch client Binder is null");
    }

    String8 id = String8(cameraId.string());
    int uid = CameraThreadState::getCallingUid();

    if (shouldRejectSystemCameraConnection(id)) {
        return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT, "Unable to set torch mode"
                " for system only device %s: ", id.string());
    }
    // verify id is valid.
    auto state = getCameraState(id);
    if (state == nullptr) {
        ALOGE("%s: camera id is invalid %s", __FUNCTION__, id.string());
        return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT,
                "Camera ID \"%s\" is a not valid camera ID", id.string());
    }

    StatusInternal cameraStatus = state->getStatus();
    if (cameraStatus != StatusInternal::PRESENT &&
            cameraStatus != StatusInternal::NOT_AVAILABLE) {
        ALOGE("%s: camera id is invalid %s, status %d", __FUNCTION__, id.string(), (int)cameraStatus);
        return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT,
                "Camera ID \"%s\" is a not valid camera ID", id.string());
    }

    {
        Mutex::Autolock al(mTorchStatusMutex);
        TorchModeStatus status;
        status_t err = getTorchStatusLocked(id, &status);
        if (err != OK) {
            if (err == NAME_NOT_FOUND) {
                return STATUS_ERROR_FMT(ERROR_ILLEGAL_ARGUMENT,
                        "Camera \"%s\" does not have a flash unit", id.string());
            }
            ALOGE("%s: getting current torch status failed for camera %s",
                    __FUNCTION__, id.string());
            return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION,
                    "Error updating torch status for camera \"%s\": %s (%d)", id.string(),
                    strerror(-err), err);
        }

        if (status == TorchModeStatus::NOT_AVAILABLE) {
            if (cameraStatus == StatusInternal::NOT_AVAILABLE) {
                ALOGE("%s: torch mode of camera %s is not available because "
                        "camera is in use", __FUNCTION__, id.string());
                return STATUS_ERROR_FMT(ERROR_CAMERA_IN_USE,
                        "Torch for camera \"%s\" is not available due to an existing camera user",
                        id.string());
            } else {
                ALOGE("%s: torch mode of camera %s is not available due to "
                        "insufficient resources", __FUNCTION__, id.string());
                return STATUS_ERROR_FMT(ERROR_MAX_CAMERAS_IN_USE,
                        "Torch for camera \"%s\" is not available due to insufficient resources",
                        id.string());
            }
        }
    }

    {
        // Update UID map - this is used in the torch status changed callbacks, so must be done
        // before setTorchMode
        Mutex::Autolock al(mTorchUidMapMutex);
        updateTorchUidMapLocked(cameraId, uid);
    }

    status_t err = mFlashlight->setTorchMode(id, enabled);

    if (err != OK) {
        int32_t errorCode;
        String8 msg;
        switch (err) {
            case -ENOSYS:
                msg = String8::format("Camera \"%s\" has no flashlight",
                    id.string());
                errorCode = ERROR_ILLEGAL_ARGUMENT;
                break;
            case -EBUSY:
                msg = String8::format("Camera \"%s\" is in use",
                    id.string());
                errorCode = ERROR_CAMERA_IN_USE;
                break;
            default:
                msg = String8::format(
                    "Setting torch mode of camera \"%s\" to %d failed: %s (%d)",
                    id.string(), enabled, strerror(-err), err);
                errorCode = ERROR_INVALID_OPERATION;
        }
        ALOGE("%s: %s", __FUNCTION__, msg.string());
        logServiceError(msg,errorCode);
        return STATUS_ERROR(errorCode, msg.string());
    }

    {
        // update the link to client's death
        Mutex::Autolock al(mTorchClientMapMutex);
        ssize_t index = mTorchClientMap.indexOfKey(id);
        if (enabled) {
            if (index == NAME_NOT_FOUND) {
                mTorchClientMap.add(id, clientBinder);
            } else {
                mTorchClientMap.valueAt(index)->unlinkToDeath(this);
                mTorchClientMap.replaceValueAt(index, clientBinder);
            }
            clientBinder->linkToDeath(this);
        } else if (index != NAME_NOT_FOUND) {
            mTorchClientMap.valueAt(index)->unlinkToDeath(this);
        }
    }

    int clientPid = CameraThreadState::getCallingPid();
    const char *id_cstr = id.c_str();
    const char *torchState = enabled ? "on" : "off";
    ALOGI("Torch for camera id %s turned %s for client PID %d", id_cstr, torchState, clientPid);
    logTorchEvent(id_cstr, torchState , clientPid);
    return Status::ok();
}

void CameraService::updateTorchUidMapLocked(const String16& cameraId, int uid) {
    String8 id = String8(cameraId.string());
    if (mTorchUidMap.find(id) == mTorchUidMap.end()) {
        mTorchUidMap[id].first = uid;
        mTorchUidMap[id].second = uid;
    } else {
        // Set the pending UID
        mTorchUidMap[id].first = uid;
    }
}

Status CameraService::notifySystemEvent(int32_t eventId,
        const std::vector<int32_t>& args) {
    const int pid = CameraThreadState::getCallingPid();
    const int selfPid = getpid();

    // Permission checks
    if (pid != selfPid) {
        // Ensure we're being called by system_server, or similar process with
        // permissions to notify the camera service about system events
        if (!checkCallingPermission(sCameraSendSystemEventsPermission)) {
            const int uid = CameraThreadState::getCallingUid();
            ALOGE("Permission Denial: cannot send updates to camera service about system"
                    " events from pid=%d, uid=%d", pid, uid);
            return STATUS_ERROR_FMT(ERROR_PERMISSION_DENIED,
                    "No permission to send updates to camera service about system events"
                    " from pid=%d, uid=%d", pid, uid);
        }
    }

    ATRACE_CALL();

    switch(eventId) {
        case ICameraService::EVENT_USER_SWITCHED: {
            // Try to register for UID and sensor privacy policy updates, in case we're recovering
            // from a system server crash
            mUidPolicy->registerSelf();
            mSensorPrivacyPolicy->registerSelf();
            doUserSwitch(/*newUserIds*/ args);
            break;
        }
        case ICameraService::EVENT_USB_DEVICE_ATTACHED:
        case ICameraService::EVENT_USB_DEVICE_DETACHED: {
            // Notify CameraProviderManager for lazy HALs
            mCameraProviderManager->notifyUsbDeviceEvent(eventId,
                                                        std::to_string(args[0]));
            break;
        }
        case ICameraService::EVENT_NONE:
        default: {
            ALOGW("%s: Received invalid system event from system_server: %d", __FUNCTION__,
                    eventId);
            break;
        }
    }
    return Status::ok();
}

void CameraService::notifyMonitoredUids() {
    Mutex::Autolock lock(mStatusListenerLock);

    for (const auto& it : mListenerList) {
        auto ret = it->getListener()->onCameraAccessPrioritiesChanged();
        if (!ret.isOk()) {
            ALOGE("%s: Failed to trigger permission callback: %d", __FUNCTION__,
                    ret.exceptionCode());
        }
    }
}

Status CameraService::notifyDeviceStateChange(int64_t newState) {
    const int pid = CameraThreadState::getCallingPid();
    const int selfPid = getpid();

    // Permission checks
    if (pid != selfPid) {
        // Ensure we're being called by system_server, or similar process with
        // permissions to notify the camera service about system events
        if (!checkCallingPermission(sCameraSendSystemEventsPermission)) {
            const int uid = CameraThreadState::getCallingUid();
            ALOGE("Permission Denial: cannot send updates to camera service about device"
                    " state changes from pid=%d, uid=%d", pid, uid);
            return STATUS_ERROR_FMT(ERROR_PERMISSION_DENIED,
                    "No permission to send updates to camera service about device state"
                    " changes from pid=%d, uid=%d", pid, uid);
        }
    }

    ATRACE_CALL();

    {
        Mutex::Autolock lock(mServiceLock);
        mDeviceState = newState;
    }

    mCameraProviderManager->notifyDeviceStateChange(newState);

    return Status::ok();
}

Status CameraService::notifyDisplayConfigurationChange() {
    ATRACE_CALL();
    const int callingPid = CameraThreadState::getCallingPid();
    const int selfPid = getpid();

    // Permission checks
    if (callingPid != selfPid) {
        // Ensure we're being called by system_server, or similar process with
        // permissions to notify the camera service about system events
        if (!checkCallingPermission(sCameraSendSystemEventsPermission)) {
            const int uid = CameraThreadState::getCallingUid();
            ALOGE("Permission Denial: cannot send updates to camera service about orientation"
                    " changes from pid=%d, uid=%d", callingPid, uid);
            return STATUS_ERROR_FMT(ERROR_PERMISSION_DENIED,
                    "No permission to send updates to camera service about orientation"
                    " changes from pid=%d, uid=%d", callingPid, uid);
        }
    }

    Mutex::Autolock lock(mServiceLock);

    // Don't do anything if rotate-and-crop override via cmd is active
    if (mOverrideRotateAndCropMode != ANDROID_SCALER_ROTATE_AND_CROP_AUTO) return Status::ok();

    const auto clients = mActiveClientManager.getAll();
    for (auto& current : clients) {
        if (current != nullptr) {
            const auto basicClient = current->getValue();
            if (basicClient.get() != nullptr && !basicClient->getOverrideToPortrait()) {
                basicClient->setRotateAndCropOverride(
                        CameraServiceProxyWrapper::getRotateAndCropOverride(
                                basicClient->getPackageName(),
                                basicClient->getCameraFacing(),
                                multiuser_get_user_id(basicClient->getClientUid())));
            }
        }
    }

    return Status::ok();
}

Status CameraService::getConcurrentCameraIds(
        std::vector<ConcurrentCameraIdCombination>* concurrentCameraIds) {
    ATRACE_CALL();
    if (!concurrentCameraIds) {
        ALOGE("%s: concurrentCameraIds is NULL", __FUNCTION__);
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, "concurrentCameraIds is NULL");
    }

    if (!mInitialized) {
        ALOGE("%s: Camera HAL couldn't be initialized", __FUNCTION__);
        logServiceError(String8::format("Camera subsystem is not available"),ERROR_DISCONNECTED);
        return STATUS_ERROR(ERROR_DISCONNECTED,
                "Camera subsystem is not available");
    }
    // First call into the provider and get the set of concurrent camera
    // combinations
    std::vector<std::unordered_set<std::string>> concurrentCameraCombinations =
            mCameraProviderManager->getConcurrentCameraIds();
    for (auto &combination : concurrentCameraCombinations) {
        std::vector<std::string> validCombination;
        for (auto &cameraId : combination) {
            // if the camera state is not present, skip
            String8 cameraIdStr(cameraId.c_str());
            auto state = getCameraState(cameraIdStr);
            if (state == nullptr) {
                ALOGW("%s: camera id %s does not exist", __FUNCTION__, cameraId.c_str());
                continue;
            }
            StatusInternal status = state->getStatus();
            if (status == StatusInternal::NOT_PRESENT || status == StatusInternal::ENUMERATING) {
                continue;
            }
            if (shouldRejectSystemCameraConnection(cameraIdStr)) {
                continue;
            }
            validCombination.push_back(cameraId);
        }
        if (validCombination.size() != 0) {
            concurrentCameraIds->push_back(std::move(validCombination));
        }
    }
    return Status::ok();
}

Status CameraService::isConcurrentSessionConfigurationSupported(
        const std::vector<CameraIdAndSessionConfiguration>& cameraIdsAndSessionConfigurations,
        int targetSdkVersion, /*out*/bool* isSupported) {
    if (!isSupported) {
        ALOGE("%s: isSupported is NULL", __FUNCTION__);
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, "isSupported is NULL");
    }

    if (!mInitialized) {
        ALOGE("%s: Camera HAL couldn't be initialized", __FUNCTION__);
        return STATUS_ERROR(ERROR_DISCONNECTED,
                "Camera subsystem is not available");
    }

    // Check for camera permissions
    int callingPid = CameraThreadState::getCallingPid();
    int callingUid = CameraThreadState::getCallingUid();
    if ((callingPid != getpid()) && !checkPermission(sCameraPermission, callingPid, callingUid)) {
        ALOGE("%s: pid %d doesn't have camera permissions", __FUNCTION__, callingPid);
        return STATUS_ERROR(ERROR_PERMISSION_DENIED,
                "android.permission.CAMERA needed to call"
                "isConcurrentSessionConfigurationSupported");
    }

    status_t res =
            mCameraProviderManager->isConcurrentSessionConfigurationSupported(
                    cameraIdsAndSessionConfigurations, mPerfClassPrimaryCameraIds,
                    targetSdkVersion, isSupported);
    if (res != OK) {
        logServiceError(String8::format("Unable to query session configuration support"),
            ERROR_INVALID_OPERATION);
        return STATUS_ERROR_FMT(ERROR_INVALID_OPERATION, "Unable to query session configuration "
                "support %s (%d)", strerror(-res), res);
    }
    return Status::ok();
}

Status CameraService::addListener(const sp<ICameraServiceListener>& listener,
        /*out*/
        std::vector<hardware::CameraStatus> *cameraStatuses) {
    return addListenerHelper(listener, cameraStatuses);
}

binder::Status CameraService::addListenerTest(const sp<hardware::ICameraServiceListener>& listener,
            std::vector<hardware::CameraStatus>* cameraStatuses) {
    return addListenerHelper(listener, cameraStatuses, false, true);
}

Status CameraService::addListenerHelper(const sp<ICameraServiceListener>& listener,
        /*out*/
        std::vector<hardware::CameraStatus> *cameraStatuses,
        bool isVendorListener, bool isProcessLocalTest) {

    ATRACE_CALL();

    ALOGV("%s: Add listener %p", __FUNCTION__, listener.get());

    if (listener == nullptr) {
        ALOGE("%s: Listener must not be null", __FUNCTION__);
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, "Null listener given to addListener");
    }

    auto clientUid = CameraThreadState::getCallingUid();
    auto clientPid = CameraThreadState::getCallingPid();
    bool openCloseCallbackAllowed = checkPermission(sCameraOpenCloseListenerPermission,
            clientPid, clientUid, /*logPermissionFailure*/false);

    Mutex::Autolock lock(mServiceLock);

    {
        Mutex::Autolock lock(mStatusListenerLock);
        for (const auto &it : mListenerList) {
            if (IInterface::asBinder(it->getListener()) == IInterface::asBinder(listener)) {
                ALOGW("%s: Tried to add listener %p which was already subscribed",
                      __FUNCTION__, listener.get());
                return STATUS_ERROR(ERROR_ALREADY_EXISTS, "Listener already registered");
            }
        }

        sp<ServiceListener> serviceListener =
                new ServiceListener(this, listener, clientUid, clientPid, isVendorListener,
                        openCloseCallbackAllowed);
        auto ret = serviceListener->initialize(isProcessLocalTest);
        if (ret != NO_ERROR) {
            String8 msg = String8::format("Failed to initialize service listener: %s (%d)",
                    strerror(-ret), ret);
            logServiceError(msg,ERROR_ILLEGAL_ARGUMENT);
            ALOGE("%s: %s", __FUNCTION__, msg.string());
            return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, msg.string());
        }
        // The listener still needs to be added to the list of listeners, regardless of what
        // permissions the listener process has / whether it is a vendor listener. Since it might be
        // eligible to listen to other camera ids.
        mListenerList.emplace_back(serviceListener);
        mUidPolicy->registerMonitorUid(clientUid);
    }

    /* Collect current devices and status */
    {
        Mutex::Autolock lock(mCameraStatesLock);
        for (auto& i : mCameraStates) {
            cameraStatuses->emplace_back(i.first,
                    mapToInterface(i.second->getStatus()), i.second->getUnavailablePhysicalIds(),
                    openCloseCallbackAllowed ? i.second->getClientPackage() : String8::empty());
        }
    }
    // Remove the camera statuses that should be hidden from the client, we do
    // this after collecting the states in order to avoid holding
    // mCameraStatesLock and mInterfaceLock (held in getSystemCameraKind()) at
    // the same time.
    cameraStatuses->erase(std::remove_if(cameraStatuses->begin(), cameraStatuses->end(),
                [this, &isVendorListener, &clientPid, &clientUid](const hardware::CameraStatus& s) {
                    SystemCameraKind deviceKind = SystemCameraKind::PUBLIC;
                    if (getSystemCameraKind(s.cameraId, &deviceKind) != OK) {
                        ALOGE("%s: Invalid camera id %s, skipping status update",
                                __FUNCTION__, s.cameraId.c_str());
                        return true;
                    }
                    return shouldSkipStatusUpdates(deviceKind, isVendorListener, clientPid,
                            clientUid);}), cameraStatuses->end());

    //cameraStatuses will have non-eligible camera ids removed.
    std::set<String16> idsChosenForCallback;
    for (const auto &s : *cameraStatuses) {
        idsChosenForCallback.insert(String16(s.cameraId));
    }

    /*
     * Immediately signal current torch status to this listener only
     * This may be a subset of all the devices, so don't include it in the response directly
     */
    {
        Mutex::Autolock al(mTorchStatusMutex);
        for (size_t i = 0; i < mTorchStatusMap.size(); i++ ) {
            String16 id = String16(mTorchStatusMap.keyAt(i).string());
            // The camera id is visible to the client. Fine to send torch
            // callback.
            if (idsChosenForCallback.find(id) != idsChosenForCallback.end()) {
                listener->onTorchStatusChanged(mapToInterface(mTorchStatusMap.valueAt(i)), id);
            }
        }
    }

    return Status::ok();
}

Status CameraService::removeListener(const sp<ICameraServiceListener>& listener) {
    ATRACE_CALL();

    ALOGV("%s: Remove listener %p", __FUNCTION__, listener.get());

    if (listener == 0) {
        ALOGE("%s: Listener must not be null", __FUNCTION__);
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, "Null listener given to removeListener");
    }

    Mutex::Autolock lock(mServiceLock);

    {
        Mutex::Autolock lock(mStatusListenerLock);
        for (auto it = mListenerList.begin(); it != mListenerList.end(); it++) {
            if (IInterface::asBinder((*it)->getListener()) == IInterface::asBinder(listener)) {
                mUidPolicy->unregisterMonitorUid((*it)->getListenerUid());
                IInterface::asBinder(listener)->unlinkToDeath(*it);
                mListenerList.erase(it);
                return Status::ok();
            }
        }
    }

    ALOGW("%s: Tried to remove a listener %p which was not subscribed",
          __FUNCTION__, listener.get());

    return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, "Unregistered listener given to removeListener");
}

Status CameraService::getLegacyParameters(int cameraId, /*out*/String16* parameters) {

    ATRACE_CALL();
    ALOGV("%s: for camera ID = %d", __FUNCTION__, cameraId);

    if (parameters == NULL) {
        ALOGE("%s: parameters must not be null", __FUNCTION__);
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, "Parameters must not be null");
    }

    Status ret = Status::ok();

    CameraParameters shimParams;
    if (!(ret = getLegacyParametersLazy(cameraId, /*out*/&shimParams)).isOk()) {
        // Error logged by caller
        return ret;
    }

    String8 shimParamsString8 = shimParams.flatten();
    String16 shimParamsString16 = String16(shimParamsString8);

    *parameters = shimParamsString16;

    return ret;
}

Status CameraService::supportsCameraApi(const String16& cameraId, int apiVersion,
        /*out*/ bool *isSupported) {
    ATRACE_CALL();

    const String8 id = String8(cameraId);

    ALOGV("%s: for camera ID = %s", __FUNCTION__, id.string());

    switch (apiVersion) {
        case API_VERSION_1:
        case API_VERSION_2:
            break;
        default:
            String8 msg = String8::format("Unknown API version %d", apiVersion);
            ALOGE("%s: %s", __FUNCTION__, msg.string());
            return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, msg.string());
    }

    int portraitRotation;
    auto deviceVersionAndTransport = getDeviceVersion(id, false, &portraitRotation);
    if (deviceVersionAndTransport.first == -1) {
        String8 msg = String8::format("Unknown camera ID %s", id.string());
        ALOGE("%s: %s", __FUNCTION__, msg.string());
        return STATUS_ERROR(ERROR_ILLEGAL_ARGUMENT, msg.string());
    }
    if (deviceVersionAndTransport.second == IPCTransport::HIDL) {
        int deviceVersion = deviceVersionAndTransport.first;
        switch (deviceVersion) {
            case CAMERA_DEVICE_API_VERSION_1_0:
            case CAMERA_DEVICE_API_VERSION_3_0:
            case CAMERA_DEVICE_API_VERSION_3_1:
                if (apiVersion == API_VERSION_2) {
                    ALOGV("%s: Camera id %s uses HAL version %d <3.2, doesn't support api2 without "
                            "shim", __FUNCTION__, id.string(), deviceVersion);
                    *isSupported = false;
                } else { // if (apiVersion == API_VERSION_1) {
                    ALOGV("%s: Camera id %s uses older HAL before 3.2, but api1 is always "
                            "supported", __FUNCTION__, id.string());
                    *isSupported = true;
                }
                break;
            case CAMERA_DEVICE_API_VERSION_3_2:
            case CAMERA_DEVICE_API_VERSION_3_3:
            case CAMERA_DEVICE_API_VERSION_3_4:
            case CAMERA_DEVICE_API_VERSION_3_5:
            case CAMERA_DEVICE_API_VERSION_3_6:
            case CAMERA_DEVICE_API_VERSION_3_7:
                ALOGV("%s: Camera id %s uses HAL3.2 or newer, supports api1/api2 directly",
                        __FUNCTION__, id.string());
                *isSupported = true;
                break;
            default: {
                String8 msg = String8::format("Unknown device version %x for device %s",
                        deviceVersion, id.string());
                ALOGE("%s: %s", __FUNCTION__, msg.string());
                return STATUS_ERROR(ERROR_INVALID_OPERATION, msg.string());
            }
        }
    } else {
        *isSupported = true;
    }
    return Status::ok();
}

Status CameraService::isHiddenPhysicalCamera(const String16& cameraId,
        /*out*/ bool *isSupported) {
    ATRACE_CALL();

    const String8 id = String8(cameraId);

    ALOGV("%s: for camera ID = %s", __FUNCTION__, id.string());
    *isSupported = mCameraProviderManager->isHiddenPhysicalCamera(id.string());

    return Status::ok();
}

Status CameraService::injectCamera(
        const String16& packageName, const String16& internalCamId,
        const String16& externalCamId,
        const sp<ICameraInjectionCallback>& callback,
        /*out*/
        sp<ICameraInjectionSession>* cameraInjectionSession) {
    ATRACE_CALL();

    if (!checkCallingPermission(sCameraInjectExternalCameraPermission)) {
        const int pid = CameraThreadState::getCallingPid();
        const int uid = CameraThreadState::getCallingUid();
        ALOGE("Permission Denial: can't inject camera pid=%d, uid=%d", pid, uid);
        return STATUS_ERROR(ERROR_PERMISSION_DENIED,
                        "Permission Denial: no permission to inject camera");
    }

    ALOGV(
        "%s: Package name = %s, Internal camera ID = %s, External camera ID = "
        "%s",
        __FUNCTION__, String8(packageName).string(),
        String8(internalCamId).string(), String8(externalCamId).string());

    {
        Mutex::Autolock lock(mInjectionParametersLock);
        mInjectionInternalCamId = String8(internalCamId);
        mInjectionExternalCamId = String8(externalCamId);
        mInjectionStatusListener->addListener(callback);
        *cameraInjectionSession = new CameraInjectionSession(this);
        status_t res = NO_ERROR;
        auto clientDescriptor = mActiveClientManager.get(mInjectionInternalCamId);
        // If the client already exists, we can directly connect to the camera device through the
        // client's injectCamera(), otherwise we need to wait until the client is established
        // (execute connectHelper()) before injecting the camera to the camera device.
        if (clientDescriptor != nullptr) {
            mInjectionInitPending = false;
            sp<BasicClient> clientSp = clientDescriptor->getValue();
            res = checkIfInjectionCameraIsPresent(mInjectionExternalCamId, clientSp);
            if(res != OK) {
                return STATUS_ERROR_FMT(ERROR_DISCONNECTED,
                        "No camera device with ID \"%s\" currently available",
                        mInjectionExternalCamId.string());
            }
            res = clientSp->injectCamera(mInjectionExternalCamId, mCameraProviderManager);
            if(res != OK) {
                mInjectionStatusListener->notifyInjectionError(mInjectionExternalCamId, res);
            }
        } else {
            mInjectionInitPending = true;
        }
    }

    return binder::Status::ok();
}

void CameraService::removeByClient(const BasicClient* client) {
    Mutex::Autolock lock(mServiceLock);
    for (auto& i : mActiveClientManager.getAll()) {
        auto clientSp = i->getValue();
        if (clientSp.get() == client) {
            cacheClientTagDumpIfNeeded(client->mCameraIdStr, clientSp.get());
            mActiveClientManager.remove(i);
        }
    }
    updateAudioRestrictionLocked();
}

bool CameraService::evictClientIdByRemote(const wp<IBinder>& remote) {
    bool ret = false;
    {
        // Acquire mServiceLock and prevent other clients from connecting
        std::unique_ptr<AutoConditionLock> lock =
                AutoConditionLock::waitAndAcquire(mServiceLockWrapper);


        std::vector<sp<BasicClient>> evicted;
        for (auto& i : mActiveClientManager.getAll()) {
            auto clientSp = i->getValue();
            if (clientSp.get() == nullptr) {
                ALOGE("%s: Dead client still in mActiveClientManager.", __FUNCTION__);
                mActiveClientManager.remove(i);
                continue;
            }
            if (remote == clientSp->getRemote()) {
                mActiveClientManager.remove(i);
                evicted.push_back(clientSp);

                // Notify the client of disconnection
                clientSp->notifyError(
                        hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_DISCONNECTED,
                        CaptureResultExtras());
            }
        }

        // Do not hold mServiceLock while disconnecting clients, but retain the condition blocking
        // other clients from connecting in mServiceLockWrapper if held
        mServiceLock.unlock();

        // Do not clear caller identity, remote caller should be client proccess

        for (auto& i : evicted) {
            if (i.get() != nullptr) {
                i->disconnect();
                ret = true;
            }
        }

        // Reacquire mServiceLock
        mServiceLock.lock();

    } // lock is destroyed, allow further connect calls

    return ret;
}

std::shared_ptr<CameraService::CameraState> CameraService::getCameraState(
        const String8& cameraId) const {
    std::shared_ptr<CameraState> state;
    {
        Mutex::Autolock lock(mCameraStatesLock);
        auto iter = mCameraStates.find(cameraId);
        if (iter != mCameraStates.end()) {
            state = iter->second;
        }
    }
    return state;
}

sp<CameraService::BasicClient> CameraService::removeClientLocked(const String8& cameraId) {
    // Remove from active clients list
    auto clientDescriptorPtr = mActiveClientManager.remove(cameraId);
    if (clientDescriptorPtr == nullptr) {
        ALOGW("%s: Could not evict client, no client for camera ID %s", __FUNCTION__,
                cameraId.string());
        return sp<BasicClient>{nullptr};
    }

    sp<BasicClient> client = clientDescriptorPtr->getValue();
    if (client.get() != nullptr) {
        cacheClientTagDumpIfNeeded(clientDescriptorPtr->getKey(), client.get());
    }
    return client;
}

void CameraService::doUserSwitch(const std::vector<int32_t>& newUserIds) {
    // Acquire mServiceLock and prevent other clients from connecting
    std::unique_ptr<AutoConditionLock> lock =
            AutoConditionLock::waitAndAcquire(mServiceLockWrapper);

    std::set<userid_t> newAllowedUsers;
    for (size_t i = 0; i < newUserIds.size(); i++) {
        if (newUserIds[i] < 0) {
            ALOGE("%s: Bad user ID %d given during user switch, ignoring.",
                    __FUNCTION__, newUserIds[i]);
            return;
        }
        newAllowedUsers.insert(static_cast<userid_t>(newUserIds[i]));
    }


    if (newAllowedUsers == mAllowedUsers) {
        ALOGW("%s: Received notification of user switch with no updated user IDs.", __FUNCTION__);
        return;
    }

    logUserSwitch(mAllowedUsers, newAllowedUsers);

    mAllowedUsers = std::move(newAllowedUsers);

    // Current user has switched, evict all current clients.
    std::vector<sp<BasicClient>> evicted;
    for (auto& i : mActiveClientManager.getAll()) {
        auto clientSp = i->getValue();

        if (clientSp.get() == nullptr) {
            ALOGE("%s: Dead client still in mActiveClientManager.", __FUNCTION__);
            continue;
        }

        // Don't evict clients that are still allowed.
        uid_t clientUid = clientSp->getClientUid();
        userid_t clientUserId = multiuser_get_user_id(clientUid);
        if (mAllowedUsers.find(clientUserId) != mAllowedUsers.end()) {
            continue;
        }

        evicted.push_back(clientSp);

        String8 curTime = getFormattedCurrentTime();

        ALOGE("Evicting conflicting client for camera ID %s due to user change",
                i->getKey().string());

        // Log the clients evicted
        logEvent(String8::format("EVICT device %s client held by package %s (PID %"
                PRId32 ", score %" PRId32 ", state %" PRId32 ")\n   - Evicted due"
                " to user switch.", i->getKey().string(),
                String8{clientSp->getPackageName()}.string(),
                i->getOwnerId(), i->getPriority().getScore(),
                i->getPriority().getState()));

    }

    // Do not hold mServiceLock while disconnecting clients, but retain the condition
    // blocking other clients from connecting in mServiceLockWrapper if held.
    mServiceLock.unlock();

    // Clear caller identity temporarily so client disconnect PID checks work correctly
    int64_t token = CameraThreadState::clearCallingIdentity();

    for (auto& i : evicted) {
        i->disconnect();
    }

    CameraThreadState::restoreCallingIdentity(token);

    // Reacquire mServiceLock
    mServiceLock.lock();
}

void CameraService::logEvent(const char* event) {
    String8 curTime = getFormattedCurrentTime();
    Mutex::Autolock l(mLogLock);
    String8 msg = String8::format("%s : %s", curTime.string(), event);
    // For service error events, print the msg only once.
    if(!msg.contains("SERVICE ERROR")) {
        mEventLog.add(msg);
    } else if(sServiceErrorEventSet.find(msg) == sServiceErrorEventSet.end()) {
        // Error event not added to the dumpsys log before
        mEventLog.add(msg);
        sServiceErrorEventSet.insert(msg);
    }
}

void CameraService::logDisconnected(const char* cameraId, int clientPid,
        const char* clientPackage) {
    // Log the clients evicted
    logEvent(String8::format("DISCONNECT device %s client for package %s (PID %d)", cameraId,
            clientPackage, clientPid));
}

void CameraService::logDisconnectedOffline(const char* cameraId, int clientPid,
        const char* clientPackage) {
    // Log the clients evicted
    logEvent(String8::format("DISCONNECT offline device %s client for package %s (PID %d)",
                cameraId, clientPackage, clientPid));
}

void CameraService::logConnected(const char* cameraId, int clientPid,
        const char* clientPackage) {
    // Log the clients evicted
    logEvent(String8::format("CONNECT device %s client for package %s (PID %d)", cameraId,
            clientPackage, clientPid));
}

void CameraService::logConnectedOffline(const char* cameraId, int clientPid,
        const char* clientPackage) {
    // Log the clients evicted
    logEvent(String8::format("CONNECT offline device %s client for package %s (PID %d)", cameraId,
            clientPackage, clientPid));
}

void CameraService::logRejected(const char* cameraId, int clientPid,
        const char* clientPackage, const char* reason) {
    // Log the client rejected
    logEvent(String8::format("REJECT device %s client for package %s (PID %d), reason: (%s)",
            cameraId, clientPackage, clientPid, reason));
}

void CameraService::logTorchEvent(const char* cameraId, const char *torchState, int clientPid) {
    // Log torch event
    logEvent(String8::format("Torch for camera id %s turned %s for client PID %d", cameraId,
            torchState, clientPid));
}

void CameraService::logUserSwitch(const std::set<userid_t>& oldUserIds,
        const std::set<userid_t>& newUserIds) {
    String8 newUsers = toString(newUserIds);
    String8 oldUsers = toString(oldUserIds);
    if (oldUsers.size() == 0) {
        oldUsers = "<None>";
    }
    // Log the new and old users
    logEvent(String8::format("USER_SWITCH previous allowed user IDs: %s, current allowed user IDs: %s",
            oldUsers.string(), newUsers.string()));
}

void CameraService::logDeviceRemoved(const char* cameraId, const char* reason) {
    // Log the device removal
    logEvent(String8::format("REMOVE device %s, reason: (%s)", cameraId, reason));
}

void CameraService::logDeviceAdded(const char* cameraId, const char* reason) {
    // Log the device removal
    logEvent(String8::format("ADD device %s, reason: (%s)", cameraId, reason));
}

void CameraService::logClientDied(int clientPid, const char* reason) {
    // Log the device removal
    logEvent(String8::format("DIED client(s) with PID %d, reason: (%s)", clientPid, reason));
}

void CameraService::logServiceError(const char* msg, int errorCode) {
    String8 curTime = getFormattedCurrentTime();
    logEvent(String8::format("SERVICE ERROR: %s : %d (%s)", msg, errorCode, strerror(-errorCode)));
}

status_t CameraService::onTransact(uint32_t code, const Parcel& data, Parcel* reply,
        uint32_t flags) {

    // Permission checks
    switch (code) {
        case SHELL_COMMAND_TRANSACTION: {
            int in = data.readFileDescriptor();
            int out = data.readFileDescriptor();
            int err = data.readFileDescriptor();
            int argc = data.readInt32();
            Vector<String16> args;
            for (int i = 0; i < argc && data.dataAvail() > 0; i++) {
               args.add(data.readString16());
            }
            sp<IBinder> unusedCallback;
            sp<IResultReceiver> resultReceiver;
            status_t status;
            if ((status = data.readNullableStrongBinder(&unusedCallback)) != NO_ERROR) {
                return status;
            }
            if ((status = data.readNullableStrongBinder(&resultReceiver)) != NO_ERROR) {
                return status;
            }
            status = shellCommand(in, out, err, args);
            if (resultReceiver != nullptr) {
                resultReceiver->send(status);
            }
            return NO_ERROR;
        }
    }

    return BnCameraService::onTransact(code, data, reply, flags);
}

// We share the media players for shutter and recording sound for all clients.
// A reference count is kept to determine when we will actually release the
// media players.

sp<MediaPlayer> CameraService::newMediaPlayer(const char *file) {
    sp<MediaPlayer> mp = new MediaPlayer();
    status_t error;
    if ((error = mp->setDataSource(NULL /* httpService */, file, NULL)) == NO_ERROR) {
        mp->setAudioStreamType(AUDIO_STREAM_ENFORCED_AUDIBLE);
        error = mp->prepare();
    }
    if (error != NO_ERROR) {
        ALOGE("Failed to load CameraService sounds: %s", file);
        mp->disconnect();
        mp.clear();
        return nullptr;
    }
    return mp;
}

void CameraService::increaseSoundRef() {
    Mutex::Autolock lock(mSoundLock);
    mSoundRef++;
}

void CameraService::loadSoundLocked(sound_kind kind) {
    ATRACE_CALL();

    LOG1("CameraService::loadSoundLocked ref=%d", mSoundRef);
    if (SOUND_SHUTTER == kind && mSoundPlayer[SOUND_SHUTTER] == NULL) {
        mSoundPlayer[SOUND_SHUTTER] = newMediaPlayer("/product/media/audio/ui/camera_click.ogg");
        if (mSoundPlayer[SOUND_SHUTTER] == nullptr) {
            mSoundPlayer[SOUND_SHUTTER] = newMediaPlayer("/system/media/audio/ui/camera_click.ogg");
        }
    } else if (SOUND_RECORDING_START == kind && mSoundPlayer[SOUND_RECORDING_START] ==  NULL) {
        mSoundPlayer[SOUND_RECORDING_START] = newMediaPlayer("/product/media/audio/ui/VideoRecord.ogg");
        if (mSoundPlayer[SOUND_RECORDING_START] == nullptr) {
            mSoundPlayer[SOUND_RECORDING_START] =
                newMediaPlayer("/system/media/audio/ui/VideoRecord.ogg");
        }
    } else if (SOUND_RECORDING_STOP == kind && mSoundPlayer[SOUND_RECORDING_STOP] == NULL) {
        mSoundPlayer[SOUND_RECORDING_STOP] = newMediaPlayer("/product/media/audio/ui/VideoStop.ogg");
        if (mSoundPlayer[SOUND_RECORDING_STOP] == nullptr) {
            mSoundPlayer[SOUND_RECORDING_STOP] = newMediaPlayer("/system/media/audio/ui/VideoStop.ogg");
        }
    }
}

void CameraService::decreaseSoundRef() {
    Mutex::Autolock lock(mSoundLock);
    LOG1("CameraService::decreaseSoundRef ref=%d", mSoundRef);
    if (--mSoundRef) return;

    for (int i = 0; i < NUM_SOUNDS; i++) {
        if (mSoundPlayer[i] != 0) {
            mSoundPlayer[i]->disconnect();
            mSoundPlayer[i].clear();
        }
    }
}

void CameraService::playSound(sound_kind kind) {
    ATRACE_CALL();

    LOG1("playSound(%d)", kind);
    if (kind < 0 || kind >= NUM_SOUNDS) {
        ALOGE("%s: Invalid sound id requested: %d", __FUNCTION__, kind);
        return;
    }

    Mutex::Autolock lock(mSoundLock);
    loadSoundLocked(kind);
    sp<MediaPlayer> player = mSoundPlayer[kind];
    if (player != 0) {
        player->seekTo(0);
        player->start();
    }
}

// ----------------------------------------------------------------------------

CameraService::Client::Client(const sp<CameraService>& cameraService,
        const sp<ICameraClient>& cameraClient,
        const String16& clientPackageName, bool systemNativeClient,
        const std::optional<String16>& clientFeatureId,
        const String8& cameraIdStr,
        int api1CameraId, int cameraFacing, int sensorOrientation,
        int clientPid, uid_t clientUid,
        int servicePid, bool overrideToPortrait) :
        CameraService::BasicClient(cameraService,
                IInterface::asBinder(cameraClient),
                clientPackageName, systemNativeClient, clientFeatureId,
                cameraIdStr, cameraFacing, sensorOrientation,
                clientPid, clientUid,
                servicePid, overrideToPortrait),
        mCameraId(api1CameraId)
{
    int callingPid = CameraThreadState::getCallingPid();
    LOG1("Client::Client E (pid %d, id %d)", callingPid, mCameraId);

    mRemoteCallback = cameraClient;

    cameraService->increaseSoundRef();

    LOG1("Client::Client X (pid %d, id %d)", callingPid, mCameraId);
}

// tear down the client
CameraService::Client::~Client() {
    ALOGV("~Client");
    mDestructionStarted = true;

    sCameraService->decreaseSoundRef();
    // unconditionally disconnect. function is idempotent
    Client::disconnect();
}

sp<CameraService> CameraService::BasicClient::BasicClient::sCameraService;

CameraService::BasicClient::BasicClient(const sp<CameraService>& cameraService,
        const sp<IBinder>& remoteCallback,
        const String16& clientPackageName, bool nativeClient,
        const std::optional<String16>& clientFeatureId, const String8& cameraIdStr,
        int cameraFacing, int sensorOrientation, int clientPid, uid_t clientUid,
        int servicePid, bool overrideToPortrait):
        mDestructionStarted(false),
        mCameraIdStr(cameraIdStr), mCameraFacing(cameraFacing), mOrientation(sensorOrientation),
        mClientPackageName(clientPackageName), mSystemNativeClient(nativeClient),
        mClientFeatureId(clientFeatureId),
        mClientPid(clientPid), mClientUid(clientUid),
        mServicePid(servicePid),
        mDisconnected(false), mUidIsTrusted(false),
        mOverrideToPortrait(overrideToPortrait),
        mAudioRestriction(hardware::camera2::ICameraDeviceUser::AUDIO_RESTRICTION_NONE),
        mRemoteBinder(remoteCallback),
        mOpsActive(false),
        mOpsStreaming(false)
{
    if (sCameraService == nullptr) {
        sCameraService = cameraService;
    }

    // There are 2 scenarios in which a client won't have AppOps operations
    // (both scenarios : native clients)
    //    1) It's an system native client*, the package name will be empty
    //       and it will return from this function in the previous if condition
    //       (This is the same as the previously existing behavior).
    //    2) It is a system native client, but its package name has been
    //       modified for debugging, however it still must not use AppOps since
    //       the package name is not a real one.
    //
    //       * system native client - native client with UID < AID_APP_START. It
    //         doesn't exclude clients not on the system partition.
    if (!mSystemNativeClient) {
        mAppOpsManager = std::make_unique<AppOpsManager>();
    }

    mUidIsTrusted = isTrustedCallingUid(mClientUid);
}

CameraService::BasicClient::~BasicClient() {
    ALOGV("~BasicClient");
    mDestructionStarted = true;
}

binder::Status CameraService::BasicClient::disconnect() {
    binder::Status res = Status::ok();
    if (mDisconnected) {
        return res;
    }
    mDisconnected = true;

    sCameraService->removeByClient(this);
    sCameraService->logDisconnected(mCameraIdStr, mClientPid, String8(mClientPackageName));
    sCameraService->mCameraProviderManager->removeRef(CameraProviderManager::DeviceMode::CAMERA,
            mCameraIdStr.c_str());

    sp<IBinder> remote = getRemote();
    if (remote != nullptr) {
        remote->unlinkToDeath(sCameraService);
    }

    finishCameraOps();
    // Notify flashlight that a camera device is closed.
    sCameraService->mFlashlight->deviceClosed(mCameraIdStr);
    ALOGI("%s: Disconnected client for camera %s for PID %d", __FUNCTION__, mCameraIdStr.string(),
            mClientPid);

    // client shouldn't be able to call into us anymore
    mClientPid = 0;

    return res;
}

status_t CameraService::BasicClient::dump(int, const Vector<String16>&) {
    // No dumping of clients directly over Binder,
    // must go through CameraService::dump
    android_errorWriteWithInfoLog(SN_EVENT_LOG_ID, "26265403",
            CameraThreadState::getCallingUid(), NULL, 0);
    return OK;
}

status_t CameraService::BasicClient::startWatchingTags(const String8&, int) {
    // Can't watch tags directly, must go through CameraService::startWatchingTags
    return OK;
}

status_t CameraService::BasicClient::stopWatchingTags(int) {
    // Can't watch tags directly, must go through CameraService::stopWatchingTags
    return OK;
}

status_t CameraService::BasicClient::dumpWatchedEventsToVector(std::vector<std::string> &) {
    // Can't watch tags directly, must go through CameraService::dumpWatchedEventsToVector
    return OK;
}

String16 CameraService::BasicClient::getPackageName() const {
    return mClientPackageName;
}

int CameraService::BasicClient::getCameraFacing() const {
    return mCameraFacing;
}

int CameraService::BasicClient::getCameraOrientation() const {
    return mOrientation;
}

int CameraService::BasicClient::getClientPid() const {
    return mClientPid;
}

uid_t CameraService::BasicClient::getClientUid() const {
    return mClientUid;
}

bool CameraService::BasicClient::canCastToApiClient(apiLevel level) const {
    // Defaults to API2.
    return level == API_2;
}

status_t CameraService::BasicClient::setAudioRestriction(int32_t mode) {
    {
        Mutex::Autolock l(mAudioRestrictionLock);
        mAudioRestriction = mode;
    }
    sCameraService->updateAudioRestriction();
    return OK;
}

int32_t CameraService::BasicClient::getServiceAudioRestriction() const {
    return sCameraService->updateAudioRestriction();
}

int32_t CameraService::BasicClient::getAudioRestriction() const {
    Mutex::Autolock l(mAudioRestrictionLock);
    return mAudioRestriction;
}

bool CameraService::BasicClient::isValidAudioRestriction(int32_t mode) {
    switch (mode) {
        case hardware::camera2::ICameraDeviceUser::AUDIO_RESTRICTION_NONE:
        case hardware::camera2::ICameraDeviceUser::AUDIO_RESTRICTION_VIBRATION:
        case hardware::camera2::ICameraDeviceUser::AUDIO_RESTRICTION_VIBRATION_SOUND:
            return true;
        default:
            return false;
    }
}

status_t CameraService::BasicClient::handleAppOpMode(int32_t mode) {
    if (mode == AppOpsManager::MODE_ERRORED) {
        ALOGI("Camera %s: Access for \"%s\" has been revoked",
                mCameraIdStr.string(), String8(mClientPackageName).string());
        return PERMISSION_DENIED;
    } else if (!mUidIsTrusted && mode == AppOpsManager::MODE_IGNORED) {
        // If the calling Uid is trusted (a native service), the AppOpsManager could
        // return MODE_IGNORED. Do not treat such case as error.
        bool isUidActive = sCameraService->mUidPolicy->isUidActive(mClientUid,
                mClientPackageName);
        bool isCameraPrivacyEnabled =
                sCameraService->mSensorPrivacyPolicy->isCameraPrivacyEnabled();
        if (!isUidActive || !isCameraPrivacyEnabled) {
            ALOGI("Camera %s: Access for \"%s\" has been restricted",
                    mCameraIdStr.string(), String8(mClientPackageName).string());
            // Return the same error as for device policy manager rejection
            return -EACCES;
        }
    }
    return OK;
}

status_t CameraService::BasicClient::startCameraOps() {
    ATRACE_CALL();

    {
        ALOGV("%s: Start camera ops, package name = %s, client UID = %d",
              __FUNCTION__, String8(mClientPackageName).string(), mClientUid);
    }
    if (mAppOpsManager != nullptr) {
        // Notify app ops that the camera is not available
        mOpsCallback = new OpsCallback(this);
        mAppOpsManager->startWatchingMode(AppOpsManager::OP_CAMERA,
                mClientPackageName, mOpsCallback);

        // Just check for camera acccess here on open - delay startOp until
        // camera frames start streaming in startCameraStreamingOps
        int32_t mode = mAppOpsManager->checkOp(AppOpsManager::OP_CAMERA, mClientUid,
                mClientPackageName);
        status_t res = handleAppOpMode(mode);
        if (res != OK) {
            return res;
        }
    }

    mOpsActive = true;

    // Transition device availability listeners from PRESENT -> NOT_AVAILABLE
    sCameraService->updateStatus(StatusInternal::NOT_AVAILABLE, mCameraIdStr);

    sCameraService->mUidPolicy->registerMonitorUid(mClientUid);

    // Notify listeners of camera open/close status
    sCameraService->updateOpenCloseStatus(mCameraIdStr, true/*open*/, mClientPackageName);

    return OK;
}

status_t CameraService::BasicClient::startCameraStreamingOps() {
    ATRACE_CALL();

    if (!mOpsActive) {
        ALOGE("%s: Calling streaming start when not yet active", __FUNCTION__);
        return INVALID_OPERATION;
    }
    if (mOpsStreaming) {
        ALOGV("%s: Streaming already active!", __FUNCTION__);
        return OK;
    }

    ALOGV("%s: Start camera streaming ops, package name = %s, client UID = %d",
            __FUNCTION__, String8(mClientPackageName).string(), mClientUid);

    if (mAppOpsManager != nullptr) {
        int32_t mode = mAppOpsManager->startOpNoThrow(AppOpsManager::OP_CAMERA, mClientUid,
                mClientPackageName, /*startIfModeDefault*/ false, mClientFeatureId,
                String16("start camera ") + String16(mCameraIdStr));
        status_t res = handleAppOpMode(mode);
        if (res != OK) {
            return res;
        }
    }

    mOpsStreaming = true;

    return OK;
}

status_t CameraService::BasicClient::noteAppOp() {
    ATRACE_CALL();

    ALOGV("%s: Start camera noteAppOp, package name = %s, client UID = %d",
            __FUNCTION__, String8(mClientPackageName).string(), mClientUid);

    // noteAppOp is only used for when camera mute is not supported, in order
    // to trigger the sensor privacy "Unblock" dialog
    if (mAppOpsManager != nullptr) {
        int32_t mode = mAppOpsManager->noteOp(AppOpsManager::OP_CAMERA, mClientUid,
                mClientPackageName, mClientFeatureId,
                String16("start camera ") + String16(mCameraIdStr));
        status_t res = handleAppOpMode(mode);
        if (res != OK) {
            return res;
        }
    }

    return OK;
}

status_t CameraService::BasicClient::finishCameraStreamingOps() {
    ATRACE_CALL();

    if (!mOpsActive) {
        ALOGE("%s: Calling streaming start when not yet active", __FUNCTION__);
        return INVALID_OPERATION;
    }
    if (!mOpsStreaming) {
        ALOGV("%s: Streaming not active!", __FUNCTION__);
        return OK;
    }

    if (mAppOpsManager != nullptr) {
        mAppOpsManager->finishOp(AppOpsManager::OP_CAMERA, mClientUid,
                mClientPackageName, mClientFeatureId);
        mOpsStreaming = false;
    }

    return OK;
}

status_t CameraService::BasicClient::finishCameraOps() {
    ATRACE_CALL();

    if (mOpsStreaming) {
        // Make sure we've notified everyone about camera stopping
        finishCameraStreamingOps();
    }

    // Check if startCameraOps succeeded, and if so, finish the camera op
    if (mOpsActive) {
        mOpsActive = false;

        // This function is called when a client disconnects. This should
        // release the camera, but actually only if it was in a proper
        // functional state, i.e. with status NOT_AVAILABLE
        std::initializer_list<StatusInternal> rejected = {StatusInternal::PRESENT,
                StatusInternal::ENUMERATING, StatusInternal::NOT_PRESENT};

        // Transition to PRESENT if the camera is not in either of the rejected states
        sCameraService->updateStatus(StatusInternal::PRESENT,
                mCameraIdStr, rejected);
    }
    // Always stop watching, even if no camera op is active
    if (mOpsCallback != nullptr && mAppOpsManager != nullptr) {
        mAppOpsManager->stopWatchingMode(mOpsCallback);
    }
    mOpsCallback.clear();

    sCameraService->mUidPolicy->unregisterMonitorUid(mClientUid);

    // Notify listeners of camera open/close status
    sCameraService->updateOpenCloseStatus(mCameraIdStr, false/*open*/, mClientPackageName);

    return OK;
}

void CameraService::BasicClient::opChanged(int32_t op, const String16&) {
    ATRACE_CALL();
    if (mAppOpsManager == nullptr) {
        return;
    }
    // TODO : add offline camera session case
    if (op != AppOpsManager::OP_CAMERA) {
        ALOGW("Unexpected app ops notification received: %d", op);
        return;
    }

    int32_t res;
    res = mAppOpsManager->checkOp(AppOpsManager::OP_CAMERA,
            mClientUid, mClientPackageName);
    ALOGV("checkOp returns: %d, %s ", res,
            res == AppOpsManager::MODE_ALLOWED ? "ALLOWED" :
            res == AppOpsManager::MODE_IGNORED ? "IGNORED" :
            res == AppOpsManager::MODE_ERRORED ? "ERRORED" :
            "UNKNOWN");

    if (res == AppOpsManager::MODE_ERRORED) {
        ALOGI("Camera %s: Access for \"%s\" revoked", mCameraIdStr.string(),
              String8(mClientPackageName).string());
        block();
    } else if (res == AppOpsManager::MODE_IGNORED) {
        bool isUidActive = sCameraService->mUidPolicy->isUidActive(mClientUid, mClientPackageName);
        bool isCameraPrivacyEnabled =
                sCameraService->mSensorPrivacyPolicy->isCameraPrivacyEnabled();
        ALOGI("Camera %s: Access for \"%s\" has been restricted, isUidTrusted %d, isUidActive %d",
                mCameraIdStr.string(), String8(mClientPackageName).string(),
                mUidIsTrusted, isUidActive);
        // If the calling Uid is trusted (a native service), or the client Uid is active (WAR for
        // b/175320666), the AppOpsManager could return MODE_IGNORED. Do not treat such cases as
        // error.
        if (!mUidIsTrusted) {
            if (isUidActive && isCameraPrivacyEnabled && supportsCameraMute()) {
                setCameraMute(true);
            } else if (!isUidActive
                || (isCameraPrivacyEnabled && !supportsCameraMute())) {
                block();
            }
        }
    } else if (res == AppOpsManager::MODE_ALLOWED) {
        setCameraMute(sCameraService->mOverrideCameraMuteMode);
    }
}

void CameraService::BasicClient::block() {
    ATRACE_CALL();

    // Reset the client PID to allow server-initiated disconnect,
    // and to prevent further calls by client.
    mClientPid = CameraThreadState::getCallingPid();
    CaptureResultExtras resultExtras; // a dummy result (invalid)
    notifyError(hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_DISABLED, resultExtras);
    disconnect();
}

// ----------------------------------------------------------------------------

void CameraService::Client::notifyError(int32_t errorCode,
        const CaptureResultExtras& resultExtras) {
    (void) resultExtras;
    if (mRemoteCallback != NULL) {
        int32_t api1ErrorCode = CAMERA_ERROR_RELEASED;
        if (errorCode == hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_DISABLED) {
            api1ErrorCode = CAMERA_ERROR_DISABLED;
        }
        mRemoteCallback->notifyCallback(CAMERA_MSG_ERROR, api1ErrorCode, 0);
    } else {
        ALOGE("mRemoteCallback is NULL!!");
    }
}

// NOTE: function is idempotent
binder::Status CameraService::Client::disconnect() {
    ALOGV("Client::disconnect");
    return BasicClient::disconnect();
}

bool CameraService::Client::canCastToApiClient(apiLevel level) const {
    return level == API_1;
}

CameraService::Client::OpsCallback::OpsCallback(wp<BasicClient> client):
        mClient(client) {
}

void CameraService::Client::OpsCallback::opChanged(int32_t op,
        const String16& packageName) {
    sp<BasicClient> client = mClient.promote();
    if (client != NULL) {
        client->opChanged(op, packageName);
    }
}

// ----------------------------------------------------------------------------
//                  UidPolicy
// ----------------------------------------------------------------------------

void CameraService::UidPolicy::registerSelf() {
    Mutex::Autolock _l(mUidLock);

    if (mRegistered) return;
    status_t res = mAm.linkToDeath(this);
    mAm.registerUidObserver(this, ActivityManager::UID_OBSERVER_GONE
            | ActivityManager::UID_OBSERVER_IDLE
            | ActivityManager::UID_OBSERVER_ACTIVE | ActivityManager::UID_OBSERVER_PROCSTATE
            | ActivityManager::UID_OBSERVER_PROC_OOM_ADJ,
            ActivityManager::PROCESS_STATE_UNKNOWN,
            String16("cameraserver"));
    if (res == OK) {
        mRegistered = true;
        ALOGV("UidPolicy: Registered with ActivityManager");
    }
}

void CameraService::UidPolicy::unregisterSelf() {
    Mutex::Autolock _l(mUidLock);

    mAm.unregisterUidObserver(this);
    mAm.unlinkToDeath(this);
    mRegistered = false;
    mActiveUids.clear();
    ALOGV("UidPolicy: Unregistered with ActivityManager");
}

void CameraService::UidPolicy::onUidGone(uid_t uid, bool disabled) {
    onUidIdle(uid, disabled);
}

void CameraService::UidPolicy::onUidActive(uid_t uid) {
    Mutex::Autolock _l(mUidLock);
    mActiveUids.insert(uid);
}

void CameraService::UidPolicy::onUidIdle(uid_t uid, bool /* disabled */) {
    bool deleted = false;
    {
        Mutex::Autolock _l(mUidLock);
        if (mActiveUids.erase(uid) > 0) {
            deleted = true;
        }
    }
    if (deleted) {
        sp<CameraService> service = mService.promote();
        if (service != nullptr) {
            service->blockClientsForUid(uid);
        }
    }
}

void CameraService::UidPolicy::onUidStateChanged(uid_t uid, int32_t procState,
        int64_t procStateSeq __unused, int32_t capability __unused) {
    bool procStateChange = false;
    {
        Mutex::Autolock _l(mUidLock);
        if (mMonitoredUids.find(uid) != mMonitoredUids.end() &&
                mMonitoredUids[uid].procState != procState) {
            mMonitoredUids[uid].procState = procState;
            procStateChange = true;
        }
    }

    if (procStateChange) {
        sp<CameraService> service = mService.promote();
        if (service != nullptr) {
            service->notifyMonitoredUids();
        }
    }
}

void CameraService::UidPolicy::onUidProcAdjChanged(uid_t uid) {
    bool procAdjChange = false;
    {
        Mutex::Autolock _l(mUidLock);
        if (mMonitoredUids.find(uid) != mMonitoredUids.end()) {
            procAdjChange = true;
        }
    }

    if (procAdjChange) {
        sp<CameraService> service = mService.promote();
        if (service != nullptr) {
            service->notifyMonitoredUids();
        }
    }
}

void CameraService::UidPolicy::registerMonitorUid(uid_t uid) {
    Mutex::Autolock _l(mUidLock);
    auto it = mMonitoredUids.find(uid);
    if (it != mMonitoredUids.end()) {
        it->second.refCount++;
    } else {
        MonitoredUid monitoredUid;
        monitoredUid.procState = ActivityManager::PROCESS_STATE_NONEXISTENT;
        monitoredUid.refCount = 1;
        mMonitoredUids.emplace(std::pair<uid_t, MonitoredUid>(uid, monitoredUid));
    }
}

void CameraService::UidPolicy::unregisterMonitorUid(uid_t uid) {
    Mutex::Autolock _l(mUidLock);
    auto it = mMonitoredUids.find(uid);
    if (it != mMonitoredUids.end()) {
        it->second.refCount--;
        if (it->second.refCount == 0) {
            mMonitoredUids.erase(it);
        }
    } else {
        ALOGE("%s: Trying to unregister uid: %d which is not monitored!", __FUNCTION__, uid);
    }
}

bool CameraService::UidPolicy::isUidActive(uid_t uid, String16 callingPackage) {
    Mutex::Autolock _l(mUidLock);
    return isUidActiveLocked(uid, callingPackage);
}

static const int64_t kPollUidActiveTimeoutTotalMillis = 300;
static const int64_t kPollUidActiveTimeoutMillis = 50;

bool CameraService::UidPolicy::isUidActiveLocked(uid_t uid, String16 callingPackage) {
    // Non-app UIDs are considered always active
    // If activity manager is unreachable, assume everything is active
    if (uid < FIRST_APPLICATION_UID || !mRegistered) {
        return true;
    }
    auto it = mOverrideUids.find(uid);
    if (it != mOverrideUids.end()) {
        return it->second;
    }
    bool active = mActiveUids.find(uid) != mActiveUids.end();
    if (!active) {
        // We want active UIDs to always access camera with their first attempt since
        // there is no guarantee the app is robustly written and would retry getting
        // the camera on failure. The inverse case is not a problem as we would take
        // camera away soon once we get the callback that the uid is no longer active.
        ActivityManager am;
        // Okay to access with a lock held as UID changes are dispatched without
        // a lock and we are a higher level component.
        int64_t startTimeMillis = 0;
        do {
            // TODO: Fix this b/109950150!
            // Okay this is a hack. There is a race between the UID turning active and
            // activity being resumed. The proper fix is very risky, so we temporary add
            // some polling which should happen pretty rarely anyway as the race is hard
            // to hit.
            active = mActiveUids.find(uid) != mActiveUids.end();
            if (!active) active = am.isUidActive(uid, callingPackage);
            if (active) {
                break;
            }
            if (startTimeMillis <= 0) {
                startTimeMillis = uptimeMillis();
            }
            int64_t ellapsedTimeMillis = uptimeMillis() - startTimeMillis;
            int64_t remainingTimeMillis = kPollUidActiveTimeoutTotalMillis - ellapsedTimeMillis;
            if (remainingTimeMillis <= 0) {
                break;
            }
            remainingTimeMillis = std::min(kPollUidActiveTimeoutMillis, remainingTimeMillis);

            mUidLock.unlock();
            usleep(remainingTimeMillis * 1000);
            mUidLock.lock();
        } while (true);

        if (active) {
            // Now that we found out the UID is actually active, cache that
            mActiveUids.insert(uid);
        }
    }
    return active;
}

int32_t CameraService::UidPolicy::getProcState(uid_t uid) {
    Mutex::Autolock _l(mUidLock);
    return getProcStateLocked(uid);
}

int32_t CameraService::UidPolicy::getProcStateLocked(uid_t uid) {
    int32_t procState = ActivityManager::PROCESS_STATE_UNKNOWN;
    if (mMonitoredUids.find(uid) != mMonitoredUids.end()) {
        procState = mMonitoredUids[uid].procState;
    }
    return procState;
}

void CameraService::UidPolicy::UidPolicy::addOverrideUid(uid_t uid,
        String16 callingPackage, bool active) {
    updateOverrideUid(uid, callingPackage, active, true);
}

void CameraService::UidPolicy::removeOverrideUid(uid_t uid, String16 callingPackage) {
    updateOverrideUid(uid, callingPackage, false, false);
}

void CameraService::UidPolicy::binderDied(const wp<IBinder>& /*who*/) {
    Mutex::Autolock _l(mUidLock);
    ALOGV("UidPolicy: ActivityManager has died");
    mRegistered = false;
    mActiveUids.clear();
}

void CameraService::UidPolicy::updateOverrideUid(uid_t uid, String16 callingPackage,
        bool active, bool insert) {
    bool wasActive = false;
    bool isActive = false;
    {
        Mutex::Autolock _l(mUidLock);
        wasActive = isUidActiveLocked(uid, callingPackage);
        mOverrideUids.erase(uid);
        if (insert) {
            mOverrideUids.insert(std::pair<uid_t, bool>(uid, active));
        }
        isActive = isUidActiveLocked(uid, callingPackage);
    }
    if (wasActive != isActive && !isActive) {
        sp<CameraService> service = mService.promote();
        if (service != nullptr) {
            service->blockClientsForUid(uid);
        }
    }
}

// ----------------------------------------------------------------------------
//                  SensorPrivacyPolicy
// ----------------------------------------------------------------------------
void CameraService::SensorPrivacyPolicy::registerSelf() {
    Mutex::Autolock _l(mSensorPrivacyLock);
    if (mRegistered) {
        return;
    }
    hasCameraPrivacyFeature(); // Called so the result is cached
    mSpm.addSensorPrivacyListener(this);
    mSensorPrivacyEnabled = mSpm.isSensorPrivacyEnabled();
    status_t res = mSpm.linkToDeath(this);
    if (res == OK) {
        mRegistered = true;
        ALOGV("SensorPrivacyPolicy: Registered with SensorPrivacyManager");
    }
}

void CameraService::SensorPrivacyPolicy::unregisterSelf() {
    Mutex::Autolock _l(mSensorPrivacyLock);
    mSpm.removeSensorPrivacyListener(this);
    mSpm.unlinkToDeath(this);
    mRegistered = false;
    ALOGV("SensorPrivacyPolicy: Unregistered with SensorPrivacyManager");
}

bool CameraService::SensorPrivacyPolicy::isSensorPrivacyEnabled() {
    Mutex::Autolock _l(mSensorPrivacyLock);
    return mSensorPrivacyEnabled;
}

bool CameraService::SensorPrivacyPolicy::isCameraPrivacyEnabled() {
    if (!hasCameraPrivacyFeature()) {
        return false;
    }
    return mSpm.isToggleSensorPrivacyEnabled(SensorPrivacyManager::TOGGLE_SENSOR_CAMERA);
}

binder::Status CameraService::SensorPrivacyPolicy::onSensorPrivacyChanged(
    int toggleType __unused, int sensor __unused, bool enabled) {
    {
        Mutex::Autolock _l(mSensorPrivacyLock);
        mSensorPrivacyEnabled = enabled;
    }
    // if sensor privacy is enabled then block all clients from accessing the camera
    if (enabled) {
        sp<CameraService> service = mService.promote();
        if (service != nullptr) {
            service->blockAllClients();
        }
    }
    return binder::Status::ok();
}

void CameraService::SensorPrivacyPolicy::binderDied(const wp<IBinder>& /*who*/) {
    Mutex::Autolock _l(mSensorPrivacyLock);
    ALOGV("SensorPrivacyPolicy: SensorPrivacyManager has died");
    mRegistered = false;
}

bool CameraService::SensorPrivacyPolicy::hasCameraPrivacyFeature() {
    bool supportsSoftwareToggle = mSpm.supportsSensorToggle(
            SensorPrivacyManager::TOGGLE_TYPE_SOFTWARE, SensorPrivacyManager::TOGGLE_SENSOR_CAMERA);
    bool supportsHardwareToggle = mSpm.supportsSensorToggle(
            SensorPrivacyManager::TOGGLE_TYPE_HARDWARE, SensorPrivacyManager::TOGGLE_SENSOR_CAMERA);
    return supportsSoftwareToggle || supportsHardwareToggle;
}

// ----------------------------------------------------------------------------
//                  CameraState
// ----------------------------------------------------------------------------

CameraService::CameraState::CameraState(const String8& id, int cost,
        const std::set<String8>& conflicting, SystemCameraKind systemCameraKind,
        const std::vector<std::string>& physicalCameras) : mId(id),
        mStatus(StatusInternal::NOT_PRESENT), mCost(cost), mConflicting(conflicting),
        mSystemCameraKind(systemCameraKind), mPhysicalCameras(physicalCameras) {}

CameraService::CameraState::~CameraState() {}

CameraService::StatusInternal CameraService::CameraState::getStatus() const {
    Mutex::Autolock lock(mStatusLock);
    return mStatus;
}

std::vector<String8> CameraService::CameraState::getUnavailablePhysicalIds() const {
    Mutex::Autolock lock(mStatusLock);
    std::vector<String8> res(mUnavailablePhysicalIds.begin(), mUnavailablePhysicalIds.end());
    return res;
}

CameraParameters CameraService::CameraState::getShimParams() const {
    return mShimParams;
}

void CameraService::CameraState::setShimParams(const CameraParameters& params) {
    mShimParams = params;
}

int CameraService::CameraState::getCost() const {
    return mCost;
}

std::set<String8> CameraService::CameraState::getConflicting() const {
    return mConflicting;
}

String8 CameraService::CameraState::getId() const {
    return mId;
}

SystemCameraKind CameraService::CameraState::getSystemCameraKind() const {
    return mSystemCameraKind;
}

bool CameraService::CameraState::containsPhysicalCamera(const std::string& physicalCameraId) const {
    return std::find(mPhysicalCameras.begin(), mPhysicalCameras.end(), physicalCameraId)
            != mPhysicalCameras.end();
}

bool CameraService::CameraState::addUnavailablePhysicalId(const String8& physicalId) {
    Mutex::Autolock lock(mStatusLock);
    auto result = mUnavailablePhysicalIds.insert(physicalId);
    return result.second;
}

bool CameraService::CameraState::removeUnavailablePhysicalId(const String8& physicalId) {
    Mutex::Autolock lock(mStatusLock);
    auto count = mUnavailablePhysicalIds.erase(physicalId);
    return count > 0;
}

void CameraService::CameraState::setClientPackage(const String8& clientPackage) {
    Mutex::Autolock lock(mStatusLock);
    mClientPackage = clientPackage;
}

String8 CameraService::CameraState::getClientPackage() const {
    Mutex::Autolock lock(mStatusLock);
    return mClientPackage;
}

// ----------------------------------------------------------------------------
//                  ClientEventListener
// ----------------------------------------------------------------------------

void CameraService::ClientEventListener::onClientAdded(
        const resource_policy::ClientDescriptor<String8,
        sp<CameraService::BasicClient>>& descriptor) {
    const auto& basicClient = descriptor.getValue();
    if (basicClient.get() != nullptr) {
        BatteryNotifier& notifier(BatteryNotifier::getInstance());
        notifier.noteStartCamera(descriptor.getKey(),
                static_cast<int>(basicClient->getClientUid()));
    }
}

void CameraService::ClientEventListener::onClientRemoved(
        const resource_policy::ClientDescriptor<String8,
        sp<CameraService::BasicClient>>& descriptor) {
    const auto& basicClient = descriptor.getValue();
    if (basicClient.get() != nullptr) {
        BatteryNotifier& notifier(BatteryNotifier::getInstance());
        notifier.noteStopCamera(descriptor.getKey(),
                static_cast<int>(basicClient->getClientUid()));
    }
}


// ----------------------------------------------------------------------------
//                  CameraClientManager
// ----------------------------------------------------------------------------

CameraService::CameraClientManager::CameraClientManager() {
    setListener(std::make_shared<ClientEventListener>());
}

CameraService::CameraClientManager::~CameraClientManager() {}

sp<CameraService::BasicClient> CameraService::CameraClientManager::getCameraClient(
        const String8& id) const {
    auto descriptor = get(id);
    if (descriptor == nullptr) {
        return sp<BasicClient>{nullptr};
    }
    return descriptor->getValue();
}

String8 CameraService::CameraClientManager::toString() const {
    auto all = getAll();
    String8 ret("[");
    bool hasAny = false;
    for (auto& i : all) {
        hasAny = true;
        String8 key = i->getKey();
        int32_t cost = i->getCost();
        int32_t pid = i->getOwnerId();
        int32_t score = i->getPriority().getScore();
        int32_t state = i->getPriority().getState();
        auto conflicting = i->getConflicting();
        auto clientSp = i->getValue();
        String8 packageName;
        userid_t clientUserId = 0;
        if (clientSp.get() != nullptr) {
            packageName = String8{clientSp->getPackageName()};
            uid_t clientUid = clientSp->getClientUid();
            clientUserId = multiuser_get_user_id(clientUid);
        }
        ret.appendFormat("\n(Camera ID: %s, Cost: %" PRId32 ", PID: %" PRId32 ", Score: %"
                PRId32 ", State: %" PRId32, key.string(), cost, pid, score, state);

        if (clientSp.get() != nullptr) {
            ret.appendFormat("User Id: %d, ", clientUserId);
        }
        if (packageName.size() != 0) {
            ret.appendFormat("Client Package Name: %s", packageName.string());
        }

        ret.append(", Conflicting Client Devices: {");
        for (auto& j : conflicting) {
            ret.appendFormat("%s, ", j.string());
        }
        ret.append("})");
    }
    if (hasAny) ret.append("\n");
    ret.append("]\n");
    return ret;
}

CameraService::DescriptorPtr CameraService::CameraClientManager::makeClientDescriptor(
        const String8& key, const sp<BasicClient>& value, int32_t cost,
        const std::set<String8>& conflictingKeys, int32_t score, int32_t ownerId,
        int32_t state, int32_t oomScoreOffset, bool systemNativeClient) {

    int32_t score_adj = systemNativeClient ? kSystemNativeClientScore : score;
    int32_t state_adj = systemNativeClient ? kSystemNativeClientState: state;

    return std::make_shared<resource_policy::ClientDescriptor<String8, sp<BasicClient>>>(
            key, value, cost, conflictingKeys, score_adj, ownerId, state_adj,
            systemNativeClient, oomScoreOffset);
}

CameraService::DescriptorPtr CameraService::CameraClientManager::makeClientDescriptor(
        const sp<BasicClient>& value, const CameraService::DescriptorPtr& partial,
        int32_t oomScoreOffset, bool systemNativeClient) {
    return makeClientDescriptor(partial->getKey(), value, partial->getCost(),
            partial->getConflicting(), partial->getPriority().getScore(),
            partial->getOwnerId(), partial->getPriority().getState(), oomScoreOffset,
            systemNativeClient);
}

// ----------------------------------------------------------------------------
//                  InjectionStatusListener
// ----------------------------------------------------------------------------

void CameraService::InjectionStatusListener::addListener(
        const sp<ICameraInjectionCallback>& callback) {
    Mutex::Autolock lock(mListenerLock);
    if (mCameraInjectionCallback) return;
    status_t res = IInterface::asBinder(callback)->linkToDeath(this);
    if (res == OK) {
        mCameraInjectionCallback = callback;
    }
}

void CameraService::InjectionStatusListener::removeListener() {
    Mutex::Autolock lock(mListenerLock);
    if (mCameraInjectionCallback == nullptr) {
        ALOGW("InjectionStatusListener: mCameraInjectionCallback == nullptr");
        return;
    }
    IInterface::asBinder(mCameraInjectionCallback)->unlinkToDeath(this);
    mCameraInjectionCallback = nullptr;
}

void CameraService::InjectionStatusListener::notifyInjectionError(
        String8 injectedCamId, status_t err) {
    if (mCameraInjectionCallback == nullptr) {
        ALOGW("InjectionStatusListener: mCameraInjectionCallback == nullptr");
        return;
    }

    switch (err) {
        case -ENODEV:
            mCameraInjectionCallback->onInjectionError(
                    ICameraInjectionCallback::ERROR_INJECTION_SESSION);
            ALOGE("No camera device with ID \"%s\" currently available!",
                    injectedCamId.string());
            break;
        case -EBUSY:
            mCameraInjectionCallback->onInjectionError(
                    ICameraInjectionCallback::ERROR_INJECTION_SESSION);
            ALOGE("Higher-priority client using camera, ID \"%s\" currently unavailable!",
                    injectedCamId.string());
            break;
        case DEAD_OBJECT:
            mCameraInjectionCallback->onInjectionError(
                    ICameraInjectionCallback::ERROR_INJECTION_SESSION);
            ALOGE("Camera ID \"%s\" object is dead!",
                    injectedCamId.string());
            break;
        case INVALID_OPERATION:
            mCameraInjectionCallback->onInjectionError(
                    ICameraInjectionCallback::ERROR_INJECTION_SESSION);
            ALOGE("Camera ID \"%s\" encountered an operating or internal error!",
                    injectedCamId.string());
            break;
        case UNKNOWN_TRANSACTION:
            mCameraInjectionCallback->onInjectionError(
                    ICameraInjectionCallback::ERROR_INJECTION_UNSUPPORTED);
            ALOGE("Camera ID \"%s\" method doesn't support!",
                    injectedCamId.string());
            break;
        default:
            mCameraInjectionCallback->onInjectionError(
                    ICameraInjectionCallback::ERROR_INJECTION_INVALID_ERROR);
            ALOGE("Unexpected error %s (%d) opening camera \"%s\"!",
                    strerror(-err), err, injectedCamId.string());
    }
}

void CameraService::InjectionStatusListener::binderDied(
        const wp<IBinder>& /*who*/) {
    ALOGV("InjectionStatusListener: ICameraInjectionCallback has died");
    auto parent = mParent.promote();
    if (parent != nullptr) {
        auto clientDescriptor = parent->mActiveClientManager.get(parent->mInjectionInternalCamId);
        if (clientDescriptor != nullptr) {
            BasicClient* baseClientPtr = clientDescriptor->getValue().get();
            baseClientPtr->stopInjection();
        }
        parent->clearInjectionParameters();
    }
}

// ----------------------------------------------------------------------------
//                  CameraInjectionSession
// ----------------------------------------------------------------------------

binder::Status CameraService::CameraInjectionSession::stopInjection() {
    Mutex::Autolock lock(mInjectionSessionLock);
    auto parent = mParent.promote();
    if (parent == nullptr) {
        ALOGE("CameraInjectionSession: Parent is gone");
        return STATUS_ERROR(ICameraInjectionCallback::ERROR_INJECTION_SERVICE,
                "Camera service encountered error");
    }

    status_t res = NO_ERROR;
    auto clientDescriptor = parent->mActiveClientManager.get(parent->mInjectionInternalCamId);
    if (clientDescriptor != nullptr) {
        BasicClient* baseClientPtr = clientDescriptor->getValue().get();
        res = baseClientPtr->stopInjection();
        if (res != OK) {
            ALOGE("CameraInjectionSession: Failed to stop the injection camera!"
                " ret != NO_ERROR: %d", res);
            return STATUS_ERROR(ICameraInjectionCallback::ERROR_INJECTION_SESSION,
                "Camera session encountered error");
        }
    }
    parent->clearInjectionParameters();
    return binder::Status::ok();
}

// ----------------------------------------------------------------------------

static const int kDumpLockRetries = 50;
static const int kDumpLockSleep = 60000;

static bool tryLock(Mutex& mutex)
{
    bool locked = false;
    for (int i = 0; i < kDumpLockRetries; ++i) {
        if (mutex.tryLock() == NO_ERROR) {
            locked = true;
            break;
        }
        usleep(kDumpLockSleep);
    }
    return locked;
}

void CameraService::cacheDump() {
    if (mMemFd != -1) {
        const Vector<String16> args;
        ATRACE_CALL();
        // Acquiring service lock here will avoid the deadlock since
        // cacheDump will not be called during the second disconnect.
        Mutex::Autolock lock(mServiceLock);

        Mutex::Autolock l(mCameraStatesLock);
        // Start collecting the info for open sessions and store it in temp file.
        for (const auto& state : mCameraStates) {
            String8 cameraId = state.first;
            auto clientDescriptor = mActiveClientManager.get(cameraId);
            if (clientDescriptor != nullptr) {
                dprintf(mMemFd, "== Camera device %s dynamic info: ==\n", cameraId.string());
                // Log the current open session info before device is disconnected.
                dumpOpenSessionClientLogs(mMemFd, args, cameraId);
            }
        }
    }
}

status_t CameraService::dump(int fd, const Vector<String16>& args) {
    ATRACE_CALL();

    if (checkCallingPermission(sDumpPermission) == false) {
        dprintf(fd, "Permission Denial: can't dump CameraService from pid=%d, uid=%d\n",
                CameraThreadState::getCallingPid(),
                CameraThreadState::getCallingUid());
        return NO_ERROR;
    }
    bool locked = tryLock(mServiceLock);
    // failed to lock - CameraService is probably deadlocked
    if (!locked) {
        dprintf(fd, "!! CameraService may be deadlocked !!\n");
    }

    if (!mInitialized) {
        dprintf(fd, "!! No camera HAL available !!\n");

        // Dump event log for error information
        dumpEventLog(fd);

        if (locked) mServiceLock.unlock();
        return NO_ERROR;
    }
    dprintf(fd, "\n== Service global info: ==\n\n");
    dprintf(fd, "Number of camera devices: %d\n", mNumberOfCameras);
    dprintf(fd, "Number of normal camera devices: %zu\n", mNormalDeviceIds.size());
    dprintf(fd, "Number of public camera devices visible to API1: %zu\n",
            mNormalDeviceIdsWithoutSystemCamera.size());
    for (size_t i = 0; i < mNormalDeviceIds.size(); i++) {
        dprintf(fd, "    Device %zu maps to \"%s\"\n", i, mNormalDeviceIds[i].c_str());
    }
    String8 activeClientString = mActiveClientManager.toString();
    dprintf(fd, "Active Camera Clients:\n%s", activeClientString.string());
    dprintf(fd, "Allowed user IDs: %s\n", toString(mAllowedUsers).string());
    if (mStreamUseCaseOverrides.size() > 0) {
        dprintf(fd, "Active stream use case overrides:");
        for (int64_t useCaseOverride : mStreamUseCaseOverrides) {
            dprintf(fd, " %" PRId64, useCaseOverride);
        }
        dprintf(fd, "\n");
    }

    dumpEventLog(fd);

    bool stateLocked = tryLock(mCameraStatesLock);
    if (!stateLocked) {
        dprintf(fd, "CameraStates in use, may be deadlocked\n");
    }

    int argSize = args.size();
    for (int i = 0; i < argSize; i++) {
        if (args[i] == TagMonitor::kMonitorOption) {
            if (i + 1 < argSize) {
                mMonitorTags = String8(args[i + 1]);
            }
            break;
        }
    }

    for (auto& state : mCameraStates) {
        String8 cameraId = state.first;

        dprintf(fd, "== Camera device %s dynamic info: ==\n", cameraId.string());

        CameraParameters p = state.second->getShimParams();
        if (!p.isEmpty()) {
            dprintf(fd, "  Camera1 API shim is using parameters:\n        ");
            p.dump(fd, args);
        }

        auto clientDescriptor = mActiveClientManager.get(cameraId);
        if (clientDescriptor != nullptr) {
            // log the current open session info
            dumpOpenSessionClientLogs(fd, args, cameraId);
        } else {
            dumpClosedSessionClientLogs(fd, cameraId);
        }

    }

    if (stateLocked) mCameraStatesLock.unlock();

    if (locked) mServiceLock.unlock();

    mCameraProviderManager->dump(fd, args);

    dprintf(fd, "\n== Vendor tags: ==\n\n");

    sp<VendorTagDescriptor> desc = VendorTagDescriptor::getGlobalVendorTagDescriptor();
    if (desc == NULL) {
        sp<VendorTagDescriptorCache> cache =
                VendorTagDescriptorCache::getGlobalVendorTagCache();
        if (cache == NULL) {
            dprintf(fd, "No vendor tags.\n");
        } else {
            cache->dump(fd, /*verbosity*/2, /*indentation*/2);
        }
    } else {
        desc->dump(fd, /*verbosity*/2, /*indentation*/2);
    }

    // Dump camera traces if there were any
    dprintf(fd, "\n");
    camera3::CameraTraces::dump(fd);

    // Process dump arguments, if any
    int n = args.size();
    String16 verboseOption("-v");
    String16 unreachableOption("--unreachable");
    for (int i = 0; i < n; i++) {
        if (args[i] == verboseOption) {
            // change logging level
            if (i + 1 >= n) continue;
            String8 levelStr(args[i+1]);
            int level = atoi(levelStr.string());
            dprintf(fd, "\nSetting log level to %d.\n", level);
            setLogLevel(level);
        } else if (args[i] == unreachableOption) {
            // Dump memory analysis
            // TODO - should limit be an argument parameter?
            UnreachableMemoryInfo info;
            bool success = GetUnreachableMemory(info, /*limit*/ 10000);
            if (!success) {
                dprintf(fd, "\n== Unable to dump unreachable memory. "
                        "Try disabling SELinux enforcement. ==\n");
            } else {
                dprintf(fd, "\n== Dumping unreachable memory: ==\n");
                std::string s = info.ToString(/*log_contents*/ true);
                write(fd, s.c_str(), s.size());
            }
        }
    }

    bool serviceLocked = tryLock(mServiceLock);

    // Dump info from previous open sessions.
    // Reposition the offset to beginning of the file before reading

    if ((mMemFd >= 0) && (lseek(mMemFd, 0, SEEK_SET) != -1)) {
        dprintf(fd, "\n**********Dumpsys from previous open session**********\n");
        ssize_t size_read;
        char buf[4096];
        while ((size_read = read(mMemFd, buf, (sizeof(buf) - 1))) > 0) {
            // Read data from file to a small buffer and write it to fd.
            write(fd, buf, size_read);
            if (size_read == -1) {
                ALOGE("%s: Error during reading the file: %s", __FUNCTION__, sFileName);
                break;
            }
        }
        dprintf(fd, "\n**********End of Dumpsys from previous open session**********\n");
    } else {
        ALOGE("%s: Error during reading the file: %s", __FUNCTION__, sFileName);
    }

    if (serviceLocked) mServiceLock.unlock();
    return NO_ERROR;
}

void CameraService::dumpOpenSessionClientLogs(int fd,
        const Vector<String16>& args, const String8& cameraId) {
    auto clientDescriptor = mActiveClientManager.get(cameraId);
    dprintf(fd, "  %s : Device %s is open. Client instance dump:\n",
            getFormattedCurrentTime().string(),
            cameraId.string());
    dprintf(fd, "    Client priority score: %d state: %d\n",
        clientDescriptor->getPriority().getScore(),
        clientDescriptor->getPriority().getState());
    dprintf(fd, "    Client PID: %d\n", clientDescriptor->getOwnerId());

    auto client = clientDescriptor->getValue();
    dprintf(fd, "    Client package: %s\n",
        String8(client->getPackageName()).string());

    client->dumpClient(fd, args);
}

void CameraService::dumpClosedSessionClientLogs(int fd, const String8& cameraId) {
    dprintf(fd, "  Device %s is closed, no client instance\n",
                    cameraId.string());
}

void CameraService::dumpEventLog(int fd) {
    dprintf(fd, "\n== Camera service events log (most recent at top): ==\n");

    Mutex::Autolock l(mLogLock);
    for (const auto& msg : mEventLog) {
        dprintf(fd, "  %s\n", msg.string());
    }

    if (mEventLog.size() == DEFAULT_EVENT_LOG_LENGTH) {
        dprintf(fd, "  ...\n");
    } else if (mEventLog.size() == 0) {
        dprintf(fd, "  [no events yet]\n");
    }
    dprintf(fd, "\n");
}

void CameraService::cacheClientTagDumpIfNeeded(const char *cameraId, BasicClient* client) {
    Mutex::Autolock lock(mLogLock);
    if (!isClientWatchedLocked(client)) { return; }

    std::vector<std::string> dumpVector;
    client->dumpWatchedEventsToVector(dumpVector);

    if (dumpVector.empty()) { return; }

    std::string dumpString;

    String8 currentTime = getFormattedCurrentTime();
    dumpString += "Cached @ ";
    dumpString += currentTime.string();
    dumpString += "\n"; // First line is the timestamp of when client is cached.


    const String16 &packageName = client->getPackageName();

    String8 packageName8 = String8(packageName);
    const char *printablePackageName = packageName8.lockBuffer(packageName.size());


    size_t i = dumpVector.size();

    // Store the string in reverse order (latest last)
    while (i > 0) {
         i--;
         dumpString += cameraId;
         dumpString += ":";
         dumpString += printablePackageName;
         dumpString += "  ";
         dumpString += dumpVector[i]; // implicitly ends with '\n'
    }

    packageName8.unlockBuffer();
    mWatchedClientsDumpCache[packageName] = dumpString;
}

void CameraService::handleTorchClientBinderDied(const wp<IBinder> &who) {
    Mutex::Autolock al(mTorchClientMapMutex);
    for (size_t i = 0; i < mTorchClientMap.size(); i++) {
        if (mTorchClientMap[i] == who) {
            // turn off the torch mode that was turned on by dead client
            String8 cameraId = mTorchClientMap.keyAt(i);
            status_t res = mFlashlight->setTorchMode(cameraId, false);
            if (res) {
                ALOGE("%s: torch client died but couldn't turn off torch: "
                    "%s (%d)", __FUNCTION__, strerror(-res), res);
                return;
            }
            mTorchClientMap.removeItemsAt(i);
            break;
        }
    }
}

/*virtual*/void CameraService::binderDied(const wp<IBinder> &who) {

    /**
      * While tempting to promote the wp<IBinder> into a sp, it's actually not supported by the
      * binder driver
      */
    // PID here is approximate and can be wrong.
    logClientDied(CameraThreadState::getCallingPid(), String8("Binder died unexpectedly"));

    // check torch client
    handleTorchClientBinderDied(who);

    // check camera device client
    if(!evictClientIdByRemote(who)) {
        ALOGV("%s: Java client's binder death already cleaned up (normal case)", __FUNCTION__);
        return;
    }

    ALOGE("%s: Java client's binder died, removing it from the list of active clients",
            __FUNCTION__);
}

void CameraService::updateStatus(StatusInternal status, const String8& cameraId) {
    updateStatus(status, cameraId, {});
}

void CameraService::updateStatus(StatusInternal status, const String8& cameraId,
        std::initializer_list<StatusInternal> rejectSourceStates) {
    // Do not lock mServiceLock here or can get into a deadlock from
    // connect() -> disconnect -> updateStatus

    auto state = getCameraState(cameraId);

    if (state == nullptr) {
        ALOGW("%s: Could not update the status for %s, no such device exists", __FUNCTION__,
                cameraId.string());
        return;
    }

    // Avoid calling getSystemCameraKind() with mStatusListenerLock held (b/141756275)
    SystemCameraKind deviceKind = SystemCameraKind::PUBLIC;
    if (getSystemCameraKind(cameraId, &deviceKind) != OK) {
        ALOGE("%s: Invalid camera id %s, skipping", __FUNCTION__, cameraId.string());
        return;
    }

    // Collect the logical cameras without holding mStatusLock in updateStatus
    // as that can lead to a deadlock(b/162192331).
    auto logicalCameraIds = getLogicalCameras(cameraId);
    // Update the status for this camera state, then send the onStatusChangedCallbacks to each
    // of the listeners with both the mStatusLock and mStatusListenerLock held
    state->updateStatus(status, cameraId, rejectSourceStates, [this, &deviceKind,
                        &logicalCameraIds]
            (const String8& cameraId, StatusInternal status) {

            if (status != StatusInternal::ENUMERATING) {
                // Update torch status if it has a flash unit.
                Mutex::Autolock al(mTorchStatusMutex);
                TorchModeStatus torchStatus;
                if (getTorchStatusLocked(cameraId, &torchStatus) !=
                        NAME_NOT_FOUND) {
                    TorchModeStatus newTorchStatus =
                            status == StatusInternal::PRESENT ?
                            TorchModeStatus::AVAILABLE_OFF :
                            TorchModeStatus::NOT_AVAILABLE;
                    if (torchStatus != newTorchStatus) {
                        onTorchStatusChangedLocked(cameraId, newTorchStatus, deviceKind);
                    }
                }
            }

            Mutex::Autolock lock(mStatusListenerLock);
            notifyPhysicalCameraStatusLocked(mapToInterface(status), String16(cameraId),
                    logicalCameraIds, deviceKind);

            for (auto& listener : mListenerList) {
                bool isVendorListener = listener->isVendorListener();
                if (shouldSkipStatusUpdates(deviceKind, isVendorListener,
                        listener->getListenerPid(), listener->getListenerUid()) ||
                        isVendorListener) {
                    ALOGV("Skipping discovery callback for system-only camera device %s",
                            cameraId.c_str());
                    continue;
                }
                listener->getListener()->onStatusChanged(mapToInterface(status),
                        String16(cameraId));
            }
        });
}

void CameraService::updateOpenCloseStatus(const String8& cameraId, bool open,
        const String16& clientPackageName) {
    auto state = getCameraState(cameraId);
    if (state == nullptr) {
        ALOGW("%s: Could not update the status for %s, no such device exists", __FUNCTION__,
                cameraId.string());
        return;
    }
    if (open) {
        state->setClientPackage(String8(clientPackageName));
    } else {
        state->setClientPackage(String8::empty());
    }

    Mutex::Autolock lock(mStatusListenerLock);

    for (const auto& it : mListenerList) {
        if (!it->isOpenCloseCallbackAllowed()) {
            continue;
        }

        binder::Status ret;
        String16 cameraId64(cameraId);
        if (open) {
            ret = it->getListener()->onCameraOpened(cameraId64, clientPackageName);
        } else {
            ret = it->getListener()->onCameraClosed(cameraId64);
        }
        if (!ret.isOk()) {
            ALOGE("%s: Failed to trigger onCameraOpened/onCameraClosed callback: %d", __FUNCTION__,
                    ret.exceptionCode());
        }
    }
}

template<class Func>
void CameraService::CameraState::updateStatus(StatusInternal status,
        const String8& cameraId,
        std::initializer_list<StatusInternal> rejectSourceStates,
        Func onStatusUpdatedLocked) {
    Mutex::Autolock lock(mStatusLock);
    StatusInternal oldStatus = mStatus;
    mStatus = status;

    if (oldStatus == status) {
        return;
    }

    ALOGV("%s: Status has changed for camera ID %s from %#x to %#x", __FUNCTION__,
            cameraId.string(), oldStatus, status);

    if (oldStatus == StatusInternal::NOT_PRESENT &&
            (status != StatusInternal::PRESENT &&
             status != StatusInternal::ENUMERATING)) {

        ALOGW("%s: From NOT_PRESENT can only transition into PRESENT or ENUMERATING",
                __FUNCTION__);
        mStatus = oldStatus;
        return;
    }

    /**
     * Sometimes we want to conditionally do a transition.
     * For example if a client disconnects, we want to go to PRESENT
     * only if we weren't already in NOT_PRESENT or ENUMERATING.
     */
    for (auto& rejectStatus : rejectSourceStates) {
        if (oldStatus == rejectStatus) {
            ALOGV("%s: Rejecting status transition for Camera ID %s,  since the source "
                    "state was was in one of the bad states.", __FUNCTION__, cameraId.string());
            mStatus = oldStatus;
            return;
        }
    }

    onStatusUpdatedLocked(cameraId, status);
}

status_t CameraService::getTorchStatusLocked(
        const String8& cameraId,
        TorchModeStatus *status) const {
    if (!status) {
        return BAD_VALUE;
    }
    ssize_t index = mTorchStatusMap.indexOfKey(cameraId);
    if (index == NAME_NOT_FOUND) {
        // invalid camera ID or the camera doesn't have a flash unit
        return NAME_NOT_FOUND;
    }

    *status = mTorchStatusMap.valueAt(index);
    return OK;
}

status_t CameraService::setTorchStatusLocked(const String8& cameraId,
        TorchModeStatus status) {
    ssize_t index = mTorchStatusMap.indexOfKey(cameraId);
    if (index == NAME_NOT_FOUND) {
        return BAD_VALUE;
    }
    mTorchStatusMap.editValueAt(index) = status;

    return OK;
}

std::list<String16> CameraService::getLogicalCameras(
        const String8& physicalCameraId) {
    std::list<String16> retList;
    Mutex::Autolock lock(mCameraStatesLock);
    for (const auto& state : mCameraStates) {
        if (state.second->containsPhysicalCamera(physicalCameraId.c_str())) {
            retList.emplace_back(String16(state.first));
        }
    }
    return retList;
}

void CameraService::notifyPhysicalCameraStatusLocked(int32_t status,
        const String16& physicalCameraId, const std::list<String16>& logicalCameraIds,
        SystemCameraKind deviceKind) {
    // mStatusListenerLock is expected to be locked
    for (const auto& logicalCameraId : logicalCameraIds) {
        for (auto& listener : mListenerList) {
            // Note: we check only the deviceKind of the physical camera id
            // since, logical camera ids and their physical camera ids are
            // guaranteed to have the same system camera kind.
            if (shouldSkipStatusUpdates(deviceKind, listener->isVendorListener(),
                    listener->getListenerPid(), listener->getListenerUid())) {
                ALOGV("Skipping discovery callback for system-only camera device %s",
                        String8(physicalCameraId).c_str());
                continue;
            }
            listener->getListener()->onPhysicalCameraStatusChanged(status,
                    logicalCameraId, physicalCameraId);
        }
    }
}


void CameraService::blockClientsForUid(uid_t uid) {
    const auto clients = mActiveClientManager.getAll();
    for (auto& current : clients) {
        if (current != nullptr) {
            const auto basicClient = current->getValue();
            if (basicClient.get() != nullptr && basicClient->getClientUid() == uid) {
                basicClient->block();
            }
        }
    }
}

void CameraService::blockAllClients() {
    const auto clients = mActiveClientManager.getAll();
    for (auto& current : clients) {
        if (current != nullptr) {
            const auto basicClient = current->getValue();
            if (basicClient.get() != nullptr) {
                basicClient->block();
            }
        }
    }
}

// NOTE: This is a remote API - make sure all args are validated
status_t CameraService::shellCommand(int in, int out, int err, const Vector<String16>& args) {
    if (!checkCallingPermission(sManageCameraPermission, nullptr, nullptr)) {
        return PERMISSION_DENIED;
    }
    if (in == BAD_TYPE || out == BAD_TYPE || err == BAD_TYPE) {
        return BAD_VALUE;
    }
    if (args.size() >= 3 && args[0] == String16("set-uid-state")) {
        return handleSetUidState(args, err);
    } else if (args.size() >= 2 && args[0] == String16("reset-uid-state")) {
        return handleResetUidState(args, err);
    } else if (args.size() >= 2 && args[0] == String16("get-uid-state")) {
        return handleGetUidState(args, out, err);
    } else if (args.size() >= 2 && args[0] == String16("set-rotate-and-crop")) {
        return handleSetRotateAndCrop(args);
    } else if (args.size() >= 1 && args[0] == String16("get-rotate-and-crop")) {
        return handleGetRotateAndCrop(out);
    } else if (args.size() >= 2 && args[0] == String16("set-image-dump-mask")) {
        return handleSetImageDumpMask(args);
    } else if (args.size() >= 1 && args[0] == String16("get-image-dump-mask")) {
        return handleGetImageDumpMask(out);
    } else if (args.size() >= 2 && args[0] == String16("set-camera-mute")) {
        return handleSetCameraMute(args);
    } else if (args.size() >= 2 && args[0] == String16("set-stream-use-case-override")) {
        return handleSetStreamUseCaseOverrides(args);
    } else if (args.size() >= 1 && args[0] == String16("clear-stream-use-case-override")) {
        return handleClearStreamUseCaseOverrides();
    } else if (args.size() >= 2 && args[0] == String16("watch")) {
        return handleWatchCommand(args, in, out);
    } else if (args.size() >= 2 && args[0] == String16("set-watchdog")) {
        return handleSetCameraServiceWatchdog(args);
    } else if (args.size() == 1 && args[0] == String16("help")) {
        printHelp(out);
        return OK;
    }
    printHelp(err);
    return BAD_VALUE;
}

status_t CameraService::handleSetUidState(const Vector<String16>& args, int err) {
    String16 packageName = args[1];

    bool active = false;
    if (args[2] == String16("active")) {
        active = true;
    } else if ((args[2] != String16("idle"))) {
        ALOGE("Expected active or idle but got: '%s'", String8(args[2]).string());
        return BAD_VALUE;
    }

    int userId = 0;
    if (args.size() >= 5 && args[3] == String16("--user")) {
        userId = atoi(String8(args[4]));
    }

    uid_t uid;
    if (getUidForPackage(packageName, userId, uid, err) == BAD_VALUE) {
        return BAD_VALUE;
    }

    mUidPolicy->addOverrideUid(uid, packageName, active);
    return NO_ERROR;
}

status_t CameraService::handleResetUidState(const Vector<String16>& args, int err) {
    String16 packageName = args[1];

    int userId = 0;
    if (args.size() >= 4 && args[2] == String16("--user")) {
        userId = atoi(String8(args[3]));
    }

    uid_t uid;
    if (getUidForPackage(packageName, userId, uid, err) == BAD_VALUE) {
        return BAD_VALUE;
    }

    mUidPolicy->removeOverrideUid(uid, packageName);
    return NO_ERROR;
}

status_t CameraService::handleGetUidState(const Vector<String16>& args, int out, int err) {
    String16 packageName = args[1];

    int userId = 0;
    if (args.size() >= 4 && args[2] == String16("--user")) {
        userId = atoi(String8(args[3]));
    }

    uid_t uid;
    if (getUidForPackage(packageName, userId, uid, err) == BAD_VALUE) {
        return BAD_VALUE;
    }

    if (mUidPolicy->isUidActive(uid, packageName)) {
        return dprintf(out, "active\n");
    } else {
        return dprintf(out, "idle\n");
    }
}

status_t CameraService::handleSetRotateAndCrop(const Vector<String16>& args) {
    int rotateValue = atoi(String8(args[1]));
    if (rotateValue < ANDROID_SCALER_ROTATE_AND_CROP_NONE ||
            rotateValue > ANDROID_SCALER_ROTATE_AND_CROP_AUTO) return BAD_VALUE;
    Mutex::Autolock lock(mServiceLock);

    mOverrideRotateAndCropMode = rotateValue;

    if (rotateValue == ANDROID_SCALER_ROTATE_AND_CROP_AUTO) return OK;

    const auto clients = mActiveClientManager.getAll();
    for (auto& current : clients) {
        if (current != nullptr) {
            const auto basicClient = current->getValue();
            if (basicClient.get() != nullptr) {
                basicClient->setRotateAndCropOverride(rotateValue);
            }
        }
    }

    return OK;
}

status_t CameraService::handleSetCameraServiceWatchdog(const Vector<String16>& args) {
    int enableWatchdog = atoi(String8(args[1]));

    if (enableWatchdog < 0 || enableWatchdog > 1) return BAD_VALUE;

    Mutex::Autolock lock(mServiceLock);

    mCameraServiceWatchdogEnabled = enableWatchdog;

    const auto clients = mActiveClientManager.getAll();
    for (auto& current : clients) {
        if (current != nullptr) {
            const auto basicClient = current->getValue();
            if (basicClient.get() != nullptr) {
                basicClient->setCameraServiceWatchdog(enableWatchdog);
            }
        }
    }

    return OK;
}

status_t CameraService::handleGetRotateAndCrop(int out) {
    Mutex::Autolock lock(mServiceLock);

    return dprintf(out, "rotateAndCrop override: %d\n", mOverrideRotateAndCropMode);
}

status_t CameraService::handleSetImageDumpMask(const Vector<String16>& args) {
    char *endPtr;
    errno = 0;
    String8 maskString8 = String8(args[1]);
    long maskValue = strtol(maskString8.c_str(), &endPtr, 10);

    if (errno != 0) return BAD_VALUE;
    if (endPtr != maskString8.c_str() + maskString8.size()) return BAD_VALUE;
    if (maskValue < 0 || maskValue > 1) return BAD_VALUE;

    Mutex::Autolock lock(mServiceLock);

    mImageDumpMask = maskValue;

    return OK;
}

status_t CameraService::handleGetImageDumpMask(int out) {
    Mutex::Autolock lock(mServiceLock);

    return dprintf(out, "Image dump mask: %d\n", mImageDumpMask);
}

status_t CameraService::handleSetCameraMute(const Vector<String16>& args) {
    int muteValue = strtol(String8(args[1]), nullptr, 10);
    if (errno != 0) return BAD_VALUE;

    if (muteValue < 0 || muteValue > 1) return BAD_VALUE;
    Mutex::Autolock lock(mServiceLock);

    mOverrideCameraMuteMode = (muteValue == 1);

    const auto clients = mActiveClientManager.getAll();
    for (auto& current : clients) {
        if (current != nullptr) {
            const auto basicClient = current->getValue();
            if (basicClient.get() != nullptr) {
                if (basicClient->supportsCameraMute()) {
                    basicClient->setCameraMute(mOverrideCameraMuteMode);
                }
            }
        }
    }

    return OK;
}

status_t CameraService::handleSetStreamUseCaseOverrides(const Vector<String16>& args) {
    std::vector<int64_t> useCasesOverride;
    for (size_t i = 1; i < args.size(); i++) {
        int64_t useCase = ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT;
        String8 arg8 = String8(args[i]);
        if (arg8 == "DEFAULT") {
            useCase = ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_DEFAULT;
        } else if (arg8 == "PREVIEW") {
            useCase = ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_PREVIEW;
        } else if (arg8 == "STILL_CAPTURE") {
            useCase = ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_STILL_CAPTURE;
        } else if (arg8 == "VIDEO_RECORD") {
            useCase = ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VIDEO_RECORD;
        } else if (arg8 == "PREVIEW_VIDEO_STILL") {
            useCase = ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_PREVIEW_VIDEO_STILL;
        } else if (arg8 == "VIDEO_CALL") {
            useCase = ANDROID_SCALER_AVAILABLE_STREAM_USE_CASES_VIDEO_CALL;
        } else {
            ALOGE("%s: Invalid stream use case %s", __FUNCTION__, String8(args[i]).c_str());
            return BAD_VALUE;
        }
        useCasesOverride.push_back(useCase);
    }

    Mutex::Autolock lock(mServiceLock);
    mStreamUseCaseOverrides = std::move(useCasesOverride);

    return OK;
}

status_t CameraService::handleClearStreamUseCaseOverrides() {
    Mutex::Autolock lock(mServiceLock);
    mStreamUseCaseOverrides.clear();

    return OK;
}

status_t CameraService::handleWatchCommand(const Vector<String16>& args, int inFd, int outFd) {
    if (args.size() >= 3 && args[1] == String16("start")) {
        return startWatchingTags(args, outFd);
    } else if (args.size() == 2 && args[1] == String16("stop")) {
        return stopWatchingTags(outFd);
    } else if (args.size() == 2 && args[1] == String16("dump")) {
        return printWatchedTags(outFd);
    } else if (args.size() >= 2 && args[1] == String16("live")) {
        return printWatchedTagsUntilInterrupt(args, inFd, outFd);
    } else if (args.size() == 2 && args[1] == String16("clear")) {
        return clearCachedMonitoredTagDumps(outFd);
    }
    dprintf(outFd, "Camera service watch commands:\n"
                 "  start -m <comma_separated_tag_list> [-c <comma_separated_client_list>]\n"
                 "        starts watching the provided tags for clients with provided package\n"
                 "        recognizes tag shorthands like '3a'\n"
                 "        watches all clients if no client is passed, or if 'all' is listed\n"
                 "  dump dumps the monitoring information and exits\n"
                 "  stop stops watching all tags\n"
                 "  live [-n <refresh_interval_ms>]\n"
                 "        prints the monitored information in real time\n"
                 "        Hit return to exit\n"
                 "  clear clears all buffers storing information for watch command");
  return BAD_VALUE;
}

status_t CameraService::startWatchingTags(const Vector<String16> &args, int outFd) {
    Mutex::Autolock lock(mLogLock);
    size_t tagsIdx; // index of '-m'
    String16 tags("");
    for (tagsIdx = 2; tagsIdx < args.size() && args[tagsIdx] != String16("-m"); tagsIdx++);
    if (tagsIdx < args.size() - 1) {
        tags = args[tagsIdx + 1];
    } else {
        dprintf(outFd, "No tags provided.\n");
        return BAD_VALUE;
    }

    size_t clientsIdx; // index of '-c'
    String16 clients = kWatchAllClientsFlag; // watch all clients if no clients are provided
    for (clientsIdx = 2; clientsIdx < args.size() && args[clientsIdx] != String16("-c");
         clientsIdx++);
    if (clientsIdx < args.size() - 1) {
        clients = args[clientsIdx + 1];
    }
    parseClientsToWatchLocked(String8(clients));

    // track tags to initialize future clients with the monitoring information
    mMonitorTags = String8(tags);

    bool serviceLock = tryLock(mServiceLock);
    int numWatchedClients = 0;
    auto cameraClients = mActiveClientManager.getAll();
    for (const auto &clientDescriptor: cameraClients) {
        if (clientDescriptor == nullptr) { continue; }
        sp<BasicClient> client = clientDescriptor->getValue();
        if (client.get() == nullptr) { continue; }

        if (isClientWatchedLocked(client.get())) {
            client->startWatchingTags(mMonitorTags, outFd);
            numWatchedClients++;
        }
    }
    dprintf(outFd, "Started watching %d active clients\n", numWatchedClients);

    if (serviceLock) { mServiceLock.unlock(); }
    return OK;
}

status_t CameraService::stopWatchingTags(int outFd) {
    // clear mMonitorTags to prevent new clients from monitoring tags at initialization
    Mutex::Autolock lock(mLogLock);
    mMonitorTags = String8::empty();

    mWatchedClientPackages.clear();
    mWatchedClientsDumpCache.clear();

    bool serviceLock = tryLock(mServiceLock);
    auto cameraClients = mActiveClientManager.getAll();
    for (const auto &clientDescriptor : cameraClients) {
        if (clientDescriptor == nullptr) { continue; }
        sp<BasicClient> client = clientDescriptor->getValue();
        if (client.get() == nullptr) { continue; }
        client->stopWatchingTags(outFd);
    }
    dprintf(outFd, "Stopped watching all clients.\n");
    if (serviceLock) { mServiceLock.unlock(); }
    return OK;
}

status_t CameraService::clearCachedMonitoredTagDumps(int outFd) {
    Mutex::Autolock lock(mLogLock);
    size_t clearedSize = mWatchedClientsDumpCache.size();
    mWatchedClientsDumpCache.clear();
    dprintf(outFd, "Cleared tag information of %zu cached clients.\n", clearedSize);
    return OK;
}

status_t CameraService::printWatchedTags(int outFd) {
    Mutex::Autolock logLock(mLogLock);
    std::set<String16> connectedMonitoredClients;

    bool printedSomething = false; // tracks if any monitoring information was printed
                                   // (from either cached or active clients)

    bool serviceLock = tryLock(mServiceLock);
    // get all watched clients that are currently connected
    for (const auto &clientDescriptor: mActiveClientManager.getAll()) {
        if (clientDescriptor == nullptr) { continue; }

        sp<BasicClient> client = clientDescriptor->getValue();
        if (client.get() == nullptr) { continue; }
        if (!isClientWatchedLocked(client.get())) { continue; }

        std::vector<std::string> dumpVector;
        client->dumpWatchedEventsToVector(dumpVector);

        size_t printIdx = dumpVector.size();
        if (printIdx == 0) {
            continue;
        }

        // Print tag dumps for active client
        const String8 &cameraId = clientDescriptor->getKey();
        String8 packageName8 = String8(client->getPackageName());
        const char *printablePackageName = packageName8.lockBuffer(packageName8.size());
        dprintf(outFd, "Client: %s (active)\n", printablePackageName);
        while(printIdx > 0) {
            printIdx--;
            dprintf(outFd, "%s:%s  %s", cameraId.string(), printablePackageName,
                    dumpVector[printIdx].c_str());
        }
        dprintf(outFd, "\n");
        packageName8.unlockBuffer();
        printedSomething = true;

        connectedMonitoredClients.emplace(client->getPackageName());
    }
    if (serviceLock) { mServiceLock.unlock(); }

    // Print entries in mWatchedClientsDumpCache for clients that are not connected
    for (const auto &kv: mWatchedClientsDumpCache) {
        const String16 &package = kv.first;
        if (connectedMonitoredClients.find(package) != connectedMonitoredClients.end()) {
            continue;
        }

        dprintf(outFd, "Client: %s (cached)\n", String8(package).string());
        dprintf(outFd, "%s\n", kv.second.c_str());
        printedSomething = true;
    }

    if (!printedSomething) {
        dprintf(outFd, "No monitoring information to print.\n");
    }

    return OK;
}

// Print all events in vector `events' that came after lastPrintedEvent
void printNewWatchedEvents(int outFd,
                           const char *cameraId,
                           const String16 &packageName,
                           const std::vector<std::string> &events,
                           const std::string &lastPrintedEvent) {
    if (events.empty()) { return; }

    // index of lastPrintedEvent in events.
    // lastPrintedIdx = events.size() if lastPrintedEvent is not in events
    size_t lastPrintedIdx;
    for (lastPrintedIdx = 0;
         lastPrintedIdx < events.size() && lastPrintedEvent != events[lastPrintedIdx];
         lastPrintedIdx++);

    if (lastPrintedIdx == 0) { return; } // early exit if no new event in `events`

    String8 packageName8(packageName);
    const char *printablePackageName = packageName8.lockBuffer(packageName8.size());

    // print events in chronological order (latest event last)
    size_t idxToPrint = lastPrintedIdx;
    do {
        idxToPrint--;
        dprintf(outFd, "%s:%s  %s", cameraId, printablePackageName, events[idxToPrint].c_str());
    } while (idxToPrint != 0);

    packageName8.unlockBuffer();
}

// Returns true if adb shell cmd watch should be interrupted based on data in inFd. The watch
// command should be interrupted if the user presses the return key, or if user loses any way to
// signal interrupt.
// If timeoutMs == 0, this function will always return false
bool shouldInterruptWatchCommand(int inFd, int outFd, long timeoutMs) {
    struct timeval startTime;
    int startTimeError = gettimeofday(&startTime, nullptr);
    if (startTimeError) {
        dprintf(outFd, "Failed waiting for interrupt, aborting.\n");
        return true;
    }

    const nfds_t numFds = 1;
    struct pollfd pollFd = { .fd = inFd, .events = POLLIN, .revents = 0 };

    struct timeval currTime;
    char buffer[2];
    while(true) {
        int currTimeError = gettimeofday(&currTime, nullptr);
        if (currTimeError) {
            dprintf(outFd, "Failed waiting for interrupt, aborting.\n");
            return true;
        }

        long elapsedTimeMs = ((currTime.tv_sec - startTime.tv_sec) * 1000L)
                + ((currTime.tv_usec - startTime.tv_usec) / 1000L);
        int remainingTimeMs = (int) (timeoutMs - elapsedTimeMs);

        if (remainingTimeMs <= 0) {
            // No user interrupt within timeoutMs, don't interrupt watch command
            return false;
        }

        int numFdsUpdated = poll(&pollFd, numFds, remainingTimeMs);
        if (numFdsUpdated < 0) {
            dprintf(outFd, "Failed while waiting for user input. Exiting.\n");
            return true;
        }

        if (numFdsUpdated == 0) {
            // No user input within timeoutMs, don't interrupt watch command
            return false;
        }

        if (!(pollFd.revents & POLLIN)) {
            dprintf(outFd, "Failed while waiting for user input. Exiting.\n");
            return true;
        }

        ssize_t sizeRead = read(inFd, buffer, sizeof(buffer) - 1);
        if (sizeRead < 0) {
            dprintf(outFd, "Error reading user input. Exiting.\n");
            return true;
        }

        if (sizeRead == 0) {
            // Reached end of input fd (can happen if input is piped)
            // User has no way to signal an interrupt, so interrupt here
            return true;
        }

        if (buffer[0] == '\n') {
            // User pressed return, interrupt watch command.
            return true;
        }
    }
}

status_t CameraService::printWatchedTagsUntilInterrupt(const Vector<String16> &args,
                                                       int inFd, int outFd) {
    // Figure out refresh interval, if present in args
    long refreshTimeoutMs = 1000L; // refresh every 1s by default
    if (args.size() > 2) {
        size_t intervalIdx; // index of '-n'
        for (intervalIdx = 2; intervalIdx < args.size() && String16("-n") != args[intervalIdx];
             intervalIdx++);

        size_t intervalValIdx = intervalIdx + 1;
        if (intervalValIdx < args.size()) {
            refreshTimeoutMs = strtol(String8(args[intervalValIdx].string()), nullptr, 10);
            if (errno) { return BAD_VALUE; }
        }
    }

    // Set min timeout of 10ms. This prevents edge cases in polling when timeout of 0 is passed.
    refreshTimeoutMs = refreshTimeoutMs < 10 ? 10 : refreshTimeoutMs;

    dprintf(outFd, "Press return to exit...\n\n");
    std::map<String16, std::string> packageNameToLastEvent;

    while (true) {
        bool serviceLock = tryLock(mServiceLock);
        auto cameraClients = mActiveClientManager.getAll();
        if (serviceLock) { mServiceLock.unlock(); }

        for (const auto& clientDescriptor : cameraClients) {
            Mutex::Autolock lock(mLogLock);
            if (clientDescriptor == nullptr) { continue; }

            sp<BasicClient> client = clientDescriptor->getValue();
            if (client.get() == nullptr) { continue; }
            if (!isClientWatchedLocked(client.get())) { continue; }

            const String16 &packageName = client->getPackageName();
            // This also initializes the map entries with an empty string
            const std::string& lastPrintedEvent = packageNameToLastEvent[packageName];

            std::vector<std::string> latestEvents;
            client->dumpWatchedEventsToVector(latestEvents);

            if (!latestEvents.empty()) {
                String8 cameraId = clientDescriptor->getKey();
                const char *printableCameraId = cameraId.lockBuffer(cameraId.size());
                printNewWatchedEvents(outFd,
                                      printableCameraId,
                                      packageName,
                                      latestEvents,
                                      lastPrintedEvent);
                packageNameToLastEvent[packageName] = latestEvents[0];
                cameraId.unlockBuffer();
            }
        }
        if (shouldInterruptWatchCommand(inFd, outFd, refreshTimeoutMs)) {
            break;
        }
    }
    return OK;
}

void CameraService::parseClientsToWatchLocked(String8 clients) {
    mWatchedClientPackages.clear();

    const char *allSentinel = String8(kWatchAllClientsFlag).string();

    char *tokenized = clients.lockBuffer(clients.size());
    char *savePtr;
    char *nextClient = strtok_r(tokenized, ",", &savePtr);

    while (nextClient != nullptr) {
        if (strcmp(nextClient, allSentinel) == 0) {
            // Don't need to track any other package if 'all' is present
            mWatchedClientPackages.clear();
            mWatchedClientPackages.emplace(kWatchAllClientsFlag);
            break;
        }

        // track package names
        mWatchedClientPackages.emplace(nextClient);
        nextClient = strtok_r(nullptr, ",", &savePtr);
    }
    clients.unlockBuffer();
}

status_t CameraService::printHelp(int out) {
    return dprintf(out, "Camera service commands:\n"
        "  get-uid-state <PACKAGE> [--user USER_ID] gets the uid state\n"
        "  set-uid-state <PACKAGE> <active|idle> [--user USER_ID] overrides the uid state\n"
        "  reset-uid-state <PACKAGE> [--user USER_ID] clears the uid state override\n"
        "  set-rotate-and-crop <ROTATION> overrides the rotate-and-crop value for AUTO backcompat\n"
        "      Valid values 0=0 deg, 1=90 deg, 2=180 deg, 3=270 deg, 4=No override\n"
        "  get-rotate-and-crop returns the current override rotate-and-crop value\n"
        "  set-image-dump-mask <MASK> specifies the formats to be saved to disk\n"
        "      Valid values 0=OFF, 1=ON for JPEG\n"
        "  get-image-dump-mask returns the current image-dump-mask value\n"
        "  set-camera-mute <0/1> enable or disable camera muting\n"
        "  set-stream-use-case-override <usecase1> <usecase2> ... override stream use cases\n"
        "      Use cases applied in descending resolutions. So usecase1 is assigned to the\n"
        "      largest resolution, usecase2 is assigned to the 2nd largest resolution, and so\n"
        "      on. In case the number of usecases is smaller than the number of streams, the\n"
        "      last use case is assigned to all the remaining streams. In case of multiple\n"
        "      streams with the same resolution, the tie-breaker is (JPEG, RAW, YUV, and PRIV)\n"
        "      Valid values are (case sensitive): DEFAULT, PREVIEW, STILL_CAPTURE, VIDEO_RECORD,\n"
        "      PREVIEW_VIDEO_STILL, VIDEO_CALL\n"
        "  clear-stream-use-case-override clear the stream use case override\n"
        "  watch <start|stop|dump|print|clear> manages tag monitoring in connected clients\n"
        "  help print this message\n");
}

bool CameraService::isClientWatched(const BasicClient *client) {
    Mutex::Autolock lock(mLogLock);
    return isClientWatchedLocked(client);
}

bool CameraService::isClientWatchedLocked(const BasicClient *client) {
    return mWatchedClientPackages.find(kWatchAllClientsFlag) != mWatchedClientPackages.end() ||
           mWatchedClientPackages.find(client->getPackageName()) != mWatchedClientPackages.end();
}

int32_t CameraService::updateAudioRestriction() {
    Mutex::Autolock lock(mServiceLock);
    return updateAudioRestrictionLocked();
}

int32_t CameraService::updateAudioRestrictionLocked() {
    int32_t mode = 0;
    // iterate through all active client
    for (const auto& i : mActiveClientManager.getAll()) {
        const auto clientSp = i->getValue();
        mode |= clientSp->getAudioRestriction();
    }

    bool modeChanged = (mAudioRestriction != mode);
    mAudioRestriction = mode;
    if (modeChanged) {
        mAppOps.setCameraAudioRestriction(mode);
    }
    return mode;
}

status_t CameraService::checkIfInjectionCameraIsPresent(const String8& externalCamId,
        sp<BasicClient> clientSp) {
    std::unique_ptr<AutoConditionLock> lock =
            AutoConditionLock::waitAndAcquire(mServiceLockWrapper);
    status_t res = NO_ERROR;
    if ((res = checkIfDeviceIsUsable(externalCamId)) != NO_ERROR) {
        ALOGW("Device %s is not usable!", externalCamId.string());
        mInjectionStatusListener->notifyInjectionError(
                externalCamId, UNKNOWN_TRANSACTION);
        clientSp->notifyError(
                hardware::camera2::ICameraDeviceCallbacks::ERROR_CAMERA_DISCONNECTED,
                CaptureResultExtras());

        // Do not hold mServiceLock while disconnecting clients, but retain the condition blocking
        // other clients from connecting in mServiceLockWrapper if held
        mServiceLock.unlock();

        // Clear caller identity temporarily so client disconnect PID checks work correctly
        int64_t token = CameraThreadState::clearCallingIdentity();
        clientSp->disconnect();
        CameraThreadState::restoreCallingIdentity(token);

        // Reacquire mServiceLock
        mServiceLock.lock();
    }

    return res;
}

void CameraService::clearInjectionParameters() {
    {
        Mutex::Autolock lock(mInjectionParametersLock);
        mInjectionInitPending = false;
        mInjectionInternalCamId = "";
    }
    mInjectionExternalCamId = "";
    mInjectionStatusListener->removeListener();
}

}; // namespace android
