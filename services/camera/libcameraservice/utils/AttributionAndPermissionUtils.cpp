/*
 * Copyright (C) 2024 The Android Open Source Project
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

#define LOG_TAG "AttributionAndPermissionUtils"
#define ATRACE_TAG ATRACE_TAG_CAMERA

#include "AttributionAndPermissionUtils.h"

#include <binder/AppOpsManager.h>
#include <binder/PermissionController.h>
#include <com_android_internal_camera_flags.h>
#include <cutils/properties.h>
#include <private/android_filesystem_config.h>

#include "CameraService.h"

#include <binder/IPCThreadState.h>
#include <binderthreadstate/CallerUtils.h>
#include <hwbinder/IPCThreadState.h>

namespace {

using android::content::AttributionSourceState;

static std::string getAttributionString(const AttributionSourceState& attributionSource) {
    std::ostringstream ret;
    const AttributionSourceState* current = &attributionSource;
    while (current != nullptr) {
        if (current != &attributionSource) {
            ret << ", ";
        }

        ret << "[uid " << current->uid << ", pid " << current->pid;
        ret << ", packageName \"" << current->packageName.value_or("<unknown>");
        ret << "\"]";

        if (!current->next.empty()) {
            current = &current->next[0];
        } else {
            current = nullptr;
        }
    }
    return ret.str();
}

static std::string getAppOpsMessage(const std::string& cameraId) {
    return cameraId.empty() ? std::string() : std::string("start camera ") + cameraId;
}

} // namespace

namespace android {

namespace flags = com::android::internal::camera::flags;

const std::string AttributionAndPermissionUtils::sDumpPermission("android.permission.DUMP");
const std::string AttributionAndPermissionUtils::sManageCameraPermission(
        "android.permission.MANAGE_CAMERA");
const std::string AttributionAndPermissionUtils::sCameraPermission("android.permission.CAMERA");
const std::string AttributionAndPermissionUtils::sSystemCameraPermission(
        "android.permission.SYSTEM_CAMERA");
const std::string AttributionAndPermissionUtils::sCameraHeadlessSystemUserPermission(
        "android.permission.CAMERA_HEADLESS_SYSTEM_USER");
const std::string AttributionAndPermissionUtils::sCameraPrivacyAllowlistPermission(
        "android.permission.CAMERA_PRIVACY_ALLOWLIST");
const std::string AttributionAndPermissionUtils::sCameraSendSystemEventsPermission(
        "android.permission.CAMERA_SEND_SYSTEM_EVENTS");
const std::string AttributionAndPermissionUtils::sCameraOpenCloseListenerPermission(
        "android.permission.CAMERA_OPEN_CLOSE_LISTENER");
const std::string AttributionAndPermissionUtils::sCameraInjectExternalCameraPermission(
        "android.permission.CAMERA_INJECT_EXTERNAL_CAMERA");

int AttributionAndPermissionUtils::getCallingUid() const {
    if (getCurrentServingCall() == BinderCallType::HWBINDER) {
        return hardware::IPCThreadState::self()->getCallingUid();
    }
    return IPCThreadState::self()->getCallingUid();
}

int AttributionAndPermissionUtils::getCallingPid() const {
    if (getCurrentServingCall() == BinderCallType::HWBINDER) {
        return hardware::IPCThreadState::self()->getCallingPid();
    }
    return IPCThreadState::self()->getCallingPid();
}

int64_t AttributionAndPermissionUtils::clearCallingIdentity() {
    if (getCurrentServingCall() == BinderCallType::HWBINDER) {
        return hardware::IPCThreadState::self()->clearCallingIdentity();
    }
    return IPCThreadState::self()->clearCallingIdentity();
}

void AttributionAndPermissionUtils::restoreCallingIdentity(int64_t token) {
    if (getCurrentServingCall() == BinderCallType::HWBINDER) {
        hardware::IPCThreadState::self()->restoreCallingIdentity(token);
    } else {
        IPCThreadState::self()->restoreCallingIdentity(token);
    }
    return;
}

binder::Status AttributionAndPermissionUtils::resolveAttributionSource(
        /*inout*/ AttributionSourceState& resolvedAttributionSource, const std::string& methodName,
        const std::optional<std::string>& cameraIdMaybe) {
    // Check if we can trust clientUid
    if (!resolveClientUid(resolvedAttributionSource.uid)) {
        return errorNotTrusted(resolvedAttributionSource.pid, resolvedAttributionSource.uid,
                               methodName, cameraIdMaybe, *resolvedAttributionSource.packageName,
                               /* isPid= */ false);
    }

    resolveAttributionPackage(resolvedAttributionSource);

    if (!resolveClientPid(resolvedAttributionSource.pid)) {
        return errorNotTrusted(resolvedAttributionSource.pid, resolvedAttributionSource.uid,
                               methodName, cameraIdMaybe, *resolvedAttributionSource.packageName,
                               /* isPid= */ true);
    }

    return binder::Status::ok();
}

PermissionChecker::PermissionResult AttributionAndPermissionUtils::checkPermission(
        const std::string& cameraId, const std::string& permission,
        const AttributionSourceState& attributionSource, const std::string& message,
        int32_t attributedOpCode, bool forDataDelivery, bool startDataDelivery,
        bool checkAutomotive) {
    if (checkAutomotive && checkAutomotivePrivilegedClient(cameraId, attributionSource)) {
        return PermissionChecker::PERMISSION_GRANTED;
    }

    PermissionChecker::PermissionResult result;
    if (forDataDelivery) {
        if (startDataDelivery) {
            result = mPermissionChecker->checkPermissionForStartDataDeliveryFromDatasource(
                    toString16(permission), attributionSource, toString16(message),
                    attributedOpCode);
        } else {
            result = mPermissionChecker->checkPermissionForDataDeliveryFromDatasource(
                    toString16(permission), attributionSource, toString16(message),
                    attributedOpCode);
        }
    } else {
        result = mPermissionChecker->checkPermissionForPreflight(
                toString16(permission), attributionSource, toString16(message), attributedOpCode);
    }

    if (result == PermissionChecker::PERMISSION_HARD_DENIED) {
        ALOGV("%s (forDataDelivery %d startDataDelivery %d): %s permission hard denied "
              "for client attribution %s",
              __FUNCTION__, forDataDelivery, startDataDelivery, permission.c_str(),
              getAttributionString(attributionSource).c_str());
    } else if (result == PermissionChecker::PERMISSION_SOFT_DENIED) {
        ALOGV("%s checkPermission (forDataDelivery %d startDataDelivery %d): %s permission soft "
              "denied "
              "for client attribution %s",
              __FUNCTION__, forDataDelivery, startDataDelivery, permission.c_str(),
              getAttributionString(attributionSource).c_str());
    }
    return result;
}

bool AttributionAndPermissionUtils::checkPermissionForPreflight(
        const std::string& cameraId, const std::string& permission,
        const AttributionSourceState& attributionSource, const std::string& message,
        int32_t attributedOpCode) {
    return checkPermission(cameraId, permission, attributionSource, message, attributedOpCode,
                           /* forDataDelivery */ false, /* startDataDelivery */ false,
                           /* checkAutomotive */ true) != PermissionChecker::PERMISSION_HARD_DENIED;
}

bool AttributionAndPermissionUtils::checkPermissionForDataDelivery(
        const std::string& cameraId, const std::string& permission,
        const AttributionSourceState& attributionSource, const std::string& message,
        int32_t attributedOpCode) {
    return checkPermission(cameraId, permission, attributionSource, message, attributedOpCode,
                           /* forDataDelivery */ true, /* startDataDelivery */ false,
                           /* checkAutomotive */ false) !=
           PermissionChecker::PERMISSION_HARD_DENIED;
}

PermissionChecker::PermissionResult
AttributionAndPermissionUtils::checkPermissionForStartDataDelivery(
        const std::string& cameraId, const std::string& permission,
        const AttributionSourceState& attributionSource, const std::string& message,
        int32_t attributedOpCode) {
    return checkPermission(cameraId, permission, attributionSource, message, attributedOpCode,
                           /* forDataDelivery */ true, /* startDataDelivery */ true,
                           /* checkAutomotive */ false);
}

// Can camera service trust the caller based on the calling UID?
bool AttributionAndPermissionUtils::isTrustedCallingUid(uid_t uid) {
    switch (uid) {
        case AID_MEDIA:        // mediaserver
        case AID_CAMERASERVER: // cameraserver
        case AID_RADIO:        // telephony
            return true;
        default:
            return false;
    }
}

bool AttributionAndPermissionUtils::isAutomotiveDevice() {
    // Checks the property ro.hardware.type and returns true if it is
    // automotive.
    char value[PROPERTY_VALUE_MAX] = {0};
    property_get("ro.hardware.type", value, "");
    return strncmp(value, "automotive", PROPERTY_VALUE_MAX) == 0;
}

bool AttributionAndPermissionUtils::isHeadlessSystemUserMode() {
    // Checks if the device is running in headless system user mode
    // by checking the property ro.fw.mu.headless_system_user.
    char value[PROPERTY_VALUE_MAX] = {0};
    property_get("ro.fw.mu.headless_system_user", value, "");
    return strncmp(value, "true", PROPERTY_VALUE_MAX) == 0;
}

bool AttributionAndPermissionUtils::isAutomotivePrivilegedClient(int32_t uid) {
    // Returns false if this is not an automotive device type.
    if (!isAutomotiveDevice()) return false;

    // Returns true if the uid is AID_AUTOMOTIVE_EVS which is a
    // privileged client uid used for safety critical use cases such as
    // rear view and surround view.
    return uid == AID_AUTOMOTIVE_EVS;
}

std::string AttributionAndPermissionUtils::getPackageNameFromUid(int clientUid) const {
    std::string packageName("");

    sp<IPermissionController> permCtrl = getPermissionController();
    if (permCtrl == nullptr) {
        // Return empty package name and the further interaction
        // with camera will likely fail
        return packageName;
    }

    Vector<String16> packages;

    permCtrl->getPackagesForUid(clientUid, packages);

    if (packages.isEmpty()) {
        ALOGE("No packages for calling UID %d", clientUid);
        // Return empty package name and the further interaction
        // with camera will likely fail
        return packageName;
    }

    // Arbitrarily pick the first name in the list
    packageName = toStdString(packages[0]);

    return packageName;
}

status_t AttributionAndPermissionUtils::getUidForPackage(const std::string& packageName, int userId,
                                                         /*inout*/ uid_t& uid, int err) {
    PermissionController pc;
    uid = pc.getPackageUid(toString16(packageName), 0);
    if (uid <= 0) {
        ALOGE("Unknown package: '%s'", packageName.c_str());
        dprintf(err, "Unknown package: '%s'\n", packageName.c_str());
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

bool AttributionAndPermissionUtils::isCallerCameraServerNotDelegating() {
    return (getCallingPid() == getpid());
}

bool AttributionAndPermissionUtils::hasPermissionsForCamera(
        const std::string& cameraId, const AttributionSourceState& attributionSource,
        bool forDataDelivery, bool checkAutomotive) {
    return checkPermission(cameraId, sCameraPermission, attributionSource,
                           getAppOpsMessage(cameraId), AppOpsManager::OP_NONE, forDataDelivery,
                           /* startDataDelivery */ false, checkAutomotive)
            != PermissionChecker::PERMISSION_HARD_DENIED;
}

PermissionChecker::PermissionResult
AttributionAndPermissionUtils::checkPermissionsForCameraForPreflight(
        const std::string& cameraId, const AttributionSourceState& attributionSource) {
    return checkPermission(cameraId, sCameraPermission, attributionSource,
                           getAppOpsMessage(cameraId), AppOpsManager::OP_NONE,
                           /* forDataDelivery */ false, /* startDataDelivery */ false,
                           /* checkAutomotive */ false);
}

PermissionChecker::PermissionResult
AttributionAndPermissionUtils::checkPermissionsForCameraForDataDelivery(
        const std::string& cameraId, const AttributionSourceState& attributionSource) {
    return checkPermission(cameraId, sCameraPermission, attributionSource,
                           getAppOpsMessage(cameraId), AppOpsManager::OP_NONE,
                           /* forDataDelivery */ true, /* startDataDelivery */ false,
                           /* checkAutomotive */ false);
}

PermissionChecker::PermissionResult
AttributionAndPermissionUtils::checkPermissionsForCameraForStartDataDelivery(
        const std::string& cameraId, const AttributionSourceState& attributionSource) {
    return checkPermission(cameraId, sCameraPermission, attributionSource,
                           getAppOpsMessage(cameraId), AppOpsManager::OP_NONE,
                           /* forDataDelivery */ true, /* startDataDelivery */ true,
                           /* checkAutomotive */ false);
}

bool AttributionAndPermissionUtils::hasPermissionsForSystemCamera(
        const std::string& cameraId, const AttributionSourceState& attributionSource,
        bool checkCameraPermissions) {
    bool systemCameraPermission =
            checkPermissionForPreflight(cameraId, sSystemCameraPermission, attributionSource,
                                        std::string(), AppOpsManager::OP_NONE);
    return systemCameraPermission &&
           (!checkCameraPermissions || hasPermissionsForCamera(cameraId, attributionSource));
}

bool AttributionAndPermissionUtils::hasPermissionsForCameraHeadlessSystemUser(
        const std::string& cameraId, const AttributionSourceState& attributionSource) {
    return checkPermissionForPreflight(cameraId, sCameraHeadlessSystemUserPermission,
                                       attributionSource, std::string(), AppOpsManager::OP_NONE);
}

bool AttributionAndPermissionUtils::hasPermissionsForCameraPrivacyAllowlist(
        const AttributionSourceState& attributionSource) {
    return checkPermissionForPreflight(std::string(), sCameraPrivacyAllowlistPermission,
                                       attributionSource, std::string(), AppOpsManager::OP_NONE);
}

bool AttributionAndPermissionUtils::hasPermissionsForOpenCloseListener(
        const AttributionSourceState& attributionSource) {
    return checkPermissionForPreflight(std::string(), sCameraOpenCloseListenerPermission,
                                       attributionSource, std::string(), AppOpsManager::OP_NONE);
}

void AttributionAndPermissionUtils::finishDataDelivery(
        const AttributionSourceState& attributionSource) {
    mPermissionChecker->finishDataDeliveryFromDatasource(AppOpsManager::OP_CAMERA,
                                                         attributionSource);
}

bool AttributionAndPermissionUtils::checkAutomotivePrivilegedClient(
        const std::string& cameraId, const AttributionSourceState& attributionSource) {
    if (isAutomotivePrivilegedClient(attributionSource.uid)) {
        // If cameraId is empty, then it means that this check is not used for the
        // purpose of accessing a specific camera, hence grant permission just
        // based on uid to the automotive privileged client.
        if (cameraId.empty()) return true;

        auto cameraService = mCameraService.promote();
        if (cameraService == nullptr) {
            ALOGE("%s: CameraService unavailable.", __FUNCTION__);
            return false;
        }

        // If this call is used for accessing a specific camera then cam_id must be provided.
        // In that case, only pre-grants the permission for accessing the exterior system only
        // camera.
        return cameraService->isAutomotiveExteriorSystemCamera(cameraId);
    }

    return false;
}

void AttributionAndPermissionUtils::resolveAttributionPackage(
        AttributionSourceState& resolvedAttributionSource) {
    if (resolvedAttributionSource.packageName.has_value() &&
        resolvedAttributionSource.packageName->size() > 0) {
        return;
    }

    // NDK calls don't come with package names, but we need one for various cases.
    // Generally, there's a 1:1 mapping between UID and package name, but shared UIDs
    // do exist. For all authentication cases, all packages under the same UID get the
    // same permissions, so picking any associated package name is sufficient. For some
    // other cases, this may give inaccurate names for clients in logs.
    resolvedAttributionSource.packageName = getPackageNameFromUid(resolvedAttributionSource.uid);
}

// TODO(362551824): Make USE_CALLING_UID more explicit with a scoped enum.
bool AttributionAndPermissionUtils::resolveClientUid(/*inout*/ int& clientUid) {
    int callingUid = getCallingUid();

    bool validUid = true;
    if (clientUid == hardware::ICameraService::USE_CALLING_UID) {
        clientUid = callingUid;
    } else {
        validUid = isTrustedCallingUid(callingUid) || (clientUid == callingUid);
    }

    return validUid;
}

// TODO(362551824): Make USE_CALLING_UID more explicit with a scoped enum.
bool AttributionAndPermissionUtils::resolveClientPid(/*inout*/ int& clientPid) {
    int callingUid = getCallingUid();
    int callingPid = getCallingPid();

    bool validPid = true;
    if (clientPid == hardware::ICameraService::USE_CALLING_PID) {
        clientPid = callingPid;
    } else {
        validPid = isTrustedCallingUid(callingUid) || (clientPid == callingPid);
    }

    return validPid;
}

binder::Status AttributionAndPermissionUtils::errorNotTrusted(
        int clientPid, int clientUid, const std::string& methodName,
        const std::optional<std::string>& cameraIdMaybe, const std::string& clientName,
        bool isPid) const {
    int callingPid = getCallingPid();
    int callingUid = getCallingUid();
    ALOGE("CameraService::%s X (calling PID %d, calling UID %d) rejected "
          "(don't trust %s %d)",
          methodName.c_str(), callingPid, callingUid, isPid ? "clientPid" : "clientUid",
          isPid ? clientPid : clientUid);
    return STATUS_ERROR_FMT(hardware::ICameraService::ERROR_PERMISSION_DENIED,
                            "Untrusted caller (calling PID %d, UID %d) trying to "
                            "forward camera access to camera %s for client %s (PID %d, UID %d)",
                            getCallingPid(), getCallingUid(), cameraIdMaybe.value_or("N/A").c_str(),
                            clientName.c_str(), clientPid, clientUid);
}

const sp<IPermissionController>& AttributionAndPermissionUtils::getPermissionController() const {
    static const char* kPermissionControllerService = "permission";
    static thread_local sp<IPermissionController> sPermissionController = nullptr;

    if (sPermissionController == nullptr ||
        !IInterface::asBinder(sPermissionController)->isBinderAlive()) {
        sp<IServiceManager> sm = defaultServiceManager();
        sp<IBinder> binder = sm->checkService(toString16(kPermissionControllerService));
        if (binder == nullptr) {
            ALOGE("%s: Could not get permission service", __FUNCTION__);
            sPermissionController = nullptr;
        } else {
            sPermissionController = interface_cast<IPermissionController>(binder);
        }
    }

    return sPermissionController;
}

} // namespace android
