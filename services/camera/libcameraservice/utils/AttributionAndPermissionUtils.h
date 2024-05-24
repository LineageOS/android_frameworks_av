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
#ifndef ANDROID_SERVERS_CAMERA_ATTRIBUTION_AND_PERMISSION_UTILS_H
#define ANDROID_SERVERS_CAMERA_ATTRIBUTION_AND_PERMISSION_UTILS_H

#include <android/content/AttributionSourceState.h>
#include <android/permission/PermissionChecker.h>
#include <binder/BinderService.h>

namespace android {

class CameraService;

using content::AttributionSourceState;
using permission::PermissionChecker;

/**
 * Utility class consolidating methods/data for verifying permissions and the identity of the
 * caller.
 */
class AttributionAndPermissionUtils {
public:
    AttributionAndPermissionUtils(wp<CameraService> cameraService) : mCameraService(cameraService)
            {}
    virtual ~AttributionAndPermissionUtils() {}

    /**
     * Pre-grants the permission if the attribution source uid is for an automotive
     * privileged client. Otherwise uses system service permission checker to check
     * for the appropriate permission. If this function is called for accessing a specific
     * camera,then the cameraID must not be empty. CameraId is used only in case of automotive
     * privileged client so that permission is pre-granted only to access system camera device
     * which is located outside of the vehicle body frame because camera located inside the vehicle
     * cabin would need user permission.
     */
    virtual bool checkPermissionForPreflight(const std::string &cameraId,
            const std::string &permission, const AttributionSourceState& attributionSource,
            const std::string& message, int32_t attributedOpCode);
    virtual bool isTrustedCallingUid(uid_t uid);
    virtual bool isAutomotiveDevice();
    virtual bool isHeadlessSystemUserMode();
    virtual bool isAutomotivePrivilegedClient(int32_t uid);
    virtual status_t getUidForPackage(const std::string &packageName, int userId,
            /*inout*/uid_t& uid, int err);
    virtual bool isCallerCameraServerNotDelegating();

    // Utils for checking specific permissions
    virtual bool hasPermissionsForCamera(const std::string& cameraId,
            const AttributionSourceState& attributionSource);
    virtual bool hasPermissionsForSystemCamera(const std::string& cameraId,
            const AttributionSourceState& attributionSource, bool checkCameraPermissions = true);
    virtual bool hasPermissionsForCameraHeadlessSystemUser(const std::string& cameraId,
            const AttributionSourceState& attributionSource);
    virtual bool hasPermissionsForCameraPrivacyAllowlist(
            const AttributionSourceState& attributionSource);
    virtual bool hasPermissionsForOpenCloseListener(
            const AttributionSourceState& attributionSource);

    static const std::string sDumpPermission;
    static const std::string sManageCameraPermission;
    static const std::string sCameraPermission;
    static const std::string sSystemCameraPermission;
    static const std::string sCameraHeadlessSystemUserPermission;
    static const std::string sCameraPrivacyAllowlistPermission;
    static const std::string sCameraSendSystemEventsPermission;
    static const std::string sCameraOpenCloseListenerPermission;
    static const std::string sCameraInjectExternalCameraPermission;

protected:
    wp<CameraService> mCameraService;

    bool checkAutomotivePrivilegedClient(const std::string &cameraId,
            const AttributionSourceState &attributionSource);
};

} // namespace android

#endif // ANDROID_SERVERS_CAMERA_ATTRIBUTION_AND_PERMISSION_UTILS_H
