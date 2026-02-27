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
#include <binder/IPermissionController.h>
#include <private/android_filesystem_config.h>

namespace android {

class CameraService;

using content::AttributionSourceState;
using permission::PermissionChecker;

class AttrSourceItr {
  public:
    using value_type = AttributionSourceState;
    using pointer = const value_type*;
    using reference = const value_type&;

    AttrSourceItr() : mAttr(nullptr) {}

    AttrSourceItr(const AttributionSourceState& attr) : mAttr(&attr) {}

    reference operator*() const { return *mAttr; }
    pointer operator->() const { return mAttr; }

    AttrSourceItr& operator++() {
        mAttr = !mAttr->next.empty() ? mAttr->next.data() : nullptr;
        return *this;
    }

    AttrSourceItr operator++(int) {
        AttrSourceItr tmp = *this;
        ++(*this);
        return tmp;
    }

    friend bool operator==(const AttrSourceItr& a, const AttrSourceItr& b) = default;

    static AttrSourceItr end() { return AttrSourceItr{}; }
private:
    const AttributionSourceState * mAttr;
};

/**
 * Utility class consolidating methods/data for verifying permissions and the identity of the
 * caller.
 */
class AttributionAndPermissionUtils {
  public:
    AttributionAndPermissionUtils() {}
    virtual ~AttributionAndPermissionUtils() {}

    void setCameraService(wp<CameraService> cameraService) { mCameraService = cameraService; }

    static AttributionSourceState buildAttributionSource(int callingPid, int callingUid) {
        AttributionSourceState attributionSource{};
        attributionSource.pid = callingPid;
        attributionSource.uid = callingUid;
        return attributionSource;
    }

    static AttributionSourceState buildAttributionSource(int callingPid, int callingUid,
                                                         int32_t deviceId) {
        AttributionSourceState attributionSource = buildAttributionSource(callingPid, callingUid);
        attributionSource.deviceId = deviceId;
        return attributionSource;
    }

    // Utilities handling Binder calling identities (previously in CameraThreadState)
    virtual int getCallingUid() const;
    virtual int getCallingPid() const;
    virtual int64_t clearCallingIdentity();
    virtual void restoreCallingIdentity(int64_t token);

    /**
     * Check the calling attribution source and resolve its package name.
     *
     * @param resolvedAttributionSource The resolved attribution source.
     * @param methodName The name of the method calling this function (for logging only).
     * @param cameraIdMaybe The camera ID, if applicable.
     * @return The status of the operation.
     */
    virtual binder::Status resolveAttributionSource(
            /*inout*/ AttributionSourceState& resolvedAttributionSource,
            const std::string& methodName,
            const std::optional<std::string>& cameraIdMaybe = std::nullopt);

    /**
     * Pre-grants the permission if the attribution source uid is for an automotive
     * privileged client. Otherwise uses system service permission checker to check
     * for the appropriate permission. If this function is called for accessing a specific
     * camera,then the cameraID must not be empty. CameraId is used only in case of automotive
     * privileged client so that permission is pre-granted only to access system camera device
     * which is located outside of the vehicle body frame because camera located inside the vehicle
     * cabin would need user permission.
     */
    virtual bool checkPermissionForPreflight(const std::string& cameraId,
                                             const std::string& permission,
                                             const AttributionSourceState& attributionSource,
                                             const std::string& message, int32_t attributedOpCode);
    virtual bool checkPermissionForDataDelivery(const std::string& cameraId,
                                                const std::string& permission,
                                                const AttributionSourceState& attributionSource,
                                                const std::string& message,
                                                int32_t attributedOpCode);
    virtual PermissionChecker::PermissionResult checkPermissionForStartDataDelivery(
            const std::string& cameraId, const std::string& permission,
            const AttributionSourceState& attributionSource, const std::string& message,
            int32_t attributedOpCode);

    // Can camera service trust the caller based on the calling UID?
    virtual bool isTrustedCallingUid(uid_t uid);

    virtual bool isAutomotiveDevice();
    virtual bool isHeadlessSystemUserMode();

    /**
     * Returns true if the client has uid AID_AUTOMOTIVE_EVS and the device is an automotive device.
     */
    virtual bool isAutomotivePrivilegedClient(int32_t uid);

    // In some cases the calling code has no access to the package it runs under.
    // For example, NDK camera API.
    // In this case we will get the packages for the calling UID and pick the first one
    // for attributing the app op. This will work correctly for runtime permissions
    // as for legacy apps we will toggle the app op for all packages in the UID.
    // The caveat is that the operation may be attributed to the wrong package and
    // stats based on app ops may be slightly off.
    virtual std::string getPackageNameFromUid(int clientUid) const;

    virtual status_t getUidForPackage(const std::string& packageName, int userId,
                                      /*inout*/ uid_t& uid, int err);
    virtual bool isCallerCameraServerNotDelegating();

    // Utils for checking specific permissions
    virtual bool hasPermissionsForCamera(const std::string& cameraId,
                                         const AttributionSourceState& attributionSource,
                                         bool forDataDelivery = false, bool checkAutomotive = true);
    virtual PermissionChecker::PermissionResult checkPermissionsForCameraForPreflight(
            const std::string& cameraId, const AttributionSourceState& attributionSource);
    virtual PermissionChecker::PermissionResult checkPermissionsForCameraForDataDelivery(
            const std::string& cameraId, const AttributionSourceState& attributionSource);
    virtual PermissionChecker::PermissionResult checkPermissionsForCameraForStartDataDelivery(
            const std::string& cameraId, const AttributionSourceState& attributionSource);
    virtual bool hasPermissionsForSystemCamera(const std::string& cameraId,
                                               const AttributionSourceState& attributionSource,
                                               bool checkCameraPermissions = true);
    virtual bool hasPermissionsForCameraHeadlessSystemUser(
            const std::string& cameraId, const AttributionSourceState& attributionSource);
    virtual bool hasPermissionsForCameraPrivacyAllowlist(
            const AttributionSourceState& attributionSource);
    virtual bool hasPermissionsForOpenCloseListener(
            const AttributionSourceState& attributionSource);
    virtual bool hasPermissionsForCameraWarmUp(
            const AttributionSourceState& attributionSource);

    virtual void finishDataDelivery(const AttributionSourceState& attributionSource);

    static const std::string sDumpPermission;
    static const std::string sManageCameraPermission;
    static const std::string sCameraPermission;
    static const std::string sSystemCameraPermission;
    static const std::string sCameraHeadlessSystemUserPermission;
    static const std::string sCameraPrivacyAllowlistPermission;
    static const std::string sCameraSendSystemEventsPermission;
    static const std::string sCameraOpenCloseListenerPermission;
    static const std::string sCameraWarmUpPermission;
    static const std::string sCameraInjectExternalCameraPermission;

  protected:
    wp<CameraService> mCameraService;

    bool checkAutomotivePrivilegedClient(const std::string& cameraId,
                                         const AttributionSourceState& attributionSource);

    // If the package name is missing from the AttributionSource and a package name exists for the
    // AttributionSource's uid, fills in the missing package name.
    void resolveAttributionPackage(AttributionSourceState& resolvedAttributionSource);

    virtual bool resolveClientUid(/*inout*/ int& clientUid);
    virtual bool resolveClientPid(/*inout*/ int& clientPid);

    virtual binder::Status errorNotTrusted(int clientPid, int clientUid,
                                           const std::string& methodName,
                                           const std::optional<std::string>& cameraIdMaybe,
                                           const std::string& clientName, bool isPid) const;

  private:
    virtual const sp<IPermissionController>& getPermissionController() const;

    virtual PermissionChecker::PermissionResult checkPermission(
            const std::string& cameraId, const std::string& permission,
            const AttributionSourceState& attributionSource, const std::string& message,
            int32_t attributedOpCode, bool forDataDelivery, bool startDataDelivery,
            bool checkAutomotive);

    std::unique_ptr<permission::PermissionChecker> mPermissionChecker =
            std::make_unique<permission::PermissionChecker>();
};

/**
 * Class to be inherited by classes encapsulating AttributionAndPermissionUtils. Provides an
 * additional utility layer above AttributionAndPermissionUtils calls, and avoids verbosity
 * in the encapsulating class's methods.
 */
class AttributionAndPermissionUtilsEncapsulator {
  protected:
    std::shared_ptr<AttributionAndPermissionUtils> mAttributionAndPermissionUtils;

  public:
    AttributionAndPermissionUtilsEncapsulator(
            std::shared_ptr<AttributionAndPermissionUtils> attributionAndPermissionUtils)
        : mAttributionAndPermissionUtils(attributionAndPermissionUtils) {}

    static AttributionSourceState buildAttributionSource(int callingPid, int callingUid) {
        return AttributionAndPermissionUtils::buildAttributionSource(callingPid, callingUid);
    }

    static AttributionSourceState buildAttributionSource(int callingPid, int callingUid,
                                                         int32_t deviceId) {
        return AttributionAndPermissionUtils::buildAttributionSource(callingPid, callingUid,
                                                                     deviceId);
    }

    static AttributionSourceState buildAttributionSource(int callingPid, int callingUid,
                                                         const std::string& packageName,
                                                         int32_t deviceId) {
        AttributionSourceState attributionSource =
                buildAttributionSource(callingPid, callingUid, deviceId);
        attributionSource.packageName = packageName;
        return attributionSource;
    }

    int getCallingUid() const { return mAttributionAndPermissionUtils->getCallingUid(); }

    int getCallingPid() const { return mAttributionAndPermissionUtils->getCallingPid(); }

    int64_t clearCallingIdentity() const {
        return mAttributionAndPermissionUtils->clearCallingIdentity();
    }

    void restoreCallingIdentity(int64_t token) const {
        mAttributionAndPermissionUtils->restoreCallingIdentity(token);
    }

    binder::Status resolveAttributionSource(AttributionSourceState& resolvedAttributionSource,
                                            const std::string& methodName,
                                            const std::optional<std::string>& cameraIdMaybe) {
        std::string passedPackageName;
        if (resolvedAttributionSource.packageName.has_value()) {
            passedPackageName = resolvedAttributionSource.packageName.value();
        }
        auto ret = mAttributionAndPermissionUtils->resolveAttributionSource(
                resolvedAttributionSource, methodName, cameraIdMaybe);
        if (!ret.isOk()) {
            return ret;
        }
        // Fix up package name
        if (passedPackageName.size() != 0) {
            resolvedAttributionSource.packageName = std::move(passedPackageName);
        }
        return ret;
    }

    // The word 'System' here does not refer to callers only on the system
    // partition. They just need to have an android system uid.
    bool callerHasSystemUid() const { return (getCallingUid() < AID_APP_START); }

    bool hasPermissionsForCamera(int callingPid, int callingUid, int32_t deviceId) const {
        return hasPermissionsForCamera(std::string(), callingPid, callingUid, deviceId);
    }

    bool hasPermissionsForCamera(int callingPid, int callingUid, const std::string& packageName,
                                 int32_t deviceId) const {
        auto attributionSource =
                buildAttributionSource(callingPid, callingUid, packageName, deviceId);
        return hasPermissionsForCamera(std::string(), attributionSource);
    }

    bool hasPermissionsForCamera(const std::string& cameraId, int callingPid, int callingUid,
                                 int32_t deviceId) const {
        auto attributionSource = buildAttributionSource(callingPid, callingUid, deviceId);
        return hasPermissionsForCamera(cameraId, attributionSource);
    }

    bool hasPermissionsForCamera(const std::string& cameraId,
                                 const AttributionSourceState& clientAttribution) const {
        return mAttributionAndPermissionUtils->hasPermissionsForCamera(cameraId, clientAttribution,
                                                                       /* forDataDelivery */ false,
                                                                       /* checkAutomotive */ true);
    }

    bool hasPermissionsForCameraForDataDelivery(
            const std::string& cameraId, const AttributionSourceState& clientAttribution) const {
        return mAttributionAndPermissionUtils->hasPermissionsForCamera(cameraId, clientAttribution,
                                                                       /* forDataDelivery */ true,
                                                                       /* checkAutomotive */ false);
    }

    PermissionChecker::PermissionResult checkPermissionsForCameraForPreflight(
            const std::string& cameraId, const AttributionSourceState& clientAttribution) const {
        return mAttributionAndPermissionUtils->checkPermissionsForCameraForPreflight(
                cameraId, clientAttribution);
    }

    PermissionChecker::PermissionResult checkPermissionsForCameraForDataDelivery(
            const std::string& cameraId, const AttributionSourceState& clientAttribution) const {
        return mAttributionAndPermissionUtils->checkPermissionsForCameraForDataDelivery(
                cameraId, clientAttribution);
    }

    PermissionChecker::PermissionResult checkPermissionsForCameraForStartDataDelivery(
            const std::string& cameraId, const AttributionSourceState& clientAttribution) const {
        return mAttributionAndPermissionUtils->checkPermissionsForCameraForStartDataDelivery(
                cameraId, clientAttribution);
    }

    bool hasPermissionsForSystemCamera(const std::string& cameraId, int callingPid, int callingUid,
                                       bool checkCameraPermissions = true) const {
        auto attributionSource = buildAttributionSource(callingPid, callingUid);
        return mAttributionAndPermissionUtils->hasPermissionsForSystemCamera(
                cameraId, attributionSource, checkCameraPermissions);
    }

    bool hasPermissionsForCameraHeadlessSystemUser(const std::string& cameraId, int callingPid,
                                                   int callingUid) const {
        auto attributionSource = buildAttributionSource(callingPid, callingUid);
        return mAttributionAndPermissionUtils->hasPermissionsForCameraHeadlessSystemUser(
                cameraId, attributionSource);
    }

    bool hasPermissionsForCameraPrivacyAllowlist(int callingPid, int callingUid) const {
        auto attributionSource = buildAttributionSource(callingPid, callingUid);
        return mAttributionAndPermissionUtils->hasPermissionsForCameraPrivacyAllowlist(
                attributionSource);
    }

    bool hasPermissionsForOpenCloseListener(int callingPid, int callingUid) const {
        auto attributionSource = buildAttributionSource(callingPid, callingUid);
        return mAttributionAndPermissionUtils->hasPermissionsForOpenCloseListener(
                attributionSource);
    }

    bool hasPermissionsForCameraWarmUp(int callingPid, int callingUid) const {
        auto attributionSource = buildAttributionSource(callingPid, callingUid);
        return mAttributionAndPermissionUtils->hasPermissionsForCameraWarmUp(
                attributionSource);
    }

    void finishDataDelivery(const AttributionSourceState& attributionSource) {
        mAttributionAndPermissionUtils->finishDataDelivery(attributionSource);
    }

    bool isAutomotiveDevice() const { return mAttributionAndPermissionUtils->isAutomotiveDevice(); }

    bool isAutomotivePrivilegedClient(int32_t uid) const {
        return mAttributionAndPermissionUtils->isAutomotivePrivilegedClient(uid);
    }

    bool isTrustedCallingUid(uid_t uid) const {
        return mAttributionAndPermissionUtils->isTrustedCallingUid(uid);
    }

    bool isHeadlessSystemUserMode() const {
        return mAttributionAndPermissionUtils->isHeadlessSystemUserMode();
    }

    status_t getUidForPackage(const std::string& packageName, int userId,
                              /*inout*/ uid_t& uid, int err) const {
        return mAttributionAndPermissionUtils->getUidForPackage(packageName, userId, uid, err);
    }

    std::string getPackageNameFromUid(int clientUid) const {
        return mAttributionAndPermissionUtils->getPackageNameFromUid(clientUid);
    }

    bool isCallerCameraServerNotDelegating() const {
        return mAttributionAndPermissionUtils->isCallerCameraServerNotDelegating();
    }
};

} // namespace android

#endif  // ANDROID_SERVERS_CAMERA_ATTRIBUTION_AND_PERMISSION_UTILS_H
