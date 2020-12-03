/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "ServiceUtilities"

#include <audio_utils/clock.h>
#include <binder/AppOpsManager.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include "mediautils/ServiceUtilities.h"

#include <iterator>
#include <algorithm>
#include <pwd.h>

/* When performing permission checks we do not use permission cache for
 * runtime permissions (protection level dangerous) as they may change at
 * runtime. All other permissions (protection level normal and dangerous)
 * can be cached as they never change. Of course all permission checked
 * here are platform defined.
 */

namespace android {

static const String16 sAndroidPermissionRecordAudio("android.permission.RECORD_AUDIO");
static const String16 sModifyPhoneState("android.permission.MODIFY_PHONE_STATE");
static const String16 sModifyAudioRouting("android.permission.MODIFY_AUDIO_ROUTING");

static String16 resolveCallingPackage(PermissionController& permissionController,
        const String16& opPackageName, uid_t uid) {
    if (opPackageName.size() > 0) {
        return opPackageName;
    }
    // In some cases the calling code has no access to the package it runs under.
    // For example, code using the wilhelm framework's OpenSL-ES APIs. In this
    // case we will get the packages for the calling UID and pick the first one
    // for attributing the app op. This will work correctly for runtime permissions
    // as for legacy apps we will toggle the app op for all packages in the UID.
    // The caveat is that the operation may be attributed to the wrong package and
    // stats based on app ops may be slightly off.
    Vector<String16> packages;
    permissionController.getPackagesForUid(uid, packages);
    if (packages.isEmpty()) {
        ALOGE("No packages for uid %d", uid);
        return opPackageName; // empty string
    }
    return packages[0];
}

static bool checkRecordingInternal(const String16& opPackageName, pid_t pid,
        uid_t uid, bool start, bool isHotwordSource) {
    // Okay to not track in app ops as audio server or media server is us and if
    // device is rooted security model is considered compromised.
    // system_server loses its RECORD_AUDIO permission when a secondary
    // user is active, but it is a core system service so let it through.
    // TODO(b/141210120): UserManager.DISALLOW_RECORD_AUDIO should not affect system user 0
    if (isAudioServerOrMediaServerOrSystemServerOrRootUid(uid)) return true;

    // We specify a pid and uid here as mediaserver (aka MediaRecorder or StageFrightRecorder)
    // may open a record track on behalf of a client.  Note that pid may be a tid.
    // IMPORTANT: DON'T USE PermissionCache - RUNTIME PERMISSIONS CHANGE.
    PermissionController permissionController;
    const bool ok = permissionController.checkPermission(sAndroidPermissionRecordAudio, pid, uid);
    if (!ok) {
        ALOGE("Request requires %s", String8(sAndroidPermissionRecordAudio).c_str());
        return false;
    }

    String16 resolvedOpPackageName = resolveCallingPackage(
            permissionController, opPackageName, uid);
    if (resolvedOpPackageName.size() == 0) {
        return false;
    }

    AppOpsManager appOps;
    const int32_t opRecordAudio = appOps.permissionToOpCode(sAndroidPermissionRecordAudio);

    if (start) {
        const int32_t op = isHotwordSource ?
                AppOpsManager::OP_RECORD_AUDIO_HOTWORD : opRecordAudio;
        if (appOps.startOpNoThrow(op, uid, resolvedOpPackageName, /*startIfModeDefault*/ false)
                != AppOpsManager::MODE_ALLOWED) {
            ALOGE("Request denied by app op: %d", op);
            return false;
        }
    } else {
        // Always use OP_RECORD_AUDIO for checks at creation time.
        if (appOps.checkOp(opRecordAudio, uid, resolvedOpPackageName)
                != AppOpsManager::MODE_ALLOWED) {
            ALOGE("Request denied by app op: %d", opRecordAudio);
            return false;
        }
    }

    return true;
}

bool recordingAllowed(const String16& opPackageName, pid_t pid, uid_t uid) {
    return checkRecordingInternal(opPackageName, pid, uid, /*start*/ false,
            /*is_hotword_source*/ false);
}

bool startRecording(const String16& opPackageName, pid_t pid, uid_t uid, bool isHotwordSource) {
     return checkRecordingInternal(opPackageName, pid, uid, /*start*/ true, isHotwordSource);
}

void finishRecording(const String16& opPackageName, uid_t uid, bool isHotwordSource) {
    // Okay to not track in app ops as audio server is us and if
    // device is rooted security model is considered compromised.
    if (isAudioServerOrRootUid(uid)) return;

    PermissionController permissionController;
    String16 resolvedOpPackageName = resolveCallingPackage(
            permissionController, opPackageName, uid);
    if (resolvedOpPackageName.size() == 0) {
        return;
    }

    AppOpsManager appOps;
    const int32_t op = isHotwordSource ? AppOpsManager::OP_RECORD_AUDIO_HOTWORD
            : appOps.permissionToOpCode(sAndroidPermissionRecordAudio);
    appOps.finishOp(op, uid, resolvedOpPackageName);
}

bool captureAudioOutputAllowed(pid_t pid, uid_t uid) {
    if (isAudioServerOrRootUid(uid)) return true;
    static const String16 sCaptureAudioOutput("android.permission.CAPTURE_AUDIO_OUTPUT");
    bool ok = PermissionCache::checkPermission(sCaptureAudioOutput, pid, uid);
    if (!ok) ALOGV("Request requires android.permission.CAPTURE_AUDIO_OUTPUT");
    return ok;
}

bool captureMediaOutputAllowed(pid_t pid, uid_t uid) {
    if (isAudioServerOrRootUid(uid)) return true;
    static const String16 sCaptureMediaOutput("android.permission.CAPTURE_MEDIA_OUTPUT");
    bool ok = PermissionCache::checkPermission(sCaptureMediaOutput, pid, uid);
    if (!ok) ALOGE("Request requires android.permission.CAPTURE_MEDIA_OUTPUT");
    return ok;
}

bool captureVoiceCommunicationOutputAllowed(pid_t pid, uid_t uid) {
    if (isAudioServerOrRootUid(uid)) return true;
    static const String16 sCaptureVoiceCommOutput(
        "android.permission.CAPTURE_VOICE_COMMUNICATION_OUTPUT");
    bool ok = PermissionCache::checkPermission(sCaptureVoiceCommOutput, pid, uid);
    if (!ok) ALOGE("Request requires android.permission.CAPTURE_VOICE_COMMUNICATION_OUTPUT");
    return ok;
}

bool captureHotwordAllowed(const String16& opPackageName, pid_t pid, uid_t uid) {
    // CAPTURE_AUDIO_HOTWORD permission implies RECORD_AUDIO permission
    bool ok = recordingAllowed(opPackageName, pid, uid);

    if (ok) {
        static const String16 sCaptureHotwordAllowed("android.permission.CAPTURE_AUDIO_HOTWORD");
        // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
        ok = PermissionCache::checkPermission(sCaptureHotwordAllowed, pid, uid);
    }
    if (!ok) ALOGV("android.permission.CAPTURE_AUDIO_HOTWORD");
    return ok;
}

bool settingsAllowed() {
    // given this is a permission check, could this be isAudioServerOrRootUid()?
    if (isAudioServerUid(IPCThreadState::self()->getCallingUid())) return true;
    static const String16 sAudioSettings("android.permission.MODIFY_AUDIO_SETTINGS");
    // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
    bool ok = PermissionCache::checkCallingPermission(sAudioSettings);
    if (!ok) ALOGE("Request requires android.permission.MODIFY_AUDIO_SETTINGS");
    return ok;
}

bool modifyAudioRoutingAllowed() {
    return modifyAudioRoutingAllowed(
        IPCThreadState::self()->getCallingPid(), IPCThreadState::self()->getCallingUid());
}

bool modifyAudioRoutingAllowed(pid_t pid, uid_t uid) {
    if (isAudioServerUid(IPCThreadState::self()->getCallingUid())) return true;
    // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
    bool ok = PermissionCache::checkPermission(sModifyAudioRouting, pid, uid);
    if (!ok) ALOGE("%s(): android.permission.MODIFY_AUDIO_ROUTING denied for uid %d",
        __func__, uid);
    return ok;
}

bool modifyDefaultAudioEffectsAllowed() {
    return modifyDefaultAudioEffectsAllowed(
        IPCThreadState::self()->getCallingPid(), IPCThreadState::self()->getCallingUid());
}

bool modifyDefaultAudioEffectsAllowed(pid_t pid, uid_t uid) {
    if (isAudioServerUid(IPCThreadState::self()->getCallingUid())) return true;

    static const String16 sModifyDefaultAudioEffectsAllowed(
            "android.permission.MODIFY_DEFAULT_AUDIO_EFFECTS");
    // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
    bool ok = PermissionCache::checkPermission(sModifyDefaultAudioEffectsAllowed, pid, uid);
    ALOGE_IF(!ok, "%s(): android.permission.MODIFY_DEFAULT_AUDIO_EFFECTS denied for uid %d",
            __func__, uid);
    return ok;
}

bool dumpAllowed() {
    static const String16 sDump("android.permission.DUMP");
    // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
    bool ok = PermissionCache::checkCallingPermission(sDump);
    // convention is for caller to dump an error message to fd instead of logging here
    //if (!ok) ALOGE("Request requires android.permission.DUMP");
    return ok;
}

bool modifyPhoneStateAllowed(pid_t pid, uid_t uid) {
    bool ok = PermissionCache::checkPermission(sModifyPhoneState, pid, uid);
    ALOGE_IF(!ok, "Request requires %s", String8(sModifyPhoneState).c_str());
    return ok;
}

// privileged behavior needed by Dialer, Settings, SetupWizard and CellBroadcastReceiver
bool bypassInterruptionPolicyAllowed(pid_t pid, uid_t uid) {
    static const String16 sWriteSecureSettings("android.permission.WRITE_SECURE_SETTINGS");
    bool ok = PermissionCache::checkPermission(sModifyPhoneState, pid, uid)
        || PermissionCache::checkPermission(sWriteSecureSettings, pid, uid)
        || PermissionCache::checkPermission(sModifyAudioRouting, pid, uid);
    ALOGE_IF(!ok, "Request requires %s or %s",
             String8(sModifyPhoneState).c_str(), String8(sWriteSecureSettings).c_str());
    return ok;
}

status_t checkIMemory(const sp<IMemory>& iMemory)
{
    if (iMemory == 0) {
        ALOGE("%s check failed: NULL IMemory pointer", __FUNCTION__);
        return BAD_VALUE;
    }

    sp<IMemoryHeap> heap = iMemory->getMemory();
    if (heap == 0) {
        ALOGE("%s check failed: NULL heap pointer", __FUNCTION__);
        return BAD_VALUE;
    }

    off_t size = lseek(heap->getHeapID(), 0, SEEK_END);
    lseek(heap->getHeapID(), 0, SEEK_SET);

    if (iMemory->unsecurePointer() == NULL || size < (off_t)iMemory->size()) {
        ALOGE("%s check failed: pointer %p size %zu fd size %u",
              __FUNCTION__, iMemory->unsecurePointer(), iMemory->size(), (uint32_t)size);
        return BAD_VALUE;
    }

    return NO_ERROR;
}

sp<content::pm::IPackageManagerNative> MediaPackageManager::retreivePackageManager() {
    const sp<IServiceManager> sm = defaultServiceManager();
    if (sm == nullptr) {
        ALOGW("%s: failed to retrieve defaultServiceManager", __func__);
        return nullptr;
    }
    sp<IBinder> packageManager = sm->checkService(String16(nativePackageManagerName));
    if (packageManager == nullptr) {
        ALOGW("%s: failed to retrieve native package manager", __func__);
        return nullptr;
    }
    return interface_cast<content::pm::IPackageManagerNative>(packageManager);
}

std::optional<bool> MediaPackageManager::doIsAllowed(uid_t uid) {
    if (mPackageManager == nullptr) {
        /** Can not fetch package manager at construction it may not yet be registered. */
        mPackageManager = retreivePackageManager();
        if (mPackageManager == nullptr) {
            ALOGW("%s: Playback capture is denied as package manager is not reachable", __func__);
            return std::nullopt;
        }
    }

    std::vector<std::string> packageNames;
    auto status = mPackageManager->getNamesForUids({(int32_t)uid}, &packageNames);
    if (!status.isOk()) {
        ALOGW("%s: Playback capture is denied for uid %u as the package names could not be "
              "retrieved from the package manager: %s", __func__, uid, status.toString8().c_str());
        return std::nullopt;
    }
    if (packageNames.empty()) {
        ALOGW("%s: Playback capture for uid %u is denied as no package name could be retrieved "
              "from the package manager: %s", __func__, uid, status.toString8().c_str());
        return std::nullopt;
    }
    std::vector<bool> isAllowed;
    status = mPackageManager->isAudioPlaybackCaptureAllowed(packageNames, &isAllowed);
    if (!status.isOk()) {
        ALOGW("%s: Playback capture is denied for uid %u as the manifest property could not be "
              "retrieved from the package manager: %s", __func__, uid, status.toString8().c_str());
        return std::nullopt;
    }
    if (packageNames.size() != isAllowed.size()) {
        ALOGW("%s: Playback capture is denied for uid %u as the package manager returned incoherent"
              " response size: %zu != %zu", __func__, uid, packageNames.size(), isAllowed.size());
        return std::nullopt;
    }

    // Zip together packageNames and isAllowed for debug logs
    Packages& packages = mDebugLog[uid];
    packages.resize(packageNames.size()); // Reuse all objects
    std::transform(begin(packageNames), end(packageNames), begin(isAllowed),
                   begin(packages), [] (auto& name, bool isAllowed) -> Package {
                       return {std::move(name), isAllowed};
                   });

    // Only allow playback record if all packages in this UID allow it
    bool playbackCaptureAllowed = std::all_of(begin(isAllowed), end(isAllowed),
                                                  [](bool b) { return b; });

    return playbackCaptureAllowed;
}

void MediaPackageManager::dump(int fd, int spaces) const {
    dprintf(fd, "%*sAllow playback capture log:\n", spaces, "");
    if (mPackageManager == nullptr) {
        dprintf(fd, "%*sNo package manager\n", spaces + 2, "");
    }
    dprintf(fd, "%*sPackage manager errors: %u\n", spaces + 2, "", mPackageManagerErrors);

    for (const auto& uidCache : mDebugLog) {
        for (const auto& package : std::get<Packages>(uidCache)) {
            dprintf(fd, "%*s- uid=%5u, allowPlaybackCapture=%s, packageName=%s\n", spaces + 2, "",
                    std::get<const uid_t>(uidCache),
                    package.playbackCaptureAllowed ? "true " : "false",
                    package.name.c_str());
        }
    }
}

// How long we hold info before we re-fetch it (24 hours) if we found it previously.
static constexpr nsecs_t INFO_EXPIRATION_NS = 24 * 60 * 60 * NANOS_PER_SECOND;
// Maximum info records we retain before clearing everything.
static constexpr size_t INFO_CACHE_MAX = 1000;

// The original code is from MediaMetricsService.cpp.
mediautils::UidInfo::Info mediautils::UidInfo::getInfo(uid_t uid)
{
    const nsecs_t now = systemTime(SYSTEM_TIME_REALTIME);
    struct mediautils::UidInfo::Info info;
    {
        std::lock_guard _l(mLock);
        auto it = mInfoMap.find(uid);
        if (it != mInfoMap.end()) {
            info = it->second;
            ALOGV("%s: uid %d expiration %lld now %lld",
                    __func__, uid, (long long)info.expirationNs, (long long)now);
            if (info.expirationNs <= now) {
                // purge the stale entry and fall into re-fetching
                ALOGV("%s: entry for uid %d expired, now %lld",
                        __func__, uid, (long long)now);
                mInfoMap.erase(it);
                info.uid = (uid_t)-1;  // this is always fully overwritten
            }
        }
    }

    // if we did not find it in our map, look it up
    if (info.uid == (uid_t)(-1)) {
        sp<IServiceManager> sm = defaultServiceManager();
        sp<content::pm::IPackageManagerNative> package_mgr;
        if (sm.get() == nullptr) {
            ALOGE("%s: Cannot find service manager", __func__);
        } else {
            sp<IBinder> binder = sm->getService(String16("package_native"));
            if (binder.get() == nullptr) {
                ALOGE("%s: Cannot find package_native", __func__);
            } else {
                package_mgr = interface_cast<content::pm::IPackageManagerNative>(binder);
            }
        }

        // find package name
        std::string pkg;
        if (package_mgr != nullptr) {
            std::vector<std::string> names;
            binder::Status status = package_mgr->getNamesForUids({(int)uid}, &names);
            if (!status.isOk()) {
                ALOGE("%s: getNamesForUids failed: %s",
                        __func__, status.exceptionMessage().c_str());
            } else {
                if (!names[0].empty()) {
                    pkg = names[0].c_str();
                }
            }
        }

        if (pkg.empty()) {
            struct passwd pw{}, *result;
            char buf[8192]; // extra buffer space - should exceed what is
                            // required in struct passwd_pw (tested),
                            // and even then this is only used in backup
                            // when the package manager is unavailable.
            if (getpwuid_r(uid, &pw, buf, sizeof(buf), &result) == 0
                    && result != nullptr
                    && result->pw_name != nullptr) {
                pkg = result->pw_name;
            }
        }

        // strip any leading "shared:" strings that came back
        if (pkg.compare(0, 7, "shared:") == 0) {
            pkg.erase(0, 7);
        }

        // determine how pkg was installed and the versionCode
        std::string installer;
        int64_t versionCode = 0;
        bool notFound = false;
        if (pkg.empty()) {
            pkg = std::to_string(uid); // not found
            notFound = true;
        } else if (strchr(pkg.c_str(), '.') == nullptr) {
            // not of form 'com.whatever...'; assume internal
            // so we don't need to look it up in package manager.
        } else if (strncmp(pkg.c_str(), "android.", 8) == 0) {
            // android.* packages are assumed fine
        } else if (package_mgr.get() != nullptr) {
            String16 pkgName16(pkg.c_str());
            binder::Status status = package_mgr->getInstallerForPackage(pkgName16, &installer);
            if (!status.isOk()) {
                ALOGE("%s: getInstallerForPackage failed: %s",
                        __func__, status.exceptionMessage().c_str());
            }

            // skip if we didn't get an installer
            if (status.isOk()) {
                status = package_mgr->getVersionCodeForPackage(pkgName16, &versionCode);
                if (!status.isOk()) {
                    ALOGE("%s: getVersionCodeForPackage failed: %s",
                            __func__, status.exceptionMessage().c_str());
                }
            }

            ALOGV("%s: package '%s' installed by '%s' versioncode %lld",
                    __func__, pkg.c_str(), installer.c_str(), (long long)versionCode);
        }

        // add it to the map, to save a subsequent lookup
        std::lock_guard _l(mLock);
        // first clear if we have too many cached elements.  This would be rare.
        if (mInfoMap.size() >= INFO_CACHE_MAX) mInfoMap.clear();

        // always overwrite
        info.uid = uid;
        info.package = std::move(pkg);
        info.installer = std::move(installer);
        info.versionCode = versionCode;
        info.expirationNs = now + (notFound ? 0 : INFO_EXPIRATION_NS);
        ALOGV("%s: adding uid %d package '%s' expirationNs: %lld",
                __func__, uid, info.package.c_str(), (long long)info.expirationNs);
        mInfoMap[uid] = info;
    }
    return info;
}

} // namespace android
