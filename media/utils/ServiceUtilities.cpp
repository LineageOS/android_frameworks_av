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

#include <binder/AppOpsManager.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include "mediautils/ServiceUtilities.h"

/* When performing permission checks we do not use permission cache for
 * runtime permissions (protection level dangerous) as they may change at
 * runtime. All other permissions (protection level normal and dangerous)
 * can be cached as they never change. Of course all permission checked
 * here are platform defined.
 */

namespace android {

static const String16 sAndroidPermissionRecordAudio("android.permission.RECORD_AUDIO");

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
        uid_t uid, bool start) {
    // Okay to not track in app ops as audio server is us and if
    // device is rooted security model is considered compromised.
    if (isAudioServerOrRootUid(uid)) return true;

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
    const int32_t op = appOps.permissionToOpCode(sAndroidPermissionRecordAudio);
    if (start) {
        if (appOps.startOpNoThrow(op, uid, resolvedOpPackageName, /*startIfModeDefault*/ false)
                != AppOpsManager::MODE_ALLOWED) {
            ALOGE("Request denied by app op: %d", op);
            return false;
        }
    } else {
        if (appOps.checkOp(op, uid, resolvedOpPackageName) != AppOpsManager::MODE_ALLOWED) {
            ALOGE("Request denied by app op: %d", op);
            return false;
        }
    }

    return true;
}

bool recordingAllowed(const String16& opPackageName, pid_t pid, uid_t uid) {
    return checkRecordingInternal(opPackageName, pid, uid, /*start*/ false);
}

bool startRecording(const String16& opPackageName, pid_t pid, uid_t uid) {
     return checkRecordingInternal(opPackageName, pid, uid, /*start*/ true);
}

void finishRecording(const String16& opPackageName, uid_t uid) {
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
    const int32_t op = appOps.permissionToOpCode(sAndroidPermissionRecordAudio);
    appOps.finishOp(op, uid, resolvedOpPackageName);
}

bool captureAudioOutputAllowed(pid_t pid, uid_t uid) {
    if (isAudioServerOrRootUid(uid)) return true;
    static const String16 sCaptureAudioOutput("android.permission.CAPTURE_AUDIO_OUTPUT");
    bool ok = PermissionCache::checkPermission(sCaptureAudioOutput, pid, uid);
    if (!ok) ALOGE("Request requires android.permission.CAPTURE_AUDIO_OUTPUT");
    return ok;
}

bool captureHotwordAllowed(pid_t pid, uid_t uid) {
    // CAPTURE_AUDIO_HOTWORD permission implies RECORD_AUDIO permission
    bool ok = recordingAllowed(String16(""), pid, uid);

    if (ok) {
        static const String16 sCaptureHotwordAllowed("android.permission.CAPTURE_AUDIO_HOTWORD");
        // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
        ok = PermissionCache::checkCallingPermission(sCaptureHotwordAllowed);
    }
    if (!ok) ALOGE("android.permission.CAPTURE_AUDIO_HOTWORD");
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
    static const String16 sModifyAudioRoutingAllowed("android.permission.MODIFY_AUDIO_ROUTING");
    // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
    bool ok = PermissionCache::checkCallingPermission(sModifyAudioRoutingAllowed);
    if (!ok) ALOGE("android.permission.MODIFY_AUDIO_ROUTING");
    return ok;
}

bool modifyDefaultAudioEffectsAllowed() {
    static const String16 sModifyDefaultAudioEffectsAllowed(
            "android.permission.MODIFY_DEFAULT_AUDIO_EFFECTS");
    // IMPORTANT: Use PermissionCache - not a runtime permission and may not change.
    bool ok = PermissionCache::checkCallingPermission(sModifyDefaultAudioEffectsAllowed);

#ifdef TARGET_ANDROID_THINGS
    if (!ok) {
        // Use a secondary permission on Android Things to allow a more lenient level of protection.
        static const String16 sModifyDefaultAudioEffectsAndroidThingsAllowed(
                "com.google.android.things.permission.MODIFY_DEFAULT_AUDIO_EFFECTS");
        ok = PermissionCache::checkCallingPermission(
                sModifyDefaultAudioEffectsAndroidThingsAllowed);
    }
    if (!ok) ALOGE("com.google.android.things.permission.MODIFY_DEFAULT_AUDIO_EFFECTS");
#else
    if (!ok) ALOGE("android.permission.MODIFY_DEFAULT_AUDIO_EFFECTS");
#endif
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
    static const String16 sModifyPhoneState("android.permission.MODIFY_PHONE_STATE");
    bool ok = PermissionCache::checkPermission(sModifyPhoneState, pid, uid);
    if (!ok) ALOGE("Request requires android.permission.MODIFY_PHONE_STATE");
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

    if (iMemory->pointer() == NULL || size < (off_t)iMemory->size()) {
        ALOGE("%s check failed: pointer %p size %zu fd size %u",
              __FUNCTION__, iMemory->pointer(), iMemory->size(), (uint32_t)size);
        return BAD_VALUE;
    }

    return NO_ERROR;
}

} // namespace android
