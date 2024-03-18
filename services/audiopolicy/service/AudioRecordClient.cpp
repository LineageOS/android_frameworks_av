/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android/content/pm/IPackageManagerNative.h>

#include "AudioRecordClient.h"
#include "AudioPolicyService.h"
#include <android_media_audiopolicy.h>

namespace android::media::audiopolicy {
namespace audiopolicy_flags = android::media::audiopolicy;
using android::AudioPolicyService;

namespace {
bool isAppOpSource(audio_source_t source)
{
    switch (source) {
        case AUDIO_SOURCE_FM_TUNER:
        case AUDIO_SOURCE_ECHO_REFERENCE:
        case AUDIO_SOURCE_REMOTE_SUBMIX:
            return false;
        default:
            break;
    }
    return true;
}

int getTargetSdkForPackageName(std::string_view packageName) {
    const auto binder = defaultServiceManager()->checkService(String16{"package_native"});
    int targetSdk = -1;
    if (binder != nullptr) {
        const auto pm = interface_cast<content::pm::IPackageManagerNative>(binder);
        if (pm != nullptr) {
            const auto status = pm->getTargetSdkVersionForPackage(
                    String16{packageName.data(), packageName.size()}, &targetSdk);
            return status.isOk() ? targetSdk : -1;
        }
    }
    return targetSdk;
}

bool doesPackageTargetAtLeastU(std::string_view packageName) {
    return getTargetSdkForPackageName(packageName) >= __ANDROID_API_U__;
}
}

// static
sp<OpRecordAudioMonitor>
OpRecordAudioMonitor::createIfNeeded(
        const AttributionSourceState &attributionSource,
        const uint32_t virtualDeviceId,
        const audio_attributes_t &attr,
        wp<AudioPolicyService::AudioCommandThread> commandThread)
{
    if (isAudioServerOrRootUid(attributionSource.uid)) {
        ALOGV("not silencing record for audio or root source %s",
                attributionSource.toString().c_str());
        return nullptr;
    }

    if (!isAppOpSource(attr.source)) {
        ALOGD("not monitoring app op for uid %d and source %d",
                attributionSource.uid, attr.source);
        return nullptr;
    }

    if (!attributionSource.packageName.has_value()
            || attributionSource.packageName.value().size() == 0) {
        return nullptr;
    }

    return new OpRecordAudioMonitor(attributionSource, virtualDeviceId, attr,
                                    getOpForSource(attr.source), commandThread);
}

OpRecordAudioMonitor::OpRecordAudioMonitor(
        const AttributionSourceState &attributionSource,
        const uint32_t virtualDeviceId, const audio_attributes_t &attr,
        int32_t appOp,
        wp<AudioPolicyService::AudioCommandThread> commandThread) :
        mHasOp(true), mAttributionSource(attributionSource),
        mVirtualDeviceId(virtualDeviceId), mAttr(attr), mAppOp(appOp),
        mCommandThread(commandThread) {
}

OpRecordAudioMonitor::~OpRecordAudioMonitor()
{
    if (mOpCallback != 0) {
        mAppOpsManager.stopWatchingMode(mOpCallback);
    }
    mOpCallback.clear();
}

void OpRecordAudioMonitor::onFirstRef()
{
    checkOp();
    mOpCallback = new RecordAudioOpCallback(this);
    ALOGV("start watching op %d for %s", mAppOp, mAttributionSource.toString().c_str());

    int flags = doesPackageTargetAtLeastU(
            mAttributionSource.packageName.value_or("")) ?
            AppOpsManager::WATCH_FOREGROUND_CHANGES : 0;
    // TODO: We need to always watch AppOpsManager::OP_RECORD_AUDIO too
    // since it controls the mic permission for legacy apps.
    mAppOpsManager.startWatchingMode(mAppOp, VALUE_OR_FATAL(aidl2legacy_string_view_String16(
        mAttributionSource.packageName.value_or(""))),
        flags,
        mOpCallback);
}

bool OpRecordAudioMonitor::hasOp() const {
    return mHasOp.load();
}

// Called by RecordAudioOpCallback when the app op corresponding to this OpRecordAudioMonitor
// is updated in AppOp callback and in onFirstRef()
// Note this method is never called (and never to be) for audio server / root track
// due to the UID in createIfNeeded(). As a result for those record track, it's:
// - not called from constructor,
// - not called from RecordAudioOpCallback because the callback is not installed in this case
void OpRecordAudioMonitor::checkOp(bool updateUidStates)
{
    // TODO: We need to always check AppOpsManager::OP_RECORD_AUDIO too
    // since it controls the mic permission for legacy apps.
    const int32_t mode = mAppOpsManager.checkOp(mAppOp,
            mAttributionSource.uid, VALUE_OR_FATAL(aidl2legacy_string_view_String16(
                mAttributionSource.packageName.value_or(""))));
    bool hasIt = (mode == AppOpsManager::MODE_ALLOWED);

    if (audiopolicy_flags::record_audio_device_aware_permission()) {
        const bool canRecord = recordingAllowed(mAttributionSource, mVirtualDeviceId, mAttr.source);
        hasIt = hasIt && canRecord;
    }
    // verbose logging only log when appOp changed
    ALOGI_IF(hasIt != mHasOp.load(),
            "App op %d missing, %ssilencing record %s",
            mAppOp, hasIt ? "un" : "", mAttributionSource.toString().c_str());
    mHasOp.store(hasIt);

    if (updateUidStates) {
          sp<AudioPolicyService::AudioCommandThread> commandThread = mCommandThread.promote();
          if (commandThread != nullptr) {
              commandThread->updateUidStatesCommand();
          }
    }
}

OpRecordAudioMonitor::RecordAudioOpCallback::RecordAudioOpCallback(
        const wp<OpRecordAudioMonitor>& monitor) : mMonitor(monitor)
{ }

void OpRecordAudioMonitor::RecordAudioOpCallback::opChanged(int32_t op,
            const String16& packageName __unused) {
    sp<OpRecordAudioMonitor> monitor = mMonitor.promote();
    if (monitor != NULL) {
        if (op != monitor->getOp()) {
            return;
        }
        monitor->checkOp(true);
    }
}

} // android::media::audiopolicy::internal
