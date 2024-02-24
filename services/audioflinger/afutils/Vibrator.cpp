/*
 *
 * Copyright 2023, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "AudioFlinger::Vibrator"
//#define LOG_NDEBUG 0

#include "Vibrator.h"

#include <android/os/ExternalVibrationScale.h>
#include <android/os/IExternalVibratorService.h>
#include <binder/IServiceManager.h>
#include <utils/Log.h>

#include <mutex>

namespace android::afutils {

static sp<os::IExternalVibratorService> getExternalVibratorService() {
    static std::mutex m;
    static sp<os::IExternalVibratorService> sExternalVibratorService;

    std::lock_guard l(m);
    if (sExternalVibratorService == nullptr) {
        const sp<IBinder> binder = defaultServiceManager()->getService(
                String16("external_vibrator_service"));
        if (binder != nullptr) {
            sExternalVibratorService = interface_cast<os::IExternalVibratorService>(binder);
        }
    }
    return sExternalVibratorService;
}

os::HapticScale onExternalVibrationStart(const sp<os::ExternalVibration>& externalVibration) {
    if (externalVibration->getAudioAttributes().flags & AUDIO_FLAG_MUTE_HAPTIC) {
        ALOGD("%s, mute haptic according to audio attributes flag", __func__);
        return os::HapticScale::mute();
    }
    const sp<os::IExternalVibratorService> evs = getExternalVibratorService();
    if (evs != nullptr) {

        os::ExternalVibrationScale ret;
        binder::Status status = evs->onExternalVibrationStart(*externalVibration, &ret);
        if (status.isOk()) {
            ALOGD("%s, start external vibration with intensity as %d", __func__, ret.scaleLevel);
            return os::ExternalVibration::externalVibrationScaleToHapticScale(ret);
        }
    }
    ALOGD("%s, start external vibration with intensity as MUTE due to %s",
            __func__,
            evs == nullptr ? "external vibration service not found"
                           : "error when querying intensity");
    return os::HapticScale::mute();
}

void onExternalVibrationStop(const sp<os::ExternalVibration>& externalVibration) {
    const sp<os::IExternalVibratorService> evs = getExternalVibratorService();
    if (evs != nullptr) {
        ALOGD("%s, stop external vibration", __func__);
        evs->onExternalVibrationStop(*externalVibration);
    }
}

}  // namespace android::afutils
