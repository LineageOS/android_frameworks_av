/*
 * Copyright (C) 2025 The Android Open Source Project
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

#pragma once

#include <android-base/thread_annotations.h>
#include <cutils/android_filesystem_config.h>
#include <log/log.h>
#include <system/audio.h>
#include <utils/RefBase.h>

namespace android::media::permission {

/**
 * Tracking ops for the following uids are pointless -- system always has ops and isn't tracked,
 * and native only services don't have packages which is what appops tracks over.
 * So, we skip tracking, and always permit access.
 * Notable omissions are AID_SHELL, AID_RADIO, and AID_BLUETOOTH, which are non-app uids which
 * interface with us, but are associated with packages so can still be attributed to.
 */
inline bool skipOpsForUid(uid_t uid) {
    switch (uid % AID_USER_OFFSET) {
        case AID_ROOT:
        case AID_SYSTEM:
        case AID_MEDIA:
        case AID_AUDIOSERVER:
        case AID_CAMERASERVER:
            return true;
        default:
            return false;
    }
}

inline bool isSystemUsage(audio_usage_t usage) {
    const std::array SYSTEM_USAGES{AUDIO_USAGE_CALL_ASSISTANT, AUDIO_USAGE_EMERGENCY,
                                   AUDIO_USAGE_SAFETY, AUDIO_USAGE_VEHICLE_STATUS,
                                   AUDIO_USAGE_ANNOUNCEMENT, AUDIO_USAGE_SPEAKER_CLEANUP,
                                   AUDIO_USAGE_NOTIFICATION_VIBRATION,
                                   AUDIO_USAGE_RINGTONE_VIBRATION};
    return std::find(std::begin(SYSTEM_USAGES), std::end(SYSTEM_USAGES), usage) !=
           std::end(SYSTEM_USAGES);
}

}  // namespace android::media::permission
