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

#include <com_android_media_audio.h>
#include "SpatializerHelper.h"


namespace android {

/*  Mapping table between device types and corresponding binaural or transaural
 *  spatialization modes used by isModeCompatibleWithDevices() implementation.
 *  If a device type is not in this table, it is not supposed to support spatialization.
 */
const std::map<audio_devices_t, spatialization_mode_t> SpatializerHelper::sDeviceModeMap = {
    {AUDIO_DEVICE_OUT_SPEAKER, SPATIALIZATION_MODE_TRANSAURAL},
    {AUDIO_DEVICE_OUT_WIRED_HEADSET, SPATIALIZATION_MODE_BINAURAL},
    {AUDIO_DEVICE_OUT_WIRED_HEADPHONE, SPATIALIZATION_MODE_BINAURAL},
    {AUDIO_DEVICE_OUT_BLUETOOTH_A2DP, SPATIALIZATION_MODE_BINAURAL},
    {AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES, SPATIALIZATION_MODE_BINAURAL},
    {AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER, SPATIALIZATION_MODE_TRANSAURAL},
    {AUDIO_DEVICE_OUT_ANLG_DOCK_HEADSET, SPATIALIZATION_MODE_TRANSAURAL},
    {AUDIO_DEVICE_OUT_DGTL_DOCK_HEADSET, SPATIALIZATION_MODE_TRANSAURAL},
    {AUDIO_DEVICE_OUT_USB_ACCESSORY, SPATIALIZATION_MODE_TRANSAURAL},
    {AUDIO_DEVICE_OUT_USB_DEVICE, SPATIALIZATION_MODE_TRANSAURAL},
    {AUDIO_DEVICE_OUT_LINE, SPATIALIZATION_MODE_TRANSAURAL},
    {AUDIO_DEVICE_OUT_SPDIF, SPATIALIZATION_MODE_TRANSAURAL},
    {AUDIO_DEVICE_OUT_AUX_LINE, SPATIALIZATION_MODE_TRANSAURAL},
    {AUDIO_DEVICE_OUT_SPEAKER_SAFE, SPATIALIZATION_MODE_TRANSAURAL},
    {AUDIO_DEVICE_OUT_USB_HEADSET, SPATIALIZATION_MODE_BINAURAL},
    {AUDIO_DEVICE_OUT_BLE_HEADSET, SPATIALIZATION_MODE_BINAURAL},
    {AUDIO_DEVICE_OUT_BLE_SPEAKER, SPATIALIZATION_MODE_TRANSAURAL},
    {AUDIO_DEVICE_OUT_BLE_BROADCAST, SPATIALIZATION_MODE_BINAURAL},
    {AUDIO_DEVICE_OUT_BLE_HEARING_AID, SPATIALIZATION_MODE_BINAURAL}
};

bool SpatializerHelper::isModeCompatibleWithDevices(spatialization_mode_t mode,
          DeviceTypeSet devices) {
    for (auto device: devices) {
         if (!sDeviceModeMap.contains(device) || sDeviceModeMap.at(device) != mode) {
             return false;
         }
    }
    return true;
}

bool SpatializerHelper::isStereoSpatializationFeatureEnabled(DeviceTypeSet devices) {
    if (!com_android_media_audio_stereo_spatialization()) {
        return false;
    }
    if (property_get_bool("ro.audio.stereo_spatialization_enabled", false)) {
        return true;
    }

    if (!com_android_media_audio_stereo_spatialization_binaural_transaural()) {
        return false;
    }
    return (isModeCompatibleWithDevices(SPATIALIZATION_MODE_BINAURAL, devices)
                && property_get_bool("ro.audio.stereo_spatialization_binaural_enabled", false))
            || (isModeCompatibleWithDevices(SPATIALIZATION_MODE_TRANSAURAL, devices)
                && property_get_bool("ro.audio.stereo_spatialization_transaural_enabled", false));
}

} // namespace android
