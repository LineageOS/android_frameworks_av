/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <sstream>
#include <string>

#include <media/AudioContainers.h>

namespace android {

const DeviceTypeSet& getAudioDeviceOutAllSet() {
    static const DeviceTypeSet audioDeviceOutAllSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_ALL_ARRAY),
            std::end(AUDIO_DEVICE_OUT_ALL_ARRAY));
    return audioDeviceOutAllSet;
}

const DeviceTypeSet& getAudioDeviceOutAllA2dpSet() {
    static const DeviceTypeSet audioDeviceOutAllA2dpSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_ALL_A2DP_ARRAY),
            std::end(AUDIO_DEVICE_OUT_ALL_A2DP_ARRAY));
    return audioDeviceOutAllA2dpSet;
}

const DeviceTypeSet& getAudioDeviceOutAllScoSet() {
    static const DeviceTypeSet audioDeviceOutAllScoSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_ALL_SCO_ARRAY),
            std::end(AUDIO_DEVICE_OUT_ALL_SCO_ARRAY));
    return audioDeviceOutAllScoSet;
}

const DeviceTypeSet& getAudioDeviceOutAllUsbSet() {
    static const DeviceTypeSet audioDeviceOutAllUsbSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_ALL_USB_ARRAY),
            std::end(AUDIO_DEVICE_OUT_ALL_USB_ARRAY));
    return audioDeviceOutAllUsbSet;
}

const DeviceTypeSet& getAudioDeviceInAllSet() {
    static const DeviceTypeSet audioDeviceInAllSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_IN_ALL_ARRAY),
            std::end(AUDIO_DEVICE_IN_ALL_ARRAY));
    return audioDeviceInAllSet;
}

const DeviceTypeSet& getAudioDeviceInAllUsbSet() {
    static const DeviceTypeSet audioDeviceInAllUsbSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_IN_ALL_USB_ARRAY),
            std::end(AUDIO_DEVICE_IN_ALL_USB_ARRAY));
    return audioDeviceInAllUsbSet;
}

const DeviceTypeSet& getAudioDeviceOutAllBleSet() {
    static const DeviceTypeSet audioDeviceOutAllBleSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_ALL_BLE_ARRAY),
            std::end(AUDIO_DEVICE_OUT_ALL_BLE_ARRAY));
    return audioDeviceOutAllBleSet;
}

const DeviceTypeSet& getAudioDeviceOutLeAudioUnicastSet() {
    static const DeviceTypeSet audioDeviceOutLeAudioUnicastSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_BLE_UNICAST_ARRAY),
            std::end(AUDIO_DEVICE_OUT_BLE_UNICAST_ARRAY));
    return audioDeviceOutLeAudioUnicastSet;
}

const DeviceTypeSet& getAudioDeviceOutLeAudioBroadcastSet() {
    static const DeviceTypeSet audioDeviceOutLeAudioUnicastSet = DeviceTypeSet(
            std::begin(AUDIO_DEVICE_OUT_BLE_BROADCAST_ARRAY),
            std::end(AUDIO_DEVICE_OUT_BLE_BROADCAST_ARRAY));
    return audioDeviceOutLeAudioUnicastSet;
}

std::string deviceTypesToString(const DeviceTypeSet &deviceTypes) {
    if (deviceTypes.empty()) {
        return "Empty device types";
    }
    std::stringstream ss;
    for (auto it = deviceTypes.begin(); it != deviceTypes.end(); ++it) {
        if (it != deviceTypes.begin()) {
            ss << ", ";
        }
        const char* strType = audio_device_to_string(*it);
        if (strlen(strType) != 0) {
            ss << strType;
        } else {
            ss << "unknown type:0x" << std::hex << *it;
        }
    }
    return ss.str();
}

bool deviceTypesToString(const DeviceTypeSet &deviceTypes, std::string &str) {
    str = deviceTypesToString(deviceTypes);
    return true;
}

std::string dumpDeviceTypes(const DeviceTypeSet &deviceTypes) {
    std::stringstream ss;
    for (auto it = deviceTypes.begin(); it != deviceTypes.end(); ++it) {
        if (it != deviceTypes.begin()) {
            ss << ", ";
        }
        ss << "0x" << std::hex << (*it);
    }
    return ss.str();
}

std::string dumpMixerBehaviors(const MixerBehaviorSet& mixerBehaviors) {
    std::stringstream ss;
    for (auto it = mixerBehaviors.begin(); it != mixerBehaviors.end(); ++it) {
        if (it != mixerBehaviors.begin()) {
            ss << ", ";
        }
        ss << (*it);
    }
    return ss.str();
}

} // namespace android
