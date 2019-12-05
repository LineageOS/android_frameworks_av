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

bool deviceTypesToString(const DeviceTypeSet &deviceTypes, std::string &str) {
    if (deviceTypes.empty()) {
        str = "Empty device types";
        return true;
    }
    bool ret = true;
    for (auto it = deviceTypes.begin(); it != deviceTypes.end();) {
        std::string deviceTypeStr;
        ret = audio_is_output_device(*it) ?
              OutputDeviceConverter::toString(*it, deviceTypeStr) :
              InputDeviceConverter::toString(*it, deviceTypeStr);
        if (!ret) {
            break;
        }
        str.append(deviceTypeStr);
        if (++it != deviceTypes.end()) {
            str.append(" , ");
        }
    }
    if (!ret) {
        str = "Unknown values";
    }
    return ret;
}

std::string dumpDeviceTypes(const DeviceTypeSet &deviceTypes) {
    std::string ret;
    for (auto it = deviceTypes.begin(); it != deviceTypes.end();) {
        std::stringstream ss;
        ss << "0x" << std::hex << (*it);
        ret.append(ss.str());
        if (++it != deviceTypes.end()) {
            ret.append(" , ");
        }
    }
    return ret;
}

std::string toString(const DeviceTypeSet& deviceTypes) {
    std::string ret;
    deviceTypesToString(deviceTypes, ret);
    return ret;
}

} // namespace android
