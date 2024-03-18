/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
#include "core-mock/ModuleMock.h"
#include "core-mock/BluetoothA2dpMock.h"
#include "core-mock/BluetoothLeMock.h"
#include "core-mock/BluetoothMock.h"
#include "core-mock/StreamInMock.h"
#include "core-mock/StreamOutMock.h"
#include "core-mock/TelephonyMock.h"
#include "sounddose-mock/SoundDoseMock.h"

namespace aidl::android::hardware::audio::core {

ModuleMock::ModuleMock() {
    // Device ports
    auto outDevice = createPort(/* PortId */ 0, /* Name */ "Default",
                                /* Flags */ 1 << AudioPortDeviceExt::FLAG_INDEX_DEFAULT_DEVICE,
                                /* isInput */ false,
                                createDeviceExt(
                                        /* DeviceType */ AudioDeviceType::OUT_DEFAULT,
                                        /* Flags */ AudioPortDeviceExt::FLAG_INDEX_DEFAULT_DEVICE));
    mPorts.push_back(outDevice);
    auto inDevice = createPort(/* PortId */ 1, /* Name */ "Default",
                               /* Flags */ 1 << AudioPortDeviceExt::FLAG_INDEX_DEFAULT_DEVICE,
                               /* isInput */ true,
                               createDeviceExt(
                                       /* DeviceType */ AudioDeviceType::IN_DEFAULT,
                                       /* Flags */ 0));
    mPorts.push_back(outDevice);
}

ndk::ScopedAStatus ModuleMock::getTelephony(std::shared_ptr<ITelephony>* _aidl_return) {
    *_aidl_return = ndk::SharedRefBase::make<TelephonyMock>();
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::getBluetooth(std::shared_ptr<IBluetooth>* _aidl_return) {
    *_aidl_return = ndk::SharedRefBase::make<BluetoothMock>();
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::getBluetoothA2dp(std::shared_ptr<IBluetoothA2dp>* _aidl_return) {
    *_aidl_return = ndk::SharedRefBase::make<BluetoothA2dpMock>();
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::getBluetoothLe(std::shared_ptr<IBluetoothLe>* _aidl_return) {
    *_aidl_return = ndk::SharedRefBase::make<BluetoothLeMock>();
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::openInputStream(const OpenInputStreamArguments&,
                                               OpenInputStreamReturn* _aidl_return) {
    _aidl_return->stream = ndk::SharedRefBase::make<StreamInMock>();
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::openOutputStream(const OpenOutputStreamArguments&,
                                                OpenOutputStreamReturn* _aidl_return) {
    _aidl_return->stream = ndk::SharedRefBase::make<StreamOutMock>();
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::getMasterMute(bool* _aidl_return) {
    *_aidl_return = mMasterMute;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::setMasterMute(bool masterMute) {
    mMasterMute = masterMute;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::getMasterVolume(float* _aidl_return) {
    *_aidl_return = mMasterVolume;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::setMasterVolume(float masterVolume) {
    mMasterVolume = masterVolume;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::getMicMute(bool* _aidl_return) {
    *_aidl_return = mMicMute;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::setMicMute(bool micMute) {
    mMicMute = micMute;
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::getSoundDose(std::shared_ptr<ISoundDose>* _aidl_return) {
    *_aidl_return = ndk::SharedRefBase::make<SoundDoseMock>();
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::getMmapPolicyInfos(AudioMMapPolicyType,
                                                  std::vector<AudioMMapPolicyInfo>* _aidl_return) {
    AudioMMapPolicyInfo never;
    never.mmapPolicy = AudioMMapPolicy::NEVER;
    _aidl_return->push_back(never);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus ModuleMock::supportsVariableLatency(bool* _aidl_return) {
    *_aidl_return = false;
    return ndk::ScopedAStatus::ok();
}

AudioPortExt ModuleMock::createDeviceExt(AudioDeviceType devType, int32_t flags) {
    AudioPortDeviceExt deviceExt;
    deviceExt.device.type.type = devType;
    deviceExt.flags = flags;
    return AudioPortExt::make<AudioPortExt::Tag::device>(deviceExt);
}

AudioPort ModuleMock::createPort(int32_t id, const std::string& name, int32_t flags, bool isInput,
                                 const AudioPortExt& ext) {
    AudioPort port;
    port.id = id;
    port.name = name;
    port.flags = isInput ? AudioIoFlags::make<AudioIoFlags::Tag::input>(flags)
                         : AudioIoFlags::make<AudioIoFlags::Tag::output>(flags);
    port.ext = ext;
    return port;
}

}  // namespace aidl::android::hardware::audio::core
