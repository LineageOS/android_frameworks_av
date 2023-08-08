/*
 * Copyright (C) 2009 The Android Open Source Project
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

#define LOG_TAG "APM_Config"

#include <AudioPolicyConfig.h>
#include <IOProfile.h>
#include <Serializer.h>
#include <hardware/audio.h>
#include <media/AidlConversion.h>
#include <media/AidlConversionUtil.h>
#include <media/AudioProfile.h>
#include <system/audio.h>
#include <system/audio_config.h>
#include <utils/Log.h>

namespace android {

using media::audio::common::AudioIoFlags;
using media::audio::common::AudioPortDeviceExt;
using media::audio::common::AudioPortExt;

namespace {

ConversionResult<sp<PolicyAudioPort>>
aidl2legacy_portId_PolicyAudioPort(int32_t portId,
        const std::unordered_map<int32_t, sp<PolicyAudioPort>>& ports) {
    if (auto it = ports.find(portId); it != ports.end()) {
        return it->second;
    }
    return base::unexpected(BAD_VALUE);
}

ConversionResult<sp<AudioRoute>>
aidl2legacy_AudioRoute(const media::AudioRoute& aidl,
        const std::unordered_map<int32_t, sp<PolicyAudioPort>>& ports) {
    auto legacy = sp<AudioRoute>::make(aidl.isExclusive ? AUDIO_ROUTE_MUX : AUDIO_ROUTE_MIX);
    auto legacySink = VALUE_OR_RETURN(aidl2legacy_portId_PolicyAudioPort(aidl.sinkPortId, ports));
    legacy->setSink(legacySink);
    PolicyAudioPortVector legacySources;
    for (int32_t portId : aidl.sourcePortIds) {
        sp<PolicyAudioPort> legacyPort = VALUE_OR_RETURN(
                aidl2legacy_portId_PolicyAudioPort(portId, ports));
        legacySources.add(legacyPort);
    }
    legacy->setSources(legacySources);
    legacySink->addRoute(legacy);
    for (const auto& legacySource : legacySources) {
        legacySource->addRoute(legacy);
    }
    return legacy;
}

status_t aidl2legacy_AudioHwModule_HwModule(const media::AudioHwModule& aidl,
        sp<HwModule>* legacy,
        DeviceVector* attachedInputDevices, DeviceVector* attachedOutputDevices,
        sp<DeviceDescriptor>* defaultOutputDevice) {
    *legacy = sp<HwModule>::make(aidl.name.c_str(), AUDIO_DEVICE_API_VERSION_CURRENT);
    audio_module_handle_t legacyHandle = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_module_handle_t(aidl.handle));
    (*legacy)->setHandle(legacyHandle);
    IOProfileCollection mixPorts;
    DeviceVector devicePorts;
    const int defaultDeviceFlag = 1 << AudioPortDeviceExt::FLAG_INDEX_DEFAULT_DEVICE;
    std::unordered_map<int32_t, sp<PolicyAudioPort>> ports;
    for (const auto& aidlPort : aidl.ports) {
        const bool isInput = aidlPort.flags.getTag() == AudioIoFlags::input;
        audio_port_v7 legacyPort = VALUE_OR_RETURN_STATUS(
                aidl2legacy_AudioPort_audio_port_v7(aidlPort, isInput));
        // This conversion fills out both 'hal' and 'sys' parts.
        media::AudioPortFw fwPort = VALUE_OR_RETURN_STATUS(
                legacy2aidl_audio_port_v7_AudioPortFw(legacyPort));
        // Since audio_port_v7 lacks some fields, for example, 'maxOpen/ActiveCount',
        // replace the converted data with the actual data from the HAL.
        fwPort.hal = aidlPort;
        if (aidlPort.ext.getTag() == AudioPortExt::mix) {
            auto mixPort = sp<IOProfile>::make("", AUDIO_PORT_ROLE_NONE);
            RETURN_STATUS_IF_ERROR(mixPort->readFromParcelable(fwPort));
            auto& profiles = mixPort->getAudioProfiles();
            if (profiles.empty()) {
                profiles.add(AudioProfile::createFullDynamic(gDynamicFormat));
            } else {
                sortAudioProfiles(mixPort->getAudioProfiles());
            }
            mixPorts.add(mixPort);
            ports.emplace(aidlPort.id, mixPort);
        } else if (aidlPort.ext.getTag() == AudioPortExt::device) {
            // In the legacy XML, device ports use 'tagName' instead of 'AudioPort.name'.
            auto devicePort =
                    sp<DeviceDescriptor>::make(AUDIO_DEVICE_NONE, aidlPort.name);
            RETURN_STATUS_IF_ERROR(devicePort->readFromParcelable(fwPort));
            devicePort->setName("");
            auto& profiles = devicePort->getAudioProfiles();
            if (profiles.empty()) {
                profiles.add(AudioProfile::createFullDynamic(gDynamicFormat));
            } else {
                sortAudioProfiles(profiles);
            }
            devicePorts.add(devicePort);
            ports.emplace(aidlPort.id, devicePort);

            if (const auto& deviceExt = aidlPort.ext.get<AudioPortExt::device>();
                    deviceExt.device.type.connection.empty()) {  // Attached device
                if (isInput) {
                    attachedInputDevices->add(devicePort);
                } else {
                    attachedOutputDevices->add(devicePort);
                    if ((deviceExt.flags & defaultDeviceFlag) != 0) {
                        *defaultOutputDevice = devicePort;
                    }
                }
            }
        } else {
            return BAD_VALUE;
        }
    }
    (*legacy)->setProfiles(mixPorts);
    (*legacy)->setDeclaredDevices(devicePorts);
    AudioRouteVector routes;
    for (const auto& aidlRoute : aidl.routes) {
        sp<AudioRoute> legacy = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioRoute(aidlRoute, ports));
        routes.add(legacy);
    }
    (*legacy)->setRoutes(routes);
    return OK;
}

status_t aidl2legacy_AudioHwModules_HwModuleCollection(
        const std::vector<media::AudioHwModule>& aidl,
        HwModuleCollection* legacyModules, DeviceVector* attachedInputDevices,
        DeviceVector* attachedOutputDevices, sp<DeviceDescriptor>* defaultOutputDevice) {
    for (const auto& aidlModule : aidl) {
        sp<HwModule> legacy;
        RETURN_STATUS_IF_ERROR(aidl2legacy_AudioHwModule_HwModule(aidlModule, &legacy,
                        attachedInputDevices, attachedOutputDevices, defaultOutputDevice));
        legacyModules->add(legacy);
    }
    return OK;
}

using SurroundFormatFamily = AudioPolicyConfig::SurroundFormats::value_type;
ConversionResult<SurroundFormatFamily>
aidl2legacy_SurroundFormatFamily(const media::SurroundSoundConfig::SurroundFormatFamily& aidl) {
    audio_format_t legacyPrimary = VALUE_OR_RETURN(
            aidl2legacy_AudioFormatDescription_audio_format_t(aidl.primaryFormat));
    std::unordered_set<audio_format_t> legacySubs = VALUE_OR_RETURN(
            convertContainer<std::unordered_set<audio_format_t>>(
                    aidl.subFormats, aidl2legacy_AudioFormatDescription_audio_format_t));
    return std::make_pair(legacyPrimary, legacySubs);
}

ConversionResult<AudioPolicyConfig::SurroundFormats>
aidl2legacy_SurroundSoundConfig_SurroundFormats(const media::SurroundSoundConfig& aidl) {
    return convertContainer<AudioPolicyConfig::SurroundFormats>(aidl.formatFamilies,
            aidl2legacy_SurroundFormatFamily);
};

}  // namespace

// static
sp<const AudioPolicyConfig> AudioPolicyConfig::createDefault() {
    auto config = sp<AudioPolicyConfig>::make();
    config->setDefault();
    return config;
}

// static
sp<const AudioPolicyConfig> AudioPolicyConfig::loadFromApmAidlConfigWithFallback(
        const media::AudioPolicyConfig& aidl) {
    auto config = sp<AudioPolicyConfig>::make();
    if (status_t status = config->loadFromAidl(aidl); status == NO_ERROR) {
        return config;
    }
    return createDefault();
}

// static
sp<const AudioPolicyConfig> AudioPolicyConfig::loadFromApmXmlConfigWithFallback(
        const std::string& xmlFilePath) {
    const std::string filePath =
            xmlFilePath.empty() ? audio_get_audio_policy_config_file() : xmlFilePath;
    auto config = sp<AudioPolicyConfig>::make();
    if (status_t status = config->loadFromXml(filePath, false /*forVts*/); status == NO_ERROR) {
        return config;
    }
    return createDefault();
}

// static
sp<AudioPolicyConfig> AudioPolicyConfig::createWritableForTests() {
    return sp<AudioPolicyConfig>::make();
}

// static
error::Result<sp<AudioPolicyConfig>> AudioPolicyConfig::loadFromCustomXmlConfigForTests(
        const std::string& xmlFilePath) {
    auto config = sp<AudioPolicyConfig>::make();
    if (status_t status = config->loadFromXml(xmlFilePath, false /*forVts*/); status == NO_ERROR) {
        return config;
    } else {
        return base::unexpected(status);
    }
}

// static
error::Result<sp<AudioPolicyConfig>> AudioPolicyConfig::loadFromCustomXmlConfigForVtsTests(
        const std::string& configPath, const std::string& xmlFileName) {
    auto filePath = configPath;
    if (filePath.empty()) {
        for (const auto& location : audio_get_configuration_paths()) {
            std::string path = location + '/' + xmlFileName;
            if (access(path.c_str(), F_OK) == 0) {
                filePath = location;
                break;
            }
        }
    }
    if (filePath.empty()) {
        ALOGE("Did not find a config file \"%s\" among known config paths", xmlFileName.c_str());
        return base::unexpected(BAD_VALUE);
    }
    auto config = sp<AudioPolicyConfig>::make();
    if (status_t status = config->loadFromXml(filePath + "/" + xmlFileName, true /*forVts*/);
            status == NO_ERROR) {
        return config;
    } else {
        return base::unexpected(status);
    }
}

void AudioPolicyConfig::augmentData() {
    // If microphones address is empty, set it according to device type
    for (size_t i = 0; i < mInputDevices.size(); i++) {
        if (mInputDevices[i]->address().empty()) {
            if (mInputDevices[i]->type() == AUDIO_DEVICE_IN_BUILTIN_MIC) {
                mInputDevices[i]->setAddress(AUDIO_BOTTOM_MICROPHONE_ADDRESS);
            } else if (mInputDevices[i]->type() == AUDIO_DEVICE_IN_BACK_MIC) {
                mInputDevices[i]->setAddress(AUDIO_BACK_MICROPHONE_ADDRESS);
            }
        }
    }
}

status_t AudioPolicyConfig::loadFromAidl(const media::AudioPolicyConfig& aidl) {
    RETURN_STATUS_IF_ERROR(aidl2legacy_AudioHwModules_HwModuleCollection(aidl.modules,
                    &mHwModules, &mInputDevices, &mOutputDevices, &mDefaultOutputDevice));
    mIsCallScreenModeSupported = std::find(aidl.supportedModes.begin(), aidl.supportedModes.end(),
            media::audio::common::AudioMode::CALL_SCREEN) != aidl.supportedModes.end();
    mSurroundFormats = VALUE_OR_RETURN_STATUS(
            aidl2legacy_SurroundSoundConfig_SurroundFormats(aidl.surroundSoundConfig));
    mSource = kAidlConfigSource;
    // No need to augmentData() as AIDL HAL must provide correct mic addresses.
    return NO_ERROR;
}

status_t AudioPolicyConfig::loadFromXml(const std::string& xmlFilePath, bool forVts) {
    if (xmlFilePath.empty()) {
        ALOGE("Audio policy configuration file name is empty");
        return BAD_VALUE;
    }
    status_t status = forVts ? deserializeAudioPolicyFileForVts(xmlFilePath.c_str(), this)
            : deserializeAudioPolicyFile(xmlFilePath.c_str(), this);
    if (status == NO_ERROR) {
        mSource = xmlFilePath;
        augmentData();
    } else {
        ALOGE("Could not load audio policy from the configuration file \"%s\": %d",
                xmlFilePath.c_str(), status);
    }
    return status;
}

void AudioPolicyConfig::setDefault() {
    mSource = kDefaultConfigSource;
    mEngineLibraryNameSuffix = kDefaultEngineLibraryNameSuffix;

    mDefaultOutputDevice = new DeviceDescriptor(AUDIO_DEVICE_OUT_SPEAKER);
    mDefaultOutputDevice->addAudioProfile(AudioProfile::createFullDynamic(gDynamicFormat));
    sp<DeviceDescriptor> defaultInputDevice = new DeviceDescriptor(AUDIO_DEVICE_IN_BUILTIN_MIC);
    defaultInputDevice->addAudioProfile(AudioProfile::createFullDynamic(gDynamicFormat));
    sp<AudioProfile> micProfile = new AudioProfile(
            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_MONO, 8000);
    defaultInputDevice->addAudioProfile(micProfile);
    mOutputDevices.add(mDefaultOutputDevice);
    mInputDevices.add(defaultInputDevice);

    sp<HwModule> module = new HwModule(
            AUDIO_HARDWARE_MODULE_ID_PRIMARY, AUDIO_DEVICE_API_VERSION_2_0);
    mHwModules.add(module);

    sp<OutputProfile> outProfile = new OutputProfile("primary");
    outProfile->addAudioProfile(
            new AudioProfile(AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO, 44100));
    outProfile->addSupportedDevice(mDefaultOutputDevice);
    outProfile->setFlags(AUDIO_OUTPUT_FLAG_PRIMARY);
    module->addOutputProfile(outProfile);

    sp<InputProfile> inProfile = new InputProfile("primary");
    inProfile->addAudioProfile(micProfile);
    inProfile->addSupportedDevice(defaultInputDevice);
    module->addInputProfile(inProfile);

    setDefaultSurroundFormats();
    augmentData();
}

void AudioPolicyConfig::setDefaultSurroundFormats() {
    mSurroundFormats = {
        {AUDIO_FORMAT_AC3, {}},
        {AUDIO_FORMAT_E_AC3, {}},
        {AUDIO_FORMAT_DTS, {}},
        {AUDIO_FORMAT_DTS_HD, {}},
        {AUDIO_FORMAT_DTS_HD_MA, {}},
        {AUDIO_FORMAT_DTS_UHD, {}},
        {AUDIO_FORMAT_DTS_UHD_P2, {}},
        {AUDIO_FORMAT_AAC_LC, {
                AUDIO_FORMAT_AAC_HE_V1, AUDIO_FORMAT_AAC_HE_V2, AUDIO_FORMAT_AAC_ELD,
                AUDIO_FORMAT_AAC_XHE}},
        {AUDIO_FORMAT_DOLBY_TRUEHD, {}},
        {AUDIO_FORMAT_E_AC3_JOC, {}},
        {AUDIO_FORMAT_AC4, {}}};
}

} // namespace android
