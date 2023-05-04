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
#include <media/AudioProfile.h>
#include <system/audio.h>
#include <system/audio_config.h>
#include <utils/Log.h>

namespace android {

// static
sp<const AudioPolicyConfig> AudioPolicyConfig::createDefault() {
    auto config = sp<AudioPolicyConfig>::make();
    config->setDefault();
    return config;
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

    sp<HwModule> module = new HwModule(AUDIO_HARDWARE_MODULE_ID_PRIMARY, 2 /*halVersionMajor*/);
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
