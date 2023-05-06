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

#pragma once

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <DeviceDescriptor.h>
#include <HwModule.h>
#include <android/media/AudioPolicyConfig.h>
#include <error/Result.h>
#include <utils/StrongPointer.h>
#include <utils/RefBase.h>

namespace android {

// This class gathers together various bits of AudioPolicyManager configuration. It can be filled
// out either as a result of parsing the audio_policy_configuration.xml file, from the HAL data, or
// to default fallback data.
//
// The data in this class is immutable once loaded, this is why a pointer to a const is returned
// from the factory methods. However, this does not prevent modifications of data bits that
// are held inside collections, for example, individual modules, devices, etc.
class AudioPolicyConfig : public RefBase
{
public:
    // Surround formats, with an optional list of subformats that are equivalent from users' POV.
    using SurroundFormats = std::unordered_map<audio_format_t, std::unordered_set<audio_format_t>>;

    // The source used to indicate the configuration from the AIDL HAL.
    static const constexpr char* const kAidlConfigSource = "AIDL HAL";
    // The source used to indicate the default fallback configuration.
    static const constexpr char* const kDefaultConfigSource = "AudioPolicyConfig::setDefault";
    // The suffix of the "engine default" implementation shared library name.
    static const constexpr char* const kDefaultEngineLibraryNameSuffix = "default";

    // Creates the default (fallback) configuration.
    static sp<const AudioPolicyConfig> createDefault();
    // Attempts to load the configuration from the AIDL config falls back to default on failure.
    static sp<const AudioPolicyConfig> loadFromApmAidlConfigWithFallback(
            const media::AudioPolicyConfig& aidl);
    // Attempts to load the configuration from the XML file, falls back to default on failure.
    // If the XML file path is not provided, uses `audio_get_audio_policy_config_file` function.
    static sp<const AudioPolicyConfig> loadFromApmXmlConfigWithFallback(
            const std::string& xmlFilePath = "");
    // The factory method to use in APM tests which craft the configuration manually.
    static sp<AudioPolicyConfig> createWritableForTests();
    // The factory method to use in APM tests which use a custom XML file.
    static error::Result<sp<AudioPolicyConfig>> loadFromCustomXmlConfigForTests(
            const std::string& xmlFilePath);
    // The factory method to use in VTS tests. If the 'configPath' is empty,
    // it is determined automatically from the list of known config paths.
    static error::Result<sp<AudioPolicyConfig>> loadFromCustomXmlConfigForVtsTests(
            const std::string& configPath, const std::string& xmlFileName);

    ~AudioPolicyConfig() = default;

    const std::string& getSource() const {
        return mSource;
    }
    void setSource(const std::string& file) {
        mSource = file;
    }

    const std::string& getEngineLibraryNameSuffix() const {
        return mEngineLibraryNameSuffix;
    }
    void setEngineLibraryNameSuffix(const std::string& suffix) {
        mEngineLibraryNameSuffix = suffix;
    }

    const HwModuleCollection& getHwModules() const { return mHwModules; }
    void setHwModules(const HwModuleCollection &hwModules)
    {
        mHwModules = hwModules;
    }

    const DeviceVector& getInputDevices() const
    {
        return mInputDevices;
    }
    const DeviceVector& getOutputDevices() const
    {
        return mOutputDevices;
    }
    void addDevice(const sp<DeviceDescriptor> &device)
    {
        if (audio_is_output_device(device->type())) {
            mOutputDevices.add(device);
        } else if (audio_is_input_device(device->type())) {
            mInputDevices.add(device);
        }
    }
    void addInputDevices(const DeviceVector &inputDevices)
    {
        mInputDevices.add(inputDevices);
    }
    void addOutputDevices(const DeviceVector &outputDevices)
    {
        mOutputDevices.add(outputDevices);
    }

    const sp<DeviceDescriptor>& getDefaultOutputDevice() const { return mDefaultOutputDevice; }
    void setDefaultOutputDevice(const sp<DeviceDescriptor> &defaultDevice)
    {
        mDefaultOutputDevice = defaultDevice;
    }

    bool isCallScreenModeSupported() const { return mIsCallScreenModeSupported; }
    void setCallScreenModeSupported(bool isCallScreenModeSupported)
    {
        mIsCallScreenModeSupported = isCallScreenModeSupported;
    }

    const SurroundFormats &getSurroundFormats() const
    {
        return mSurroundFormats;
    }
    void setDefaultSurroundFormats();
    void setSurroundFormats(const SurroundFormats &surroundFormats)
    {
        mSurroundFormats = surroundFormats;
    }

    void setDefault();

private:
    friend class sp<AudioPolicyConfig>;

    AudioPolicyConfig() = default;

    void augmentData();
    status_t loadFromAidl(const media::AudioPolicyConfig& aidl);
    status_t loadFromXml(const std::string& xmlFilePath, bool forVts);

    std::string mSource;  // Not kDefaultConfigSource. Empty source means an empty config.
    std::string mEngineLibraryNameSuffix = kDefaultEngineLibraryNameSuffix;
    HwModuleCollection mHwModules; /**< Collection of Module, with Profiles, i.e. Mix Ports. */
    DeviceVector mOutputDevices;  // Attached output devices.
    DeviceVector mInputDevices;   // Attached input devices.
    sp<DeviceDescriptor> mDefaultOutputDevice;
    bool mIsCallScreenModeSupported = false;
    SurroundFormats mSurroundFormats;
};

} // namespace android
