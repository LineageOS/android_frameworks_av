/******************************************************************************
 *
 * Copyright (C) 2021 The Android Open Source Project
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
 ******************************************************************************/
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>
#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <Serializer.h>
#include <android-base/file.h>
#include <android/content/AttributionSourceState.h>
#include <libxml/parser.h>
#include <libxml/xinclude.h>
#include <media/AudioPolicy.h>
#include <media/PatchBuilder.h>
#include <media/RecordingActivityTracker.h>

#include <AudioPolicyInterface.h>
#include <android_audio_policy_configuration_V7_0-enums.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <tests/AudioPolicyManagerTestClient.h>
#include <tests/AudioPolicyTestClient.h>
#include <tests/AudioPolicyTestManager.h>
#include <xsdc/XsdcSupport.h>

using namespace android;

namespace xsd {
using namespace ::android::audio::policy::configuration::V7_0;
}

using content::AttributionSourceState;

static const std::vector<audio_format_t> kAudioFormats = [] {
    std::vector<audio_format_t> result;
    for (const auto enumVal : xsdc_enum_range<xsd::AudioFormat>{}) {
        audio_format_t audioFormatHal;
        std::string audioFormat = toString(enumVal);
        if (audio_format_from_string(audioFormat.c_str(), &audioFormatHal)) {
            result.push_back(audioFormatHal);
        }
    }
    return result;
}();

static const std::vector<audio_channel_mask_t> kAudioChannelOutMasks = [] {
    std::vector<audio_channel_mask_t> result;
    for (const auto enumVal : xsdc_enum_range<xsd::AudioChannelMask>{}) {
        audio_channel_mask_t audioChannelMaskHal;
        std::string audioChannelMask = toString(enumVal);
        if (enumVal != xsd::AudioChannelMask::AUDIO_CHANNEL_NONE &&
            audioChannelMask.find("_IN_") == std::string::npos &&
            audio_channel_mask_from_string(audioChannelMask.c_str(), &audioChannelMaskHal)) {
            result.push_back(audioChannelMaskHal);
        }
    }
    return result;
}();

static const std::vector<audio_channel_mask_t> kAudioChannelInMasks = [] {
    std::vector<audio_channel_mask_t> result;
    for (const auto enumVal : xsdc_enum_range<xsd::AudioChannelMask>{}) {
        audio_channel_mask_t audioChannelMaskHal;
        std::string audioChannelMask = toString(enumVal);
        if (enumVal != xsd::AudioChannelMask::AUDIO_CHANNEL_NONE &&
            audioChannelMask.find("_OUT_") == std::string::npos &&
            audio_channel_mask_from_string(audioChannelMask.c_str(), &audioChannelMaskHal)) {
            result.push_back(audioChannelMaskHal);
        }
    }
    return result;
}();

static const std::vector<audio_output_flags_t> kAudioOutputFlags = [] {
    std::vector<audio_output_flags_t> result;
    for (const auto enumVal : xsdc_enum_range<xsd::AudioInOutFlag>{}) {
        audio_output_flags_t audioOutputFlagHal;
        std::string audioOutputFlag = toString(enumVal);
        if (audioOutputFlag.find("_OUTPUT_") != std::string::npos &&
            audio_output_flag_from_string(audioOutputFlag.c_str(), &audioOutputFlagHal)) {
            result.push_back(audioOutputFlagHal);
        }
    }
    return result;
}();

static const std::vector<audio_devices_t> kAudioDevices = [] {
    std::vector<audio_devices_t> result;
    for (const auto enumVal : xsdc_enum_range<xsd::AudioDevice>{}) {
        audio_devices_t audioDeviceHal;
        std::string audioDevice = toString(enumVal);
        if (audio_device_from_string(audioDevice.c_str(), &audioDeviceHal)) {
            result.push_back(audioDeviceHal);
        }
    }
    return result;
}();

static const std::vector<audio_usage_t> kAudioUsages = [] {
    std::vector<audio_usage_t> result;
    for (const auto enumVal : xsdc_enum_range<xsd::AudioUsage>{}) {
        audio_usage_t audioUsageHal;
        std::string audioUsage = toString(enumVal);
        if (audio_usage_from_string(audioUsage.c_str(), &audioUsageHal)) {
            result.push_back(audioUsageHal);
        }
    }
    return result;
}();

static const std::vector<audio_source_t> kAudioSources = [] {
    std::vector<audio_source_t> result;
    for (const auto enumVal : xsdc_enum_range<xsd::AudioSource>{}) {
        audio_source_t audioSourceHal;
        std::string audioSource = toString(enumVal);
        if (audio_source_from_string(audioSource.c_str(), &audioSourceHal)) {
            result.push_back(audioSourceHal);
        }
    }
    return result;
}();

static const std::vector<audio_content_type_t> kAudioContentTypes = [] {
    std::vector<audio_content_type_t> result;
    for (const auto enumVal : xsdc_enum_range<xsd::AudioContentType>{}) {
        audio_content_type_t audioContentTypeHal;
        std::string audioContentType = toString(enumVal);
        if (audio_content_type_from_string(audioContentType.c_str(), &audioContentTypeHal)) {
            result.push_back(audioContentTypeHal);
        }
    }
    return result;
}();

std::vector<int> kMixTypes = {MIX_TYPE_PLAYERS, MIX_TYPE_RECORDERS};

std::vector<int> kMixRouteFlags = {MIX_ROUTE_FLAG_RENDER, MIX_ROUTE_FLAG_LOOP_BACK,
                                   MIX_ROUTE_FLAG_LOOP_BACK_AND_RENDER, MIX_ROUTE_FLAG_ALL};

std::vector<audio_flags_mask_t> kAudioFlagMasks = {
    AUDIO_FLAG_NONE,           AUDIO_FLAG_AUDIBILITY_ENFORCED,
    AUDIO_FLAG_SECURE,         AUDIO_FLAG_SCO,
    AUDIO_FLAG_BEACON,         AUDIO_FLAG_HW_AV_SYNC,
    AUDIO_FLAG_HW_HOTWORD,     AUDIO_FLAG_BYPASS_INTERRUPTION_POLICY,
    AUDIO_FLAG_BYPASS_MUTE,    AUDIO_FLAG_LOW_LATENCY,
    AUDIO_FLAG_DEEP_BUFFER,    AUDIO_FLAG_NO_MEDIA_PROJECTION,
    AUDIO_FLAG_MUTE_HAPTIC,    AUDIO_FLAG_NO_SYSTEM_CAPTURE,
    AUDIO_FLAG_CAPTURE_PRIVATE};

std::vector<audio_policy_dev_state_t> kAudioPolicyDeviceStates = {
    AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
    AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
    AUDIO_POLICY_DEVICE_STATE_CNT,
};

std::vector<uint32_t> kSamplingRates = {8000, 16000, 44100, 48000, 88200, 96000};

template <typename T>
T getValueFromVector(FuzzedDataProvider *fdp, std::vector<T> arr) {
    if (fdp->ConsumeBool()) {
        return arr[fdp->ConsumeIntegralInRange<int32_t>(0, arr.size() - 1)];
    } else {
        return (T)fdp->ConsumeIntegral<uint32_t>();
    }
}

class AudioPolicyManagerFuzzer {
   public:
    explicit AudioPolicyManagerFuzzer(FuzzedDataProvider *fdp);
    virtual ~AudioPolicyManagerFuzzer() = default;
    virtual bool initialize();
    virtual void SetUpManagerConfig();
    bool getOutputForAttr(audio_port_handle_t *selectedDeviceId, audio_format_t format,
                          audio_channel_mask_t channelMask, int sampleRate,
                          audio_output_flags_t flags = AUDIO_OUTPUT_FLAG_NONE,
                          audio_io_handle_t *output = nullptr,
                          audio_port_handle_t *portId = nullptr, audio_attributes_t attr = {});
    bool getInputForAttr(const audio_attributes_t &attr, audio_unique_id_t riid,
                         audio_port_handle_t *selectedDeviceId, audio_format_t format,
                         audio_channel_mask_t channelMask, int sampleRate,
                         audio_input_flags_t flags = AUDIO_INPUT_FLAG_NONE,
                         audio_port_handle_t *portId = nullptr);
    bool findDevicePort(audio_port_role_t role, audio_devices_t deviceType,
                        const std::string &address, audio_port_v7 *foundPort);
    static audio_port_handle_t getDeviceIdFromPatch(const struct audio_patch *patch);
    audio_patch createFuzzedPatch();
    void fuzzPatchCreation();
    virtual void process();

   protected:
    std::unique_ptr<AudioPolicyManagerTestClient> mClient{new AudioPolicyManagerTestClient};
    std::unique_ptr<AudioPolicyTestManager> mManager{new AudioPolicyTestManager(mClient.get())};
    FuzzedDataProvider *mFdp;
};

AudioPolicyManagerFuzzer::AudioPolicyManagerFuzzer(FuzzedDataProvider *fdp)
        : mFdp(fdp) {}

bool AudioPolicyManagerFuzzer::initialize() {
    if (mFdp->remaining_bytes() < 1) {
        return false;
    }
    // init code
    SetUpManagerConfig();

    if (mManager->initialize() != NO_ERROR) {
        return false;
    }
    if (mManager->initCheck() != NO_ERROR) {
        return false;
    }
    return true;
}

void AudioPolicyManagerFuzzer::SetUpManagerConfig() { mManager->getConfig().setDefault(); }

bool AudioPolicyManagerFuzzer::getOutputForAttr(
    audio_port_handle_t *selectedDeviceId, audio_format_t format, audio_channel_mask_t channelMask,
    int sampleRate, audio_output_flags_t flags, audio_io_handle_t *output,
    audio_port_handle_t *portId, audio_attributes_t attr) {
    audio_io_handle_t localOutput;
    if (!output) output = &localOutput;
    *output = AUDIO_IO_HANDLE_NONE;
    audio_stream_type_t stream = AUDIO_STREAM_DEFAULT;
    audio_config_t config = AUDIO_CONFIG_INITIALIZER;
    config.sample_rate = sampleRate;
    config.channel_mask = channelMask;
    config.format = format;
    audio_port_handle_t localPortId;
    if (!portId) portId = &localPortId;
    *portId = AUDIO_PORT_HANDLE_NONE;
    AudioPolicyInterface::output_type_t outputType;

    // TODO b/182392769: use attribution source util
    AttributionSourceState attributionSource;
    attributionSource.uid = 0;
    attributionSource.token = sp<BBinder>::make();
    if (mManager->getOutputForAttr(&attr, output, AUDIO_SESSION_NONE, &stream, attributionSource,
            &config, &flags, selectedDeviceId, portId, {}, &outputType) != OK) {
        return false;
    }
    if (*output == AUDIO_IO_HANDLE_NONE || *portId == AUDIO_PORT_HANDLE_NONE) {
        return false;
    }
    return true;
}

bool AudioPolicyManagerFuzzer::getInputForAttr(
    const audio_attributes_t &attr, audio_unique_id_t riid, audio_port_handle_t *selectedDeviceId,
    audio_format_t format, audio_channel_mask_t channelMask, int sampleRate,
    audio_input_flags_t flags, audio_port_handle_t *portId) {
    audio_io_handle_t input = AUDIO_IO_HANDLE_NONE;
    audio_config_base_t config = AUDIO_CONFIG_BASE_INITIALIZER;
    config.sample_rate = sampleRate;
    config.channel_mask = channelMask;
    config.format = format;
    audio_port_handle_t localPortId;
    if (!portId) portId = &localPortId;
    *portId = AUDIO_PORT_HANDLE_NONE;
    AudioPolicyInterface::input_type_t inputType;

    AttributionSourceState attributionSource;
    attributionSource.uid = 0;
    attributionSource.token = sp<BBinder>::make();
    if (mManager->getInputForAttr(&attr, &input, riid, AUDIO_SESSION_NONE, attributionSource,
            &config, flags, selectedDeviceId, &inputType, portId) != OK) {
        return false;
    }
    if (*portId == AUDIO_PORT_HANDLE_NONE || input == AUDIO_IO_HANDLE_NONE) {
        return false;
    }
    return true;
}

bool AudioPolicyManagerFuzzer::findDevicePort(audio_port_role_t role, audio_devices_t deviceType,
                                              const std::string &address,
                                              audio_port_v7 *foundPort) {
    uint32_t numPorts = 0;
    uint32_t generation1;
    status_t ret;

    ret = mManager->listAudioPorts(role, AUDIO_PORT_TYPE_DEVICE, &numPorts, nullptr, &generation1);
    if (ret != NO_ERROR) {
        return false;
    }

    uint32_t generation2;
    struct audio_port_v7 ports[numPorts];
    ret = mManager->listAudioPorts(role, AUDIO_PORT_TYPE_DEVICE, &numPorts, ports, &generation2);
    if (ret != NO_ERROR) {
        return false;
    }

    for (const auto &port : ports) {
        if (port.role == role && port.ext.device.type == deviceType &&
            (strncmp(port.ext.device.address, address.c_str(), AUDIO_DEVICE_MAX_ADDRESS_LEN) ==
             0)) {
            if (foundPort) *foundPort = port;
            return true;
        }
    }
    return false;
}

audio_port_handle_t AudioPolicyManagerFuzzer::getDeviceIdFromPatch(
    const struct audio_patch *patch) {
    if (patch->num_sources != 0 && patch->num_sinks != 0) {
        if (patch->sources[0].type == AUDIO_PORT_TYPE_MIX) {
            return patch->sinks[0].id;
        } else {
            return patch->sources[0].id;
        }
    }
    return AUDIO_PORT_HANDLE_NONE;
}

audio_patch AudioPolicyManagerFuzzer::createFuzzedPatch() {
    audio_patch patch{};
    patch.id = mFdp->ConsumeIntegral<uint32_t>();
    patch.num_sources = mFdp->ConsumeIntegralInRange(0, AUDIO_PATCH_PORTS_MAX);
    for (int i = 0; i < patch.num_sources; ++i) {
        audio_port_config config{};
        std::vector<uint8_t> bytes = mFdp->ConsumeBytes<uint8_t>(sizeof(config));
        memcpy(reinterpret_cast<uint8_t *>(&config), &bytes[0], bytes.size());
        patch.sources[i] = config;
    }
    patch.num_sinks = mFdp->ConsumeIntegralInRange(0, AUDIO_PATCH_PORTS_MAX);
    for (int i = 0; i < patch.num_sinks; ++i) {
        audio_port_config config{};
        std::vector<uint8_t> bytes = mFdp->ConsumeBytes<uint8_t>(sizeof(config));
        memcpy(reinterpret_cast<uint8_t *>(&config), &bytes[0], bytes.size());
        patch.sinks[i] = config;
    }
    return patch;
}

void AudioPolicyManagerFuzzer::fuzzPatchCreation() {
    if (mFdp->remaining_bytes()) {
        audio_patch_handle_t handle = AUDIO_PATCH_HANDLE_NONE;
        uid_t uid = mFdp->ConsumeIntegral<uint32_t>();

        // create a fuzzed patch
        handle = AUDIO_PATCH_HANDLE_NONE;
        audio_patch patch = createFuzzedPatch();
        uid = mFdp->ConsumeIntegral<uint32_t>();
        if (mManager->createAudioPatch(&patch, &handle, uid) == NO_ERROR) {
            mManager->releaseAudioPatch(handle, uid);
        }
    }
}

void AudioPolicyManagerFuzzer::process() {
    if (initialize()) {
        fuzzPatchCreation();
    }
}

class AudioPolicyManagerFuzzerWithConfigurationFile : public AudioPolicyManagerFuzzer {
   public:
    explicit AudioPolicyManagerFuzzerWithConfigurationFile(FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzer(fdp){};

   protected:
    void SetUpManagerConfig() override;
    virtual std::string getConfigFile();
    void traverseAndFuzzXML(xmlDocPtr pDoc, xmlNodePtr curr);
    std::string fuzzXML(std::string xmlPath);

    static inline const std::string sExecutableDir = base::GetExecutableDirectory() + "/";
    static inline const std::string sDefaultConfig =
            sExecutableDir + "data/test_audio_policy_configuration.xml";
    static inline const std::string sFuzzedConfig = sExecutableDir + "fuzzed.xml";;
};

std::string AudioPolicyManagerFuzzerWithConfigurationFile::getConfigFile() {
    return fuzzXML(sDefaultConfig);
}

void AudioPolicyManagerFuzzerWithConfigurationFile::SetUpManagerConfig() {
    deserializeAudioPolicyFile(getConfigFile().c_str(), &mManager->getConfig());
}

void AudioPolicyManagerFuzzerWithConfigurationFile::traverseAndFuzzXML(xmlDocPtr pDoc,
                                                                       xmlNodePtr curr) {
    if (curr == nullptr) {
        return;
    }

    xmlAttr *attribute = curr->properties;
    while (attribute) {
        if (!xmlStrcmp(attribute->name, reinterpret_cast<const xmlChar *>("format"))) {
            const char *newFormat =
                audio_format_to_string(getValueFromVector<audio_format_t>(mFdp, kAudioFormats));
            xmlSetProp(curr, attribute->name, reinterpret_cast<const xmlChar *>(newFormat));
        }
        if (!xmlStrcmp(attribute->name, reinterpret_cast<const xmlChar *>("flags"))) {
            std::string newFlag = "";
            uint16_t numFlags = std::max((uint16_t)1, mFdp->ConsumeIntegral<uint16_t>());
            for (uint16_t i = 0; i < numFlags; ++i) {
                newFlag += std::string(audio_output_flag_to_string(
                    getValueFromVector<audio_output_flags_t>(mFdp, kAudioOutputFlags)));
                if (i != (numFlags - 1)) {
                    newFlag += std::string("|");
                }
            }
            xmlSetProp(curr, attribute->name, reinterpret_cast<const xmlChar *>(newFlag.c_str()));
        }
        if (!xmlStrcmp(attribute->name, reinterpret_cast<const xmlChar *>("samplingRates"))) {
            std::string newRate = "";
            uint16_t numRates = std::max((uint16_t)1, mFdp->ConsumeIntegral<uint16_t>());
            for (uint16_t i = 0; i < numRates; ++i) {
                newRate += std::to_string(getValueFromVector<uint32_t>(mFdp, kSamplingRates));
                if (i != (numRates - 1)) {
                    newRate += std::string(",");
                }
            }
            xmlSetProp(curr, attribute->name, reinterpret_cast<const xmlChar *>(newRate.c_str()));
        }
        if (!xmlStrcmp(attribute->name, reinterpret_cast<const xmlChar *>("channelMasks"))) {
            int isOutMask = -1;
            char *value =
                reinterpret_cast<char *>(xmlNodeListGetString(pDoc, attribute->children, 1));
            if (std::string(value).find(std::string("_OUT_")) != std::string::npos) {
                // OUT mask
                isOutMask = 1;
            } else if (std::string(value).find(std::string("_IN_")) != std::string::npos) {
                // IN mask
                isOutMask = 0;
            }
            if (isOutMask != -1) {
                std::string newMask = "";
                uint16_t numMasks = std::max((uint16_t)1, mFdp->ConsumeIntegral<uint16_t>());
                for (uint16_t i = 0; i < numMasks; ++i) {
                    if (isOutMask) {
                        newMask += std::string(audio_channel_out_mask_to_string(
                            getValueFromVector<audio_channel_mask_t>(mFdp, kAudioChannelOutMasks)));
                    } else {
                        newMask += std::string(audio_channel_in_mask_to_string(
                            getValueFromVector<audio_channel_mask_t>(mFdp, kAudioChannelInMasks)));
                    }
                    if (i != (numMasks - 1)) {
                        newMask += std::string(",");
                    }
                }
                xmlSetProp(curr, attribute->name,
                           reinterpret_cast<const xmlChar *>(newMask.c_str()));
            }
            xmlFree(value);
        }
        attribute = attribute->next;
    }

    curr = curr->xmlChildrenNode;
    while (curr != nullptr) {
        traverseAndFuzzXML(pDoc, curr);
        curr = curr->next;
    }
}

std::string AudioPolicyManagerFuzzerWithConfigurationFile::fuzzXML(std::string xmlPath) {
    std::string outPath = sFuzzedConfig;

    // Load in the xml file from disk
    xmlDocPtr pDoc = xmlParseFile(xmlPath.c_str());
    xmlNodePtr root = xmlDocGetRootElement(pDoc);

    traverseAndFuzzXML(pDoc, root);

    // Save the document back out to disk.
    xmlSaveFileEnc(outPath.c_str(), pDoc, "UTF-8");
    xmlFreeDoc(pDoc);

    return outPath;
}

class AudioPolicyManagerFuzzerMsd : public AudioPolicyManagerFuzzerWithConfigurationFile {
   public:
    explicit AudioPolicyManagerFuzzerMsd(FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzerWithConfigurationFile(fdp) {}

   protected:
    std::string getConfigFile() override;

    static inline const std::string sMsdConfig =
            sExecutableDir + "data/test_audio_policy_msd_configuration.xml";
};

std::string AudioPolicyManagerFuzzerMsd::getConfigFile() { return fuzzXML(sMsdConfig); }

using PolicyMixTuple = std::tuple<audio_usage_t, audio_source_t, uint32_t>;

class AudioPolicyManagerFuzzerDynamicPolicy : public AudioPolicyManagerFuzzerWithConfigurationFile {
   public:
    explicit AudioPolicyManagerFuzzerDynamicPolicy(FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzerWithConfigurationFile(fdp){};
    ~AudioPolicyManagerFuzzerDynamicPolicy() override;
    void process() override;

   protected:
    status_t addPolicyMix(int mixType, int mixFlag, audio_devices_t deviceType,
                          std::string mixAddress, const audio_config_t &audioConfig,
                          const std::vector<PolicyMixTuple> &rules);
    void clearPolicyMix();
    void registerPolicyMixes();
    void unregisterPolicyMixes();

    Vector<AudioMix> mAudioMixes;
    const std::string mMixAddress = "remote_submix_media";
};

AudioPolicyManagerFuzzerDynamicPolicy::~AudioPolicyManagerFuzzerDynamicPolicy() {
    clearPolicyMix();
}

status_t AudioPolicyManagerFuzzerDynamicPolicy::addPolicyMix(
    int mixType, int mixFlag, audio_devices_t deviceType, std::string mixAddress,
    const audio_config_t &audioConfig, const std::vector<PolicyMixTuple> &rules) {
    Vector<AudioMixMatchCriterion> myMixMatchCriteria;

    for (const auto &rule : rules) {
        myMixMatchCriteria.add(
            AudioMixMatchCriterion(std::get<0>(rule), std::get<1>(rule), std::get<2>(rule)));
    }

    AudioMix myAudioMix(myMixMatchCriteria, mixType, audioConfig, mixFlag,
                        String8(mixAddress.c_str()), 0);
    myAudioMix.mDeviceType = deviceType;
    // Clear mAudioMix before add new one to make sure we don't add already existing mixes.
    mAudioMixes.clear();
    mAudioMixes.add(myAudioMix);

    // As the policy mixes registration may fail at some case,
    // caller need to check the returned status.
    status_t ret = mManager->registerPolicyMixes(mAudioMixes);
    return ret;
}

void AudioPolicyManagerFuzzerDynamicPolicy::clearPolicyMix() {
    if (mManager != nullptr) {
        mManager->unregisterPolicyMixes(mAudioMixes);
    }
    mAudioMixes.clear();
}

void AudioPolicyManagerFuzzerDynamicPolicy::registerPolicyMixes() {
    const uint32_t numPolicies = mFdp->ConsumeIntegralInRange<uint32_t>(1, MAX_MIXES_PER_POLICY);

    for (int i = 0; i < numPolicies; ++i) {
        audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
        audioConfig.channel_mask = getValueFromVector<audio_channel_mask_t>(
            mFdp, mFdp->ConsumeBool() ? kAudioChannelInMasks : kAudioChannelOutMasks);
        audioConfig.format = getValueFromVector<audio_format_t>(mFdp, kAudioFormats);
        audioConfig.sample_rate = getValueFromVector<uint32_t>(mFdp, kSamplingRates);
        addPolicyMix(getValueFromVector<int>(mFdp, kMixTypes),
                     getValueFromVector<int>(mFdp, kMixRouteFlags),
                     getValueFromVector<audio_devices_t>(mFdp, kAudioDevices), "", audioConfig,
                     std::vector<PolicyMixTuple>());
    }
}

void AudioPolicyManagerFuzzerDynamicPolicy::unregisterPolicyMixes() {
    mManager->unregisterPolicyMixes(mAudioMixes);
}

void AudioPolicyManagerFuzzerDynamicPolicy::process() {
    if (initialize()) {
        registerPolicyMixes();
        fuzzPatchCreation();
        unregisterPolicyMixes();
    }
}

class AudioPolicyManagerFuzzerDPNoRemoteSubmixModule
    : public AudioPolicyManagerFuzzerDynamicPolicy {
   public:
    explicit AudioPolicyManagerFuzzerDPNoRemoteSubmixModule(FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzerDynamicPolicy(fdp){};

   protected:
    std::string getConfigFile() override;

    static inline const std::string sPrimaryOnlyConfig =
            sExecutableDir + "data/test_audio_policy_primary_only_configuration.xml";
};

std::string AudioPolicyManagerFuzzerDPNoRemoteSubmixModule::getConfigFile() {
    return fuzzXML(sPrimaryOnlyConfig);
}

class AudioPolicyManagerFuzzerDPPlaybackReRouting : public AudioPolicyManagerFuzzerDynamicPolicy {
   public:
    explicit AudioPolicyManagerFuzzerDPPlaybackReRouting(FuzzedDataProvider *fdp);
    ~AudioPolicyManagerFuzzerDPPlaybackReRouting() override;
    void process() override;

   protected:
    bool initialize() override;
    void playBackReRouting();

    std::unique_ptr<RecordingActivityTracker> mTracker;

    std::vector<PolicyMixTuple> mUsageRules = {
        {AUDIO_USAGE_MEDIA, AUDIO_SOURCE_DEFAULT, RULE_MATCH_ATTRIBUTE_USAGE},
        {AUDIO_USAGE_ALARM, AUDIO_SOURCE_DEFAULT, RULE_MATCH_ATTRIBUTE_USAGE}};

    struct audio_port_v7 mInjectionPort;
    audio_port_handle_t mPortId = AUDIO_PORT_HANDLE_NONE;
    audio_config_t mAudioConfig;
};

AudioPolicyManagerFuzzerDPPlaybackReRouting::AudioPolicyManagerFuzzerDPPlaybackReRouting(
        FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzerDynamicPolicy(fdp) {
    const uint32_t numRules = mFdp->ConsumeIntegralInRange<uint32_t>(1, 10);
    for (int i = 0; i < numRules; ++i) {
        PolicyMixTuple rule = {getValueFromVector<audio_usage_t>(mFdp, kAudioUsages),
                               getValueFromVector<audio_source_t>(mFdp, kAudioSources),
                               RULE_MATCH_ATTRIBUTE_USAGE};
        mUsageRules.push_back(rule);
    }
}

AudioPolicyManagerFuzzerDPPlaybackReRouting::~AudioPolicyManagerFuzzerDPPlaybackReRouting() {
    mManager->stopInput(mPortId);
}

bool AudioPolicyManagerFuzzerDPPlaybackReRouting::initialize() {
    if (!AudioPolicyManagerFuzzerDynamicPolicy::initialize()) {
        return false;
    }
    mTracker.reset(new RecordingActivityTracker());

    mAudioConfig = AUDIO_CONFIG_INITIALIZER;
    mAudioConfig.channel_mask =
        getValueFromVector<audio_channel_mask_t>(mFdp, kAudioChannelOutMasks);
    mAudioConfig.format = getValueFromVector<audio_format_t>(mFdp, kAudioFormats);
    mAudioConfig.sample_rate = getValueFromVector<uint32_t>(mFdp, kSamplingRates);
    status_t ret = addPolicyMix(getValueFromVector<int>(mFdp, kMixTypes),
                                getValueFromVector<int>(mFdp, kMixRouteFlags),
                                getValueFromVector<audio_devices_t>(mFdp, kAudioDevices),
                                mMixAddress, mAudioConfig, mUsageRules);
    if (ret != NO_ERROR) {
        return false;
    }

    struct audio_port_v7 extractionPort;
    findDevicePort(AUDIO_PORT_ROLE_SOURCE, getValueFromVector<audio_devices_t>(mFdp, kAudioDevices),
                   mMixAddress, &extractionPort);

    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_source_t source = getValueFromVector<audio_source_t>(mFdp, kAudioSources);
    audio_attributes_t attr = {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, source,
                               AUDIO_FLAG_NONE, ""};
    std::string tags = "addr=" + mMixAddress;
    strncpy(attr.tags, tags.c_str(), AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1);
    getInputForAttr(attr, mTracker->getRiid(), &selectedDeviceId, mAudioConfig.format,
                    mAudioConfig.channel_mask, mAudioConfig.sample_rate, AUDIO_INPUT_FLAG_NONE,
                    &mPortId);

    ret = mManager->startInput(mPortId);
    if (ret != NO_ERROR) {
        return false;
    }
    if (!findDevicePort(AUDIO_PORT_ROLE_SINK,
                        getValueFromVector<audio_devices_t>(mFdp, kAudioDevices), mMixAddress,
                        &mInjectionPort)) {
        return false;
    }

    return true;
}

void AudioPolicyManagerFuzzerDPPlaybackReRouting::playBackReRouting() {
    const uint32_t numTestCases = mFdp->ConsumeIntegralInRange<uint32_t>(1, 10);
    for (int i = 0; i < numTestCases; ++i) {
        audio_attributes_t attr;
        attr.content_type = getValueFromVector<audio_content_type_t>(mFdp, kAudioContentTypes);
        attr.usage = getValueFromVector<audio_usage_t>(mFdp, kAudioUsages);
        attr.source = getValueFromVector<audio_source_t>(mFdp, kAudioSources);
        attr.flags = getValueFromVector<audio_flags_mask_t>(mFdp, kAudioFlagMasks);
        std::string tags(mFdp->ConsumeBool() ? "" : "addr=remote_submix_media");
        strncpy(attr.tags, tags.c_str(), AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1);

        audio_port_handle_t playbackRoutedPortId = AUDIO_PORT_HANDLE_NONE;
        getOutputForAttr(&playbackRoutedPortId, mAudioConfig.format, mAudioConfig.channel_mask,
                         mAudioConfig.sample_rate, AUDIO_OUTPUT_FLAG_NONE, nullptr /*output*/,
                         nullptr /*portId*/, attr);
    }
}

void AudioPolicyManagerFuzzerDPPlaybackReRouting::process() {
    if (initialize()) {
        playBackReRouting();
        registerPolicyMixes();
        fuzzPatchCreation();
        unregisterPolicyMixes();
    }
}

class AudioPolicyManagerFuzzerDPMixRecordInjection : public AudioPolicyManagerFuzzerDynamicPolicy {
   public:
    explicit AudioPolicyManagerFuzzerDPMixRecordInjection(FuzzedDataProvider *fdp);
    ~AudioPolicyManagerFuzzerDPMixRecordInjection() override;
    void process() override;

   protected:
    bool initialize() override;
    void recordingInjection();

    std::unique_ptr<RecordingActivityTracker> mTracker;

    std::vector<PolicyMixTuple> mSourceRules = {
        {AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_CAMCORDER, RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET},
        {AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_MIC, RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET},
        {AUDIO_USAGE_UNKNOWN, AUDIO_SOURCE_VOICE_COMMUNICATION,
         RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET}};

    struct audio_port_v7 mExtractionPort;
    audio_port_handle_t mPortId = AUDIO_PORT_HANDLE_NONE;
    audio_config_t mAudioConfig;
};

AudioPolicyManagerFuzzerDPMixRecordInjection::AudioPolicyManagerFuzzerDPMixRecordInjection(
        FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzerDynamicPolicy(fdp) {
    const uint32_t numRules = mFdp->ConsumeIntegralInRange<uint32_t>(1, 10);
    for (int i = 0; i < numRules; ++i) {
        PolicyMixTuple rule = {getValueFromVector<audio_usage_t>(mFdp, kAudioUsages),
                               getValueFromVector<audio_source_t>(mFdp, kAudioSources),
                               RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET};
        mSourceRules.push_back(rule);
    }
}

AudioPolicyManagerFuzzerDPMixRecordInjection::~AudioPolicyManagerFuzzerDPMixRecordInjection() {
    mManager->stopOutput(mPortId);
}

bool AudioPolicyManagerFuzzerDPMixRecordInjection::initialize() {
    if (!AudioPolicyManagerFuzzerDynamicPolicy::initialize()) {
        return false;
    }

    mTracker.reset(new RecordingActivityTracker());

    mAudioConfig = AUDIO_CONFIG_INITIALIZER;
    mAudioConfig.channel_mask =
        getValueFromVector<audio_channel_mask_t>(mFdp, kAudioChannelInMasks);
    mAudioConfig.format = getValueFromVector<audio_format_t>(mFdp, kAudioFormats);
    mAudioConfig.sample_rate = getValueFromVector<uint32_t>(mFdp, kSamplingRates);
    status_t ret = addPolicyMix(getValueFromVector<int>(mFdp, kMixTypes),
                                getValueFromVector<int>(mFdp, kMixRouteFlags),
                                getValueFromVector<audio_devices_t>(mFdp, kAudioDevices),
                                mMixAddress, mAudioConfig, mSourceRules);
    if (ret != NO_ERROR) {
        return false;
    }

    struct audio_port_v7 injectionPort;
    findDevicePort(AUDIO_PORT_ROLE_SINK, getValueFromVector<audio_devices_t>(mFdp, kAudioDevices),
                   mMixAddress, &injectionPort);

    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_usage_t usage = getValueFromVector<audio_usage_t>(mFdp, kAudioUsages);
    audio_attributes_t attr = {AUDIO_CONTENT_TYPE_UNKNOWN, usage, AUDIO_SOURCE_DEFAULT,
                               AUDIO_FLAG_NONE, ""};
    std::string tags = std::string("addr=") + mMixAddress;
    strncpy(attr.tags, tags.c_str(), AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1);
    getOutputForAttr(&selectedDeviceId, mAudioConfig.format, mAudioConfig.channel_mask,
                     mAudioConfig.sample_rate /*sampleRate*/, AUDIO_OUTPUT_FLAG_NONE,
                     nullptr /*output*/, &mPortId, attr);
    ret = mManager->startOutput(mPortId);
    if (ret != NO_ERROR) {
        return false;
    }
    getDeviceIdFromPatch(mClient->getLastAddedPatch());
    if (!findDevicePort(AUDIO_PORT_ROLE_SOURCE,
                        getValueFromVector<audio_devices_t>(mFdp, kAudioDevices), mMixAddress,
                        &mExtractionPort)) {
        return false;
    }

    return true;
}

void AudioPolicyManagerFuzzerDPMixRecordInjection::recordingInjection() {
    const uint32_t numTestCases = mFdp->ConsumeIntegralInRange<uint32_t>(1, 10);
    for (int i = 0; i < numTestCases; ++i) {
        audio_attributes_t attr;
        attr.content_type = getValueFromVector<audio_content_type_t>(mFdp, kAudioContentTypes);
        attr.usage = getValueFromVector<audio_usage_t>(mFdp, kAudioUsages);
        attr.source = getValueFromVector<audio_source_t>(mFdp, kAudioSources);
        attr.flags = getValueFromVector<audio_flags_mask_t>(mFdp, kAudioFlagMasks);
        std::string tags(mFdp->ConsumeBool() ? "" : "addr=remote_submix_media");
        strncpy(attr.tags, tags.c_str(), AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1);

        audio_port_handle_t captureRoutedPortId = AUDIO_PORT_HANDLE_NONE;
        audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
        getInputForAttr(attr, mTracker->getRiid(), &captureRoutedPortId, mAudioConfig.format,
                        mAudioConfig.channel_mask, mAudioConfig.sample_rate, AUDIO_INPUT_FLAG_NONE,
                        &portId);
    }
}

void AudioPolicyManagerFuzzerDPMixRecordInjection::process() {
    if (initialize()) {
        recordingInjection();
        registerPolicyMixes();
        fuzzPatchCreation();
        unregisterPolicyMixes();
    }
}

using DeviceConnectionTestParams =
    std::tuple<audio_devices_t /*type*/, std::string /*name*/, std::string /*address*/>;

class AudioPolicyManagerFuzzerDeviceConnection
    : public AudioPolicyManagerFuzzerWithConfigurationFile {
   public:
    explicit AudioPolicyManagerFuzzerDeviceConnection(FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzerWithConfigurationFile(fdp){};
    void process() override;

   protected:
    void setDeviceConnectionState();
    void explicitlyRoutingAfterConnection();
};

void AudioPolicyManagerFuzzerDeviceConnection::setDeviceConnectionState() {
    const uint32_t numTestCases = mFdp->ConsumeIntegralInRange<uint32_t>(1, 10);
    for (int i = 0; i < numTestCases; ++i) {
        const audio_devices_t type = getValueFromVector<audio_devices_t>(mFdp, kAudioDevices);
        const std::string name = mFdp->ConsumeRandomLengthString();
        const std::string address = mFdp->ConsumeRandomLengthString();
        mManager->setDeviceConnectionState(
            type, getValueFromVector<audio_policy_dev_state_t>(mFdp, kAudioPolicyDeviceStates),
            address.c_str(), name.c_str(), getValueFromVector<audio_format_t>(mFdp, kAudioFormats));
    }
}

void AudioPolicyManagerFuzzerDeviceConnection::explicitlyRoutingAfterConnection() {
    const uint32_t numTestCases = mFdp->ConsumeIntegralInRange<uint32_t>(1, 10);
    for (int i = 0; i < numTestCases; ++i) {
        const audio_devices_t type = getValueFromVector<audio_devices_t>(mFdp, kAudioDevices);
        const std::string name = mFdp->ConsumeRandomLengthString();
        const std::string address = mFdp->ConsumeRandomLengthString();
        mManager->setDeviceConnectionState(
            type, getValueFromVector<audio_policy_dev_state_t>(mFdp, kAudioPolicyDeviceStates),
            address.c_str(), name.c_str(), getValueFromVector<audio_format_t>(mFdp, kAudioFormats));

        audio_port_v7 devicePort;
        const audio_port_role_t role =
            audio_is_output_device(type) ? AUDIO_PORT_ROLE_SINK : AUDIO_PORT_ROLE_SOURCE;
        findDevicePort(role, type, address, &devicePort);

        audio_port_handle_t routedPortId = devicePort.id;
        // Try start input or output according to the device type
        if (audio_is_output_devices(type)) {
            getOutputForAttr(&routedPortId, getValueFromVector<audio_format_t>(mFdp, kAudioFormats),
                             getValueFromVector<audio_channel_mask_t>(mFdp, kAudioChannelOutMasks),
                             getValueFromVector<uint32_t>(mFdp, kSamplingRates),
                             AUDIO_OUTPUT_FLAG_NONE);
        } else if (audio_is_input_device(type)) {
            RecordingActivityTracker tracker;
            getInputForAttr({}, tracker.getRiid(), &routedPortId,
                            getValueFromVector<audio_format_t>(mFdp, kAudioFormats),
                            getValueFromVector<audio_channel_mask_t>(mFdp, kAudioChannelInMasks),
                            getValueFromVector<uint32_t>(mFdp, kSamplingRates),
                            AUDIO_INPUT_FLAG_NONE);
        }
    }
}

void AudioPolicyManagerFuzzerDeviceConnection::process() {
    if (initialize()) {
        setDeviceConnectionState();
        explicitlyRoutingAfterConnection();
        fuzzPatchCreation();
    }
}

class AudioPolicyManagerTVFuzzer : public AudioPolicyManagerFuzzerWithConfigurationFile {
   public:
    explicit AudioPolicyManagerTVFuzzer(FuzzedDataProvider *fdp)
        : AudioPolicyManagerFuzzerWithConfigurationFile(fdp){};
    void process() override;

   protected:
    std::string getConfigFile();
    void testHDMIPortSelection(audio_output_flags_t flags);

    static inline const std::string sTvConfig =
            AudioPolicyManagerTVFuzzer::sExecutableDir + "data/test_tv_apm_configuration.xml";
};

std::string AudioPolicyManagerTVFuzzer::getConfigFile() { return fuzzXML(sTvConfig); }

void AudioPolicyManagerTVFuzzer::testHDMIPortSelection(audio_output_flags_t flags) {
    audio_devices_t audioDevice = getValueFromVector<audio_devices_t>(mFdp, kAudioDevices);
    audio_format_t audioFormat = getValueFromVector<audio_format_t>(mFdp, kAudioFormats);
    status_t ret = mManager->setDeviceConnectionState(
        audioDevice, AUDIO_POLICY_DEVICE_STATE_AVAILABLE, "" /*address*/, "" /*name*/, audioFormat);
    if (ret != NO_ERROR) {
        return;
    }
    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t output;
    audio_port_handle_t portId;
    getOutputForAttr(&selectedDeviceId, getValueFromVector<audio_format_t>(mFdp, kAudioFormats),
                     getValueFromVector<audio_channel_mask_t>(mFdp, kAudioChannelOutMasks),
                     getValueFromVector<uint32_t>(mFdp, kSamplingRates), flags, &output, &portId);
    sp<SwAudioOutputDescriptor> outDesc = mManager->getOutputs().valueFor(output);
    if (outDesc.get() == nullptr) {
        return;
    }
    audio_port_v7 port = {};
    outDesc->toAudioPort(&port);
    mManager->releaseOutput(portId);
    mManager->setDeviceConnectionState(audioDevice, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                       "" /*address*/, "" /*name*/, audioFormat);
}

void AudioPolicyManagerTVFuzzer::process() {
    if (initialize()) {
        testHDMIPortSelection(getValueFromVector<audio_output_flags_t>(mFdp, kAudioOutputFlags));
        fuzzPatchCreation();
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    FuzzedDataProvider fdp = FuzzedDataProvider(data, size);
    while (fdp.remaining_bytes() > 0) {
        AudioPolicyManagerFuzzer audioPolicyManagerFuzzer(&fdp);
        audioPolicyManagerFuzzer.process();

        AudioPolicyManagerFuzzerMsd audioPolicyManagerFuzzerMsd(&fdp);
        audioPolicyManagerFuzzerMsd.process();

        AudioPolicyManagerFuzzerWithConfigurationFile audioPolicyManagerFuzzerWithConfigurationFile(
            &fdp);
        audioPolicyManagerFuzzerWithConfigurationFile.process();

        AudioPolicyManagerFuzzerDynamicPolicy audioPolicyManagerFuzzerDynamicPolicy(&fdp);
        audioPolicyManagerFuzzerDynamicPolicy.process();

        AudioPolicyManagerFuzzerDPNoRemoteSubmixModule
            audioPolicyManagerFuzzerDPNoRemoteSubmixModule(&fdp);
        audioPolicyManagerFuzzerDPNoRemoteSubmixModule.process();

        AudioPolicyManagerFuzzerDPPlaybackReRouting audioPolicyManagerFuzzerDPPlaybackReRouting(
            &fdp);
        audioPolicyManagerFuzzerDPPlaybackReRouting.process();

        AudioPolicyManagerFuzzerDPMixRecordInjection audioPolicyManagerFuzzerDPMixRecordInjection(
            &fdp);
        audioPolicyManagerFuzzerDPMixRecordInjection.process();

        AudioPolicyManagerFuzzerDeviceConnection audioPolicyManagerFuzzerDeviceConnection(&fdp);
        audioPolicyManagerFuzzerDeviceConnection.process();

        AudioPolicyManagerTVFuzzer audioPolicyManagerTVFuzzer(&fdp);
        audioPolicyManagerTVFuzzer.process();
    }
    return 0;
}
