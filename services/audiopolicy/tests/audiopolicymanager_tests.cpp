/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <cstring>
#include <memory>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#define LOG_TAG "APM_Test"
#include <Serializer.h>
#include <android-base/file.h>
#include <android-base/properties.h>
#include <android/content/AttributionSourceState.h>
#include <android_media_audiopolicy.h>
#include <com_android_media_audio.h>
#include <com_android_media_audioserver.h>
#include <cutils/multiuser.h>
#include <cutils/properties.h>
#include <flag_macros.h>
#include <hardware/audio_effect.h>
#include <media/AudioPolicy.h>
#include <media/PatchBuilder.h>
#include <media/RecordingActivityTracker.h>
#include <media/TypeConverter.h>
#include <utils/Log.h>
#include <utils/Unicode.h>
#include <utils/Vector.h>

#include "AudioPolicyInterface.h"
#include "AudioPolicyManagerTestClient.h"
#include "AudioPolicyTestClient.h"
#include "AudioPolicyTestManager.h"
#include "test_execution_tracer.h"

using namespace android;
using testing::UnorderedElementsAre;
using testing::IsEmpty;
using android::content::AttributionSourceState;

namespace {

AudioMixMatchCriterion createUidCriterion(uint32_t uid, bool exclude = false) {
    AudioMixMatchCriterion criterion;
    criterion.mValue.mUid = uid;
    criterion.mRule = exclude ? RULE_EXCLUDE_UID : RULE_MATCH_UID;
    return criterion;
}

AudioMixMatchCriterion createUserIdCriterion(int userId, bool exclude = false) {
    AudioMixMatchCriterion criterion;
    criterion.mValue.mUserId = userId;
    criterion.mRule = exclude ? RULE_EXCLUDE_USERID : RULE_MATCH_USERID;
    return criterion;
}

AudioMixMatchCriterion createUsageCriterion(audio_usage_t usage, bool exclude = false) {
    AudioMixMatchCriterion criterion;
    criterion.mValue.mUsage = usage;
    criterion.mRule = exclude ? RULE_EXCLUDE_ATTRIBUTE_USAGE : RULE_MATCH_ATTRIBUTE_USAGE;
    return criterion;
}

AudioMixMatchCriterion createCapturePresetCriterion(audio_source_t source, bool exclude = false) {
    AudioMixMatchCriterion criterion;
    criterion.mValue.mSource = source;
    criterion.mRule = exclude ?
        RULE_EXCLUDE_ATTRIBUTE_CAPTURE_PRESET : RULE_MATCH_ATTRIBUTE_CAPTURE_PRESET;
    return criterion;
}

AudioMixMatchCriterion createSessionIdCriterion(audio_session_t session, bool exclude = false) {
    AudioMixMatchCriterion criterion;
    criterion.mValue.mAudioSessionId = session;
    criterion.mRule = exclude ?
        RULE_EXCLUDE_AUDIO_SESSION_ID : RULE_MATCH_AUDIO_SESSION_ID;
    return criterion;
}

// TODO b/182392769: use attribution source util
AttributionSourceState createAttributionSourceState(uid_t uid) {
    AttributionSourceState attributionSourceState;
    attributionSourceState.uid = uid;
    attributionSourceState.token = sp<BBinder>::make();
    return attributionSourceState;
}
} // namespace

TEST(AudioPolicyConfigTest, DefaultConfigForTestsIsEmpty) {
    auto config = AudioPolicyConfig::createWritableForTests();
    EXPECT_TRUE(config->getSource().empty());
    EXPECT_TRUE(config->getHwModules().isEmpty());
    EXPECT_TRUE(config->getInputDevices().isEmpty());
    EXPECT_TRUE(config->getOutputDevices().isEmpty());
}

TEST(AudioPolicyConfigTest, FallbackToDefault) {
    auto config = AudioPolicyConfig::loadFromApmXmlConfigWithFallback(
            base::GetExecutableDirectory() + "/test_invalid_audio_policy_configuration.xml");
    EXPECT_EQ(AudioPolicyConfig::kDefaultConfigSource, config->getSource());
}

TEST(AudioPolicyConfigTest, LoadForTests) {
    {
        auto result = AudioPolicyConfig::loadFromCustomXmlConfigForTests(
                base::GetExecutableDirectory() + "/test_invalid_audio_policy_configuration.xml");
        EXPECT_FALSE(result.ok());
    }
    {
        const std::string source =
                base::GetExecutableDirectory() + "/test_audio_policy_configuration.xml";
        auto result = AudioPolicyConfig::loadFromCustomXmlConfigForTests(source);
        ASSERT_TRUE(result.ok());
        EXPECT_EQ(source, result.value()->getSource());
        EXPECT_FALSE(result.value()->getHwModules().isEmpty());
        EXPECT_FALSE(result.value()->getInputDevices().isEmpty());
        EXPECT_FALSE(result.value()->getOutputDevices().isEmpty());
    }
}

TEST(AudioPolicyManagerTestInit, EngineFailure) {
    AudioPolicyTestClient client;
    auto config = AudioPolicyConfig::createWritableForTests();
    config->setDefault();
    config->setEngineLibraryNameSuffix("non-existent");
    AudioPolicyTestManager manager(config, &client);
    ASSERT_EQ(NO_INIT, manager.initialize());
    ASSERT_EQ(NO_INIT, manager.initCheck());
}

TEST(AudioPolicyManagerTestInit, ClientFailure) {
    AudioPolicyTestClient client;
    AudioPolicyTestManager manager(&client);
    // Since the default client fails to open anything,
    // APM should indicate that the initialization didn't succeed.
    ASSERT_EQ(NO_INIT, manager.initialize());
    ASSERT_EQ(NO_INIT, manager.initCheck());
}


class PatchCountCheck {
  public:
    explicit PatchCountCheck(AudioPolicyManagerTestClient *client)
            : mClient{client},
              mInitialCount{mClient->getActivePatchesCount()} {}
    int deltaFromSnapshot() const {
        size_t currentCount = mClient->getActivePatchesCount();
        if (mInitialCount <= currentCount) {
            return currentCount - mInitialCount;
        } else {
            return -(static_cast<int>(mInitialCount - currentCount));
        }
    }
  private:
    const AudioPolicyManagerTestClient *mClient;
    const size_t mInitialCount;
};

class AudioPolicyManagerTest : public testing::Test {
  public:
    constexpr static uint32_t k384000SamplingRate = 384000;
    constexpr static uint32_t k48000SamplingRate = 48000;
    constexpr static uint32_t k96000SamplingRate = 96000;

  protected:
    void SetUp() override;
    void TearDown() override;
    virtual void SetUpManagerConfig();
    virtual std::string getEngineConfigFilePath() const { return sTestEngineConfig; }

    void dumpToLog();
    // When explicit routing is needed, selectedDeviceId needs to be set as the wanted port
    // id. Otherwise, selectedDeviceId needs to be initialized as AUDIO_PORT_HANDLE_NONE.
    void getOutputForAttr(
            DeviceIdVector *selectedDeviceIds,
            audio_format_t format,
            audio_channel_mask_t channelMask,
            int sampleRate,
            audio_output_flags_t flags = AUDIO_OUTPUT_FLAG_NONE,
            audio_io_handle_t *output = nullptr,
            audio_port_handle_t *portId = nullptr,
            audio_attributes_t attr = AUDIO_ATTRIBUTES_INITIALIZER,
            audio_session_t session = AUDIO_SESSION_NONE,
            int uid = 0,
            bool* isBitPerfect = nullptr);
    void getInputForAttr(
            const audio_attributes_t &attr,
            audio_io_handle_t *input,
            audio_session_t session,
            audio_unique_id_t riid,
            audio_port_handle_t *selectedDeviceId,
            audio_format_t format,
            audio_channel_mask_t channelMask,
            int sampleRate,
            audio_input_flags_t flags = AUDIO_INPUT_FLAG_NONE,
            audio_port_handle_t *portId = nullptr,
            uint32_t *virtualDeviceId = nullptr);
    PatchCountCheck snapshotPatchCount() { return PatchCountCheck(mClient.get()); }

    void getAudioPorts(audio_port_type_t type, audio_port_role_t role,
            std::vector<audio_port_v7>* ports);
    // Tries to find a device port. If 'foundPort' isn't nullptr,
    // will generate a failure if the port hasn't been found.
    bool findDevicePort(audio_port_role_t role, audio_devices_t deviceType,
            const std::string &address, audio_port_v7 *foundPort);
    static audio_port_handle_t getDeviceIdFromPatch(const struct audio_patch* patch);
    virtual AudioPolicyManagerTestClient* getClient() { return new AudioPolicyManagerTestClient; }
    void verifyBuiltInStrategyIdsAreValid();

    sp<AudioPolicyConfig> mConfig;
    std::unique_ptr<AudioPolicyManagerTestClient> mClient;
    std::unique_ptr<AudioPolicyTestManager> mManager;

    static const std::string sTestEngineConfig;
};

const std::string AudioPolicyManagerTest::sTestEngineConfig =
        base::GetExecutableDirectory() + "/engine/test_audio_policy_engine_configuration.xml";

void AudioPolicyManagerTest::SetUp() {
    mClient.reset(getClient());
    ASSERT_NO_FATAL_FAILURE(SetUpManagerConfig());  // Subclasses may want to customize the config.
    mManager.reset(new AudioPolicyTestManager(mConfig, mClient.get(), getEngineConfigFilePath()));
    ASSERT_EQ(NO_ERROR, mManager->initialize());
    ASSERT_EQ(NO_ERROR, mManager->initCheck());
}

void AudioPolicyManagerTest::TearDown() {
    mManager.reset();
    mClient.reset();
}

void AudioPolicyManagerTest::SetUpManagerConfig() {
    mConfig = AudioPolicyConfig::createWritableForTests();
    mConfig->setDefault();
}

void AudioPolicyManagerTest::dumpToLog() {
    int pipefd[2];
    ASSERT_NE(-1, pipe(pipefd));
    pid_t cpid = fork();
    ASSERT_NE(-1, cpid);
    if (cpid == 0) {
        // Child process reads from the pipe and logs.
        close(pipefd[1]);
        std::string line;
        char buf;
        while (read(pipefd[0], &buf, sizeof(buf)) > 0) {
            if (buf != '\n') {
                line += buf;
            } else {
                ALOGI("%s", line.c_str());
                line = "";
            }
        }
        if (!line.empty()) ALOGI("%s", line.c_str());
        close(pipefd[0]);
        _exit(EXIT_SUCCESS);
    } else {
        // Parent does the dump and checks the status code.
        close(pipefd[0]);
        ASSERT_EQ(NO_ERROR, mManager->dump(pipefd[1]));
        close(pipefd[1]);
        wait(NULL);  // Wait for the child to exit.
    }
}

void AudioPolicyManagerTest::getOutputForAttr(
        DeviceIdVector *selectedDeviceIds,
        audio_format_t format,
        audio_channel_mask_t channelMask,
        int sampleRate,
        audio_output_flags_t flags,
        audio_io_handle_t *output,
        audio_port_handle_t *portId,
        audio_attributes_t attr,
        audio_session_t session,
        int uid,
        bool* isBitPerfect) {
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
    bool isSpatialized;
    bool isBitPerfectInternal;
    AttributionSourceState attributionSource = createAttributionSourceState(uid);
    ASSERT_EQ(OK, mManager->getOutputForAttr(
                    &attr, output, session, &stream, attributionSource, &config, &flags,
                    selectedDeviceIds, portId, {}, &outputType, &isSpatialized,
                    isBitPerfect == nullptr ? &isBitPerfectInternal : isBitPerfect));
    ASSERT_NE(AUDIO_PORT_HANDLE_NONE, *portId);
    ASSERT_NE(AUDIO_IO_HANDLE_NONE, *output);
}

void AudioPolicyManagerTest::getInputForAttr(
        const audio_attributes_t &attr,
        audio_io_handle_t *input,
        const audio_session_t session,
        audio_unique_id_t riid,
        audio_port_handle_t *selectedDeviceId,
        audio_format_t format,
        audio_channel_mask_t channelMask,
        int sampleRate,
        audio_input_flags_t flags,
        audio_port_handle_t *portId,
        uint32_t *virtualDeviceId) {
    audio_config_base_t config = AUDIO_CONFIG_BASE_INITIALIZER;
    config.sample_rate = sampleRate;
    config.channel_mask = channelMask;
    config.format = format;
    audio_port_handle_t localPortId;
    if (!portId) portId = &localPortId;
    *portId = AUDIO_PORT_HANDLE_NONE;
    if (!virtualDeviceId) virtualDeviceId = 0;
    AttributionSourceState attributionSource = createAttributionSourceState(/*uid=*/ 0);
    auto inputRes = mManager->getInputForAttr(attr, *input, *selectedDeviceId,
        config, flags, riid, session, attributionSource);
    ASSERT_TRUE(inputRes.has_value());
    ASSERT_NE(inputRes->portId, AUDIO_PORT_HANDLE_NONE);
    *input = inputRes->input;
    if (selectedDeviceId != nullptr) *selectedDeviceId = inputRes->selectedDeviceId;
    *portId = inputRes->portId;
    if (virtualDeviceId != nullptr) *virtualDeviceId = inputRes->virtualDeviceId;
}

void AudioPolicyManagerTest::getAudioPorts(audio_port_type_t type, audio_port_role_t role,
        std::vector<audio_port_v7>* ports) {
    uint32_t numPorts = 0;
    uint32_t generation1;
    status_t ret;

    ret = mManager->listAudioPorts(role, type, &numPorts, nullptr, &generation1);
    ASSERT_EQ(NO_ERROR, ret) << "mManager->listAudioPorts returned error";

    uint32_t generation2;
    ports->resize(numPorts);
    ret = mManager->listAudioPorts(role, type, &numPorts, ports->data(), &generation2);
    ASSERT_EQ(NO_ERROR, ret) << "mManager->listAudioPorts returned error";
    ASSERT_EQ(generation1, generation2) << "Generations changed during ports retrieval";
}

bool AudioPolicyManagerTest::findDevicePort(audio_port_role_t role,
        audio_devices_t deviceType, const std::string &address, audio_port_v7 *foundPort) {
    std::vector<audio_port_v7> ports;
    getAudioPorts(AUDIO_PORT_TYPE_DEVICE, role, &ports);
    if (HasFailure()) return false;

    for (const auto &port : ports) {
        if (port.role == role && port.ext.device.type == deviceType &&
                (strncmp(port.ext.device.address, address.c_str(),
                         AUDIO_DEVICE_MAX_ADDRESS_LEN) == 0)) {
            if (foundPort) *foundPort = port;
            return true;
        }
    }
    if (foundPort) {
        ADD_FAILURE() << "Device port with role " << role << " and address "
                      << address << " not found";
    }
    return false;
}

audio_port_handle_t AudioPolicyManagerTest::getDeviceIdFromPatch(
        const struct audio_patch* patch) {
    // The logic here is the same as the one in AudioIoDescriptor.
    // Note this function is aim to get routed device id for test.
    // In that case, device to device patch is not expected here.
    if (patch->num_sources != 0 && patch->num_sinks != 0) {
        if (patch->sources[0].type == AUDIO_PORT_TYPE_MIX) {
            return patch->sinks[0].id;
        } else {
            return patch->sources[0].id;
        }
    }
    return AUDIO_PORT_HANDLE_NONE;
}

void AudioPolicyManagerTest::verifyBuiltInStrategyIdsAreValid() {
    AudioProductStrategyVector strategies;
    ASSERT_EQ(NO_ERROR, mManager->listAudioProductStrategies(strategies));
    for (const auto& strategy : strategies) {
        // Since ids are unsigned, this will also cover the case when the id is 'NONE' which is -1.
        EXPECT_LT(strategy.getId(),
                  media::audio::common::AudioHalProductStrategy::VENDOR_STRATEGY_ID_START)
                << strategy.getName();
    }
}

TEST_F(AudioPolicyManagerTest, InitSuccess) {
    // SetUp must finish with no assertions.
}

TEST_F(AudioPolicyManagerTest, Dump) {
    dumpToLog();
}

TEST_F(AudioPolicyManagerTest, CreateAudioPatchFailure) {
    audio_patch patch{};
    audio_patch_handle_t handle = AUDIO_PATCH_HANDLE_NONE;
    const PatchCountCheck patchCount = snapshotPatchCount();
    ASSERT_EQ(BAD_VALUE, mManager->createAudioPatch(nullptr, &handle, 0));
    ASSERT_EQ(BAD_VALUE, mManager->createAudioPatch(&patch, nullptr, 0));
    ASSERT_EQ(BAD_VALUE, mManager->createAudioPatch(&patch, &handle, 0));
    patch.num_sources = AUDIO_PATCH_PORTS_MAX + 1;
    patch.num_sinks = 1;
    ASSERT_EQ(BAD_VALUE, mManager->createAudioPatch(&patch, &handle, 0));
    patch.num_sources = 1;
    patch.num_sinks = AUDIO_PATCH_PORTS_MAX + 1;
    ASSERT_EQ(BAD_VALUE, mManager->createAudioPatch(&patch, &handle, 0));
    patch.num_sources = 2;
    patch.num_sinks = 1;
    ASSERT_EQ(INVALID_OPERATION, mManager->createAudioPatch(&patch, &handle, 0));
    patch = {};
    patch.num_sources = 1;
    patch.sources[0].role = AUDIO_PORT_ROLE_SINK;
    patch.num_sinks = 1;
    patch.sinks[0].role = AUDIO_PORT_ROLE_SINK;
    ASSERT_EQ(INVALID_OPERATION, mManager->createAudioPatch(&patch, &handle, 0));
    patch = {};
    patch.num_sources = 1;
    patch.sources[0].role = AUDIO_PORT_ROLE_SOURCE;
    patch.num_sinks = 1;
    patch.sinks[0].role = AUDIO_PORT_ROLE_SOURCE;
    ASSERT_EQ(INVALID_OPERATION, mManager->createAudioPatch(&patch, &handle, 0));
    // Verify that the handle is left unchanged.
    ASSERT_EQ(AUDIO_PATCH_HANDLE_NONE, handle);
    ASSERT_EQ(0, patchCount.deltaFromSnapshot());
}

TEST_F(AudioPolicyManagerTest, CreateAudioPatchFromMix) {
    audio_patch_handle_t handle = AUDIO_PATCH_HANDLE_NONE;
    uid_t uid = 42;
    const PatchCountCheck patchCount = snapshotPatchCount();
    ASSERT_FALSE(mManager->getAvailableInputDevices().isEmpty());
    PatchBuilder patchBuilder;
    patchBuilder.addSource(mManager->getAvailableInputDevices()[0]).
            addSink(mManager->getConfig().getDefaultOutputDevice());
    ASSERT_EQ(NO_ERROR, mManager->createAudioPatch(patchBuilder.patch(), &handle, uid));
    ASSERT_NE(AUDIO_PATCH_HANDLE_NONE, handle);
    ASSERT_EQ(1, patchCount.deltaFromSnapshot());
}

// TODO: Add patch creation tests that involve already existing patch

TEST_F(AudioPolicyManagerTest, BuiltInStrategyIdsAreValid) {
    verifyBuiltInStrategyIdsAreValid();
}

class AudioPolicyManagerTestWithDefaultEngineConfig : public AudioPolicyManagerTest {
  protected:
    // The APM will use the default engine config from EngineDefaultConfig.h.
    std::string getEngineConfigFilePath() const override { return "non_existent_file.xml"; }
};

TEST_F(AudioPolicyManagerTestWithDefaultEngineConfig, BuiltInStrategyIdsAreValid) {
    verifyBuiltInStrategyIdsAreValid();
}

enum
{
    MSD_AUDIO_PATCH_COUNT_NUM_AUDIO_PATCHES_INDEX = 0,
    MSD_AUDIO_PATCH_COUNT_NAME_INDEX = 1
};
using MsdAudioPatchCountSpecification = std::tuple<size_t, std::string>;

class AudioPolicyManagerTestMsd : public AudioPolicyManagerTest,
        public ::testing::WithParamInterface<MsdAudioPatchCountSpecification> {
  public:
    AudioPolicyManagerTestMsd();
  protected:
    void SetUpManagerConfig() override;
    void TearDown() override;
    AudioProfileVector getDirectProfilesForAttributes(const audio_attributes_t& attr);

    sp<DeviceDescriptor> mMsdOutputDevice;
    sp<DeviceDescriptor> mMsdInputDevice;
    sp<DeviceDescriptor> mDefaultOutputDevice;

    const size_t mExpectedAudioPatchCount;
    sp<DeviceDescriptor> mSpdifDevice;

    sp<DeviceDescriptor> mHdmiInputDevice;
};

AudioPolicyManagerTestMsd::AudioPolicyManagerTestMsd()
    : mExpectedAudioPatchCount(std::get<MSD_AUDIO_PATCH_COUNT_NUM_AUDIO_PATCHES_INDEX>(
            GetParam())) {}

INSTANTIATE_TEST_CASE_P(
        MsdAudioPatchCount,
        AudioPolicyManagerTestMsd,
        ::testing::Values(
                MsdAudioPatchCountSpecification(2u, "single"),
                MsdAudioPatchCountSpecification(3u, "dual")
        ),
        [](const ::testing::TestParamInfo<MsdAudioPatchCountSpecification> &info) {
                return std::get<MSD_AUDIO_PATCH_COUNT_NAME_INDEX>(info.param); }
);

void AudioPolicyManagerTestMsd::SetUpManagerConfig() {
    // TODO: Consider using Serializer to load part of the config from a string.
    ASSERT_NO_FATAL_FAILURE(AudioPolicyManagerTest::SetUpManagerConfig());
    mConfig->getHwModules().getModuleFromName(
            AUDIO_HARDWARE_MODULE_ID_PRIMARY)->setHalVersion(3, 0);

    mMsdOutputDevice = new DeviceDescriptor(AUDIO_DEVICE_OUT_BUS);
    sp<AudioProfile> pcmOutputProfile = new AudioProfile(
            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate);
    sp<AudioProfile> ac3OutputProfile = new AudioProfile(
            AUDIO_FORMAT_AC3, AUDIO_CHANNEL_OUT_5POINT1, k48000SamplingRate);
    sp<AudioProfile> iec958OutputProfile = new AudioProfile(
            AUDIO_FORMAT_IEC60958, AUDIO_CHANNEL_INDEX_MASK_24, k48000SamplingRate);
    mMsdOutputDevice->addAudioProfile(pcmOutputProfile);
    mMsdOutputDevice->addAudioProfile(ac3OutputProfile);
    mMsdOutputDevice->addAudioProfile(iec958OutputProfile);
    mMsdInputDevice = new DeviceDescriptor(AUDIO_DEVICE_IN_BUS);
    // Match output profile from AudioPolicyConfig::setDefault.
    sp<AudioProfile> pcmInputProfile = new AudioProfile(
            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO, 44100);
    mMsdInputDevice->addAudioProfile(pcmInputProfile);
    mConfig->addDevice(mMsdOutputDevice);
    mConfig->addDevice(mMsdInputDevice);

    if (mExpectedAudioPatchCount == 3) {
        // Add SPDIF device with PCM output profile as a second device for dual MSD audio patching.
        mSpdifDevice = new DeviceDescriptor(AUDIO_DEVICE_OUT_SPDIF);
        mSpdifDevice->addAudioProfile(pcmOutputProfile);
        mConfig->addDevice(mSpdifDevice);

        sp<OutputProfile> spdifOutputProfile = new OutputProfile("spdif output");
        spdifOutputProfile->addAudioProfile(pcmOutputProfile);
        spdifOutputProfile->addSupportedRoutableDevice(mSpdifDevice);
        mConfig->getHwModules().getModuleFromName(AUDIO_HARDWARE_MODULE_ID_PRIMARY)->
                addOutputProfile(spdifOutputProfile);
    }

    sp<HwModule> msdModule = new HwModule(AUDIO_HARDWARE_MODULE_ID_MSD, 3 /*halVersionMajor*/);
    HwModuleCollection modules = mConfig->getHwModules();
    modules.add(msdModule);
    mConfig->setHwModules(modules);

    sp<OutputProfile> msdOutputProfile = new OutputProfile("msd input");
    msdOutputProfile->addAudioProfile(pcmOutputProfile);
    msdOutputProfile->addSupportedRoutableDevice(mMsdOutputDevice);
    msdModule->addOutputProfile(msdOutputProfile);
    sp<OutputProfile> msdCompressedOutputProfile = new OutputProfile("msd compressed input");
    msdCompressedOutputProfile->addAudioProfile(ac3OutputProfile);
    msdCompressedOutputProfile->setFlags(
            AUDIO_OUTPUT_FLAG_DIRECT | AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD |
            AUDIO_OUTPUT_FLAG_NON_BLOCKING);
    msdCompressedOutputProfile->addSupportedRoutableDevice(mMsdOutputDevice);
    msdModule->addOutputProfile(msdCompressedOutputProfile);
    sp<OutputProfile> msdIec958OutputProfile = new OutputProfile("msd iec958 input");
    msdIec958OutputProfile->addAudioProfile(iec958OutputProfile);
    msdIec958OutputProfile->setFlags(AUDIO_OUTPUT_FLAG_DIRECT);
    msdIec958OutputProfile->addSupportedRoutableDevice(mMsdOutputDevice);
    msdModule->addOutputProfile(msdIec958OutputProfile);

    sp<InputProfile> msdInputProfile = new InputProfile("msd output");
    msdInputProfile->addAudioProfile(pcmInputProfile);
    msdInputProfile->addSupportedRoutableDevice(mMsdInputDevice);
    msdModule->addInputProfile(msdInputProfile);

    // Add a profile with another encoding to the default device to test routing
    // of streams that are not supported by MSD.
    sp<AudioProfile> dtsOutputProfile = new AudioProfile(
            AUDIO_FORMAT_DTS, AUDIO_CHANNEL_OUT_5POINT1, k48000SamplingRate);
    mConfig->getDefaultOutputDevice()->addAudioProfile(dtsOutputProfile);
    sp<OutputProfile> primaryEncodedOutputProfile = new OutputProfile("encoded");
    primaryEncodedOutputProfile->addAudioProfile(dtsOutputProfile);
    primaryEncodedOutputProfile->setFlags(AUDIO_OUTPUT_FLAG_DIRECT);
    primaryEncodedOutputProfile->addSupportedRoutableDevice(mConfig->getDefaultOutputDevice());
    mConfig->getHwModules().getModuleFromName(AUDIO_HARDWARE_MODULE_ID_PRIMARY)->
            addOutputProfile(primaryEncodedOutputProfile);

    mDefaultOutputDevice = mConfig->getDefaultOutputDevice();
    if (mExpectedAudioPatchCount == 3) {
        mSpdifDevice->addAudioProfile(dtsOutputProfile);
        primaryEncodedOutputProfile->addSupportedRoutableDevice(mSpdifDevice);
    }

    // Add HDMI input device with IEC60958 profile for HDMI in -> MSD patching.
    mHdmiInputDevice = new DeviceDescriptor(AUDIO_DEVICE_IN_HDMI);
    sp<AudioProfile> iec958InputProfile = new AudioProfile(
            AUDIO_FORMAT_IEC60958, AUDIO_CHANNEL_INDEX_MASK_24, k48000SamplingRate);
    mHdmiInputDevice->addAudioProfile(iec958InputProfile);
    mConfig->addDevice(mHdmiInputDevice);
    sp<InputProfile> hdmiInputProfile = new InputProfile("hdmi input");
    hdmiInputProfile->addAudioProfile(iec958InputProfile);
    hdmiInputProfile->setFlags(AUDIO_INPUT_FLAG_DIRECT);
    hdmiInputProfile->addSupportedRoutableDevice(mHdmiInputDevice);
    mConfig->getHwModules().getModuleFromName(AUDIO_HARDWARE_MODULE_ID_PRIMARY)->
            addInputProfile(hdmiInputProfile);
}

void AudioPolicyManagerTestMsd::TearDown() {
    mMsdOutputDevice.clear();
    mMsdInputDevice.clear();
    mDefaultOutputDevice.clear();
    mSpdifDevice.clear();
    mHdmiInputDevice.clear();
    AudioPolicyManagerTest::TearDown();
}

AudioProfileVector AudioPolicyManagerTestMsd::getDirectProfilesForAttributes(
                                                    const audio_attributes_t& attr) {
    AudioProfileVector audioProfilesVector;
    mManager->getDirectProfilesForAttributes(&attr, audioProfilesVector);
    return audioProfilesVector;
}

TEST_P(AudioPolicyManagerTestMsd, InitSuccess) {
    ASSERT_TRUE(mMsdOutputDevice);
    ASSERT_TRUE(mMsdInputDevice);
    ASSERT_TRUE(mDefaultOutputDevice);
}

TEST_P(AudioPolicyManagerTestMsd, Dump) {
    dumpToLog();
}

TEST_P(AudioPolicyManagerTestMsd, PatchCreationOnSetForceUse) {
    const PatchCountCheck patchCount = snapshotPatchCount();
    mManager->setForceUse(AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND,
            AUDIO_POLICY_FORCE_ENCODED_SURROUND_ALWAYS);
    ASSERT_EQ(mExpectedAudioPatchCount -1 , patchCount.deltaFromSnapshot());
}

TEST_P(AudioPolicyManagerTestMsd, PatchCreationSetReleaseMsdOutputPatches) {
    const PatchCountCheck patchCount = snapshotPatchCount();
    DeviceVector devices = mManager->getAvailableOutputDevices();
    // Remove MSD output device to avoid patching to itself
    devices.remove(mMsdOutputDevice);
    ASSERT_EQ(mExpectedAudioPatchCount -1 , devices.size());
    mManager->setMsdOutputPatches(&devices);
    ASSERT_EQ(mExpectedAudioPatchCount - 1, patchCount.deltaFromSnapshot());
    // Dual patch: exercise creating one new audio patch and reusing another existing audio patch.
    DeviceVector singleDevice(devices[0]);
    mManager->releaseMsdOutputPatches(singleDevice);
    ASSERT_EQ(mExpectedAudioPatchCount - 2, patchCount.deltaFromSnapshot());
    mManager->setMsdOutputPatches(&devices);
    ASSERT_EQ(mExpectedAudioPatchCount - 1, patchCount.deltaFromSnapshot());
    mManager->releaseMsdOutputPatches(devices);
    ASSERT_EQ(0, patchCount.deltaFromSnapshot());
}

TEST_P(AudioPolicyManagerTestMsd, GetOutputForAttrEncodedRoutesToMsd) {
    const PatchCountCheck patchCount = snapshotPatchCount();
    DeviceIdVector selectedDeviceIds;
    ASSERT_NO_FATAL_FAILURE(
            getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_AC3, AUDIO_CHANNEL_OUT_5POINT1,
            k48000SamplingRate, AUDIO_OUTPUT_FLAG_DIRECT));
    ASSERT_EQ(mDefaultOutputDevice->getId(), selectedDeviceIds[0]);
    ASSERT_EQ(mExpectedAudioPatchCount, patchCount.deltaFromSnapshot());
}

TEST_P(AudioPolicyManagerTestMsd, GetOutputForAttrPcmRoutesToMsd) {
    const PatchCountCheck patchCount = snapshotPatchCount();
    DeviceIdVector selectedDeviceIds;
    ASSERT_NO_FATAL_FAILURE(
            getOutputForAttr(&selectedDeviceIds,
            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate));
    ASSERT_EQ(mDefaultOutputDevice->getId(), selectedDeviceIds[0]);
    ASSERT_EQ(mExpectedAudioPatchCount - 1, patchCount.deltaFromSnapshot());
}

TEST_P(AudioPolicyManagerTestMsd, GetOutputForAttrEncodedPlusPcmRoutesToMsd) {
    const PatchCountCheck patchCount = snapshotPatchCount();
    DeviceIdVector selectedDeviceIds;
    ASSERT_NO_FATAL_FAILURE(
            getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_AC3, AUDIO_CHANNEL_OUT_5POINT1,
            k48000SamplingRate, AUDIO_OUTPUT_FLAG_DIRECT));
    ASSERT_EQ(mDefaultOutputDevice->getId(), selectedDeviceIds[0]);
    ASSERT_EQ(mExpectedAudioPatchCount, patchCount.deltaFromSnapshot());
    selectedDeviceIds.clear();
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds,
            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate));
    ASSERT_EQ(mDefaultOutputDevice->getId(), selectedDeviceIds[0]);
    ASSERT_EQ(mExpectedAudioPatchCount, patchCount.deltaFromSnapshot());
}

TEST_P(AudioPolicyManagerTestMsd, GetOutputForAttrUnsupportedFormatBypassesMsd) {
    const PatchCountCheck patchCount = snapshotPatchCount();
    DeviceIdVector selectedDeviceIds;
    ASSERT_NO_FATAL_FAILURE(
            getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_DTS, AUDIO_CHANNEL_OUT_5POINT1,
            k48000SamplingRate, AUDIO_OUTPUT_FLAG_DIRECT));
    ASSERT_NE(mMsdOutputDevice->getId(), selectedDeviceIds[0]);
    ASSERT_EQ(1, patchCount.deltaFromSnapshot());
}

TEST_P(AudioPolicyManagerTestMsd, GetOutputForAttrFormatSwitching) {
    // Switch between formats that are supported and not supported by MSD.
    {
        const PatchCountCheck patchCount = snapshotPatchCount();
        DeviceIdVector selectedDeviceIds;
        audio_port_handle_t portId;
        ASSERT_NO_FATAL_FAILURE(
                getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_AC3, AUDIO_CHANNEL_OUT_5POINT1,
                k48000SamplingRate, AUDIO_OUTPUT_FLAG_DIRECT, nullptr /*output*/, &portId));
        ASSERT_EQ(mDefaultOutputDevice->getId(), selectedDeviceIds[0]);
        ASSERT_EQ(mExpectedAudioPatchCount, patchCount.deltaFromSnapshot());
        mManager->releaseOutput(portId);
        ASSERT_EQ(mExpectedAudioPatchCount - 1, patchCount.deltaFromSnapshot());
    }
    {
        const PatchCountCheck patchCount = snapshotPatchCount();
        DeviceIdVector selectedDeviceIds;
        audio_port_handle_t portId;
        ASSERT_NO_FATAL_FAILURE(
                getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_DTS, AUDIO_CHANNEL_OUT_5POINT1,
                k48000SamplingRate, AUDIO_OUTPUT_FLAG_DIRECT, nullptr /*output*/, &portId));
        ASSERT_GT(selectedDeviceIds.size(), 0);
        ASSERT_NE(mMsdOutputDevice->getId(), selectedDeviceIds[0]);
        ASSERT_EQ(-static_cast<int>(mExpectedAudioPatchCount) + 2, patchCount.deltaFromSnapshot());
        mManager->releaseOutput(portId);
        ASSERT_EQ(0, patchCount.deltaFromSnapshot());
    }
    {
        const PatchCountCheck patchCount = snapshotPatchCount();
        DeviceIdVector selectedDeviceIds;
        ASSERT_NO_FATAL_FAILURE(
                getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_AC3, AUDIO_CHANNEL_OUT_5POINT1,
                k48000SamplingRate, AUDIO_OUTPUT_FLAG_DIRECT));
        ASSERT_EQ(mDefaultOutputDevice->getId(), selectedDeviceIds[0]);
        ASSERT_EQ(1, patchCount.deltaFromSnapshot());
    }
}

TEST_P(AudioPolicyManagerTestMsd, PatchCreationFromHdmiInToMsd) {
    audio_patch_handle_t handle = AUDIO_PATCH_HANDLE_NONE;
    uid_t uid = 42;
    const PatchCountCheck patchCount = snapshotPatchCount();
    ASSERT_FALSE(mManager->getAvailableInputDevices().isEmpty());
    PatchBuilder patchBuilder;
    patchBuilder.
            addSource(mManager->getAvailableInputDevices().
                    getDevice(AUDIO_DEVICE_IN_HDMI, String8(""), AUDIO_FORMAT_DEFAULT)).
            addSink(mManager->getAvailableOutputDevices().
                    getDevice(AUDIO_DEVICE_OUT_BUS, String8(""), AUDIO_FORMAT_DEFAULT));
    ASSERT_EQ(NO_ERROR, mManager->createAudioPatch(patchBuilder.patch(), &handle, uid));
    ASSERT_NE(AUDIO_PATCH_HANDLE_NONE, handle);
    AudioPatchCollection patches = mManager->getAudioPatches();
    sp<AudioPatch> patch = patches.valueFor(handle);
    ASSERT_EQ(1, patch->mPatch.num_sources);
    ASSERT_EQ(1, patch->mPatch.num_sinks);
    ASSERT_EQ(AUDIO_PORT_ROLE_SOURCE, patch->mPatch.sources[0].role);
    ASSERT_EQ(AUDIO_PORT_ROLE_SINK, patch->mPatch.sinks[0].role);
    ASSERT_EQ(AUDIO_FORMAT_IEC60958, patch->mPatch.sources[0].format);
    ASSERT_EQ(AUDIO_FORMAT_IEC60958, patch->mPatch.sinks[0].format);
    ASSERT_EQ(AUDIO_CHANNEL_INDEX_MASK_24, patch->mPatch.sources[0].channel_mask);
    ASSERT_EQ(AUDIO_CHANNEL_INDEX_MASK_24, patch->mPatch.sinks[0].channel_mask);
    ASSERT_EQ(k48000SamplingRate, patch->mPatch.sources[0].sample_rate);
    ASSERT_EQ(k48000SamplingRate, patch->mPatch.sinks[0].sample_rate);
    ASSERT_EQ(1, patchCount.deltaFromSnapshot());
}

TEST_P(AudioPolicyManagerTestMsd, GetDirectProfilesForAttributesWithMsd) {
    const audio_attributes_t attr = {
        AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN,
        AUDIO_SOURCE_INVALID, AUDIO_FLAG_NONE, ""};

    // count expected direct profiles for the default device
    int countDirectProfilesPrimary = 0;
    const auto& primary = mManager->getConfig().getHwModules()
            .getModuleFromName(AUDIO_HARDWARE_MODULE_ID_PRIMARY);
    for (const auto& outputProfile : primary->getOutputProfiles()) {
        if (outputProfile->asAudioPort()->isDirectOutput()) {
            countDirectProfilesPrimary += outputProfile->asAudioPort()->getAudioProfiles().size();
        }
    }

    // count expected direct profiles for the msd device
    int countDirectProfilesMsd = 0;
    const auto& msd = mManager->getConfig().getHwModules()
            .getModuleFromName(AUDIO_HARDWARE_MODULE_ID_MSD);
    for (const auto& outputProfile : msd->getOutputProfiles()) {
        if (outputProfile->asAudioPort()->isDirectOutput()) {
            countDirectProfilesMsd += outputProfile->asAudioPort()->getAudioProfiles().size();
        }
    }

    // before setting up MSD audio patches we only have the primary hal direct profiles
    ASSERT_EQ(countDirectProfilesPrimary, getDirectProfilesForAttributes(attr).size());

    DeviceVector outputDevices = mManager->getAvailableOutputDevices();
    // Remove MSD output device to avoid patching to itself
    outputDevices.remove(mMsdOutputDevice);
    mManager->setMsdOutputPatches(&outputDevices);

    // after setting up MSD audio patches the MSD direct profiles are added
    ASSERT_EQ(countDirectProfilesPrimary + countDirectProfilesMsd,
                getDirectProfilesForAttributes(attr).size());

    mManager->releaseMsdOutputPatches(outputDevices);
    // releasing the MSD audio patches gets us back to the primary hal direct profiles only
    ASSERT_EQ(countDirectProfilesPrimary, getDirectProfilesForAttributes(attr).size());
}

TEST_P(AudioPolicyManagerTestMsd, IsDirectPlaybackSupportedWithMsd) {
    const audio_attributes_t attr = {
        AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN,
        AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};

    audio_config_base_t directConfig = AUDIO_CONFIG_BASE_INITIALIZER;
    directConfig.format = AUDIO_FORMAT_DTS;
    directConfig.sample_rate = k48000SamplingRate;
    directConfig.channel_mask = AUDIO_CHANNEL_OUT_5POINT1;

    audio_config_base_t nonDirectConfig = AUDIO_CONFIG_BASE_INITIALIZER;
    nonDirectConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    nonDirectConfig.sample_rate = k48000SamplingRate;
    nonDirectConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;

    audio_config_base_t nonExistentConfig = AUDIO_CONFIG_BASE_INITIALIZER;
    nonExistentConfig.format = AUDIO_FORMAT_E_AC3;
    nonExistentConfig.sample_rate = k48000SamplingRate;
    nonExistentConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;

    audio_config_base_t msdDirectConfig1 = AUDIO_CONFIG_BASE_INITIALIZER;
    msdDirectConfig1.format = AUDIO_FORMAT_AC3;
    msdDirectConfig1.sample_rate = k48000SamplingRate;
    msdDirectConfig1.channel_mask = AUDIO_CHANNEL_OUT_5POINT1;

    audio_config_base_t msdDirectConfig2 = AUDIO_CONFIG_BASE_INITIALIZER;
    msdDirectConfig2.format = AUDIO_FORMAT_IEC60958;
    msdDirectConfig2.sample_rate = k48000SamplingRate;
    msdDirectConfig2.channel_mask = AUDIO_CHANNEL_INDEX_MASK_24;

    audio_config_base_t msdNonDirectConfig = AUDIO_CONFIG_BASE_INITIALIZER;
    msdNonDirectConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    msdNonDirectConfig.sample_rate = 96000;
    msdNonDirectConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;

    ASSERT_TRUE(mManager->isDirectOutputSupported(directConfig, attr));
    ASSERT_FALSE(mManager->isDirectOutputSupported(nonDirectConfig, attr));
    ASSERT_FALSE(mManager->isDirectOutputSupported(nonExistentConfig, attr));
    // before setting MSD patches the direct MSD configs return false
    ASSERT_FALSE(mManager->isDirectOutputSupported(msdDirectConfig1, attr));
    ASSERT_FALSE(mManager->isDirectOutputSupported(msdDirectConfig2, attr));
    ASSERT_FALSE(mManager->isDirectOutputSupported(msdNonDirectConfig, attr));

    DeviceVector outputDevices = mManager->getAvailableOutputDevices();
    // Remove MSD output device to avoid patching to itself
    outputDevices.remove(mMsdOutputDevice);
    mManager->setMsdOutputPatches(&outputDevices);

    ASSERT_TRUE(mManager->isDirectOutputSupported(directConfig, attr));
    ASSERT_FALSE(mManager->isDirectOutputSupported(nonDirectConfig, attr));
    ASSERT_FALSE(mManager->isDirectOutputSupported(nonExistentConfig, attr));
    // after setting MSD patches the direct MSD configs return true
    ASSERT_TRUE(mManager->isDirectOutputSupported(msdDirectConfig1, attr));
    ASSERT_TRUE(mManager->isDirectOutputSupported(msdDirectConfig2, attr));
    ASSERT_FALSE(mManager->isDirectOutputSupported(msdNonDirectConfig, attr));

    mManager->releaseMsdOutputPatches(outputDevices);

    ASSERT_TRUE(mManager->isDirectOutputSupported(directConfig, attr));
    ASSERT_FALSE(mManager->isDirectOutputSupported(nonDirectConfig, attr));
    ASSERT_FALSE(mManager->isDirectOutputSupported(nonExistentConfig, attr));
    // AFTER releasing MSD patches the direct MSD configs return false
    ASSERT_FALSE(mManager->isDirectOutputSupported(msdDirectConfig1, attr));
    ASSERT_FALSE(mManager->isDirectOutputSupported(msdDirectConfig2, attr));
    ASSERT_FALSE(mManager->isDirectOutputSupported(msdNonDirectConfig, attr));
}

TEST_P(AudioPolicyManagerTestMsd, GetDirectPlaybackSupportWithMsd) {
    const audio_attributes_t attr = {
        AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN,
        AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};

    audio_config_t directConfig = AUDIO_CONFIG_INITIALIZER;
    directConfig.format = AUDIO_FORMAT_DTS;
    directConfig.sample_rate = k48000SamplingRate;
    directConfig.channel_mask = AUDIO_CHANNEL_OUT_5POINT1;

    audio_config_t nonDirectConfig = AUDIO_CONFIG_INITIALIZER;
    nonDirectConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    nonDirectConfig.sample_rate = k48000SamplingRate;
    nonDirectConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;

    audio_config_t nonExistentConfig = AUDIO_CONFIG_INITIALIZER;
    nonExistentConfig.format = AUDIO_FORMAT_E_AC3;
    nonExistentConfig.sample_rate = k48000SamplingRate;
    nonExistentConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;

    audio_config_t msdDirectConfig1 = AUDIO_CONFIG_INITIALIZER;
    msdDirectConfig1.format = AUDIO_FORMAT_AC3;
    msdDirectConfig1.sample_rate = k48000SamplingRate;
    msdDirectConfig1.channel_mask = AUDIO_CHANNEL_OUT_5POINT1;

    audio_config_t msdDirectConfig2 = AUDIO_CONFIG_INITIALIZER;
    msdDirectConfig2.format = AUDIO_FORMAT_IEC60958;
    msdDirectConfig2.sample_rate = k48000SamplingRate;
    msdDirectConfig2.channel_mask = AUDIO_CHANNEL_INDEX_MASK_24;

    audio_config_t msdNonDirectConfig = AUDIO_CONFIG_INITIALIZER;
    msdNonDirectConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    msdNonDirectConfig.sample_rate = 96000;
    msdNonDirectConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;

    ASSERT_EQ(AUDIO_DIRECT_BITSTREAM_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &directConfig));
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &nonDirectConfig));
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &nonExistentConfig));
    // before setting MSD patches the direct MSD configs return AUDIO_DIRECT_NOT_SUPPORTED
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &msdDirectConfig1));
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &msdDirectConfig2));
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &msdNonDirectConfig));

    DeviceVector outputDevices = mManager->getAvailableOutputDevices();
    // Remove MSD output device to avoid patching to itself
    outputDevices.remove(mMsdOutputDevice);
    mManager->setMsdOutputPatches(&outputDevices);

    ASSERT_EQ(AUDIO_DIRECT_BITSTREAM_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &directConfig));
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &nonDirectConfig));
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &nonExistentConfig));
    // after setting MSD patches the direct MSD configs return values according to their flags
    ASSERT_EQ(AUDIO_DIRECT_OFFLOAD_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &msdDirectConfig1));
    ASSERT_EQ(AUDIO_DIRECT_BITSTREAM_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &msdDirectConfig2));
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &msdNonDirectConfig));

    mManager->releaseMsdOutputPatches(outputDevices);

    ASSERT_EQ(AUDIO_DIRECT_BITSTREAM_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &directConfig));
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &nonDirectConfig));
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &nonExistentConfig));
    // after releasing MSD patches the direct MSD configs return AUDIO_DIRECT_NOT_SUPPORTED
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &msdDirectConfig1));
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &msdDirectConfig2));
    ASSERT_EQ(AUDIO_DIRECT_NOT_SUPPORTED,
                mManager->getDirectPlaybackSupport(&attr, &msdNonDirectConfig));
}

class AudioPolicyManagerTestWithConfigurationFile : public AudioPolicyManagerTest {
protected:
    void SetUpManagerConfig() override;
    virtual std::string getConfigFile() { return sDefaultConfig; }

    static const std::string sExecutableDir;
    static const std::string sDefaultConfig;
};

const std::string AudioPolicyManagerTestWithConfigurationFile::sExecutableDir =
        base::GetExecutableDirectory() + "/";

const std::string AudioPolicyManagerTestWithConfigurationFile::sDefaultConfig =
        sExecutableDir + "test_audio_policy_configuration.xml";

void AudioPolicyManagerTestWithConfigurationFile::SetUpManagerConfig() {
    auto result = AudioPolicyConfig::loadFromCustomXmlConfigForTests(getConfigFile());
    ASSERT_TRUE(result.ok());
    mConfig = result.value();
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, InitSuccess) {
    // SetUp must finish with no assertions.
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, Dump) {
    dumpToLog();
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, ListAudioPortsHasFlags) {
    // Create an input for VOIP TX because it's not opened automatically like outputs are.
    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_port_handle_t mixPortId = AUDIO_PORT_HANDLE_NONE;
    audio_source_t source = AUDIO_SOURCE_VOICE_COMMUNICATION;
    audio_attributes_t attr = {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, source,
                               AUDIO_FLAG_NONE, ""};
    audio_io_handle_t input = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input, AUDIO_SESSION_NONE, 1,
                                            &selectedDeviceId, AUDIO_FORMAT_PCM_16_BIT,
                                            AUDIO_CHANNEL_IN_MONO, 8000, AUDIO_INPUT_FLAG_VOIP_TX,
                                            &mixPortId));

    std::vector<audio_port_v7> ports;
    ASSERT_NO_FATAL_FAILURE(
            getAudioPorts(AUDIO_PORT_TYPE_MIX, AUDIO_PORT_ROLE_NONE, &ports));
    EXPECT_NE(0, ports.size());
    bool hasFlags = false, foundPrimary = false, foundVoipRx = false, foundVoipTx = false;
    for (const auto& port : ports) {
        if ((port.active_config.config_mask & AUDIO_PORT_CONFIG_FLAGS) != 0) {
            hasFlags = true;
            if (port.role == AUDIO_PORT_ROLE_SOURCE) {
                if ((port.active_config.flags.output & AUDIO_OUTPUT_FLAG_PRIMARY) != 0) {
                    foundPrimary = true;
                }
                if ((port.active_config.flags.output & AUDIO_OUTPUT_FLAG_VOIP_RX) != 0) {
                    foundVoipRx = true;
                }
            } else if (port.role == AUDIO_PORT_ROLE_SINK) {
                if ((port.active_config.flags.input & AUDIO_INPUT_FLAG_VOIP_TX) != 0) {
                    foundVoipTx = true;
                }
            }
        }
    }
    EXPECT_TRUE(hasFlags);
    EXPECT_TRUE(foundPrimary);
    EXPECT_TRUE(foundVoipRx);
    EXPECT_TRUE(foundVoipTx);
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, HandleDeviceConfigChange) {
    {
        const auto prevCounter = mClient->getRoutingUpdatedCounter();

        EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP,
                                                               AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                               "", "", AUDIO_FORMAT_LDAC));
        const auto currCounter = mClient->getRoutingUpdatedCounter();
        EXPECT_GT(currCounter, prevCounter);
    }
    {
        const auto prevCounter = mClient->getRoutingUpdatedCounter();
        // Update device configuration
        EXPECT_EQ(NO_ERROR, mManager->handleDeviceConfigChange(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP,
                                                               "" /*address*/, "" /*name*/,
                                                               AUDIO_FORMAT_AAC));

        // As mClient marks isReconfigA2dpSupported to false, device state needs to be toggled for
        // config changes to take effect
        const auto currCounter = mClient->getRoutingUpdatedCounter();
        EXPECT_GT(currCounter, prevCounter);
    }
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, PreferredMixerAttributes) {
    mClient->addSupportedFormat(AUDIO_FORMAT_PCM_16_BIT);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_OUT_STEREO);
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
    auto devices = mManager->getAvailableOutputDevices();
    audio_port_handle_t maxPortId = 0;
    audio_port_handle_t speakerPortId;
    audio_port_handle_t usbPortId;
    for (auto device : devices) {
        maxPortId = std::max(maxPortId, device->getId());
        if (device->type() == AUDIO_DEVICE_OUT_SPEAKER) {
            speakerPortId = device->getId();
        } else if (device->type() == AUDIO_DEVICE_OUT_USB_DEVICE) {
            usbPortId = device->getId();
        }
    }

    const uid_t uid = 1234;
    const uid_t otherUid = 4321;
    const audio_attributes_t mediaAttr = {
            .content_type = AUDIO_CONTENT_TYPE_MUSIC,
            .usage = AUDIO_USAGE_MEDIA,
    };
    const audio_attributes_t alarmAttr = {
            .content_type = AUDIO_CONTENT_TYPE_SONIFICATION,
            .usage = AUDIO_USAGE_ALARM,
    };

    std::vector<audio_mixer_attributes_t> mixerAttributes;
    EXPECT_EQ(NO_ERROR, mManager->getSupportedMixerAttributes(usbPortId, mixerAttributes));
    for (const auto attrToSet : mixerAttributes) {
        audio_mixer_attributes_t attrFromQuery = AUDIO_MIXER_ATTRIBUTES_INITIALIZER;

        // The given device is not available
        EXPECT_EQ(BAD_VALUE,
                  mManager->setPreferredMixerAttributes(
                          &mediaAttr, maxPortId + 1, uid, &attrToSet));
        // The only allowed device is USB
        EXPECT_EQ(BAD_VALUE,
                  mManager->setPreferredMixerAttributes(
                          &mediaAttr, speakerPortId, uid, &attrToSet));
        // The only allowed usage is media
        EXPECT_EQ(BAD_VALUE,
                  mManager->setPreferredMixerAttributes(&alarmAttr, usbPortId, uid, &attrToSet));
        // Nothing set yet, must get null when query
        EXPECT_EQ(NAME_NOT_FOUND,
                  mManager->getPreferredMixerAttributes(&mediaAttr, usbPortId, &attrFromQuery));
        EXPECT_EQ(NO_ERROR,
                  mManager->setPreferredMixerAttributes(
                          &mediaAttr, usbPortId, uid, &attrToSet));
        EXPECT_EQ(NO_ERROR,
                  mManager->getPreferredMixerAttributes(&mediaAttr, usbPortId, &attrFromQuery));
        EXPECT_EQ(attrToSet.config.format, attrFromQuery.config.format);
        EXPECT_EQ(attrToSet.config.sample_rate, attrFromQuery.config.sample_rate);
        EXPECT_EQ(attrToSet.config.channel_mask, attrFromQuery.config.channel_mask);
        EXPECT_EQ(attrToSet.mixer_behavior, attrFromQuery.mixer_behavior);
        EXPECT_EQ(NAME_NOT_FOUND,
                  mManager->clearPreferredMixerAttributes(&mediaAttr, speakerPortId, uid));
        EXPECT_EQ(PERMISSION_DENIED,
                  mManager->clearPreferredMixerAttributes(&mediaAttr, usbPortId, otherUid));
        EXPECT_EQ(NO_ERROR,
                  mManager->clearPreferredMixerAttributes(&mediaAttr, usbPortId, uid));
    }

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           "", "", AUDIO_FORMAT_LDAC));
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, RoutingChangedWithPreferredMixerAttributes) {
    mClient->addSupportedFormat(AUDIO_FORMAT_PCM_16_BIT);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_OUT_STEREO);
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
    auto devices = mManager->getAvailableOutputDevices();
    audio_port_handle_t usbPortId = AUDIO_PORT_HANDLE_NONE;
    for (auto device : devices) {
        if (device->type() == AUDIO_DEVICE_OUT_USB_DEVICE) {
            usbPortId = device->getId();
            break;
        }
    }
    EXPECT_NE(AUDIO_PORT_HANDLE_NONE, usbPortId);

    const uid_t uid = 1234;
    const audio_attributes_t mediaAttr = {
            .content_type = AUDIO_CONTENT_TYPE_MUSIC,
            .usage = AUDIO_USAGE_MEDIA,
    };

    std::vector<audio_mixer_attributes_t> mixerAttributes;
    EXPECT_EQ(NO_ERROR, mManager->getSupportedMixerAttributes(usbPortId, mixerAttributes));
    EXPECT_GT(mixerAttributes.size(), 0);
    EXPECT_EQ(NO_ERROR,
              mManager->setPreferredMixerAttributes(
                      &mediaAttr, usbPortId, uid, &mixerAttributes[0]));

    audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;
    DeviceIdVector selectedDeviceIds;
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(
            getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
            k48000SamplingRate, AUDIO_OUTPUT_FLAG_NONE, &output, &portId, mediaAttr,
            AUDIO_SESSION_NONE, uid));
    bool muted{};
    float volume{};
    status_t status = mManager->startOutput(portId, &volume, &muted);
    if (status == DEAD_OBJECT) {
        ASSERT_NO_FATAL_FAILURE(getOutputForAttr(
                        &selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
                        k48000SamplingRate, AUDIO_OUTPUT_FLAG_NONE, &output, &portId, mediaAttr,
                        AUDIO_SESSION_NONE, uid));
        status = mManager->startOutput(portId, &volume, &muted);
    }
    EXPECT_EQ(NO_ERROR, status);
    EXPECT_GE(volume, 0.f);
    EXPECT_LE(volume, 1.f);
    EXPECT_NE(AUDIO_IO_HANDLE_NONE, output);
    EXPECT_NE(nullptr, mManager->getOutputs().valueFor(output));
    EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP,
                                                           AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                           "", "", AUDIO_FORMAT_LDAC));
    // When BT device is connected, it will be selected as media device and trigger routing changed.
    // When this happens, existing output that is opened with preferred mixer attributes will be
    // closed and reopened with default config.
    EXPECT_EQ(nullptr, mManager->getOutputs().valueFor(output));

    EXPECT_EQ(NO_ERROR,
              mManager->clearPreferredMixerAttributes(&mediaAttr, usbPortId, uid));

    EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_BLUETOOTH_A2DP,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           "", "", AUDIO_FORMAT_LDAC));
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           "", "", AUDIO_FORMAT_LDAC));
}

template <typename T>
bool hasDuplicates(const T& container) {
    return std::unordered_set<typename T::value_type>(container.begin(),
                                                      container.end()).size() != container.size();
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, UniqueSelectedDeviceIds) {
    mClient->addSupportedFormat(AUDIO_FORMAT_PCM_16_BIT);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_OUT_STEREO);
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
    auto devices = mManager->getAvailableOutputDevices();
    audio_port_handle_t usbPortId = AUDIO_PORT_HANDLE_NONE;
    audio_port_handle_t speakerPortId = AUDIO_PORT_HANDLE_NONE;
    for (auto device : devices) {
        if (device->type() == AUDIO_DEVICE_OUT_USB_DEVICE) {
            usbPortId = device->getId();
        }
        if (device->type() == AUDIO_DEVICE_OUT_SPEAKER) {
            speakerPortId = device->getId();
        }
    }
    EXPECT_NE(AUDIO_PORT_HANDLE_NONE, usbPortId);
    EXPECT_NE(AUDIO_PORT_HANDLE_NONE, speakerPortId);

    const uid_t uid = 1234;
    const audio_attributes_t mediaAttr = {
            .content_type = AUDIO_CONTENT_TYPE_SONIFICATION,
            .usage = AUDIO_USAGE_ALARM,
    };

    audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;
    DeviceIdVector selectedDeviceIds;
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
            AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate, AUDIO_OUTPUT_FLAG_NONE, &output,
            &portId, mediaAttr, AUDIO_SESSION_NONE, uid));
    EXPECT_FALSE(selectedDeviceIds.empty());
    EXPECT_NE(std::find(selectedDeviceIds.begin(), selectedDeviceIds.end(), usbPortId),
            selectedDeviceIds.end());
    EXPECT_NE(std::find(selectedDeviceIds.begin(), selectedDeviceIds.end(), speakerPortId),
                  selectedDeviceIds.end());
    EXPECT_FALSE(hasDuplicates(selectedDeviceIds));

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, PreferExactConfigForInput) {
    const audio_channel_mask_t deviceChannelMask = AUDIO_CHANNEL_IN_3POINT1;
    mClient->addSupportedFormat(AUDIO_FORMAT_PCM_16_BIT);
    mClient->addSupportedChannelMask(deviceChannelMask);
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_IN_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));

    const audio_port_handle_t requestedDeviceId = AUDIO_PORT_HANDLE_NONE;
    const audio_io_handle_t requestedInput = AUDIO_PORT_HANDLE_NONE;
    const AttributionSourceState attributionSource = createAttributionSourceState(/*uid=*/ 0);
    AudioPolicyInterface::input_type_t inputType;

    audio_attributes_t attr = {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN,
                               AUDIO_SOURCE_VOICE_COMMUNICATION,AUDIO_FLAG_NONE, ""};
    audio_config_base_t requestedConfig = {
            .sample_rate = k48000SamplingRate,
            .channel_mask = AUDIO_CHANNEL_IN_STEREO,
            .format = AUDIO_FORMAT_PCM_16_BIT,
    };
    auto inputRes = mManager->getInputForAttr(attr, requestedInput, requestedDeviceId,
                                              requestedConfig, AUDIO_INPUT_FLAG_NONE, 1 /*riid*/,
                                              AUDIO_SESSION_NONE, attributionSource);
    ASSERT_TRUE(inputRes.has_value());
    ASSERT_NE(inputRes->portId, AUDIO_PORT_HANDLE_NONE);
    ASSERT_EQ(VALUE_OR_FATAL(legacy2aidl_audio_config_base_t_AudioConfigBase(
                               requestedConfig, true /* isInput */)),
                       inputRes->config);

    attr = {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN,
            AUDIO_SOURCE_VOICE_COMMUNICATION, AUDIO_FLAG_NONE, ""};
    requestedConfig.channel_mask = deviceChannelMask;

    inputRes = mManager->getInputForAttr(attr, requestedInput, requestedDeviceId, requestedConfig,
                                         AUDIO_INPUT_FLAG_NONE, 1 /*riid*/, AUDIO_SESSION_NONE,
                                         attributionSource);
    ASSERT_TRUE(inputRes.has_value());
    ASSERT_NE(inputRes->portId, AUDIO_PORT_HANDLE_NONE);
    ASSERT_EQ(VALUE_OR_FATAL(legacy2aidl_audio_config_base_t_AudioConfigBase(requestedConfig,
                                                                             true /* isInput */)),
              inputRes->config);

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_IN_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, CheckInputsForDeviceClosesStreams) {
    mClient->addSupportedFormat(AUDIO_FORMAT_PCM_16_BIT);
    mClient->addSupportedFormat(AUDIO_FORMAT_PCM_24_BIT_PACKED);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_IN_MONO);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_IN_STEREO);
    // Since 'checkInputsForDevice' is called as part of the 'setDeviceConnectionState',
    // call it directly here, as we need to ensure that it does not keep all intermediate
    // streams opened, as it may cause a rejection from the HAL based on the cap.
    const size_t streamCountBefore = mClient->getOpenedInputsCount();
    sp<DeviceDescriptor> device = mManager->getHwModules().getDeviceDescriptor(
            AUDIO_DEVICE_IN_USB_DEVICE, "", "", AUDIO_FORMAT_DEFAULT, true /*allowToCreate*/);
    ASSERT_NE(nullptr, device.get());
    EXPECT_EQ(NO_ERROR,
            mManager->checkInputsForDevice(device, AUDIO_POLICY_DEVICE_STATE_AVAILABLE));
    EXPECT_EQ(streamCountBefore, mClient->getOpenedInputsCount());
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, SetDeviceConnectionStateClosesStreams) {
    mClient->addSupportedFormat(AUDIO_FORMAT_PCM_16_BIT);
    mClient->addSupportedFormat(AUDIO_FORMAT_PCM_24_BIT_PACKED);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_IN_MONO);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_IN_STEREO);
    const size_t streamCountBefore = mClient->getOpenedInputsCount();
    EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_IN_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
    EXPECT_EQ(streamCountBefore, mClient->getOpenedInputsCount());
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, UpdateConfigFromInexactProfile) {
    const audio_format_t expectedFormat = AUDIO_FORMAT_PCM_16_BIT;
    const uint32_t expectedSampleRate = 48000;
    const audio_channel_mask_t expectedChannelMask = AUDIO_CHANNEL_IN_STEREO;
    const std::string expectedIOProfile = "primary input";

    auto devices = mManager->getAvailableInputDevices();
    sp<DeviceDescriptor> mic = nullptr;
    for (auto device : devices) {
        if (device->type() == AUDIO_DEVICE_IN_BUILTIN_MIC) {
            mic = device;
            break;
        }
    }
    EXPECT_NE(nullptr, mic);

    audio_format_t requestedFormat = AUDIO_FORMAT_PCM_16_BIT;
    uint32_t requestedSampleRate = 44100;
    audio_channel_mask_t requestedChannelMask = AUDIO_CHANNEL_IN_STEREO;
    auto profile = mManager->getInputProfile(
            mic, requestedSampleRate, requestedFormat, requestedChannelMask, AUDIO_INPUT_FLAG_NONE);
    EXPECT_EQ(expectedIOProfile, profile->getName());
    EXPECT_EQ(expectedFormat, requestedFormat);
    EXPECT_EQ(expectedSampleRate, requestedSampleRate);
    EXPECT_EQ(expectedChannelMask, requestedChannelMask);
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, UpdateConfigFromExactProfile) {
    const audio_format_t expectedFormat = AUDIO_FORMAT_PCM_16_BIT;
    const uint32_t expectedSampleRate = 48000;
    const audio_channel_mask_t expectedChannelMask = AUDIO_CHANNEL_IN_STEREO;
    const audio_input_flags_t expectedFlags = AUDIO_INPUT_FLAG_FAST;
    const std::string expectedIOProfile = "mixport_fast_input";

    auto devices = mManager->getAvailableInputDevices();
    sp<DeviceDescriptor> mic = nullptr;
    for (auto device : devices) {
        if (device->type() == AUDIO_DEVICE_IN_BUILTIN_MIC) {
            mic = device;
            break;
        }
    }
    EXPECT_NE(nullptr, mic);

    audio_format_t requestedFormat = AUDIO_FORMAT_PCM_16_BIT;
    uint32_t requestedSampleRate = 48000;
    audio_channel_mask_t requestedChannelMask = AUDIO_CHANNEL_IN_STEREO;
    audio_input_flags_t requestedFlags = AUDIO_INPUT_FLAG_FAST;
    auto profile = mManager->getInputProfile(
            mic, requestedSampleRate, requestedFormat, requestedChannelMask, requestedFlags);
    EXPECT_EQ(expectedIOProfile, profile->getName());
    EXPECT_EQ(expectedFormat, requestedFormat);
    EXPECT_EQ(expectedSampleRate, requestedSampleRate);
    EXPECT_EQ(expectedChannelMask, requestedChannelMask);
    EXPECT_EQ(expectedFlags, profile->getFlags());
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, MatchesMoreInputFlagsWhenPossible) {
    const audio_format_t expectedFormat = AUDIO_FORMAT_PCM_16_BIT;
    const uint32_t expectedSampleRate = 48000;
    const audio_channel_mask_t expectedChannelMask = AUDIO_CHANNEL_IN_STEREO;
    const std::string expectedIOProfile = "mixport_fast_input";

    auto devices = mManager->getAvailableInputDevices();
    sp<DeviceDescriptor> mic = nullptr;
    for (auto device : devices) {
        if (device->type() == AUDIO_DEVICE_IN_BUILTIN_MIC) {
            mic = device;
        break;
        }
    }
    EXPECT_NE(nullptr, mic);

    audio_format_t requestedFormat = AUDIO_FORMAT_PCM_24_BIT_PACKED;
    uint32_t requestedSampleRate = 48000;
    audio_channel_mask_t requestedChannelMask = AUDIO_CHANNEL_IN_STEREO;
    auto profile = mManager->getInputProfile(
            mic, requestedSampleRate, requestedFormat, requestedChannelMask, AUDIO_INPUT_FLAG_FAST);
    EXPECT_EQ(expectedIOProfile, profile->getName());
    EXPECT_EQ(expectedFormat, requestedFormat);
    EXPECT_EQ(expectedSampleRate, requestedSampleRate);
    EXPECT_EQ(expectedChannelMask, requestedChannelMask);
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, AudioSourceFixedByGetInputforAttr) {
    const audio_port_handle_t requestedDeviceId = AUDIO_PORT_HANDLE_NONE;
    const audio_io_handle_t requestedInput = AUDIO_PORT_HANDLE_NONE;
    const AttributionSourceState attributionSource = createAttributionSourceState(/*uid=*/ 0);

    audio_attributes_t attr = {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN,
                               AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};
    audio_config_base_t requestedConfig = {
            .sample_rate = k48000SamplingRate,
            .channel_mask = AUDIO_CHANNEL_IN_STEREO,
            .format = AUDIO_FORMAT_PCM_16_BIT,
    };
    auto inputRes = mManager->getInputForAttr(attr, requestedInput, requestedDeviceId,
                                              requestedConfig, AUDIO_INPUT_FLAG_NONE, 1 /*riid*/,
                                              AUDIO_SESSION_NONE, attributionSource);
    ASSERT_TRUE(inputRes.has_value());
    ASSERT_NE(VALUE_OR_FATAL(aidl2legacy_AudioSource_audio_source_t(inputRes.value().source)),
                             AUDIO_SOURCE_DEFAULT);

    attr = {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN,
            AUDIO_SOURCE_VOICE_COMMUNICATION, AUDIO_FLAG_NONE, ""};

    inputRes = mManager->getInputForAttr(attr, requestedInput, requestedDeviceId, requestedConfig,
                                         AUDIO_INPUT_FLAG_NONE, 1 /*riid*/, AUDIO_SESSION_NONE,
                                         attributionSource);
    ASSERT_TRUE(inputRes.has_value());
    ASSERT_EQ(VALUE_OR_FATAL(aidl2legacy_AudioSource_audio_source_t(inputRes.value().source)),
                             AUDIO_SOURCE_VOICE_COMMUNICATION);
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, SelectMMapOffloadOnlyWhenRequested) {
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));

    auto devices = mManager->getAvailableOutputDevices();
    audio_port_handle_t usbPortId = AUDIO_PORT_HANDLE_NONE;
    for (auto device : devices) {
        if (device->type() == AUDIO_DEVICE_OUT_USB_DEVICE) {
            usbPortId = device->getId();
            break;
        }
    }
    EXPECT_NE(AUDIO_PORT_HANDLE_NONE, usbPortId);

    const audio_attributes_t mediaAttr = {
            .content_type = AUDIO_CONTENT_TYPE_MUSIC,
            .usage = AUDIO_USAGE_MEDIA,
    };

    for (auto flags : {(AUDIO_OUTPUT_FLAG_MMAP_NOIRQ | AUDIO_OUTPUT_FLAG_DIRECT),
                       (AUDIO_OUTPUT_FLAG_MMAP_NOIRQ | AUDIO_OUTPUT_FLAG_DIRECT |
                            AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD),
                       (AUDIO_OUTPUT_FLAG_DIRECT | AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD)}) {
        audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;
        // Use preferred device to ensure usb is selected so that mmap mix port can be used
        DeviceIdVector selectedDeviceIds = {usbPortId};
        audio_port_handle_t portId;
        ASSERT_NO_FATAL_FAILURE(getOutputForAttr(
                        &selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
                        k48000SamplingRate, static_cast<audio_output_flags_t>(flags), &output,
                        &portId));
        EXPECT_NE(AUDIO_IO_HANDLE_NONE, output);
        sp<SwAudioOutputDescriptor> outDesc = mManager->getOutputs().valueFor(output);
        ASSERT_NE(nullptr, outDesc.get());
        EXPECT_EQ(flags, outDesc->getFlags().output);
        mManager->releaseOutput(portId);
    }

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
}

TEST_F_WITH_FLAGS(AudioPolicyManagerTestWithConfigurationFile,
                  MMapOffloadMutuallyExclusive,
                  REQUIRES_FLAGS_ENABLED(
                          ACONFIG_FLAG(com::android::media::audioserver,
                                       mmap_pcm_offload_support))) {
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));

    auto devices = mManager->getAvailableOutputDevices();
    audio_port_handle_t usbPortId = AUDIO_PORT_HANDLE_NONE;
    for (auto device : devices) {
        if (device->type() == AUDIO_DEVICE_OUT_USB_DEVICE) {
            usbPortId = device->getId();
            break;
        }
    }
    ASSERT_NE(AUDIO_PORT_HANDLE_NONE, usbPortId);

    const audio_attributes_t mediaAttr = {
            .content_type = AUDIO_CONTENT_TYPE_MUSIC,
            .usage = AUDIO_USAGE_MEDIA,
    };

    const uint32_t mmapLowlatencyFlag = (AUDIO_OUTPUT_FLAG_MMAP_NOIRQ | AUDIO_OUTPUT_FLAG_DIRECT);
    const uint32_t mmapOffloadFlag = (mmapLowlatencyFlag | AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD);
    const uint32_t compressOffloadFlag =
            (AUDIO_OUTPUT_FLAG_DIRECT | AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD);

    std::map<std::string, std::vector<std::pair<uint32_t, uint32_t>>>
            systemProperty2ExclusiveFlags = {
            {"ro.audio.mmap_offload_exclusive", {
                    {mmapOffloadFlag, compressOffloadFlag},
                    {compressOffloadFlag, mmapOffloadFlag}
            }},
            {"ro.audio.mmap_low_latency_offload_exclusive", {
                    {mmapOffloadFlag, mmapLowlatencyFlag},
                    {mmapLowlatencyFlag, mmapOffloadFlag}
            }}
    };
    for (const auto& [systemProperty, mutuallyExclusiveFlagsPair] : systemProperty2ExclusiveFlags) {
        for (auto flagsPair: mutuallyExclusiveFlagsPair) {
            audio_io_handle_t output1 = AUDIO_IO_HANDLE_NONE;
            // Use preferred device to ensure usb is selected so that mmap mix port can be used
            DeviceIdVector selectedDeviceIds = {usbPortId};
            audio_port_handle_t portId1;
            ASSERT_NO_FATAL_FAILURE(getOutputForAttr(
                    &selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
                    k48000SamplingRate, static_cast<audio_output_flags_t>(flagsPair.first),
                    &output1, &portId1));
            EXPECT_NE(AUDIO_IO_HANDLE_NONE, output1);
            if (output1 == AUDIO_IO_HANDLE_NONE) {
                break;
            }
            sp<SwAudioOutputDescriptor> outDesc = mManager->getOutputs().valueFor(output1);
            ASSERT_NE(nullptr, outDesc.get());
            EXPECT_EQ(flagsPair.first, outDesc->getFlags().output);

            // Request with same output flags will get the same output.
            audio_io_handle_t output2 = AUDIO_IO_HANDLE_NONE;
            audio_port_handle_t portId2;
            ASSERT_NO_FATAL_FAILURE(getOutputForAttr(
                    &selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
                    k48000SamplingRate, static_cast<audio_output_flags_t>(flagsPair.first),
                    &output2, &portId2));
            EXPECT_EQ(output1, output2);
            mManager->releaseOutput(portId2);

            // Request with mutually exclusive flags will fail.
            audio_output_flags_t mutuallyExclusiveFlags =
                    static_cast<audio_output_flags_t>(flagsPair.second);
            audio_io_handle_t output3 = AUDIO_IO_HANDLE_NONE;
            audio_port_handle_t portId3 = AUDIO_PORT_HANDLE_NONE;
            audio_stream_type_t stream = AUDIO_STREAM_DEFAULT;
            audio_config_t config = AUDIO_CONFIG_INITIALIZER;
            config.sample_rate = k48000SamplingRate;
            config.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
            config.format = AUDIO_FORMAT_PCM_16_BIT;
            audio_port_handle_t localPortId;
            AudioPolicyInterface::output_type_t outputType;
            bool isSpatialized;
            bool isBitPerfect;
            AttributionSourceState attributionSource = createAttributionSourceState(0);
            auto result = mManager->getOutputForAttr(
                    &mediaAttr, &output3, AUDIO_SESSION_NONE, &stream, attributionSource, &config,
                    &mutuallyExclusiveFlags, &selectedDeviceIds, &portId3, {}, &outputType,
                    &isSpatialized, &isBitPerfect);
            if (property_get_bool(systemProperty.c_str(), false /*default_value*/)) {
                EXPECT_EQ(INVALID_OPERATION, result) << systemProperty
                        << " is true, should not be able to open output with flag "
                        << flagsPair.second;
                EXPECT_EQ(AUDIO_IO_HANDLE_NONE, output3) << systemProperty
                        << "is true, open failed, io handle should be none";
            } else {
                EXPECT_EQ(NO_ERROR, result) << systemProperty
                        << " is false, should be able to open output with flag "
                        << flagsPair.second;
                EXPECT_NE(AUDIO_IO_HANDLE_NONE, output3) << systemProperty
                        << " is false, open succeeded, io handle should not be none";
            }

            mManager->releaseOutput(portId1);
            mManager->releaseOutput(portId3);
        }
    }

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, PreferConfigForInputDevice) {
    mClient->addSupportedFormat(AUDIO_FORMAT_PCM_16_BIT);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_IN_MONO);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_IN_STEREO);
    const std::set<audio_channel_mask_t> kChannelMasks =
            {AUDIO_CHANNEL_IN_STEREO, AUDIO_CHANNEL_IN_MONO};
    const std::string usbAddress = "card=1;device=0";
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_IN_USB_DEVICE, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            usbAddress.c_str(), "", AUDIO_FORMAT_DEFAULT));
    audio_port_v7 usbDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SOURCE, AUDIO_DEVICE_IN_USB_DEVICE,
                               usbAddress, &usbDevicePort));
    ASSERT_EQ(1, kChannelMasks.count(usbDevicePort.active_config.channel_mask));

    const audio_port_handle_t requestedDeviceId = usbDevicePort.id;
    const audio_io_handle_t requestedInput = AUDIO_IO_HANDLE_NONE;
    const AttributionSourceState attributionSource = createAttributionSourceState(/*uid=*/ 0);
    AudioPolicyInterface::input_type_t inputType;
    audio_attributes_t attr = {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN,
                               AUDIO_SOURCE_VOICE_COMMUNICATION, AUDIO_FLAG_NONE, ""};
    audio_channel_mask_t requestedChannelMask = AUDIO_CHANNEL_IN_MONO;
    if (requestedChannelMask == usbDevicePort.active_config.channel_mask) {
        requestedChannelMask = AUDIO_CHANNEL_IN_STEREO;
    }
    audio_config_base_t requestedConfig = {
            .sample_rate = k48000SamplingRate,
            .channel_mask = requestedChannelMask,
            .format = AUDIO_FORMAT_PCM_16_BIT,
    };
    auto inputRes = mManager->getInputForAttr(
            attr, requestedInput, requestedDeviceId, requestedConfig, AUDIO_INPUT_FLAG_NONE,
            1 /*riid*/, AUDIO_SESSION_NONE, attributionSource);

    ASSERT_TRUE(inputRes.has_value());
    ASSERT_NE(inputRes->portId, AUDIO_PORT_HANDLE_NONE);
    ASSERT_EQ(requestedDeviceId,inputRes->selectedDeviceId);

    // The input is using a different channel mask from the default one for the device.
    // After the client starts, the device should use the same configuration as the client.
    ASSERT_EQ(NO_ERROR, mManager->startInput(inputRes->portId));
    audio_port_v7 usbDevicePort2;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SOURCE, AUDIO_DEVICE_IN_USB_DEVICE,
                               usbAddress, &usbDevicePort2));
    ASSERT_EQ(requestedChannelMask, usbDevicePort2.active_config.channel_mask);

    // After the client is released, the device should reuse the default configuration.
    ASSERT_EQ(NO_ERROR, mManager->stopInput(inputRes->portId));
    mManager->releaseInput(inputRes->portId);
    audio_port_v7 usbDevicePort3;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SOURCE, AUDIO_DEVICE_IN_USB_DEVICE,
                               usbAddress, &usbDevicePort3));
    ASSERT_EQ(usbDevicePort.active_config.channel_mask, usbDevicePort3.active_config.channel_mask);

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_IN_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
}

TEST_F(AudioPolicyManagerTestWithConfigurationFile, SystemEnforcement) {
    mClient->addSupportedFormat(AUDIO_FORMAT_PCM_16_BIT);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_OUT_STEREO);
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
    auto devices = mManager->getAvailableOutputDevices();
    audio_port_handle_t usbPortId = AUDIO_PORT_HANDLE_NONE;
    audio_port_handle_t speakerPortId = AUDIO_PORT_HANDLE_NONE;
    for (auto device : devices) {
        if (device->type() == AUDIO_DEVICE_OUT_USB_DEVICE) {
            usbPortId = device->getId();
        }
        if (device->type() == AUDIO_DEVICE_OUT_SPEAKER) {
            speakerPortId = device->getId();
        }
    }
    ASSERT_NE(AUDIO_PORT_HANDLE_NONE, usbPortId);
    ASSERT_NE(AUDIO_PORT_HANDLE_NONE, speakerPortId);

    mManager->setForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM, AUDIO_POLICY_FORCE_SYSTEM_ENFORCED);

    mManager->setPhoneState(AUDIO_MODE_IN_CALL);

    const uid_t uid = 1234;
    const audio_attributes_t enforcedAttr = {
            .content_type = AUDIO_CONTENT_TYPE_SONIFICATION,
            .usage = AUDIO_USAGE_ASSISTANCE_SONIFICATION,
            .source = AUDIO_SOURCE_DEFAULT,
            .flags = AUDIO_FLAG_AUDIBILITY_ENFORCED,
            .tags = ""
    };

    audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;
    DeviceIdVector selectedDeviceIds;
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                                             AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                                             AUDIO_OUTPUT_FLAG_NONE, &output, &portId,
                                             enforcedAttr, AUDIO_SESSION_NONE, uid));

    EXPECT_FALSE(selectedDeviceIds.empty());
    EXPECT_NE(std::find(selectedDeviceIds.begin(), selectedDeviceIds.end(), usbPortId),
              selectedDeviceIds.end());
    EXPECT_NE(std::find(selectedDeviceIds.begin(), selectedDeviceIds.end(), speakerPortId),
              selectedDeviceIds.end());

    float volume;
    bool muted;
    EXPECT_EQ(NO_ERROR, mManager->startOutput(portId, &volume, &muted));
    const auto outputDesc = mManager->getOutputs().valueFor(output);
    EXPECT_NE(nullptr, outputDesc);
    EXPECT_EQ(2, outputDesc->devices().size());
    EXPECT_NE(nullptr, outputDesc->devices().getDeviceFromId(usbPortId));
    EXPECT_NE(nullptr, outputDesc->devices().getDeviceFromId(speakerPortId));

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
}

class AudioPolicyManagerTestDynamicPolicy : public AudioPolicyManagerTestWithConfigurationFile {
protected:
    void TearDown() override;

    status_t addPolicyMix(int mixType, int mixFlag, audio_devices_t deviceType,
            std::string mixAddress, const audio_config_t& audioConfig,
            const std::vector<AudioMixMatchCriterion>& matchCriteria);

    status_t addPolicyMix(const AudioMix& mix);

    status_t removePolicyMixes(const std::vector<AudioMix>& mixes);

    std::vector<AudioMix> getRegisteredPolicyMixes();
    void clearPolicyMix();
    void addPolicyMixAndStartInputForLoopback(
            int mixType, int mixFlag, audio_devices_t deviceType, std::string mixAddress,
            const audio_config_t& audioConfig,
            const std::vector<AudioMixMatchCriterion>& matchCriteria,
            audio_session_t session=AUDIO_SESSION_NONE,
            audio_config_base_t config=DEFAULT_INPUT_CONFIG,
            audio_input_flags_t inputFlags=AUDIO_INPUT_FLAG_NONE);

    std::vector<AudioMix> mAudioMixes;
    const std::string mMixAddress = "remote_submix_media";

    audio_port_handle_t mLoopbackInputPortId = AUDIO_PORT_HANDLE_NONE;
    std::unique_ptr<RecordingActivityTracker> mTracker;
    struct audio_port_v7 mInjectionPort;

    constexpr static const audio_config_base_t DEFAULT_INPUT_CONFIG = {
            .sample_rate = k48000SamplingRate,
            .channel_mask = AUDIO_CHANNEL_IN_STEREO,
            .format = AUDIO_FORMAT_PCM_16_BIT
    };
};

void AudioPolicyManagerTestDynamicPolicy::TearDown() {
    clearPolicyMix();
    AudioPolicyManagerTestWithConfigurationFile::TearDown();
}

status_t AudioPolicyManagerTestDynamicPolicy::addPolicyMix(int mixType, int mixFlag,
        audio_devices_t deviceType, std::string mixAddress, const audio_config_t& audioConfig,
        const std::vector<AudioMixMatchCriterion>& matchCriteria = {}) {
    AudioMix myAudioMix(matchCriteria, mixType, audioConfig, mixFlag,
            String8(mixAddress.c_str()), 0);
    myAudioMix.mDeviceType = deviceType;
    myAudioMix.mToken = sp<BBinder>::make();
    // Clear mAudioMix before add new one to make sure we don't add already exist mixes.
    mAudioMixes.clear();
    return addPolicyMix(myAudioMix);
}

status_t AudioPolicyManagerTestDynamicPolicy::addPolicyMix(const AudioMix& mix) {
    mAudioMixes.push_back(mix);

    // As the policy mixes registration may fail at some case,
    // caller need to check the returned status.
    status_t ret = mManager->registerPolicyMixes(mAudioMixes);
    return ret;
}

status_t AudioPolicyManagerTestDynamicPolicy::removePolicyMixes(
        const std::vector<AudioMix>& mixes) {
    status_t ret = mManager->unregisterPolicyMixes(mixes);
    return ret;
}

std::vector<AudioMix> AudioPolicyManagerTestDynamicPolicy::getRegisteredPolicyMixes() {
    std::vector<AudioMix> audioMixes;
    if (mManager != nullptr) {
        status_t ret = mManager->getRegisteredPolicyMixes(audioMixes);
        EXPECT_EQ(NO_ERROR, ret);
    }
    return audioMixes;
}

void AudioPolicyManagerTestDynamicPolicy::clearPolicyMix() {
    if (mManager != nullptr) {
        mManager->stopInput(mLoopbackInputPortId);
        mManager->unregisterPolicyMixes(mAudioMixes);
    }
    mAudioMixes.clear();
}

void AudioPolicyManagerTestDynamicPolicy::addPolicyMixAndStartInputForLoopback(
        int mixType, int mixFlag, audio_devices_t deviceType, std::string mixAddress,
        const audio_config_t& audioConfig,
        const std::vector<AudioMixMatchCriterion>& matchCriteria, audio_session_t session,
        audio_config_base_t config, audio_input_flags_t inputFlags) {
    ASSERT_EQ(NO_ERROR,
              addPolicyMix(mixType, mixFlag, deviceType, mixAddress, audioConfig, matchCriteria));
    if ((mixFlag & MIX_ROUTE_FLAG_LOOP_BACK) != MIX_ROUTE_FLAG_LOOP_BACK) {
        return;
    }

    mTracker.reset(new RecordingActivityTracker());
    struct audio_port_v7 extractionPort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SOURCE, AUDIO_DEVICE_IN_REMOTE_SUBMIX,
                               mixAddress, &extractionPort));
    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_source_t source = AUDIO_SOURCE_REMOTE_SUBMIX;
    audio_attributes_t attr = {
            AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN, source, AUDIO_FLAG_NONE, ""};
    std::string tags = "addr=" + mMixAddress;
    audio_io_handle_t input = AUDIO_PORT_HANDLE_NONE;
    strncpy(attr.tags, tags.c_str(), AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1);
    ASSERT_NO_FATAL_FAILURE(
            getInputForAttr(attr, &input, session, mTracker->getRiid(),
                            &selectedDeviceId, config.format, config.channel_mask,
                            config.sample_rate, inputFlags, &mLoopbackInputPortId));
    ASSERT_EQ(NO_ERROR, mManager->startInput(mLoopbackInputPortId));
    ASSERT_EQ(extractionPort.id, selectedDeviceId);

    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_REMOTE_SUBMIX,
                               mMixAddress, &mInjectionPort));
}

TEST_F(AudioPolicyManagerTestDynamicPolicy, InitSuccess) {
    // SetUp must finish with no assertions
}

TEST_F(AudioPolicyManagerTestDynamicPolicy, Dump) {
    dumpToLog();
}

TEST_F(AudioPolicyManagerTestDynamicPolicy, RegisterPolicyMixes) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;

    // Only capture of playback is allowed in LOOP_BACK &RENDER mode
    ret = addPolicyMix(MIX_TYPE_RECORDERS, MIX_ROUTE_FLAG_LOOP_BACK_AND_RENDER,
            AUDIO_DEVICE_OUT_REMOTE_SUBMIX, "", audioConfig);
    ASSERT_EQ(INVALID_OPERATION, ret);

    // Fail due to the device is already connected.
    clearPolicyMix();
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_LOOP_BACK,
            AUDIO_DEVICE_OUT_REMOTE_SUBMIX, "", audioConfig);
    ASSERT_EQ(INVALID_OPERATION, ret);

    // The first time to register policy mixes with valid parameter should succeed.
    clearPolicyMix();
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_LOOP_BACK,
            AUDIO_DEVICE_OUT_REMOTE_SUBMIX, mMixAddress, audioConfig);
    ASSERT_EQ(NO_ERROR, ret);
    // Registering the same policy mixes should fail.
    ret = mManager->registerPolicyMixes(mAudioMixes);
    ASSERT_EQ(INVALID_OPERATION, ret);

    // Registration should fail due to device not found.
    // Note that earpiece is not present in the test configuration file.
    // This will need to be updated if earpiece is added in the test configuration file.
    clearPolicyMix();
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_EARPIECE, "", audioConfig);
    ASSERT_EQ(INVALID_OPERATION, ret);

    // Registration should fail due to output not found.
    clearPolicyMix();
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_REMOTE_SUBMIX, "", audioConfig);
    ASSERT_EQ(INVALID_OPERATION, ret);

    // The first time to register valid loopback policy mix should succeed.
    clearPolicyMix();
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_LOOP_BACK,
            AUDIO_DEVICE_OUT_REMOTE_SUBMIX, "addr", audioConfig);
    ASSERT_EQ(NO_ERROR, ret);
    // Registering the render policy for the loopback address should succeed.
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_REMOTE_SUBMIX, "addr", audioConfig);
    ASSERT_EQ(INVALID_OPERATION, ret);
}

TEST_F(AudioPolicyManagerTestDynamicPolicy, UnregisterPolicyMixes) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;

    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_LOOP_BACK,
            AUDIO_DEVICE_OUT_REMOTE_SUBMIX, mMixAddress, audioConfig);
    ASSERT_EQ(NO_ERROR, ret);

    // After successfully registering policy mixes, it should be able to unregister.
    ret = mManager->unregisterPolicyMixes(mAudioMixes);
    ASSERT_EQ(NO_ERROR, ret);

    // After unregistering policy mixes successfully, it should fail unregistering
    // the same policy mixes as they are not registered.
    ret = mManager->unregisterPolicyMixes(mAudioMixes);
    ASSERT_EQ(INVALID_OPERATION, ret);
}

TEST_F(AudioPolicyManagerTestDynamicPolicy, RegisterPolicyWithConsistentMixSucceeds) {
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;

    std::vector<AudioMixMatchCriterion> mixMatchCriteria = {
        createUidCriterion(/*uid=*/42),
        createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/true)};
    status_t ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_LOOP_BACK,
                                AUDIO_DEVICE_OUT_REMOTE_SUBMIX, mMixAddress, audioConfig,
                                mixMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
}

TEST_F(AudioPolicyManagerTestDynamicPolicy, RegisterPolicyWithInconsistentMixFails) {
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;

    std::vector<AudioMixMatchCriterion> mixMatchCriteria = {
        createUidCriterion(/*uid=*/42),
        createUidCriterion(/*uid=*/1235, /*exclude=*/true),
        createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/true)};
    status_t ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_LOOP_BACK,
                                AUDIO_DEVICE_OUT_REMOTE_SUBMIX, mMixAddress, audioConfig,
                                mixMatchCriteria);
    ASSERT_EQ(INVALID_OPERATION, ret);
}

TEST_F(AudioPolicyManagerTestDynamicPolicy, RegisterInvalidMixesDoesNotImpactPriorMixes) {
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;

    std::vector<AudioMixMatchCriterion> validMixMatchCriteria = {
            createUidCriterion(/*uid=*/42),
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/true)};
    AudioMix validAudioMix(validMixMatchCriteria, MIX_TYPE_PLAYERS, audioConfig,
                           MIX_ROUTE_FLAG_LOOP_BACK, String8(mMixAddress.c_str()), 0);
    validAudioMix.mDeviceType = AUDIO_DEVICE_OUT_REMOTE_SUBMIX;

    mAudioMixes.clear();
    status_t ret = addPolicyMix(validAudioMix);

    ASSERT_EQ(NO_ERROR, ret);

    std::vector<AudioMix> registeredMixes = getRegisteredPolicyMixes();
    ASSERT_EQ(1, registeredMixes.size());

    std::vector<AudioMixMatchCriterion> invalidMixMatchCriteria = {
            createUidCriterion(/*uid=*/42),
            createUidCriterion(/*uid=*/1235, /*exclude=*/true),
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/true)};

    AudioMix invalidAudioMix(invalidMixMatchCriteria, MIX_TYPE_PLAYERS, audioConfig,
                             MIX_ROUTE_FLAG_LOOP_BACK, String8(mMixAddress.c_str()), 0);
    validAudioMix.mDeviceType = AUDIO_DEVICE_OUT_REMOTE_SUBMIX;

    ret = addPolicyMix(invalidAudioMix);

    ASSERT_EQ(INVALID_OPERATION, ret);

    std::vector<AudioMix> remainingMixes = getRegisteredPolicyMixes();
    ASSERT_EQ(registeredMixes.size(), remainingMixes.size());
}

TEST_F(AudioPolicyManagerTestDynamicPolicy, UnregisterInvalidMixesReturnsError) {
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;

    std::vector<AudioMixMatchCriterion> validMixMatchCriteria = {
            createUidCriterion(/*uid=*/42),
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/true)};
    AudioMix validAudioMix(validMixMatchCriteria, MIX_TYPE_PLAYERS, audioConfig,
                           MIX_ROUTE_FLAG_LOOP_BACK, String8(mMixAddress.c_str()), 0);
    validAudioMix.mDeviceType = AUDIO_DEVICE_OUT_REMOTE_SUBMIX;

    mAudioMixes.clear();
    status_t ret = addPolicyMix(validAudioMix);

    ASSERT_EQ(NO_ERROR, ret);

    std::vector<AudioMix> registeredMixes = getRegisteredPolicyMixes();
    ASSERT_EQ(1, registeredMixes.size());

    std::vector<AudioMixMatchCriterion> invalidMixMatchCriteria = {
            createUidCriterion(/*uid=*/42),
            createUidCriterion(/*uid=*/1235, /*exclude=*/true),
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/true)};

    AudioMix invalidAudioMix(invalidMixMatchCriteria, MIX_TYPE_PLAYERS, audioConfig,
                             MIX_ROUTE_FLAG_LOOP_BACK, String8(mMixAddress.c_str()), 0);
    invalidAudioMix.mDeviceType = AUDIO_DEVICE_OUT_REMOTE_SUBMIX;

    std::vector<AudioMix> mixes{
        invalidAudioMix,
        validAudioMix,
    };
    ret = removePolicyMixes(mixes);

    ASSERT_EQ(INVALID_OPERATION, ret);

    std::vector<AudioMix> remainingMixes = getRegisteredPolicyMixes();
    EXPECT_THAT(remainingMixes, IsEmpty());
}

TEST_F(AudioPolicyManagerTestDynamicPolicy, GetRegisteredPolicyMixes) {
    std::vector<AudioMix> mixes = getRegisteredPolicyMixes();
    EXPECT_THAT(mixes, IsEmpty());
}

TEST_F(AudioPolicyManagerTestDynamicPolicy, AddPolicyMixAndVerifyGetRegisteredPolicyMixes) {
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;

    std::vector<AudioMixMatchCriterion> mixMatchCriteria = {
            createUidCriterion(/*uid=*/42),
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/true)};
    status_t ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_LOOP_BACK,
                                AUDIO_DEVICE_OUT_REMOTE_SUBMIX, mMixAddress, audioConfig,
                                mixMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);

    std::vector<AudioMix> mixes = getRegisteredPolicyMixes();
    ASSERT_EQ(mixes.size(), 1);

    const AudioMix& mix = mixes[0];
    ASSERT_EQ(mix.mCriteria.size(), mixMatchCriteria.size());
    for (uint32_t i = 0; i < mixMatchCriteria.size(); i++) {
        EXPECT_EQ(mix.mCriteria[i].mRule, mixMatchCriteria[i].mRule);
        EXPECT_EQ(mix.mCriteria[i].mValue.mUsage, mixMatchCriteria[i].mValue.mUsage);
    }
    EXPECT_EQ(mix.mDeviceType, AUDIO_DEVICE_OUT_REMOTE_SUBMIX);
    EXPECT_EQ(mix.mRouteFlags, MIX_ROUTE_FLAG_LOOP_BACK);
    EXPECT_EQ(mix.mMixType, MIX_TYPE_PLAYERS);
    EXPECT_EQ(mix.mFormat.channel_mask, audioConfig.channel_mask);
    EXPECT_EQ(mix.mFormat.format, audioConfig.format);
    EXPECT_EQ(mix.mFormat.sample_rate, audioConfig.sample_rate);
    EXPECT_EQ(mix.mFormat.frame_count, audioConfig.frame_count);
}

class AudioPolicyManagerTestForHdmi
        : public AudioPolicyManagerTestWithConfigurationFile,
          public testing::WithParamInterface<audio_format_t> {
protected:
    void SetUp() override;
    std::string getConfigFile() override { return sTvConfig; }
    std::map<audio_format_t, bool> getSurroundFormatsHelper();
    std::vector<audio_format_t> getReportedSurroundFormatsHelper();
    std::unordered_set<audio_format_t> getFormatsFromPorts();
    void TearDown() override;

    static const std::string sTvConfig;

};

const std::string AudioPolicyManagerTestForHdmi::sTvConfig =
        AudioPolicyManagerTestForHdmi::sExecutableDir +
        "test_settop_box_surround_configuration.xml";

void AudioPolicyManagerTestForHdmi::SetUp() {
    ASSERT_NO_FATAL_FAILURE(AudioPolicyManagerTest::SetUp());
    mClient->addSupportedFormat(AUDIO_FORMAT_AC3);
    mClient->addSupportedFormat(AUDIO_FORMAT_E_AC3);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_OUT_STEREO);
    mManager->setDeviceConnectionState(
            AUDIO_DEVICE_OUT_HDMI, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            "" /*address*/, "" /*name*/, AUDIO_FORMAT_DEFAULT);
}

void AudioPolicyManagerTestForHdmi::TearDown() {
    mManager->setDeviceConnectionState(
            AUDIO_DEVICE_OUT_HDMI, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
            "" /*address*/, "" /*name*/, AUDIO_FORMAT_DEFAULT);
    AudioPolicyManagerTest::TearDown();
}

std::map<audio_format_t, bool>
        AudioPolicyManagerTestForHdmi::getSurroundFormatsHelper() {
    unsigned int numSurroundFormats = 0;
    std::map<audio_format_t, bool> surroundFormatsMap;
    status_t ret = mManager->getSurroundFormats(
            &numSurroundFormats, nullptr /* surroundFormats */,
            nullptr /* surroundFormatsEnabled */);
    EXPECT_EQ(NO_ERROR, ret);
    if (ret != NO_ERROR) {
        return surroundFormatsMap;
    }
    audio_format_t surroundFormats[numSurroundFormats];
    memset(surroundFormats, 0, sizeof(audio_format_t) * numSurroundFormats);
    bool surroundFormatsEnabled[numSurroundFormats];
    memset(surroundFormatsEnabled, 0, sizeof(bool) * numSurroundFormats);
    ret = mManager->getSurroundFormats(
            &numSurroundFormats, surroundFormats, surroundFormatsEnabled);
    EXPECT_EQ(NO_ERROR, ret);
    if (ret != NO_ERROR) {
        return surroundFormatsMap;
    }
    for (int i = 0; i< numSurroundFormats; i++) {
        surroundFormatsMap[surroundFormats[i]] = surroundFormatsEnabled[i];
    }
    return surroundFormatsMap;
}

std::vector<audio_format_t> AudioPolicyManagerTestForHdmi::getReportedSurroundFormatsHelper() {
    unsigned int numSurroundFormats = 0;
    std::vector<audio_format_t>  surroundFormatsVector;
    status_t ret = mManager->getReportedSurroundFormats(
            &numSurroundFormats, nullptr /* surroundFormats */);
    EXPECT_EQ(NO_ERROR, ret);
    if (ret != NO_ERROR) {
        return surroundFormatsVector;
    }
    audio_format_t surroundFormats[numSurroundFormats];
    memset(surroundFormats, 0, sizeof(audio_format_t) * numSurroundFormats);
    ret = mManager->getReportedSurroundFormats(&numSurroundFormats, surroundFormats);
    EXPECT_EQ(NO_ERROR, ret);
    if (ret != NO_ERROR) {
        return surroundFormatsVector;
    }
    for (const auto &surroundFormat : surroundFormats) {
        surroundFormatsVector.push_back(surroundFormat);
    }
    return surroundFormatsVector;
}

std::unordered_set<audio_format_t>
        AudioPolicyManagerTestForHdmi::getFormatsFromPorts() {
    uint32_t numPorts = 0;
    uint32_t generation1;
    status_t ret;
    std::unordered_set<audio_format_t> formats;
    ret = mManager->listAudioPorts(
            AUDIO_PORT_ROLE_SINK, AUDIO_PORT_TYPE_DEVICE, &numPorts, nullptr, &generation1);
    EXPECT_EQ(NO_ERROR, ret) << "mManager->listAudioPorts returned error";
    if (ret != NO_ERROR) {
        return formats;
    }
    struct audio_port_v7 ports[numPorts];
    ret = mManager->listAudioPorts(
            AUDIO_PORT_ROLE_SINK, AUDIO_PORT_TYPE_DEVICE, &numPorts, ports, &generation1);
    EXPECT_EQ(NO_ERROR, ret) << "mManager->listAudioPorts returned error";
    if (ret != NO_ERROR) {
        return formats;
    }
    for (const auto &port : ports) {
        for (size_t i = 0; i < port.num_audio_profiles; ++i) {
            formats.insert(port.audio_profiles[i].format);
        }
    }
    return formats;
}

TEST_P(AudioPolicyManagerTestForHdmi, GetSurroundFormatsReturnsSupportedFormats) {
    mManager->setForceUse(
            AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND, AUDIO_POLICY_FORCE_ENCODED_SURROUND_ALWAYS);
    auto surroundFormats = getSurroundFormatsHelper();
    ASSERT_EQ(1, surroundFormats.count(GetParam()));
}

TEST_P(AudioPolicyManagerTestForHdmi,
        GetSurroundFormatsReturnsManipulatedFormats) {
    mManager->setForceUse(
            AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND, AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL);

    status_t ret =
            mManager->setSurroundFormatEnabled(GetParam(), false /*enabled*/);
    ASSERT_EQ(NO_ERROR, ret);
    auto surroundFormats = getSurroundFormatsHelper();
    ASSERT_EQ(1, surroundFormats.count(GetParam()));
    ASSERT_FALSE(surroundFormats[GetParam()]);

    ret = mManager->setSurroundFormatEnabled(GetParam(), true /*enabled*/);
    ASSERT_EQ(NO_ERROR, ret);
    surroundFormats = getSurroundFormatsHelper();
    ASSERT_EQ(1, surroundFormats.count(GetParam()));
    ASSERT_TRUE(surroundFormats[GetParam()]);

    ret = mManager->setSurroundFormatEnabled(GetParam(), false /*enabled*/);
    ASSERT_EQ(NO_ERROR, ret);
    surroundFormats = getSurroundFormatsHelper();
    ASSERT_EQ(1, surroundFormats.count(GetParam()));
    ASSERT_FALSE(surroundFormats[GetParam()]);
}

TEST_P(AudioPolicyManagerTestForHdmi,
        ListAudioPortsReturnManipulatedHdmiFormats) {
    mManager->setForceUse(
            AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND, AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL);

    ASSERT_EQ(NO_ERROR, mManager->setSurroundFormatEnabled(GetParam(), true /*enabled*/));
    auto formats = getFormatsFromPorts();
    ASSERT_EQ(1, formats.count(GetParam()));

    ASSERT_EQ(NO_ERROR, mManager->setSurroundFormatEnabled(GetParam(), false /*enabled*/));
    formats = getFormatsFromPorts();
    ASSERT_EQ(0, formats.count(GetParam()));
}

TEST_P(AudioPolicyManagerTestForHdmi,
        GetReportedSurroundFormatsReturnsHdmiReportedFormats) {
    mManager->setForceUse(
            AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND, AUDIO_POLICY_FORCE_ENCODED_SURROUND_ALWAYS);
    auto surroundFormats = getReportedSurroundFormatsHelper();
    ASSERT_EQ(1, std::count(surroundFormats.begin(), surroundFormats.end(), GetParam()));
}

TEST_P(AudioPolicyManagerTestForHdmi,
        GetReportedSurroundFormatsReturnsNonManipulatedHdmiReportedFormats) {
    mManager->setForceUse(
            AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND, AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL);

    status_t ret = mManager->setSurroundFormatEnabled(GetParam(), false /*enabled*/);
    ASSERT_EQ(NO_ERROR, ret);
    auto surroundFormats = getReportedSurroundFormatsHelper();
    ASSERT_EQ(1, std::count(surroundFormats.begin(), surroundFormats.end(), GetParam()));

    ret = mManager->setSurroundFormatEnabled(GetParam(), true /*enabled*/);
    ASSERT_EQ(NO_ERROR, ret);
    surroundFormats = getReportedSurroundFormatsHelper();
    ASSERT_EQ(1, std::count(surroundFormats.begin(), surroundFormats.end(), GetParam()));
}

TEST_P(AudioPolicyManagerTestForHdmi, GetSurroundFormatsIgnoresSupportedFormats) {
    mManager->setForceUse(
            AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND, AUDIO_POLICY_FORCE_ENCODED_SURROUND_NEVER);
    auto surroundFormats = getSurroundFormatsHelper();
    ASSERT_EQ(1, surroundFormats.count(GetParam()));
    ASSERT_FALSE(surroundFormats[GetParam()]);
}

INSTANTIATE_TEST_SUITE_P(SurroundFormatSupport, AudioPolicyManagerTestForHdmi,
        testing::Values(AUDIO_FORMAT_AC3, AUDIO_FORMAT_E_AC3),
        [](const ::testing::TestParamInfo<AudioPolicyManagerTestForHdmi::ParamType>& info) {
            return audio_format_to_string(info.param);
        });

class AudioPolicyManagerTestDPNoRemoteSubmixModule : public AudioPolicyManagerTestDynamicPolicy {
protected:
    std::string getConfigFile() override { return sPrimaryOnlyConfig; }

    static const std::string sPrimaryOnlyConfig;
};

const std::string AudioPolicyManagerTestDPNoRemoteSubmixModule::sPrimaryOnlyConfig =
        sExecutableDir + "test_audio_policy_primary_only_configuration.xml";

TEST_F(AudioPolicyManagerTestDPNoRemoteSubmixModule, InitSuccess) {
    // SetUp must finish with no assertions.
}

TEST_F(AudioPolicyManagerTestDPNoRemoteSubmixModule, Dump) {
    dumpToLog();
}

TEST_F(AudioPolicyManagerTestDPNoRemoteSubmixModule, RegistrationFailure) {
    // Registration/Unregistration should fail due to module for remote submix not found.
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_LOOP_BACK,
            AUDIO_DEVICE_OUT_REMOTE_SUBMIX, "", audioConfig);
    ASSERT_EQ(INVALID_OPERATION, ret);

    ret = mManager->unregisterPolicyMixes(mAudioMixes);
    ASSERT_EQ(INVALID_OPERATION, ret);
}

struct DPTestParam {
    DPTestParam(const std::vector<AudioMixMatchCriterion>& mixCriteria,
                bool expected_match = false)
     : mixCriteria(mixCriteria), attributes(defaultAttr), session(AUDIO_SESSION_NONE),
       expected_match(expected_match) {}

    DPTestParam& withUsage(audio_usage_t usage) {
        attributes.usage = usage;
        return *this;
    }

    DPTestParam& withTags(const char *tags) {
        std::strncpy(attributes.tags, tags, sizeof(attributes.tags));
        return *this;
    }

    DPTestParam& withSource(audio_source_t source) {
        attributes.source = source;
        return *this;
    }

    DPTestParam& withSessionId(audio_session_t sessionId) {
        session = sessionId;
        return *this;
    }

    std::vector<AudioMixMatchCriterion> mixCriteria;
    audio_attributes_t attributes;
    audio_session_t session;
    bool expected_match;
};

class AudioPolicyManagerTestDPPlaybackReRouting : public AudioPolicyManagerTestDynamicPolicy,
        public testing::WithParamInterface<DPTestParam> {
protected:
    void SetUp() override;
};

void AudioPolicyManagerTestDPPlaybackReRouting::SetUp() {
    ASSERT_NO_FATAL_FAILURE(AudioPolicyManagerTestDynamicPolicy::SetUp());

    mTracker.reset(new RecordingActivityTracker());

    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;

    DPTestParam param = GetParam();
    ASSERT_NO_FATAL_FAILURE(
            addPolicyMixAndStartInputForLoopback(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_LOOP_BACK,
            AUDIO_DEVICE_OUT_REMOTE_SUBMIX, mMixAddress, audioConfig, param.mixCriteria,
            param.session));
}

TEST_P(AudioPolicyManagerTestDPPlaybackReRouting, PlaybackReRouting) {
    const DPTestParam param = GetParam();
    const audio_attributes_t& attr = param.attributes;

    DeviceIdVector playbackRoutedPortIds;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&playbackRoutedPortIds, AUDIO_FORMAT_PCM_16_BIT,
                    AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                    AUDIO_OUTPUT_FLAG_NONE,
                    nullptr /*output*/, nullptr /*portId*/,
                    attr, param.session));
    if (param.expected_match) {
        ASSERT_EQ(mInjectionPort.id, playbackRoutedPortIds[0]);
    } else {
        ASSERT_GT(playbackRoutedPortIds.size(), 0);
        ASSERT_NE(mInjectionPort.id, playbackRoutedPortIds[0]);
    }
}

const std::vector<AudioMixMatchCriterion> USAGE_MEDIA_ALARM_CRITERIA = {
            createUsageCriterion(AUDIO_USAGE_MEDIA),
            createUsageCriterion(AUDIO_USAGE_ALARM)
};

INSTANTIATE_TEST_SUITE_P(
    PlaybackReroutingUsageMatch,
    AudioPolicyManagerTestDPPlaybackReRouting,
    testing::Values(
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_MEDIA),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_MEDIA).withTags("addr=other"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_ALARM),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_VOICE_COMMUNICATION),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_NOTIFICATION),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_NOTIFICATION_EVENT),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_ASSISTANCE_SONIFICATION),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_GAME),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ false)
            .withUsage(AUDIO_USAGE_ASSISTANT)));

INSTANTIATE_TEST_SUITE_P(
    PlaybackReroutingAddressPriorityMatch,
    AudioPolicyManagerTestDPPlaybackReRouting,
    testing::Values(
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_MEDIA).withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_VOICE_COMMUNICATION).withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_ALARM)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_NOTIFICATION)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_NOTIFICATION_EVENT)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_ASSISTANCE_SONIFICATION)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_GAME)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_VIRTUAL_SOURCE)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_ASSISTANT)
            .withTags("addr=remote_submix_media"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_ASSISTANT)
            .withTags("sometag;addr=remote_submix_media;othertag=somevalue"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_ASSISTANT)
            .withTags("addr=remote_submix_media;othertag"),
        DPTestParam(USAGE_MEDIA_ALARM_CRITERIA, /*expected_match=*/ true)
            .withUsage(AUDIO_USAGE_ASSISTANT)
            .withTags("sometag;othertag;addr=remote_submix_media")));

static constexpr audio_session_t TEST_SESSION_ID = static_cast<audio_session_t>(42);
static constexpr audio_session_t OTHER_SESSION_ID = static_cast<audio_session_t>(77);

INSTANTIATE_TEST_SUITE_P(
    PlaybackReRoutingWithSessionId,
    AudioPolicyManagerTestDPPlaybackReRouting,
    testing::Values(
        // Mix is matched because the session id matches the one specified by the mix rule.
        DPTestParam(/*mixCriteria=*/ {createSessionIdCriterion(TEST_SESSION_ID)},
                    /*expected_match=*/ true)
            .withSessionId(TEST_SESSION_ID),
        // Mix is not matched because the session id doesn't match the one specified
        // by the mix rule.
        DPTestParam(/*mixCriteria=*/ {createSessionIdCriterion(TEST_SESSION_ID)},
                    /*expected_match=*/ false)
            .withSessionId(OTHER_SESSION_ID),
        // Mix is matched, the session id doesn't match the one specified by rule,
        // but there's address specified in the tags which takes precedence.
        DPTestParam(/*mixCriteria=*/ {createSessionIdCriterion(TEST_SESSION_ID)},
                    /*expected_match=*/ true)
            .withSessionId(OTHER_SESSION_ID).withTags("addr=remote_submix_media"),
        // Mix is matched, both the session id and the usage match ones specified by mix rule.
        DPTestParam(/*mixCriteria=*/ {createSessionIdCriterion(TEST_SESSION_ID),
                                      createUsageCriterion(AUDIO_USAGE_MEDIA)},
                    /*expected_match=*/ true)
            .withSessionId(TEST_SESSION_ID).withUsage(AUDIO_USAGE_MEDIA),
        // Mix is not matched, the session id matches the one specified by mix rule,
        // but usage does not.
        DPTestParam(/*mixCriteria=*/ {createSessionIdCriterion(TEST_SESSION_ID),
                                      createUsageCriterion(AUDIO_USAGE_MEDIA)},
                    /*expected_match=*/ false)
                    .withSessionId(TEST_SESSION_ID).withUsage(AUDIO_USAGE_GAME),
        // Mix is not matched, the usage matches the one specified by mix rule,
        // but the session id is excluded.
        DPTestParam(/*mixCriteria=*/ {createSessionIdCriterion(TEST_SESSION_ID, /*exclude=*/ true),
                                     createUsageCriterion(AUDIO_USAGE_MEDIA)},
                    /*expected_match=*/ false)
                    .withSessionId(TEST_SESSION_ID).withUsage(AUDIO_USAGE_MEDIA)));

struct DPMmapTestParam {
    DPMmapTestParam(int mixRouteFlags, audio_devices_t deviceType, const std::string& deviceAddress)
        : mixRouteFlags(mixRouteFlags), deviceType(deviceType), deviceAddress(deviceAddress) {}

    int mixRouteFlags;
    audio_devices_t deviceType;
    std::string deviceAddress;
};

class AudioPolicyManagerTestMMapPlaybackRerouting
    : public AudioPolicyManagerTestDynamicPolicy,
      public ::testing::WithParamInterface<DPMmapTestParam> {
  protected:
    void SetUp() override {
        AudioPolicyManagerTestDynamicPolicy::SetUp();
        audioConfig = AUDIO_CONFIG_INITIALIZER;
        audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
        audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
        audioConfig.sample_rate = k48000SamplingRate;
    }

    audio_config_t audioConfig;
    audio_io_handle_t mOutput;
    audio_stream_type_t mStream = AUDIO_STREAM_DEFAULT;
    DeviceIdVector mSelectedDeviceIds;
    audio_port_handle_t mPortId = AUDIO_PORT_HANDLE_NONE;
    AudioPolicyInterface::output_type_t mOutputType;
    audio_attributes_t attr = AUDIO_ATTRIBUTES_INITIALIZER;
    bool mIsSpatialized;
    bool mIsBitPerfect;
    float mVolume;
    bool mMuted;
};

TEST_P(AudioPolicyManagerTestMMapPlaybackRerouting, MmapPlaybackStreamMatchingLoopbackDapMixFails) {
    // Add mix matching the test uid.
    const int testUid = 12345;
    const auto param = GetParam();
    ASSERT_NO_FATAL_FAILURE(
            addPolicyMixAndStartInputForLoopback(MIX_TYPE_PLAYERS, param.mixRouteFlags,
                                                 param.deviceType, param.deviceAddress, audioConfig,
                                                 {createUidCriterion(testUid)}));

    // Getting output for matching uid and mmap-ed stream should fail.
    audio_output_flags_t outputFlags =
            (audio_output_flags_t) (AUDIO_OUTPUT_FLAG_MMAP_NOIRQ | AUDIO_OUTPUT_FLAG_DIRECT);
    ASSERT_EQ(INVALID_OPERATION,
              mManager->getOutputForAttr(&attr, &mOutput, AUDIO_SESSION_NONE, &mStream,
                                         createAttributionSourceState(testUid), &audioConfig,
                                         &outputFlags, &mSelectedDeviceIds, &mPortId, {},
                                         &mOutputType, &mIsSpatialized, &mIsBitPerfect));
}

TEST_P(AudioPolicyManagerTestMMapPlaybackRerouting,
        NonMmapPlaybackStreamMatchingLoopbackDapMixSucceeds) {
    // Add mix matching the test uid.
    const int testUid = 12345;
    const auto param = GetParam();
    ASSERT_NO_FATAL_FAILURE(
            addPolicyMixAndStartInputForLoopback(MIX_TYPE_PLAYERS, param.mixRouteFlags,
                                                 param.deviceType,param.deviceAddress, audioConfig,
                                                 {createUidCriterion(testUid)}));

    // Getting output for matching uid should succeed for non-mmaped stream.
    audio_output_flags_t outputFlags = AUDIO_OUTPUT_FLAG_NONE;
    ASSERT_EQ(NO_ERROR,
              mManager->getOutputForAttr(&attr, &mOutput, AUDIO_SESSION_NONE, &mStream,
                                         createAttributionSourceState(testUid), &audioConfig,
                                         &outputFlags, &mSelectedDeviceIds, &mPortId, {},
                                         &mOutputType, &mIsSpatialized, &mIsBitPerfect));
}

TEST_F(AudioPolicyManagerTestMMapPlaybackRerouting,
        MmapPlaybackStreamMatchingRenderDapMixSupportingMmapSucceeds) {
    const std::string usbAddress = "card=1;device=0";
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_OUT_USB_DEVICE, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            usbAddress.c_str(), "", AUDIO_FORMAT_DEFAULT));
    audio_port_v7 usbDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_USB_DEVICE,
                               usbAddress, &usbDevicePort));

    // Add render-only mix matching the test uid.
    const int testUid = 12345;
    // test_audio_policy_configuration.xml declares mmap-capable mix port
    // for AUDIO_DEVICE_OUT_USB_DEVICE.
    ASSERT_EQ(NO_ERROR,
              addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
                           AUDIO_DEVICE_OUT_USB_DEVICE, /*mixAddress=*/"",
                           audioConfig, {createUidCriterion(testUid)}));

    static const audio_output_flags_t mmapDirectFlags =
            (audio_output_flags_t) (AUDIO_OUTPUT_FLAG_MMAP_NOIRQ | AUDIO_OUTPUT_FLAG_DIRECT);
    // Getting output for matching uid should succeed for mmaped stream, because matched mix
    // redirects to mmap capable device.
    audio_output_flags_t outputFlags = mmapDirectFlags;
    ASSERT_EQ(NO_ERROR,
              mManager->getOutputForAttr(&attr, &mOutput, AUDIO_SESSION_NONE, &mStream,
                                         createAttributionSourceState(testUid), &audioConfig,
                                         &outputFlags, &mSelectedDeviceIds, &mPortId, {},
                                         &mOutputType, &mIsSpatialized, &mIsBitPerfect));
    auto outputDesc = mManager->getOutputs().valueFor(mOutput);
    ASSERT_NE(nullptr, outputDesc);
    ASSERT_EQ(mmapDirectFlags, outputDesc->getFlags().output);

    // After releasing the client, the output is closed. APM should reselect output for the policy
    // mix.
    mManager->releaseOutput(mPortId);
    ASSERT_EQ(nullptr, mManager->getOutputs().valueFor(mOutput));
    outputFlags = AUDIO_OUTPUT_FLAG_NONE;
    mPortId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_EQ(NO_ERROR,
              mManager->getOutputForAttr(&attr, &mOutput, AUDIO_SESSION_NONE, &mStream,
                                         createAttributionSourceState(testUid), &audioConfig,
                                         &outputFlags, &mSelectedDeviceIds, &mPortId, {},
                                         &mOutputType, &mIsSpatialized, &mIsBitPerfect));
    ASSERT_EQ(usbDevicePort.id, mSelectedDeviceIds[0]);
    outputDesc = mManager->getOutputs().valueFor(mOutput);
    ASSERT_NE(nullptr, outputDesc);
    ASSERT_NE(mmapDirectFlags, outputDesc->getFlags().output);

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_OUT_USB_DEVICE, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
            usbAddress.c_str(), "", AUDIO_FORMAT_DEFAULT));
}

TEST_F(AudioPolicyManagerTestMMapPlaybackRerouting,
        MmapPlaybackStreamMatchingRenderDapMixNotSupportingMmapFails) {
    // Add render-only mix matching the test uid.
    const int testUid = 12345;
    // Per test_audio_policy_configuration.xml AUDIO_DEVICE_OUT_SPEAKER doesn't support mmap.
    ASSERT_EQ(NO_ERROR,
              addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
                           AUDIO_DEVICE_OUT_SPEAKER, /*mixAddress=*/"", audioConfig,
                           {createUidCriterion(testUid)}));

    // Getting output for matching uid should fail for mmaped stream, because
    // matched mix redirects to device which doesn't support mmap.
    audio_output_flags_t outputFlags =
            (audio_output_flags_t) (AUDIO_OUTPUT_FLAG_MMAP_NOIRQ | AUDIO_OUTPUT_FLAG_DIRECT);
    ASSERT_EQ(INVALID_OPERATION,
              mManager->getOutputForAttr(&attr, &mOutput, AUDIO_SESSION_NONE, &mStream,
                                         createAttributionSourceState(testUid), &audioConfig,
                                         &outputFlags, &mSelectedDeviceIds, &mPortId, {},
                                         &mOutputType, &mIsSpatialized, &mIsBitPerfect));
}

INSTANTIATE_TEST_SUITE_P(
        MmapPlaybackRerouting, AudioPolicyManagerTestMMapPlaybackRerouting,
        testing::Values(DPMmapTestParam(MIX_ROUTE_FLAG_LOOP_BACK, AUDIO_DEVICE_OUT_REMOTE_SUBMIX,
                                        /*deviceAddress=*/"remote_submix_media"),
                        DPMmapTestParam(MIX_ROUTE_FLAG_LOOP_BACK_AND_RENDER,
                                        AUDIO_DEVICE_OUT_REMOTE_SUBMIX,
                                        /*deviceAddress=*/"remote_submix_media"),
                        DPMmapTestParam(MIX_ROUTE_FLAG_RENDER, AUDIO_DEVICE_OUT_SPEAKER,
                                        /*deviceAddress=*/"")));

class AudioPolicyManagerTestDPMixRecordInjection : public AudioPolicyManagerTestDynamicPolicy,
        public testing::WithParamInterface<DPTestParam> {
protected:
    void SetUp() override;
    void TearDown() override;

    std::unique_ptr<RecordingActivityTracker> mTracker;
    struct audio_port_v7 mExtractionPort;
    audio_port_handle_t mPortId = AUDIO_PORT_HANDLE_NONE;
};

void AudioPolicyManagerTestDPMixRecordInjection::SetUp() {
    ASSERT_NO_FATAL_FAILURE(AudioPolicyManagerTestDynamicPolicy::SetUp());

    mTracker.reset(new RecordingActivityTracker());

    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_IN_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;

    DPTestParam param = GetParam();
    status_t ret = addPolicyMix(MIX_TYPE_RECORDERS, MIX_ROUTE_FLAG_LOOP_BACK,
            AUDIO_DEVICE_IN_REMOTE_SUBMIX, mMixAddress, audioConfig, param.mixCriteria);
    ASSERT_EQ(NO_ERROR, ret);

    struct audio_port_v7 injectionPort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_REMOTE_SUBMIX,
                    mMixAddress, &injectionPort));

    DeviceIdVector selectedDeviceIds;
    audio_usage_t usage = AUDIO_USAGE_VIRTUAL_SOURCE;
    audio_attributes_t attr =
            {AUDIO_CONTENT_TYPE_UNKNOWN, usage, AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};
    std::string tags = std::string("addr=") + mMixAddress;
    strncpy(attr.tags, tags.c_str(), AUDIO_ATTRIBUTES_TAGS_MAX_SIZE - 1);
    ASSERT_NO_FATAL_FAILURE(
            getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
            k48000SamplingRate, AUDIO_OUTPUT_FLAG_NONE, nullptr /*output*/, &mPortId, attr));
    bool muted{};
    float volume{};
    ASSERT_EQ(NO_ERROR, mManager->startOutput(mPortId, &volume, &muted));
    EXPECT_GE(volume, 0.f);
    EXPECT_LE(volume, 1.f);
    ASSERT_EQ(injectionPort.id, getDeviceIdFromPatch(mClient->getLastAddedPatch()));

    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SOURCE, AUDIO_DEVICE_IN_REMOTE_SUBMIX,
                    mMixAddress, &mExtractionPort));
}

void AudioPolicyManagerTestDPMixRecordInjection::TearDown() {
    mManager->stopOutput(mPortId);
    AudioPolicyManagerTestDynamicPolicy::TearDown();
}

TEST_P(AudioPolicyManagerTestDPMixRecordInjection, RecordingInjection) {
    const DPTestParam param = GetParam();

    audio_port_handle_t captureRoutedPortId = AUDIO_PORT_HANDLE_NONE;
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t input = AUDIO_PORT_HANDLE_NONE;
    getInputForAttr(param.attributes, &input, param.session, mTracker->getRiid(),
                    &captureRoutedPortId, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                    k48000SamplingRate, AUDIO_INPUT_FLAG_NONE, &portId);
    if (param.expected_match) {
        EXPECT_EQ(mExtractionPort.id, captureRoutedPortId);
    } else {
        EXPECT_NE(mExtractionPort.id, captureRoutedPortId);
    }
}

const std::vector<AudioMixMatchCriterion> SOURCE_CAM_MIC_VOICE_CRITERIA = {
        createCapturePresetCriterion(AUDIO_SOURCE_CAMCORDER),
        createCapturePresetCriterion(AUDIO_SOURCE_MIC),
        createCapturePresetCriterion(AUDIO_SOURCE_VOICE_COMMUNICATION)
};

// No address priority rule for remote recording, address is a "don't care"
INSTANTIATE_TEST_CASE_P(
        RecordInjectionSource,
        AudioPolicyManagerTestDPMixRecordInjection,
        testing::Values(
            DPTestParam(SOURCE_CAM_MIC_VOICE_CRITERIA, /*expected_match=*/ true)
                .withSource(AUDIO_SOURCE_CAMCORDER),
            DPTestParam(SOURCE_CAM_MIC_VOICE_CRITERIA, /*expected_match=*/ true)
                .withSource(AUDIO_SOURCE_CAMCORDER)
                .withTags("addr=remote_submix_media"),
            DPTestParam(SOURCE_CAM_MIC_VOICE_CRITERIA, /*expected_match=*/ true)
                .withSource(AUDIO_SOURCE_MIC),
            DPTestParam(SOURCE_CAM_MIC_VOICE_CRITERIA, /*expected_match=*/ true)
                .withSource(AUDIO_SOURCE_MIC)
                .withTags("addr=remote_submix_media"),
            DPTestParam(SOURCE_CAM_MIC_VOICE_CRITERIA, /*expected_match=*/ true)
                .withSource(AUDIO_SOURCE_VOICE_COMMUNICATION),
            DPTestParam(SOURCE_CAM_MIC_VOICE_CRITERIA, /*expected_match=*/ true)
                .withSource(AUDIO_SOURCE_VOICE_COMMUNICATION)
                .withTags("addr=remote_submix_media"),
            DPTestParam(SOURCE_CAM_MIC_VOICE_CRITERIA, /*expected_match=*/ false)
                .withSource(AUDIO_SOURCE_VOICE_RECOGNITION),
            DPTestParam(SOURCE_CAM_MIC_VOICE_CRITERIA, /*expected_match=*/ false)
                .withSource(AUDIO_SOURCE_VOICE_RECOGNITION)
                .withTags("addr=remote_submix_media"),
            DPTestParam(SOURCE_CAM_MIC_VOICE_CRITERIA, /*expected_match=*/ false)
                .withSource(AUDIO_SOURCE_HOTWORD),
            DPTestParam(SOURCE_CAM_MIC_VOICE_CRITERIA, /*expected_match=*/ false)
                .withSource(AUDIO_SOURCE_HOTWORD)
                .withTags("addr=remote_submix_media")));

INSTANTIATE_TEST_CASE_P(
        RecordInjectionWithSessionId,
        AudioPolicyManagerTestDPMixRecordInjection,
        testing::Values(
            // Mix is matched because the session id matches the one specified by the mix rule.
            DPTestParam(/*mixCriteria=*/ {createSessionIdCriterion(TEST_SESSION_ID)},
                        /*expected_match=*/ true)
                .withSessionId(TEST_SESSION_ID),
            // Mix is not matched because the session id doesn't match the one specified
            // by the mix rule.
            DPTestParam(/*mixCriteria=*/ {createSessionIdCriterion(TEST_SESSION_ID)},
                        /*expected_match=*/ false)
                .withSessionId(OTHER_SESSION_ID),
            // Mix is not matched, the session id doesn't match the one specified by rule,
            // but tand address specified in the tags is ignored for recorder mix.
            DPTestParam(/*mixCriteria=*/ {createSessionIdCriterion(TEST_SESSION_ID)},
                        /*expected_match=*/ false)
                .withSessionId(OTHER_SESSION_ID).withTags("addr=remote_submix_media"),
            // Mix is matched, both the session id and the source match ones specified by mix rule
            DPTestParam(/*mixCriteria=*/ {createSessionIdCriterion(TEST_SESSION_ID),
                                          createCapturePresetCriterion(AUDIO_SOURCE_CAMCORDER)},
                        /*expected_match=*/ true)
                .withSessionId(TEST_SESSION_ID).withSource(AUDIO_SOURCE_CAMCORDER),
            // Mix is not matched, the session id matches the one specified by mix rule,
            // but source does not.
            DPTestParam(/*mixCriteria=*/ {createSessionIdCriterion(TEST_SESSION_ID),
                                          createCapturePresetCriterion(AUDIO_SOURCE_CAMCORDER)},
                        /*expected_match=*/ false)
                .withSessionId(TEST_SESSION_ID).withSource(AUDIO_SOURCE_MIC),
            // Mix is not matched, the source matches the one specified by mix rule,
            // but the session id is excluded.
            DPTestParam(/*mixCriteria=*/ {createSessionIdCriterion(TEST_SESSION_ID,
                                                                       /*exclude=*/ true),
                                          createCapturePresetCriterion(AUDIO_SOURCE_MIC)},
                        /*expected_match=*/ false)
                .withSessionId(TEST_SESSION_ID).withSource(AUDIO_SOURCE_MIC)));

using DeviceConnectionTestParams =
        std::tuple<audio_devices_t /*type*/, std::string /*name*/, std::string /*address*/>;

class AudioPolicyManagerTestDeviceConnection : public AudioPolicyManagerTestWithConfigurationFile,
        public testing::WithParamInterface<DeviceConnectionTestParams> {
};

TEST_F(AudioPolicyManagerTestDeviceConnection, InitSuccess) {
    // SetUp must finish with no assertions.
}

TEST_F(AudioPolicyManagerTestDeviceConnection, Dump) {
    dumpToLog();
}

TEST_F(AudioPolicyManagerTestDeviceConnection, RoutingUpdate) {
    mClient->resetRoutingUpdatedCounter();
    // Connecting a valid output device with valid parameters should trigger a routing update
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_OUT_BLUETOOTH_SCO, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            "00:11:22:33:44:55", "b", AUDIO_FORMAT_DEFAULT));
    ASSERT_EQ(1, mClient->getRoutingUpdatedCounter());

    // Disconnecting a connected device should succeed and trigger a routing update
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_OUT_BLUETOOTH_SCO, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
            "00:11:22:33:44:55", "b", AUDIO_FORMAT_DEFAULT));
    ASSERT_EQ(2, mClient->getRoutingUpdatedCounter());

    // Disconnecting a disconnected device should fail and not trigger a routing update
    ASSERT_EQ(INVALID_OPERATION, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_OUT_BLUETOOTH_SCO, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
            "00:11:22:33:44:55", "b",  AUDIO_FORMAT_DEFAULT));
    ASSERT_EQ(2, mClient->getRoutingUpdatedCounter());

    // Changing force use should trigger an update
    auto config = mManager->getForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA);
    auto newConfig = config == AUDIO_POLICY_FORCE_BT_A2DP ?
            AUDIO_POLICY_FORCE_NONE : AUDIO_POLICY_FORCE_BT_A2DP;
    mManager->setForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA, newConfig);
    ASSERT_EQ(3, mClient->getRoutingUpdatedCounter());
}

TEST_P(AudioPolicyManagerTestDeviceConnection, SetDeviceConnectionState) {
    const audio_devices_t type = std::get<0>(GetParam());
    const std::string name = std::get<1>(GetParam());
    const std::string address = std::get<2>(GetParam());

    if (type == AUDIO_DEVICE_OUT_HDMI) {
        // Set device connection state failed due to no device descriptor found
        // For HDMI case, it is easier to simulate device descriptor not found error
        // by using an encoded format which isn't listed in the 'encodedFormats'
        // attribute for this devicePort.
        ASSERT_EQ(INVALID_OPERATION, mManager->setDeviceConnectionState(
                type, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                address.c_str(), name.c_str(), AUDIO_FORMAT_MAT_2_1));
    }
    // Connect with valid parameters should succeed
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            type, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            address.c_str(), name.c_str(), AUDIO_FORMAT_DEFAULT));
    // Try to connect with the same device again should fail
    ASSERT_EQ(INVALID_OPERATION, mManager->setDeviceConnectionState(
            type, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            address.c_str(), name.c_str(), AUDIO_FORMAT_DEFAULT));
    // Disconnect the connected device should succeed
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            type, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
            address.c_str(), name.c_str(), AUDIO_FORMAT_DEFAULT));
    // Disconnect device that is not connected should fail
    ASSERT_EQ(INVALID_OPERATION, mManager->setDeviceConnectionState(
            type, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
            address.c_str(), name.c_str(), AUDIO_FORMAT_DEFAULT));
    // Try to set device connection state  with a invalid connection state should fail
    ASSERT_EQ(BAD_VALUE, mManager->setDeviceConnectionState(
            type, AUDIO_POLICY_DEVICE_STATE_CNT,
            "", "", AUDIO_FORMAT_DEFAULT));
}

TEST_P(AudioPolicyManagerTestDeviceConnection, ExplicitlyRoutingAfterConnection) {
    const audio_devices_t type = std::get<0>(GetParam());
    const std::string name = std::get<1>(GetParam());
    const std::string address = std::get<2>(GetParam());

    // Connect device to do explicitly routing test
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            type, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            address.c_str(), name.c_str(), AUDIO_FORMAT_DEFAULT));

    audio_port_v7 devicePort;
    const audio_port_role_t role = audio_is_output_device(type)
            ? AUDIO_PORT_ROLE_SINK : AUDIO_PORT_ROLE_SOURCE;
    ASSERT_TRUE(findDevicePort(role, type, address, &devicePort));

    // Try start input or output according to the device type
    if (audio_is_output_devices(type)) {
        DeviceIdVector routedPortIds = { devicePort.id };
        ASSERT_NO_FATAL_FAILURE(getOutputForAttr(
                        &routedPortIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
                        k48000SamplingRate, AUDIO_OUTPUT_FLAG_NONE));
        ASSERT_EQ(devicePort.id, routedPortIds[0]);
    } else if (audio_is_input_device(type)) {
        audio_port_handle_t routedPortId = devicePort.id;
        RecordingActivityTracker tracker;
        audio_io_handle_t input = AUDIO_PORT_HANDLE_NONE;
        getInputForAttr({}, &input, AUDIO_SESSION_NONE, tracker.getRiid(), &routedPortId,
                        AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO, k48000SamplingRate,
                        AUDIO_INPUT_FLAG_NONE);
        ASSERT_EQ(devicePort.id, routedPortId);
    }

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            type, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
            address.c_str(), name.c_str(), AUDIO_FORMAT_DEFAULT));
}

android::media::audio::common::ExtraAudioDescriptor make_ExtraAudioDescriptor(
        android::media::audio::common::AudioStandard audioStandard,
        android::media::audio::common::AudioEncapsulationType audioEncapsulationType) {
    android::media::audio::common::ExtraAudioDescriptor result;
    result.standard = audioStandard;
    result.audioDescriptor = {0xb4, 0xaf, 0x98, 0x1a};
    result.encapsulationType = audioEncapsulationType;
    return result;
}

TEST_P(AudioPolicyManagerTestDeviceConnection, PassingExtraAudioDescriptors) {
    const audio_devices_t type = std::get<0>(GetParam());
    if (!audio_device_is_digital(type)) {
        // EADs are used only for HDMI devices.
        GTEST_SKIP() << "Not a digital device type: " << audio_device_to_string(type);
    }
    const std::string name = std::get<1>(GetParam());
    const std::string address = std::get<2>(GetParam());
    android::media::AudioPortFw audioPort;
    ASSERT_EQ(NO_ERROR,
            mManager->deviceToAudioPort(type, address.c_str(), name.c_str(), &audioPort));
    android::media::audio::common::AudioPort& port = audioPort.hal;
    port.extraAudioDescriptors.push_back(make_ExtraAudioDescriptor(
                    android::media::audio::common::AudioStandard::EDID,
                    android::media::audio::common::AudioEncapsulationType::IEC61937));
    const size_t lastConnectedDevicePortCount = mClient->getConnectedDevicePortCount();
    const size_t lastDisconnectedDevicePortCount = mClient->getDisconnectedDevicePortCount();
    EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
                    AUDIO_POLICY_DEVICE_STATE_AVAILABLE, port, AUDIO_FORMAT_DEFAULT, false));
    EXPECT_EQ(lastConnectedDevicePortCount + 1, mClient->getConnectedDevicePortCount());
    EXPECT_EQ(lastDisconnectedDevicePortCount, mClient->getDisconnectedDevicePortCount());
    const audio_port_v7* devicePort = mClient->getLastConnectedDevicePort();
    EXPECT_EQ(port.extraAudioDescriptors.size(), devicePort->num_extra_audio_descriptors);
    EXPECT_EQ(AUDIO_STANDARD_EDID, devicePort->extra_audio_descriptors[0].standard);
    EXPECT_EQ(AUDIO_ENCAPSULATION_TYPE_IEC61937,
            devicePort->extra_audio_descriptors[0].encapsulation_type);
    EXPECT_NE(0, devicePort->extra_audio_descriptors[0].descriptor[0]);
}

bool isDevicePortNameValidUtf8String(const char* devicePortName) {
    return utf8_to_utf16_length(reinterpret_cast<const uint8_t*>(devicePortName),
                                strlen(devicePortName)) != -1;
}

std::vector<std::string> generateTestStrings() {
    std::vector<std::string> testStrings;
    const std::vector<std::string> multiByteChars = {
            "\xC4\x80",         // 2 bytes
            "\xEa\xB0\x80",     // 3 bytes
            "\xF0\x90\x80\x80"  // 4 bytes
    };

    // Generate a 126-byte(AUDIO_PORT_MAX_NAME_LEN - 2) string with single byte characters and
    // append multi-byte character at the end.
    std::string singleByteCharString;
    const int singleByteCharSize = AUDIO_PORT_MAX_NAME_LEN - 2;
    for (int i = 0; i < singleByteCharSize; ++i) {
        singleByteCharString += ('a' + (i % 26));
    }
    for (const auto& multiByteChar : multiByteChars) {
        testStrings.push_back(singleByteCharString + multiByteChar);
    }

    // Generate strings of size >= AUDIO_PORT_MAX_NAME_LEN by repeatedly appending a multi-byte
    // character.
    for (const auto& multiByteChar : multiByteChars) {
        std::string multiByteCharString;
        while (multiByteCharString.length() < AUDIO_PORT_MAX_NAME_LEN) {
            multiByteCharString += multiByteChar;
        }
        testStrings.push_back(multiByteCharString);
    }

    // Generate string of length AUDIO_PORT_MAX_NAME_LEN + 1 bytes using only single byte characters
    while (singleByteCharString.length() <= AUDIO_PORT_MAX_NAME_LEN) {
        singleByteCharString += ('a' + (singleByteCharString.length() % 26));
    }
    testStrings.push_back(singleByteCharString);
    return testStrings;
}

TEST_P(AudioPolicyManagerTestDeviceConnection, InvalidDevicePortNamesTest) {
    const audio_devices_t type = std::get<0>(GetParam());
    const std::string address = std::get<2>(GetParam());
    const std::vector<std::string> testDevicePortNames = generateTestStrings();
    for (std::string devicePortName : testDevicePortNames) {
        EXPECT_GE(devicePortName.length(), AUDIO_PORT_MAX_NAME_LEN)
                << "Test doesn't detect invalid truncation. Device port name length is valid, less "
                   "than the max supported length.";
        android::media::AudioPortFw audioPort;
        EXPECT_EQ(NO_ERROR, mManager->deviceToAudioPort(type, address.c_str(),
                                                        devicePortName.c_str(), &audioPort));
        android::media::audio::common::AudioPort& port = audioPort.hal;
        EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                               port, AUDIO_FORMAT_DEFAULT, false));
        const audio_port_v7* devicePort = mClient->getLastConnectedDevicePort();
        EXPECT_TRUE(isDevicePortNameValidUtf8String((devicePort->name)))
                << "Device port name is not properly truncated.";
        // Disconnect the device
        EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
                                    type, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, "" /*address*/,
                                    "" /*name*/, AUDIO_FORMAT_DEFAULT));
    }
}

INSTANTIATE_TEST_CASE_P(
        DeviceConnectionState,
        AudioPolicyManagerTestDeviceConnection,
        testing::Values(
                DeviceConnectionTestParams({AUDIO_DEVICE_IN_HDMI, "test_in_hdmi",
                                            "audio_policy_test_in_hdmi"}),
                DeviceConnectionTestParams({AUDIO_DEVICE_OUT_HDMI, "test_out_hdmi",
                                            "audio_policy_test_out_hdmi"}),
                DeviceConnectionTestParams({AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, "bt_hfp_in",
                                            "00:11:22:33:44:55"}),
                DeviceConnectionTestParams({AUDIO_DEVICE_OUT_BLUETOOTH_SCO, "bt_hfp_out",
                                            "00:11:22:33:44:55"})
                )
        );

namespace {

class AudioPolicyManagerTestClientOpenFails : public AudioPolicyManagerTestClient {
  public:
    status_t openOutput(audio_module_handle_t module,
                        audio_io_handle_t *output,
                        audio_config_t * halConfig,
                        audio_config_base_t * mixerConfig,
                        const sp<DeviceDescriptorBase>& device,
                        uint32_t * latencyMs,
                        audio_output_flags_t *flags,
                        audio_attributes_t attributes,
                        int32_t mixPortHalId) override {
        return mSimulateFailure ? BAD_VALUE :
                AudioPolicyManagerTestClient::openOutput(
                        module, output, halConfig, mixerConfig, device, latencyMs, flags,
                        attributes, mixPortHalId);
    }

    status_t openInput(audio_module_handle_t module,
                       audio_io_handle_t *input,
                       audio_config_t * config,
                       audio_devices_t * device,
                       const String8 & address,
                       audio_source_t source,
                       audio_input_flags_t flags,
                       int32_t mixPortHalId) override {
        return mSimulateFailure ? BAD_VALUE :
                AudioPolicyManagerTestClient::openInput(
                        module, input, config, device, address, source, flags, mixPortHalId);
    }

    void setSimulateFailure(bool simulateFailure) { mSimulateFailure = simulateFailure; }

    void setSimulateBroadcastDeviceStatus(audio_devices_t device, status_t status) {
        if (status != NO_ERROR) {
            // simulate device connect status
            mSimulateBroadcastDeviceStatus[device] = status;
        } else {
            // remove device connection fixed status
            mSimulateBroadcastDeviceStatus.erase(device);
        }
    }

    status_t setDeviceConnectedState(const struct audio_port_v7* port,
                                     media::DeviceConnectedState state) override {
        if (mSimulateBroadcastDeviceStatus.find(port->ext.device.type) !=
            mSimulateBroadcastDeviceStatus.end()) {
            // If a simulated status exists, return a status value
            return mSimulateBroadcastDeviceStatus[port->ext.device.type];
        }
        return AudioPolicyManagerTestClient::setDeviceConnectedState(port, state);
    }

  private:
    bool mSimulateFailure = false;
    std::map<audio_devices_t, status_t> mSimulateBroadcastDeviceStatus;
};

}  // namespace

using DeviceConnectionWithFormatTestParams =
        std::tuple<audio_devices_t /*type*/, std::string /*name*/, std::string /*address*/,
        audio_format_t /*format*/>;

class AudioPolicyManagerTestDeviceConnectionFailed :
        public AudioPolicyManagerTestWithConfigurationFile,
        public testing::WithParamInterface<DeviceConnectionWithFormatTestParams> {
  protected:
    std::string getConfigFile() override { return sBluetoothConfig; }
  AudioPolicyManagerTestClient* getClient() override {
        mFullClient = new AudioPolicyManagerTestClientOpenFails;
        return mFullClient;
    }
    void setSimulateOpenFailure(bool simulateFailure) {
        mFullClient->setSimulateFailure(simulateFailure); }

    void setSimulateBroadcastDeviceStatus(audio_devices_t device, status_t status) {
        mFullClient->setSimulateBroadcastDeviceStatus(device, status); }

    static const std::string sBluetoothConfig;

  private:
    AudioPolicyManagerTestClientOpenFails* mFullClient;
};

const std::string AudioPolicyManagerTestDeviceConnectionFailed::sBluetoothConfig =
        AudioPolicyManagerTestDeviceConnectionFailed::sExecutableDir +
        "test_audio_policy_configuration_bluetooth.xml";

TEST_P(AudioPolicyManagerTestDeviceConnectionFailed, SetDeviceConnectedStateHasAddress) {
    const audio_devices_t type = std::get<0>(GetParam());
    const std::string name = std::get<1>(GetParam());
    const std::string address = std::get<2>(GetParam());
    const audio_format_t format = std::get<3>(GetParam());

    EXPECT_EQ(0, mClient->getConnectedDevicePortCount());
    EXPECT_EQ(0, mClient->getDisconnectedDevicePortCount());

    setSimulateOpenFailure(true);
    ASSERT_EQ(INVALID_OPERATION, mManager->setDeviceConnectionState(
            type, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            address.c_str(), name.c_str(), format));

    // Since the failure happens when opening input/output, the device must be connected
    // first and then disconnected.
    EXPECT_EQ(1, mClient->getConnectedDevicePortCount());
    EXPECT_EQ(1, mClient->getDisconnectedDevicePortCount());

    if (mClient->getConnectedDevicePortCount() > 0) {
        auto port = mClient->getLastConnectedDevicePort();
        EXPECT_EQ(type, port->ext.device.type);
        EXPECT_EQ(0, strncmp(port->ext.device.address, address.c_str(),
                        AUDIO_DEVICE_MAX_ADDRESS_LEN)) << "\"" << port->ext.device.address << "\"";
    }
    if (mClient->getDisconnectedDevicePortCount() > 0) {
        auto port = mClient->getLastDisconnectedDevicePort();
        EXPECT_EQ(type, port->ext.device.type);
        EXPECT_EQ(0, strncmp(port->ext.device.address, address.c_str(),
                        AUDIO_DEVICE_MAX_ADDRESS_LEN)) << "\"" << port->ext.device.address << "\"";
    }
}

TEST_P(AudioPolicyManagerTestDeviceConnectionFailed, BroadcastDeviceFailure) {
    const audio_devices_t type = std::get<0>(GetParam());
    const std::string name = std::get<1>(GetParam());
    const std::string address = std::get<2>(GetParam());
    const audio_format_t format = std::get<3>(GetParam());

    // simulate broadcastDeviceConnectionState return failure
    setSimulateBroadcastDeviceStatus(type, INVALID_OPERATION);
    ASSERT_EQ(INVALID_OPERATION, mManager->setDeviceConnectionState(
            type, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            address.c_str(), name.c_str(), format));

    // if broadcast is fail, device should not be added to available devices list
    if (audio_is_output_device(type)) {
        auto availableDevices = mManager->getAvailableOutputDevices();
        EXPECT_FALSE(availableDevices.containsDeviceWithType(type));
    } else if (audio_is_input_device(type)) {
        auto availableDevices = mManager->getAvailableInputDevices();
        EXPECT_FALSE(availableDevices.containsDeviceWithType(type));
    }

    setSimulateBroadcastDeviceStatus(type, NO_ERROR);
}

INSTANTIATE_TEST_CASE_P(
        DeviceConnectionFailure,
        AudioPolicyManagerTestDeviceConnectionFailed,
        testing::Values(
                DeviceConnectionWithFormatTestParams({AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET,
                            "bt_hfp_in", "00:11:22:33:44:55", AUDIO_FORMAT_DEFAULT}),
                DeviceConnectionWithFormatTestParams({AUDIO_DEVICE_OUT_BLUETOOTH_SCO,
                            "bt_hfp_out", "00:11:22:33:44:55", AUDIO_FORMAT_DEFAULT}),
                DeviceConnectionWithFormatTestParams({AUDIO_DEVICE_OUT_BLUETOOTH_A2DP,
                            "bt_a2dp_out", "00:11:22:33:44:55", AUDIO_FORMAT_DEFAULT}),
                DeviceConnectionWithFormatTestParams({AUDIO_DEVICE_OUT_BLUETOOTH_A2DP,
                            "bt_a2dp_out", "00:11:22:33:44:66", AUDIO_FORMAT_LDAC})
                )
        );

class AudioPolicyManagerCarTest : public AudioPolicyManagerTestDynamicPolicy {
protected:
    std::string getConfigFile() override { return sCarConfig; }

    static const std::string sCarConfig;
    static const std::string sCarBusMediaOutput;
    static const std::string sCarBusNavigationOutput;
    static const std::string sCarRearZoneOneOutput;
    static const std::string sCarRearZoneTwoOutput;
    static const std::string sCarBusMmapOutput;
};

const std::string AudioPolicyManagerCarTest::sCarConfig =
        AudioPolicyManagerCarTest::sExecutableDir + "test_car_ap_atmos_offload_configuration.xml";

const std::string AudioPolicyManagerCarTest::sCarBusMediaOutput = "bus0_media_out";

const std::string AudioPolicyManagerCarTest::sCarBusNavigationOutput = "bus1_navigation_out";

const std::string AudioPolicyManagerCarTest::sCarRearZoneOneOutput = "bus100_audio_zone_1";

const std::string AudioPolicyManagerCarTest::sCarRearZoneTwoOutput = "bus200_audio_zone_2";

const std::string AudioPolicyManagerCarTest::sCarBusMmapOutput = "bus8_mmap_out";

TEST_F(AudioPolicyManagerCarTest, InitSuccess) {
    // SetUp must finish with no assertions.
}

TEST_F(AudioPolicyManagerCarTest, Dump) {
    dumpToLog();
}

TEST_F(AudioPolicyManagerCarTest, GetOutputForAttrAtmosOutputAfterRegisteringPolicyMix) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput, audioConfig);
    ASSERT_EQ(NO_ERROR, ret);

    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t output;
    audio_port_handle_t portId;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(
                    &selectedDeviceIds, AUDIO_FORMAT_E_AC3_JOC, AUDIO_CHANNEL_OUT_5POINT1,
                    k48000SamplingRate, AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId));
    ASSERT_GT(selectedDeviceIds.size(), 0);
    sp<SwAudioOutputDescriptor> outDesc = mManager->getOutputs().valueFor(output);
    ASSERT_NE(nullptr, outDesc.get());
    ASSERT_EQ(AUDIO_FORMAT_E_AC3_JOC, outDesc->getFormat());
    ASSERT_EQ(AUDIO_CHANNEL_OUT_5POINT1, outDesc->getChannelMask());
    ASSERT_EQ(k48000SamplingRate, outDesc->getSamplingRate());

    selectedDeviceIds.clear();
    output = AUDIO_IO_HANDLE_NONE;
    portId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(
                    &selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_7POINT1POINT4,
                    k48000SamplingRate, AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId));
    ASSERT_GT(selectedDeviceIds.size(), 0);
    outDesc = mManager->getOutputs().valueFor(output);
    ASSERT_NE(nullptr, outDesc.get());
    ASSERT_EQ(AUDIO_FORMAT_PCM_16_BIT, outDesc->getFormat());
    ASSERT_EQ(AUDIO_CHANNEL_OUT_7POINT1POINT4, outDesc->getChannelMask());
    ASSERT_EQ(k48000SamplingRate, outDesc->getSamplingRate());
}

TEST_F(AudioPolicyManagerCarTest, GetOutputForAttrAfterRegisteringPolicyMix) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    std::vector<AudioMixMatchCriterion> mediaMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    std::vector<AudioMixMatchCriterion> navMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                    /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusNavigationOutput, audioConfig, navMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    audio_port_v7 mediaDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_BUS,
            sCarBusMediaOutput, &mediaDevicePort));
    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t output;
    audio_port_handle_t portId;
    const audio_attributes_t mediaAttribute = {
            AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_MEDIA,
            AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};

    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                    AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                    AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId, mediaAttribute));

    ASSERT_EQ(mediaDevicePort.id, selectedDeviceIds[0]);
}

TEST_F(AudioPolicyManagerCarTest, GetOutputForAttrWithSelectedOutputAfterRegisteringPolicyMix) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    std::vector<AudioMixMatchCriterion> mediaMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    std::vector<AudioMixMatchCriterion> navMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                    /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusNavigationOutput, audioConfig, navMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    audio_port_v7 navDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_BUS,
            sCarBusNavigationOutput, &navDevicePort));
    DeviceIdVector selectedDeviceIds = { navDevicePort.id };
    audio_io_handle_t output;
    audio_port_handle_t portId;
    const audio_attributes_t mediaAttribute = {
            AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_MEDIA,
            AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};

    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                    AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                    AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId, mediaAttribute));

    ASSERT_EQ(navDevicePort.id, selectedDeviceIds[0]);
}

TEST_F(AudioPolicyManagerCarTest, GetOutputForAttrWithSelectedOutputAfterUserAffinities) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    std::vector<AudioMixMatchCriterion> mediaMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    std::vector<AudioMixMatchCriterion> navMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                    /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusNavigationOutput, audioConfig, navMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    const AudioDeviceTypeAddr mediaOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput);
    const AudioDeviceTypeAddrVector outputDevices = {mediaOutputDevice};
    mManager->setUserIdDeviceAffinities(/* userId */ 0, outputDevices);
    audio_port_v7 navDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_BUS,
            sCarBusNavigationOutput, &navDevicePort));
    DeviceIdVector selectedDeviceIds = { navDevicePort.id };
    audio_io_handle_t output;
    audio_port_handle_t portId;
    const audio_attributes_t mediaAttribute = {
                AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_MEDIA,
                AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};

    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                    AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                    AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId, mediaAttribute));

    ASSERT_GT(selectedDeviceIds.size(), 0);
    ASSERT_NE(navDevicePort.id, selectedDeviceIds[0]);
}

TEST_F(AudioPolicyManagerCarTest, GetOutputForAttrWithExcludeUserIdCriteria) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    std::vector<AudioMixMatchCriterion> mediaMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    std::vector<AudioMixMatchCriterion> navMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                    /*exclude=*/ false),
            createUserIdCriterion(/* userId */ 0, /* exclude */ true)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusNavigationOutput, audioConfig, navMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    audio_port_v7 navDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_BUS,
            sCarBusNavigationOutput, &navDevicePort));
    audio_io_handle_t output;
    audio_port_handle_t portId;
    const audio_attributes_t navigationAttribute = {
            AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
            AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};
    DeviceIdVector selectedDeviceIds;

    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                    AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                    AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId, navigationAttribute));

    ASSERT_GT(selectedDeviceIds.size(), 0);
    ASSERT_NE(navDevicePort.id, selectedDeviceIds[0]);
}

TEST_F(AudioPolicyManagerCarTest, GetOutputForAttrWithSelectedOutputExcludeUserIdCriteria) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    std::vector<AudioMixMatchCriterion> mediaMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    std::vector<AudioMixMatchCriterion> navMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                    /*exclude=*/ false),
            createUserIdCriterion(0 /* userId */, /* exclude */ true)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusNavigationOutput, audioConfig, navMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    audio_port_v7 navDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_BUS,
                               sCarBusNavigationOutput, &navDevicePort));
    DeviceIdVector selectedDeviceIds = { navDevicePort.id };
    audio_io_handle_t output;
    audio_port_handle_t portId;
    const audio_attributes_t mediaAttribute = {
            AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_MEDIA,
            AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};

    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                    AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                    AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId, mediaAttribute));

    ASSERT_EQ(navDevicePort.id, selectedDeviceIds[0]);
}

TEST_F(AudioPolicyManagerCarTest,
       GetOutputForAttrWithMatchingMixAndSelectedOutputAfterUserAffinities) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    std::vector<AudioMixMatchCriterion> mediaMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    std::vector<AudioMixMatchCriterion> navMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                    /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusNavigationOutput, audioConfig, navMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    const AudioDeviceTypeAddr mediaOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput);
    const AudioDeviceTypeAddr navOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarBusNavigationOutput);
    const AudioDeviceTypeAddrVector outputDevices = {mediaOutputDevice, navOutputDevice};
    mManager->setUserIdDeviceAffinities(/* userId */ 0, outputDevices);
    audio_port_v7 navDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_BUS,
            sCarBusNavigationOutput, &navDevicePort));
    DeviceIdVector selectedDeviceIds = { navDevicePort.id };
    audio_io_handle_t output;
    audio_port_handle_t portId;
    const audio_attributes_t mediaAttribute = {
            AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_MEDIA,
            AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};

    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                    AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                    AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId, mediaAttribute));

    ASSERT_EQ(navDevicePort.id, selectedDeviceIds[0]);
}

TEST_F(AudioPolicyManagerCarTest,
       GetOutputForAttrWithNoMatchingMaxAndSelectedOutputAfterUserAffinities) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    std::vector<AudioMixMatchCriterion> mediaMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    std::vector<AudioMixMatchCriterion> navMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                    /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusNavigationOutput, audioConfig, navMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    const AudioDeviceTypeAddr mediaOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput);
    const AudioDeviceTypeAddr navOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarBusNavigationOutput);
    const AudioDeviceTypeAddrVector outputDevices = {mediaOutputDevice, navOutputDevice};
    mManager->setUserIdDeviceAffinities(/* userId */ 0, outputDevices);
    audio_port_v7 navDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_BUS,
            sCarBusNavigationOutput, &navDevicePort));
    DeviceIdVector selectedDeviceIds = { navDevicePort.id };
    audio_io_handle_t output;
    audio_port_handle_t portId;
    const audio_attributes_t alarmAttribute = {
            AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_ALARM,
            AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};

    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                    AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                    AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId, alarmAttribute));

    ASSERT_EQ(navDevicePort.id, selectedDeviceIds[0]);
}

TEST_F(AudioPolicyManagerCarTest,
       GetOutputForAttrWithMatMixAfterUserAffinitiesForOneUser) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    std::vector<AudioMixMatchCriterion> mediaMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarRearZoneOneOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarRearZoneTwoOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    const AudioDeviceTypeAddr mediaOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput);
    const AudioDeviceTypeAddrVector primaryZoneDevices = {mediaOutputDevice};
    mManager->setUserIdDeviceAffinities(/* userId */ 0, primaryZoneDevices);
    audio_port_v7 primaryZoneDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_BUS,
            sCarBusMediaOutput, &primaryZoneDevicePort));
    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t output;
    audio_port_handle_t portId;
    const audio_attributes_t mediaAttribute = {
            AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_MEDIA,
            AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};
    uid_t user11AppUid = multiuser_get_uid(/* user_id */ 11, /* app_id */ 12345);

    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                    AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                    AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId, mediaAttribute,
                    AUDIO_SESSION_NONE, user11AppUid));

    ASSERT_EQ(primaryZoneDevicePort.id, selectedDeviceIds[0]);
}

TEST_F(AudioPolicyManagerCarTest,
       GetOutputForAttrWithMatMixAfterUserAffinitiesForTwoUsers) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    std::vector<AudioMixMatchCriterion> mediaMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarRearZoneOneOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarRearZoneTwoOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    const AudioDeviceTypeAddr mediaOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput);
    const AudioDeviceTypeAddrVector primaryZoneDevices = {mediaOutputDevice};
    mManager->setUserIdDeviceAffinities(/* userId */ 0, primaryZoneDevices);
    const AudioDeviceTypeAddr secondaryOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarRearZoneOneOutput);
    const AudioDeviceTypeAddrVector secondaryZoneDevices = {secondaryOutputDevice};
    mManager->setUserIdDeviceAffinities(/* userId */ 11, secondaryZoneDevices);
    audio_port_v7 secondaryZoneDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_BUS,
            sCarRearZoneOneOutput, &secondaryZoneDevicePort));
    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t output;
    audio_port_handle_t portId;
    const audio_attributes_t mediaAttribute = {
            AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_MEDIA,
            AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};
    uid_t user11AppUid = multiuser_get_uid(/* user_id */ 11, /* app_id */ 12345);

    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                    AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                    AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId, mediaAttribute,
                    AUDIO_SESSION_NONE, user11AppUid));

    ASSERT_EQ(secondaryZoneDevicePort.id, selectedDeviceIds[0]);
}

TEST_F(AudioPolicyManagerCarTest,
       GetOutputForAttrWithMatMixAfterUserAffinitiesForThreeUsers) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    std::vector<AudioMixMatchCriterion> mediaMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarRearZoneOneOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarRearZoneTwoOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    const AudioDeviceTypeAddr mediaOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput);
    const AudioDeviceTypeAddrVector primaryZoneDevices = {mediaOutputDevice};
    mManager->setUserIdDeviceAffinities(/* userId */ 0, primaryZoneDevices);
    const AudioDeviceTypeAddr secondaryOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarRearZoneOneOutput);
    const AudioDeviceTypeAddrVector secondaryZoneDevices = {secondaryOutputDevice};
    mManager->setUserIdDeviceAffinities(/* userId */ 11, secondaryZoneDevices);
    const AudioDeviceTypeAddr tertiaryOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarRearZoneTwoOutput);
    const AudioDeviceTypeAddrVector tertiaryZoneDevices = {tertiaryOutputDevice};
    mManager->setUserIdDeviceAffinities(/* userId */ 15, tertiaryZoneDevices);
    audio_port_v7 tertiaryZoneDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_BUS,
            sCarRearZoneTwoOutput, &tertiaryZoneDevicePort));
    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t output;
    audio_port_handle_t portId;
    const audio_attributes_t mediaAttribute = {
            AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_MEDIA,
            AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};
    uid_t user15AppUid = multiuser_get_uid(/* user_id */ 15, /* app_id */ 12345);

    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                    AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                    AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId, mediaAttribute,
                    AUDIO_SESSION_NONE, user15AppUid));

    ASSERT_EQ(tertiaryZoneDevicePort.id, selectedDeviceIds[0]);
}

TEST_F(AudioPolicyManagerCarTest, GetOutputForAttrWithNoMatchingMix) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    std::vector<AudioMixMatchCriterion> mediaMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    std::vector<AudioMixMatchCriterion> navMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE,
                    /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusNavigationOutput, audioConfig, navMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    const AudioDeviceTypeAddr mediaOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarBusMediaOutput);
    const AudioDeviceTypeAddr navOutputDevice(AUDIO_DEVICE_OUT_BUS, sCarBusNavigationOutput);
    const AudioDeviceTypeAddrVector outputDevices = {mediaOutputDevice, navOutputDevice};
    mManager->setUserIdDeviceAffinities(/* userId */ 0, outputDevices);
    audio_port_v7 navDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_BUS,
            sCarBusNavigationOutput, &navDevicePort));
    DeviceIdVector selectedDeviceIds = { navDevicePort.id };
    audio_io_handle_t output;
    audio_port_handle_t portId;
    const audio_attributes_t alarmAttribute = {
            AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_ALARM,
            AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};

    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                    AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                    AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId, alarmAttribute));

    ASSERT_EQ(navDevicePort.id, selectedDeviceIds[0]);
}

TEST_F(AudioPolicyManagerCarTest, GetOutputForAttrForMMapWithPolicyMatched) {
    status_t ret;
    audio_config_t audioConfig = AUDIO_CONFIG_INITIALIZER;
    audioConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    audioConfig.format = AUDIO_FORMAT_PCM_16_BIT;
    audioConfig.sample_rate = k48000SamplingRate;
    std::vector<AudioMixMatchCriterion> mediaMatchCriteria = {
            createUsageCriterion(AUDIO_USAGE_MEDIA, /*exclude=*/ false)};
    ret = addPolicyMix(MIX_TYPE_PLAYERS, MIX_ROUTE_FLAG_RENDER,
            AUDIO_DEVICE_OUT_BUS, sCarBusMmapOutput, audioConfig, mediaMatchCriteria);
    ASSERT_EQ(NO_ERROR, ret);
    ASSERT_EQ(NO_ERROR, ret);
    audio_port_v7 mmapDevicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, AUDIO_DEVICE_OUT_BUS,
            sCarBusMmapOutput, &mmapDevicePort));
    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t output;
    audio_port_handle_t portId;
    const audio_attributes_t mediaAttribute = {
            AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_MEDIA,
            AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};

    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(
            &selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
            k48000SamplingRate,
            (audio_output_flags_t)(AUDIO_OUTPUT_FLAG_MMAP_NOIRQ | AUDIO_OUTPUT_FLAG_DIRECT),
            &output, &portId, mediaAttribute));

    ASSERT_EQ(mmapDevicePort.id, selectedDeviceIds[0]);

}

class AudioPolicyManagerTVTest : public AudioPolicyManagerTestWithConfigurationFile {
protected:
    std::string getConfigFile() override { return sTvConfig; }
    void testHDMIPortSelection(audio_output_flags_t flags, const char* expectedMixPortName);

    static const std::string sTvConfig;
};

const std::string AudioPolicyManagerTVTest::sTvConfig =
        AudioPolicyManagerTVTest::sExecutableDir + "test_tv_apm_configuration.xml";

// SwAudioOutputDescriptor doesn't populate flags so check against the port name.
void AudioPolicyManagerTVTest::testHDMIPortSelection(
        audio_output_flags_t flags, const char* expectedMixPortName) {
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_OUT_AUX_DIGITAL, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            "" /*address*/, "" /*name*/, AUDIO_FORMAT_DEFAULT));
    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t output;
    audio_port_handle_t portId;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(
                    &selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
                    k48000SamplingRate, flags, &output, &portId));
    sp<SwAudioOutputDescriptor> outDesc = mManager->getOutputs().valueFor(output);
    ASSERT_NE(nullptr, outDesc.get());
    audio_port_v7 port = {};
    outDesc->toAudioPort(&port);
    mManager->releaseOutput(portId);
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_OUT_AUX_DIGITAL, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
            "" /*address*/, "" /*name*/, AUDIO_FORMAT_DEFAULT));
    ASSERT_EQ(AUDIO_PORT_TYPE_MIX, port.type);
    ASSERT_EQ(AUDIO_PORT_ROLE_SOURCE, port.role);
    ASSERT_STREQ(expectedMixPortName, port.name);
}

TEST_F(AudioPolicyManagerTVTest, InitSuccess) {
    // SetUp must finish with no assertions.
}

TEST_F(AudioPolicyManagerTVTest, Dump) {
    dumpToLog();
}

TEST_F(AudioPolicyManagerTVTest, MatchNoFlags) {
    testHDMIPortSelection(AUDIO_OUTPUT_FLAG_NONE, "primary output");
}

TEST_F(AudioPolicyManagerTVTest, MatchOutputDirectNoHwAvSync) {
    // b/140447125: The selected port must not have HW AV Sync flag (see the config file).
    testHDMIPortSelection(AUDIO_OUTPUT_FLAG_DIRECT, "direct");
}

TEST_F(AudioPolicyManagerTVTest, MatchOutputDirectHwAvSync) {
    testHDMIPortSelection(static_cast<audio_output_flags_t>(
                    AUDIO_OUTPUT_FLAG_DIRECT|AUDIO_OUTPUT_FLAG_HW_AV_SYNC),
            "tunnel");
}

TEST_F(AudioPolicyManagerTVTest, MatchOutputDirectMMapNoIrq) {
    testHDMIPortSelection(static_cast<audio_output_flags_t>(
                    AUDIO_OUTPUT_FLAG_DIRECT|AUDIO_OUTPUT_FLAG_MMAP_NOIRQ),
            "low latency");
}

class AudioPolicyManagerPhoneTest : public AudioPolicyManagerTestWithConfigurationFile {
protected:
    std::string getConfigFile() override { return sPhoneConfig; }
    void testOutputMixPortSelectionForAttr(audio_output_flags_t flags, audio_format_t format,
            int samplingRate, bool isMusic, const char* expectedMixPortName);
    void testOutputMixPortSelectionForStream(
            audio_stream_type_t stream, const char* expectedMixPortName);
    void verifyMixPortNameAndFlags(audio_io_handle_t output, const char* expectedMixPortName);

    static const std::string sPhoneConfig;
    static const std::map<std::string, audio_output_flags_t> sMixPortFlags;
};

const std::string AudioPolicyManagerPhoneTest::sPhoneConfig =
        AudioPolicyManagerPhoneTest::sExecutableDir + "test_phone_apm_configuration.xml";

// Must be in sync with the contents of the sPhoneConfig file.
const std::map<std::string, audio_output_flags_t> AudioPolicyManagerPhoneTest::sMixPortFlags = {
        {"primary output",
         (audio_output_flags_t)(AUDIO_OUTPUT_FLAG_PRIMARY | AUDIO_OUTPUT_FLAG_FAST)},
        {"direct", AUDIO_OUTPUT_FLAG_DIRECT},
        {"deep buffer", AUDIO_OUTPUT_FLAG_DEEP_BUFFER},
        {"compressed_offload",
         (audio_output_flags_t)(AUDIO_OUTPUT_FLAG_DIRECT | AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD |
                                AUDIO_OUTPUT_FLAG_NON_BLOCKING |
                                AUDIO_OUTPUT_FLAG_GAPLESS_OFFLOAD)},
        {"raw", (audio_output_flags_t)(AUDIO_OUTPUT_FLAG_RAW | AUDIO_OUTPUT_FLAG_FAST)},
        {"mmap_no_irq_out",
         (audio_output_flags_t)(AUDIO_OUTPUT_FLAG_DIRECT|AUDIO_OUTPUT_FLAG_MMAP_NOIRQ)},
        {"voip_rx", AUDIO_OUTPUT_FLAG_VOIP_RX},
};

void AudioPolicyManagerPhoneTest::testOutputMixPortSelectionForAttr(
        audio_output_flags_t flags, audio_format_t format, int samplingRate, bool isMusic,
        const char* expectedMixPortName) {

    if (mConfig->useDeepBufferForMedia() && flags == AUDIO_OUTPUT_FLAG_NONE
            && samplingRate > SAMPLE_RATE_HZ_MAX) {
        GTEST_SKIP() << "Skipping forced deep buffer test for sampling rate > 192kHz";
    }

    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t output;
    audio_port_handle_t portId;
    audio_attributes_t attr = AUDIO_ATTRIBUTES_INITIALIZER;
    if (isMusic) {
        attr.content_type = AUDIO_CONTENT_TYPE_MUSIC;
        attr.usage = AUDIO_USAGE_MEDIA;
    }
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(
                    &selectedDeviceIds, format, AUDIO_CHANNEL_OUT_STEREO, samplingRate, flags,
                    &output, &portId, attr));
    EXPECT_NO_FATAL_FAILURE(verifyMixPortNameAndFlags(output, expectedMixPortName));
    mManager->releaseOutput(portId);
}

void AudioPolicyManagerPhoneTest::testOutputMixPortSelectionForStream(
        audio_stream_type_t stream, const char* expectedMixPortName) {
    audio_io_handle_t output = mManager->getOutput(stream);
    EXPECT_NO_FATAL_FAILURE(verifyMixPortNameAndFlags(output, expectedMixPortName));
}

void AudioPolicyManagerPhoneTest::verifyMixPortNameAndFlags(audio_io_handle_t output,
                                                            const char* expectedMixPortName) {
    ALOGI("%s: checking output %d", __func__, output);
    sp<SwAudioOutputDescriptor> outDesc = mManager->getOutputs().valueFor(output);
    ASSERT_NE(nullptr, outDesc.get());
    audio_port_v7 port = {};
    outDesc->toAudioPort(&port);
    EXPECT_EQ(AUDIO_PORT_TYPE_MIX, port.type);
    EXPECT_EQ(AUDIO_PORT_ROLE_SOURCE, port.role);
    ASSERT_STREQ(expectedMixPortName, port.name);

    auto iter = sMixPortFlags.find(port.name);
    ASSERT_NE(iter, sMixPortFlags.end()) << "\"" << port.name << "\" is not in sMixPortFlags";
    auto actualFlags = mClient->getOpenOutputFlags(output);
    ASSERT_TRUE(actualFlags.has_value()) << "\"" << port.name << "\" was not opened via client";
    EXPECT_EQ(*actualFlags, iter->second);
}

TEST_F(AudioPolicyManagerPhoneTest, InitSuccess) {
    // SetUp must finish with no assertions.
}

TEST_F(AudioPolicyManagerPhoneTest, Dump) {
    dumpToLog();
}

TEST_F(AudioPolicyManagerPhoneTest, NoPatchChangesDuringAlarmPlayback) {
    audio_port_handle_t alarmPortId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t alarmOutput = AUDIO_IO_HANDLE_NONE;
    bool muted{};
    float volume{};
    {
        // Uses STRATEGY_SONIFICATION, routed to AUDIO_DEVICE_OUT_SPEAKER_SAFE.
        audio_attributes_t attr = {
            .content_type = AUDIO_CONTENT_TYPE_UNKNOWN,
            .usage = AUDIO_USAGE_ALARM,
        };
        DeviceIdVector selectedDeviceIds;
        ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                        AUDIO_CHANNEL_OUT_STEREO, 48000,
                        AUDIO_OUTPUT_FLAG_NONE,
                        &alarmOutput, &alarmPortId, attr));
        EXPECT_EQ(NO_ERROR, mManager->startOutput(alarmPortId, &volume, &muted));
        EXPECT_GE(volume, 0.f);
        EXPECT_LE(volume, 1.f);
    }
    const audio_patch lastPatchBefore = *(mClient->getLastAddedPatch());

    {
        // Uses STRATEGY_MEDIA, routed to AUDIO_DEVICE_OUT_SPEAKER.
        audio_attributes_t attr = {
            .content_type = AUDIO_CONTENT_TYPE_UNKNOWN,
            .usage = AUDIO_USAGE_MEDIA,
        };
        DeviceIdVector selectedDeviceIds;
        audio_port_handle_t notifPortId = AUDIO_PORT_HANDLE_NONE;
        audio_io_handle_t notifOutput = AUDIO_IO_HANDLE_NONE;
        ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                        AUDIO_CHANNEL_OUT_STEREO, 48000,
                        AUDIO_OUTPUT_FLAG_NONE,
                        &notifOutput, &notifPortId, attr));
        EXPECT_EQ(NO_ERROR, mManager->startOutput(notifPortId, &volume, &muted));
        EXPECT_GE(volume, 0.f);
        EXPECT_LE(volume, 1.f);
    }
    dumpToLog();
    const audio_patch lastPatchAfter = *(mClient->getLastAddedPatch());
    EXPECT_TRUE(audio_patches_are_equal(&lastPatchBefore, &lastPatchAfter)) <<
            "Unexpected change in patches detected";
}

TEST_F(AudioPolicyManagerPhoneTest, ForceReleaseDirectOutput) {
    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t output;
    audio_port_handle_t portId;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_FLOAT,
                                             AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                                             AUDIO_OUTPUT_FLAG_DIRECT, &output, &portId));
    EXPECT_NE(nullptr, mManager->getOutputs().valueFor(output));
    ASSERT_EQ(OK, mManager->forceReleaseDirectOutput(output));
    EXPECT_EQ(nullptr, mManager->getOutputs().valueFor(output));
}

TEST_F(AudioPolicyManagerPhoneTest, ForceReleaseDirectOutputForNonDirect) {
    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t output;
    audio_port_handle_t portId;
    // This should select the default (non-direct) output.
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                                             AUDIO_CHANNEL_OUT_STEREO, k48000SamplingRate,
                                             AUDIO_OUTPUT_FLAG_NONE, &output, &portId));
    EXPECT_NE(nullptr, mManager->getOutputs().valueFor(output));
    EXPECT_EQ(BAD_VALUE, mManager->forceReleaseDirectOutput(output));
    EXPECT_NE(nullptr, mManager->getOutputs().valueFor(output));
}

TEST_F(AudioPolicyManagerPhoneTest, HangupReevaluatesAndRestoresDevice) {

    EXPECT_FALSE(mManager->sawFromCacheTriggered());
    DeviceIdVector initialDeviceIds;
    audio_io_handle_t outputHandle = AUDIO_IO_HANDLE_NONE;
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&initialDeviceIds,
                                             AUDIO_FORMAT_PCM_16_BIT,
                                             AUDIO_CHANNEL_OUT_STEREO,
                                             k48000SamplingRate,
                                             AUDIO_OUTPUT_FLAG_NONE,
                                             &outputHandle,
                                             &portId,
                                             AUDIO_ATTRIBUTES_INITIALIZER,
                                             AUDIO_SESSION_NONE));

    ASSERT_EQ(initialDeviceIds.size(), 1u);
    auto initialDevice =
            mManager->getAvailableOutputDevices().getDeviceFromId(initialDeviceIds[0]);
    ASSERT_NE(nullptr, initialDevice);

    mManager->setPhoneState(AUDIO_MODE_IN_CALL);
    DeviceIdVector inCallDeviceIds;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&inCallDeviceIds,
                                             AUDIO_FORMAT_PCM_16_BIT,
                                             AUDIO_CHANNEL_OUT_STEREO,
                                             k48000SamplingRate,
                                             AUDIO_OUTPUT_FLAG_NONE,
                                             &outputHandle,
                                             &portId,
                                             AUDIO_ATTRIBUTES_INITIALIZER,
                                             AUDIO_SESSION_NONE));

    ASSERT_EQ(inCallDeviceIds.size(), 1u);
    auto inCallDevice = mManager->getAvailableOutputDevices().getDeviceFromId(inCallDeviceIds[0]);
    ASSERT_NE(nullptr, inCallDevice);
    EXPECT_NE(inCallDevice, initialDevice);

    mManager->resetCacheObservation();
    mManager->setPhoneState(AUDIO_MODE_NORMAL);
    EXPECT_FALSE(mManager->sawFromCacheTriggered());

    DeviceIdVector normalDeviceIds;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&normalDeviceIds,
                                             AUDIO_FORMAT_PCM_16_BIT,
                                             AUDIO_CHANNEL_OUT_STEREO,
                                             k48000SamplingRate,
                                             AUDIO_OUTPUT_FLAG_NONE,
                                             &outputHandle,
                                             &portId,
                                             AUDIO_ATTRIBUTES_INITIALIZER,
                                             AUDIO_SESSION_NONE));

    ASSERT_EQ(normalDeviceIds.size(), 1u);
    auto normalDevice = mManager->getAvailableOutputDevices().getDeviceFromId(normalDeviceIds[0]);
    ASSERT_NE(nullptr, normalDevice);
    EXPECT_EQ(normalDevice, initialDevice);
}

enum {
    MIX_PORT_ATTR_EXPECTED_NAME_PARAMETER,
    MIX_PORT_ATTR_EXPECTED_NAME_WITH_DBFM_PARAMETER,
    MIX_PORT_ATTR_FLAGS_PARAMETER,
    MIX_PORT_ATTR_FORMAT_PARAMETER,
    MIX_PORT_ATTR_SAMPLING_RATE_PARAMETER,
};
using MixPortSelectionForAttr =
        std::tuple<const char*, const char*, audio_output_flags_t, audio_format_t, int>;

class AudioPolicyManagerOutputMixPortForAttrSelectionTest
    : public AudioPolicyManagerPhoneTest,
      public testing::WithParamInterface<MixPortSelectionForAttr> {
};

// There is no easy way to create a flat tuple from tuples via ::testing::Combine.
// Instead, just run the same selection twice while altering the deep buffer for media setting.
TEST_P(AudioPolicyManagerOutputMixPortForAttrSelectionTest, SelectPortByFlags) {
    mConfig->setUseDeepBufferForMediaOverrideForTests(false);
    ASSERT_NO_FATAL_FAILURE(testOutputMixPortSelectionForAttr(
                    std::get<MIX_PORT_ATTR_FLAGS_PARAMETER>(GetParam()),
                    std::get<MIX_PORT_ATTR_FORMAT_PARAMETER>(GetParam()),
                    std::get<MIX_PORT_ATTR_SAMPLING_RATE_PARAMETER>(GetParam()),
                    false /*isMusic*/,
                    std::get<MIX_PORT_ATTR_EXPECTED_NAME_PARAMETER>(GetParam())));
}
TEST_P(AudioPolicyManagerOutputMixPortForAttrSelectionTest, SelectPortByFlags_Music) {
    mConfig->setUseDeepBufferForMediaOverrideForTests(false);
    ASSERT_NO_FATAL_FAILURE(testOutputMixPortSelectionForAttr(
                    std::get<MIX_PORT_ATTR_FLAGS_PARAMETER>(GetParam()),
                    std::get<MIX_PORT_ATTR_FORMAT_PARAMETER>(GetParam()),
                    std::get<MIX_PORT_ATTR_SAMPLING_RATE_PARAMETER>(GetParam()),
                    true /*isMusic*/,
                    std::get<MIX_PORT_ATTR_EXPECTED_NAME_PARAMETER>(GetParam())));
}
TEST_P(AudioPolicyManagerOutputMixPortForAttrSelectionTest, SelectPortByFlags_DeepMedia) {
    mConfig->setUseDeepBufferForMediaOverrideForTests(true);
    const char* fallbackName = std::get<MIX_PORT_ATTR_EXPECTED_NAME_PARAMETER>(GetParam());
    ASSERT_NO_FATAL_FAILURE(
            testOutputMixPortSelectionForAttr(std::get<MIX_PORT_ATTR_FLAGS_PARAMETER>(GetParam()),
                                       std::get<MIX_PORT_ATTR_FORMAT_PARAMETER>(GetParam()),
                                       std::get<MIX_PORT_ATTR_SAMPLING_RATE_PARAMETER>(GetParam()),
                                       false /*isMusic*/,
                                       std::get<MIX_PORT_ATTR_EXPECTED_NAME_WITH_DBFM_PARAMETER>(
                                               GetParam()) ?: fallbackName));
}
TEST_P(AudioPolicyManagerOutputMixPortForAttrSelectionTest, SelectPortByFlags_DeepMedia_Music) {
    mConfig->setUseDeepBufferForMediaOverrideForTests(true);
    const char* fallbackName = std::get<MIX_PORT_ATTR_EXPECTED_NAME_PARAMETER>(GetParam());
    ASSERT_NO_FATAL_FAILURE(
            testOutputMixPortSelectionForAttr(std::get<MIX_PORT_ATTR_FLAGS_PARAMETER>(GetParam()),
                                       std::get<MIX_PORT_ATTR_FORMAT_PARAMETER>(GetParam()),
                                       std::get<MIX_PORT_ATTR_SAMPLING_RATE_PARAMETER>(GetParam()),
                                       true /*isMusic*/,
                                       std::get<MIX_PORT_ATTR_EXPECTED_NAME_WITH_DBFM_PARAMETER>(
                                               GetParam()) ?: fallbackName));
}

INSTANTIATE_TEST_CASE_P(AudioPolicyManagerOutputMixPortForAttrSelection,
        AudioPolicyManagerOutputMixPortForAttrSelectionTest,
        ::testing::Values(
                std::make_tuple("primary output", "deep buffer", AUDIO_OUTPUT_FLAG_NONE,
                        AUDIO_FORMAT_PCM_16_BIT, AudioPolicyManagerTest::k48000SamplingRate),
                std::make_tuple("primary output", "deep buffer", AUDIO_OUTPUT_FLAG_NONE,
                        AUDIO_FORMAT_PCM_FLOAT, AudioPolicyManagerTest::k48000SamplingRate),
                // Note: this goes to "direct" because 384000 > SAMPLE_RATE_HZ_MAX (192000)
                std::make_tuple("direct", "deep buffer", AUDIO_OUTPUT_FLAG_NONE,
                        AUDIO_FORMAT_PCM_FLOAT, AudioPolicyManagerTest::k384000SamplingRate),
                std::make_tuple("primary output", nullptr, AUDIO_OUTPUT_FLAG_FAST,
                        AUDIO_FORMAT_PCM_16_BIT, AudioPolicyManagerTest::k48000SamplingRate),
                std::make_tuple("direct", nullptr, AUDIO_OUTPUT_FLAG_DIRECT,
                        AUDIO_FORMAT_PCM_FLOAT, AudioPolicyManagerTest::k96000SamplingRate),
                std::make_tuple("direct", nullptr, AUDIO_OUTPUT_FLAG_DIRECT,
                        AUDIO_FORMAT_PCM_FLOAT, AudioPolicyManagerTest::k384000SamplingRate),
                std::make_tuple("deep buffer", nullptr, AUDIO_OUTPUT_FLAG_DEEP_BUFFER,
                        AUDIO_FORMAT_PCM_16_BIT, AudioPolicyManagerTest::k48000SamplingRate),
                std::make_tuple("deep buffer", nullptr, AUDIO_OUTPUT_FLAG_DEEP_BUFFER,
                        AUDIO_FORMAT_PCM_FLOAT, AudioPolicyManagerTest::k384000SamplingRate),
                std::make_tuple("compressed_offload", nullptr,
                        (audio_output_flags_t)(AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD |
                                AUDIO_OUTPUT_FLAG_NON_BLOCKING),
                        AUDIO_FORMAT_MP3, AudioPolicyManagerTest::k48000SamplingRate),
                std::make_tuple("raw", nullptr,
                        AUDIO_OUTPUT_FLAG_RAW, AUDIO_FORMAT_PCM_32_BIT,
                        AudioPolicyManagerTest::k48000SamplingRate),
                std::make_tuple("mmap_no_irq_out", nullptr,
                        (audio_output_flags_t)(AUDIO_OUTPUT_FLAG_DIRECT |
                                AUDIO_OUTPUT_FLAG_MMAP_NOIRQ),
                        AUDIO_FORMAT_PCM_FLOAT, AudioPolicyManagerTest::k48000SamplingRate),
                std::make_tuple("mmap_no_irq_out", nullptr,
                        (audio_output_flags_t)(AUDIO_OUTPUT_FLAG_DIRECT |
                                AUDIO_OUTPUT_FLAG_MMAP_NOIRQ),
                        AUDIO_FORMAT_PCM_FLOAT, AudioPolicyManagerTest::k384000SamplingRate),
                std::make_tuple("voip_rx", nullptr, AUDIO_OUTPUT_FLAG_VOIP_RX,
                        AUDIO_FORMAT_PCM_16_BIT, AudioPolicyManagerTest::k48000SamplingRate)),
        [](const ::testing::TestParamInfo<MixPortSelectionForAttr>& info) {
            static const std::string flagPrefix = "AUDIO_OUTPUT_FLAG_";
            static const std::string formatPrefix = "AUDIO_FORMAT_";
            std::string flags;
            TypeConverter<OutputFlagTraits>::maskToString(
                    std::get<MIX_PORT_ATTR_FLAGS_PARAMETER>(info.param), flags, "__");
            size_t index = 0;
            while (true) {
                index = flags.rfind(flagPrefix);
                if (index == std::string::npos) break;
                flags.erase(index, flagPrefix.length());
            }
            std::string format;
            TypeConverter<FormatTraits>::toString(
                    std::get<MIX_PORT_ATTR_FORMAT_PARAMETER>(info.param), format);
            if (size_t index = format.find(formatPrefix); index != std::string::npos) {
                format.erase(index, formatPrefix.length());
            }
            return flags + "__" + format + "__" +
                    std::to_string(std::get<MIX_PORT_ATTR_SAMPLING_RATE_PARAMETER>(info.param));
        }
);


enum {
    MIX_PORT_STRM_EXPECTED_NAME_PARAMETER,
    MIX_PORT_STRM_EXPECTED_NAME_WITH_DBFM_PARAMETER,
    MIX_PORT_STRM_STREAM_PARAMETER,
};
using MixPortSelectionForStream =
        std::tuple<const char*, const char*, audio_stream_type_t>;

class AudioPolicyManagerOutputMixPortForStreamSelectionTest
    : public AudioPolicyManagerPhoneTest,
      public testing::WithParamInterface<MixPortSelectionForStream> {
};

// There is no easy way to create a flat tuple from tuples via ::testing::Combine.
// Instead, just run the same selection twice while altering the deep buffer for media setting.
TEST_P(AudioPolicyManagerOutputMixPortForStreamSelectionTest, SelectPort_NoDBFM) {
    mConfig->setUseDeepBufferForMediaOverrideForTests(false);
    ASSERT_NO_FATAL_FAILURE(testOutputMixPortSelectionForStream(
                    std::get<MIX_PORT_STRM_STREAM_PARAMETER>(GetParam()),
                    std::get<MIX_PORT_STRM_EXPECTED_NAME_PARAMETER>(GetParam())));
}
TEST_P(AudioPolicyManagerOutputMixPortForStreamSelectionTest, SelectPort_WithDBFM) {
    mConfig->setUseDeepBufferForMediaOverrideForTests(true);
    const char* fallbackName = std::get<MIX_PORT_STRM_EXPECTED_NAME_PARAMETER>(GetParam());
    ASSERT_NO_FATAL_FAILURE(testOutputMixPortSelectionForStream(
                    std::get<MIX_PORT_STRM_STREAM_PARAMETER>(GetParam()),
                    std::get<MIX_PORT_STRM_EXPECTED_NAME_WITH_DBFM_PARAMETER>(
                            GetParam()) ?: fallbackName));
}

INSTANTIATE_TEST_CASE_P(
        AudioPolicyManagerOutputMixPortForStreamSelection,
        AudioPolicyManagerOutputMixPortForStreamSelectionTest,
        ::testing::Values(std::make_tuple("primary output", nullptr, AUDIO_STREAM_DEFAULT),
                          std::make_tuple("primary output", nullptr, AUDIO_STREAM_SYSTEM),
                          std::make_tuple("primary output", nullptr, AUDIO_STREAM_RING),
                          std::make_tuple("primary output", "deep buffer", AUDIO_STREAM_MUSIC),
                          std::make_tuple("primary output", nullptr, AUDIO_STREAM_ALARM),
                          std::make_tuple("primary output", nullptr, AUDIO_STREAM_NOTIFICATION),
                          std::make_tuple("primary output", nullptr, AUDIO_STREAM_BLUETOOTH_SCO),
                          std::make_tuple("primary output", nullptr, AUDIO_STREAM_ENFORCED_AUDIBLE),
                          std::make_tuple("primary output", nullptr, AUDIO_STREAM_DTMF),
                          std::make_tuple("primary output", nullptr, AUDIO_STREAM_TTS),
                          std::make_tuple("primary output", nullptr, AUDIO_STREAM_ACCESSIBILITY),
                          std::make_tuple("primary output", nullptr, AUDIO_STREAM_ASSISTANT)),
        [](const ::testing::TestParamInfo<MixPortSelectionForStream>& info) {
            static const std::string streamPrefix = "AUDIO_STREAM_";
            std::string stream;
            TypeConverter<StreamTraits>::toString(
                    std::get<MIX_PORT_STRM_STREAM_PARAMETER>(info.param), stream);
            if (size_t index = stream.find(streamPrefix); index != std::string::npos) {
                stream.erase(index, streamPrefix.length());
            }
            return stream;
        }
);

class AudioPolicyManagerDynamicHwModulesTest : public AudioPolicyManagerTestWithConfigurationFile {
protected:
    void SetUpManagerConfig() override;
};

void AudioPolicyManagerDynamicHwModulesTest::SetUpManagerConfig() {
    ASSERT_NO_FATAL_FAILURE(AudioPolicyManagerTestWithConfigurationFile::SetUpManagerConfig());
    // Only allow successful opening of "primary" hw module during APM initialization.
    mClient->swapAllowedModuleNames({"primary"});
}

TEST_F(AudioPolicyManagerDynamicHwModulesTest, InitSuccess) {
    // SetUp must finish with no assertions.
}

TEST_F(AudioPolicyManagerDynamicHwModulesTest, DynamicAddition) {
    const auto handleBefore = mClient->peekNextModuleHandle();
    mManager->onNewAudioModulesAvailable();
    ASSERT_EQ(handleBefore, mClient->peekNextModuleHandle());
    // Reset module loading restrictions.
    mClient->swapAllowedModuleNames();
    mManager->onNewAudioModulesAvailable();
    const auto handleAfter = mClient->peekNextModuleHandle();
    ASSERT_GT(handleAfter, handleBefore);
    mManager->onNewAudioModulesAvailable();
    ASSERT_EQ(handleAfter, mClient->peekNextModuleHandle());
}

TEST_F(AudioPolicyManagerDynamicHwModulesTest, AddedDeviceAvailable) {
    ASSERT_EQ(AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE, mManager->getDeviceConnectionState(
                    AUDIO_DEVICE_IN_REMOTE_SUBMIX, "0"));
    mClient->swapAllowedModuleNames({"primary", "r_submix"});
    mManager->onNewAudioModulesAvailable();
    ASSERT_EQ(AUDIO_POLICY_DEVICE_STATE_AVAILABLE, mManager->getDeviceConnectionState(
                    AUDIO_DEVICE_IN_REMOTE_SUBMIX, "0"));
}

TEST_F(AudioPolicyManagerDynamicHwModulesTest, ListAddedAudioPorts) {
    ASSERT_FALSE(
            findDevicePort(AUDIO_PORT_ROLE_SOURCE, AUDIO_DEVICE_IN_REMOTE_SUBMIX, "0", nullptr));
    mClient->swapAllowedModuleNames({"primary", "r_submix"});
    mManager->onNewAudioModulesAvailable();
    struct audio_port_v7 port;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SOURCE, AUDIO_DEVICE_IN_REMOTE_SUBMIX, "0", &port));
}

TEST_F(AudioPolicyManagerDynamicHwModulesTest, ClientIsUpdated) {
    const size_t prevAudioPortListUpdateCount = mClient->getAudioPortListUpdateCount();
    const uint32_t prevAudioPortGeneration = mManager->getAudioPortGeneration();
    mClient->swapAllowedModuleNames({"primary", "r_submix"});
    mManager->onNewAudioModulesAvailable();
    EXPECT_GT(mClient->getAudioPortListUpdateCount(), prevAudioPortListUpdateCount);
    EXPECT_GT(mManager->getAudioPortGeneration(), prevAudioPortGeneration);
}

using DevicesRoleForCapturePresetParam = std::tuple<audio_source_t, device_role_t>;

class AudioPolicyManagerDevicesRoleForCapturePresetTest
        : public AudioPolicyManagerTestWithConfigurationFile,
          public testing::WithParamInterface<DevicesRoleForCapturePresetParam> {
protected:
    // The `inputDevice` and `inputDevice2` indicate the audio devices type to be used for setting
    // device role. They must be declared in the test_audio_policy_configuration.xml
    AudioDeviceTypeAddr inputDevice = AudioDeviceTypeAddr(AUDIO_DEVICE_IN_BUILTIN_MIC, "");
    AudioDeviceTypeAddr inputDevice2 = AudioDeviceTypeAddr(AUDIO_DEVICE_IN_HDMI, "");
};

TEST_P(AudioPolicyManagerDevicesRoleForCapturePresetTest, DevicesRoleForCapturePreset) {
    const audio_source_t audioSource = std::get<0>(GetParam());
    const device_role_t role = std::get<1>(GetParam());

    // Test invalid device when setting
    const AudioDeviceTypeAddr outputDevice(AUDIO_DEVICE_OUT_SPEAKER, "");
    const AudioDeviceTypeAddrVector outputDevices = {outputDevice};
    ASSERT_EQ(BAD_VALUE,
              mManager->setDevicesRoleForCapturePreset(audioSource, role, outputDevices));
    ASSERT_EQ(BAD_VALUE,
              mManager->addDevicesRoleForCapturePreset(audioSource, role, outputDevices));
    AudioDeviceTypeAddrVector devices;
    ASSERT_EQ(NAME_NOT_FOUND,
              mManager->getDevicesForRoleAndCapturePreset(audioSource, role, devices));
    ASSERT_TRUE(devices.empty());
    ASSERT_EQ(BAD_VALUE,
              mManager->removeDevicesRoleForCapturePreset(audioSource, role, outputDevices));

    // Without setting, call get/remove/clear must fail
    ASSERT_EQ(NAME_NOT_FOUND,
              mManager->getDevicesForRoleAndCapturePreset(audioSource, role, devices));
    ASSERT_EQ(NAME_NOT_FOUND,
              mManager->removeDevicesRoleForCapturePreset(audioSource, role, devices));
    ASSERT_EQ(NAME_NOT_FOUND,
              mManager->clearDevicesRoleForCapturePreset(audioSource, role));

    // Test set/get devices role
    const AudioDeviceTypeAddrVector inputDevices = {inputDevice};
    ASSERT_EQ(NO_ERROR,
              mManager->setDevicesRoleForCapturePreset(audioSource, role, inputDevices));
    ASSERT_EQ(NO_ERROR, mManager->getDevicesForRoleAndCapturePreset(audioSource, role, devices));
    EXPECT_THAT(devices, UnorderedElementsAre(inputDevice));

    // Test setting will change the previously set devices
    const AudioDeviceTypeAddrVector inputDevices2 = {inputDevice2};
    ASSERT_EQ(NO_ERROR,
              mManager->setDevicesRoleForCapturePreset(audioSource, role, inputDevices2));
    devices.clear();
    ASSERT_EQ(NO_ERROR, mManager->getDevicesForRoleAndCapturePreset(audioSource, role, devices));
    EXPECT_THAT(devices, UnorderedElementsAre(inputDevice2));

    // Test add devices
    ASSERT_EQ(NO_ERROR,
              mManager->addDevicesRoleForCapturePreset(audioSource, role, inputDevices));
    devices.clear();
    ASSERT_EQ(NO_ERROR, mManager->getDevicesForRoleAndCapturePreset(audioSource, role, devices));
    EXPECT_THAT(devices, UnorderedElementsAre(inputDevice, inputDevice2));

    // Test remove devices
    ASSERT_EQ(NO_ERROR,
              mManager->removeDevicesRoleForCapturePreset(audioSource, role, inputDevices));
    devices.clear();
    ASSERT_EQ(NO_ERROR, mManager->getDevicesForRoleAndCapturePreset(audioSource, role, devices));
    EXPECT_THAT(devices, UnorderedElementsAre(inputDevice2));

    // Test remove devices that are not set as the device role
    ASSERT_EQ(BAD_VALUE,
              mManager->removeDevicesRoleForCapturePreset(audioSource, role, inputDevices));

    // Test clear devices
    ASSERT_EQ(NO_ERROR,
              mManager->clearDevicesRoleForCapturePreset(audioSource, role));
    devices.clear();
    ASSERT_EQ(NAME_NOT_FOUND,
              mManager->getDevicesForRoleAndCapturePreset(audioSource, role, devices));
}

TEST_F(AudioPolicyManagerDevicesRoleForCapturePresetTest, PreferredDeviceUsedForInput) {
    const audio_source_t source = AUDIO_SOURCE_MIC;
    const device_role_t role = DEVICE_ROLE_PREFERRED;
    const std::string address = "card=1;device=0";
    const std::string deviceName = "randomName";

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_IN_USB_DEVICE, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            address.c_str(), deviceName.c_str(), AUDIO_FORMAT_DEFAULT));
    auto availableDevices = mManager->getAvailableInputDevices();
    ASSERT_GT(availableDevices.size(), 1);

    audio_attributes_t attr = AUDIO_ATTRIBUTES_INITIALIZER;
    attr.source = source;
    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t input = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input, AUDIO_SESSION_NONE, 1, &selectedDeviceId,
                                            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                            k48000SamplingRate));
    auto selectedDevice = availableDevices.getDeviceFromId(selectedDeviceId);
    ASSERT_NE(nullptr, selectedDevice);

    sp<DeviceDescriptor> preferredDevice = nullptr;
    for (const auto& device : availableDevices) {
        if (device != selectedDevice) {
            preferredDevice = device;
            break;
        }
    }
    ASSERT_NE(nullptr, preferredDevice);
    // After setting preferred device for capture preset, the selected device for input should be
    // the preferred device.
    ASSERT_EQ(NO_ERROR,
              mManager->setDevicesRoleForCapturePreset(source, role,
                                                       {preferredDevice->getDeviceTypeAddr()}));
    selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    input = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input, AUDIO_SESSION_NONE, 1, &selectedDeviceId,
                                            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                            k48000SamplingRate));
    ASSERT_EQ(preferredDevice, availableDevices.getDeviceFromId(selectedDeviceId));

    // After clearing preferred device for capture preset, the selected device for input should be
    // the same as original one.
    ASSERT_EQ(NO_ERROR,
              mManager->clearDevicesRoleForCapturePreset(source, role));
    selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    input = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input, AUDIO_SESSION_NONE, 1, &selectedDeviceId,
                                            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                            k48000SamplingRate));
    ASSERT_EQ(selectedDevice, availableDevices.getDeviceFromId(selectedDeviceId));

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_IN_USB_DEVICE, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
            address.c_str(), deviceName.c_str(), AUDIO_FORMAT_DEFAULT));
}

TEST_F(AudioPolicyManagerDevicesRoleForCapturePresetTest, DisabledDeviceNotUsedForInput) {
    const audio_source_t source = AUDIO_SOURCE_MIC;
    const device_role_t role = DEVICE_ROLE_DISABLED;
    const std::string address = "card=1;device=0";
    const std::string deviceName = "randomName";

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_IN_USB_DEVICE, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            address.c_str(), deviceName.c_str(), AUDIO_FORMAT_DEFAULT));
    auto availableDevices = mManager->getAvailableInputDevices();
    ASSERT_GT(availableDevices.size(), 1);

    audio_attributes_t attr = AUDIO_ATTRIBUTES_INITIALIZER;
    attr.source = source;
    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t input = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input, AUDIO_SESSION_NONE, 1, &selectedDeviceId,
                                            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                            k48000SamplingRate));
    auto selectedDevice = availableDevices.getDeviceFromId(selectedDeviceId);
    ASSERT_NE(nullptr, selectedDevice);

    // After setting disabled device for capture preset, the disabled device must not be
    // selected for input.
    ASSERT_EQ(NO_ERROR,
              mManager->setDevicesRoleForCapturePreset(source, role,
                                                       {selectedDevice->getDeviceTypeAddr()}));
    selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    input = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input, AUDIO_SESSION_NONE, 1,
                                            &selectedDeviceId, AUDIO_FORMAT_PCM_16_BIT,
                                            AUDIO_CHANNEL_IN_STEREO, k48000SamplingRate));
    ASSERT_NE(selectedDevice, availableDevices.getDeviceFromId(selectedDeviceId));

    // After clearing disabled device for capture preset, the selected device for input should be
    // the original one.
    ASSERT_EQ(NO_ERROR,
              mManager->clearDevicesRoleForCapturePreset(source, role));
    selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    input = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input, AUDIO_SESSION_NONE, 1, &selectedDeviceId,
                                            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                            k48000SamplingRate));
    ASSERT_EQ(selectedDevice, availableDevices.getDeviceFromId(selectedDeviceId));

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_IN_USB_DEVICE, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
            address.c_str(), deviceName.c_str(), AUDIO_FORMAT_DEFAULT));
}

INSTANTIATE_TEST_CASE_P(
        DevicesRoleForCapturePresetOperation,
        AudioPolicyManagerDevicesRoleForCapturePresetTest,
        testing::Values(
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_MIC, DEVICE_ROLE_PREFERRED}),
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_VOICE_UPLINK,
                                                  DEVICE_ROLE_PREFERRED}),
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_VOICE_DOWNLINK,
                                                  DEVICE_ROLE_PREFERRED}),
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_VOICE_CALL, DEVICE_ROLE_PREFERRED}),
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_CAMCORDER, DEVICE_ROLE_PREFERRED}),
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_VOICE_RECOGNITION,
                                                  DEVICE_ROLE_PREFERRED}),
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_VOICE_COMMUNICATION,
                                                  DEVICE_ROLE_PREFERRED}),
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_REMOTE_SUBMIX,
                                                  DEVICE_ROLE_PREFERRED}),
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_UNPROCESSED, DEVICE_ROLE_PREFERRED}),
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_VOICE_PERFORMANCE,
                                                  DEVICE_ROLE_PREFERRED}),
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_ECHO_REFERENCE,
                                                  DEVICE_ROLE_PREFERRED}),
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_FM_TUNER, DEVICE_ROLE_PREFERRED}),
                DevicesRoleForCapturePresetParam({AUDIO_SOURCE_HOTWORD, DEVICE_ROLE_PREFERRED})
                )
        );


const effect_descriptor_t TEST_EFFECT_DESC = {
        {0xf2a4bb20, 0x0c3c, 0x11e3, 0x8b07, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}}, // type
        {0xff93e360, 0x0c3c, 0x11e3, 0x8a97, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}}, // uuid
        EFFECT_CONTROL_API_VERSION,
        EFFECT_FLAG_TYPE_PRE_PROC,
        0,
        1,
        "APM test Effect",
        "The Android Open Source Project",
};

class AudioPolicyManagerPreProcEffectTest : public AudioPolicyManagerTestWithConfigurationFile {
};

TEST_F(AudioPolicyManagerPreProcEffectTest, DeviceDisconnectWhileClientActive) {
    const audio_source_t source = AUDIO_SOURCE_MIC;
    const std::string address = "BUS00_MIC";
    const std::string deviceName = "randomName";
    audio_port_handle_t portId;
    audio_devices_t type = AUDIO_DEVICE_IN_BUS;

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(type,
            AUDIO_POLICY_DEVICE_STATE_AVAILABLE, address.c_str(), deviceName.c_str(),
            AUDIO_FORMAT_DEFAULT));
    auto availableDevices = mManager->getAvailableInputDevices();
    ASSERT_GT(availableDevices.size(), 1);

    audio_attributes_t attr = AUDIO_ATTRIBUTES_INITIALIZER;
    attr.source = source;
    audio_session_t session = TEST_SESSION_ID;
    audio_io_handle_t inputClientHandle = 777;
    int effectId = 666;
    audio_port_v7 devicePort;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SOURCE, type, address, &devicePort));

    audio_port_handle_t routedPortId = devicePort.id;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &inputClientHandle, session, 1, &routedPortId,
                                            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                            48000, AUDIO_INPUT_FLAG_NONE, &portId));
    ASSERT_EQ(devicePort.id, routedPortId);
    auto selectedDevice = availableDevices.getDeviceFromId(routedPortId);
    ASSERT_NE(nullptr, selectedDevice);

    // Add a pre processing effect on the input client session
    ASSERT_EQ(NO_ERROR, mManager->registerEffect(&TEST_EFFECT_DESC, inputClientHandle,
            PRODUCT_STRATEGY_NONE, session, effectId));

    ASSERT_EQ(NO_ERROR, mManager->startInput(portId));

    // Force a device disconnection to close the input, no crash expected of APM
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            type, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
            address.c_str(), deviceName.c_str(), AUDIO_FORMAT_DEFAULT));

    // Reconnect the device
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            type, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            address.c_str(), deviceName.c_str(), AUDIO_FORMAT_DEFAULT));

    inputClientHandle += 1;
    ASSERT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SOURCE, type, address, &devicePort));
    routedPortId = devicePort.id;

    // Reconnect the client changing voluntarily the io, but keeping the session to get the
    // effect attached again
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &inputClientHandle, session, 1, &routedPortId,
                                            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                            k48000SamplingRate));

    // unregister effect should succeed since effect shall have been restore on the client session
    ASSERT_EQ(NO_ERROR, mManager->unregisterEffect(effectId));
}

namespace {

class AudioPolicyManagerTestClientVolumeChecker : public AudioPolicyManagerTestClient {
public:

    status_t setPortsVolume(const std::vector<audio_port_handle_t>& ports, float volume,
                            bool /*muted*/, audio_io_handle_t /*output*/,
                            int /*delayMs*/) override {
        for (const auto& port : ports) {
            mLastPortVolume[port] = volume;
        }
        return NO_ERROR;
    }

    status_t setVoiceVolume(float volume, int /*delayMs*/) override {
        mLastVoiceVolume = volume;
        return NO_ERROR;
    }

    float getLastPortVolume(audio_port_handle_t port) {
        return mLastPortVolume[port];
    }

    float getLastVoiceVolume() const {
        return mLastVoiceVolume;
    }

private:
    std::unordered_map<audio_port_handle_t, float> mLastPortVolume;
    float mLastVoiceVolume;
};

}  // namespace

class AudioPolicyManagerTestAbsoluteVolume : public AudioPolicyManagerTestWithConfigurationFile {
protected:
    void SetUp() override;
    void TearDown() override;

    AudioPolicyManagerTestClientVolumeChecker* mVolumeCheckerClient;

    AudioPolicyManagerTestClient* getClient() override {
        return mVolumeCheckerClient = new AudioPolicyManagerTestClientVolumeChecker();
    }

    void setVolumeIndexForAttributesForDrivingStream();
    void setVolumeIndexForAttributesForNonDrivingStream();
    void setVolumeIndexForDtmfAttributesOnSco();

    audio_port_handle_t mOutputPortId = AUDIO_PORT_HANDLE_NONE;
    static constexpr audio_attributes_t sMediaAttr = {
            .content_type = AUDIO_CONTENT_TYPE_MUSIC,
            .usage = AUDIO_USAGE_MEDIA,
    };
    static constexpr audio_attributes_t sNotifAttr = {
            .content_type = AUDIO_CONTENT_TYPE_SONIFICATION,
            .usage = AUDIO_USAGE_NOTIFICATION,
    };
    static constexpr audio_attributes_t sVoiceCallAttr = {
            .content_type = AUDIO_CONTENT_TYPE_SPEECH,
            .usage = AUDIO_USAGE_VOICE_COMMUNICATION,
    };
    static constexpr audio_attributes_t sDtmfAttr = {
            .content_type = AUDIO_CONTENT_TYPE_UNKNOWN,
            .usage = AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
    };

    static constexpr char sDefBtAddress[] = "00:11:22:33:44:55";
};

void AudioPolicyManagerTestAbsoluteVolume::SetUp() {
    ASSERT_NO_FATAL_FAILURE(AudioPolicyManagerTestWithConfigurationFile::SetUp());

    mManager->setDeviceAbsoluteVolumeEnabled(AUDIO_DEVICE_OUT_USB_DEVICE, "", /*enabled=*/true,
                                             AUDIO_STREAM_MUSIC);
    mManager->setDeviceAbsoluteVolumeEnabled(AUDIO_DEVICE_OUT_BLUETOOTH_SCO, "", /*enabled=*/true,
                                             AUDIO_STREAM_VOICE_CALL);
}

void AudioPolicyManagerTestAbsoluteVolume::TearDown() {
    mManager->setPhoneState(AUDIO_MODE_NORMAL);

    ASSERT_EQ(NO_ERROR, mManager->stopOutput(mOutputPortId));
    ASSERT_EQ(NO_ERROR, mManager->releaseOutput(mOutputPortId));

    ASSERT_NO_FATAL_FAILURE(AudioPolicyManagerTestWithConfigurationFile::TearDown());
}

void AudioPolicyManagerTestAbsoluteVolume::setVolumeIndexForAttributesForDrivingStream() {
    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t mediaOutput = AUDIO_IO_HANDLE_NONE;
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                           "", "", AUDIO_FORMAT_PCM_16_BIT));
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                                             AUDIO_CHANNEL_OUT_STEREO, 48000,
                                             AUDIO_OUTPUT_FLAG_NONE,
                                             &mediaOutput, &mOutputPortId, sMediaAttr));
    bool muted{};
    float volume{};
    ASSERT_EQ(NO_ERROR, mManager->startOutput(mOutputPortId, &volume, &muted));
    EXPECT_GE(volume, 0.f);
    EXPECT_LE(volume, 1.f);
    EXPECT_EQ(NO_ERROR, mManager->setVolumeIndexForAttributes(sMediaAttr, /*index=*/1,
                                                              /*muted=*/false,
                                                              AUDIO_DEVICE_OUT_USB_DEVICE));

    EXPECT_EQ(1.f, mVolumeCheckerClient->getLastPortVolume(mOutputPortId));

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
}

TEST_F(AudioPolicyManagerTestAbsoluteVolume,
                  SetVolumeIndexForAttributesForDrivingStreamWithPortApi) {
    setVolumeIndexForAttributesForDrivingStream();
}

void AudioPolicyManagerTestAbsoluteVolume::setVolumeIndexForAttributesForNonDrivingStream() {
    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t notifOutput = AUDIO_IO_HANDLE_NONE;
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                           "", "", AUDIO_FORMAT_PCM_16_BIT));
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                                             AUDIO_CHANNEL_OUT_STEREO, 48000,
                                             AUDIO_OUTPUT_FLAG_NONE,
                                             &notifOutput, &mOutputPortId, sNotifAttr));
    bool muted{};
    float volume{};
    ASSERT_EQ(NO_ERROR, mManager->startOutput(mOutputPortId, &volume, &muted));
    EXPECT_GE(volume, 0.f);
    EXPECT_LE(volume, 1.f);
    EXPECT_EQ(NO_ERROR, mManager->setVolumeIndexForAttributes(sNotifAttr, /*index=*/1,
                                                              /*muted=*/false,
                                                              AUDIO_DEVICE_OUT_USB_DEVICE));

    EXPECT_GT(1.f, mVolumeCheckerClient->getLastPortVolume(mOutputPortId));

    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
}

TEST_F(AudioPolicyManagerTestAbsoluteVolume,
       SetVolumeIndexForAttributesForNonDrivingStreamWithPortApi) {
    setVolumeIndexForAttributesForNonDrivingStream();
}

TEST_F(AudioPolicyManagerTestAbsoluteVolume, SetVolumeIndexForVoiceCallAttributesNoScoBle) {
    mManager->setPhoneState(AUDIO_MODE_IN_COMMUNICATION);

    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t voiceOutput = AUDIO_IO_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                                             AUDIO_CHANNEL_OUT_STEREO, 48000,
                                             AUDIO_OUTPUT_FLAG_PRIMARY,
                                             &voiceOutput, &mOutputPortId, sVoiceCallAttr));
    bool muted{};
    float volume{};
    ASSERT_EQ(NO_ERROR, mManager->startOutput(mOutputPortId, &volume, &muted));
    EXPECT_GE(volume, 0.f);
    EXPECT_LE(volume, 1.f);

    EXPECT_EQ(NO_ERROR, mManager->setVolumeIndexForAttributes(sVoiceCallAttr, /*index=*/1,
                                                              /*muted=*/false,
                                                              AUDIO_DEVICE_OUT_USB_DEVICE));

    // setVoiceVolume is sent with actual value if no sco/ble device is connected
    EXPECT_GT(1.f, mVolumeCheckerClient->getLastVoiceVolume());
}

TEST_F(AudioPolicyManagerTestAbsoluteVolume, SetVolumeIndexForVoiceCallAttributesOnSco) {
    mManager->setPhoneState(AUDIO_MODE_IN_COMMUNICATION);
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_OUT_BLUETOOTH_SCO, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            sDefBtAddress, "", AUDIO_FORMAT_DEFAULT));

    const AudioDeviceTypeAddr scoOutputDevice(AUDIO_DEVICE_OUT_BLUETOOTH_SCO, sDefBtAddress);
    const AudioDeviceTypeAddrVector outputDevices = {scoOutputDevice};
    ASSERT_EQ(NO_ERROR, mManager->setDevicesRoleForStrategy(
            mManager->getStrategyForStream(AUDIO_STREAM_VOICE_CALL),
            DEVICE_ROLE_PREFERRED, outputDevices));

    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t voiceOutput = AUDIO_IO_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                                             AUDIO_CHANNEL_OUT_STEREO, 48000,
                                             AUDIO_OUTPUT_FLAG_PRIMARY,
                                             &voiceOutput, &mOutputPortId, sVoiceCallAttr));
    bool muted{};
    float volume{};
    ASSERT_EQ(NO_ERROR, mManager->startOutput(mOutputPortId, &volume, &muted));
    EXPECT_GE(volume, 0.f);
    EXPECT_LE(volume, 1.f);

    EXPECT_EQ(NO_ERROR, mManager->setVolumeIndexForAttributes(sVoiceCallAttr, /*index=*/1,
                                                              /*muted=*/false,
                                                              AUDIO_DEVICE_OUT_BLUETOOTH_SCO));

    EXPECT_EQ(1.f, mVolumeCheckerClient->getLastVoiceVolume());

    EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_BLUETOOTH_SCO,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           sDefBtAddress, "",
                                                           AUDIO_FORMAT_DEFAULT));
    EXPECT_EQ(NO_ERROR, mManager->clearDevicesRoleForStrategy(
            mManager->getStrategyForStream(AUDIO_STREAM_VOICE_CALL),
            DEVICE_ROLE_PREFERRED));
}

void AudioPolicyManagerTestAbsoluteVolume::setVolumeIndexForDtmfAttributesOnSco() {
    mManager->setPhoneState(AUDIO_MODE_IN_COMMUNICATION);
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_OUT_BLUETOOTH_SCO, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            sDefBtAddress, "", AUDIO_FORMAT_DEFAULT));

    const AudioDeviceTypeAddr scoOutputDevice(AUDIO_DEVICE_OUT_BLUETOOTH_SCO, sDefBtAddress);
    const AudioDeviceTypeAddrVector outputDevices = {scoOutputDevice};
    ASSERT_EQ(NO_ERROR, mManager->setDevicesRoleForStrategy(
            mManager->getStrategyForStream(AUDIO_STREAM_VOICE_CALL),
            DEVICE_ROLE_PREFERRED, outputDevices));

    DeviceIdVector selectedDeviceIds;
    audio_io_handle_t dtmfOutput = AUDIO_IO_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT,
                                             AUDIO_CHANNEL_OUT_STEREO, 48000,
                                             AUDIO_OUTPUT_FLAG_PRIMARY,
                                             &dtmfOutput, &mOutputPortId, sDtmfAttr));
    bool muted{};
    float volume{};
    ASSERT_EQ(NO_ERROR, mManager->startOutput(mOutputPortId, &volume, &muted));
    EXPECT_GE(volume, 0.f);
    EXPECT_LE(volume, 1.f);

    // voice call needs to be adjusted to the same level since they are usually aliased
    EXPECT_EQ(NO_ERROR, mManager->setVolumeIndexForAttributes(sVoiceCallAttr, /*index=*/1,
                                                              /*muted=*/false,
                                                              AUDIO_DEVICE_OUT_BLUETOOTH_SCO));
    EXPECT_EQ(NO_ERROR, mManager->setVolumeIndexForAttributes(sDtmfAttr, /*index=*/1,
                                                              /*muted=*/false,
                                                              AUDIO_DEVICE_OUT_BLUETOOTH_SCO));

    EXPECT_EQ(1.f, mVolumeCheckerClient->getLastPortVolume(mOutputPortId));

    EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_BLUETOOTH_SCO,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           sDefBtAddress, "",
                                                           AUDIO_FORMAT_DEFAULT));
    EXPECT_EQ(NO_ERROR, mManager->clearDevicesRoleForStrategy(
            mManager->getStrategyForStream(AUDIO_STREAM_VOICE_CALL),
            DEVICE_ROLE_PREFERRED));
}

TEST_F(AudioPolicyManagerTestAbsoluteVolume,
                  SetVolumeIndexForDtmfAttributesOnScoWithPortApi) {
    setVolumeIndexForDtmfAttributesOnSco();
}

class AudioPolicyManagerTestVolumeGroupID : public AudioPolicyManagerTestWithConfigurationFile {
public:
    static constexpr int sMinIndex = 5;
    static constexpr int sMaxIndex = 10;
    static const std::vector<audio_stream_type_t> sStreams;
protected:
    void SetUp() override;
    void TearDown() override;
};

const std::vector<audio_stream_type_t> AudioPolicyManagerTestVolumeGroupID::sStreams{
        AUDIO_STREAM_VOICE_CALL,
        AUDIO_STREAM_SYSTEM,
        AUDIO_STREAM_RING,
        AUDIO_STREAM_MUSIC,
        AUDIO_STREAM_ALARM,
        AUDIO_STREAM_NOTIFICATION,
        AUDIO_STREAM_BLUETOOTH_SCO,
        AUDIO_STREAM_ENFORCED_AUDIBLE,
        AUDIO_STREAM_DTMF,
        AUDIO_STREAM_TTS,
        AUDIO_STREAM_ACCESSIBILITY,
        AUDIO_STREAM_ASSISTANT,
        AUDIO_STREAM_CALL_ASSISTANT,
};

void AudioPolicyManagerTestVolumeGroupID::SetUp() {
    ASSERT_NO_FATAL_FAILURE(AudioPolicyManagerTestWithConfigurationFile::SetUp());
    for (audio_stream_type_t stream : sStreams) {
        mManager->initStreamVolume(stream, sMinIndex, sMaxIndex);
    }
}

void AudioPolicyManagerTestVolumeGroupID::TearDown() {
    ASSERT_NO_FATAL_FAILURE(AudioPolicyManagerTestWithConfigurationFile::TearDown());
}

TEST_F_WITH_FLAGS(AudioPolicyManagerTestVolumeGroupID, GetMinMaxVolumeWithId,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::media::audiopolicy,
                                            volume_group_management_update))) {
    AudioVolumeGroupVector groups;
    EXPECT_EQ(OK, mManager->listAudioVolumeGroups(groups));
    for (const auto& group : groups) {
        if (group.getStreamTypes().empty()) continue;
        volume_group_t vg = group.getId();
        audio_stream_type_t streamType = group.getStreamTypes()[0];
        if (streamType >= AUDIO_STREAM_PUBLIC_CNT) continue;
        int minIndex;
        int maxIndex;

        EXPECT_EQ(OK, mManager->getMinVolumeIndexForGroup(vg, minIndex));
        EXPECT_EQ(OK, mManager->getMaxVolumeIndexForGroup(vg, maxIndex));

        EXPECT_EQ(sMinIndex, minIndex) << "Min index for group " << group.getName().c_str();
        EXPECT_EQ(sMaxIndex, maxIndex) << "Max index for group " << group.getName().c_str();
    }
}

TEST_F_WITH_FLAGS(AudioPolicyManagerTestVolumeGroupID, SetMinMaxVolumeWithId,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::media::audiopolicy,
                                            volume_group_management_update))) {
    AudioVolumeGroupVector groups;
    EXPECT_EQ(OK, mManager->listAudioVolumeGroups(groups));
    int testMinIndex = sMinIndex + 1;
    int testMaxIndex = sMaxIndex - 1;
    for (const auto& group : groups) {
        if (group.getStreamTypes().empty()) continue;
        volume_group_t vg = group.getId();
        audio_stream_type_t streamType = group.getStreamTypes()[0];
        if (streamType >= AUDIO_STREAM_PUBLIC_CNT) continue;

        EXPECT_EQ(OK, mManager->setMinVolumeIndexForGroup(vg, testMinIndex));
        EXPECT_EQ(OK, mManager->setMaxVolumeIndexForGroup(vg, testMaxIndex));

        int minIndex;
        int maxIndex;
        EXPECT_EQ(OK, mManager->getMinVolumeIndexForGroup(vg, minIndex));
        EXPECT_EQ(OK, mManager->getMaxVolumeIndexForGroup(vg, maxIndex));
        EXPECT_EQ(testMinIndex, minIndex) << "Min index for group after setting it "
            << group.getName().c_str();
        EXPECT_EQ(testMaxIndex, maxIndex) << "Max index for group after setting it "
            << group.getName().c_str();
    }
}

TEST_F_WITH_FLAGS(AudioPolicyManagerTestVolumeGroupID, SetAndGetVolumeWithId,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::media::audiopolicy,
                                            volume_group_management_update))) {
    AudioVolumeGroupVector groups;
    EXPECT_EQ(OK, mManager->listAudioVolumeGroups(groups));
    audio_devices_t type = AUDIO_DEVICE_OUT_SPEAKER;
    int testIndex = 7;
    for (const auto& group : groups) {
        if (group.getStreamTypes().empty()) continue;
        volume_group_t vg = group.getId();
        audio_stream_type_t streamType = group.getStreamTypes()[0];
        if (streamType >= AUDIO_STREAM_PUBLIC_CNT) continue;
        int setIndex;

        EXPECT_EQ(OK, mManager->setVolumeIndexForGroup(vg, testIndex, /* muted= */ false, type));
        EXPECT_EQ(OK, mManager->getVolumeIndexForGroup(vg, setIndex, type));

        EXPECT_EQ(testIndex, setIndex) << "Set index for group " << group.getName().c_str();
    }
}

TEST_F_WITH_FLAGS(AudioPolicyManagerTestVolumeGroupID, SetAndGetVolumeWithStream,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::media::audiopolicy,
                                            volume_group_management_update))) {
    AudioVolumeGroupVector groups;
    EXPECT_EQ(OK, mManager->listAudioVolumeGroups(groups));
    audio_devices_t type = AUDIO_DEVICE_OUT_SPEAKER;
    int testIndex = 8;
    for (const auto& group : groups) {
        if (group.getStreamTypes().empty()) continue;
        volume_group_t vg = group.getId();
        audio_stream_type_t streamType = group.getStreamTypes()[0];
        if (streamType >= AUDIO_STREAM_PUBLIC_CNT) continue;
        int setIndex;
        EXPECT_EQ(OK,
                  mManager->setStreamVolumeIndex(streamType, testIndex, /* muted= */ false, type));

        EXPECT_EQ(OK, mManager->getVolumeIndexForGroup(vg, setIndex, type));

        EXPECT_EQ(testIndex, setIndex) << "Set index for stream in " << group.getName().c_str();
    }
}

TEST_F_WITH_FLAGS(AudioPolicyManagerTestVolumeGroupID, SetWithIDAndGetVolumeWithStream,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::media::audiopolicy,
                                            volume_group_management_update))) {
    AudioVolumeGroupVector groups;
    EXPECT_EQ(OK, mManager->listAudioVolumeGroups(groups));
    audio_devices_t type = AUDIO_DEVICE_OUT_SPEAKER;
    int testIndex = 9;
    for (const auto& group : groups) {
        if (group.getStreamTypes().empty()) continue;
        volume_group_t vg = group.getId();
        audio_stream_type_t streamType = group.getStreamTypes()[0];
        if (streamType >= AUDIO_STREAM_PUBLIC_CNT) continue;
        int setIndex;

        EXPECT_EQ(OK, mManager->setVolumeIndexForGroup(vg, testIndex, /* muted= */ false, type));

        EXPECT_EQ(OK, mManager->getStreamVolumeIndex(streamType, &setIndex, type));
        EXPECT_EQ(testIndex, setIndex) << "Get index for stream in " << group.getName().c_str();
    }
}

TEST_F_WITH_FLAGS(AudioPolicyManagerTestVolumeGroupID, SetWithInvalidIndexVolumeWithId,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::media::audiopolicy,
                                            volume_group_management_update))) {
    AudioVolumeGroupVector groups;
    EXPECT_EQ(OK, mManager->listAudioVolumeGroups(groups));
    audio_devices_t type = AUDIO_DEVICE_OUT_SPEAKER;
    int testIndex = sMaxIndex + 1;
    for (const auto& group : groups) {
        if (group.getStreamTypes().empty()) continue;
        volume_group_t vg = group.getId();
        audio_stream_type_t streamType = group.getStreamTypes()[0];
        if (streamType >= AUDIO_STREAM_PUBLIC_CNT) continue;

        EXPECT_EQ(BAD_VALUE,
                  mManager->setVolumeIndexForGroup(vg, testIndex, /* muted= */ false, type));
    }
}

TEST_F_WITH_FLAGS(AudioPolicyManagerTestVolumeGroupID, SetWithInvalidId,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::media::audiopolicy,
                                            volume_group_management_update))) {
    audio_devices_t type = AUDIO_DEVICE_OUT_SPEAKER;

    EXPECT_EQ(BAD_VALUE, mManager->setVolumeIndexForGroup(VOLUME_GROUP_NONE, sMaxIndex,
                                                          /* muted= */ false, type));
}

TEST_F_WITH_FLAGS(AudioPolicyManagerTestVolumeGroupID, GetWithInvalidId,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::media::audiopolicy,
                                            volume_group_management_update))) {
    audio_devices_t type = AUDIO_DEVICE_OUT_SPEAKER;
    int index;

    EXPECT_EQ(BAD_VALUE, mManager->getVolumeIndexForGroup(VOLUME_GROUP_NONE, index, type));
}

TEST_F_WITH_FLAGS(AudioPolicyManagerTestVolumeGroupID, GetMinMaxWithInvalidId,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::media::audiopolicy,
                                            volume_group_management_update))) {
    int index;

    EXPECT_EQ(BAD_VALUE, mManager->getMinVolumeIndexForGroup(VOLUME_GROUP_NONE, index));
    EXPECT_EQ(BAD_VALUE, mManager->getMaxVolumeIndexForGroup(VOLUME_GROUP_NONE, index));
}

TEST_F_WITH_FLAGS(AudioPolicyManagerTestVolumeGroupID, SetMinMaxWithInvalidId,
        REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(android::media::audiopolicy,
                                            volume_group_management_update))) {
    int index = sMinIndex;

    EXPECT_EQ(BAD_VALUE, mManager->setMinVolumeIndexForGroup(VOLUME_GROUP_NONE, index));
    EXPECT_EQ(BAD_VALUE, mManager->setMaxVolumeIndexForGroup(VOLUME_GROUP_NONE, index));
}

class AudioPolicyManagerTestBitPerfectBase : public AudioPolicyManagerTestWithConfigurationFile {
protected:
    void SetUp() override;
    void TearDown() override;

    void startBitPerfectOutput();
    void reset();
    void getBitPerfectOutput(status_t expected);

    const audio_format_t mBitPerfectFormat = AUDIO_FORMAT_PCM_16_BIT;
    const audio_channel_mask_t mBitPerfectChannelMask = AUDIO_CHANNEL_OUT_STEREO;
    const uint32_t mBitPerfectSampleRate = k48000SamplingRate;
    const uid_t mUid = 1234;
    audio_port_handle_t mUsbPortId = AUDIO_PORT_HANDLE_NONE;

    audio_io_handle_t mBitPerfectOutput = AUDIO_IO_HANDLE_NONE;
    DeviceIdVector mSelectedDeviceIds;
    audio_port_handle_t mBitPerfectPortId = AUDIO_PORT_HANDLE_NONE;

    static constexpr audio_attributes_t sMediaAttr = {
            .content_type = AUDIO_CONTENT_TYPE_MUSIC,
            .usage = AUDIO_USAGE_MEDIA,
    };
};

void AudioPolicyManagerTestBitPerfectBase::SetUp() {
    ASSERT_NO_FATAL_FAILURE(AudioPolicyManagerTestWithConfigurationFile::SetUp());

    mClient->addSupportedFormat(mBitPerfectFormat);
    mClient->addSupportedChannelMask(mBitPerfectChannelMask);
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                                           "", "", AUDIO_FORMAT_DEFAULT));
    auto devices = mManager->getAvailableOutputDevices();
    mUsbPortId = AUDIO_PORT_HANDLE_NONE;
    for (auto device : devices) {
        if (device->type() == AUDIO_DEVICE_OUT_USB_DEVICE) {
            mUsbPortId = device->getId();
            break;
        }
    }
    EXPECT_NE(AUDIO_PORT_HANDLE_NONE, mUsbPortId);

    std::vector<audio_mixer_attributes_t> mixerAttributes;
    EXPECT_EQ(NO_ERROR, mManager->getSupportedMixerAttributes(mUsbPortId, mixerAttributes));
    EXPECT_GT(mixerAttributes.size(), 0);
    size_t bitPerfectIndex = 0;
    for (; bitPerfectIndex < mixerAttributes.size(); ++bitPerfectIndex) {
        if (mixerAttributes[bitPerfectIndex].mixer_behavior == AUDIO_MIXER_BEHAVIOR_BIT_PERFECT) {
            break;
        }
    }
    EXPECT_LT(bitPerfectIndex, mixerAttributes.size());
    EXPECT_EQ(mBitPerfectFormat, mixerAttributes[bitPerfectIndex].config.format);
    EXPECT_EQ(mBitPerfectChannelMask, mixerAttributes[bitPerfectIndex].config.channel_mask);
    EXPECT_EQ(mBitPerfectSampleRate, mixerAttributes[bitPerfectIndex].config.sample_rate);
    EXPECT_EQ(NO_ERROR,
              mManager->setPreferredMixerAttributes(
                      &sMediaAttr, mUsbPortId, mUid, &mixerAttributes[bitPerfectIndex]));
}

void AudioPolicyManagerTestBitPerfectBase::TearDown() {
    EXPECT_EQ(NO_ERROR,
              mManager->clearPreferredMixerAttributes(&sMediaAttr, mUsbPortId, mUid));
    ASSERT_EQ(NO_ERROR, mManager->setDeviceConnectionState(AUDIO_DEVICE_OUT_USB_DEVICE,
                                                           AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                           "", "", AUDIO_FORMAT_LDAC));

    ASSERT_NO_FATAL_FAILURE(AudioPolicyManagerTestWithConfigurationFile::TearDown());
}

void AudioPolicyManagerTestBitPerfectBase::startBitPerfectOutput() {
    reset();
    bool isBitPerfect;

    getOutputForAttr(&mSelectedDeviceIds, mBitPerfectFormat, mBitPerfectChannelMask,
                     mBitPerfectSampleRate, AUDIO_OUTPUT_FLAG_NONE, &mBitPerfectOutput,
                     &mBitPerfectPortId, sMediaAttr, AUDIO_SESSION_NONE, mUid, &isBitPerfect);
    bool muted{};
    float volume{};
    status_t status = mManager->startOutput(mBitPerfectPortId, &volume, &muted);
    if (status == DEAD_OBJECT) {
        getOutputForAttr(&mSelectedDeviceIds, mBitPerfectFormat, mBitPerfectChannelMask,
                         mBitPerfectSampleRate, AUDIO_OUTPUT_FLAG_NONE, &mBitPerfectOutput,
                         &mBitPerfectPortId, sMediaAttr, AUDIO_SESSION_NONE, mUid, &isBitPerfect);
        status = mManager->startOutput(mBitPerfectPortId, &volume, &muted);
    }
    EXPECT_EQ(NO_ERROR, status);
    EXPECT_GE(volume, 0.f);
    EXPECT_LE(volume, 1.f);
    EXPECT_TRUE(isBitPerfect);
    EXPECT_NE(AUDIO_IO_HANDLE_NONE, mBitPerfectOutput);
    const auto bitPerfectOutputDesc = mManager->getOutputs().valueFor(mBitPerfectOutput);
    EXPECT_NE(nullptr, bitPerfectOutputDesc);
    EXPECT_EQ(AUDIO_OUTPUT_FLAG_BIT_PERFECT,
              bitPerfectOutputDesc->mFlags & AUDIO_OUTPUT_FLAG_BIT_PERFECT);
};

void AudioPolicyManagerTestBitPerfectBase::reset() {
    mBitPerfectOutput = AUDIO_IO_HANDLE_NONE;
    mBitPerfectPortId = AUDIO_PORT_HANDLE_NONE;
    mSelectedDeviceIds.clear();
}

void AudioPolicyManagerTestBitPerfectBase::getBitPerfectOutput(status_t expected) {
    reset();
    audio_stream_type_t stream = AUDIO_STREAM_DEFAULT;
    AttributionSourceState attributionSource = createAttributionSourceState(mUid);
    audio_config_t config = AUDIO_CONFIG_INITIALIZER;
    config.sample_rate = mBitPerfectSampleRate;
    config.channel_mask = mBitPerfectChannelMask;
    config.format = mBitPerfectFormat;
    audio_output_flags_t flags = AUDIO_OUTPUT_FLAG_BIT_PERFECT;
    AudioPolicyInterface::output_type_t outputType;
    bool isSpatialized;
    bool isBitPerfect;
    EXPECT_EQ(expected,
              mManager->getOutputForAttr(&sMediaAttr, &mBitPerfectOutput, AUDIO_SESSION_NONE,
                                         &stream, attributionSource, &config, &flags,
                                         &mSelectedDeviceIds, &mBitPerfectPortId, {}, &outputType,
                                         &isSpatialized, &isBitPerfect));
}

class AudioPolicyManagerTestBitPerfect : public AudioPolicyManagerTestBitPerfectBase {
};

TEST_F(AudioPolicyManagerTestBitPerfect, UseBitPerfectOutput) {
    const uid_t anotherUid = 5678;
    audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;
    DeviceIdVector selectedDeviceIds;
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
    bool isBitPerfect;

    // When there is no active bit-perfect playback, the output selection will follow default
    // routing strategy.
    getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_QUAD,
                     48000, AUDIO_OUTPUT_FLAG_NONE, &output, &portId, sMediaAttr,
                     AUDIO_SESSION_NONE, mUid, &isBitPerfect);
    EXPECT_FALSE(isBitPerfect);
    EXPECT_NE(AUDIO_IO_HANDLE_NONE, output);
    const auto outputDesc = mManager->getOutputs().valueFor(output);
    EXPECT_NE(nullptr, outputDesc);
    EXPECT_NE(AUDIO_OUTPUT_FLAG_BIT_PERFECT, outputDesc->mFlags & AUDIO_OUTPUT_FLAG_BIT_PERFECT);

    // Start bit-perfect playback
    ASSERT_NO_FATAL_FAILURE(startBitPerfectOutput());

    // If the playback is from preferred mixer attributes owner but the request doesn't match
    // preferred mixer attributes, it will not be bit-perfect.
    getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_QUAD,
                     48000, AUDIO_OUTPUT_FLAG_NONE, &output, &portId, sMediaAttr,
                     AUDIO_SESSION_NONE, mUid, &isBitPerfect);
    EXPECT_FALSE(isBitPerfect);
    EXPECT_EQ(mBitPerfectOutput, output);

    // When bit-perfect playback is active, all other playback will be routed to bit-perfect output.
    getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
                     48000, AUDIO_OUTPUT_FLAG_NONE, &output, &portId, sMediaAttr,
                     AUDIO_SESSION_NONE, anotherUid, &isBitPerfect);
    EXPECT_FALSE(isBitPerfect);
    EXPECT_EQ(mBitPerfectOutput, output);

    // When bit-pefect playback is active, dtmf will also be routed to bit-perfect output.
    const audio_attributes_t dtmfAttr = {
            .content_type = AUDIO_CONTENT_TYPE_UNKNOWN,
            .usage = AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING,
    };
    audio_io_handle_t dtmfOutput = AUDIO_IO_HANDLE_NONE;
    selectedDeviceIds.clear();
    portId = AUDIO_PORT_HANDLE_NONE;
    getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
                     48000, AUDIO_OUTPUT_FLAG_NONE, &dtmfOutput, &portId, dtmfAttr,
                     AUDIO_SESSION_NONE, anotherUid, &isBitPerfect);
    EXPECT_FALSE(isBitPerfect);
    EXPECT_EQ(mBitPerfectOutput, dtmfOutput);

    // When configuration matches preferred mixer attributes, which is bit-perfect, but the client
    // is not the owner of preferred mixer attributes, the playback will not be bit-perfect.
    getOutputForAttr(&selectedDeviceIds, mBitPerfectFormat, mBitPerfectChannelMask,
                     mBitPerfectSampleRate, AUDIO_OUTPUT_FLAG_NONE, &output, &portId, sMediaAttr,
                     AUDIO_SESSION_NONE, anotherUid, &isBitPerfect);
    EXPECT_FALSE(isBitPerfect);
    EXPECT_EQ(mBitPerfectOutput, output);
}

TEST_F(AudioPolicyManagerTestBitPerfect, InternalMuteWhenBitPerfectCLientIsActive) {
    ASSERT_NO_FATAL_FAILURE(startBitPerfectOutput());

    // When bit-perfect playback is active, the system sound will be routed to bit-perfect output.
    // The system sound will be muted internally in this case. The bit-perfect client will be
    // played normally.
    const uint32_t anotherSampleRate = 44100;
    audio_port_handle_t systemSoundPortId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t systemSoundOutput = AUDIO_IO_HANDLE_NONE;
    const audio_attributes_t systemSoundAttr = {
            .content_type = AUDIO_CONTENT_TYPE_SONIFICATION,
            .usage = AUDIO_USAGE_ASSISTANCE_SONIFICATION,
    };
    DeviceIdVector selectedDeviceIds;
    bool isBitPerfect;
    getOutputForAttr(&selectedDeviceIds, mBitPerfectFormat, mBitPerfectChannelMask,
                     anotherSampleRate, AUDIO_OUTPUT_FLAG_NONE, &systemSoundOutput,
                     &systemSoundPortId, systemSoundAttr, AUDIO_SESSION_NONE, mUid, &isBitPerfect);
    EXPECT_FALSE(isBitPerfect);
    EXPECT_EQ(mBitPerfectOutput, systemSoundOutput);
    bool muted{};
    float volume{};
    EXPECT_EQ(NO_ERROR, mManager->startOutput(systemSoundPortId, &volume, &muted));
    EXPECT_GE(volume, 0.f);
    EXPECT_LE(volume, 1.f);
    EXPECT_TRUE(mClient->getTrackInternalMute(systemSoundPortId));
    EXPECT_FALSE(mClient->getTrackInternalMute(mBitPerfectPortId));
    EXPECT_EQ(NO_ERROR, mManager->stopOutput(systemSoundPortId));
    EXPECT_FALSE(mClient->getTrackInternalMute(mBitPerfectPortId));

    // When bit-perfect playback is active, the notification will be routed to bit-perfect output.
    // The notification sound will be played normally while the bit-perfect client will be muted
    // internally.
    audio_port_handle_t notificationPortId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t notificationOutput = AUDIO_IO_HANDLE_NONE;
    const audio_attributes_t notificationAttr = {
            .content_type = AUDIO_CONTENT_TYPE_SONIFICATION,
            .usage = AUDIO_USAGE_NOTIFICATION,
    };
    getOutputForAttr(&selectedDeviceIds, mBitPerfectFormat, mBitPerfectChannelMask,
                     anotherSampleRate, AUDIO_OUTPUT_FLAG_NONE, &notificationOutput,
                     &notificationPortId, notificationAttr, AUDIO_SESSION_NONE, mUid,
                     &isBitPerfect);
    EXPECT_FALSE(isBitPerfect);
    EXPECT_EQ(mBitPerfectOutput, notificationOutput);
    EXPECT_EQ(NO_ERROR, mManager->startOutput(notificationPortId, &volume, &muted));
    EXPECT_GE(volume, 0.f);
    EXPECT_LE(volume, 1.f);
    EXPECT_FALSE(mClient->getTrackInternalMute(notificationPortId));
    EXPECT_TRUE(mClient->getTrackInternalMute(mBitPerfectPortId));
    EXPECT_EQ(NO_ERROR, mManager->stopOutput(notificationPortId));
    EXPECT_FALSE(mClient->getTrackInternalMute(mBitPerfectPortId));

    EXPECT_EQ(NO_ERROR, mManager->stopOutput(mBitPerfectPortId));
}

class AudioPolicyManagerTestBitPerfectPhoneMode : public AudioPolicyManagerTestBitPerfectBase,
        public testing::WithParamInterface<audio_mode_t> {
};

TEST_P(AudioPolicyManagerTestBitPerfectPhoneMode, RejectBitPerfectWhenPhoneModeIsNotNormal) {
    ASSERT_NO_FATAL_FAILURE(startBitPerfectOutput());

    audio_mode_t mode = GetParam();
    mManager->setPhoneState(mode);
    // When the phone mode is not normal, the bit-perfect output will be reopned
    EXPECT_EQ(nullptr, mManager->getOutputs().valueFor(mBitPerfectOutput));

    // When the phone mode is not normal, the bit-perfect output will be closed.
    ASSERT_NO_FATAL_FAILURE(getBitPerfectOutput(INVALID_OPERATION));

    mManager->setPhoneState(AUDIO_MODE_NORMAL);
}

INSTANTIATE_TEST_CASE_P(
        PhoneMode,
        AudioPolicyManagerTestBitPerfectPhoneMode,
        testing::Values(AUDIO_MODE_IN_CALL,
                        AUDIO_MODE_RINGTONE,
                        AUDIO_MODE_IN_COMMUNICATION,
                        AUDIO_MODE_CALL_SCREEN)
);

class AudioPolicyManagerTestBitPerfectHigherPriorityUseCaseActive :
        public AudioPolicyManagerTestBitPerfectBase,
        public testing::WithParamInterface<audio_usage_t> {
};

TEST_P(AudioPolicyManagerTestBitPerfectHigherPriorityUseCaseActive,
       RejectBitPerfectWhenHigherPriorityUseCaseIsActive) {
    ASSERT_NO_FATAL_FAILURE(startBitPerfectOutput());

    audio_attributes_t attr = {
            .content_type = AUDIO_CONTENT_TYPE_UNKNOWN,
            .usage = GetParam(),
    };
    DeviceIdVector selectedDeviceIds;
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(
            getOutputForAttr(&selectedDeviceIds, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
                   48000, AUDIO_OUTPUT_FLAG_NONE, &output, &portId, attr));
    EXPECT_NE(mBitPerfectOutput, output);
    bool muted{};
    float volume{};
    EXPECT_EQ(NO_ERROR, mManager->startOutput(portId, &volume, &muted));
    EXPECT_GE(volume, 0.f);
    EXPECT_LE(volume, 1.f);
    // When a high priority use case is active, the bit-perfect output will be closed.
    EXPECT_EQ(nullptr, mManager->getOutputs().valueFor(mBitPerfectOutput));

    // When any higher priority use case is active, the bit-perfect request will be rejected.
    ASSERT_NO_FATAL_FAILURE(getBitPerfectOutput(INVALID_OPERATION));
}

INSTANTIATE_TEST_CASE_P(
        HigherPriorityUseCases,
        AudioPolicyManagerTestBitPerfectHigherPriorityUseCaseActive,
        testing::Values(AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE,
                        AUDIO_USAGE_ALARM)
);

class AudioPolicyManagerInputPreemptionTest : public AudioPolicyManagerTestWithConfigurationFile {
};

TEST_F_WITH_FLAGS(
        AudioPolicyManagerInputPreemptionTest,
        SameSessionReusesInput,
        REQUIRES_FLAGS_ENABLED(
                ACONFIG_FLAG(com::android::media::audioserver, fix_input_sharing_logic))
) {
    mClient->resetInputApiCallsCounters();

    audio_attributes_t attr = AUDIO_ATTRIBUTES_INITIALIZER;
    attr.source = AUDIO_SOURCE_MIC;
    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t input1 = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input1, TEST_SESSION_ID, 1, &selectedDeviceId,
                                            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                            k48000SamplingRate));

    EXPECT_EQ(1, mClient->getOpenInputCallsCount());

    audio_io_handle_t input2 = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input2, TEST_SESSION_ID, 1, &selectedDeviceId,
                                        AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                        k48000SamplingRate));

    EXPECT_EQ(1, mClient->getOpenInputCallsCount());
    EXPECT_EQ(0, mClient->getCloseInputCallsCount());
    EXPECT_EQ(input1, input2);
}

TEST_F_WITH_FLAGS(
        AudioPolicyManagerInputPreemptionTest,
        SameDeviceAndSourceReusesInput,
        REQUIRES_FLAGS_ENABLED(
        ACONFIG_FLAG(com::android::media::audioserver, fix_input_sharing_logic))
) {
    mClient->resetInputApiCallsCounters();

    audio_attributes_t attr = AUDIO_ATTRIBUTES_INITIALIZER;
    attr.source = AUDIO_SOURCE_VOICE_RECOGNITION;
    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t input1 = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input1, TEST_SESSION_ID, 1, &selectedDeviceId,
                                            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                            k48000SamplingRate));

    EXPECT_EQ(1, mClient->getOpenInputCallsCount());

    audio_io_handle_t input2 = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input2, OTHER_SESSION_ID, 1, &selectedDeviceId,
                                            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                            k48000SamplingRate));

    EXPECT_EQ(1, mClient->getOpenInputCallsCount());
    EXPECT_EQ(0, mClient->getCloseInputCallsCount());
    EXPECT_EQ(input1, input2);
}

TEST_F_WITH_FLAGS(
        AudioPolicyManagerInputPreemptionTest,
        LesserPriorityReusesInput,
        REQUIRES_FLAGS_ENABLED(
                ACONFIG_FLAG(com::android::media::audioserver, fix_input_sharing_logic))
) {
    mClient->resetInputApiCallsCounters();

    audio_attributes_t attr = AUDIO_ATTRIBUTES_INITIALIZER;
    attr.source = AUDIO_SOURCE_MIC;
    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t input1 = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input1, TEST_SESSION_ID, 1, &selectedDeviceId,
                                            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                            k48000SamplingRate));

    EXPECT_EQ(1, mClient->getOpenInputCallsCount());

    audio_io_handle_t input2 = AUDIO_PORT_HANDLE_NONE;
    attr.source = AUDIO_SOURCE_VOICE_RECOGNITION;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input2, OTHER_SESSION_ID, 1, &selectedDeviceId,
                                        AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                        k48000SamplingRate));

    EXPECT_EQ(1, mClient->getOpenInputCallsCount());
    EXPECT_EQ(0, mClient->getCloseInputCallsCount());
    EXPECT_EQ(input1, input2);
}

TEST_F_WITH_FLAGS(
        AudioPolicyManagerInputPreemptionTest,
        HigherPriorityPreemptsInput,
        REQUIRES_FLAGS_ENABLED(
                ACONFIG_FLAG(com::android::media::audioserver, fix_input_sharing_logic))
) {
    mClient->resetInputApiCallsCounters();

    audio_attributes_t attr = AUDIO_ATTRIBUTES_INITIALIZER;
    attr.source = AUDIO_SOURCE_MIC;
    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
    audio_io_handle_t input1 = AUDIO_PORT_HANDLE_NONE;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input1, TEST_SESSION_ID, 1, &selectedDeviceId,
                                            AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                            k48000SamplingRate));

    EXPECT_EQ(1, mClient->getOpenInputCallsCount());

    audio_io_handle_t input2 = AUDIO_PORT_HANDLE_NONE;
    attr.source = AUDIO_SOURCE_CAMCORDER;
    ASSERT_NO_FATAL_FAILURE(getInputForAttr(attr, &input2, OTHER_SESSION_ID, 1, &selectedDeviceId,
                                        AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_IN_STEREO,
                                        k48000SamplingRate));

    EXPECT_EQ(2, mClient->getOpenInputCallsCount());
    EXPECT_EQ(1, mClient->getCloseInputCallsCount());
    EXPECT_NE(input1, input2);
}

class AudioPolicyManagerPortRoutingTest : public AudioPolicyManagerTestWithConfigurationFile {
};

TEST_F_WITH_FLAGS(
        AudioPolicyManagerPortRoutingTest,
        RoutableReducesToSupportedWhenFlagDisabled,
        REQUIRES_FLAGS_DISABLED(
                ACONFIG_FLAG(com::android::media::audio, check_route_in_get_audio_mix_port),
                ACONFIG_FLAG(com::android::media::audioserver, enable_strict_port_routing_checks))
) {
    mManager->setPhoneState(AUDIO_MODE_IN_COMMUNICATION);


    const audio_devices_t kBtOutScoType = AUDIO_DEVICE_OUT_BLUETOOTH_SCO;
    const char btAddress[] = "11:22:33:44:55:66";

    sp<DeviceDescriptor> devDesc =
          new DeviceDescriptor(AudioDeviceTypeAddr(kBtOutScoType, btAddress));

    EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            kBtOutScoType, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
            btAddress, "", AUDIO_FORMAT_DEFAULT));

    bool atLeastOneProfileContainsDevice = false;

    for (const auto& hwModule : mManager->getHwModules()) {
        for (size_t i = 0; i < hwModule->getOutputProfiles().size(); ++i) {
            sp<IOProfile> outProfile = hwModule->getOutputProfiles()[i];

            const auto& supportedDevices = outProfile->getSupportedDevices();
            const auto& routableDevices = outProfile->getRoutableDevices();
            EXPECT_EQ(supportedDevices, routableDevices);

            if (supportedDevices.contains(devDesc)) {
                atLeastOneProfileContainsDevice = true;
                EXPECT_TRUE(outProfile->supportsDevice(devDesc));
                EXPECT_TRUE(outProfile->routesToDevice(devDesc));
            }
        }
    }

    EXPECT_TRUE(atLeastOneProfileContainsDevice);

    EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
            AUDIO_DEVICE_OUT_BLUETOOTH_SCO, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
            btAddress, "", AUDIO_FORMAT_DEFAULT));

    mManager->setPhoneState(AUDIO_MODE_NORMAL);
}

TEST_F_WITH_FLAGS(
        AudioPolicyManagerPortRoutingTest,
        PortRoutingOverUsbIsRespected,
        REQUIRES_FLAGS_ENABLED(
                ACONFIG_FLAG(com::android::media::audio, check_route_in_get_audio_mix_port),
                ACONFIG_FLAG(com::android::media::audioserver, enable_strict_port_routing_checks))
) {
    // These values must match the number of input and output mix ports defined
    // for the "usb" module in the test_audio_policy_configuration.xml file:
    //
    // Number of USB devices that we will connect at once for testing.
    const size_t NUM_DEVICES = 2;
    // Number of USB mix ports that we expect to find in the config.
    const size_t NUM_MIX_PORTS = 2;

    const audio_devices_t kUsbInHsType = AUDIO_DEVICE_IN_USB_HEADSET;
    const audio_devices_t kUsbOutHsType = AUDIO_DEVICE_OUT_USB_HEADSET;
    const std::string usbAddrs[NUM_DEVICES] = {"card=1;device=0", "card=2;device=0"};

    mClient->addSupportedFormat(AUDIO_FORMAT_PCM_16_BIT);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_OUT_STEREO);
    mClient->addSupportedChannelMask(AUDIO_CHANNEL_IN_STEREO);

    // This test is based on XML config parsing and does not have HAL IDs.
    // We assign some unique numbers to test this AIDL feature.
    int32_t halIdCounter = AUDIO_PORT_HANDLE_NONE + 1;
    for (const auto& hwModule : mManager->getHwModules()) {
        for (size_t i = 0; i < hwModule->getOutputProfiles().size(); ++i) {
            sp<IOProfile> outProfile = hwModule->getOutputProfiles()[i];
            outProfile->setHalIdForTest(halIdCounter++);
        }
        for (size_t i = 0; i < hwModule->getInputProfiles().size(); ++i) {
            sp<IOProfile> inProfile = hwModule->getInputProfiles()[i];
            inProfile->setHalIdForTest(halIdCounter++);
        }
    }

    sp<HwModule> usbModule = nullptr;
    for (const auto& hwModule : mManager->getHwModules()) {
        if (strcmp(hwModule->getName(), "usb") == 0) {
            usbModule = hwModule;
            break;
        }
    }
    ASSERT_NE(nullptr, usbModule.get());

    // General device descriptors to identify profiles that support
    // the USB device type.
    sp<DeviceDescriptor> usbGeneralInDevDesc =
          new DeviceDescriptor(AudioDeviceTypeAddr(kUsbInHsType, ""));
    sp<DeviceDescriptor> usbGeneralOutDevDesc =
          new DeviceDescriptor(AudioDeviceTypeAddr(kUsbOutHsType, ""));

    // Find eligible mix port profiles in the usb module.
    std::vector<sp<IOProfile>> usbInMixPortProfiles;
    for (size_t i = 0; i < usbModule->getInputProfiles().size(); ++i) {
        sp<IOProfile> inProfile = usbModule->getInputProfiles()[i];
        if (inProfile->supportsDevice(usbGeneralInDevDesc)) {
            usbInMixPortProfiles.push_back(inProfile);
        }
    }
    EXPECT_EQ(NUM_MIX_PORTS, usbInMixPortProfiles.size());

    std::vector<sp<IOProfile>> usbOutMixPortProfiles;
    for (size_t i = 0; i < usbModule->getOutputProfiles().size(); ++i) {
        sp<IOProfile> outProfile = usbModule->getOutputProfiles()[i];
        if (outProfile->supportsDevice(usbGeneralOutDevDesc)) {
            usbOutMixPortProfiles.push_back(outProfile);
        }
    }
    EXPECT_EQ(NUM_MIX_PORTS, usbOutMixPortProfiles.size());

    // Connect each device.
    for (size_t i = 0; i < NUM_DEVICES; ++i) {
        // Simulate exclusive routing from HAL.
        std::set<int32_t> nonRoutableInPortIds;
        std::set<int32_t> nonRoutableOutPortIds;
        for (size_t halId = AUDIO_PORT_HANDLE_NONE + 1; halId < halIdCounter; ++halId) {
            if (usbInMixPortProfiles[i]->getHalId() != halId) {
                nonRoutableInPortIds.insert(halId);
            }
            if (usbOutMixPortProfiles[i]->getHalId() != halId) {
                nonRoutableOutPortIds.insert(halId);
            }
        }

        mClient->setNonRoutableMixPortsForDevice(kUsbInHsType, usbAddrs[i], nonRoutableInPortIds);
        mClient->setNonRoutableMixPortsForDevice(kUsbOutHsType, usbAddrs[i], nonRoutableOutPortIds);

        EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
                kUsbInHsType, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                usbAddrs[i].c_str(), "", AUDIO_FORMAT_DEFAULT));
        EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
                kUsbOutHsType, AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                usbAddrs[i].c_str(), "", AUDIO_FORMAT_DEFAULT));
    }

    // Verify port connectivity and routability.
    for (size_t i = 0; i < NUM_DEVICES; ++i) {
        // Device port can be identified by type and address.
        audio_port_v7 usbInDevicePort;
        EXPECT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SOURCE, kUsbInHsType,
                                   usbAddrs[i], &usbInDevicePort));

        audio_port_v7 usbOutDevicePort;
        EXPECT_TRUE(findDevicePort(AUDIO_PORT_ROLE_SINK, kUsbOutHsType,
                                   usbAddrs[i], &usbOutDevicePort));

        sp<DeviceDescriptor> inDevDesc =
              mManager->getAvailableInputDevices().getDeviceFromDeviceTypeAddr(
                  AudioDeviceTypeAddr(kUsbInHsType, usbAddrs[i]));
        EXPECT_NE(nullptr, inDevDesc);

        sp<DeviceDescriptor> outDevDesc =
              mManager->getAvailableOutputDevices().getDeviceFromDeviceTypeAddr(
                  AudioDeviceTypeAddr(kUsbOutHsType, usbAddrs[i]));
        EXPECT_NE(nullptr, outDevDesc);

        // The device maps to the intended mix port profile.
        audio_format_t requestedFormat = AUDIO_FORMAT_PCM_16_BIT;
        uint32_t requestedRate = 48000;
        audio_channel_mask_t requestedChannelMask = AUDIO_CHANNEL_IN_STEREO;
        auto inProfile = mManager->getInputProfile(
            inDevDesc, requestedRate, requestedFormat, requestedChannelMask, AUDIO_INPUT_FLAG_NONE);
        ASSERT_NE(nullptr, inProfile.get());
        EXPECT_EQ(usbInMixPortProfiles[i]->getHalId(), inProfile->getHalId());

        DeviceVector outDevices(outDevDesc);
        std::set<audio_io_handle_t> outIoHandles =
              mManager->getOutputsForDevices(outDevices, mManager->getOutputs());

        for (audio_io_handle_t handle : outIoHandles) {
            const auto desc = mManager->getOutputs().valueFor(handle);

            EXPECT_EQ(true, desc->routesToDevice(outDevDesc));

            if (!desc->isDuplicated()) {
                EXPECT_EQ(usbOutMixPortProfiles[i]->getHalId(),
                          mClient->getMixPortIdByIoHandle(handle));
            }
        }
    }

    // Disconnect each device.
    for (size_t i = 0; i < NUM_DEVICES; ++i) {
        mClient->setNonRoutableMixPortsForDevice(kUsbInHsType, usbAddrs[i], std::set<int32_t>());
        EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
                kUsbInHsType, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                usbAddrs[i].c_str(), "", AUDIO_FORMAT_DEFAULT));

        mClient->setNonRoutableMixPortsForDevice(kUsbOutHsType, usbAddrs[i], std::set<int32_t>());
        EXPECT_EQ(NO_ERROR, mManager->setDeviceConnectionState(
                kUsbOutHsType, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                usbAddrs[i].c_str(), "", AUDIO_FORMAT_DEFAULT));
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new TestExecutionTracer());
    return RUN_ALL_TESTS();
}
