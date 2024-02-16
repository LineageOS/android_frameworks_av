/*
 * Copyright 2022 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#define LOG_TAG "EffectsFactoryHalInterfaceTest"

#include <aidl/android/media/audio/common/AudioUuid.h>
#include <android/media/audio/common/HeadTracking.h>
#include <android/media/audio/common/Spatialization.h>
#include <gtest/gtest.h>
#include <media/AidlConversionCppNdk.h>
#include <media/audiohal/EffectsFactoryHalInterface.h>
#include <system/audio_aidl_utils.h>
#include <system/audio_effect.h>
#include <system/audio_effects/audio_effects_utils.h>
#include <system/audio_effects/effect_aec.h>
#include <system/audio_effects/effect_agc.h>
#include <system/audio_effects/effect_agc2.h>
#include <system/audio_effects/effect_bassboost.h>
#include <system/audio_effects/effect_downmix.h>
#include <system/audio_effects/effect_dynamicsprocessing.h>
#include <system/audio_effects/effect_hapticgenerator.h>
#include <system/audio_effects/effect_loudnessenhancer.h>
#include <system/audio_effects/effect_ns.h>
#include <system/audio_effects/effect_spatializer.h>
#include <utils/RefBase.h>
#include <vibrator/ExternalVibrationUtils.h>

namespace android {

using aidl::android::media::audio::common::AudioUuid;
using android::audio::utils::toString;
using effect::utils::EffectParamReader;
using effect::utils::EffectParamWriter;
using media::audio::common::HeadTracking;
using media::audio::common::Spatialization;

// EffectsFactoryHalInterface
TEST(libAudioHalTest, createEffectsFactoryHalInterface) {
    ASSERT_NE(nullptr, EffectsFactoryHalInterface::create());
}

TEST(libAudioHalTest, queryNumberEffects) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    uint32_t numEffects = 0;
    EXPECT_EQ(OK, factory->queryNumberEffects(&numEffects));
    EXPECT_NE(0ul, numEffects);
}

TEST(libAudioHalTest, getDescriptorByNumber) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    uint32_t numEffects = 0;
    EXPECT_EQ(OK, factory->queryNumberEffects(&numEffects));
    EXPECT_NE(0ul, numEffects);

    effect_descriptor_t desc;
    for (uint32_t i = 0; i < numEffects; i++) {
        EXPECT_EQ(OK, factory->getDescriptor(i, &desc));
    }
}

TEST(libAudioHalTest, createEffect) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    uint32_t numEffects = 0;
    EXPECT_EQ(OK, factory->queryNumberEffects(&numEffects));
    EXPECT_NE(0ul, numEffects);

    effect_descriptor_t desc;
    for (uint32_t i = 0; i < numEffects; i++) {
        sp<EffectHalInterface> interface;
        EXPECT_EQ(OK, factory->getDescriptor(i, &desc));
        EXPECT_EQ(OK, factory->createEffect(&desc.uuid, 1 /* sessionId */, 1 /* ioId */,
                                            1 /* deviceId */, &interface));
    }
}

TEST(libAudioHalTest, getProcessings) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    const auto &processings = factory->getProcessings();
    if (processings) {
        EXPECT_NE(0UL, processings->preprocess.size() + processings->postprocess.size() +
                               processings->deviceprocess.size());

        auto processingChecker = [](const auto& processings) {
            if (processings.size() != 0) {
                // any process need at least 1 effect inside
                std::for_each(processings.begin(), processings.end(), [](const auto& process) {
                    EXPECT_NE(0ul, process.effects.size());
                    // any effect should have a valid name string, and not proxy
                    for (const auto& effect : process.effects) {
                        SCOPED_TRACE("Effect: {" +
                                     (effect == nullptr
                                              ? "NULL}"
                                              : ("{name: " + effect->name + ", isproxy: " +
                                                 (effect->isProxy ? "true" : "false") + ", sw: " +
                                                 (effect->libSw ? "non-null" : "null") + ", hw: " +
                                                 (effect->libHw ? "non-null" : "null") + "}")));
                        EXPECT_NE(nullptr, effect);
                        EXPECT_NE("", effect->name);
                        EXPECT_EQ(false, effect->isProxy);
                        EXPECT_EQ(nullptr, effect->libSw);
                        EXPECT_EQ(nullptr, effect->libHw);
                    }
                });
            }
        };

        processingChecker(processings->preprocess);
        processingChecker(processings->postprocess);
        processingChecker(processings->deviceprocess);
    } else {
        GTEST_SKIP() << "no processing found, skipping the test";
    }
}

TEST(libAudioHalTest, getHalVersion) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    auto version = factory->getHalVersion();
    EXPECT_NE(0, version.getMajorVersion());
}

enum ParamSetGetType { SET_N_GET, SET_ONLY, GET_ONLY };
class EffectParamCombination {
  public:
    template <typename P, typename V>
    void init(const P& p, const V& v, size_t len, ParamSetGetType type) {
        if (type != GET_ONLY) {
            mSetBuffer.resize(sizeof(effect_param_t) + sizeof(p) + sizeof(v) + 4);
            mParameterSet =
                    std::make_shared<EffectParamReader>(createEffectParam(mSetBuffer.data(), p, v));
        }

        if (type != SET_ONLY) {
            mGetBuffer.resize(sizeof(effect_param_t) + sizeof(p) + len + 4);
            mExpectBuffer.resize(sizeof(effect_param_t) + sizeof(p) + len + 4);
            mParameterGet =
                    std::make_shared<EffectParamReader>(createEffectParam(mGetBuffer.data(), p, v));
            mParameterExpect = std::make_shared<EffectParamReader>(
                    createEffectParam(mExpectBuffer.data(), p, v));
            mValueSize = len;
        }
        mType = type;
    }

    std::shared_ptr<EffectParamReader> mParameterSet;    /* setParameter */
    std::shared_ptr<EffectParamReader> mParameterGet;    /* getParameter */
    std::shared_ptr<EffectParamReader> mParameterExpect; /* expected from getParameter */
    size_t mValueSize = 0ul; /* ValueSize expect to write in reply data buffer */
    ParamSetGetType mType = SET_N_GET;

    std::string toString() {
        uint32_t command = 0;
        std::string str = "Command: ";
        if (mType != GET_ONLY) {
            str += (OK == mParameterSet->readFromParameter(&command) ? std::to_string(command)
                                                                     : mParameterSet->toString());
        } else {
            str += (OK == mParameterGet->readFromParameter(&command) ? std::to_string(command)
                                                                     : mParameterSet->toString());
        }
        str += "_";
        str += toString(mType);
        return str;
    }

    static std::string toString(ParamSetGetType type) {
        switch (type) {
            case SET_N_GET:
                return "Type:SetAndGet";
            case SET_ONLY:
                return "Type:SetOnly";
            case GET_ONLY:
                return "Type:GetOnly";
        }
    }

  private:
    std::vector<uint8_t> mSetBuffer;
    std::vector<uint8_t> mGetBuffer;
    std::vector<uint8_t> mExpectBuffer;

    template <typename P, typename V>
    static EffectParamReader createEffectParam(void* buf, const P& p, const V& v) {
        effect_param_t* paramRet = (effect_param_t*)buf;
        paramRet->psize = sizeof(P);
        paramRet->vsize = sizeof(V);
        EffectParamWriter writer(*paramRet);
        EXPECT_EQ(OK, writer.writeToParameter(&p));
        EXPECT_EQ(OK, writer.writeToValue(&v));
        writer.finishValueWrite();
        return writer;
    }
};

template <typename P, typename V>
std::shared_ptr<EffectParamCombination> createEffectParamCombination(
        const P& p, const V& v, size_t len, ParamSetGetType type = SET_N_GET) {
    auto comb = std::make_shared<EffectParamCombination>();
    comb->init(p, v, len, type);
    return comb;
}

enum ParamName { TUPLE_UUID, TUPLE_IS_INPUT, TUPLE_PARAM_COMBINATION };
using EffectParamTestTuple = std::tuple<const effect_uuid_t* /* type UUID */, bool /* isInput */,
                                        std::vector<std::shared_ptr<EffectParamCombination>>>;
static const effect_uuid_t EXTEND_EFFECT_TYPE_UUID = {
        0xfa81dbde, 0x588b, 0x11ed, 0x9b6a, {0x02, 0x42, 0xac, 0x12, 0x00, 0x02}};
constexpr std::array<uint8_t, 10> kVendorExtensionData({0xff, 0x5, 0x50, 0xab, 0xcd, 0x00, 0xbd,
                                                        0xdb, 0xee, 0xff});
static std::vector<EffectParamTestTuple> testPairs = {
        std::make_tuple(
                FX_IID_AEC, true /* isInput */,
                std::vector<std::shared_ptr<EffectParamCombination>>{
                        createEffectParamCombination(AEC_PARAM_ECHO_DELAY, 0xff /* echoDelayMs */,
                                                     sizeof(int32_t) /* returnValueSize */)}),
        std::make_tuple(
                FX_IID_AGC, false /* isInput */,
                std::vector<std::shared_ptr<EffectParamCombination>>{
                        createEffectParamCombination(AGC_PARAM_TARGET_LEVEL, 20 /* targetLevel */,
                                                     sizeof(int16_t) /* returnValueSize */)}),
        std::make_tuple(
                SL_IID_BASSBOOST, false /* isInput */,
                std::vector<std::shared_ptr<EffectParamCombination>>{
                        createEffectParamCombination(BASSBOOST_PARAM_STRENGTH, 20 /* strength */,
                                                     sizeof(int16_t) /* returnValueSize */)}),
        std::make_tuple(
                EFFECT_UIID_DOWNMIX, false /* isInput */,
                std::vector<std::shared_ptr<EffectParamCombination>>{
                        createEffectParamCombination(DOWNMIX_PARAM_TYPE, DOWNMIX_TYPE_FOLD,
                                                     sizeof(int16_t) /* returnValueSize */)}),
        std::make_tuple(
                SL_IID_DYNAMICSPROCESSING, false /* isInput */,
                std::vector<std::shared_ptr<EffectParamCombination>>{createEffectParamCombination(
                        std::array<uint32_t, 2>({DP_PARAM_INPUT_GAIN, 0 /* channel */}),
                        30 /* gainDb */, sizeof(int32_t) /* returnValueSize */)}),
        std::make_tuple(
                FX_IID_LOUDNESS_ENHANCER, false /* isInput */,
                std::vector<std::shared_ptr<EffectParamCombination>>{createEffectParamCombination(
                        LOUDNESS_ENHANCER_PARAM_TARGET_GAIN_MB, 5 /* gain */,
                        sizeof(int32_t) /* returnValueSize */)}),
        std::make_tuple(
                FX_IID_NS, true /* isInput */,
                std::vector<std::shared_ptr<EffectParamCombination>>{createEffectParamCombination(
                        NS_PARAM_LEVEL, 1 /* level */, sizeof(int32_t) /* returnValueSize */)}),
        std::make_tuple(
                FX_IID_SPATIALIZER, false /* isInput */,
                std::vector<std::shared_ptr<EffectParamCombination>>{
                        createEffectParamCombination(SPATIALIZER_PARAM_LEVEL,
                                                     SPATIALIZATION_LEVEL_MULTICHANNEL,
                                                     sizeof(uint8_t), SET_N_GET),
                        createEffectParamCombination(SPATIALIZER_PARAM_HEADTRACKING_MODE,
                                                     HeadTracking::Mode::RELATIVE_WORLD,
                                                     sizeof(uint8_t), SET_N_GET),
                        createEffectParamCombination(
                                SPATIALIZER_PARAM_HEAD_TO_STAGE,
                                std::array<float, 6>{.55f, 0.2f, 1.f, .999f, .43f, 19.f},
                                sizeof(std::array<float, 6>), SET_ONLY),
                        createEffectParamCombination(
                                SPATIALIZER_PARAM_HEADTRACKING_CONNECTION,
                                std::array<uint32_t, 2>{
                                        static_cast<uint32_t>(HeadTracking::ConnectionMode::
                                                                      DIRECT_TO_SENSOR_TUNNEL),
                                        0x5e /* sensorId */},
                                sizeof(std::array<uint32_t, 2>), SET_N_GET),
                        createEffectParamCombination(
                                SPATIALIZER_PARAM_SUPPORTED_LEVELS,
                                std::array<Spatialization::Level, 3>{
                                        Spatialization::Level::NONE,
                                        Spatialization::Level::MULTICHANNEL,
                                        Spatialization::Level::BED_PLUS_OBJECTS},
                                sizeof(std::array<uint8_t, 3>), GET_ONLY),
                        createEffectParamCombination(SPATIALIZER_PARAM_HEADTRACKING_SUPPORTED, true,
                                                     sizeof(bool), GET_ONLY),
                        createEffectParamCombination(SPATIALIZER_PARAM_SUPPORTED_CHANNEL_MASKS,
                                                     AUDIO_CHANNEL_OUT_5POINT1, sizeof(uint8_t),
                                                     GET_ONLY),
                        createEffectParamCombination(
                                SPATIALIZER_PARAM_SUPPORTED_SPATIALIZATION_MODES,
                                std::array<Spatialization::Mode, 2>{
                                        Spatialization::Mode::BINAURAL,
                                        Spatialization::Mode::TRANSAURAL},
                                sizeof(std::array<uint8_t, 2>), GET_ONLY),
                        createEffectParamCombination(
                                SPATIALIZER_PARAM_SUPPORTED_HEADTRACKING_CONNECTION,
                                std::array<HeadTracking::ConnectionMode, 3>{
                                        HeadTracking::ConnectionMode::FRAMEWORK_PROCESSED,
                                        HeadTracking::ConnectionMode::DIRECT_TO_SENSOR_SW,
                                        HeadTracking::ConnectionMode::DIRECT_TO_SENSOR_TUNNEL},
                                sizeof(std::array<uint8_t, 3>), GET_ONLY),
                }),
        std::make_tuple(
                &EXTEND_EFFECT_TYPE_UUID, false /* isInput */,
                std::vector<std::shared_ptr<EffectParamCombination>>{createEffectParamCombination(
                        uint32_t{8}, kVendorExtensionData, sizeof(kVendorExtensionData))}),
};

class libAudioHalEffectParamTest : public ::testing::TestWithParam<EffectParamTestTuple> {
  public:
    libAudioHalEffectParamTest()
        : mParamTuple(GetParam()),
          mFactory(EffectsFactoryHalInterface::create()),
          mTypeUuid(std::get<TUPLE_UUID>(mParamTuple)),
          mCombinations(std::get<TUPLE_PARAM_COMBINATION>(mParamTuple)),
          mIsInput(std::get<TUPLE_IS_INPUT>(mParamTuple)),
          mDescs([&]() {
              std::vector<effect_descriptor_t> descs;
              if (mFactory && mTypeUuid && OK == mFactory->getDescriptors(mTypeUuid, &descs)) {
                  return descs;
              }
              return descs;
          }()) {}

    void SetUp() override {
        if (0ul == mDescs.size()) {
            GTEST_SKIP() << "Effect type not available on device, skipping";
        }
        for (const auto& desc : mDescs) {
            sp<EffectHalInterface> interface = createEffectHal(desc);
            ASSERT_NE(nullptr, interface);
            mHalInterfaces.push_back(interface);
        }
    }

    void initEffect(const sp<EffectHalInterface>& interface) {
        uint32_t reply = 0;
        uint32_t replySize = sizeof(reply);
        ASSERT_EQ(OK, interface->command(EFFECT_CMD_INIT, 0, nullptr, &replySize, &reply));

        ASSERT_EQ(OK, interface->command(EFFECT_CMD_SET_CONFIG, sizeof(effect_config_t),
                                         &mEffectConfig, &replySize, &reply));
    }

    void TearDown() override {
        for (auto& interface : mHalInterfaces) {
            interface->close();
        }
    }

    sp<EffectHalInterface> createEffectHal(const effect_descriptor_t& desc) {
        sp<EffectHalInterface> interface = nullptr;
        if (0 == std::memcmp(&desc.type, mTypeUuid, sizeof(effect_uuid_t)) &&
            OK == mFactory->createEffect(&desc.uuid, 1 /* sessionId */, 1 /* ioId */,
                                         1 /* deviceId */, &interface)) {
            return interface;
        }
        return nullptr;
    }

    void setAndGetParameter(const sp<EffectHalInterface>& interface) {
        for (const auto combination : mCombinations) {
            uint32_t replySize = kSetParamReplySize;
            uint8_t reply[replySize];
            const auto type = combination->mType;
            if (type != GET_ONLY) {
                const auto& set = combination->mParameterSet;
                ASSERT_EQ(OK,
                          interface->command(EFFECT_CMD_SET_PARAM, (uint32_t)set->getTotalSize(),
                                             const_cast<effect_param_t*>(&set->getEffectParam()),
                                             &replySize, &reply))
                        << set->toString();
                ASSERT_EQ(replySize, kSetParamReplySize);
            }

            if (type != SET_ONLY) {
                auto get = combination->mParameterGet;
                auto expect = combination->mParameterExpect;
                effect_param_t* getParam = const_cast<effect_param_t*>(&get->getEffectParam());
                size_t maxReplySize = combination->mValueSize + sizeof(effect_param_t) +
                                      sizeof(expect->getPaddedParameterSize());
                replySize = maxReplySize;
                EXPECT_EQ(OK,
                          interface->command(EFFECT_CMD_GET_PARAM, (uint32_t)expect->getTotalSize(),
                                             const_cast<effect_param_t*>(&expect->getEffectParam()),
                                             &replySize, getParam));

                EffectParamReader getReader(*getParam);
                EXPECT_EQ(replySize, getReader.getTotalSize()) << getReader.toString();
                if (combination->mValueSize) {
                    std::vector<uint8_t> expectedData(combination->mValueSize);
                    EXPECT_EQ(OK, expect->readFromValue(expectedData.data(), expectedData.size()))
                            << combination->toString();
                    std::vector<uint8_t> response(combination->mValueSize);
                    EXPECT_EQ(OK, getReader.readFromValue(response.data(), combination->mValueSize))
                            << " try get valueSize " << combination->mValueSize << " from:\n"
                            << getReader.toString() << "\nexpect:\n"
                            << expect->toString();
                    EXPECT_EQ(expectedData, response) << combination->toString();
                }
            }
        }
    }

    static constexpr size_t kSetParamReplySize = sizeof(uint32_t);
    const EffectParamTestTuple mParamTuple;
    const sp<EffectsFactoryHalInterface> mFactory;
    const effect_uuid_t* mTypeUuid;
    std::vector<std::shared_ptr<EffectParamCombination>> mCombinations{};
    const bool mIsInput;
    const std::vector<effect_descriptor_t> mDescs;
    std::vector<sp<EffectHalInterface>> mHalInterfaces{};
    effect_config_t mEffectConfig = {
            .inputCfg =
                    {
                            .buffer = {.frameCount = 0x100},
                            .samplingRate = 48000,
                            .channels = mIsInput ? AUDIO_CHANNEL_IN_VOICE_CALL_MONO
                                                 : AUDIO_CHANNEL_IN_STEREO,
                            .bufferProvider = {.getBuffer = nullptr,
                                               .releaseBuffer = nullptr,
                                               .cookie = nullptr},
                            .format = AUDIO_FORMAT_PCM_FLOAT,
                            .accessMode = EFFECT_BUFFER_ACCESS_READ,
                            .mask = EFFECT_CONFIG_ALL,
                    },
            .outputCfg =
                    {
                            .buffer = {.frameCount = 0x100},
                            .samplingRate = 48000,
                            .channels = mIsInput ? AUDIO_CHANNEL_IN_VOICE_CALL_MONO
                                                 : AUDIO_CHANNEL_OUT_STEREO,
                            .bufferProvider = {.getBuffer = nullptr,
                                               .releaseBuffer = nullptr,
                                               .cookie = nullptr},
                            .format = AUDIO_FORMAT_PCM_FLOAT,
                            .accessMode = EFFECT_BUFFER_ACCESS_WRITE,
                            .mask = EFFECT_CONFIG_ALL,
                    },
    };
};

TEST_P(libAudioHalEffectParamTest, setAndGetParam) {
    for (auto& interface : mHalInterfaces) {
        EXPECT_NO_FATAL_FAILURE(initEffect(interface));
        EXPECT_NO_FATAL_FAILURE(setAndGetParameter(interface));
    }
}

TEST_P(libAudioHalEffectParamTest, deviceIndicationUpdate) {
    for (auto& interface : mHalInterfaces) {
        EXPECT_NO_FATAL_FAILURE(initEffect(interface));

        // output device
        uint32_t deviceTypes = AUDIO_DEVICE_OUT_SPEAKER | AUDIO_DEVICE_OUT_BLE_SPEAKER;
        status_t cmdStatus;
        uint32_t replySize = sizeof(cmdStatus);
        EXPECT_EQ(OK, interface->command(EFFECT_CMD_SET_DEVICE, sizeof(uint32_t), &deviceTypes,
                                         &replySize, &cmdStatus));
        // input device
        deviceTypes = AUDIO_DEVICE_IN_WIRED_HEADSET | AUDIO_DEVICE_IN_BLUETOOTH_BLE;
        EXPECT_EQ(OK, interface->command(EFFECT_CMD_SET_DEVICE, sizeof(uint32_t), &deviceTypes,
                                         &replySize, &cmdStatus));
    }
}

TEST_P(libAudioHalEffectParamTest, audioModeIndicationUpdate) {
    for (auto& interface : mHalInterfaces) {
        EXPECT_NO_FATAL_FAILURE(initEffect(interface));
        uint32_t mode = AUDIO_MODE_IN_CALL;
        status_t cmdStatus;
        uint32_t replySize = sizeof(cmdStatus);
        EXPECT_EQ(OK, interface->command(EFFECT_CMD_SET_AUDIO_MODE, sizeof(uint32_t), &mode,
                                         &replySize, &cmdStatus));
    }
}

TEST_P(libAudioHalEffectParamTest, audioSourceIndicationUpdate) {
    for (auto& interface : mHalInterfaces) {
        EXPECT_NO_FATAL_FAILURE(initEffect(interface));
        uint32_t source = AUDIO_SOURCE_MIC;
        status_t cmdStatus;
        uint32_t replySize = sizeof(cmdStatus);
        EXPECT_EQ(OK, interface->command(EFFECT_CMD_SET_AUDIO_SOURCE, sizeof(uint32_t), &source,
                                         &replySize, &cmdStatus));
    }
}

INSTANTIATE_TEST_SUITE_P(
        libAudioHalEffectParamTest, libAudioHalEffectParamTest, ::testing::ValuesIn(testPairs),
        [](const testing::TestParamInfo<libAudioHalEffectParamTest::ParamType>& info) {
            AudioUuid uuid = ::aidl::android::legacy2aidl_audio_uuid_t_AudioUuid(
                                     *std::get<TUPLE_UUID>(info.param))
                                     .value();
            std::string name = "UUID_" + toString(uuid) + "_";
            name += std::get<TUPLE_IS_INPUT>(info.param) ? "_input" : "_output";
            std::replace_if(
                    name.begin(), name.end(), [](const char c) { return !std::isalnum(c); }, '_');
            return name;
        });
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(libAudioHalEffectParamTest);

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

} // namespace android
