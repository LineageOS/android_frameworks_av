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
#include <cstdint>
#define LOG_TAG "EffectsFactoryHalInterfaceTest"

#include <media/audiohal/EffectsFactoryHalInterface.h>

#include <system/audio_effects/audio_effects_utils.h>
#include <system/audio_effects/effect_aec.h>
#include <system/audio_effects/effect_dynamicsprocessing.h>
#include <system/audio_effect.h>

#include <gtest/gtest.h>
#include <utils/RefBase.h>

namespace android {

using effect::utils::EffectParamReader;
using effect::utils::EffectParamWriter;

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

TEST(libAudioHalTest, getHalVersion) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    auto version = factory->getHalVersion();
    EXPECT_NE(0, version.getMajorVersion());
}

static char testDataBuffer[sizeof(effect_param_t) + 0xff] = {};
static char testResponseBuffer[sizeof(effect_param_t) + 0xff] = {};
TEST(libAudioHalTest, agcNotInit) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    std::vector<effect_descriptor_t> descs;
    EXPECT_EQ(OK, factory->getDescriptors(&FX_IID_AEC_, &descs));
    for (const auto& desc : descs) {
        ASSERT_EQ(0, std::memcmp(&desc.type, &FX_IID_AEC_, sizeof(FX_IID_AEC_)));
        sp<EffectHalInterface> interface;
        EXPECT_EQ(OK, factory->createEffect(&desc.uuid, 1 /* sessionId */, 1 /* ioId */,
                                            1 /* deviceId */, &interface));
        EXPECT_NE(nullptr, interface);
        effect_param_t* param = (effect_param_t*)testDataBuffer;
        uint32_t type = AEC_PARAM_ECHO_DELAY, value = 0xbead;
        param->psize = sizeof(type);
        param->vsize = sizeof(value);
        //EXPECT_EQ(1, 0) << param->psize << " " << param->vsize;
        EffectParamWriter writer(*param);
        EXPECT_EQ(OK, writer.writeToParameter(&type)) << writer.toString();
        EXPECT_EQ(OK, writer.writeToValue(&value)) << writer.toString();
        status_t reply = 0;
        uint32_t replySize = sizeof(reply);
        EXPECT_NE(OK, interface->command(EFFECT_CMD_SET_PARAM, (uint32_t)writer.getTotalSize(),
                                         param, &replySize, &reply));
        EXPECT_EQ(replySize, sizeof(reply));
        EXPECT_NE(OK, reply);
    }
}

// TODO: rethink about this test case to make it general for all types of effects
TEST(libAudioHalTest, aecInitSetAndGet) {
    auto factory = EffectsFactoryHalInterface::create();
    ASSERT_NE(nullptr, factory);

    std::vector<effect_descriptor_t> descs;
    EXPECT_EQ(OK, factory->getDescriptors(&FX_IID_AEC_, &descs));
    static constexpr uint32_t delayValue = 0x20;
    for (const auto& desc : descs) {
        ASSERT_EQ(0, std::memcmp(&desc.type, &FX_IID_AEC_, sizeof(effect_uuid_t)));
        sp<EffectHalInterface> interface;
        EXPECT_EQ(OK, factory->createEffect(&desc.uuid, 1 /* sessionId */, 1 /* ioId */,
                                            1 /* deviceId */, &interface));
        EXPECT_NE(nullptr, interface);
        effect_param_t* param = (effect_param_t*)testDataBuffer;
        uint32_t type = AEC_PARAM_ECHO_DELAY, value = delayValue;
        param->psize = sizeof(type);
        param->vsize = sizeof(value);
        EffectParamWriter writer(*param);
        EXPECT_EQ(OK, writer.writeToParameter(&type)) << writer.toString();
        EXPECT_EQ(OK, writer.writeToValue(&value)) << writer.toString();
        status_t reply = 0;
        uint32_t replySize = sizeof(reply);
        EXPECT_EQ(OK, interface->command(EFFECT_CMD_INIT, 0, nullptr, &replySize, &reply));
        EXPECT_EQ(OK, interface->command(EFFECT_CMD_SET_PARAM, (uint32_t)writer.getTotalSize(),
                                         param, &replySize, &reply)) << writer.toString();
        EXPECT_EQ(replySize, sizeof(reply));
        EXPECT_EQ(OK, reply);

        effect_param_t* responseParam = (effect_param_t*)testResponseBuffer;
        param->psize = sizeof(type);
        param->vsize = sizeof(value);
        EffectParamWriter request(*param);
        EXPECT_EQ(OK, request.writeToParameter(&type)) << request.toString();
        replySize = request.getTotalSize();
        EXPECT_EQ(OK, interface->command(EFFECT_CMD_GET_PARAM, (uint32_t)writer.getTotalSize(),
                                         param, &replySize, responseParam));
        EffectParamReader response(*responseParam);
        EXPECT_EQ(replySize, response.getTotalSize()) << response.toString();
        EXPECT_EQ(OK, response.readFromValue(&value)) << response.toString();
        EXPECT_EQ(delayValue, value) << response.toString();
    }
}
// TODO: b/263986405 Add multi-thread testing

} // namespace android
