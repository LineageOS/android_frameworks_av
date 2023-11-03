/*
 * Copyright (C) 2021 The Android Open Source Project
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
#define LOG_TAG "AudioEffectUnitTests"

#include <gtest/gtest.h>
#include <media/AudioEffect.h>
#include <system/audio_effects/effect_hapticgenerator.h>
#include <system/audio_effects/effect_spatializer.h>
#include <system/audio_effects/effect_visualizer.h>

#include "audio_test_utils.h"

using namespace android;

class AudioEffectCallback : public AudioEffect::IAudioEffectCallback {
  public:
    bool receivedFramesProcessed = false;

    void onFramesProcessed(int32_t framesProcessed) override {
        ALOGE("number of frames processed %d", framesProcessed);
        receivedFramesProcessed = true;
    }
};

static constexpr int kDefaultInputEffectPriority = -1;
static constexpr int kDefaultOutputEffectPriority = 0;

static const char* gPackageName = "AudioEffectTest";

bool doesDeviceSupportLowLatencyMode(std::vector<struct audio_port_v7>& ports) {
    for (const auto& port : ports) {
        if (port.role == AUDIO_PORT_ROLE_SOURCE && port.type == AUDIO_PORT_TYPE_MIX) {
            if ((port.active_config.flags.output & AUDIO_OUTPUT_FLAG_FAST) != 0) {
                return true;
            }
        }
    }
    return false;
}

sp<AudioEffect> createEffect(const effect_uuid_t* type, const effect_uuid_t* uuid = nullptr,
                             int priority = 0, audio_session_t sessionId = AUDIO_SESSION_OUTPUT_MIX,
                             const wp<AudioEffectCallback>& callback = nullptr) {
    std::string packageName{gPackageName};
    AttributionSourceState attributionSource;
    attributionSource.packageName = packageName;
    attributionSource.uid = VALUE_OR_FATAL(legacy2aidl_uid_t_int32_t(getuid()));
    attributionSource.pid = VALUE_OR_FATAL(legacy2aidl_pid_t_int32_t(getpid()));
    attributionSource.token = sp<BBinder>::make();
    sp<AudioEffect> effect = new AudioEffect(attributionSource);
    effect->set(type, uuid, priority, callback, sessionId, AUDIO_IO_HANDLE_NONE, {}, false,
                (callback != nullptr));
    return effect;
}

status_t isEffectExistsOnAudioSession(const effect_uuid_t* type, const effect_uuid_t* uuid,
                                      int priority, audio_session_t sessionId) {
    sp<AudioEffect> effect = createEffect(type, uuid, priority, sessionId);
    return effect->initCheck();
}

bool isEffectDefaultOnRecord(const effect_uuid_t* type, const effect_uuid_t* uuid,
                             const sp<AudioRecord>& audioRecord) {
    effect_descriptor_t descriptors[AudioEffect::kMaxPreProcessing];
    uint32_t numEffects = AudioEffect::kMaxPreProcessing;
    status_t ret = AudioEffect::queryDefaultPreProcessing(audioRecord->getSessionId(), descriptors,
                                                          &numEffects);
    if (ret != OK) {
        return false;
    }
    for (int i = 0; i < numEffects; i++) {
        if ((memcmp(&descriptors[i].type, type, sizeof(effect_uuid_t)) == 0) &&
            (memcmp(&descriptors[i].uuid, uuid, sizeof(effect_uuid_t)) == 0)) {
            return true;
        }
    }
    return false;
}

void listEffectsAvailable(std::vector<effect_descriptor_t>& descriptors) {
    uint32_t numEffects = 0;
    ASSERT_EQ(NO_ERROR, AudioEffect::queryNumberEffects(&numEffects));
    for (auto i = 0; i < numEffects; i++) {
        effect_descriptor_t des;
        ASSERT_EQ(NO_ERROR, AudioEffect::queryEffect(i, &des));
        descriptors.push_back(des);
    }
}

bool isPreprocessing(effect_descriptor_t& descriptor) {
    return ((descriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_PRE_PROC);
}

bool isInsert(effect_descriptor_t& descriptor) {
    return ((descriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_INSERT);
}

bool isAux(effect_descriptor_t& descriptor) {
    return ((descriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_AUXILIARY);
}

bool isPostproc(effect_descriptor_t& descriptor) {
    return ((descriptor.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_POST_PROC);
}

bool isFastCompatible(effect_descriptor_t& descriptor) {
    return !(((descriptor.flags & EFFECT_FLAG_HW_ACC_MASK) == 0) &&
             ((descriptor.flags & EFFECT_FLAG_NO_PROCESS) == 0));
}

bool isSpatializer(effect_descriptor_t& descriptor) {
    return (memcmp(&descriptor.type, FX_IID_SPATIALIZER, sizeof(effect_uuid_t)) == 0);
}

bool isHapticGenerator(effect_descriptor_t& descriptor) {
    return (memcmp(&descriptor.type, FX_IID_HAPTICGENERATOR, sizeof(effect_uuid_t)) == 0);
}

std::tuple<std::string, std::string> typeAndUuidToString(const effect_descriptor_t& desc) {
    char type[512];
    AudioEffect::guidToString(&desc.type, type, sizeof(type));
    char uuid[512];
    AudioEffect::guidToString(&desc.uuid, uuid, sizeof(uuid));
    return std::make_tuple(type, uuid);
}

// UNIT TESTS
TEST(AudioEffectTest, getEffectDescriptor) {
    effect_uuid_t randomType = {
            0x81781c08, 0x93dd, 0x11ec, 0xb909, {0x02, 0x42, 0xac, 0x12, 0x00, 0x02}};
    effect_uuid_t randomUuid = {
            0x653730e1, 0x1be1, 0x438e, 0xa35a, {0xfc, 0x9b, 0xa1, 0x2a, 0x5e, 0xc9}};
    effect_uuid_t empty = EFFECT_UUID_INITIALIZER;

    effect_descriptor_t descriptor;
    EXPECT_EQ(NAME_NOT_FOUND, AudioEffect::getEffectDescriptor(&randomUuid, &randomType,
                                                               EFFECT_FLAG_TYPE_MASK, &descriptor));

    std::vector<effect_descriptor_t> descriptors;
    ASSERT_NO_FATAL_FAILURE(listEffectsAvailable(descriptors));

    for (auto i = 0; i < descriptors.size(); i++) {
        EXPECT_EQ(NO_ERROR,
                  AudioEffect::getEffectDescriptor(&descriptors[i].uuid, &descriptors[i].type,
                                                   EFFECT_FLAG_TYPE_MASK, &descriptor));
        EXPECT_EQ(0, memcmp(&descriptor, &descriptors[i], sizeof(effect_uuid_t)));
    }
    // negative tests
    if (descriptors.size() > 0) {
        EXPECT_EQ(BAD_VALUE,
                  AudioEffect::getEffectDescriptor(&descriptors[0].uuid, &descriptors[0].type,
                                                   EFFECT_FLAG_TYPE_MASK, nullptr));
    }
    EXPECT_EQ(BAD_VALUE, AudioEffect::getEffectDescriptor(nullptr, nullptr,
                                                          EFFECT_FLAG_TYPE_PRE_PROC, &descriptor));
    EXPECT_EQ(BAD_VALUE, AudioEffect::getEffectDescriptor(&empty, &randomType,
                                                          EFFECT_FLAG_TYPE_MASK, nullptr));
    EXPECT_EQ(BAD_VALUE, AudioEffect::getEffectDescriptor(nullptr, &randomType,
                                                          EFFECT_FLAG_TYPE_POST_PROC, &descriptor));
    EXPECT_EQ(BAD_VALUE, AudioEffect::getEffectDescriptor(&randomUuid, nullptr,
                                                          EFFECT_FLAG_TYPE_INSERT, &descriptor));
}

TEST(AudioEffectTest, DISABLED_GetSetParameterForEffect) {
    sp<AudioEffect> visualizer = createEffect(SL_IID_VISUALIZATION);
    status_t status = visualizer->initCheck();
    ASSERT_TRUE(status == NO_ERROR || status == ALREADY_EXISTS) << "Init check error";
    ASSERT_EQ(NO_ERROR, visualizer->setEnabled(true)) << "visualizer not enabled";

    uint32_t buf32[3][sizeof(effect_param_t) / sizeof(uint32_t) + 2];
    effect_param_t* vis_none = (effect_param_t*)(buf32[0]);
    effect_param_t* vis_rms = (effect_param_t*)(buf32[1]);
    effect_param_t* vis_tmp = (effect_param_t*)(buf32[2]);

    // Visualizer::setMeasurementMode()
    vis_none->psize = sizeof(uint32_t);
    vis_none->vsize = sizeof(uint32_t);
    *(int32_t*)vis_none->data = VISUALIZER_PARAM_MEASUREMENT_MODE;
    *((int32_t*)vis_none->data + 1) = MEASUREMENT_MODE_NONE;
    EXPECT_EQ(NO_ERROR, visualizer->setParameter(vis_none))
            << "setMeasurementMode doesn't report success";

    // Visualizer::getMeasurementMode()
    vis_tmp->psize = sizeof(uint32_t);
    vis_tmp->vsize = sizeof(uint32_t);
    *(int32_t*)vis_tmp->data = VISUALIZER_PARAM_MEASUREMENT_MODE;
    *((int32_t*)vis_tmp->data + 1) = 23;
    EXPECT_EQ(NO_ERROR, visualizer->getParameter(vis_tmp))
            << "getMeasurementMode doesn't report success";
    EXPECT_EQ(*((int32_t*)vis_tmp->data + 1), *((int32_t*)vis_none->data + 1))
            << "target mode does not match set mode";

    // Visualizer::setMeasurementModeDeferred()
    vis_rms->psize = sizeof(uint32_t);
    vis_rms->vsize = sizeof(uint32_t);
    *(int32_t*)vis_rms->data = VISUALIZER_PARAM_MEASUREMENT_MODE;
    *((int32_t*)vis_rms->data + 1) = MEASUREMENT_MODE_PEAK_RMS;
    EXPECT_EQ(NO_ERROR, visualizer->setParameterDeferred(vis_rms))
            << "setMeasurementModeDeferred doesn't report success";

    *((int32_t*)vis_tmp->data + 1) = 23;
    EXPECT_EQ(NO_ERROR, visualizer->getParameter(vis_tmp))
            << "getMeasurementMode doesn't report success";
    EXPECT_EQ(*((int32_t*)vis_tmp->data + 1), *((int32_t*)vis_none->data + 1))
            << "target mode does not match set mode";

    // setParameterCommit
    EXPECT_EQ(NO_ERROR, visualizer->setParameterCommit())
            << "setMeasurementModeCommit does not report success";

    // validate Params
    *((int32_t*)vis_tmp->data + 1) = 23;
    EXPECT_EQ(NO_ERROR, visualizer->getParameter(vis_tmp))
            << "getMeasurementMode doesn't report success";
    EXPECT_EQ(*((int32_t*)vis_tmp->data + 1), *((int32_t*)vis_rms->data + 1))
            << "target mode does not match set mode";
}

TEST(AudioEffectTest, ManageSourceDefaultEffects) {
    int32_t selectedEffect = -1;

    const uint32_t sampleRate = 44100;
    const audio_format_t format = AUDIO_FORMAT_PCM_16_BIT;
    const audio_channel_mask_t channelMask = AUDIO_CHANNEL_IN_STEREO;
    sp<AudioCapture> capture = nullptr;

    std::vector<effect_descriptor_t> descriptors;
    ASSERT_NO_FATAL_FAILURE(listEffectsAvailable(descriptors));
    for (auto i = 0; i < descriptors.size(); i++) {
        if (isPreprocessing(descriptors[i])) {
            capture = new AudioCapture(AUDIO_SOURCE_MIC, sampleRate, format, channelMask);
            ASSERT_NE(capture, nullptr) << "Unable to create Record Application";
            EXPECT_EQ(NO_ERROR, capture->create());
            EXPECT_EQ(NO_ERROR, capture->start());
            if (!isEffectDefaultOnRecord(&descriptors[i].type, &descriptors[i].uuid,
                                         capture->getAudioRecordHandle())) {
                selectedEffect = i;
                EXPECT_EQ(OK, capture->stop());
                break;
            }
            EXPECT_EQ(OK, capture->stop());
        }
    }
    if (selectedEffect == -1) GTEST_SKIP() << " expected at least one preprocessing effect";

    effect_uuid_t* selectedEffectType = &descriptors[selectedEffect].type;
    effect_uuid_t* selectedEffectUuid = &descriptors[selectedEffect].uuid;
    auto [type, uuid] = typeAndUuidToString(descriptors[selectedEffect]);
    capture = new AudioCapture(AUDIO_SOURCE_MIC, sampleRate, format, channelMask);
    ASSERT_NE(capture, nullptr) << "Unable to create Record Application";
    EXPECT_EQ(NO_ERROR, capture->create());
    EXPECT_EQ(NO_ERROR, capture->start());
    EXPECT_FALSE(isEffectDefaultOnRecord(selectedEffectType, selectedEffectUuid,
                                         capture->getAudioRecordHandle()))
            << "Effect should not have been default on record. " << type;
    EXPECT_EQ(NO_ERROR,
              isEffectExistsOnAudioSession(selectedEffectType, selectedEffectUuid,
                                           kDefaultInputEffectPriority - 1,
                                           capture->getAudioRecordHandle()->getSessionId()))
            << "Effect should not have been added. " << type;
    EXPECT_EQ(OK, capture->audioProcess());
    EXPECT_EQ(OK, capture->stop());

    String16 name{gPackageName};
    audio_unique_id_t effectId;
    status_t status = AudioEffect::addSourceDefaultEffect(type.c_str(), name, uuid.c_str(),
                                                          kDefaultInputEffectPriority,
                                                          AUDIO_SOURCE_MIC, &effectId);
    EXPECT_EQ(NO_ERROR, status) << "Adding default effect failed: " << type;

    capture = new AudioCapture(AUDIO_SOURCE_MIC, sampleRate, format, channelMask);
    ASSERT_NE(capture, nullptr) << "Unable to create Record Application";
    EXPECT_EQ(NO_ERROR, capture->create());
    EXPECT_EQ(NO_ERROR, capture->start());
    EXPECT_TRUE(isEffectDefaultOnRecord(selectedEffectType, selectedEffectUuid,
                                        capture->getAudioRecordHandle()))
            << "Effect should have been default on record. " << type;
    EXPECT_EQ(ALREADY_EXISTS,
              isEffectExistsOnAudioSession(selectedEffectType, selectedEffectUuid,
                                           kDefaultInputEffectPriority - 1,
                                           capture->getAudioRecordHandle()->getSessionId()))
            << "Effect should have been added. " << type;
    EXPECT_EQ(OK, capture->audioProcess());
    EXPECT_EQ(OK, capture->stop());

    status = AudioEffect::removeSourceDefaultEffect(effectId);
    EXPECT_EQ(NO_ERROR, status);
    capture = new AudioCapture(AUDIO_SOURCE_MIC, sampleRate, format, channelMask);
    ASSERT_NE(capture, nullptr) << "Unable to create Record Application";
    EXPECT_EQ(NO_ERROR, capture->create());
    EXPECT_EQ(NO_ERROR, capture->start());
    EXPECT_FALSE(isEffectDefaultOnRecord(selectedEffectType, selectedEffectUuid,
                                         capture->getAudioRecordHandle()))
            << "Effect should not have been default on record. " << type;
    EXPECT_EQ(NO_ERROR,
              isEffectExistsOnAudioSession(selectedEffectType, selectedEffectUuid,
                                           kDefaultInputEffectPriority - 1,
                                           capture->getAudioRecordHandle()->getSessionId()))
            << "Effect should not have been added. " << type;
    EXPECT_EQ(OK, capture->audioProcess());
    EXPECT_EQ(OK, capture->stop());
}

TEST(AudioEffectTest, AuxEffectSanityTest) {
    int32_t selectedEffect = -1;
    std::vector<effect_descriptor_t> descriptors;
    ASSERT_NO_FATAL_FAILURE(listEffectsAvailable(descriptors));
    for (auto i = 0; i < descriptors.size(); i++) {
        if (isAux(descriptors[i])) {
            selectedEffect = i;
            break;
        }
    }
    if (selectedEffect == -1) GTEST_SKIP() << "expected at least one aux effect";
    effect_uuid_t* selectedEffectType = &descriptors[selectedEffect].type;
    effect_uuid_t* selectedEffectUuid = &descriptors[selectedEffect].uuid;
    auto [type, uuid] = typeAndUuidToString(descriptors[selectedEffect]);
    String16 name{gPackageName};
    audio_session_t sessionId =
            (audio_session_t)AudioSystem::newAudioUniqueId(AUDIO_UNIQUE_ID_USE_SESSION);
    sp<AudioEffect> audioEffect = createEffect(selectedEffectType, selectedEffectUuid,
                                               kDefaultInputEffectPriority, sessionId);
    EXPECT_EQ(NO_INIT, audioEffect->initCheck())
            << "error, creating auxiliary effect (" << type << ") on session id " << (int)sessionId
            << " successful ";
    audio_unique_id_t id;
    status_t status = AudioEffect::addStreamDefaultEffect(
            type.c_str(), name, uuid.c_str(), kDefaultOutputEffectPriority, AUDIO_USAGE_MEDIA, &id);
    if (status == NO_ERROR) {
        EXPECT_EQ(NO_ERROR, AudioEffect::removeStreamDefaultEffect(id));
        EXPECT_NE(NO_ERROR, status) << "error, adding auxiliary effect (" << type
                                    << ") as stream default effect is successful";
    }
}

class AudioPlaybackEffectTest : public ::testing::TestWithParam<bool> {
  public:
    AudioPlaybackEffectTest() : mSelectFastMode(GetParam()){};

    const bool mSelectFastMode;

    bool mIsFastCompatibleEffect;
    effect_uuid_t mType;
    effect_uuid_t mUuid;
    std::string mTypeStr;
    std::string mUuidStr;

    void SetUp() override {
        if (mSelectFastMode) {
            std::vector<struct audio_port_v7> ports;
            ASSERT_EQ(OK, listAudioPorts(ports));
            if (!doesDeviceSupportLowLatencyMode(ports)) {
                GTEST_SKIP() << "device does not support low latency mode";
            }
        }

        int32_t selectedEffect = -1;
        std::vector<effect_descriptor_t> descriptors;
        ASSERT_NO_FATAL_FAILURE(listEffectsAvailable(descriptors));
        for (auto i = 0; i < descriptors.size(); i++) {
            if (isSpatializer(descriptors[i])) continue;
            if (isHapticGenerator(descriptors[i]) && !AudioSystem::isHapticPlaybackSupported())
                continue;
            if (!isInsert(descriptors[i])) continue;
            selectedEffect = i;
            mIsFastCompatibleEffect = isFastCompatible(descriptors[i]);
            // in fast mode, pick fast compatible effect if available
            if (mSelectFastMode == mIsFastCompatibleEffect) break;
        }
        if (selectedEffect == -1) {
            GTEST_SKIP() << "expected at least one valid effect";
        }

        mType = descriptors[selectedEffect].type;
        mUuid = descriptors[selectedEffect].uuid;
        std::tie(mTypeStr, mUuidStr) = typeAndUuidToString(descriptors[selectedEffect]);
    }
};

TEST_P(AudioPlaybackEffectTest, StreamDefaultEffectTest) {
    SCOPED_TRACE(testing::Message()
                 << "\n selected effect type is :: " << mTypeStr
                 << "\n selected effect uuid is :: " << mUuidStr
                 << "\n audiotrack output flag : " << (mSelectFastMode ? "fast" : "default")
                 << "\n audio effect is fast compatible : "
                 << (mIsFastCompatibleEffect ? "yes" : "no"));

    bool compatCheck = !mSelectFastMode || (mSelectFastMode && mIsFastCompatibleEffect);

    // create track
    audio_attributes_t attributes;
    attributes.usage = AUDIO_USAGE_MEDIA;
    attributes.content_type = AUDIO_CONTENT_TYPE_MUSIC;
    auto playback = sp<AudioPlayback>::make(
            0 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
            mSelectFastMode ? AUDIO_OUTPUT_FLAG_FAST : AUDIO_OUTPUT_FLAG_NONE, AUDIO_SESSION_NONE,
            AudioTrack::TRANSFER_SHARED, &attributes);
    ASSERT_NE(nullptr, playback);
    ASSERT_EQ(NO_ERROR, playback->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"));
    EXPECT_EQ(NO_ERROR, playback->create());
    EXPECT_EQ(NO_ERROR, playback->start());
    EXPECT_EQ(compatCheck ? NO_ERROR : NO_INIT,
              isEffectExistsOnAudioSession(&mType, &mUuid, kDefaultOutputEffectPriority - 1,
                                           playback->getAudioTrackHandle()->getSessionId()))
            << "Effect should not have been added. " << mTypeStr;
    EXPECT_EQ(NO_ERROR, playback->waitForConsumption());
    playback->stop();
    playback.clear();

    String16 name{gPackageName};
    audio_unique_id_t id;
    status_t status = AudioEffect::addStreamDefaultEffect(mTypeStr.c_str(), name, mUuidStr.c_str(),
                                                          kDefaultOutputEffectPriority,
                                                          AUDIO_USAGE_MEDIA, &id);
    EXPECT_EQ(NO_ERROR, status) << "Adding default effect failed: " << mTypeStr;

    playback = sp<AudioPlayback>::make(
            0 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
            mSelectFastMode ? AUDIO_OUTPUT_FLAG_FAST : AUDIO_OUTPUT_FLAG_NONE, AUDIO_SESSION_NONE,
            AudioTrack::TRANSFER_SHARED, &attributes);
    ASSERT_NE(nullptr, playback);
    ASSERT_EQ(NO_ERROR, playback->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"));
    EXPECT_EQ(NO_ERROR, playback->create());
    EXPECT_EQ(NO_ERROR, playback->start());
    // If effect chosen is not compatible with the session, then effect won't be applied
    EXPECT_EQ(compatCheck ? ALREADY_EXISTS : NO_INIT,
              isEffectExistsOnAudioSession(&mType, &mUuid, kDefaultOutputEffectPriority - 1,
                                           playback->getAudioTrackHandle()->getSessionId()))
            << "Effect should have been added. " << mTypeStr;
    EXPECT_EQ(NO_ERROR, playback->waitForConsumption());
    if (mSelectFastMode) {
        EXPECT_EQ(AUDIO_OUTPUT_FLAG_FAST,
                  playback->getAudioTrackHandle()->getFlags() & AUDIO_OUTPUT_FLAG_FAST);
    }
    playback->stop();
    playback.clear();

    status = AudioEffect::removeStreamDefaultEffect(id);
    EXPECT_EQ(NO_ERROR, status);
    playback = sp<AudioPlayback>::make(
            0 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
            mSelectFastMode ? AUDIO_OUTPUT_FLAG_FAST : AUDIO_OUTPUT_FLAG_NONE, AUDIO_SESSION_NONE,
            AudioTrack::TRANSFER_SHARED, &attributes);
    ASSERT_NE(nullptr, playback);
    ASSERT_EQ(NO_ERROR, playback->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"));
    EXPECT_EQ(NO_ERROR, playback->create());
    EXPECT_EQ(NO_ERROR, playback->start());
    EXPECT_EQ(compatCheck ? NO_ERROR : NO_INIT,
              isEffectExistsOnAudioSession(&mType, &mUuid, kDefaultOutputEffectPriority - 1,
                                           playback->getAudioTrackHandle()->getSessionId()))
            << "Effect should not have been added. " << mTypeStr;
    EXPECT_EQ(NO_ERROR, playback->waitForConsumption());
    playback->stop();
    playback.clear();
}

TEST_P(AudioPlaybackEffectTest, CheckOutputFlagCompatibility) {
    SCOPED_TRACE(testing::Message()
                 << "\n selected effect type is :: " << mTypeStr
                 << "\n selected effect uuid is :: " << mUuidStr
                 << "\n audiotrack output flag : " << (mSelectFastMode ? "fast" : "default")
                 << "\n audio effect is fast compatible : "
                 << (mIsFastCompatibleEffect ? "yes" : "no"));

    audio_attributes_t attributes;
    attributes.usage = AUDIO_USAGE_MEDIA;
    attributes.content_type = AUDIO_CONTENT_TYPE_MUSIC;
    audio_session_t sessionId =
            (audio_session_t)AudioSystem::newAudioUniqueId(AUDIO_UNIQUE_ID_USE_SESSION);
    sp<AudioEffectCallback> cb = sp<AudioEffectCallback>::make();
    sp<AudioEffect> audioEffect =
            createEffect(&mType, &mUuid, kDefaultOutputEffectPriority, sessionId, cb);
    ASSERT_EQ(OK, audioEffect->initCheck());
    ASSERT_EQ(NO_ERROR, audioEffect->setEnabled(true));
    auto playback = sp<AudioPlayback>::make(
            0 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_MONO,
            mSelectFastMode ? AUDIO_OUTPUT_FLAG_FAST : AUDIO_OUTPUT_FLAG_NONE, sessionId,
            AudioTrack::TRANSFER_SHARED, &attributes);
    ASSERT_NE(nullptr, playback);
    ASSERT_EQ(NO_ERROR, playback->loadResource("/data/local/tmp/bbb_1ch_8kHz_s16le.raw"));
    EXPECT_EQ(NO_ERROR, playback->create());
    EXPECT_EQ(NO_ERROR, playback->start());

    EXPECT_EQ(ALREADY_EXISTS, isEffectExistsOnAudioSession(
                                      &mType, &mUuid, kDefaultOutputEffectPriority - 1, sessionId))
            << "Effect should have been added. " << mTypeStr;
    if (mSelectFastMode) {
        EXPECT_EQ(mIsFastCompatibleEffect ? AUDIO_OUTPUT_FLAG_FAST : 0,
                  playback->getAudioTrackHandle()->getFlags() & AUDIO_OUTPUT_FLAG_FAST);
    }
    EXPECT_EQ(NO_ERROR, playback->waitForConsumption());
    EXPECT_EQ(NO_ERROR, playback->getAudioTrackHandle()->attachAuxEffect(0));
    playback->stop();
    playback.clear();
    EXPECT_TRUE(cb->receivedFramesProcessed)
            << "AudioEffect frames processed callback not received";
}

INSTANTIATE_TEST_SUITE_P(EffectParameterizedTests, AudioPlaybackEffectTest, ::testing::Bool());

TEST(AudioEffectTest, TestHapticEffect) {
    if (!AudioSystem::isHapticPlaybackSupported())
        GTEST_SKIP() << "Haptic playback is not supported";
    int32_t selectedEffect = -1;
    std::vector<effect_descriptor_t> descriptors;
    ASSERT_NO_FATAL_FAILURE(listEffectsAvailable(descriptors));
    for (auto i = 0; i < descriptors.size(); i++) {
        if (!isHapticGenerator(descriptors[i])) continue;
        selectedEffect = i;
        break;
    }
    if (selectedEffect == -1) GTEST_SKIP() << "expected at least one valid effect";

    effect_uuid_t* selectedEffectType = &descriptors[selectedEffect].type;
    effect_uuid_t* selectedEffectUuid = &descriptors[selectedEffect].uuid;
    auto [type, uuid] = typeAndUuidToString(descriptors[selectedEffect]);

    SCOPED_TRACE(testing::Message() << "\n selected effect type is :: " << type
                                    << "\n selected effect uuid is :: " << uuid);

    audio_attributes_t attributes;
    attributes.usage = AUDIO_USAGE_MEDIA;
    attributes.content_type = AUDIO_CONTENT_TYPE_MUSIC;
    audio_session_t sessionId =
            (audio_session_t)AudioSystem::newAudioUniqueId(AUDIO_UNIQUE_ID_USE_SESSION);
    sp<AudioEffectCallback> cb = sp<AudioEffectCallback>::make();
    sp<AudioEffect> audioEffect = createEffect(selectedEffectType, selectedEffectUuid,
                                               kDefaultOutputEffectPriority, sessionId, cb);
    ASSERT_EQ(OK, audioEffect->initCheck());
    ASSERT_EQ(NO_ERROR, audioEffect->setEnabled(true));
    auto playback = sp<AudioPlayback>::make(0 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT,
                                            AUDIO_CHANNEL_OUT_STEREO, AUDIO_OUTPUT_FLAG_NONE,
                                            sessionId, AudioTrack::TRANSFER_SHARED, &attributes);
    ASSERT_NE(nullptr, playback);
    ASSERT_EQ(NO_ERROR, playback->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"));
    EXPECT_EQ(NO_ERROR, playback->create());
    EXPECT_EQ(NO_ERROR, playback->start());
    EXPECT_TRUE(isEffectExistsOnAudioSession(selectedEffectType, selectedEffectUuid,
                                             kDefaultOutputEffectPriority - 1, sessionId))
            << "Effect should have been added. " << type;
    EXPECT_EQ(NO_ERROR, playback->waitForConsumption());
    playback->stop();
    playback.clear();
    EXPECT_TRUE(cb->receivedFramesProcessed)
            << "AudioEffect frames processed callback not received";
}
