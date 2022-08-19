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
#include <system/audio_effects/effect_visualizer.h>

#include "audio_test_utils.h"

using namespace android;

static constexpr int kDefaultInputEffectPriority = -1;
static constexpr int kDefaultOutputEffectPriority = 0;

static const char* gPackageName = "AudioEffectTest";

bool isEffectExistsOnAudioSession(const effect_uuid_t* type, int priority,
                                  audio_session_t sessionId) {
    std::string packageName{gPackageName};
    AttributionSourceState attributionSource;
    attributionSource.packageName = packageName;
    attributionSource.uid = VALUE_OR_FATAL(legacy2aidl_uid_t_int32_t(getuid()));
    attributionSource.pid = VALUE_OR_FATAL(legacy2aidl_pid_t_int32_t(getpid()));
    attributionSource.token = sp<BBinder>::make();
    sp<AudioEffect> effect = new AudioEffect(attributionSource);
    effect->set(type, nullptr /* uid */, priority, nullptr /* callback */, sessionId);
    return effect->initCheck() == ALREADY_EXISTS;
}

bool isEffectDefaultOnRecord(const effect_uuid_t* type, const sp<AudioRecord>& audioRecord) {
    effect_descriptor_t descriptors[AudioEffect::kMaxPreProcessing];
    uint32_t numEffects = AudioEffect::kMaxPreProcessing;
    status_t ret = AudioEffect::queryDefaultPreProcessing(audioRecord->getSessionId(), descriptors,
                                                          &numEffects);
    if (ret != OK) {
        return false;
    }
    for (int i = 0; i < numEffects; i++) {
        if (memcmp(&descriptors[i].type, type, sizeof(effect_uuid_t)) == 0) {
            return true;
        }
    }
    return false;
}

void listEffectsAvailable(std::vector<effect_descriptor_t>& descriptors) {
    uint32_t numEffects = 0;
    if (NO_ERROR == AudioEffect::queryNumberEffects(&numEffects)) {
        for (auto i = 0; i < numEffects; i++) {
            effect_descriptor_t des;
            if (NO_ERROR == AudioEffect::queryEffect(i, &des)) descriptors.push_back(des);
        }
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

bool isFastCompatible(effect_descriptor_t& descriptor) {
    return !(((descriptor.flags & EFFECT_FLAG_HW_ACC_MASK) == 0) &&
             ((descriptor.flags & EFFECT_FLAG_NO_PROCESS) == 0));
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
    listEffectsAvailable(descriptors);

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
    std::string packageName{gPackageName};
    AttributionSourceState attributionSource;
    attributionSource.packageName = packageName;
    attributionSource.uid = VALUE_OR_FATAL(legacy2aidl_uid_t_int32_t(getuid()));
    attributionSource.pid = VALUE_OR_FATAL(legacy2aidl_pid_t_int32_t(getpid()));
    attributionSource.token = sp<BBinder>::make();
    sp<AudioEffect> visualizer = new AudioEffect(attributionSource);
    ASSERT_NE(visualizer, nullptr) << "effect not created";
    visualizer->set(SL_IID_VISUALIZATION);
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
    listEffectsAvailable(descriptors);
    for (auto i = 0; i < descriptors.size(); i++) {
        if (isPreprocessing(descriptors[i])) {
            capture = new AudioCapture(AUDIO_SOURCE_MIC, sampleRate, format, channelMask);
            ASSERT_NE(capture, nullptr) << "Unable to create Record Application";
            EXPECT_EQ(NO_ERROR, capture->create());
            EXPECT_EQ(NO_ERROR, capture->start());
            if (!isEffectDefaultOnRecord(&descriptors[i].type, capture->getAudioRecordHandle())) {
                selectedEffect = i;
                break;
            }
        }
    }
    if (selectedEffect == -1) GTEST_SKIP() << " expected at least one preprocessing effect";
    effect_uuid_t selectedEffectType = descriptors[selectedEffect].type;

    char type[512];
    AudioEffect::guidToString(&selectedEffectType, type, sizeof(type));

    capture = new AudioCapture(AUDIO_SOURCE_MIC, sampleRate, format, channelMask);
    ASSERT_NE(capture, nullptr) << "Unable to create Record Application";
    EXPECT_EQ(NO_ERROR, capture->create());
    EXPECT_EQ(NO_ERROR, capture->start());
    EXPECT_FALSE(isEffectDefaultOnRecord(&selectedEffectType, capture->getAudioRecordHandle()))
            << "Effect should not have been default on record. " << type;
    EXPECT_FALSE(isEffectExistsOnAudioSession(&selectedEffectType, kDefaultInputEffectPriority - 1,
                                              capture->getAudioRecordHandle()->getSessionId()))
            << "Effect should not have been added. " << type;
    EXPECT_EQ(OK, capture->audioProcess());
    EXPECT_EQ(OK, capture->stop());

    String16 name{gPackageName};
    audio_unique_id_t effectId;
    status_t status = AudioEffect::addSourceDefaultEffect(
            type, name, nullptr, kDefaultInputEffectPriority, AUDIO_SOURCE_MIC, &effectId);
    EXPECT_EQ(NO_ERROR, status) << "Adding default effect failed: " << type;

    capture = new AudioCapture(AUDIO_SOURCE_MIC, sampleRate, format, channelMask);
    ASSERT_NE(capture, nullptr) << "Unable to create Record Application";
    EXPECT_EQ(NO_ERROR, capture->create());
    EXPECT_EQ(NO_ERROR, capture->start());
    EXPECT_TRUE(isEffectDefaultOnRecord(&selectedEffectType, capture->getAudioRecordHandle()))
            << "Effect should have been default on record. " << type;
    EXPECT_TRUE(isEffectExistsOnAudioSession(&selectedEffectType, kDefaultInputEffectPriority - 1,
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
    EXPECT_FALSE(isEffectDefaultOnRecord(&selectedEffectType, capture->getAudioRecordHandle()))
            << "Effect should not have been default on record. " << type;
    EXPECT_FALSE(isEffectExistsOnAudioSession(&selectedEffectType, kDefaultInputEffectPriority - 1,
                                              capture->getAudioRecordHandle()->getSessionId()))
            << "Effect should not have been added. " << type;
    EXPECT_EQ(OK, capture->audioProcess());
    EXPECT_EQ(OK, capture->stop());
}

TEST(AudioEffectTest, ManageStreamDefaultEffects) {
    int32_t selectedEffect = -1;

    std::vector<effect_descriptor_t> descriptors;
    listEffectsAvailable(descriptors);
    for (auto i = 0; i < descriptors.size(); i++) {
        if (isAux(descriptors[i])) {
            selectedEffect = i;
            break;
        }
    }
    if (selectedEffect == -1) GTEST_SKIP() << " expected at least one Aux effect";
    effect_uuid_t* selectedEffectType = &descriptors[selectedEffect].type;

    char type[512];
    AudioEffect::guidToString(selectedEffectType, type, sizeof(type));
    // create track
    audio_attributes_t attributes;
    attributes.usage = AUDIO_USAGE_MEDIA;
    attributes.content_type = AUDIO_CONTENT_TYPE_MUSIC;
    auto playback = sp<AudioPlayback>::make(
            44100 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
            AUDIO_OUTPUT_FLAG_NONE, AUDIO_SESSION_NONE, AudioTrack::TRANSFER_SHARED, &attributes);
    ASSERT_NE(nullptr, playback);
    ASSERT_EQ(NO_ERROR, playback->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"));
    EXPECT_EQ(NO_ERROR, playback->create());
    EXPECT_EQ(NO_ERROR, playback->start());
    EXPECT_FALSE(isEffectExistsOnAudioSession(selectedEffectType, kDefaultOutputEffectPriority - 1,
                                              playback->getAudioTrackHandle()->getSessionId()))
            << "Effect should not have been added. " << type;
    EXPECT_EQ(NO_ERROR, playback->waitForConsumption());
    playback->stop();
    playback.clear();

    String16 name{gPackageName};
    audio_unique_id_t id;
    status_t status = AudioEffect::addStreamDefaultEffect(
            type, name, nullptr, kDefaultOutputEffectPriority, AUDIO_USAGE_MEDIA, &id);
    EXPECT_EQ(NO_ERROR, status) << "Adding default effect failed: " << type;

    playback = sp<AudioPlayback>::make(
            44100 /* sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
            AUDIO_OUTPUT_FLAG_NONE, AUDIO_SESSION_NONE, AudioTrack::TRANSFER_SHARED, &attributes);
    ASSERT_NE(nullptr, playback);
    ASSERT_EQ(NO_ERROR, playback->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"));
    EXPECT_EQ(NO_ERROR, playback->create());
    float level = 0.2f, levelGot;
    playback->getAudioTrackHandle()->setAuxEffectSendLevel(level);
    EXPECT_EQ(NO_ERROR, playback->start());
    EXPECT_TRUE(isEffectExistsOnAudioSession(selectedEffectType, kDefaultOutputEffectPriority - 1,
                                             playback->getAudioTrackHandle()->getSessionId()))
            << "Effect should have been added. " << type;
    EXPECT_EQ(NO_ERROR, playback->waitForConsumption());
    playback->getAudioTrackHandle()->getAuxEffectSendLevel(&levelGot);
    EXPECT_EQ(level, levelGot);
    playback->stop();
    playback.clear();

    status = AudioEffect::removeStreamDefaultEffect(id);
    EXPECT_EQ(NO_ERROR, status);
    playback = sp<AudioPlayback>::make(
            44100 /*sampleRate */, AUDIO_FORMAT_PCM_16_BIT, AUDIO_CHANNEL_OUT_STEREO,
            AUDIO_OUTPUT_FLAG_NONE, AUDIO_SESSION_NONE, AudioTrack::TRANSFER_SHARED, &attributes);
    ASSERT_NE(nullptr, playback);
    ASSERT_EQ(NO_ERROR, playback->loadResource("/data/local/tmp/bbb_2ch_24kHz_s16le.raw"));
    EXPECT_EQ(NO_ERROR, playback->create());
    EXPECT_EQ(NO_ERROR, playback->start());
    EXPECT_FALSE(isEffectExistsOnAudioSession(selectedEffectType, kDefaultOutputEffectPriority - 1,
                                              playback->getAudioTrackHandle()->getSessionId()))
            << "Effect should not have been added. " << type;
    EXPECT_EQ(NO_ERROR, playback->waitForConsumption());
    playback->stop();
    playback.clear();
}
