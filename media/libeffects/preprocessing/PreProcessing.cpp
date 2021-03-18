/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include <stdlib.h>
#include <string.h>
#define LOG_TAG "PreProcessing"
//#define LOG_NDEBUG 0
#include <audio_effects/effect_aec.h>
#include <audio_effects/effect_agc.h>
#include <hardware/audio_effect.h>
#include <utils/Log.h>
#include <utils/Timers.h>
#include <audio_effects/effect_agc2.h>
#include <audio_effects/effect_ns.h>
#include <audio_processing.h>
#include <module_common_types.h>

// undefine to perform multi channels API functional tests
//#define DUAL_MIC_TEST

//------------------------------------------------------------------------------
// local definitions
//------------------------------------------------------------------------------

// maximum number of sessions
#define PREPROC_NUM_SESSIONS 8

// types of pre processing modules
enum preproc_id {
    PREPROC_AGC,  // Automatic Gain Control
    PREPROC_AGC2,  // Automatic Gain Control 2
    PREPROC_AEC,  // Acoustic Echo Canceler
    PREPROC_NS,   // Noise Suppressor
    PREPROC_NUM_EFFECTS
};

// Session state
enum preproc_session_state {
    PREPROC_SESSION_STATE_INIT,   // initialized
    PREPROC_SESSION_STATE_CONFIG  // configuration received
};

// Effect/Preprocessor state
enum preproc_effect_state {
    PREPROC_EFFECT_STATE_INIT,     // initialized
    PREPROC_EFFECT_STATE_CREATED,  // webRTC engine created
    PREPROC_EFFECT_STATE_CONFIG,   // configuration received/disabled
    PREPROC_EFFECT_STATE_ACTIVE    // active/enabled
};

// handle on webRTC engine
typedef void* preproc_fx_handle_t;

typedef struct preproc_session_s preproc_session_t;
typedef struct preproc_effect_s preproc_effect_t;
typedef struct preproc_ops_s preproc_ops_t;

// Effect operation table. Functions for all pre processors are declared in sPreProcOps[] table.
// Function pointer can be null if no action required.
struct preproc_ops_s {
    int (*create)(preproc_effect_t* fx);
    int (*init)(preproc_effect_t* fx);
    int (*reset)(preproc_effect_t* fx);
    void (*enable)(preproc_effect_t* fx);
    void (*disable)(preproc_effect_t* fx);
    int (*set_parameter)(preproc_effect_t* fx, void* param, void* value);
    int (*get_parameter)(preproc_effect_t* fx, void* param, uint32_t* size, void* value);
    int (*set_device)(preproc_effect_t* fx, uint32_t device);
};

// Effect context
struct preproc_effect_s {
    const struct effect_interface_s* itfe;
    uint32_t procId;             // type of pre processor (enum preproc_id)
    uint32_t state;              // current state (enum preproc_effect_state)
    preproc_session_t* session;  // session the effect is on
    const preproc_ops_t* ops;    // effect ops table
    preproc_fx_handle_t engine;  // handle on webRTC engine
    uint32_t type;               // subtype of effect
#ifdef DUAL_MIC_TEST
    bool aux_channels_on;       // support auxiliary channels
    size_t cur_channel_config;  // current auciliary channel configuration
#endif
};

// Session context
struct preproc_session_s {
    struct preproc_effect_s effects[PREPROC_NUM_EFFECTS];  // effects in this session
    uint32_t state;                // current state (enum preproc_session_state)
    int id;                        // audio session ID
    int io;                        // handle of input stream this session is on
    webrtc::AudioProcessing* apm;  // handle on webRTC audio processing module (APM)
    // Audio Processing module builder
    webrtc::AudioProcessingBuilder ap_builder;
    // frameCount represents the size of the buffers used for processing, and must represent 10ms.
    size_t frameCount;
    uint32_t samplingRate;     // sampling rate at effect process interface
    uint32_t inChannelCount;   // input channel count
    uint32_t outChannelCount;  // output channel count
    uint32_t createdMsk;       // bit field containing IDs of crested pre processors
    uint32_t enabledMsk;       // bit field containing IDs of enabled pre processors
    uint32_t processedMsk;     // bit field containing IDs of pre processors already
                               // processed in current round
    // audio config strucutre
    webrtc::AudioProcessing::Config config;
    webrtc::StreamConfig inputConfig;   // input stream configuration
    webrtc::StreamConfig outputConfig;  // output stream configuration
    uint32_t revChannelCount;  // number of channels on reverse stream
    uint32_t revEnabledMsk;    // bit field containing IDs of enabled pre processors
                               // with reverse channel
    uint32_t revProcessedMsk;  // bit field containing IDs of pre processors with reverse
                               // channel already processed in current round
    webrtc::StreamConfig revConfig;     // reverse stream configuration.
};

#ifdef DUAL_MIC_TEST
enum {
    PREPROC_CMD_DUAL_MIC_ENABLE = EFFECT_CMD_FIRST_PROPRIETARY,  // enable dual mic mode
    PREPROC_CMD_DUAL_MIC_PCM_DUMP_START,                         // start pcm capture
    PREPROC_CMD_DUAL_MIC_PCM_DUMP_STOP                           // stop pcm capture
};

enum {
    CHANNEL_CFG_MONO,
    CHANNEL_CFG_STEREO,
    CHANNEL_CFG_MONO_AUX,
    CHANNEL_CFG_STEREO_AUX,
    CHANNEL_CFG_CNT,
    CHANNEL_CFG_FIRST_AUX = CHANNEL_CFG_MONO_AUX,
};

const channel_config_t sDualMicConfigs[CHANNEL_CFG_CNT] = {
        {AUDIO_CHANNEL_IN_MONO, 0},
        {AUDIO_CHANNEL_IN_STEREO, 0},
        {AUDIO_CHANNEL_IN_FRONT, AUDIO_CHANNEL_IN_BACK},
        {AUDIO_CHANNEL_IN_STEREO, AUDIO_CHANNEL_IN_RIGHT}};

bool sHasAuxChannels[PREPROC_NUM_EFFECTS] = {
        false,  // PREPROC_AGC
        true,   // PREPROC_AEC
        true,   // PREPROC_NS
};

bool gDualMicEnabled;
FILE* gPcmDumpFh;
static pthread_mutex_t gPcmDumpLock = PTHREAD_MUTEX_INITIALIZER;
#endif

//------------------------------------------------------------------------------
// Effect descriptors
//------------------------------------------------------------------------------

// UUIDs for effect types have been generated from http://www.itu.int/ITU-T/asn1/uuid.html
// as the pre processing effects are not defined by OpenSL ES

// Automatic Gain Control
static const effect_descriptor_t sAgcDescriptor = {
        {0x0a8abfe0, 0x654c, 0x11e0, 0xba26, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // type
        {0xaa8130e0, 0x66fc, 0x11e0, 0xbad0, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // uuid
        EFFECT_CONTROL_API_VERSION,
        (EFFECT_FLAG_TYPE_PRE_PROC | EFFECT_FLAG_DEVICE_IND),
        0,  // FIXME indicate CPU load
        0,  // FIXME indicate memory usage
        "Automatic Gain Control",
        "The Android Open Source Project"};

// Automatic Gain Control 2
static const effect_descriptor_t sAgc2Descriptor = {
        {0xae3c653b, 0xbe18, 0x4ab8, 0x8938, {0x41, 0x8f, 0x0a, 0x7f, 0x06, 0xac}},  // type
        {0x89f38e65, 0xd4d2, 0x4d64, 0xad0e, {0x2b, 0x3e, 0x79, 0x9e, 0xa8, 0x86}},  // uuid
        EFFECT_CONTROL_API_VERSION,
        (EFFECT_FLAG_TYPE_PRE_PROC | EFFECT_FLAG_DEVICE_IND),
        0,  // FIXME indicate CPU load
        0,  // FIXME indicate memory usage
        "Automatic Gain Control 2",
        "The Android Open Source Project"};

// Acoustic Echo Cancellation
static const effect_descriptor_t sAecDescriptor = {
        {0x7b491460, 0x8d4d, 0x11e0, 0xbd61, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // type
        {0xbb392ec0, 0x8d4d, 0x11e0, 0xa896, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // uuid
        EFFECT_CONTROL_API_VERSION,
        (EFFECT_FLAG_TYPE_PRE_PROC | EFFECT_FLAG_DEVICE_IND),
        0,  // FIXME indicate CPU load
        0,  // FIXME indicate memory usage
        "Acoustic Echo Canceler",
        "The Android Open Source Project"};

// Noise suppression
static const effect_descriptor_t sNsDescriptor = {
        {0x58b4b260, 0x8e06, 0x11e0, 0xaa8e, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // type
        {0xc06c8400, 0x8e06, 0x11e0, 0x9cb6, {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}},  // uuid
        EFFECT_CONTROL_API_VERSION,
        (EFFECT_FLAG_TYPE_PRE_PROC | EFFECT_FLAG_DEVICE_IND),
        0,  // FIXME indicate CPU load
        0,  // FIXME indicate memory usage
        "Noise Suppression",
        "The Android Open Source Project"};

static const effect_descriptor_t* sDescriptors[PREPROC_NUM_EFFECTS] = {&sAgcDescriptor,
                                                                       &sAgc2Descriptor,
                                                                       &sAecDescriptor,
                                                                       &sNsDescriptor};

//------------------------------------------------------------------------------
// Helper functions
//------------------------------------------------------------------------------

const effect_uuid_t* const sUuidToPreProcTable[PREPROC_NUM_EFFECTS] = {FX_IID_AGC,
                                                                       FX_IID_AGC2,
                                                                       FX_IID_AEC, FX_IID_NS};

const effect_uuid_t* ProcIdToUuid(int procId) {
    if (procId >= PREPROC_NUM_EFFECTS) {
        return EFFECT_UUID_NULL;
    }
    return sUuidToPreProcTable[procId];
}

uint32_t UuidToProcId(const effect_uuid_t* uuid) {
    size_t i;
    for (i = 0; i < PREPROC_NUM_EFFECTS; i++) {
        if (memcmp(uuid, sUuidToPreProcTable[i], sizeof(*uuid)) == 0) {
            break;
        }
    }
    return i;
}

bool HasReverseStream(uint32_t procId) {
    if (procId == PREPROC_AEC) {
        return true;
    }
    return false;
}

//------------------------------------------------------------------------------
// Automatic Gain Control (AGC)
//------------------------------------------------------------------------------

static const int kAgcDefaultTargetLevel = 3;
static const int kAgcDefaultCompGain = 9;
static const bool kAgcDefaultLimiter = true;

int Agc2Init(preproc_effect_t* effect) {
    ALOGV("Agc2Init");
    effect->session->config = effect->session->apm->GetConfig();
    effect->session->config.gain_controller2.fixed_digital.gain_db = 0.f;
    effect->session->config.gain_controller2.adaptive_digital.level_estimator =
            effect->session->config.gain_controller2.kRms;
    effect->session->config.gain_controller2.adaptive_digital.extra_saturation_margin_db = 2.f;
    effect->session->apm->ApplyConfig(effect->session->config);
    return 0;
}

int AgcInit(preproc_effect_t* effect) {
    ALOGV("AgcInit");
    effect->session->config = effect->session->apm->GetConfig();
    effect->session->config.gain_controller1.target_level_dbfs = kAgcDefaultTargetLevel;
    effect->session->config.gain_controller1.compression_gain_db = kAgcDefaultCompGain;
    effect->session->config.gain_controller1.enable_limiter = kAgcDefaultLimiter;
    effect->session->apm->ApplyConfig(effect->session->config);
    return 0;
}

int Agc2Create(preproc_effect_t* effect) {
    Agc2Init(effect);
    return 0;
}

int AgcCreate(preproc_effect_t* effect) {
    AgcInit(effect);
    return 0;
}

int Agc2GetParameter(preproc_effect_t* effect, void* pParam, uint32_t* pValueSize, void* pValue) {
    int status = 0;
    uint32_t param = *(uint32_t*)pParam;
    agc2_settings_t* pProperties = (agc2_settings_t*)pValue;

    switch (param) {
        case AGC2_PARAM_FIXED_DIGITAL_GAIN:
            if (*pValueSize < sizeof(float)) {
                *pValueSize = 0.f;
                return -EINVAL;
            }
            break;
        case AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR:
            if (*pValueSize < sizeof(int32_t)) {
                *pValueSize = 0;
                return -EINVAL;
            }
            break;
        case AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN:
            if (*pValueSize < sizeof(float)) {
                *pValueSize = 0.f;
                return -EINVAL;
            }
            break;
        case AGC2_PARAM_PROPERTIES:
            if (*pValueSize < sizeof(agc2_settings_t)) {
                *pValueSize = 0;
                return -EINVAL;
            }
            break;

        default:
            ALOGW("Agc2GetParameter() unknown param %08x", param);
            status = -EINVAL;
            break;
    }

    effect->session->config = effect->session->apm->GetConfig();
    switch (param) {
        case AGC2_PARAM_FIXED_DIGITAL_GAIN:
            *(float*)pValue =
                    (float)(effect->session->config.gain_controller2.fixed_digital.gain_db);
            ALOGV("Agc2GetParameter() target level %f dB", *(float*)pValue);
            break;
        case AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR:
            *(uint32_t*)pValue = (uint32_t)(
                    effect->session->config.gain_controller2.adaptive_digital.level_estimator);
            ALOGV("Agc2GetParameter() level estimator %d",
                  *(webrtc::AudioProcessing::Config::GainController2::LevelEstimator*)pValue);
            break;
        case AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN:
            *(float*)pValue = (float)(effect->session->config.gain_controller2.adaptive_digital
                                              .extra_saturation_margin_db);
            ALOGV("Agc2GetParameter() extra saturation margin %f dB", *(float*)pValue);
            break;
        case AGC2_PARAM_PROPERTIES:
            pProperties->fixedDigitalGain =
                    (float)(effect->session->config.gain_controller2.fixed_digital.gain_db);
            pProperties->level_estimator = (uint32_t)(
                    effect->session->config.gain_controller2.adaptive_digital.level_estimator);
            pProperties->extraSaturationMargin =
                    (float)(effect->session->config.gain_controller2.adaptive_digital
                                    .extra_saturation_margin_db);
            break;
        default:
            ALOGW("Agc2GetParameter() unknown param %d", param);
            status = -EINVAL;
            break;
    }

    return status;
}

int AgcGetParameter(preproc_effect_t* effect, void* pParam, uint32_t* pValueSize, void* pValue) {
    int status = 0;
    uint32_t param = *(uint32_t*)pParam;
    t_agc_settings* pProperties = (t_agc_settings*)pValue;

    switch (param) {
        case AGC_PARAM_TARGET_LEVEL:
        case AGC_PARAM_COMP_GAIN:
            if (*pValueSize < sizeof(int16_t)) {
                *pValueSize = 0;
                return -EINVAL;
            }
            break;
        case AGC_PARAM_LIMITER_ENA:
            if (*pValueSize < sizeof(bool)) {
                *pValueSize = 0;
                return -EINVAL;
            }
            break;
        case AGC_PARAM_PROPERTIES:
            if (*pValueSize < sizeof(t_agc_settings)) {
                *pValueSize = 0;
                return -EINVAL;
            }
            break;

        default:
            ALOGW("AgcGetParameter() unknown param %08x", param);
            status = -EINVAL;
            break;
    }

    effect->session->config = effect->session->apm->GetConfig();
    switch (param) {
        case AGC_PARAM_TARGET_LEVEL:
            *(int16_t*)pValue =
                    (int16_t)(effect->session->config.gain_controller1.target_level_dbfs * -100);
            ALOGV("AgcGetParameter() target level %d milliBels", *(int16_t*)pValue);
            break;
        case AGC_PARAM_COMP_GAIN:
            *(int16_t*)pValue =
                    (int16_t)(effect->session->config.gain_controller1.compression_gain_db * -100);
            ALOGV("AgcGetParameter() comp gain %d milliBels", *(int16_t*)pValue);
            break;
        case AGC_PARAM_LIMITER_ENA:
            *(bool*)pValue = (bool)(effect->session->config.gain_controller1.enable_limiter);
            ALOGV("AgcGetParameter() limiter enabled %s",
                  (*(int16_t*)pValue != 0) ? "true" : "false");
            break;
        case AGC_PARAM_PROPERTIES:
            pProperties->targetLevel =
                    (int16_t)(effect->session->config.gain_controller1.target_level_dbfs * -100);
            pProperties->compGain =
                    (int16_t)(effect->session->config.gain_controller1.compression_gain_db * -100);
            pProperties->limiterEnabled =
                    (bool)(effect->session->config.gain_controller1.enable_limiter);
            break;
        default:
            ALOGW("AgcGetParameter() unknown param %d", param);
            status = -EINVAL;
            break;
    }
    return status;
}

int Agc2SetParameter(preproc_effect_t* effect, void* pParam, void* pValue) {
    int status = 0;
    uint32_t param = *(uint32_t*)pParam;
    float valueFloat = 0.f;
    agc2_settings_t* pProperties = (agc2_settings_t*)pValue;
    effect->session->config = effect->session->apm->GetConfig();
    switch (param) {
        case AGC2_PARAM_FIXED_DIGITAL_GAIN:
            valueFloat = (float)(*(int32_t*)pValue);
            ALOGV("Agc2SetParameter() fixed digital gain %f dB", valueFloat);
            effect->session->config.gain_controller2.fixed_digital.gain_db = valueFloat;
            break;
        case AGC2_PARAM_ADAPT_DIGI_LEVEL_ESTIMATOR:
            ALOGV("Agc2SetParameter() level estimator %d",
                  *(webrtc::AudioProcessing::Config::GainController2::LevelEstimator*)pValue);
            effect->session->config.gain_controller2.adaptive_digital.level_estimator =
                    (*(webrtc::AudioProcessing::Config::GainController2::LevelEstimator*)pValue);
            break;
        case AGC2_PARAM_ADAPT_DIGI_EXTRA_SATURATION_MARGIN:
            valueFloat = (float)(*(int32_t*)pValue);
            ALOGV("Agc2SetParameter() extra saturation margin %f dB", valueFloat);
            effect->session->config.gain_controller2.adaptive_digital.extra_saturation_margin_db =
                    valueFloat;
            break;
        case AGC2_PARAM_PROPERTIES:
            ALOGV("Agc2SetParameter() properties gain %f, level %d margin %f",
                  pProperties->fixedDigitalGain, pProperties->level_estimator,
                  pProperties->extraSaturationMargin);
            effect->session->config.gain_controller2.fixed_digital.gain_db =
                    pProperties->fixedDigitalGain;
            effect->session->config.gain_controller2.adaptive_digital.level_estimator =
                    (webrtc::AudioProcessing::Config::GainController2::LevelEstimator)
                            pProperties->level_estimator;
            effect->session->config.gain_controller2.adaptive_digital.extra_saturation_margin_db =
                    pProperties->extraSaturationMargin;
            break;
        default:
            ALOGW("Agc2SetParameter() unknown param %08x value %08x", param, *(uint32_t*)pValue);
            status = -EINVAL;
            break;
    }
    effect->session->apm->ApplyConfig(effect->session->config);

    ALOGV("Agc2SetParameter() done status %d", status);

    return status;
}

int AgcSetParameter(preproc_effect_t* effect, void* pParam, void* pValue) {
    int status = 0;
    uint32_t param = *(uint32_t*)pParam;
    t_agc_settings* pProperties = (t_agc_settings*)pValue;
    effect->session->config = effect->session->apm->GetConfig();
    switch (param) {
        case AGC_PARAM_TARGET_LEVEL:
            ALOGV("AgcSetParameter() target level %d milliBels", *(int16_t*)pValue);
            effect->session->config.gain_controller1.target_level_dbfs =
                    (-(*(int16_t*)pValue / 100));
            break;
        case AGC_PARAM_COMP_GAIN:
            ALOGV("AgcSetParameter() comp gain %d milliBels", *(int16_t*)pValue);
            effect->session->config.gain_controller1.compression_gain_db =
                    (*(int16_t*)pValue / 100);
            break;
        case AGC_PARAM_LIMITER_ENA:
            ALOGV("AgcSetParameter() limiter enabled %s", *(bool*)pValue ? "true" : "false");
            effect->session->config.gain_controller1.enable_limiter = (*(bool*)pValue);
            break;
        case AGC_PARAM_PROPERTIES:
            ALOGV("AgcSetParameter() properties level %d, gain %d limiter %d",
                  pProperties->targetLevel, pProperties->compGain, pProperties->limiterEnabled);
            effect->session->config.gain_controller1.target_level_dbfs =
                    -(pProperties->targetLevel / 100);
            effect->session->config.gain_controller1.compression_gain_db =
                    pProperties->compGain / 100;
            effect->session->config.gain_controller1.enable_limiter = pProperties->limiterEnabled;
            break;
        default:
            ALOGW("AgcSetParameter() unknown param %08x value %08x", param, *(uint32_t*)pValue);
            status = -EINVAL;
            break;
    }
    effect->session->apm->ApplyConfig(effect->session->config);

    ALOGV("AgcSetParameter() done status %d", status);

    return status;
}

void Agc2Enable(preproc_effect_t* effect) {
    effect->session->config = effect->session->apm->GetConfig();
    effect->session->config.gain_controller2.enabled = true;
    effect->session->apm->ApplyConfig(effect->session->config);
}

void AgcEnable(preproc_effect_t* effect) {
    effect->session->config = effect->session->apm->GetConfig();
    effect->session->config.gain_controller1.enabled = true;
    effect->session->apm->ApplyConfig(effect->session->config);
}

void Agc2Disable(preproc_effect_t* effect) {
    effect->session->config = effect->session->apm->GetConfig();
    effect->session->config.gain_controller2.enabled = false;
    effect->session->apm->ApplyConfig(effect->session->config);
}

void AgcDisable(preproc_effect_t* effect) {
    effect->session->config = effect->session->apm->GetConfig();
    effect->session->config.gain_controller1.enabled = false;
    effect->session->apm->ApplyConfig(effect->session->config);
}

static const preproc_ops_t sAgcOps = {AgcCreate,       AgcInit,         NULL, AgcEnable, AgcDisable,
                                      AgcSetParameter, AgcGetParameter, NULL};

static const preproc_ops_t sAgc2Ops = {Agc2Create,       Agc2Init,    NULL,
                                       Agc2Enable,       Agc2Disable, Agc2SetParameter,
                                       Agc2GetParameter, NULL};

//------------------------------------------------------------------------------
// Acoustic Echo Canceler (AEC)
//------------------------------------------------------------------------------


int AecInit(preproc_effect_t* effect) {
    ALOGV("AecInit");
    effect->session->config = effect->session->apm->GetConfig();
    effect->session->config.echo_canceller.mobile_mode = true;
    effect->session->apm->ApplyConfig(effect->session->config);
    return 0;
}

int AecCreate(preproc_effect_t* effect) {
    AecInit(effect);
    return 0;
}

int AecGetParameter(preproc_effect_t* effect, void* pParam, uint32_t* pValueSize, void* pValue) {
    int status = 0;
    uint32_t param = *(uint32_t*)pParam;

    if (*pValueSize < sizeof(uint32_t)) {
        return -EINVAL;
    }
    switch (param) {
        case AEC_PARAM_ECHO_DELAY:
        case AEC_PARAM_PROPERTIES:
            *(uint32_t*)pValue = 1000 * effect->session->apm->stream_delay_ms();
            ALOGV("AecGetParameter() echo delay %d us", *(uint32_t*)pValue);
            break;
        case AEC_PARAM_MOBILE_MODE:
            effect->session->config = effect->session->apm->GetConfig();
            *(uint32_t*)pValue = effect->session->config.echo_canceller.mobile_mode;
            ALOGV("AecGetParameter() mobile mode %d us", *(uint32_t*)pValue);
            break;
        default:
            ALOGW("AecGetParameter() unknown param %08x value %08x", param, *(uint32_t*)pValue);
            status = -EINVAL;
            break;
    }
    return status;
}

int AecSetParameter(preproc_effect_t* effect, void* pParam, void* pValue) {
    int status = 0;
    uint32_t param = *(uint32_t*)pParam;
    uint32_t value = *(uint32_t*)pValue;

    switch (param) {
        case AEC_PARAM_ECHO_DELAY:
        case AEC_PARAM_PROPERTIES:
            status = effect->session->apm->set_stream_delay_ms(value / 1000);
            ALOGV("AecSetParameter() echo delay %d us, status %d", value, status);
            break;
        case AEC_PARAM_MOBILE_MODE:
            effect->session->config = effect->session->apm->GetConfig();
            effect->session->config.echo_canceller.mobile_mode = value;
            ALOGV("AecSetParameter() mobile mode %d us", value);
            effect->session->apm->ApplyConfig(effect->session->config);
            break;
        default:
            ALOGW("AecSetParameter() unknown param %08x value %08x", param, *(uint32_t*)pValue);
            status = -EINVAL;
            break;
    }
    return status;
}

void AecEnable(preproc_effect_t* effect) {
    effect->session->config = effect->session->apm->GetConfig();
    effect->session->config.echo_canceller.enabled = true;
    effect->session->apm->ApplyConfig(effect->session->config);
}

void AecDisable(preproc_effect_t* effect) {
    effect->session->config = effect->session->apm->GetConfig();
    effect->session->config.echo_canceller.enabled = false;
    effect->session->apm->ApplyConfig(effect->session->config);
}

int AecSetDevice(preproc_effect_t* effect, uint32_t device) {
    ALOGV("AecSetDevice %08x", device);

    if (audio_is_input_device(device)) {
        return 0;
    }

    return 0;
}

static const preproc_ops_t sAecOps = {AecCreate,       AecInit,     NULL,
                                      AecEnable,       AecDisable,  AecSetParameter,
                                      AecGetParameter, AecSetDevice};

//------------------------------------------------------------------------------
// Noise Suppression (NS)
//------------------------------------------------------------------------------

static const webrtc::AudioProcessing::Config::NoiseSuppression::Level kNsDefaultLevel =
        webrtc::AudioProcessing::Config::NoiseSuppression::kModerate;

int NsInit(preproc_effect_t* effect) {
    ALOGV("NsInit");
    effect->session->config = effect->session->apm->GetConfig();
    effect->session->config.noise_suppression.level = kNsDefaultLevel;
    effect->session->apm->ApplyConfig(effect->session->config);
    effect->type = NS_TYPE_SINGLE_CHANNEL;
    return 0;
}

int NsCreate(preproc_effect_t* effect) {
    NsInit(effect);
    return 0;
}

int NsGetParameter(preproc_effect_t* /*effect __unused*/, void* /*pParam __unused*/,
                   uint32_t* /*pValueSize __unused*/, void* /*pValue __unused*/) {
    int status = 0;
    return status;
}

int NsSetParameter(preproc_effect_t* effect, void* pParam, void* pValue) {
    int status = 0;
    uint32_t param = *(uint32_t*)pParam;
    uint32_t value = *(uint32_t*)pValue;
    effect->session->config = effect->session->apm->GetConfig();
    switch (param) {
        case NS_PARAM_LEVEL:
            effect->session->config.noise_suppression.level =
                    (webrtc::AudioProcessing::Config::NoiseSuppression::Level)value;
            ALOGV("NsSetParameter() level %d", value);
            break;
        default:
            ALOGW("NsSetParameter() unknown param %08x value %08x", param, value);
            status = -EINVAL;
    }
    effect->session->apm->ApplyConfig(effect->session->config);

    return status;
}

void NsEnable(preproc_effect_t* effect) {
    effect->session->config = effect->session->apm->GetConfig();
    effect->session->config.noise_suppression.enabled = true;
    effect->session->apm->ApplyConfig(effect->session->config);
}

void NsDisable(preproc_effect_t* effect) {
    ALOGV("NsDisable");
    effect->session->config = effect->session->apm->GetConfig();
    effect->session->config.noise_suppression.enabled = false;
    effect->session->apm->ApplyConfig(effect->session->config);
}

static const preproc_ops_t sNsOps = {NsCreate,  NsInit,         NULL,           NsEnable,
                                     NsDisable, NsSetParameter, NsGetParameter, NULL};

static const preproc_ops_t* sPreProcOps[PREPROC_NUM_EFFECTS] = {&sAgcOps,
                                                                &sAgc2Ops,
                                                                &sAecOps, &sNsOps};

//------------------------------------------------------------------------------
// Effect functions
//------------------------------------------------------------------------------

void Session_SetProcEnabled(preproc_session_t* session, uint32_t procId, bool enabled);

extern "C" const struct effect_interface_s sEffectInterface;
extern "C" const struct effect_interface_s sEffectInterfaceReverse;

#define BAD_STATE_ABORT(from, to) LOG_ALWAYS_FATAL("Bad state transition from %d to %d", from, to);

int Effect_SetState(preproc_effect_t* effect, uint32_t state) {
    int status = 0;
    ALOGV("Effect_SetState proc %d, new %d old %d", effect->procId, state, effect->state);
    switch (state) {
        case PREPROC_EFFECT_STATE_INIT:
            switch (effect->state) {
                case PREPROC_EFFECT_STATE_ACTIVE:
                    effect->ops->disable(effect);
                    Session_SetProcEnabled(effect->session, effect->procId, false);
                    break;
                case PREPROC_EFFECT_STATE_CONFIG:
                case PREPROC_EFFECT_STATE_CREATED:
                case PREPROC_EFFECT_STATE_INIT:
                    break;
                default:
                    BAD_STATE_ABORT(effect->state, state);
            }
            break;
        case PREPROC_EFFECT_STATE_CREATED:
            switch (effect->state) {
                case PREPROC_EFFECT_STATE_INIT:
                    status = effect->ops->create(effect);
                    break;
                case PREPROC_EFFECT_STATE_CREATED:
                case PREPROC_EFFECT_STATE_ACTIVE:
                case PREPROC_EFFECT_STATE_CONFIG:
                    ALOGE("Effect_SetState invalid transition");
                    status = -ENOSYS;
                    break;
                default:
                    BAD_STATE_ABORT(effect->state, state);
            }
            break;
        case PREPROC_EFFECT_STATE_CONFIG:
            switch (effect->state) {
                case PREPROC_EFFECT_STATE_INIT:
                    ALOGE("Effect_SetState invalid transition");
                    status = -ENOSYS;
                    break;
                case PREPROC_EFFECT_STATE_ACTIVE:
                    effect->ops->disable(effect);
                    Session_SetProcEnabled(effect->session, effect->procId, false);
                    break;
                case PREPROC_EFFECT_STATE_CREATED:
                case PREPROC_EFFECT_STATE_CONFIG:
                    break;
                default:
                    BAD_STATE_ABORT(effect->state, state);
            }
            break;
        case PREPROC_EFFECT_STATE_ACTIVE:
            switch (effect->state) {
                case PREPROC_EFFECT_STATE_INIT:
                case PREPROC_EFFECT_STATE_CREATED:
                    ALOGE("Effect_SetState invalid transition");
                    status = -ENOSYS;
                    break;
                case PREPROC_EFFECT_STATE_ACTIVE:
                    // enabling an already enabled effect is just ignored
                    break;
                case PREPROC_EFFECT_STATE_CONFIG:
                    effect->ops->enable(effect);
                    Session_SetProcEnabled(effect->session, effect->procId, true);
                    break;
                default:
                    BAD_STATE_ABORT(effect->state, state);
            }
            break;
        default:
            BAD_STATE_ABORT(effect->state, state);
    }
    if (status == 0) {
        effect->state = state;
    }
    return status;
}

int Effect_Init(preproc_effect_t* effect, uint32_t procId) {
    if (HasReverseStream(procId)) {
        effect->itfe = &sEffectInterfaceReverse;
    } else {
        effect->itfe = &sEffectInterface;
    }
    effect->ops = sPreProcOps[procId];
    effect->procId = procId;
    effect->state = PREPROC_EFFECT_STATE_INIT;
    return 0;
}

int Effect_Create(preproc_effect_t* effect, preproc_session_t* session,
                  effect_handle_t* interface) {
    effect->session = session;
    *interface = (effect_handle_t)&effect->itfe;
    return Effect_SetState(effect, PREPROC_EFFECT_STATE_CREATED);
}

int Effect_Release(preproc_effect_t* effect) {
    return Effect_SetState(effect, PREPROC_EFFECT_STATE_INIT);
}

//------------------------------------------------------------------------------
// Session functions
//------------------------------------------------------------------------------

#define RESAMPLER_QUALITY SPEEX_RESAMPLER_QUALITY_VOIP

static const int kPreprocDefaultSr = 16000;
static const int kPreProcDefaultCnl = 1;

int Session_Init(preproc_session_t* session) {
    size_t i;
    int status = 0;

    session->state = PREPROC_SESSION_STATE_INIT;
    session->id = 0;
    session->io = 0;
    session->createdMsk = 0;
    for (i = 0; i < PREPROC_NUM_EFFECTS && status == 0; i++) {
        status = Effect_Init(&session->effects[i], i);
    }
    return status;
}

extern "C" int Session_CreateEffect(preproc_session_t* session, int32_t procId,
                                    effect_handle_t* interface) {
    int status = -ENOMEM;

    ALOGV("Session_CreateEffect procId %d, createdMsk %08x", procId, session->createdMsk);

    if (session->createdMsk == 0) {
        session->apm = session->ap_builder.Create();
        if (session->apm == NULL) {
            ALOGW("Session_CreateEffect could not get apm engine");
            goto error;
        }
        session->frameCount = kPreprocDefaultSr / 100;
        session->samplingRate = kPreprocDefaultSr;
        session->inChannelCount = kPreProcDefaultCnl;
        session->outChannelCount = kPreProcDefaultCnl;
        session->inputConfig.set_sample_rate_hz(kPreprocDefaultSr);
        session->inputConfig.set_num_channels(kPreProcDefaultCnl);
        session->outputConfig.set_sample_rate_hz(kPreprocDefaultSr);
        session->outputConfig.set_num_channels(kPreProcDefaultCnl);
        session->revChannelCount = kPreProcDefaultCnl;
        session->revConfig.set_sample_rate_hz(kPreprocDefaultSr);
        session->revConfig.set_num_channels(kPreProcDefaultCnl);
        session->enabledMsk = 0;
        session->processedMsk = 0;
        session->revEnabledMsk = 0;
        session->revProcessedMsk = 0;
    }
    status = Effect_Create(&session->effects[procId], session, interface);
    if (status < 0) {
        goto error;
    }
    ALOGV("Session_CreateEffect OK");
    session->createdMsk |= (1 << procId);
    return status;

error:
    if (session->createdMsk == 0) {
        delete session->apm;
        session->apm = NULL;
    }
    return status;
}

int Session_ReleaseEffect(preproc_session_t* session, preproc_effect_t* fx) {
    ALOGW_IF(Effect_Release(fx) != 0, " Effect_Release() failed for proc ID %d", fx->procId);
    session->createdMsk &= ~(1 << fx->procId);
    if (session->createdMsk == 0) {
        delete session->apm;
        session->apm = NULL;
        session->id = 0;
    }

    return 0;
}

int Session_SetConfig(preproc_session_t* session, effect_config_t* config) {
    uint32_t inCnl = audio_channel_count_from_in_mask(config->inputCfg.channels);
    uint32_t outCnl = audio_channel_count_from_in_mask(config->outputCfg.channels);

    if (config->inputCfg.samplingRate != config->outputCfg.samplingRate ||
        config->inputCfg.format != config->outputCfg.format ||
        config->inputCfg.format != AUDIO_FORMAT_PCM_16_BIT) {
        return -EINVAL;
    }

    ALOGV("Session_SetConfig sr %d cnl %08x", config->inputCfg.samplingRate,
          config->inputCfg.channels);

    session->samplingRate = config->inputCfg.samplingRate;
    session->frameCount = session->samplingRate / 100;
    session->inChannelCount = inCnl;
    session->outChannelCount = outCnl;
    session->inputConfig.set_sample_rate_hz(session->samplingRate);
    session->inputConfig.set_num_channels(inCnl);
    session->outputConfig.set_sample_rate_hz(session->samplingRate);
    session->outputConfig.set_num_channels(inCnl);

    session->revChannelCount = inCnl;
    session->revConfig.set_sample_rate_hz(session->samplingRate);
    session->revConfig.set_num_channels(inCnl);

    session->state = PREPROC_SESSION_STATE_CONFIG;
    return 0;
}

void Session_GetConfig(preproc_session_t* session, effect_config_t* config) {
    memset(config, 0, sizeof(effect_config_t));
    config->inputCfg.samplingRate = config->outputCfg.samplingRate = session->samplingRate;
    config->inputCfg.format = config->outputCfg.format = AUDIO_FORMAT_PCM_16_BIT;
    config->inputCfg.channels = audio_channel_in_mask_from_count(session->inChannelCount);
    // "out" doesn't mean output device, so this is the correct API to convert channel count to mask
    config->outputCfg.channels = audio_channel_in_mask_from_count(session->outChannelCount);
    config->inputCfg.mask = config->outputCfg.mask =
            (EFFECT_CONFIG_SMP_RATE | EFFECT_CONFIG_CHANNELS | EFFECT_CONFIG_FORMAT);
}

int Session_SetReverseConfig(preproc_session_t* session, effect_config_t* config) {
    if (config->inputCfg.samplingRate != config->outputCfg.samplingRate ||
        config->inputCfg.format != config->outputCfg.format ||
        config->inputCfg.format != AUDIO_FORMAT_PCM_16_BIT) {
        return -EINVAL;
    }

    ALOGV("Session_SetReverseConfig sr %d cnl %08x", config->inputCfg.samplingRate,
          config->inputCfg.channels);

    if (session->state < PREPROC_SESSION_STATE_CONFIG) {
        return -ENOSYS;
    }
    if (config->inputCfg.samplingRate != session->samplingRate ||
        config->inputCfg.format != AUDIO_FORMAT_PCM_16_BIT) {
        return -EINVAL;
    }
    uint32_t inCnl = audio_channel_count_from_out_mask(config->inputCfg.channels);
    session->revChannelCount = inCnl;

    return 0;
}

void Session_GetReverseConfig(preproc_session_t* session, effect_config_t* config) {
    memset(config, 0, sizeof(effect_config_t));
    config->inputCfg.samplingRate = config->outputCfg.samplingRate = session->samplingRate;
    config->inputCfg.format = config->outputCfg.format = AUDIO_FORMAT_PCM_16_BIT;
    config->inputCfg.channels = config->outputCfg.channels =
            audio_channel_in_mask_from_count(session->revChannelCount);
    config->inputCfg.mask = config->outputCfg.mask =
            (EFFECT_CONFIG_SMP_RATE | EFFECT_CONFIG_CHANNELS | EFFECT_CONFIG_FORMAT);
}

void Session_SetProcEnabled(preproc_session_t* session, uint32_t procId, bool enabled) {
    if (enabled) {
        session->enabledMsk |= (1 << procId);
        if (HasReverseStream(procId)) {
            session->revEnabledMsk |= (1 << procId);
        }
    } else {
        session->enabledMsk &= ~(1 << procId);
        if (HasReverseStream(procId)) {
            session->revEnabledMsk &= ~(1 << procId);
        }
    }
    ALOGV("Session_SetProcEnabled proc %d, enabled %d enabledMsk %08x revEnabledMsk %08x", procId,
          enabled, session->enabledMsk, session->revEnabledMsk);
    session->processedMsk = 0;
    if (HasReverseStream(procId)) {
        session->revProcessedMsk = 0;
    }
}

//------------------------------------------------------------------------------
// Bundle functions
//------------------------------------------------------------------------------

static int sInitStatus = 1;
static preproc_session_t sSessions[PREPROC_NUM_SESSIONS];

preproc_session_t* PreProc_GetSession(int32_t procId, int32_t sessionId, int32_t ioId) {
    size_t i;
    for (i = 0; i < PREPROC_NUM_SESSIONS; i++) {
        if (sSessions[i].id == sessionId) {
            if (sSessions[i].createdMsk & (1 << procId)) {
                return NULL;
            }
            return &sSessions[i];
        }
    }
    for (i = 0; i < PREPROC_NUM_SESSIONS; i++) {
        if (sSessions[i].id == 0) {
            sSessions[i].id = sessionId;
            sSessions[i].io = ioId;
            return &sSessions[i];
        }
    }
    return NULL;
}

int PreProc_Init() {
    size_t i;
    int status = 0;

    if (sInitStatus <= 0) {
        return sInitStatus;
    }
    for (i = 0; i < PREPROC_NUM_SESSIONS && status == 0; i++) {
        status = Session_Init(&sSessions[i]);
    }
    sInitStatus = status;
    return sInitStatus;
}

const effect_descriptor_t* PreProc_GetDescriptor(const effect_uuid_t* uuid) {
    size_t i;
    for (i = 0; i < PREPROC_NUM_EFFECTS; i++) {
        if (memcmp(&sDescriptors[i]->uuid, uuid, sizeof(effect_uuid_t)) == 0) {
            return sDescriptors[i];
        }
    }
    return NULL;
}

extern "C" {

//------------------------------------------------------------------------------
// Effect Control Interface Implementation
//------------------------------------------------------------------------------

int PreProcessingFx_Process(effect_handle_t self, audio_buffer_t* inBuffer,
                            audio_buffer_t* outBuffer) {
    preproc_effect_t* effect = (preproc_effect_t*)self;

    if (effect == NULL) {
        ALOGV("PreProcessingFx_Process() ERROR effect == NULL");
        return -EINVAL;
    }
    preproc_session_t* session = (preproc_session_t*)effect->session;

    if (inBuffer == NULL || inBuffer->raw == NULL || outBuffer == NULL || outBuffer->raw == NULL) {
        ALOGW("PreProcessingFx_Process() ERROR bad pointer");
        return -EINVAL;
    }

    if (inBuffer->frameCount != outBuffer->frameCount) {
        ALOGW("inBuffer->frameCount %zu is not equal to outBuffer->frameCount %zu",
              inBuffer->frameCount, outBuffer->frameCount);
        return -EINVAL;
    }

    if (inBuffer->frameCount != session->frameCount) {
        ALOGW("inBuffer->frameCount %zu != %zu representing 10ms at sampling rate %d",
              inBuffer->frameCount, session->frameCount, session->samplingRate);
        return -EINVAL;
    }

    session->processedMsk |= (1 << effect->procId);

    //    ALOGV("PreProcessingFx_Process In %d frames enabledMsk %08x processedMsk %08x",
    //         inBuffer->frameCount, session->enabledMsk, session->processedMsk);
    if ((session->processedMsk & session->enabledMsk) == session->enabledMsk) {
        effect->session->processedMsk = 0;
        if (int status = effect->session->apm->ProcessStream(
                    (const int16_t* const)inBuffer->s16,
                    (const webrtc::StreamConfig)effect->session->inputConfig,
                    (const webrtc::StreamConfig)effect->session->outputConfig,
                    (int16_t* const)outBuffer->s16);
            status != 0) {
            ALOGE("Process Stream failed with error %d\n", status);
            return status;
        }
        return 0;
    } else {
        return -ENODATA;
    }
}

int PreProcessingFx_Command(effect_handle_t self, uint32_t cmdCode, uint32_t cmdSize,
                            void* pCmdData, uint32_t* replySize, void* pReplyData) {
    preproc_effect_t* effect = (preproc_effect_t*)self;

    if (effect == NULL) {
        return -EINVAL;
    }

    // ALOGV("PreProcessingFx_Command: command %d cmdSize %d",cmdCode, cmdSize);

    switch (cmdCode) {
        case EFFECT_CMD_INIT:
            if (pReplyData == NULL || *replySize != sizeof(int)) {
                return -EINVAL;
            }
            if (effect->ops->init) {
                effect->ops->init(effect);
            }
            *(int*)pReplyData = 0;
            break;

        case EFFECT_CMD_SET_CONFIG: {
            if (pCmdData == NULL || cmdSize != sizeof(effect_config_t) || pReplyData == NULL ||
                *replySize != sizeof(int)) {
                ALOGV("PreProcessingFx_Command cmdCode Case: "
                      "EFFECT_CMD_SET_CONFIG: ERROR");
                return -EINVAL;
            }
#ifdef DUAL_MIC_TEST
            // make sure that the config command is accepted by making as if all effects were
            // disabled: this is OK for functional tests
            uint32_t enabledMsk = effect->session->enabledMsk;
            if (gDualMicEnabled) {
                effect->session->enabledMsk = 0;
            }
#endif
            *(int*)pReplyData = Session_SetConfig(effect->session, (effect_config_t*)pCmdData);
#ifdef DUAL_MIC_TEST
            if (gDualMicEnabled) {
                effect->session->enabledMsk = enabledMsk;
            }
#endif
            if (*(int*)pReplyData != 0) {
                break;
            }
            if (effect->state != PREPROC_EFFECT_STATE_ACTIVE) {
                *(int*)pReplyData = Effect_SetState(effect, PREPROC_EFFECT_STATE_CONFIG);
            }
        } break;

        case EFFECT_CMD_GET_CONFIG:
            if (pReplyData == NULL || *replySize != sizeof(effect_config_t)) {
                ALOGV("\tLVM_ERROR : PreProcessingFx_Command cmdCode Case: "
                      "EFFECT_CMD_GET_CONFIG: ERROR");
                return -EINVAL;
            }

            Session_GetConfig(effect->session, (effect_config_t*)pReplyData);
            break;

        case EFFECT_CMD_SET_CONFIG_REVERSE:
            if (pCmdData == NULL || cmdSize != sizeof(effect_config_t) || pReplyData == NULL ||
                *replySize != sizeof(int)) {
                ALOGV("PreProcessingFx_Command cmdCode Case: "
                      "EFFECT_CMD_SET_CONFIG_REVERSE: ERROR");
                return -EINVAL;
            }
            *(int*)pReplyData =
                    Session_SetReverseConfig(effect->session, (effect_config_t*)pCmdData);
            if (*(int*)pReplyData != 0) {
                break;
            }
            break;

        case EFFECT_CMD_GET_CONFIG_REVERSE:
            if (pReplyData == NULL || *replySize != sizeof(effect_config_t)) {
                ALOGV("PreProcessingFx_Command cmdCode Case: "
                      "EFFECT_CMD_GET_CONFIG_REVERSE: ERROR");
                return -EINVAL;
            }
            Session_GetReverseConfig(effect->session, (effect_config_t*)pCmdData);
            break;

        case EFFECT_CMD_RESET:
            if (effect->ops->reset) {
                effect->ops->reset(effect);
            }
            break;

        case EFFECT_CMD_GET_PARAM: {
            effect_param_t* p = (effect_param_t*)pCmdData;

            if (pCmdData == NULL || cmdSize < sizeof(effect_param_t) ||
                cmdSize < (sizeof(effect_param_t) + p->psize) || pReplyData == NULL ||
                replySize == NULL || *replySize < (sizeof(effect_param_t) + p->psize)) {
                ALOGV("PreProcessingFx_Command cmdCode Case: "
                      "EFFECT_CMD_GET_PARAM: ERROR");
                return -EINVAL;
            }

            memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + p->psize);

            p = (effect_param_t*)pReplyData;

            int voffset = ((p->psize - 1) / sizeof(int32_t) + 1) * sizeof(int32_t);

            if (effect->ops->get_parameter) {
                p->status =
                        effect->ops->get_parameter(effect, p->data, &p->vsize, p->data + voffset);
                *replySize = sizeof(effect_param_t) + voffset + p->vsize;
            }
        } break;

        case EFFECT_CMD_SET_PARAM: {
            if (pCmdData == NULL || cmdSize < sizeof(effect_param_t) || pReplyData == NULL ||
                replySize == NULL || *replySize != sizeof(int32_t)) {
                ALOGV("PreProcessingFx_Command cmdCode Case: "
                      "EFFECT_CMD_SET_PARAM: ERROR");
                return -EINVAL;
            }
            effect_param_t* p = (effect_param_t*)pCmdData;

            if (p->psize != sizeof(int32_t)) {
                ALOGV("PreProcessingFx_Command cmdCode Case: "
                      "EFFECT_CMD_SET_PARAM: ERROR, psize is not sizeof(int32_t)");
                return -EINVAL;
            }
            if (effect->ops->set_parameter) {
                *(int*)pReplyData =
                        effect->ops->set_parameter(effect, (void*)p->data, p->data + p->psize);
            }
        } break;

        case EFFECT_CMD_ENABLE:
            if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
                ALOGV("PreProcessingFx_Command cmdCode Case: EFFECT_CMD_ENABLE: ERROR");
                return -EINVAL;
            }
            *(int*)pReplyData = Effect_SetState(effect, PREPROC_EFFECT_STATE_ACTIVE);
            break;

        case EFFECT_CMD_DISABLE:
            if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
                ALOGV("PreProcessingFx_Command cmdCode Case: EFFECT_CMD_DISABLE: ERROR");
                return -EINVAL;
            }
            *(int*)pReplyData = Effect_SetState(effect, PREPROC_EFFECT_STATE_CONFIG);
            break;

        case EFFECT_CMD_SET_DEVICE:
        case EFFECT_CMD_SET_INPUT_DEVICE:
            if (pCmdData == NULL || cmdSize != sizeof(uint32_t)) {
                ALOGV("PreProcessingFx_Command cmdCode Case: EFFECT_CMD_SET_DEVICE: ERROR");
                return -EINVAL;
            }

            if (effect->ops->set_device) {
                effect->ops->set_device(effect, *(uint32_t*)pCmdData);
            }
            break;

        case EFFECT_CMD_SET_VOLUME:
        case EFFECT_CMD_SET_AUDIO_MODE:
            break;

#ifdef DUAL_MIC_TEST
        ///// test commands start
        case PREPROC_CMD_DUAL_MIC_ENABLE: {
            if (pCmdData == NULL || cmdSize != sizeof(uint32_t) || pReplyData == NULL ||
                replySize == NULL) {
                ALOGE("PreProcessingFx_Command cmdCode Case: "
                      "PREPROC_CMD_DUAL_MIC_ENABLE: ERROR");
                *replySize = 0;
                return -EINVAL;
            }
            gDualMicEnabled = *(bool*)pCmdData;
            if (gDualMicEnabled) {
                effect->aux_channels_on = sHasAuxChannels[effect->procId];
            } else {
                effect->aux_channels_on = false;
            }
            effect->cur_channel_config =
                    (effect->session->inChannelCount == 1) ? CHANNEL_CFG_MONO : CHANNEL_CFG_STEREO;

            ALOGV("PREPROC_CMD_DUAL_MIC_ENABLE: %s", gDualMicEnabled ? "enabled" : "disabled");
            *replySize = sizeof(int);
            *(int*)pReplyData = 0;
        } break;
        case PREPROC_CMD_DUAL_MIC_PCM_DUMP_START: {
            if (pCmdData == NULL || pReplyData == NULL || replySize == NULL) {
                ALOGE("PreProcessingFx_Command cmdCode Case: "
                      "PREPROC_CMD_DUAL_MIC_PCM_DUMP_START: ERROR");
                *replySize = 0;
                return -EINVAL;
            }
            pthread_mutex_lock(&gPcmDumpLock);
            if (gPcmDumpFh != NULL) {
                fclose(gPcmDumpFh);
                gPcmDumpFh = NULL;
            }
            char* path = strndup((char*)pCmdData, cmdSize);
            gPcmDumpFh = fopen((char*)path, "wb");
            pthread_mutex_unlock(&gPcmDumpLock);
            ALOGV("PREPROC_CMD_DUAL_MIC_PCM_DUMP_START: path %s gPcmDumpFh %p", path, gPcmDumpFh);
            ALOGE_IF(gPcmDumpFh <= 0, "gPcmDumpFh open error %d %s", errno, strerror(errno));
            free(path);
            *replySize = sizeof(int);
            *(int*)pReplyData = 0;
        } break;
        case PREPROC_CMD_DUAL_MIC_PCM_DUMP_STOP: {
            if (pReplyData == NULL || replySize == NULL) {
                ALOGE("PreProcessingFx_Command cmdCode Case: "
                      "PREPROC_CMD_DUAL_MIC_PCM_DUMP_STOP: ERROR");
                *replySize = 0;
                return -EINVAL;
            }
            pthread_mutex_lock(&gPcmDumpLock);
            if (gPcmDumpFh != NULL) {
                fclose(gPcmDumpFh);
                gPcmDumpFh = NULL;
            }
            pthread_mutex_unlock(&gPcmDumpLock);
            ALOGV("PREPROC_CMD_DUAL_MIC_PCM_DUMP_STOP");
            *replySize = sizeof(int);
            *(int*)pReplyData = 0;
        } break;
            ///// test commands end

        case EFFECT_CMD_GET_FEATURE_SUPPORTED_CONFIGS: {
            if (!gDualMicEnabled) {
                return -EINVAL;
            }
            if (pCmdData == NULL || cmdSize != 2 * sizeof(uint32_t) || pReplyData == NULL ||
                replySize == NULL) {
                ALOGE("PreProcessingFx_Command cmdCode Case: "
                      "EFFECT_CMD_GET_FEATURE_SUPPORTED_CONFIGS: ERROR");
                *replySize = 0;
                return -EINVAL;
            }
            if (*(uint32_t*)pCmdData != EFFECT_FEATURE_AUX_CHANNELS || !effect->aux_channels_on) {
                ALOGV("PreProcessingFx_Command feature EFFECT_FEATURE_AUX_CHANNELS not supported by"
                      " fx %d",
                      effect->procId);
                *(uint32_t*)pReplyData = -ENOSYS;
                *replySize = sizeof(uint32_t);
                break;
            }
            size_t num_configs = *((uint32_t*)pCmdData + 1);
            if (*replySize < (2 * sizeof(uint32_t) + num_configs * sizeof(channel_config_t))) {
                *replySize = 0;
                return -EINVAL;
            }

            *((uint32_t*)pReplyData + 1) = CHANNEL_CFG_CNT;
            if (num_configs < CHANNEL_CFG_CNT ||
                *replySize < (2 * sizeof(uint32_t) + CHANNEL_CFG_CNT * sizeof(channel_config_t))) {
                *(uint32_t*)pReplyData = -ENOMEM;
            } else {
                num_configs = CHANNEL_CFG_CNT;
                *(uint32_t*)pReplyData = 0;
            }
            ALOGV("PreProcessingFx_Command EFFECT_CMD_GET_FEATURE_SUPPORTED_CONFIGS num config %d",
                  num_configs);

            *replySize = 2 * sizeof(uint32_t) + num_configs * sizeof(channel_config_t);
            *((uint32_t*)pReplyData + 1) = num_configs;
            memcpy((uint32_t*)pReplyData + 2, &sDualMicConfigs,
                   num_configs * sizeof(channel_config_t));
        } break;
        case EFFECT_CMD_GET_FEATURE_CONFIG:
            if (!gDualMicEnabled) {
                return -EINVAL;
            }
            if (pCmdData == NULL || cmdSize != sizeof(uint32_t) || pReplyData == NULL ||
                replySize == NULL || *replySize < sizeof(uint32_t) + sizeof(channel_config_t)) {
                ALOGE("PreProcessingFx_Command cmdCode Case: "
                      "EFFECT_CMD_GET_FEATURE_CONFIG: ERROR");
                return -EINVAL;
            }
            if (*(uint32_t*)pCmdData != EFFECT_FEATURE_AUX_CHANNELS || !effect->aux_channels_on) {
                *(uint32_t*)pReplyData = -ENOSYS;
                *replySize = sizeof(uint32_t);
                break;
            }
            ALOGV("PreProcessingFx_Command EFFECT_CMD_GET_FEATURE_CONFIG");
            *(uint32_t*)pReplyData = 0;
            *replySize = sizeof(uint32_t) + sizeof(channel_config_t);
            memcpy((uint32_t*)pReplyData + 1, &sDualMicConfigs[effect->cur_channel_config],
                   sizeof(channel_config_t));
            break;
        case EFFECT_CMD_SET_FEATURE_CONFIG: {
            ALOGV("PreProcessingFx_Command EFFECT_CMD_SET_FEATURE_CONFIG: "
                  "gDualMicEnabled %d effect->aux_channels_on %d",
                  gDualMicEnabled, effect->aux_channels_on);
            if (!gDualMicEnabled) {
                return -EINVAL;
            }
            if (pCmdData == NULL || cmdSize != (sizeof(uint32_t) + sizeof(channel_config_t)) ||
                pReplyData == NULL || replySize == NULL || *replySize < sizeof(uint32_t)) {
                ALOGE("PreProcessingFx_Command cmdCode Case: "
                      "EFFECT_CMD_SET_FEATURE_CONFIG: ERROR\n"
                      "pCmdData %p cmdSize %d pReplyData %p replySize %p *replySize %d",
                      pCmdData, cmdSize, pReplyData, replySize, replySize ? *replySize : -1);
                return -EINVAL;
            }
            *replySize = sizeof(uint32_t);
            if (*(uint32_t*)pCmdData != EFFECT_FEATURE_AUX_CHANNELS || !effect->aux_channels_on) {
                *(uint32_t*)pReplyData = -ENOSYS;
                ALOGV("PreProcessingFx_Command cmdCode Case: "
                      "EFFECT_CMD_SET_FEATURE_CONFIG: ERROR\n"
                      "CmdData %d effect->aux_channels_on %d",
                      *(uint32_t*)pCmdData, effect->aux_channels_on);
                break;
            }
            size_t i;
            for (i = 0; i < CHANNEL_CFG_CNT; i++) {
                if (memcmp((uint32_t*)pCmdData + 1, &sDualMicConfigs[i],
                           sizeof(channel_config_t)) == 0) {
                    break;
                }
            }
            if (i == CHANNEL_CFG_CNT) {
                *(uint32_t*)pReplyData = -EINVAL;
                ALOGW("PreProcessingFx_Command EFFECT_CMD_SET_FEATURE_CONFIG invalid config"
                      "[%08x].[%08x]",
                      *((uint32_t*)pCmdData + 1), *((uint32_t*)pCmdData + 2));
            } else {
                effect->cur_channel_config = i;
                *(uint32_t*)pReplyData = 0;
                ALOGV("PreProcessingFx_Command EFFECT_CMD_SET_FEATURE_CONFIG New config"
                      "[%08x].[%08x]",
                      sDualMicConfigs[i].main_channels, sDualMicConfigs[i].aux_channels);
            }
        } break;
#endif
        default:
            return -EINVAL;
    }
    return 0;
}

int PreProcessingFx_GetDescriptor(effect_handle_t self, effect_descriptor_t* pDescriptor) {
    preproc_effect_t* effect = (preproc_effect_t*)self;

    if (effect == NULL || pDescriptor == NULL) {
        return -EINVAL;
    }

    *pDescriptor = *sDescriptors[effect->procId];

    return 0;
}

int PreProcessingFx_ProcessReverse(effect_handle_t self, audio_buffer_t* inBuffer,
                                   audio_buffer_t* outBuffer) {
    preproc_effect_t* effect = (preproc_effect_t*)self;

    if (effect == NULL) {
        ALOGW("PreProcessingFx_ProcessReverse() ERROR effect == NULL");
        return -EINVAL;
    }
    preproc_session_t* session = (preproc_session_t*)effect->session;

    if (inBuffer == NULL || inBuffer->raw == NULL) {
        ALOGW("PreProcessingFx_ProcessReverse() ERROR bad pointer");
        return -EINVAL;
    }

    if (inBuffer->frameCount != outBuffer->frameCount) {
        ALOGW("inBuffer->frameCount %zu is not equal to outBuffer->frameCount %zu",
              inBuffer->frameCount, outBuffer->frameCount);
        return -EINVAL;
    }

    if (inBuffer->frameCount != session->frameCount) {
        ALOGW("inBuffer->frameCount %zu != %zu representing 10ms at sampling rate %d",
              inBuffer->frameCount, session->frameCount, session->samplingRate);
        return -EINVAL;
    }

    session->revProcessedMsk |= (1 << effect->procId);

    //    ALOGV("PreProcessingFx_ProcessReverse In %d frames revEnabledMsk %08x revProcessedMsk
    //    %08x",
    //         inBuffer->frameCount, session->revEnabledMsk, session->revProcessedMsk);

    if ((session->revProcessedMsk & session->revEnabledMsk) == session->revEnabledMsk) {
        effect->session->revProcessedMsk = 0;
        if (int status = effect->session->apm->ProcessReverseStream(
                    (const int16_t* const)inBuffer->s16,
                    (const webrtc::StreamConfig)effect->session->revConfig,
                    (const webrtc::StreamConfig)effect->session->revConfig,
                    (int16_t* const)outBuffer->s16);
            status != 0) {
            ALOGE("Process Reverse Stream failed with error %d\n", status);
            return status;
        }
        return 0;
    } else {
        return -ENODATA;
    }
}

// effect_handle_t interface implementation for effect
const struct effect_interface_s sEffectInterface = {
        PreProcessingFx_Process, PreProcessingFx_Command, PreProcessingFx_GetDescriptor, NULL};

const struct effect_interface_s sEffectInterfaceReverse = {
        PreProcessingFx_Process, PreProcessingFx_Command, PreProcessingFx_GetDescriptor,
        PreProcessingFx_ProcessReverse};

//------------------------------------------------------------------------------
// Effect Library Interface Implementation
//------------------------------------------------------------------------------

int PreProcessingLib_Create(const effect_uuid_t* uuid, int32_t sessionId, int32_t ioId,
                            effect_handle_t* pInterface) {
    ALOGV("EffectCreate: uuid: %08x session %d IO: %d", uuid->timeLow, sessionId, ioId);

    int status;
    const effect_descriptor_t* desc;
    preproc_session_t* session;
    uint32_t procId;

    if (PreProc_Init() != 0) {
        return sInitStatus;
    }
    desc = PreProc_GetDescriptor(uuid);
    if (desc == NULL) {
        ALOGW("EffectCreate: fx not found uuid: %08x", uuid->timeLow);
        return -EINVAL;
    }
    procId = UuidToProcId(&desc->type);

    session = PreProc_GetSession(procId, sessionId, ioId);
    if (session == NULL) {
        ALOGW("EffectCreate: no more session available");
        return -EINVAL;
    }

    status = Session_CreateEffect(session, procId, pInterface);

    if (status < 0 && session->createdMsk == 0) {
        session->id = 0;
    }
    return status;
}

int PreProcessingLib_Release(effect_handle_t interface) {
    ALOGV("EffectRelease start %p", interface);
    if (PreProc_Init() != 0) {
        return sInitStatus;
    }

    preproc_effect_t* fx = (preproc_effect_t*)interface;

    if (fx->session->id == 0) {
        return -EINVAL;
    }
    return Session_ReleaseEffect(fx->session, fx);
}

int PreProcessingLib_GetDescriptor(const effect_uuid_t* uuid, effect_descriptor_t* pDescriptor) {
    if (pDescriptor == NULL || uuid == NULL) {
        return -EINVAL;
    }

    const effect_descriptor_t* desc = PreProc_GetDescriptor(uuid);
    if (desc == NULL) {
        ALOGV("PreProcessingLib_GetDescriptor() not found");
        return -EINVAL;
    }

    ALOGV("PreProcessingLib_GetDescriptor() got fx %s", desc->name);

    *pDescriptor = *desc;
    return 0;
}

// This is the only symbol that needs to be exported
__attribute__((visibility("default"))) audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM = {
        .tag = AUDIO_EFFECT_LIBRARY_TAG,
        .version = EFFECT_LIBRARY_API_VERSION,
        .name = "Audio Preprocessing Library",
        .implementor = "The Android Open Source Project",
        .create_effect = PreProcessingLib_Create,
        .release_effect = PreProcessingLib_Release,
        .get_descriptor = PreProcessingLib_GetDescriptor};

};  // extern "C"
