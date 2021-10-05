/*
 * Copyright (C) 2012 The Android Open Source Project
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

#define LOG_TAG "EffectDownmix"
//#define LOG_NDEBUG 0
#include <log/log.h>

#include "EffectDownmix.h"
#include <audio_utils/ChannelMix.h>

// Do not submit with DOWNMIX_TEST_CHANNEL_INDEX defined, strictly for testing
//#define DOWNMIX_TEST_CHANNEL_INDEX 0
// Do not submit with DOWNMIX_ALWAYS_USE_GENERIC_DOWNMIXER defined, strictly for testing
//#define DOWNMIX_ALWAYS_USE_GENERIC_DOWNMIXER 0

#define MINUS_3_DB_IN_FLOAT M_SQRT1_2 // -3dB = 0.70710678

typedef enum {
    DOWNMIX_STATE_UNINITIALIZED,
    DOWNMIX_STATE_INITIALIZED,
    DOWNMIX_STATE_ACTIVE,
} downmix_state_t;

/* parameters for each downmixer */
struct downmix_object_t {
    downmix_state_t state;
    downmix_type_t type;
    bool apply_volume_correction;
    uint8_t input_channel_count;
    android::audio_utils::channels::ChannelMix channelMix;
};

typedef struct downmix_module_s {
    const struct effect_interface_s *itfe;
    effect_config_t config;
    downmix_object_t context;
} downmix_module_t;


// Audio Effect API
static int32_t DownmixLib_Create(const effect_uuid_t *uuid,
        int32_t sessionId,
        int32_t ioId,
        effect_handle_t *pHandle);
static int32_t DownmixLib_Release(effect_handle_t handle);
static int32_t DownmixLib_GetDescriptor(const effect_uuid_t *uuid,
        effect_descriptor_t *pDescriptor);
static int32_t Downmix_Process(effect_handle_t self,
        audio_buffer_t *inBuffer,
        audio_buffer_t *outBuffer);
static int32_t Downmix_Command(effect_handle_t self,
        uint32_t cmdCode,
        uint32_t cmdSize,
        void *pCmdData,
        uint32_t *replySize,
        void *pReplyData);
static int32_t Downmix_GetDescriptor(effect_handle_t self,
        effect_descriptor_t *pDescriptor);

// Internal methods
static int Downmix_Init(downmix_module_t *pDwmModule);
static int Downmix_Configure(downmix_module_t *pDwmModule, effect_config_t *pConfig, bool init);
static int Downmix_Reset(downmix_object_t *pDownmixer, bool init);
static int Downmix_setParameter(
        downmix_object_t *pDownmixer, int32_t param, uint32_t size, void *pValue);
static int Downmix_getParameter(
        downmix_object_t *pDownmixer, int32_t param, uint32_t *pSize, void *pValue);

// effect_handle_t interface implementation for downmix effect
const struct effect_interface_s gDownmixInterface = {
        Downmix_Process,
        Downmix_Command,
        Downmix_GetDescriptor,
        NULL /* no process_reverse function, no reference stream needed */
};

// This is the only symbol that needs to be exported
__attribute__ ((visibility ("default")))
audio_effect_library_t AUDIO_EFFECT_LIBRARY_INFO_SYM = {
    .tag = AUDIO_EFFECT_LIBRARY_TAG,
    .version = EFFECT_LIBRARY_API_VERSION,
    .name = "Downmix Library",
    .implementor = "The Android Open Source Project",
    .create_effect = DownmixLib_Create,
    .release_effect = DownmixLib_Release,
    .get_descriptor = DownmixLib_GetDescriptor,
};

// AOSP insert downmix UUID: 93f04452-e4fe-41cc-91f9-e475b6d1d69f
static const effect_descriptor_t gDownmixDescriptor = {
        EFFECT_UIID_DOWNMIX__, //type
        {0x93f04452, 0xe4fe, 0x41cc, 0x91f9, {0xe4, 0x75, 0xb6, 0xd1, 0xd6, 0x9f}}, // uuid
        EFFECT_CONTROL_API_VERSION,
        EFFECT_FLAG_TYPE_INSERT | EFFECT_FLAG_INSERT_FIRST,
        0, //FIXME what value should be reported? // cpu load
        0, //FIXME what value should be reported? // memory usage
        "Multichannel Downmix To Stereo", // human readable effect name
        "The Android Open Source Project" // human readable effect implementor name
};

// gDescriptors contains pointers to all defined effect descriptor in this library
static const effect_descriptor_t * const gDescriptors[] = {
        &gDownmixDescriptor
};

// number of effects in this library
const int kNbEffects = sizeof(gDescriptors) / sizeof(const effect_descriptor_t *);

static inline float clamp_float(float value) {
    return fmin(fmax(value, -1.f), 1.f);
}

/*----------------------------------------------------------------------------
 * Test code
 *--------------------------------------------------------------------------*/
#ifdef DOWNMIX_TEST_CHANNEL_INDEX
// strictly for testing, logs the indices of the channels for a given mask,
// uses the same code as Downmix_foldGeneric()
void Downmix_testIndexComputation(uint32_t mask) {
    ALOGI("Testing index computation for %#x:", mask);
    // check against unsupported channels
    if (mask & kUnsupported) {
        ALOGE("Unsupported channels (top or front left/right of center)");
        return;
    }
    // verify has FL/FR
    if ((mask & AUDIO_CHANNEL_OUT_STEREO) != AUDIO_CHANNEL_OUT_STEREO) {
        ALOGE("Front channels must be present");
        return;
    }
    // verify uses SIDE as a pair (ok if not using SIDE at all)
    bool hasSides = false;
    if ((mask & kSides) != 0) {
        if ((mask & kSides) != kSides) {
            ALOGE("Side channels must be used as a pair");
            return;
        }
        hasSides = true;
    }
    // verify uses BACK as a pair (ok if not using BACK at all)
    bool hasBacks = false;
    if ((mask & kBacks) != 0) {
        if ((mask & kBacks) != kBacks) {
            ALOGE("Back channels must be used as a pair");
            return;
        }
        hasBacks = true;
    }

    const int numChan = audio_channel_count_from_out_mask(mask);
    const bool hasFC = ((mask & AUDIO_CHANNEL_OUT_FRONT_CENTER) == AUDIO_CHANNEL_OUT_FRONT_CENTER);
    const bool hasLFE =
            ((mask & AUDIO_CHANNEL_OUT_LOW_FREQUENCY) == AUDIO_CHANNEL_OUT_LOW_FREQUENCY);
    const bool hasBC = ((mask & AUDIO_CHANNEL_OUT_BACK_CENTER) == AUDIO_CHANNEL_OUT_BACK_CENTER);
    // compute at what index each channel is: samples will be in the following order:
    //   FL FR FC LFE BL BR BC SL SR
    // when a channel is not present, its index is set to the same as the index of the preceding
    // channel
    const int indexFC  = hasFC    ? 2            : 1;        // front center
    const int indexLFE = hasLFE   ? indexFC + 1  : indexFC;  // low frequency
    const int indexBL  = hasBacks ? indexLFE + 1 : indexLFE; // back left
    const int indexBR  = hasBacks ? indexBL + 1  : indexBL;  // back right
    const int indexBC  = hasBC    ? indexBR + 1  : indexBR;  // back center
    const int indexSL  = hasSides ? indexBC + 1  : indexBC;  // side left
    const int indexSR  = hasSides ? indexSL + 1  : indexSL;  // side right

    ALOGI("  FL FR FC LFE BL BR BC SL SR");
    ALOGI("   %d  %d  %d   %d  %d  %d  %d  %d  %d",
            0, 1, indexFC, indexLFE, indexBL, indexBR, indexBC, indexSL, indexSR);
}
#endif

static bool Downmix_validChannelMask(uint32_t mask)
{
    if (!mask) {
        return false;
    }
    // check against unsupported channels (up to FCC_26)
    constexpr uint32_t MAXIMUM_CHANNEL_MASK = AUDIO_CHANNEL_OUT_22POINT2
            | AUDIO_CHANNEL_OUT_FRONT_WIDE_LEFT | AUDIO_CHANNEL_OUT_FRONT_WIDE_RIGHT;
    if (mask & ~MAXIMUM_CHANNEL_MASK) {
        ALOGE("Unsupported channels in %#x", mask & ~MAXIMUM_CHANNEL_MASK);
        return false;
    }
    return true;
}

/*----------------------------------------------------------------------------
 * Effect API implementation
 *--------------------------------------------------------------------------*/

/*--- Effect Library Interface Implementation ---*/

static int32_t DownmixLib_Create(const effect_uuid_t *uuid,
        int32_t /* sessionId */,
        int32_t /* ioId */,
        effect_handle_t *pHandle) {
    int ret;
    int i;
    downmix_module_t *module;
    const effect_descriptor_t *desc;

    ALOGV("DownmixLib_Create()");

#ifdef DOWNMIX_TEST_CHANNEL_INDEX
    // should work (won't log an error)
    ALOGI("DOWNMIX_TEST_CHANNEL_INDEX: should work:");
    Downmix_testIndexComputation(AUDIO_CHANNEL_OUT_FRONT_LEFT | AUDIO_CHANNEL_OUT_FRONT_RIGHT |
                    AUDIO_CHANNEL_OUT_LOW_FREQUENCY | AUDIO_CHANNEL_OUT_BACK_CENTER);
    Downmix_testIndexComputation(AUDIO_CHANNEL_OUT_QUAD_SIDE | AUDIO_CHANNEL_OUT_QUAD_BACK);
    Downmix_testIndexComputation(AUDIO_CHANNEL_OUT_5POINT1_SIDE | AUDIO_CHANNEL_OUT_BACK_CENTER);
    Downmix_testIndexComputation(AUDIO_CHANNEL_OUT_5POINT1_BACK | AUDIO_CHANNEL_OUT_BACK_CENTER);
    // shouldn't work (will log an error, won't display channel indices)
    ALOGI("DOWNMIX_TEST_CHANNEL_INDEX: should NOT work:");
    Downmix_testIndexComputation(AUDIO_CHANNEL_OUT_FRONT_LEFT | AUDIO_CHANNEL_OUT_FRONT_RIGHT |
                        AUDIO_CHANNEL_OUT_LOW_FREQUENCY | AUDIO_CHANNEL_OUT_BACK_LEFT);
    Downmix_testIndexComputation(AUDIO_CHANNEL_OUT_FRONT_LEFT | AUDIO_CHANNEL_OUT_FRONT_RIGHT |
                            AUDIO_CHANNEL_OUT_LOW_FREQUENCY | AUDIO_CHANNEL_OUT_SIDE_LEFT);
    Downmix_testIndexComputation(AUDIO_CHANNEL_OUT_FRONT_LEFT |
                        AUDIO_CHANNEL_OUT_BACK_LEFT | AUDIO_CHANNEL_OUT_BACK_RIGHT);
    Downmix_testIndexComputation(AUDIO_CHANNEL_OUT_FRONT_LEFT |
                            AUDIO_CHANNEL_OUT_SIDE_LEFT | AUDIO_CHANNEL_OUT_SIDE_RIGHT);
#endif

    if (pHandle == NULL || uuid == NULL) {
        return -EINVAL;
    }

    for (i = 0 ; i < kNbEffects ; i++) {
        desc = gDescriptors[i];
        if (memcmp(uuid, &desc->uuid, sizeof(effect_uuid_t)) == 0) {
            break;
        }
    }

    if (i == kNbEffects) {
        return -ENOENT;
    }

    module = new downmix_module_t{};

    module->itfe = &gDownmixInterface;

    module->context.state = DOWNMIX_STATE_UNINITIALIZED;

    ret = Downmix_Init(module);
    if (ret < 0) {
        ALOGW("DownmixLib_Create() init failed");
        free(module);
        return ret;
    }

    *pHandle = (effect_handle_t) module;

    ALOGV("DownmixLib_Create() %p , size %zu", module, sizeof(downmix_module_t));

    return 0;
}

static int32_t DownmixLib_Release(effect_handle_t handle) {
    downmix_module_t *pDwmModule = (downmix_module_t *)handle;

    ALOGV("DownmixLib_Release() %p", handle);
    if (handle == NULL) {
        return -EINVAL;
    }

    pDwmModule->context.state = DOWNMIX_STATE_UNINITIALIZED;

    delete pDwmModule;
    return 0;
}

static int32_t DownmixLib_GetDescriptor(
        const effect_uuid_t *uuid, effect_descriptor_t *pDescriptor) {
    ALOGV("DownmixLib_GetDescriptor()");
    int i;

    if (pDescriptor == NULL || uuid == NULL){
        ALOGE("DownmixLib_Create() called with NULL pointer");
        return -EINVAL;
    }
    ALOGV("DownmixLib_GetDescriptor() nb effects=%d", kNbEffects);
    for (i = 0; i < kNbEffects; i++) {
        ALOGV("DownmixLib_GetDescriptor() i=%d", i);
        if (memcmp(uuid, &gDescriptors[i]->uuid, sizeof(effect_uuid_t)) == 0) {
            memcpy(pDescriptor, gDescriptors[i], sizeof(effect_descriptor_t));
            ALOGV("EffectGetDescriptor - UUID matched downmix type %d, UUID = %#x",
                 i, gDescriptors[i]->uuid.timeLow);
            return 0;
        }
    }

    return -EINVAL;
}

/*--- Effect Control Interface Implementation ---*/

static int32_t Downmix_Process(effect_handle_t self,
        audio_buffer_t *inBuffer, audio_buffer_t *outBuffer) {

    downmix_object_t *pDownmixer;
    const float *pSrc;
    float *pDst;
    downmix_module_t *pDwmModule = (downmix_module_t *)self;

    if (pDwmModule == NULL) {
        return -EINVAL;
    }

    if (inBuffer == NULL || inBuffer->raw == NULL ||
        outBuffer == NULL || outBuffer->raw == NULL ||
        inBuffer->frameCount != outBuffer->frameCount) {
        return -EINVAL;
    }

    pDownmixer = (downmix_object_t*) &pDwmModule->context;

    if (pDownmixer->state == DOWNMIX_STATE_UNINITIALIZED) {
        ALOGE("Downmix_Process error: trying to use an uninitialized downmixer");
        return -EINVAL;
    } else if (pDownmixer->state == DOWNMIX_STATE_INITIALIZED) {
        ALOGE("Downmix_Process error: trying to use a non-configured downmixer");
        return -ENODATA;
    }

    pSrc = inBuffer->f32;
    pDst = outBuffer->f32;
    size_t numFrames = outBuffer->frameCount;

    const bool accumulate =
            (pDwmModule->config.outputCfg.accessMode == EFFECT_BUFFER_ACCESS_ACCUMULATE);
    const audio_channel_mask_t downmixInputChannelMask =
            (audio_channel_mask_t)pDwmModule->config.inputCfg.channels;

    switch(pDownmixer->type) {

      case DOWNMIX_TYPE_STRIP:
          if (accumulate) {
              while (numFrames) {
                  pDst[0] = clamp_float(pDst[0] + pSrc[0]);
                  pDst[1] = clamp_float(pDst[1] + pSrc[1]);
                  pSrc += pDownmixer->input_channel_count;
                  pDst += 2;
                  numFrames--;
              }
          } else {
              while (numFrames) {
                  pDst[0] = pSrc[0];
                  pDst[1] = pSrc[1];
                  pSrc += pDownmixer->input_channel_count;
                  pDst += 2;
                  numFrames--;
              }
          }
          break;

      case DOWNMIX_TYPE_FOLD: {
            if (!pDownmixer->channelMix.process(
                    pSrc, pDst, numFrames, accumulate, downmixInputChannelMask)) {
                ALOGE("Multichannel configuration %#x is not supported",
                      downmixInputChannelMask);
                return -EINVAL;
            }
        }
        break;

      default:
        return -EINVAL;
    }

    return 0;
}

static int32_t Downmix_Command(effect_handle_t self, uint32_t cmdCode, uint32_t cmdSize,
        void *pCmdData, uint32_t *replySize, void *pReplyData) {

    downmix_module_t *pDwmModule = (downmix_module_t *) self;
    downmix_object_t *pDownmixer;

    if (pDwmModule == NULL || pDwmModule->context.state == DOWNMIX_STATE_UNINITIALIZED) {
        return -EINVAL;
    }

    pDownmixer = (downmix_object_t*) &pDwmModule->context;

    ALOGV("Downmix_Command command %u cmdSize %u", cmdCode, cmdSize);

    switch (cmdCode) {
    case EFFECT_CMD_INIT:
        if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
            return -EINVAL;
        }
        *(int *) pReplyData = Downmix_Init(pDwmModule);
        break;

    case EFFECT_CMD_SET_CONFIG:
        if (pCmdData == NULL || cmdSize != sizeof(effect_config_t)
                || pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
            return -EINVAL;
        }
        *(int *) pReplyData = Downmix_Configure(pDwmModule,
                (effect_config_t *)pCmdData, false);
        break;

    case EFFECT_CMD_RESET:
        Downmix_Reset(pDownmixer, false);
        break;

    case EFFECT_CMD_GET_PARAM: {
        ALOGV("Downmix_Command EFFECT_CMD_GET_PARAM pCmdData %p, *replySize %u, pReplyData: %p",
                pCmdData, *replySize, pReplyData);
        if (pCmdData == NULL || cmdSize < (int)(sizeof(effect_param_t) + sizeof(int32_t)) ||
                pReplyData == NULL || replySize == NULL ||
                *replySize < (int) sizeof(effect_param_t) + 2 * sizeof(int32_t)) {
            return -EINVAL;
        }
        effect_param_t *rep = (effect_param_t *) pReplyData;
        memcpy(pReplyData, pCmdData, sizeof(effect_param_t) + sizeof(int32_t));
        ALOGV("Downmix_Command EFFECT_CMD_GET_PARAM param %d, replySize %u",
                *(int32_t *)rep->data, rep->vsize);
        rep->status = Downmix_getParameter(pDownmixer, *(int32_t *)rep->data, &rep->vsize,
                rep->data + sizeof(int32_t));
        *replySize = sizeof(effect_param_t) + sizeof(int32_t) + rep->vsize;
        break;
    }
    case EFFECT_CMD_SET_PARAM: {
        ALOGV("Downmix_Command EFFECT_CMD_SET_PARAM cmdSize %d pCmdData %p, *replySize %u"
                ", pReplyData %p", cmdSize, pCmdData, *replySize, pReplyData);
        if (pCmdData == NULL || (cmdSize < (int)(sizeof(effect_param_t) + sizeof(int32_t)))
                || pReplyData == NULL || replySize == NULL || *replySize != (int)sizeof(int32_t)) {
            return -EINVAL;
        }
        effect_param_t *cmd = (effect_param_t *) pCmdData;
        if (cmd->psize != sizeof(int32_t)) {
            android_errorWriteLog(0x534e4554, "63662938");
            return -EINVAL;
        }
        *(int *)pReplyData = Downmix_setParameter(pDownmixer, *(int32_t *)cmd->data,
                cmd->vsize, cmd->data + sizeof(int32_t));
        break;
    }

    case EFFECT_CMD_SET_PARAM_DEFERRED:
        //FIXME implement
        ALOGW("Downmix_Command command EFFECT_CMD_SET_PARAM_DEFERRED not supported, FIXME");
        break;

    case EFFECT_CMD_SET_PARAM_COMMIT:
        //FIXME implement
        ALOGW("Downmix_Command command EFFECT_CMD_SET_PARAM_COMMIT not supported, FIXME");
        break;

    case EFFECT_CMD_ENABLE:
        if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
            return -EINVAL;
        }
        if (pDownmixer->state != DOWNMIX_STATE_INITIALIZED) {
            return -ENOSYS;
        }
        pDownmixer->state = DOWNMIX_STATE_ACTIVE;
        ALOGV("EFFECT_CMD_ENABLE() OK");
        *(int *)pReplyData = 0;
        break;

    case EFFECT_CMD_DISABLE:
        if (pReplyData == NULL || replySize == NULL || *replySize != sizeof(int)) {
            return -EINVAL;
        }
        if (pDownmixer->state != DOWNMIX_STATE_ACTIVE) {
            return -ENOSYS;
        }
        pDownmixer->state = DOWNMIX_STATE_INITIALIZED;
        ALOGV("EFFECT_CMD_DISABLE() OK");
        *(int *)pReplyData = 0;
        break;

    case EFFECT_CMD_SET_DEVICE:
        if (pCmdData == NULL || cmdSize != (int)sizeof(uint32_t)) {
            return -EINVAL;
        }
        // FIXME change type if playing on headset vs speaker
        ALOGV("Downmix_Command EFFECT_CMD_SET_DEVICE: %#x", *(uint32_t *)pCmdData);
        break;

    case EFFECT_CMD_SET_VOLUME: {
        // audio output is always stereo => 2 channel volumes
        if (pCmdData == NULL || cmdSize != (int)sizeof(uint32_t) * 2) {
            return -EINVAL;
        }
        // FIXME change volume
        ALOGW("Downmix_Command command EFFECT_CMD_SET_VOLUME not supported, FIXME");
        float left = (float)(*(uint32_t *)pCmdData) / (1 << 24);
        float right = (float)(*((uint32_t *)pCmdData + 1)) / (1 << 24);
        ALOGV("Downmix_Command EFFECT_CMD_SET_VOLUME: left %f, right %f ", left, right);
        break;
    }

    case EFFECT_CMD_SET_AUDIO_MODE:
        if (pCmdData == NULL || cmdSize != (int)sizeof(uint32_t)) {
            return -EINVAL;
        }
        ALOGV("Downmix_Command EFFECT_CMD_SET_AUDIO_MODE: %u", *(uint32_t *)pCmdData);
        break;

    case EFFECT_CMD_SET_CONFIG_REVERSE:
    case EFFECT_CMD_SET_INPUT_DEVICE:
        // these commands are ignored by a downmix effect
        break;

    default:
        ALOGW("Downmix_Command invalid command %u", cmdCode);
        return -EINVAL;
    }

    return 0;
}

static int32_t Downmix_GetDescriptor(effect_handle_t self, effect_descriptor_t *pDescriptor)
{
    downmix_module_t *pDwnmxModule = (downmix_module_t *) self;

    if (pDwnmxModule == NULL ||
            pDwnmxModule->context.state == DOWNMIX_STATE_UNINITIALIZED) {
        return -EINVAL;
    }

    memcpy(pDescriptor, &gDownmixDescriptor, sizeof(effect_descriptor_t));

    return 0;
}


/*----------------------------------------------------------------------------
 * Downmix internal functions
 *--------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------
 * Downmix_Init()
 *----------------------------------------------------------------------------
 * Purpose:
 * Initialize downmix context and apply default parameters
 *
 * Inputs:
 *  pDwmModule    pointer to downmix effect module
 *
 * Outputs:
 *
 * Returns:
 *  0             indicates success
 *
 * Side Effects:
 *  updates:
 *           pDwmModule->context.type
 *           pDwmModule->context.apply_volume_correction
 *           pDwmModule->config.inputCfg
 *           pDwmModule->config.outputCfg
 *           pDwmModule->config.inputCfg.samplingRate
 *           pDwmModule->config.outputCfg.samplingRate
 *           pDwmModule->context.state
 *  doesn't set:
 *           pDwmModule->itfe
 *
 *----------------------------------------------------------------------------
 */

static int Downmix_Init(downmix_module_t *pDwmModule) {

    ALOGV("Downmix_Init module %p", pDwmModule);
    int ret = 0;

    memset(&pDwmModule->context, 0, sizeof(downmix_object_t));

    pDwmModule->config.inputCfg.accessMode = EFFECT_BUFFER_ACCESS_READ;
    pDwmModule->config.inputCfg.format = AUDIO_FORMAT_PCM_FLOAT;
    pDwmModule->config.inputCfg.channels = AUDIO_CHANNEL_OUT_7POINT1;
    pDwmModule->config.inputCfg.bufferProvider.getBuffer = NULL;
    pDwmModule->config.inputCfg.bufferProvider.releaseBuffer = NULL;
    pDwmModule->config.inputCfg.bufferProvider.cookie = NULL;
    pDwmModule->config.inputCfg.mask = EFFECT_CONFIG_ALL;

    pDwmModule->config.inputCfg.samplingRate = 44100;
    pDwmModule->config.outputCfg.samplingRate = pDwmModule->config.inputCfg.samplingRate;

    // set a default value for the access mode, but should be overwritten by caller
    pDwmModule->config.outputCfg.accessMode = EFFECT_BUFFER_ACCESS_ACCUMULATE;
    pDwmModule->config.outputCfg.format = AUDIO_FORMAT_PCM_FLOAT;
    pDwmModule->config.outputCfg.channels = AUDIO_CHANNEL_OUT_STEREO;
    pDwmModule->config.outputCfg.bufferProvider.getBuffer = NULL;
    pDwmModule->config.outputCfg.bufferProvider.releaseBuffer = NULL;
    pDwmModule->config.outputCfg.bufferProvider.cookie = NULL;
    pDwmModule->config.outputCfg.mask = EFFECT_CONFIG_ALL;

    ret = Downmix_Configure(pDwmModule, &pDwmModule->config, true);
    if (ret != 0) {
        ALOGV("Downmix_Init error %d on module %p", ret, pDwmModule);
    } else {
        pDwmModule->context.state = DOWNMIX_STATE_INITIALIZED;
    }

    return ret;
}


/*----------------------------------------------------------------------------
 * Downmix_Configure()
 *----------------------------------------------------------------------------
 * Purpose:
 *  Set input and output audio configuration.
 *
 * Inputs:
 *  pDwmModule  pointer to downmix effect module
 *  pConfig     pointer to effect_config_t structure containing input
 *                  and output audio parameters configuration
 *  init        true if called from init function
 *
 * Outputs:
 *
 * Returns:
 *  0           indicates success
 *
 * Side Effects:
 *
 *----------------------------------------------------------------------------
 */

static int Downmix_Configure(downmix_module_t *pDwmModule, effect_config_t *pConfig, bool init) {

    downmix_object_t *pDownmixer = &pDwmModule->context;

    // Check configuration compatibility with build options, and effect capabilities
    if (pConfig->inputCfg.samplingRate != pConfig->outputCfg.samplingRate
        || pConfig->outputCfg.channels != AUDIO_CHANNEL_OUT_STEREO
        || pConfig->inputCfg.format != AUDIO_FORMAT_PCM_FLOAT
        || pConfig->outputCfg.format != AUDIO_FORMAT_PCM_FLOAT) {
        ALOGE("Downmix_Configure error: invalid config");
        return -EINVAL;
    }
    // when configuring the effect, do not allow a blank or unsupported channel mask
    if (!Downmix_validChannelMask(pConfig->inputCfg.channels)) {
        ALOGE("Downmix_Configure error: input channel mask(0x%x) not supported",
                                                    pConfig->inputCfg.channels);
        return -EINVAL;
    }

    if (&pDwmModule->config != pConfig) {
        memcpy(&pDwmModule->config, pConfig, sizeof(effect_config_t));
    }

    if (init) {
        pDownmixer->type = DOWNMIX_TYPE_FOLD;
        pDownmixer->apply_volume_correction = false;
        pDownmixer->input_channel_count = 8; // matches default input of AUDIO_CHANNEL_OUT_7POINT1
    } else {
        pDownmixer->input_channel_count =
                audio_channel_count_from_out_mask(pConfig->inputCfg.channels);
    }

    Downmix_Reset(pDownmixer, init);

    return 0;
}


/*----------------------------------------------------------------------------
 * Downmix_Reset()
 *----------------------------------------------------------------------------
 * Purpose:
 *  Reset internal states.
 *
 * Inputs:
 *  pDownmixer   pointer to downmix context
 *  init         true if called from init function
 *
 * Outputs:
*
 * Returns:
 *  0            indicates success
 *
 * Side Effects:
 *
 *----------------------------------------------------------------------------
 */

static int Downmix_Reset(downmix_object_t* /* pDownmixer */, bool /* init */) {
    // nothing to do here
    return 0;
}


/*----------------------------------------------------------------------------
 * Downmix_setParameter()
 *----------------------------------------------------------------------------
 * Purpose:
 * Set a Downmix parameter
 *
 * Inputs:
 *  pDownmixer    handle to instance data
 *  param         parameter
 *  pValue        pointer to parameter value
 *  size          value size
 *
 * Outputs:
 *
 * Returns:
 *  0             indicates success
 *
 * Side Effects:
 *
 *----------------------------------------------------------------------------
 */
static int Downmix_setParameter(
        downmix_object_t *pDownmixer, int32_t param, uint32_t size, void *pValue) {

    int16_t value16;
    ALOGV("Downmix_setParameter, context %p, param %d, value16 %d, value32 %d",
            pDownmixer, param, *(int16_t *)pValue, *(int32_t *)pValue);

    switch (param) {

      case DOWNMIX_PARAM_TYPE:
        if (size != sizeof(downmix_type_t)) {
            ALOGE("Downmix_setParameter(DOWNMIX_PARAM_TYPE) invalid size %u, should be %zu",
                    size, sizeof(downmix_type_t));
            return -EINVAL;
        }
        value16 = *(int16_t *)pValue;
        ALOGV("set DOWNMIX_PARAM_TYPE, type %d", value16);
        if (!((value16 > DOWNMIX_TYPE_INVALID) && (value16 <= DOWNMIX_TYPE_LAST))) {
            ALOGE("Downmix_setParameter invalid DOWNMIX_PARAM_TYPE value %d", value16);
            return -EINVAL;
        } else {
            pDownmixer->type = (downmix_type_t) value16;
        break;

      default:
        ALOGE("Downmix_setParameter unknown parameter %d", param);
        return -EINVAL;
    }
}

    return 0;
} /* end Downmix_setParameter */

/*----------------------------------------------------------------------------
 * Downmix_getParameter()
 *----------------------------------------------------------------------------
 * Purpose:
 * Get a Downmix parameter
 *
 * Inputs:
 *  pDownmixer    handle to instance data
 *  param         parameter
 *  pValue        pointer to variable to hold retrieved value
 *  pSize         pointer to value size: maximum size as input
 *
 * Outputs:
 *  *pValue updated with parameter value
 *  *pSize updated with actual value size
 *
 * Returns:
 *  0             indicates success
 *
 * Side Effects:
 *
 *----------------------------------------------------------------------------
 */
static int Downmix_getParameter(
        downmix_object_t *pDownmixer, int32_t param, uint32_t *pSize, void *pValue) {
    int16_t *pValue16;

    switch (param) {

    case DOWNMIX_PARAM_TYPE:
      if (*pSize < sizeof(int16_t)) {
          ALOGE("Downmix_getParameter invalid parameter size %u for DOWNMIX_PARAM_TYPE", *pSize);
          return -EINVAL;
      }
      pValue16 = (int16_t *)pValue;
      *pValue16 = (int16_t) pDownmixer->type;
      *pSize = sizeof(int16_t);
      ALOGV("Downmix_getParameter DOWNMIX_PARAM_TYPE is %d", *pValue16);
      break;

    default:
      ALOGE("Downmix_getParameter unknown parameter %d", param);
      return -EINVAL;
    }

    return 0;
} /* end Downmix_getParameter */

