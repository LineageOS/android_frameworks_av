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
#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

#include <audio_utils/channels.h>
#include <audio_utils/primitives.h>
#include <log/log.h>

#include "EffectBundle.h"
#include "LVM_Private.h"

#ifdef VERY_VERY_VERBOSE_LOGGING
#define ALOGVV ALOGV
#else
#define ALOGVV(a...) \
  do {               \
  } while (false)
#endif

#define CHECK_ARG(cond)                                \
  {                                                    \
    if (!(cond)) {                                     \
      ALOGE("\tLVM_ERROR : Invalid argument: " #cond); \
      return -EINVAL;                                  \
    }                                                  \
  \
}

#define LVM_ERROR_CHECK(LvmStatus, callingFunc, calledFunc)     \
  {                                                             \
    if ((LvmStatus) == LVM_NULLADDRESS) {                       \
      ALOGE(                                                    \
          "\tLVM_ERROR : Parameter error - "                    \
          "null pointer returned by %s in %s\n\n\n\n",          \
          callingFunc, calledFunc);                             \
    }                                                           \
    if ((LvmStatus) == LVM_ALIGNMENTERROR) {                    \
      ALOGE(                                                    \
          "\tLVM_ERROR : Parameter error - "                    \
          "bad alignment returned by %s in %s\n\n\n\n",         \
          callingFunc, calledFunc);                             \
    }                                                           \
    if ((LvmStatus) == LVM_INVALIDNUMSAMPLES) {                 \
      ALOGE(                                                    \
          "\tLVM_ERROR : Parameter error - "                    \
          "bad number of samples returned by %s in %s\n\n\n\n", \
          callingFunc, calledFunc);                             \
    }                                                           \
    if ((LvmStatus) == LVM_OUTOFRANGE) {                        \
      ALOGE(                                                    \
          "\tLVM_ERROR : Parameter error - "                    \
          "out of range returned by %s in %s\n",                \
          callingFunc, calledFunc);                             \
    }                                                           \
  }

struct lvmConfigParams_t {
  int              samplingFreq    = 44100;
  int              nrChannels      = 2;
  int              fChannels       = 2;
  int              bassEffectLevel = 0;
  int              eqPresetLevel   = 0;
  int              frameLength     = 256;
  LVM_BE_Mode_en   bassEnable      = LVM_BE_OFF;
  LVM_TE_Mode_en   trebleEnable    = LVM_TE_OFF;
  LVM_EQNB_Mode_en eqEnable        = LVM_EQNB_OFF;
  LVM_Mode_en      csEnable        = LVM_MODE_OFF;
};

void printUsage() {
  printf("\nUsage: ");
  printf("\n     <exceutable> -i:<input_file> -o:<out_file> [options]\n");
  printf("\nwhere, \n     <inputfile>  is the input file name");
  printf("\n                  on which LVM effects are applied");
  printf("\n     <outputfile> processed output file");
  printf("\n     and options are mentioned below");
  printf("\n");
  printf("\n     -help (or) -h");
  printf("\n           Prints this usage information");
  printf("\n");
  printf("\n     -ch:<process_channels> (1 through 8)\n\n");
  printf("\n     -fch:<file_channels> (1 through 8)\n\n");
  printf("\n     -basslvl:<effect_level>");
  printf("\n           A value that ranges between 0 - 15 default 0");
  printf("\n");
  printf("\n     -eqPreset:<preset Value>");
  printf("\n           0 - Normal");
  printf("\n           1 - Classical");
  printf("\n           2 - Dance");
  printf("\n           3 - Flat");
  printf("\n           4 - Folk");
  printf("\n           5 - Heavy Metal");
  printf("\n           6 - Hip Hop");
  printf("\n           7 - Jazz");
  printf("\n           8 - Pop");
  printf("\n           9 - Rock");
  printf("\n           default 0");
  printf("\n     -bE ");
  printf("\n           Enable Dynamic Bass Enhancement");
  printf("\n");
  printf("\n     -tE ");
  printf("\n           Enable Treble Boost");
  printf("\n");
  printf("\n     -csE ");
  printf("\n           Enable Concert Surround");
  printf("\n");
  printf("\n     -eqE ");
  printf("\n           Enable Equalizer");
}

//----------------------------------------------------------------------------
// LvmEffect_free()
//----------------------------------------------------------------------------
// Purpose: Free all memory associated with the Bundle.
//
// Inputs:
//  pContext:   effect engine context
//
// Outputs:
//
//----------------------------------------------------------------------------

void LvmEffect_free(struct EffectContext *pContext) {
  LVM_ReturnStatus_en LvmStatus = LVM_SUCCESS; /* Function call status */
  LVM_MemTab_t MemTab;

  /* Free the algorithm memory */
  LvmStatus = LVM_GetMemoryTable(pContext->pBundledContext->hInstance, &MemTab,
                                 LVM_NULL);

  LVM_ERROR_CHECK(LvmStatus, "LVM_GetMemoryTable", "LvmEffect_free")

  for (int i = 0; i < LVM_NR_MEMORY_REGIONS; i++) {
    if (MemTab.Region[i].Size != 0) {
      if (MemTab.Region[i].pBaseAddress != NULL) {
        ALOGV("\tLvmEffect_free - START freeing %" PRIu32
              " bytes for region %u at %p\n",
              MemTab.Region[i].Size, i, MemTab.Region[i].pBaseAddress);

        free(MemTab.Region[i].pBaseAddress);

        ALOGV("\tLvmEffect_free - END   freeing %" PRIu32
              " bytes for region %u at %p\n",
              MemTab.Region[i].Size, i, MemTab.Region[i].pBaseAddress);
      } else {
        ALOGE(
            "\tLVM_ERROR : LvmEffect_free - trying to free with NULL pointer "
            "%" PRIu32 " bytes for region %u at %p ERROR\n",
            MemTab.Region[i].Size, i, MemTab.Region[i].pBaseAddress);
      }
    }
  }
} /* end LvmEffect_free */

//----------------------------------------------------------------------------
// LvmBundle_init()
//----------------------------------------------------------------------------
// Purpose: Initialize engine with default configuration, creates instance
// with all effects disabled.
//
// Inputs:
//  pContext:   effect engine context
//
// Outputs:
//
//----------------------------------------------------------------------------

int LvmBundle_init(struct EffectContext *pContext, LVM_ControlParams_t *params) {
  ALOGV("\tLvmBundle_init start");

  pContext->config.inputCfg.accessMode = EFFECT_BUFFER_ACCESS_READ;
  pContext->config.inputCfg.channels = AUDIO_CHANNEL_OUT_STEREO;
  pContext->config.inputCfg.format = EFFECT_BUFFER_FORMAT;
  pContext->config.inputCfg.samplingRate = 44100;
  pContext->config.inputCfg.bufferProvider.getBuffer = NULL;
  pContext->config.inputCfg.bufferProvider.releaseBuffer = NULL;
  pContext->config.inputCfg.bufferProvider.cookie = NULL;
  pContext->config.inputCfg.mask = EFFECT_CONFIG_ALL;
  pContext->config.outputCfg.accessMode = EFFECT_BUFFER_ACCESS_ACCUMULATE;
  pContext->config.outputCfg.channels = AUDIO_CHANNEL_OUT_STEREO;
  pContext->config.outputCfg.format = EFFECT_BUFFER_FORMAT;
  pContext->config.outputCfg.samplingRate = 44100;
  pContext->config.outputCfg.bufferProvider.getBuffer = NULL;
  pContext->config.outputCfg.bufferProvider.releaseBuffer = NULL;
  pContext->config.outputCfg.bufferProvider.cookie = NULL;
  pContext->config.outputCfg.mask = EFFECT_CONFIG_ALL;

  if (pContext->pBundledContext->hInstance != NULL) {
    ALOGV(
        "\tLvmBundle_init pContext->pBassBoost != NULL "
        "-> Calling pContext->pBassBoost->free()");

    LvmEffect_free(pContext);

    ALOGV(
        "\tLvmBundle_init pContext->pBassBoost != NULL "
        "-> Called pContext->pBassBoost->free()");
  }

  LVM_ReturnStatus_en LvmStatus = LVM_SUCCESS; /* Function call status */
  LVM_InstParams_t InstParams;                 /* Instance parameters */
  LVM_EQNB_BandDef_t BandDefs[MAX_NUM_BANDS];  /* Equaliser band definitions */
  LVM_HeadroomParams_t HeadroomParams;         /* Headroom parameters */
  LVM_HeadroomBandDef_t HeadroomBandDef[LVM_HEADROOM_MAX_NBANDS];
  LVM_MemTab_t MemTab; /* Memory allocation table */
  bool bMallocFailure = LVM_FALSE;

  /* Set the capabilities */
  InstParams.BufferMode = LVM_UNMANAGED_BUFFERS;
  InstParams.MaxBlockSize = MAX_CALL_SIZE;
  InstParams.EQNB_NumBands = MAX_NUM_BANDS;
  InstParams.PSA_Included = LVM_PSA_ON;

  /* Allocate memory, forcing alignment */
  LvmStatus = LVM_GetMemoryTable(LVM_NULL, &MemTab, &InstParams);

  LVM_ERROR_CHECK(LvmStatus, "LVM_GetMemoryTable", "LvmBundle_init");
  if (LvmStatus != LVM_SUCCESS) return -EINVAL;

  ALOGV("\tCreateInstance Succesfully called LVM_GetMemoryTable\n");

  /* Allocate memory */
  for (int i = 0; i < LVM_NR_MEMORY_REGIONS; i++) {
    if (MemTab.Region[i].Size != 0) {
      MemTab.Region[i].pBaseAddress = malloc(MemTab.Region[i].Size);

      if (MemTab.Region[i].pBaseAddress == LVM_NULL) {
        ALOGE(
            "\tLVM_ERROR :LvmBundle_init CreateInstance Failed to allocate "
            "%" PRIu32 " bytes for region %u\n",
            MemTab.Region[i].Size, i);
        bMallocFailure = LVM_TRUE;
        break;
      } else {
        ALOGV("\tLvmBundle_init CreateInstance allocated %" PRIu32
              " bytes for region %u at %p\n",
              MemTab.Region[i].Size, i, MemTab.Region[i].pBaseAddress);
      }
    }
  }

  /* If one or more of the memory regions failed to allocate, free the regions
   * that were
   * succesfully allocated and return with an error
   */
  if (bMallocFailure == LVM_TRUE) {
    for (int i = 0; i < LVM_NR_MEMORY_REGIONS; i++) {
      if (MemTab.Region[i].pBaseAddress == LVM_NULL) {
        ALOGE(
            "\tLVM_ERROR :LvmBundle_init CreateInstance Failed to allocate "
            "%" PRIu32 " bytes for region %u Not freeing\n",
            MemTab.Region[i].Size, i);
      } else {
        ALOGE(
            "\tLVM_ERROR :LvmBundle_init CreateInstance Failed: but allocated "
            "%" PRIu32 " bytes for region %u at %p- free\n",
            MemTab.Region[i].Size, i, MemTab.Region[i].pBaseAddress);
        free(MemTab.Region[i].pBaseAddress);
      }
    }
    return -EINVAL;
  }
  ALOGV("\tLvmBundle_init CreateInstance Succesfully malloc'd memory\n");

  /* Initialise */
  pContext->pBundledContext->hInstance = LVM_NULL;

  /* Init sets the instance handle */
  LvmStatus = LVM_GetInstanceHandle(&pContext->pBundledContext->hInstance,
                                    &MemTab, &InstParams);

  LVM_ERROR_CHECK(LvmStatus, "LVM_GetInstanceHandle", "LvmBundle_init");
  if (LvmStatus != LVM_SUCCESS) return -EINVAL;

  ALOGV(
      "\tLvmBundle_init CreateInstance Succesfully called "
      "LVM_GetInstanceHandle\n");

  /* Set the initial process parameters */
  /* General parameters */
  params->OperatingMode = LVM_MODE_ON;
  params->SampleRate = LVM_FS_44100;
  params->SourceFormat = LVM_STEREO;
  params->SpeakerType = LVM_HEADPHONES;

  pContext->pBundledContext->SampleRate = LVM_FS_44100;

  /* Concert Sound parameters */
  params->VirtualizerOperatingMode = LVM_MODE_OFF;
  params->VirtualizerType = LVM_CONCERTSOUND;
  params->VirtualizerReverbLevel = 100;
  params->CS_EffectLevel = LVM_CS_EFFECT_NONE;

  /* N-Band Equaliser parameters */
  params->EQNB_OperatingMode = LVM_EQNB_ON;
  params->EQNB_NBands = FIVEBAND_NUMBANDS;
  params->pEQNB_BandDefinition = &BandDefs[0];

  for (int i = 0; i < FIVEBAND_NUMBANDS; i++) {
    BandDefs[i].Frequency = EQNB_5BandPresetsFrequencies[i];
    BandDefs[i].QFactor = EQNB_5BandPresetsQFactors[i];
    BandDefs[i].Gain = EQNB_5BandSoftPresets[i];
  }

  /* Volume Control parameters */
  params->VC_EffectLevel = 0;
  params->VC_Balance = 0;

  /* Treble Enhancement parameters */
  params->TE_OperatingMode = LVM_TE_OFF;
  params->TE_EffectLevel = 0;

  /* PSA Control parameters */
  params->PSA_Enable = LVM_PSA_OFF;
  params->PSA_PeakDecayRate = (LVM_PSA_DecaySpeed_en)0;

  /* Bass Enhancement parameters */
  params->BE_OperatingMode = LVM_BE_ON;
  params->BE_EffectLevel = 0;
  params->BE_CentreFreq = LVM_BE_CENTRE_90Hz;
  params->BE_HPF = LVM_BE_HPF_ON;

  /* PSA Control parameters */
  params->PSA_Enable = LVM_PSA_OFF;
  params->PSA_PeakDecayRate = LVM_PSA_SPEED_MEDIUM;

  /* TE Control parameters */
  params->TE_OperatingMode = LVM_TE_OFF;
  params->TE_EffectLevel = 0;

  /* Activate the initial settings */
  LvmStatus =
      LVM_SetControlParameters(pContext->pBundledContext->hInstance, params);

  LVM_ERROR_CHECK(LvmStatus, "LVM_SetControlParameters", "LvmBundle_init");
  if (LvmStatus != LVM_SUCCESS) return -EINVAL;

  ALOGV(
      "\tLvmBundle_init CreateInstance Succesfully called "
      "LVM_SetControlParameters\n");

  /* Set the headroom parameters */
  HeadroomBandDef[0].Limit_Low = 20;
  HeadroomBandDef[0].Limit_High = 4999;
  HeadroomBandDef[0].Headroom_Offset = 0;
  HeadroomBandDef[1].Limit_Low = 5000;
  HeadroomBandDef[1].Limit_High = 24000;
  HeadroomBandDef[1].Headroom_Offset = 0;
  HeadroomParams.pHeadroomDefinition = &HeadroomBandDef[0];
  HeadroomParams.Headroom_OperatingMode = LVM_HEADROOM_ON;
  HeadroomParams.NHeadroomBands = 2;

  LvmStatus = LVM_SetHeadroomParams(pContext->pBundledContext->hInstance,
                                    &HeadroomParams);

  LVM_ERROR_CHECK(LvmStatus, "LVM_SetHeadroomParams", "LvmBundle_init");
  if (LvmStatus != LVM_SUCCESS) return -EINVAL;

  ALOGV(
      "\tLvmBundle_init CreateInstance Succesfully called "
      "LVM_SetHeadroomParams\n");
  ALOGV("\tLvmBundle_init End");
  return 0;
} /* end LvmBundle_init */

int lvmCreate(struct EffectContext *pContext,
              lvmConfigParams_t    *plvmConfigParams,
              LVM_ControlParams_t  *params) {
  int ret = 0;
  pContext->pBundledContext = NULL;
  pContext->pBundledContext = (BundledEffectContext *)malloc(sizeof(struct BundledEffectContext));
  if (NULL == pContext->pBundledContext) {
    return -EINVAL;
  }

  pContext->pBundledContext->SessionNo = 0;
  pContext->pBundledContext->SessionId = 0;
  pContext->pBundledContext->hInstance = NULL;
  pContext->pBundledContext->bVolumeEnabled = LVM_FALSE;
  pContext->pBundledContext->bEqualizerEnabled = LVM_FALSE;
  pContext->pBundledContext->bBassEnabled = LVM_FALSE;
  pContext->pBundledContext->bBassTempDisabled = LVM_FALSE;
  pContext->pBundledContext->bVirtualizerEnabled = LVM_FALSE;
  pContext->pBundledContext->bVirtualizerTempDisabled = LVM_FALSE;
  pContext->pBundledContext->nOutputDevice = AUDIO_DEVICE_NONE;
  pContext->pBundledContext->nVirtualizerForcedDevice = AUDIO_DEVICE_NONE;
  pContext->pBundledContext->NumberEffectsEnabled = 0;
  pContext->pBundledContext->NumberEffectsCalled = 0;
  pContext->pBundledContext->firstVolume = LVM_TRUE;
  pContext->pBundledContext->volume = 0;

  /* Saved strength is used to return the exact strength that was used in the
   * set to the get
   * because we map the original strength range of 0:1000 to 1:15, and this will
   * avoid
   * quantisation like effect when returning
   */
  pContext->pBundledContext->BassStrengthSaved = 0;
  pContext->pBundledContext->VirtStrengthSaved = 0;
  pContext->pBundledContext->CurPreset = PRESET_CUSTOM;
  pContext->pBundledContext->levelSaved = 0;
  pContext->pBundledContext->bMuteEnabled = LVM_FALSE;
  pContext->pBundledContext->bStereoPositionEnabled = LVM_FALSE;
  pContext->pBundledContext->positionSaved = 0;
  pContext->pBundledContext->workBuffer = NULL;
  pContext->pBundledContext->frameCount = -1;
  pContext->pBundledContext->SamplesToExitCountVirt = 0;
  pContext->pBundledContext->SamplesToExitCountBb = 0;
  pContext->pBundledContext->SamplesToExitCountEq = 0;
#if defined(BUILD_FLOAT) && !defined(NATIVE_FLOAT_BUFFER)
  pContext->pBundledContext->pInputBuffer = NULL;
  pContext->pBundledContext->pOutputBuffer = NULL;
#endif
  for (int i = 0; i < FIVEBAND_NUMBANDS; i++) {
    pContext->pBundledContext->bandGaindB[i] = EQNB_5BandSoftPresets[i];
  }
  pContext->config.inputCfg.channels = plvmConfigParams->nrChannels;
  ALOGV("\tEffectCreate - Calling LvmBundle_init");
  ret = LvmBundle_init(pContext, params);

  if (ret < 0) {
    ALOGE("\tLVM_ERROR : lvmCreate() Bundle init failed");
    return ret;
  }
  return 0;
}

int lvmControl(struct EffectContext *pContext,
               lvmConfigParams_t    *plvmConfigParams,
               LVM_ControlParams_t  *params) {
  LVM_ReturnStatus_en LvmStatus = LVM_SUCCESS; /* Function call status */

  /* Set the initial process parameters */
  /* General parameters */
  params->OperatingMode = LVM_MODE_ON;
  params->SpeakerType = LVM_HEADPHONES;

  const int nrChannels = plvmConfigParams->nrChannels;
  params->NrChannels = nrChannels;
  if (nrChannels == 1) {
    params->SourceFormat = LVM_MONO;
  } else if (nrChannels == 2) {
    params->SourceFormat = LVM_STEREO;
  } else if (nrChannels > 2 && nrChannels <= 8) { // FCC_2 FCC_8
    params->SourceFormat = LVM_MULTICHANNEL;
  } else {
      return -EINVAL;
  }

  LVM_Fs_en sampleRate;
  switch (plvmConfigParams->samplingFreq) {
    case 8000:
      sampleRate = LVM_FS_8000;
      break;
    case 11025:
      sampleRate = LVM_FS_11025;
      break;
    case 12000:
      sampleRate = LVM_FS_12000;
      break;
    case 16000:
      sampleRate = LVM_FS_16000;
      break;
    case 22050:
      sampleRate = LVM_FS_22050;
      break;
    case 24000:
      sampleRate = LVM_FS_24000;
      break;
    case 32000:
      sampleRate = LVM_FS_32000;
      break;
    case 44100:
      sampleRate = LVM_FS_44100;
      break;
    case 48000:
      sampleRate = LVM_FS_48000;
      break;
    case 88200:
      sampleRate = LVM_FS_88200;
      break;
    case 96000:
      sampleRate = LVM_FS_96000;
      break;
    case 176400:
      sampleRate = LVM_FS_176400;
      break;
    case 192000:
      sampleRate = LVM_FS_192000;
      break;
    default:
      return -EINVAL;
  }
  params->SampleRate = sampleRate;

  /* Concert Sound parameters */
  params->VirtualizerOperatingMode = plvmConfigParams->csEnable;
  params->VirtualizerType = LVM_CONCERTSOUND;
  params->VirtualizerReverbLevel = 100;
  params->CS_EffectLevel = LVM_CS_EFFECT_NONE;

  /* N-Band Equaliser parameters */
  const int eqPresetLevel = plvmConfigParams->eqPresetLevel;
  LVM_EQNB_BandDef_t BandDefs[MAX_NUM_BANDS];  /* Equaliser band definitions */
  for (int i = 0; i < FIVEBAND_NUMBANDS; i++) {
    BandDefs[i].Frequency = EQNB_5BandPresetsFrequencies[i];
    BandDefs[i].QFactor = EQNB_5BandPresetsQFactors[i];
    BandDefs[i].Gain =
        EQNB_5BandSoftPresets[(FIVEBAND_NUMBANDS * eqPresetLevel) + i];
  }
  params->EQNB_OperatingMode = plvmConfigParams->eqEnable;
 // Caution: raw pointer to stack data, stored in instance by LVM_SetControlParameters.
  params->pEQNB_BandDefinition = &BandDefs[0];

  /* Volume Control parameters */
  params->VC_EffectLevel = 0;
  params->VC_Balance = 0;

  /* Treble Enhancement parameters */
  params->TE_OperatingMode = plvmConfigParams->trebleEnable;

  /* PSA Control parameters */
  params->PSA_Enable = LVM_PSA_ON;

  /* Bass Enhancement parameters */
  params->BE_OperatingMode = plvmConfigParams->bassEnable;

  /* Activate the initial settings */
  LvmStatus =
      LVM_SetControlParameters(pContext->pBundledContext->hInstance, params);

  LVM_ERROR_CHECK(LvmStatus, "LVM_SetControlParameters", "LvmBundle_init");
  if (LvmStatus != LVM_SUCCESS) return -EINVAL;

  LvmStatus = LVM_ApplyNewSettings(pContext->pBundledContext->hInstance);

  if (LvmStatus != LVM_SUCCESS) return -EINVAL;

  return 0;
}

int lvmExecute(float *floatIn, float *floatOut, struct EffectContext *pContext,
               lvmConfigParams_t *plvmConfigParams) {
  const int frameLength = plvmConfigParams->frameLength;
  return
      LVM_Process(pContext->pBundledContext->hInstance, /* Instance handle */
                  floatIn,                              /* Input buffer */
                  floatOut,                             /* Output buffer */
                  (LVM_UINT16)frameLength, /* Number of samples to read */
                  0);                      /* Audio Time */
}

int lvmMainProcess(lvmConfigParams_t *plvmConfigParams, FILE *finp, FILE *fout) {
  struct EffectContext context;
  LVM_ControlParams_t params;

  int errCode = lvmCreate(&context, plvmConfigParams, &params);
  if (errCode) {
    ALOGE("Error: lvmCreate returned with %d\n", errCode);
    return errCode;
  }

  errCode = lvmControl(&context, plvmConfigParams, &params);
  if (errCode) {
    ALOGE("Error: lvmControl returned with %d\n", errCode);
    return errCode;
  }

  const int channelCount = plvmConfigParams->nrChannels;
  const int frameLength = plvmConfigParams->frameLength;
  const int frameSize = channelCount * sizeof(float);  // processing size
  const int ioChannelCount = plvmConfigParams->fChannels;
  const int ioFrameSize = ioChannelCount * sizeof(short); // file load size
  const int maxChannelCount = std::max(channelCount, ioChannelCount);
  /*
   * Mono input will be converted to 2 channels internally in the process call
   * by copying the same data into the second channel.
   * Hence when channelCount is 1, output buffer should be allocated for
   * 2 channels. The memAllocChCount takes care of allocation of sufficient
   * memory for the output buffer.
   */
  const int memAllocChCount = (channelCount == 1 ? 2 : channelCount);

  std::vector<short> in(frameLength * maxChannelCount);
  std::vector<short> out(frameLength * maxChannelCount);
  std::vector<float> floatIn(frameLength * channelCount);
  std::vector<float> floatOut(frameLength * memAllocChCount);

  int frameCounter = 0;
  while (fread(in.data(), ioFrameSize, frameLength, finp) == (size_t)frameLength) {
    if (ioChannelCount != channelCount) {
        adjust_channels(in.data(), ioChannelCount, in.data(), channelCount,
               sizeof(short), frameLength * ioFrameSize);
    }
    memcpy_to_float_from_i16(floatIn.data(), in.data(), frameLength * channelCount);

#if 1
    errCode = lvmExecute(floatIn.data(), floatOut.data(), &context, plvmConfigParams);
    if (errCode) {
      printf("\nError: lvmExecute returned with %d\n", errCode);
      return errCode;
    }

    (void)frameSize; // eliminate warning
#else
    memcpy(floatOut.data(), floatIn.data(), frameLength * frameSize);
#endif
    memcpy_to_i16_from_float(out.data(), floatOut.data(), frameLength * channelCount);
    if (ioChannelCount != channelCount) {
        adjust_channels(out.data(), channelCount, out.data(), ioChannelCount,
               sizeof(short), frameLength * channelCount * sizeof(short));
    }
    (void) fwrite(out.data(), ioFrameSize, frameLength, fout);
    frameCounter += frameLength;
  }
  printf("frameCounter: [%d]\n", frameCounter);
  return 0;
}

int main(int argc, const char *argv[]) {
  if (argc == 1) {
    printUsage();
    return -1;
  }

  lvmConfigParams_t lvmConfigParams{}; // default initialize
  FILE *finp = nullptr, *fout = nullptr;

  for (int i = 1; i < argc; i++) {
    printf("%s ", argv[i]);
    if (!strncmp(argv[i], "-i:", 3)) {
      finp = fopen(argv[i] + 3, "rb");
    } else if (!strncmp(argv[i], "-o:", 3)) {
      fout = fopen(argv[i] + 3, "wb");
    } else if (!strncmp(argv[i], "-fs:", 4)) {
      const int samplingFreq = atoi(argv[i] + 4);
      if (samplingFreq != 8000 && samplingFreq != 11025 &&
          samplingFreq != 12000 && samplingFreq != 16000 &&
          samplingFreq != 22050 && samplingFreq != 24000 &&
          samplingFreq != 32000 && samplingFreq != 44100 &&
          samplingFreq != 48000 && samplingFreq != 88200 &&
          samplingFreq != 96000 && samplingFreq != 176400 &&
          samplingFreq != 192000) {
        ALOGE("\nError: Unsupported Sampling Frequency : %d\n", samplingFreq);
        return -1;
      }
      lvmConfigParams.samplingFreq = samplingFreq;
    } else if (!strncmp(argv[i], "-ch:", 4)) {
      const int nrChannels = atoi(argv[i] + 4);
      if (nrChannels > 8 || nrChannels < 1) {
        ALOGE("\nError: Unsupported number of channels : %d\n", nrChannels);
        return -1;
      }
      lvmConfigParams.nrChannels = nrChannels;
    } else if (!strncmp(argv[i], "-fch:", 5)) {
      const int fChannels = atoi(argv[i] + 5);
      if (fChannels > 8 || fChannels < 1) {
             ALOGE("\nError: Unsupported number of file channels : %d\n", fChannels);
             return -1;
           }
           lvmConfigParams.fChannels = fChannels;
    } else if (!strncmp(argv[i], "-basslvl:", 9)) {
      const int bassEffectLevel = atoi(argv[i] + 9);
      if (bassEffectLevel > 15 || bassEffectLevel < 0) {
        ALOGE("\nError: Unsupported Bass Effect Level : %d\n",
               bassEffectLevel);
        printUsage();
        return -1;
      }
      lvmConfigParams.bassEffectLevel = bassEffectLevel;
    } else if (!strncmp(argv[i], "-eqPreset:", 10)) {
      const int eqPresetLevel = atoi(argv[i] + 10);
      if (eqPresetLevel > 9 || eqPresetLevel < 0) {
        ALOGE("\nError: Unsupported Equalizer Preset : %d\n", eqPresetLevel);
        printUsage();
        return -1;
      }
      lvmConfigParams.eqPresetLevel = eqPresetLevel;
    } else if (!strcmp(argv[i], "-bE")) {
      lvmConfigParams.bassEnable = LVM_BE_ON;
    } else if (!strcmp(argv[i], "-eqE")) {
      lvmConfigParams.eqEnable = LVM_EQNB_ON;
    } else if (!strcmp(argv[i], "-tE")) {
      lvmConfigParams.trebleEnable = LVM_TE_ON;
    } else if (!strcmp(argv[i], "-csE")) {
      lvmConfigParams.csEnable = LVM_MODE_ON;
    } else if (!strcmp(argv[i], "-h")) {
      printUsage();
      return 0;
    }
  }

  if (finp == nullptr || fout == nullptr) {
    ALOGE("\nError: missing input/output files\n");
    printUsage();
    // ok not to close.
    return -1;
  }

  const int errCode = lvmMainProcess(&lvmConfigParams, finp, fout);
  fclose(finp);
  fclose(fout);

  if (errCode) {
    ALOGE("Error: lvmMainProcess returns with the error: %d \n", errCode);
    return -1;
  }
  return 0;
}
