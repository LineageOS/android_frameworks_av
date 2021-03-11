/*
 * Copyright (C) 2004-2010 NXP Software
 * Copyright (C) 2010 The Android Open Source Project
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

/****************************************************************************************/
/*                                                                                      */
/*    Includes                                                                          */
/*                                                                                      */
/****************************************************************************************/

#include <system/audio.h>
#include <stdlib.h>
#include "LVDBE.h"
#include "LVDBE_Private.h"

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                 LVDBE_Init                                                 */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*    Create and initialisation function for the Bass Enhancement module                */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  phInstance               Pointer to instance handle                                 */
/*  pCapabilities            Pointer to the initialisation capabilities                 */
/*  pScratch                 Pointer to the bundle scratch buffer                       */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVDBE_SUCCESS            Initialisation succeeded                                   */
/*  LVDBE_NULLADDRESS        One or more memory has a NULL pointer - malloc failure     */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1.    This function must not be interrupted by the LVDBE_Process function           */
/*                                                                                      */
/****************************************************************************************/
LVDBE_ReturnStatus_en LVDBE_Init(LVDBE_Handle_t* phInstance, LVDBE_Capabilities_t* pCapabilities,
                                 void* pScratch) {
    LVDBE_Instance_t* pInstance;
    LVMixer3_1St_FLOAT_st* pMixer_Instance;
    LVMixer3_2St_FLOAT_st* pBypassMixer_Instance;
    LVM_FLOAT MixGain;

    /*
     * Create the instance handle if not already initialised
     */
    if (*phInstance == LVM_NULL) {
        *phInstance = new LVDBE_Instance_t{};
    }
    pInstance = (LVDBE_Instance_t*)*phInstance;

    /*
     * Save the memory table in the instance structure
     */
    pInstance->Capabilities = *pCapabilities;

    pInstance->pScratch = pScratch;

    /*
     * Set the default instance parameters
     */
    pInstance->Params.CentreFrequency = LVDBE_CENTRE_55HZ;
    pInstance->Params.EffectLevel = 0;
    pInstance->Params.HeadroomdB = 0;
    pInstance->Params.HPFSelect = LVDBE_HPF_OFF;
    pInstance->Params.OperatingMode = LVDBE_OFF;
    pInstance->Params.SampleRate = LVDBE_FS_8000;
    pInstance->Params.VolumeControl = LVDBE_VOLUME_OFF;
    pInstance->Params.VolumedB = 0;
    pInstance->Params.NrChannels = FCC_2;

    /*
     * Create pointer to data and coef memory
     */
    pInstance->pData = (LVDBE_Data_FLOAT_t*)calloc(1, sizeof(*(pInstance->pData)));
    if (pInstance->pData == NULL) {
        return LVDBE_NULLADDRESS;
    }
    /*
     * Create biquad instance
     */
    pInstance->pHPFBiquad.reset(
            new android::audio_utils::BiquadFilter<LVM_FLOAT>(pInstance->Params.NrChannels));
    pInstance->pBPFBiquad.reset(new android::audio_utils::BiquadFilter<LVM_FLOAT>(FCC_1));

    /*
     * Initialise the filters
     */
    LVDBE_SetFilters(pInstance, /* Set the filter taps and coefficients */
                     &pInstance->Params);

    /*
     * Initialise the AGC
     */
    LVDBE_SetAGC(pInstance, /* Set the AGC gain */
                 &pInstance->Params);
    pInstance->pData->AGCInstance.AGC_Gain = pInstance->pData->AGCInstance.AGC_MaxGain;
    /* Default to the bass boost setting */

    // initialize the mixer with some fixes values since otherwise LVDBE_SetVolume ends up
    // reading uninitialized data
    pMixer_Instance = &pInstance->pData->BypassVolume;
    LVC_Mixer_Init(&pMixer_Instance->MixerStream[0], 1.0, 1.0);

    /*
     * Initialise the volume
     */
    LVDBE_SetVolume(pInstance, /* Set the Volume */
                    &pInstance->Params);

    pInstance->pData->AGCInstance.Volume = pInstance->pData->AGCInstance.Target;
    /* Initialise as the target */
    MixGain = LVC_Mixer_GetTarget(&pMixer_Instance->MixerStream[0]);
    LVC_Mixer_Init(&pMixer_Instance->MixerStream[0], MixGain, MixGain);

    /* Configure the mixer process path */
    pMixer_Instance->MixerStream[0].CallbackParam = 0;
    pMixer_Instance->MixerStream[0].pCallbackHandle = LVM_NULL;
    pMixer_Instance->MixerStream[0].pCallBack = LVM_NULL;
    pMixer_Instance->MixerStream[0].CallbackSet = 0;

    /*
     * Initialise the clicks minimisation BypassMixer
     */

    pBypassMixer_Instance = &pInstance->pData->BypassMixer;

    /*
     * Setup the mixer gain for the processed path
     */
    pBypassMixer_Instance->MixerStream[0].CallbackParam = 0;
    pBypassMixer_Instance->MixerStream[0].pCallbackHandle = LVM_NULL;
    pBypassMixer_Instance->MixerStream[0].pCallBack = LVM_NULL;
    pBypassMixer_Instance->MixerStream[0].CallbackSet = 0;

    LVC_Mixer_Init(&pBypassMixer_Instance->MixerStream[0], 0, 0);
    LVC_Mixer_SetTimeConstant(&pBypassMixer_Instance->MixerStream[0], LVDBE_BYPASS_MIXER_TC,
                              (LVM_Fs_en)pInstance->Params.SampleRate, 2);

    /*
     * Setup the mixer gain for the unprocessed path
     */
    pBypassMixer_Instance->MixerStream[1].CallbackParam = 0;
    pBypassMixer_Instance->MixerStream[1].pCallbackHandle = LVM_NULL;
    pBypassMixer_Instance->MixerStream[1].pCallBack = LVM_NULL;
    pBypassMixer_Instance->MixerStream[1].CallbackSet = 0;
    LVC_Mixer_Init(&pBypassMixer_Instance->MixerStream[1], 1.0, 1.0);
    LVC_Mixer_SetTimeConstant(&pBypassMixer_Instance->MixerStream[1], LVDBE_BYPASS_MIXER_TC,
                              (LVM_Fs_en)pInstance->Params.SampleRate, 2);

    return (LVDBE_SUCCESS);
}

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                 LVDBE_DeInit                                               */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*    Free the memories created during LVDBE_Init including instance handle             */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  phInstance               Pointer to instance handle                                 */
/*                                                                                      */
/****************************************************************************************/
void LVDBE_DeInit(LVDBE_Handle_t* phInstance) {
    LVDBE_Instance_t* pInstance = (LVDBE_Instance_t*)*phInstance;
    if (pInstance == LVM_NULL) {
        return;
    }
    if (pInstance->pData != LVM_NULL) {
        free(pInstance->pData);
        pInstance->pData = LVM_NULL;
    }
    delete pInstance;
    *phInstance = LVM_NULL;
}
