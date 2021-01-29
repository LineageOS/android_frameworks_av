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
/*  Includes                                                                            */
/*                                                                                      */
/****************************************************************************************/

#include <stdlib.h>
#include "LVEQNB.h"
#include "LVEQNB_Private.h"
#include "InstAlloc.h"
#include <string.h> /* For memset */

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                LVEQNB_Init                                                 */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  Create and initialisation function for the N-Band equaliser module.                 */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  phInstance              Pointer to instance handle                                  */
/*  pCapabilities           Pointer to the initialisation capabilities                  */
/*  pScratch                Pointer to bundle scratch buffer                            */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVEQNB_SUCCESS          Initialisation succeeded                                    */
/*  LVEQNB_NULLADDRESS      One or more memory has a NULL pointer - malloc failure      */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1.  This function must not be interrupted by the LVEQNB_Process function            */
/*                                                                                      */
/****************************************************************************************/

LVEQNB_ReturnStatus_en LVEQNB_Init(LVEQNB_Handle_t* phInstance,
                                   LVEQNB_Capabilities_t* pCapabilities, void* pScratch) {
    LVEQNB_Instance_t* pInstance;

    *phInstance = calloc(1, sizeof(*pInstance));
    if (phInstance == LVM_NULL) {
        return LVEQNB_NULLADDRESS;
    }
    pInstance = (LVEQNB_Instance_t*)*phInstance;

    pInstance->Capabilities = *pCapabilities;
    pInstance->pScratch = pScratch;

    /* Equaliser Biquad Instance */
    LVM_UINT32 MemSize = pCapabilities->MaxBands * sizeof(*(pInstance->pBandDefinitions));
    pInstance->pBandDefinitions = (LVEQNB_BandDef_t*)calloc(1, MemSize);
    if (pInstance->pBandDefinitions == LVM_NULL) {
        return LVEQNB_NULLADDRESS;
    }
    // clear all the bands, setting their gain to 0, otherwise when applying new params,
    // it will compare against uninitialized values
    memset(pInstance->pBandDefinitions, 0, MemSize);

    MemSize = (pCapabilities->MaxBands * sizeof(*(pInstance->pBiquadType)));
    pInstance->pBiquadType = (LVEQNB_BiquadType_en*)calloc(1, MemSize);
    if (pInstance->pBiquadType == LVM_NULL) {
        return LVEQNB_NULLADDRESS;
    }

    pInstance->pFastTemporary = (LVM_FLOAT*)pScratch;

    /*
     * Update the instance parameters
     */
    pInstance->Params.NBands = 0;
    pInstance->Params.OperatingMode = LVEQNB_BYPASS;
    pInstance->Params.pBandDefinition = LVM_NULL;
    pInstance->Params.SampleRate = LVEQNB_FS_8000;
    pInstance->Params.SourceFormat = LVEQNB_STEREO;

    /*
     * Initialise the filters
     */
    LVEQNB_SetFilters(pInstance, /* Set the filter types */
                      &pInstance->Params);

    /*
     * Initialise the bypass variables
     */
    pInstance->BypassMixer.MixerStream[0].CallbackSet = 0;
    pInstance->BypassMixer.MixerStream[0].CallbackParam = 0;
    pInstance->BypassMixer.MixerStream[0].pCallbackHandle = (void*)pInstance;
    pInstance->BypassMixer.MixerStream[0].pCallBack = LVEQNB_BypassMixerCallBack;

    LVC_Mixer_Init(&pInstance->BypassMixer.MixerStream[0], 0, 0);
    LVC_Mixer_SetTimeConstant(&pInstance->BypassMixer.MixerStream[0], 0, LVM_FS_8000, 2);

    pInstance->BypassMixer.MixerStream[1].CallbackSet = 1;
    pInstance->BypassMixer.MixerStream[1].CallbackParam = 0;
    pInstance->BypassMixer.MixerStream[1].pCallbackHandle = LVM_NULL;
    pInstance->BypassMixer.MixerStream[1].pCallBack = LVM_NULL;
    LVC_Mixer_Init(&pInstance->BypassMixer.MixerStream[1], 0, 1.0f);
    LVC_Mixer_SetTimeConstant(&pInstance->BypassMixer.MixerStream[1], 0, LVM_FS_8000, 2);

    pInstance->bInOperatingModeTransition = LVM_FALSE;

    return (LVEQNB_SUCCESS);
}
/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                LVEQNB_DeInit                                               */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*    Free the memories created during LVEQNB_Init including instance handle            */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  phInstance              Pointer to instance handle                                  */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1.  This function must not be interrupted by the LVEQNB_Process function            */
/*                                                                                      */
/****************************************************************************************/

void LVEQNB_DeInit(LVEQNB_Handle_t* phInstance) {
    LVEQNB_Instance_t* pInstance;
    if (phInstance == LVM_NULL) {
        return;
    }
    pInstance = (LVEQNB_Instance_t*)*phInstance;

    if (pInstance->pBandDefinitions != LVM_NULL) {
        free(pInstance->pBandDefinitions);
        pInstance->pBandDefinitions = LVM_NULL;
    }
    if (pInstance->pBiquadType != LVM_NULL) {
        free(pInstance->pBiquadType);
        pInstance->pBiquadType = LVM_NULL;
    }
    free(pInstance);
    *phInstance = LVM_NULL;
}
