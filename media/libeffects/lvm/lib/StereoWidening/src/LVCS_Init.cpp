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

/************************************************************************************/
/*                                                                                  */
/*  Includes                                                                        */
/*                                                                                  */
/************************************************************************************/
#include <stdlib.h>
#include "LVCS.h"
#include "LVCS_Private.h"
#include "LVCS_Tables.h"

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:                LVCS_Init                                               */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Create and initialisation function for the Concert Sound module                 */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  phInstance              Pointer to instance handle                              */
/*  pCapabilities           Pointer to the capabilities structure                   */
/*  pScratch                Pointer to scratch buffer                               */
/*                                                                                  */
/* RETURNS:                                                                         */
/*  LVCS_Success            Initialisation succeeded                                */
/*  LVDBE_NULLADDRESS       One or more memory has a NULL pointer - malloc failure  */
/*                                                                                  */
/* NOTES:                                                                           */
/*  1.  This function must not be interrupted by the LVCS_Process function          */
/*                                                                                  */
/************************************************************************************/

LVCS_ReturnStatus_en LVCS_Init(LVCS_Handle_t* phInstance, LVCS_Capabilities_t* pCapabilities,
                               void* pScratch) {
    LVCS_Instance_t* pInstance;
    LVCS_VolCorrect_t* pLVCS_VolCorrectTable;

    /*
     * Create the instance handle if not already initialised
     */
    if (*phInstance == LVM_NULL) {
        *phInstance = calloc(1, sizeof(*pInstance));
    }
    if (*phInstance == LVM_NULL) {
        return LVCS_NULLADDRESS;
    }
    pInstance = (LVCS_Instance_t*)*phInstance;

    /*
     * Save the capabilities in the instance structure
     */
    pInstance->Capabilities = *pCapabilities;

    pInstance->pScratch = pScratch;

    /*
     * Set all initial parameters to invalid to force a full initialisation
     */
    pInstance->Params.OperatingMode = LVCS_OFF;
    pInstance->Params.SpeakerType = LVCS_SPEAKERTYPE_MAX;
    pInstance->OutputDevice = LVCS_HEADPHONE;
    pInstance->Params.SourceFormat = LVCS_SOURCEMAX;
    pInstance->Params.CompressorMode = LVM_MODE_OFF;
    pInstance->Params.SampleRate = LVM_FS_INVALID;
    pInstance->Params.EffectLevel = 0;
    pInstance->Params.ReverbLevel = (LVM_UINT16)0x8000;
    pLVCS_VolCorrectTable = (LVCS_VolCorrect_t*)&LVCS_VolCorrectTable[0];
    pInstance->VolCorrect = pLVCS_VolCorrectTable[0];
    pInstance->TransitionGain = 0;

    /* These current and target values are intialized again in LVCS_Control.c */
    LVC_Mixer_Init(&pInstance->BypassMix.Mixer_Instance.MixerStream[0], 0, 0);
    /* These current and target values are intialized again in LVCS_Control.c */
    LVC_Mixer_Init(&pInstance->BypassMix.Mixer_Instance.MixerStream[1], 0, 0);

    /*
     * Initialise the bypass variables
     */
    pInstance->MSTarget0 = 0;
    pInstance->MSTarget1 = 0;
    pInstance->bInOperatingModeTransition = LVM_FALSE;
    pInstance->bTimerDone = LVM_FALSE;
    pInstance->TimerParams.CallBackParam = 0;
    pInstance->TimerParams.pCallBack = LVCS_TimerCallBack;
    pInstance->TimerParams.pCallbackInstance = pInstance;
    pInstance->TimerParams.pCallBackParams = LVM_NULL;

    return (LVCS_SUCCESS);
}

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:                LVCS_DeInit                                             */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Free memories created during the LVCS_Init call including instance handle       */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  phInstance              Pointer to instance handle                              */
/*                                                                                  */
/* NOTES:                                                                           */
/*  1.  This function must not be interrupted by the LVCS_Process function          */
/*                                                                                  */
/************************************************************************************/
void LVCS_DeInit(LVCS_Handle_t* phInstance) {
    LVCS_Instance_t* pInstance = (LVCS_Instance_t*)*phInstance;
    if (pInstance == LVM_NULL) {
        return;
    }
    free(pInstance);
    *phInstance = LVM_NULL;
    return;
}
