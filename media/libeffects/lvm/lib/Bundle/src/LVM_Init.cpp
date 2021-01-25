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

#include "LVM_Private.h"
#include "LVM_Tables.h"
#include "VectorArithmetic.h"
#include "InstAlloc.h"

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                LVM_GetInstanceHandle                                       */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  This function is used to create a bundle instance.                                  */
/*  All parameters are set to their default, inactive state.                            */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  phInstance              Pointer to the instance handle                              */
/*  pInstParams             Pointer to the instance parameters                          */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVM_SUCCESS             Initialisation succeeded                                    */
/*  LVM_NULLADDRESS         One or more memory has a NULL pointer                       */
/*  LVM_OUTOFRANGE          When any of the Instance parameters are out of range        */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1. This function must not be interrupted by the LVM_Process function                */
/*                                                                                      */
/****************************************************************************************/
LVM_ReturnStatus_en LVM_GetInstanceHandle(LVM_Handle_t* phInstance, LVM_InstParams_t* pInstParams) {
    LVM_ReturnStatus_en Status = LVM_SUCCESS;
    LVM_Instance_t* pInstance;
    LVM_INT16 i;
    LVM_UINT16 InternalBlockSize;
    LVM_INT32 BundleScratchSize;

    /*
     * Check valid points have been given
     */
    if ((phInstance == LVM_NULL) || (pInstParams == LVM_NULL)) {
        return (LVM_NULLADDRESS);
    }

    /*
     * Check the instance parameters
     */
    if ((pInstParams->BufferMode != LVM_MANAGED_BUFFERS) &&
        (pInstParams->BufferMode != LVM_UNMANAGED_BUFFERS)) {
        return (LVM_OUTOFRANGE);
    }

    if (pInstParams->EQNB_NumBands > 32) {
        return (LVM_OUTOFRANGE);
    }

    if (pInstParams->BufferMode == LVM_MANAGED_BUFFERS) {
        if ((pInstParams->MaxBlockSize < LVM_MIN_MAXBLOCKSIZE) ||
            (pInstParams->MaxBlockSize > LVM_MANAGED_MAX_MAXBLOCKSIZE)) {
            return (LVM_OUTOFRANGE);
        }
    } else {
        if ((pInstParams->MaxBlockSize < LVM_MIN_MAXBLOCKSIZE) ||
            (pInstParams->MaxBlockSize > LVM_UNMANAGED_MAX_MAXBLOCKSIZE)) {
            return (LVM_OUTOFRANGE);
        }
    }

    if (pInstParams->PSA_Included > LVM_PSA_ON) {
        return (LVM_OUTOFRANGE);
    }

    /*
     * Create the instance handle
     */
    *phInstance = (LVM_Handle_t)calloc(1, sizeof(*pInstance));
    if (*phInstance == LVM_NULL) {
        return LVM_NULLADDRESS;
    }
    pInstance = (LVM_Instance_t*)*phInstance;

    pInstance->InstParams = *pInstParams;

    /*
     * Create the bundle scratch memory and initialse the buffer management
     */
    InternalBlockSize = (LVM_UINT16)(
            (pInstParams->MaxBlockSize) &
            MIN_INTERNAL_BLOCKMASK); /* Force to a multiple of MIN_INTERNAL_BLOCKSIZE */
    if (InternalBlockSize < MIN_INTERNAL_BLOCKSIZE) {
        InternalBlockSize = MIN_INTERNAL_BLOCKSIZE;
    }

    /* Maximum Internal Black Size should not be more than MAX_INTERNAL_BLOCKSIZE*/
    if (InternalBlockSize > MAX_INTERNAL_BLOCKSIZE) {
        InternalBlockSize = MAX_INTERNAL_BLOCKSIZE;
    }
    pInstance->InternalBlockSize = (LVM_INT16)InternalBlockSize;

    /*
     * Common settings for managed and unmanaged buffers
     */
    pInstance->SamplesToProcess = 0; /* No samples left to process */
    BundleScratchSize =
            (LVM_INT32)(3 * LVM_MAX_CHANNELS * (MIN_INTERNAL_BLOCKSIZE + InternalBlockSize) *
                        sizeof(LVM_FLOAT));
    pInstance->pScratch = calloc(1, BundleScratchSize);
    if (pInstance->pScratch == LVM_NULL) {
        return LVM_NULLADDRESS;
    }

    if (pInstParams->BufferMode == LVM_MANAGED_BUFFERS) {
        /*
         * Managed buffers required
         */
        pInstance->pBufferManagement =
                (LVM_Buffer_t*)calloc(1, sizeof(*(pInstance->pBufferManagement)));
        if (pInstance->pBufferManagement == LVM_NULL) {
            return LVM_NULLADDRESS;
        }

        pInstance->pBufferManagement->pScratch = (LVM_FLOAT*)pInstance->pScratch;

        LoadConst_Float(0, /* Clear the input delay buffer */
                        (LVM_FLOAT*)&pInstance->pBufferManagement->InDelayBuffer,
                        (LVM_INT16)(LVM_MAX_CHANNELS * MIN_INTERNAL_BLOCKSIZE));
        pInstance->pBufferManagement->InDelaySamples =
                MIN_INTERNAL_BLOCKSIZE;                    /* Set the number of delay samples */
        pInstance->pBufferManagement->OutDelaySamples = 0; /* No samples in the output buffer */
        pInstance->pBufferManagement->BufferState =
                LVM_FIRSTCALL; /* Set the state ready for the first call */
    }

    /*
     * Set default parameters
     */
    pInstance->Params.OperatingMode = LVM_MODE_OFF;
    pInstance->Params.SampleRate = LVM_FS_8000;
    pInstance->Params.SourceFormat = LVM_MONO;
    pInstance->Params.SpeakerType = LVM_HEADPHONES;
    pInstance->Params.VC_EffectLevel = 0;
    pInstance->Params.VC_Balance = 0;

    /*
     * Set callback
     */
    pInstance->CallBack = LVM_AlgoCallBack;

    /*
     * DC removal filter
     */
    DC_Mc_D16_TRC_WRA_01_Init(&pInstance->DC_RemovalInstance);

    /*
     * Treble Enhancement
     */
    pInstance->Params.TE_OperatingMode = LVM_TE_OFF;
    pInstance->Params.TE_EffectLevel = 0;
    pInstance->TE_Active = LVM_FALSE;

    /*
     * Set the volume control and initialise Current to Target
     */
    pInstance->VC_Volume.MixerStream[0].CallbackParam = 0;
    pInstance->VC_Volume.MixerStream[0].CallbackSet = 0;
    pInstance->VC_Volume.MixerStream[0].pCallbackHandle = pInstance;
    pInstance->VC_Volume.MixerStream[0].pCallBack = LVM_VCCallBack;

    /* In managed buffering, start with low signal level as delay in buffer management causes a
     * click*/
    if (pInstParams->BufferMode == LVM_MANAGED_BUFFERS) {
        LVC_Mixer_Init(&pInstance->VC_Volume.MixerStream[0], 0, 0);
    } else {
        LVC_Mixer_Init(&pInstance->VC_Volume.MixerStream[0], LVM_MAXFLOAT, LVM_MAXFLOAT);
    }

    LVC_Mixer_SetTimeConstant(&pInstance->VC_Volume.MixerStream[0], 0, LVM_FS_8000, 2);

    pInstance->VC_VolumedB = 0;
    pInstance->VC_AVLFixedVolume = 0;
    pInstance->VC_Active = LVM_FALSE;

    pInstance->VC_BalanceMix.MixerStream[0].CallbackParam = 0;
    pInstance->VC_BalanceMix.MixerStream[0].CallbackSet = 0;
    pInstance->VC_BalanceMix.MixerStream[0].pCallbackHandle = pInstance;
    pInstance->VC_BalanceMix.MixerStream[0].pCallBack = LVM_VCCallBack;
    LVC_Mixer_Init(&pInstance->VC_BalanceMix.MixerStream[0], LVM_MAXFLOAT, LVM_MAXFLOAT);
    LVC_Mixer_VarSlope_SetTimeConstant(&pInstance->VC_BalanceMix.MixerStream[0], LVM_VC_MIXER_TIME,
                                       LVM_FS_8000, 2);

    pInstance->VC_BalanceMix.MixerStream[1].CallbackParam = 0;
    pInstance->VC_BalanceMix.MixerStream[1].CallbackSet = 0;
    pInstance->VC_BalanceMix.MixerStream[1].pCallbackHandle = pInstance;
    pInstance->VC_BalanceMix.MixerStream[1].pCallBack = LVM_VCCallBack;
    LVC_Mixer_Init(&pInstance->VC_BalanceMix.MixerStream[1], LVM_MAXFLOAT, LVM_MAXFLOAT);
    LVC_Mixer_VarSlope_SetTimeConstant(&pInstance->VC_BalanceMix.MixerStream[1], LVM_VC_MIXER_TIME,
                                       LVM_FS_8000, 2);

    /*
     * Create the default EQNB pre-gain and pointer to the band definitions
     */
    pInstance->pEQNB_BandDefs = (LVM_EQNB_BandDef_t*)calloc(pInstParams->EQNB_NumBands,
                                                            sizeof(*(pInstance->pEQNB_BandDefs)));
    if (pInstance->pEQNB_BandDefs == LVM_NULL) {
        return LVM_NULLADDRESS;
    }
    pInstance->pEQNB_UserDefs = (LVM_EQNB_BandDef_t*)calloc(pInstParams->EQNB_NumBands,
                                                            sizeof(*(pInstance->pEQNB_UserDefs)));
    if (pInstance->pEQNB_UserDefs == LVM_NULL) {
        return LVM_NULLADDRESS;
    }

    /*
     * Initialise the Concert Sound module
     */
    {
        LVCS_Handle_t hCSInstance;           /* Instance handle */
        LVCS_Capabilities_t CS_Capabilities; /* Initial capabilities */
        LVCS_ReturnStatus_en LVCS_Status;    /* Function call status */

        /*
         * Set default parameters
         */
        pInstance->Params.VirtualizerReverbLevel = 100;
        pInstance->Params.VirtualizerType = LVM_CONCERTSOUND;
        pInstance->Params.VirtualizerOperatingMode = LVM_MODE_OFF;
        pInstance->CS_Active = LVM_FALSE;

        /*
         * Set the initialisation capabilities
         */
        CS_Capabilities.MaxBlockSize = (LVM_UINT16)InternalBlockSize;
        CS_Capabilities.CallBack = pInstance->CallBack;
        CS_Capabilities.pBundleInstance = (void*)pInstance;

        /*
         * Initialise the Concert Sound instance and save the instance handle
         */
        hCSInstance = LVM_NULL;               /* Set to NULL to return handle */
        LVCS_Status = LVCS_Init(&hCSInstance, /* Create and initiailse */
                                &CS_Capabilities, pInstance->pScratch);
        if (LVCS_Status != LVCS_SUCCESS) return ((LVM_ReturnStatus_en)LVCS_Status);
        pInstance->hCSInstance = hCSInstance; /* Save the instance handle */
    }

    /*
     * Initialise the Bass Enhancement module
     */
    {
        LVDBE_Handle_t hDBEInstance;           /* Instance handle */
        LVDBE_Capabilities_t DBE_Capabilities; /* Initial capabilities */
        LVDBE_ReturnStatus_en LVDBE_Status;    /* Function call status */

        /*
         * Set the initialisation parameters
         */
        pInstance->Params.BE_OperatingMode = LVM_BE_OFF;
        pInstance->Params.BE_CentreFreq = LVM_BE_CENTRE_55Hz;
        pInstance->Params.BE_EffectLevel = 0;
        pInstance->Params.BE_HPF = LVM_BE_HPF_OFF;

        pInstance->DBE_Active = LVM_FALSE;

        /*
         * Set the initialisation capabilities
         */
        DBE_Capabilities.SampleRate = LVDBE_CAP_FS_8000 | LVDBE_CAP_FS_11025 | LVDBE_CAP_FS_12000 |
                                      LVDBE_CAP_FS_16000 | LVDBE_CAP_FS_22050 | LVDBE_CAP_FS_24000 |
                                      LVDBE_CAP_FS_32000 | LVDBE_CAP_FS_44100 | LVDBE_CAP_FS_48000 |
                                      LVDBE_CAP_FS_88200 | LVDBE_CAP_FS_96000 |
                                      LVDBE_CAP_FS_176400 | LVDBE_CAP_FS_192000;

        DBE_Capabilities.CentreFrequency = LVDBE_CAP_CENTRE_55Hz | LVDBE_CAP_CENTRE_55Hz |
                                           LVDBE_CAP_CENTRE_66Hz | LVDBE_CAP_CENTRE_78Hz |
                                           LVDBE_CAP_CENTRE_90Hz;
        DBE_Capabilities.MaxBlockSize = (LVM_UINT16)InternalBlockSize;

        /*
         * Initialise the Dynamic Bass Enhancement instance and save the instance handle
         */
        hDBEInstance = LVM_NULL;                 /* Set to NULL to return handle */
        LVDBE_Status = LVDBE_Init(&hDBEInstance, /* Create and initiailse */
                                  &DBE_Capabilities, pInstance->pScratch);
        if (LVDBE_Status != LVDBE_SUCCESS) return ((LVM_ReturnStatus_en)LVDBE_Status);
        pInstance->hDBEInstance = hDBEInstance; /* Save the instance handle */
    }

    /*
     * Initialise the N-Band Equaliser module
     */
    {
        LVEQNB_Handle_t hEQNBInstance;           /* Instance handle */
        LVEQNB_Capabilities_t EQNB_Capabilities; /* Initial capabilities */
        LVEQNB_ReturnStatus_en LVEQNB_Status;    /* Function call status */

        /*
         * Set the initialisation parameters
         */
        pInstance->Params.EQNB_OperatingMode = LVM_EQNB_OFF;
        pInstance->Params.EQNB_NBands = 0;
        pInstance->Params.pEQNB_BandDefinition = LVM_NULL;
        pInstance->EQNB_Active = LVM_FALSE;

        /*
         * Set the initialisation capabilities
         */
        EQNB_Capabilities.SampleRate =
                LVEQNB_CAP_FS_8000 | LVEQNB_CAP_FS_11025 | LVEQNB_CAP_FS_12000 |
                LVEQNB_CAP_FS_16000 | LVEQNB_CAP_FS_22050 | LVEQNB_CAP_FS_24000 |
                LVEQNB_CAP_FS_32000 | LVEQNB_CAP_FS_44100 | LVEQNB_CAP_FS_48000 |
                LVEQNB_CAP_FS_88200 | LVEQNB_CAP_FS_96000 | LVEQNB_CAP_FS_176400 |
                LVEQNB_CAP_FS_192000;

        EQNB_Capabilities.MaxBlockSize = (LVM_UINT16)InternalBlockSize;
        EQNB_Capabilities.MaxBands = pInstParams->EQNB_NumBands;
        EQNB_Capabilities.SourceFormat = LVEQNB_CAP_STEREO | LVEQNB_CAP_MONOINSTEREO;
        EQNB_Capabilities.CallBack = pInstance->CallBack;
        EQNB_Capabilities.pBundleInstance = (void*)pInstance;

        /*
         * Initialise the Dynamic Bass Enhancement instance and save the instance handle
         */
        hEQNBInstance = LVM_NULL;                   /* Set to NULL to return handle */
        LVEQNB_Status = LVEQNB_Init(&hEQNBInstance, /* Create and initiailse */
                                    &EQNB_Capabilities, pInstance->pScratch);
        if (LVEQNB_Status != LVEQNB_SUCCESS) return ((LVM_ReturnStatus_en)LVEQNB_Status);
        pInstance->hEQNBInstance = hEQNBInstance; /* Save the instance handle */
    }

    /*
     * Headroom management memory allocation
     */
    {
        pInstance->pHeadroom_BandDefs = (LVM_HeadroomBandDef_t*)calloc(
                LVM_HEADROOM_MAX_NBANDS, sizeof(*(pInstance->pHeadroom_BandDefs)));
        if (pInstance->pHeadroom_BandDefs == LVM_NULL) {
            return LVM_NULLADDRESS;
        }
        pInstance->pHeadroom_UserDefs = (LVM_HeadroomBandDef_t*)calloc(
                LVM_HEADROOM_MAX_NBANDS, sizeof(*(pInstance->pHeadroom_UserDefs)));
        if (pInstance->pHeadroom_UserDefs == LVM_NULL) {
            return LVM_NULLADDRESS;
        }

        /* Headroom management parameters initialisation */
        pInstance->NewHeadroomParams.NHeadroomBands = 2;
        pInstance->NewHeadroomParams.pHeadroomDefinition = pInstance->pHeadroom_BandDefs;
        pInstance->NewHeadroomParams.pHeadroomDefinition[0].Limit_Low = 20;
        pInstance->NewHeadroomParams.pHeadroomDefinition[0].Limit_High = 4999;
        pInstance->NewHeadroomParams.pHeadroomDefinition[0].Headroom_Offset = 3;
        pInstance->NewHeadroomParams.pHeadroomDefinition[1].Limit_Low = 5000;
        pInstance->NewHeadroomParams.pHeadroomDefinition[1].Limit_High = 24000;
        pInstance->NewHeadroomParams.pHeadroomDefinition[1].Headroom_Offset = 4;
        pInstance->NewHeadroomParams.Headroom_OperatingMode = LVM_HEADROOM_ON;

        pInstance->Headroom = 0;
    }

    /*
     * Initialise the PSA module
     */
    {
        pLVPSA_Handle_t hPSAInstance = LVM_NULL; /* Instance handle */
        LVPSA_RETURN PSA_Status;                 /* Function call status */
        LVPSA_FilterParam_t FiltersParams[9];

        if (pInstParams->PSA_Included == LVM_PSA_ON) {
            pInstance->PSA_InitParams.SpectralDataBufferDuration = (LVM_UINT16)500;
            pInstance->PSA_InitParams.MaxInputBlockSize = (LVM_UINT16)2048;
            pInstance->PSA_InitParams.nBands = (LVM_UINT16)9;
            pInstance->PSA_InitParams.pFiltersParams = &FiltersParams[0];
            for (i = 0; i < pInstance->PSA_InitParams.nBands; i++) {
                FiltersParams[i].CenterFrequency = (LVM_UINT16)1000;
                FiltersParams[i].QFactor = (LVM_UINT16)100;
                FiltersParams[i].PostGain = (LVM_INT16)0;
            }

            /*Initialise PSA instance and save the instance handle*/
            pInstance->PSA_ControlParams.Fs = LVM_FS_48000;
            pInstance->PSA_ControlParams.LevelDetectionSpeed = LVPSA_SPEED_MEDIUM;
            pInstance->pPSAInput = (LVM_FLOAT*)calloc(MAX_INTERNAL_BLOCKSIZE, sizeof(LVM_FLOAT));
            if (pInstance->pPSAInput == LVM_NULL) {
                return LVM_NULLADDRESS;
            }
            PSA_Status = LVPSA_Init(&hPSAInstance, &pInstance->PSA_InitParams,
                                    &pInstance->PSA_ControlParams, pInstance->pScratch);

            if (PSA_Status != LVPSA_OK) {
                return ((LVM_ReturnStatus_en)LVM_ALGORITHMPSA);
            }

            pInstance->hPSAInstance = hPSAInstance; /* Save the instance handle */
            pInstance->PSA_GainOffset = 0;
        } else {
            pInstance->hPSAInstance = LVM_NULL;
        }

        /*
         * Set the initialisation parameters.
         */
        pInstance->Params.PSA_PeakDecayRate = LVM_PSA_SPEED_MEDIUM;
        pInstance->Params.PSA_Enable = LVM_PSA_OFF;
    }

    /*
     * Copy the initial parameters to the new parameters for correct readback of
     * the settings.
     */
    pInstance->NewParams = pInstance->Params;

    /*
     * Create configuration number
     */
    pInstance->ConfigurationNumber = 0x00000000;
    pInstance->ConfigurationNumber += LVM_CS_MASK;
    pInstance->ConfigurationNumber += LVM_EQNB_MASK;
    pInstance->ConfigurationNumber += LVM_DBE_MASK;
    pInstance->ConfigurationNumber += LVM_VC_MASK;
    pInstance->ConfigurationNumber += LVM_PSA_MASK;

    if (((pInstance->ConfigurationNumber & LVM_CS_MASK) != 0) ||
        ((pInstance->ConfigurationNumber & LVM_DBE_MASK) != 0) ||
        ((pInstance->ConfigurationNumber & LVM_EQNB_MASK) != 0) ||
        ((pInstance->ConfigurationNumber & LVM_TE_MASK) != 0) ||
        ((pInstance->ConfigurationNumber & LVM_VC_MASK) != 0)) {
        pInstance->BlickSizeMultiple = 4;
    } else {
        pInstance->BlickSizeMultiple = 1;
    }

    return (Status);
}
/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                LVM_DelInstanceHandle                                       */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  This function is used to create a bundle instance. It returns the created instance  */
/*  handle through phInstance. All parameters are set to their default, inactive state. */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  phInstance              Pointer to the instance handle                              */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1. This function must not be interrupted by the LVM_Process function                */
/*                                                                                      */
/****************************************************************************************/
void LVM_DelInstanceHandle(LVM_Handle_t* phInstance) {
    LVM_Instance_t* pInstance = (LVM_Instance_t*)*phInstance;

    if (pInstance->pScratch != LVM_NULL) {
        free(pInstance->pScratch);
        pInstance->pScratch = LVM_NULL;
    }

    if (pInstance->InstParams.BufferMode == LVM_MANAGED_BUFFERS) {
        /*
         * Managed buffers required
         */
        if (pInstance->pBufferManagement != LVM_NULL) {
            free(pInstance->pBufferManagement);
            pInstance->pBufferManagement = LVM_NULL;
        }
    }

    /*
     * Treble Enhancement
     */

    /*
     * Free the default EQNB pre-gain and pointer to the band definitions
     */
    if (pInstance->pEQNB_BandDefs != LVM_NULL) {
        free(pInstance->pEQNB_BandDefs);
        pInstance->pEQNB_BandDefs = LVM_NULL;
    }
    if (pInstance->pEQNB_UserDefs != LVM_NULL) {
        free(pInstance->pEQNB_UserDefs);
        pInstance->pEQNB_UserDefs = LVM_NULL;
    }

    /*
     * De-initialise the Concert Sound module
     */
    if (pInstance->hCSInstance != LVM_NULL) {
        LVCS_DeInit(&pInstance->hCSInstance);
    }

    /*
     * De-initialise the Bass Enhancement module
     */
    if (pInstance->hDBEInstance != LVM_NULL) {
        LVDBE_DeInit(&pInstance->hDBEInstance);
    }

    /*
     * De-initialise the N-Band Equaliser module
     */
    if (pInstance->hEQNBInstance != LVM_NULL) {
        LVEQNB_DeInit(&pInstance->hEQNBInstance);
    }

    /*
     * Free Headroom management memory.
     */
    if (pInstance->pHeadroom_BandDefs != LVM_NULL) {
        free(pInstance->pHeadroom_BandDefs);
        pInstance->pHeadroom_BandDefs = LVM_NULL;
    }
    if (pInstance->pHeadroom_UserDefs != LVM_NULL) {
        free(pInstance->pHeadroom_UserDefs);
        pInstance->pHeadroom_UserDefs = LVM_NULL;
    }

    /*
     * De-initialise the PSA module
     */
    if (pInstance->hPSAInstance != LVM_NULL) {
        LVPSA_DeInit(&pInstance->hPSAInstance);
    }
    if (pInstance->pPSAInput != LVM_NULL) {
        free(pInstance->pPSAInput);
        pInstance->pPSAInput = LVM_NULL;
    }

    free(*phInstance);
    return;
}

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                LVM_ClearAudioBuffers                                       */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  This function is used to clear the internal audio buffers of the bundle.            */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  hInstance               Instance handle                                             */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVM_SUCCESS             Initialisation succeeded                                    */
/*  LVM_NULLADDRESS         Instance or scratch memory has a NULL pointer               */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1. This function must not be interrupted by the LVM_Process function                */
/*                                                                                      */
/****************************************************************************************/

LVM_ReturnStatus_en LVM_ClearAudioBuffers(LVM_Handle_t hInstance) {
    LVM_InstParams_t InstParams;                            /* Instance parameters */
    LVM_ControlParams_t Params;                             /* Control Parameters */
    LVM_Instance_t* pInstance = (LVM_Instance_t*)hInstance; /* Pointer to Instance */
    LVM_HeadroomParams_t HeadroomParams;

    if (hInstance == LVM_NULL) {
        return LVM_NULLADDRESS;
    }

    /* Save the control parameters */ /* coverity[unchecked_value] */ /* Do not check return value
                                                                         internal function calls */
    LVM_GetControlParameters(hInstance, &Params);

    /*Save the headroom parameters*/
    LVM_GetHeadroomParams(hInstance, &HeadroomParams);

    /*  Save the instance parameters */
    InstParams = pInstance->InstParams;

    /*  Call  LVM_GetInstanceHandle to re-initialise the bundle */
    /* Restore control parameters */ /* coverity[unchecked_value] */ /* Do not check return value
                                                                        internal function calls */
    LVM_SetControlParameters(hInstance, &Params);

    /*Restore the headroom parameters*/
    LVM_SetHeadroomParams(hInstance, &HeadroomParams);

    /* DC removal filter */
    DC_Mc_D16_TRC_WRA_01_Init(&pInstance->DC_RemovalInstance);

    return LVM_SUCCESS;
}
