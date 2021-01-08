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

#include <stdlib.h>
#include "LVPSA.h"
#include "LVPSA_Private.h"
#include "InstAlloc.h"

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:            LVPSA_Init                                                  */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Create and Initialize the LVPSA module including instance handle                */
/*                                                                                  */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  phInstance          Pointer to the instance handle                              */
/*  InitParams          Init parameters structure                                   */
/*  ControlParams       Control parameters structure                                */
/*  pScratch            Pointer to bundle scratch memory area                       */
/*                                                                                  */
/*                                                                                  */
/* RETURNS:                                                                         */
/*  LVPSA_OK            Succeeds                                                    */
/*  otherwise           Error due to bad parameters                                 */
/*                                                                                  */
/************************************************************************************/
LVPSA_RETURN LVPSA_Init(pLVPSA_Handle_t* phInstance, LVPSA_InitParams_t* pInitParams,
                        LVPSA_ControlParams_t* pControlParams, void* pScratch) {
    LVPSA_InstancePr_t* pLVPSA_Inst;
    LVPSA_RETURN errorCode = LVPSA_OK;
    LVM_UINT32 ii;
    extern LVM_FLOAT LVPSA_Float_GainTable[];
    LVM_UINT32 BufferLength = 0;

    /* Set the instance handle if not already initialised */
    *phInstance = calloc(1, sizeof(*pLVPSA_Inst));
    if (*phInstance == LVM_NULL) {
        return LVPSA_ERROR_NULLADDRESS;
    }
    pLVPSA_Inst = (LVPSA_InstancePr_t*)*phInstance;

    pLVPSA_Inst->pScratch = pScratch;

    /* Initialize module's internal parameters */
    pLVPSA_Inst->bControlPending = LVM_FALSE;
    pLVPSA_Inst->nBands = pInitParams->nBands;
    pLVPSA_Inst->MaxInputBlockSize = pInitParams->MaxInputBlockSize;
    pLVPSA_Inst->SpectralDataBufferDuration = pInitParams->SpectralDataBufferDuration;
    pLVPSA_Inst->CurrentParams.Fs = LVM_FS_DUMMY;
    pLVPSA_Inst->CurrentParams.LevelDetectionSpeed = LVPSA_SPEED_DUMMY;

    { /* for avoiding QAC warnings */
        LVM_INT32 SDBD = (LVM_INT32)pLVPSA_Inst->SpectralDataBufferDuration;
        LVM_INT32 IRTI = (LVM_INT32)LVPSA_InternalRefreshTimeInv;
        LVM_INT32 BL;

        MUL32x32INTO32(SDBD, IRTI, BL, LVPSA_InternalRefreshTimeShift)

                BufferLength = (LVM_UINT32)BL;
    }

    if ((BufferLength * LVPSA_InternalRefreshTime) != pLVPSA_Inst->SpectralDataBufferDuration) {
        pLVPSA_Inst->SpectralDataBufferLength = BufferLength + 1;
    } else {
        pLVPSA_Inst->SpectralDataBufferLength = BufferLength;
    }

    /* Assign the pointers */
    pLVPSA_Inst->pPostGains =
            (LVM_FLOAT*)calloc(pInitParams->nBands, sizeof(*(pLVPSA_Inst->pPostGains)));
    if (pLVPSA_Inst->pPostGains == LVM_NULL) {
        return LVPSA_ERROR_NULLADDRESS;
    }
    pLVPSA_Inst->pFiltersParams = (LVPSA_FilterParam_t*)calloc(
            pInitParams->nBands, sizeof(*(pLVPSA_Inst->pFiltersParams)));
    if (pLVPSA_Inst->pFiltersParams == LVM_NULL) {
        return LVPSA_ERROR_NULLADDRESS;
    }
    pLVPSA_Inst->pSpectralDataBufferStart = (LVM_UINT8*)calloc(
            pInitParams->nBands, pLVPSA_Inst->SpectralDataBufferLength *
                                         sizeof(*(pLVPSA_Inst->pSpectralDataBufferStart)));
    if (pLVPSA_Inst->pSpectralDataBufferStart == LVM_NULL) {
        return LVPSA_ERROR_NULLADDRESS;
    }
    pLVPSA_Inst->pPreviousPeaks =
            (LVM_UINT8*)calloc(pInitParams->nBands, sizeof(*(pLVPSA_Inst->pPreviousPeaks)));
    if (pLVPSA_Inst->pPreviousPeaks == LVM_NULL) {
        return LVPSA_ERROR_NULLADDRESS;
    }
    pLVPSA_Inst->pBPFiltersPrecision = (LVPSA_BPFilterPrecision_en*)calloc(
            pInitParams->nBands, sizeof(*(pLVPSA_Inst->pBPFiltersPrecision)));
    if (pLVPSA_Inst->pBPFiltersPrecision == LVM_NULL) {
        return LVPSA_ERROR_NULLADDRESS;
    }
#ifndef BIQUAD_OPT
    pLVPSA_Inst->pBP_Instances = (Biquad_FLOAT_Instance_t*)calloc(
            pInitParams->nBands, sizeof(*(pLVPSA_Inst->pBP_Instances)));
    if (pLVPSA_Inst->pBP_Instances == LVM_NULL) {
        return LVPSA_ERROR_NULLADDRESS;
    }
#endif
    pLVPSA_Inst->pQPD_States =
            (QPD_FLOAT_State_t*)calloc(pInitParams->nBands, sizeof(*(pLVPSA_Inst->pQPD_States)));
    if (pLVPSA_Inst->pQPD_States == LVM_NULL) {
        return LVPSA_ERROR_NULLADDRESS;
    }
#ifndef BIQUAD_OPT
    pLVPSA_Inst->pBP_Taps = (Biquad_1I_Order2_FLOAT_Taps_t*)calloc(
            pInitParams->nBands, sizeof(*(pLVPSA_Inst->pBP_Taps)));
    if (pLVPSA_Inst->pBP_Taps == LVM_NULL) {
        return LVPSA_ERROR_NULLADDRESS;
    }
#endif
    pLVPSA_Inst->pQPD_Taps =
            (QPD_FLOAT_Taps_t*)calloc(pInitParams->nBands, sizeof(*(pLVPSA_Inst->pQPD_Taps)));
    if (pLVPSA_Inst->pQPD_Taps == LVM_NULL) {
        return LVPSA_ERROR_NULLADDRESS;
    }

    /* Copy filters parameters in the private instance */
    for (ii = 0; ii < pLVPSA_Inst->nBands; ii++) {
        pLVPSA_Inst->pFiltersParams[ii] = pInitParams->pFiltersParams[ii];
    }

    /* Set Post filters gains*/
    for (ii = 0; ii < pLVPSA_Inst->nBands; ii++) {
        pLVPSA_Inst->pPostGains[ii] =
                LVPSA_Float_GainTable[15 + pInitParams->pFiltersParams[ii].PostGain];
    }
    pLVPSA_Inst->pSpectralDataBufferWritePointer = pLVPSA_Inst->pSpectralDataBufferStart;

    /* Initialize control dependant internal parameters */
    errorCode = LVPSA_Control(*phInstance, pControlParams);

    if (errorCode != 0) {
        return errorCode;
    }

    errorCode = LVPSA_ApplyNewSettings(pLVPSA_Inst);

    if (errorCode != 0) {
        return errorCode;
    }

    return (errorCode);
}

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:            LVPSA_DeInit                                                */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*    Free the memories created in LVPSA_Init call including instance handle        */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  phInstance          Pointer to the instance handle                              */
/*                                                                                  */
/************************************************************************************/
void LVPSA_DeInit(pLVPSA_Handle_t* phInstance) {
    LVPSA_InstancePr_t* pLVPSA_Inst = (LVPSA_InstancePr_t*)*phInstance;
    if (pLVPSA_Inst == LVM_NULL) {
        return;
    }
    if (pLVPSA_Inst->pPostGains != LVM_NULL) {
        free(pLVPSA_Inst->pPostGains);
        pLVPSA_Inst->pPostGains = LVM_NULL;
    }
    if (pLVPSA_Inst->pFiltersParams != LVM_NULL) {
        free(pLVPSA_Inst->pFiltersParams);
        pLVPSA_Inst->pFiltersParams = LVM_NULL;
    }
    if (pLVPSA_Inst->pSpectralDataBufferStart != LVM_NULL) {
        free(pLVPSA_Inst->pSpectralDataBufferStart);
        pLVPSA_Inst->pSpectralDataBufferStart = LVM_NULL;
    }
    if (pLVPSA_Inst->pPreviousPeaks != LVM_NULL) {
        free(pLVPSA_Inst->pPreviousPeaks);
        pLVPSA_Inst->pPreviousPeaks = LVM_NULL;
    }
    if (pLVPSA_Inst->pBPFiltersPrecision != LVM_NULL) {
        free(pLVPSA_Inst->pBPFiltersPrecision);
        pLVPSA_Inst->pBPFiltersPrecision = LVM_NULL;
    }
#ifndef BIQUAD_OPT
    if (pLVPSA_Inst->pBP_Instances != LVM_NULL) {
        free(pLVPSA_Inst->pBP_Instances);
        pLVPSA_Inst->pBP_Instances = LVM_NULL;
    }
#endif
    if (pLVPSA_Inst->pQPD_States != LVM_NULL) {
        free(pLVPSA_Inst->pQPD_States);
        pLVPSA_Inst->pQPD_States = LVM_NULL;
    }
#ifndef BIQUAD_OPT
    if (pLVPSA_Inst->pBP_Taps != LVM_NULL) {
        free(pLVPSA_Inst->pBP_Taps);
        pLVPSA_Inst->pBP_Taps = LVM_NULL;
    }
#endif
    if (pLVPSA_Inst->pQPD_Taps != LVM_NULL) {
        free(pLVPSA_Inst->pQPD_Taps);
        pLVPSA_Inst->pQPD_Taps = LVM_NULL;
    }
    free(pLVPSA_Inst);
    *phInstance = LVM_NULL;
}
