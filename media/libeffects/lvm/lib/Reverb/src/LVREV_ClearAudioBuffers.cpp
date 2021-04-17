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
/* Includes                                                                             */
/*                                                                                      */
/****************************************************************************************/
#include "LVREV_Private.h"
#include "VectorArithmetic.h"

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                LVREV_ClearAudioBuffers                                     */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  This function is used to clear the internal audio buffers of the module.            */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  hInstance               Instance handle                                             */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVREV_SUCCESS          Initialisation succeeded                                     */
/*  LVREV_NULLADDRESS      Instance is NULL                                             */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1. This function must not be interrupted by the LVM_Process function                */
/*                                                                                      */
/****************************************************************************************/
LVREV_ReturnStatus_en LVREV_ClearAudioBuffers(LVREV_Handle_t hInstance) {
    LVREV_Instance_st* pLVREV_Private = (LVREV_Instance_st*)hInstance;

    /*
     * Check for error conditions
     */
    /* Check for NULL pointers */
    if (hInstance == LVM_NULL) {
        return LVREV_NULLADDRESS;
    }

    /*
     * Clear all filter tap data, delay-lines and other signal related data
     */

    pLVREV_Private->pRevHPFBiquad->clear();
    pLVREV_Private->pRevLPFBiquad->clear();
    for (size_t i = 0; i < pLVREV_Private->InstanceParams.NumDelays; i++) {
        pLVREV_Private->revLPFBiquad[i]->clear();
        memset(pLVREV_Private->pDelay_T[i], 0, LVREV_MAX_T_DELAY[i] *
                sizeof(pLVREV_Private->pDelay_T[i][0]));
    }
    return LVREV_SUCCESS;
}

/* End of file */
