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

#include <system/audio.h>
#include "LVCS.h"
#include "LVCS_Private.h"
#include "LVCS_Equaliser.h"
#include "BIQUAD.h"
#include "VectorArithmetic.h"
#include "LVCS_Tables.h"

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:                LVCS_EqualiserInit                                      */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Initialises the equaliser module                                                */
/*                                                                                  */
/*  The function selects the coefficients for the filters and clears the data       */
/*  history. It is also used for re-initialisation when one of the system control   */
/*  parameters changes but will only change the coefficients and clear the history  */
/*  if the sample rate or speaker type has changed.                                 */
/*                                                                                  */
/*  To avoid excessive testing during the sample processing the biquad type is      */
/*  set as a callback function in the init routine.                                 */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  hInstance               Instance Handle                                         */
/*  pParams                 Initialisation parameters                               */
/*                                                                                  */
/* RETURNS:                                                                         */
/*  LVCS_Success            Always succeeds                                         */
/*                                                                                  */
/* NOTES:                                                                           */
/*                                                                                  */
/************************************************************************************/
LVCS_ReturnStatus_en LVCS_EqualiserInit(LVCS_Handle_t hInstance, LVCS_Params_t* pParams) {
    LVM_UINT16 Offset;
    LVCS_Instance_t* pInstance = (LVCS_Instance_t*)hInstance;
    const BiquadA012B12CoefsSP_t* pEqualiserCoefTable;

    /*
     * If the sample rate changes re-initialise the filters
     */
    if ((pInstance->Params.SampleRate != pParams->SampleRate) ||
        (pInstance->Params.SpeakerType != pParams->SpeakerType)) {
        /*
         * Setup the filter coefficients and clear the history
         */
        Offset = (LVM_UINT16)(pParams->SampleRate + (pParams->SpeakerType * (1 + LVM_FS_48000)));
        pEqualiserCoefTable = (BiquadA012B12CoefsSP_t*)&LVCS_EqualiserCoefTable[0];

        std::array<LVM_FLOAT, android::audio_utils::kBiquadNumCoefs> coefs = {
                pEqualiserCoefTable[Offset].A0, pEqualiserCoefTable[Offset].A1,
                pEqualiserCoefTable[Offset].A2, -(pEqualiserCoefTable[Offset].B1),
                -(pEqualiserCoefTable[Offset].B2)};
        pInstance->pEqBiquad.reset(new android::audio_utils::BiquadFilter<LVM_FLOAT>(
                (pParams->NrChannels == FCC_1) ? FCC_1 : FCC_2, coefs));
    }

    return (LVCS_SUCCESS);
}
/************************************************************************************/
/*                                                                                  */
/* FUNCTION:                LVCS_Equaliser                                          */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Apply the equaliser filter.                                                     */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  hInstance               Instance Handle                                         */
/*  pInputOutput            Pointer to the input/output buffer                      */
/*  NumSamples              The number of samples to process                        */
/*                                                                                  */
/* RETURNS:                                                                         */
/*  LVCS_Success            Always succeeds                                         */
/*                                                                                  */
/* NOTES:                                                                           */
/*  1.  Always processes in place.                                                  */
/*                                                                                  */
/************************************************************************************/
LVCS_ReturnStatus_en LVCS_Equaliser(LVCS_Handle_t hInstance, LVM_FLOAT* pInputOutput,
                                    LVM_UINT16 NumSamples) {
    LVCS_Instance_t* pInstance = (LVCS_Instance_t*)hInstance;

    /*
     * Check if the equaliser is required
     */
    if ((pInstance->Params.OperatingMode & LVCS_EQUALISERSWITCH) != 0) {
        /* Apply filter to the left and right channels */
        pInstance->pEqBiquad->process(pInputOutput, pInputOutput, NumSamples);
    }

    return (LVCS_SUCCESS);
}
