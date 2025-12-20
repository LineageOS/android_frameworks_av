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

#include <system/audio.h>
#include "LVEQNB.h"
#include "LVEQNB_Private.h"
#include "VectorArithmetic.h"
#include "BIQUAD.h"

/****************************************************************************************/
/*                                                                                      */
/*  Defines                                                                             */
/*                                                                                      */
/****************************************************************************************/

#define LOW_FREQ 298  /* 32768/110 for low test frequency */
#define HIGH_FREQ 386 /* 32768/85 for high test frequency */

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                 LVEQNB_GetParameters                                       */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  Request the N-Band equaliser parameters. The current parameter set is returned via  */
/*  the parameter pointer.                                                              */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  hInstance                Instance handle                                            */
/*  pParams                  Pointer to an empty parameter structure                    */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVEQNB_SUCCESS          Succeeds                                                    */
/*  LVEQNB_NULLADDRESS      Instance or pParams  is NULL pointer                        */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1.  This function may be interrupted by the LVEQNB_Process function                 */
/*                                                                                      */
/****************************************************************************************/

LVEQNB_ReturnStatus_en LVEQNB_GetParameters(LVEQNB_Handle_t hInstance, LVEQNB_Params_t* pParams) {
    LVEQNB_Instance_t* pInstance = (LVEQNB_Instance_t*)hInstance;

    /*
     * Check for error conditions
     */
    if ((hInstance == LVM_NULL) || (pParams == LVM_NULL)) {
        return LVEQNB_NULLADDRESS;
    }

    *pParams = pInstance->Params;

    return (LVEQNB_SUCCESS);
}

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:                 LVEQNB_GetCapabilities                                 */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Get the N-Band equaliser capabilities. The current capabilities are returned    */
/*  via the pointer.                                                                */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  hInstance                Instance handle                                        */
/*  pCapabilities            Pointer to an empty capability structure               */
/*                                                                                  */
/* RETURNS:                                                                         */
/*  LVEQNB_Success           Succeeds                                               */
/*  LVEQNB_NULLADDRESS       hInstance or pCapabilities is NULL                     */
/*                                                                                  */
/* NOTES:                                                                           */
/*  1.  This function may be interrupted by the LVEQNB_Process function             */
/*                                                                                  */
/************************************************************************************/

LVEQNB_ReturnStatus_en LVEQNB_GetCapabilities(LVEQNB_Handle_t hInstance,
                                              LVEQNB_Capabilities_t* pCapabilities) {
    LVEQNB_Instance_t* pInstance = (LVEQNB_Instance_t*)hInstance;

    if ((hInstance == LVM_NULL) || (pCapabilities == LVM_NULL)) {
        return LVEQNB_NULLADDRESS;
    }

    *pCapabilities = pInstance->Capabilities;

    return (LVEQNB_SUCCESS);
}

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:            LVEQNB_SetFilters                                           */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Sets the filter type based on the definition.                                   */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  pInstance           Pointer to the instance                                     */
/*  pParams             Initialisation parameters                                   */
/*                                                                                  */
/* RETURNS:                                                                         */
/*  void                Nothing                                                     */
/*                                                                                  */
/* NOTES:                                                                           */
/*  1. To select the biquad type the follow rules are applied:                      */
/*          Double precision    if (fc <= fs/110)                                   */
/*          Double precision    if (fs/110 < fc < fs/85) & (Q>3)                    */
/*          Single precision    otherwise                                           */
/*                                                                                  */
/************************************************************************************/

void LVEQNB_SetFilters(LVEQNB_Instance_t* pInstance, LVEQNB_Params_t* pParams) {
    extern const LVM_UINT32 LVEQNB_SampleRateTab[]; /* Sample rate table */

    LVM_UINT16 i; /* Filter band index */
    LVM_UINT32 fs =
            (LVM_UINT32)LVEQNB_SampleRateTab[(LVM_UINT16)pParams->SampleRate]; /* Sample rate */
    LVM_UINT32 fc;     /* Filter centre frequency */

    pInstance->NBands = pParams->NBands;

    for (i = 0; i < pParams->NBands; i++) {
        /*
         * Get the filter settings
         */
        fc = (LVM_UINT32)pParams->pBandDefinition[i].Frequency; /* Get the band centre frequency */

        pInstance->pBiquadType[i] = LVEQNB_SinglePrecision_Float; /* Default to single precision */

        /*
         * Check for out of range frequencies
         */
        if (fc > (fs >> 1)) {
            pInstance->pBiquadType[i] = LVEQNB_OutOfRange;
        }

        /*
         * Copy the filter definition to persistant memory
         */
        pInstance->pBandDefinitions[i] = pParams->pBandDefinition[i];
    }
}

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:            LVEQNB_SetCoefficients                                      */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Sets the filter coefficients. This uses the type to select single or double     */
/*  precision coefficients.                                                         */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  pInstance           Pointer to the instance                                     */
/*  pParams             Initialisation parameters                                   */
/*                                                                                  */
/************************************************************************************/

void LVEQNB_SetCoefficients(LVEQNB_Instance_t* pInstance) {
    LVM_UINT16 i;                    /* Filter band index */
    LVEQNB_BiquadType_en BiquadType; /* Filter biquad type */

    pInstance->gain.resize(pInstance->Params.NBands);
    /*
     * Set the coefficients for each band by the init function
     */
    for (i = 0; i < pInstance->Params.NBands; i++) {
        /*
         * Check band type for correct initialisation method and recalculate the coefficients
         */
        BiquadType = pInstance->pBiquadType[i];
        switch (BiquadType) {
            case LVEQNB_SinglePrecision_Float: {
                PK_FLOAT_Coefs_t Coefficients;
                /*
                 * Calculate the single precision coefficients
                 */
                LVEQNB_SinglePrecCoefs((LVM_UINT16)pInstance->Params.SampleRate,
                                       &pInstance->pBandDefinitions[i], &Coefficients);
                /*
                 * Set the coefficients
                 */
                pInstance->gain[i] = Coefficients.G;
                std::array<LVM_FLOAT, android::audio_utils::kBiquadNumCoefs> coefs = {
                        Coefficients.A0, 0.0, -(Coefficients.A0), -(Coefficients.B1),
                        -(Coefficients.B2)};
                pInstance->eqBiquad[i]
                        .setCoefficients<
                                std::array<LVM_FLOAT, android::audio_utils::kBiquadNumCoefs>>(
                                coefs);
                break;
            }
            default:
                break;
        }
    }
}

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:            LVEQNB_ClearFilterHistory                                   */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Clears the filter data history                                                  */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  pInstance           Pointer to the instance                                     */
/*                                                                                  */
/************************************************************************************/
void LVEQNB_ClearFilterHistory(LVEQNB_Instance_t* pInstance) {
    for (size_t i = 0; i < pInstance->eqBiquad.size(); i++) {
        pInstance->eqBiquad[i].clear();
    }
}
/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                LVEQNB_Control                                              */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  Sets or changes the LifeVibes module parameters.                                    */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  hInstance               Instance handle                                             */
/*  pParams                 Pointer to a parameter structure                            */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVEQNB_Success          Always succeeds                                             */
/*  LVEQNB_NULLADDRESS      Instance or pParams  is NULL pointer                        */
/*  LVEQNB_NULLADDRESS      NULL address for the equaliser filter definitions and the   */
/*                          number of bands is non-zero                                 */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1.  This function may be interrupted by the LVEQNB_Process function                 */
/*                                                                                      */
/****************************************************************************************/

LVEQNB_ReturnStatus_en LVEQNB_Control(LVEQNB_Handle_t hInstance, LVEQNB_Params_t* pParams) {
    LVEQNB_Instance_t* pInstance = (LVEQNB_Instance_t*)hInstance;
    LVM_INT16 bChange = LVM_FALSE;
    LVM_INT16 i = 0;
    LVEQNB_Mode_en OperatingModeSave;

    /*
     * Check for error conditions
     */
    if ((hInstance == LVM_NULL) || (pParams == LVM_NULL)) {
        return LVEQNB_NULLADDRESS;
    }

    if ((pParams->NBands != 0) && (pParams->pBandDefinition == LVM_NULL)) {
        return LVEQNB_NULLADDRESS;
    }

    OperatingModeSave = pInstance->Params.OperatingMode;

    /* Set the alpha factor of the mixer */
    if (pParams->SampleRate != pInstance->Params.SampleRate) {
        LVC_Mixer_VarSlope_SetTimeConstant(&pInstance->BypassMixer.MixerStream[0],
                                           LVEQNB_BYPASS_MIXER_TC, (LVM_Fs_en)pParams->SampleRate,
                                           2);
        LVC_Mixer_VarSlope_SetTimeConstant(&pInstance->BypassMixer.MixerStream[1],
                                           LVEQNB_BYPASS_MIXER_TC, (LVM_Fs_en)pParams->SampleRate,
                                           2);
    }

    if ((pInstance->Params.NBands != pParams->NBands) ||
        (pInstance->Params.OperatingMode != pParams->OperatingMode) ||
        (pInstance->Params.pBandDefinition != pParams->pBandDefinition) ||
        (pInstance->Params.SampleRate != pParams->SampleRate) ||
        (pInstance->Params.SourceFormat != pParams->SourceFormat)) {
        bChange = LVM_TRUE;
    } else {
        for (i = 0; i < pParams->NBands; i++) {
            if ((pInstance->pBandDefinitions[i].Frequency !=
                 pParams->pBandDefinition[i].Frequency) ||
                (pInstance->pBandDefinitions[i].Gain != pParams->pBandDefinition[i].Gain) ||
                (pInstance->pBandDefinitions[i].QFactor != pParams->pBandDefinition[i].QFactor)) {
                bChange = LVM_TRUE;
            }
        }
    }

    // During operating mode transition, there is a race condition where the mode
    // is still LVEQNB_ON, but the effect is considered disabled in the upper layers.
    // modeChange handles this special race condition.
    const int /* bool */ modeChange =
            pParams->OperatingMode != OperatingModeSave ||
            (OperatingModeSave == LVEQNB_ON && pInstance->bInOperatingModeTransition &&
             LVC_Mixer_GetTarget(&pInstance->BypassMixer.MixerStream[0]) == 0);

    /*
     * Create biquad instance
     */
    if (pParams->NrChannels != pInstance->Params.NrChannels) {
        pInstance->eqBiquad.clear();
        pInstance->eqBiquad.resize(pParams->NBands,
                           android::audio_utils::BiquadFilter<LVM_FLOAT>(pParams->NrChannels));
    }
    if (bChange || modeChange) {
        LVEQNB_ClearFilterHistory(pInstance);
        /*
         * If the sample rate has changed clear the history
         */
        if (pInstance->Params.SampleRate != pParams->SampleRate) {
            LVEQNB_ClearFilterHistory(pInstance); /* Clear the history */
        }

        /*
         * Update the instance parameters
         */
        pInstance->Params = *pParams;

        /*
         * Reset the filters except if the algo is switched off
         */
        if (pParams->OperatingMode != LVEQNB_BYPASS) {
            /*
             * Reset the filters as all parameters could have changed
             */
            LVEQNB_SetFilters(pInstance, /* Instance pointer */
                              pParams);  /* New parameters */

            /*
             * Update the filters
             */
            LVEQNB_SetCoefficients(pInstance); /* Instance pointer */
        }

        if (modeChange) {
            if (pParams->OperatingMode == LVEQNB_ON) {
                LVC_Mixer_SetTarget(&pInstance->BypassMixer.MixerStream[0], 1.0f);
                LVC_Mixer_SetTarget(&pInstance->BypassMixer.MixerStream[1], 0.0f);
                pInstance->BypassMixer.MixerStream[0].CallbackSet = 1;
                pInstance->BypassMixer.MixerStream[1].CallbackSet = 1;
            } else {
                /* Stay on the ON operating mode until the transition is done */
                // This may introduce a state race condition if the effect is enabled again
                // while in transition.  This is fixed in the modeChange logic.
                pInstance->Params.OperatingMode = LVEQNB_ON;
                LVC_Mixer_SetTarget(&pInstance->BypassMixer.MixerStream[0], 0.0f);
                LVC_Mixer_SetTarget(&pInstance->BypassMixer.MixerStream[1], 1.0f);
                pInstance->BypassMixer.MixerStream[0].CallbackSet = 1;
                pInstance->BypassMixer.MixerStream[1].CallbackSet = 1;
            }
            LVC_Mixer_VarSlope_SetTimeConstant(&pInstance->BypassMixer.MixerStream[0],
                                               LVEQNB_BYPASS_MIXER_TC,
                                               (LVM_Fs_en)pParams->SampleRate, 2);
            LVC_Mixer_VarSlope_SetTimeConstant(&pInstance->BypassMixer.MixerStream[1],
                                               LVEQNB_BYPASS_MIXER_TC,
                                               (LVM_Fs_en)pParams->SampleRate, 2);
            pInstance->bInOperatingModeTransition = LVM_TRUE;
        }
    }
    return (LVEQNB_SUCCESS);
}

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                LVEQNB_BypassMixerCallBack                                  */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*  CallBack function of the mixer                                                      */
/*  transition                                                                          */
/*                                                                                      */
/****************************************************************************************/
LVM_INT32 LVEQNB_BypassMixerCallBack(void* hInstance, void* pGeneralPurpose,
                                     LVM_INT16 CallbackParam) {
    LVEQNB_Instance_t* pInstance = (LVEQNB_Instance_t*)hInstance;
    LVM_Callback CallBack = pInstance->Capabilities.CallBack;

    (void)pGeneralPurpose;

    /*
     * Send an ALGOFF event if the ON->OFF switch transition is finished
     */
    if ((LVC_Mixer_GetTarget(&pInstance->BypassMixer.MixerStream[0]) == 0) &&
        (CallbackParam == 0)) {
        pInstance->Params.OperatingMode = LVEQNB_BYPASS;
        if (CallBack != LVM_NULL) {
            CallBack(pInstance->Capabilities.pBundleInstance, LVM_NULL,
                     ALGORITHM_EQNB_ID | LVEQNB_EVENT_ALGOFF);
        }
    }

    /*
     *  Exit transition state
     */
    pInstance->bInOperatingModeTransition = LVM_FALSE;

    return 1;
}
