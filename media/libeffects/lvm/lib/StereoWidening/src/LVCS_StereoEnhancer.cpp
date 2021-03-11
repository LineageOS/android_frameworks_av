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
#include "LVCS_StereoEnhancer.h"
#include "VectorArithmetic.h"
#include "LVCS_Tables.h"

/************************************************************************************/
/*                                                                                  */
/* FUNCTION:                LVCS_StereoEnhanceInit                                  */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Initialises the stereo enhancement module based on the sample rate.             */
/*                                                                                  */
/*  The function selects the coefficients for the filters and clears the data       */
/*  history. It is also used for re-initialisation when one of the system control   */
/*  parameters changes but will only change the coefficients and clear the history  */
/*  if the sample rate or speaker type has changed.                                 */
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
LVCS_ReturnStatus_en LVCS_SEnhancerInit(LVCS_Handle_t hInstance, LVCS_Params_t* pParams) {
    LVM_UINT16 Offset;
    LVCS_Instance_t* pInstance = (LVCS_Instance_t*)hInstance;
    const BiquadA012B12CoefsSP_t* pSESideCoefs;

    /*
     * If the sample rate or speaker type has changed update the filters
     */
    if ((pInstance->Params.SampleRate != pParams->SampleRate) ||
        (pInstance->Params.SpeakerType != pParams->SpeakerType)) {
        /*
         * Set the filter coefficients based on the sample rate
         */
        /* Mid filter */
        Offset = (LVM_UINT16)pParams->SampleRate;

        std::array<LVM_FLOAT, android::audio_utils::kBiquadNumCoefs> coefs = {
                LVCS_SEMidCoefTable[Offset].A0, LVCS_SEMidCoefTable[Offset].A1, 0.0,
                LVCS_SEMidCoefTable[Offset].B1, 0.0};
        pInstance->pSEMidBiquad.reset(
                new android::audio_utils::BiquadFilter<LVM_FLOAT>(FCC_1, coefs));

        Offset = (LVM_UINT16)(pParams->SampleRate);
        pSESideCoefs = (BiquadA012B12CoefsSP_t*)&LVCS_SESideCoefTable[0];

        /* Side filter */
        coefs = {pSESideCoefs[Offset].A0, pSESideCoefs[Offset].A1, pSESideCoefs[Offset].A2,
                 pSESideCoefs[Offset].B1, pSESideCoefs[Offset].B2};
        pInstance->pSESideBiquad.reset(
                new android::audio_utils::BiquadFilter<LVM_FLOAT>(FCC_1, coefs));
    }

    return (LVCS_SUCCESS);
}
/************************************************************************************/
/*                                                                                  */
/* FUNCTION:                LVCS_StereoEnhance                                      */
/*                                                                                  */
/* DESCRIPTION:                                                                     */
/*  Enhance the stereo image in the input samples based on the following block      */
/*  diagram:                                                                        */
/*                                                                                  */
/*                               ________                                           */
/*          ________            |        |          ________                        */
/*         |        |  Middle   | Treble |         |        |                       */
/*         |        |---------->| Boost  |-------->|        |                       */
/*         | Stereo |           |________|         | M & S  |                       */
/*      -->|   to   |            ________          |   to   |-->                    */
/*         | M & S  |  Side     |        |         | Stereo |                       */
/*         |        |---------->| Side   |-------->|        |                       */
/*         |________|           | Boost  |         |________|                       */
/*                              |________|                                          */
/*                                                                                  */
/*                                                                                  */
/*  If the input signal is a mono signal there will be no side signal and hence     */
/*  the side filter will not be run. In mobile speaker mode the middle filter is    */
/*  not required and the Trebble boost filter is replaced by a simple gain block.   */
/*                                                                                  */
/*                                                                                  */
/* PARAMETERS:                                                                      */
/*  hInstance               Instance Handle                                         */
/*  pInData                 Pointer to the input data                               */
/*  pOutData                Pointer to the output data                              */
/*  NumSamples              Number of samples to process                            */
/*                                                                                  */
/* RETURNS:                                                                         */
/*  LVCS_Success            Always succeeds                                         */
/*                                                                                  */
/* NOTES:                                                                           */
/*  1.  The side filter is not used in Mobile Speaker mode                          */
/*                                                                                  */
/************************************************************************************/
LVCS_ReturnStatus_en LVCS_StereoEnhancer(LVCS_Handle_t hInstance, const LVM_FLOAT* pInData,
                                         LVM_FLOAT* pOutData, LVM_UINT16 NumSamples) {
    LVCS_Instance_t* pInstance = (LVCS_Instance_t*)hInstance;
    LVCS_StereoEnhancer_t* pConfig = (LVCS_StereoEnhancer_t*)&pInstance->StereoEnhancer;
    LVM_FLOAT* pScratch;
    pScratch = (LVM_FLOAT*)pInstance->pScratch;
    LVM_INT32 NumChannels = pInstance->Params.NrChannels;
    LVM_UINT16 destNumSamples = (NumChannels == FCC_1) ? NumSamples : FCC_2 * NumSamples;
    /*
     * Check if the Stereo Enhancer is enabled
     */
    if ((pInstance->Params.OperatingMode & LVCS_STEREOENHANCESWITCH) != 0) {
        /*
         * Convert from stereo to middle and side
         */
        if (NumChannels == 1) {
            // Copy same input to scratch as Middle data
            Copy_Float((LVM_FLOAT*)pInData, (LVM_FLOAT*)pScratch, (LVM_INT16)NumSamples);
        } else {
            From2iToMS_Float(pInData, pScratch, pScratch + NumSamples, (LVM_INT16)NumSamples);
        }

        /*
         * Apply filter to the middle signal
         */
        if (pInstance->OutputDevice == LVCS_HEADPHONE) {
            pInstance->pSEMidBiquad->process(pScratch, pScratch, NumSamples);
        } else {
            Mult3s_Float(pScratch,                    /* Source */
                         (LVM_FLOAT)pConfig->MidGain, /* Gain */
                         pScratch,                    /* Destination */
                         (LVM_INT16)NumSamples);      /* Number of samples */
        }

        /*
         * Apply the filter the side signal only in stereo mode for headphones
         * and in all modes for mobile speakers
         */
        if (pInstance->Params.SourceFormat == LVCS_STEREO) {
            pInstance->pSESideBiquad->process(pScratch + NumSamples, pScratch + NumSamples,
                                              NumSamples);
        }

        if (NumChannels == 1) {
            // Copy processed Middle data from scratch to pOutData
            Copy_Float((LVM_FLOAT*)pScratch, (LVM_FLOAT*)pOutData, (LVM_INT16)NumSamples);
        } else {
            /*
             * Convert from middle and side to stereo
             */
            MSTo2i_Sat_Float(pScratch, pScratch + NumSamples, pOutData, (LVM_INT16)NumSamples);
        }

    } else {
        /*
         * The stereo enhancer is disabled so just copy the data
         */
        Copy_Float((LVM_FLOAT*)pInData,        /* Source */
                   (LVM_FLOAT*)pOutData,       /* Destination */
                   (LVM_INT16)destNumSamples); /* Number of frames */
    }

    return (LVCS_SUCCESS);
}
