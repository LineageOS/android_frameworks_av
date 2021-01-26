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

#ifndef __LVEQNB_PRIVATE_H__
#define __LVEQNB_PRIVATE_H__

/****************************************************************************************/
/*                                                                                      */
/*  Includes                                                                            */
/*                                                                                      */
/****************************************************************************************/

#include <audio_utils/BiquadFilter.h>
#include "LVEQNB.h" /* Calling or Application layer definitions */
#include "BIQUAD.h"
#include "LVC_Mixer.h"

/****************************************************************************************/
/*                                                                                      */
/*  Defines                                                                             */
/*                                                                                      */
/****************************************************************************************/

/* General */
#define LVEQNB_INVALID 0xFFFF      /* Invalid init parameter */
#define LVEQNB_BYPASS_MIXER_TC 100 /* Bypass Mixer TC */

/****************************************************************************************/
/*                                                                                      */
/*  Types                                                                               */
/*                                                                                      */
/****************************************************************************************/

/* Filter biquad types */
typedef enum {
    LVEQNB_SinglePrecision_Float = -1,
    LVEQNB_SinglePrecision = 0,
    LVEQNB_DoublePrecision = 1,
    LVEQNB_OutOfRange = 2,
    LVEQNB_BIQUADTYPE_MAX = LVM_MAXINT_32
} LVEQNB_BiquadType_en;

/****************************************************************************************/
/*                                                                                      */
/*  Structures                                                                          */
/*                                                                                      */
/****************************************************************************************/

/* Instance structure */
typedef struct {
    /* Public parameters */
    void* pScratch;                     /* Pointer to bundle scratch buffer */
    LVEQNB_Params_t Params;             /* Instance parameters */
    LVEQNB_Capabilities_t Capabilities; /* Instance capabilities */

    /* Aligned memory pointers */
    LVM_FLOAT* pFastTemporary; /* Fast temporary data base address */

    std::vector<android::audio_utils::BiquadFilter<LVM_FLOAT>>
            eqBiquad;            /* Biquad filter instances */
    std::vector<LVM_FLOAT> gain; /* Gain values for all bands*/

    /* Filter definitions and call back */
    LVM_UINT16 NBands;                  /* Number of bands */
    LVEQNB_BandDef_t* pBandDefinitions; /* Filter band definitions */
    LVEQNB_BiquadType_en* pBiquadType;  /* Filter biquad types */

    /* Bypass variable */
    LVMixer3_2St_FLOAT_st BypassMixer;

    LVM_INT16 bInOperatingModeTransition; /* Operating mode transition flag */

} LVEQNB_Instance_t;

/****************************************************************************************/
/*                                                                                      */
/* Function prototypes                                                                  */
/*                                                                                      */
/****************************************************************************************/

void LVEQNB_SetFilters(LVEQNB_Instance_t* pInstance, LVEQNB_Params_t* pParams);

void LVEQNB_SetCoefficients(LVEQNB_Instance_t* pInstance);

void LVEQNB_ClearFilterHistory(LVEQNB_Instance_t* pInstance);
LVEQNB_ReturnStatus_en LVEQNB_SinglePrecCoefs(LVM_UINT16 Fs, LVEQNB_BandDef_t* pFilterDefinition,
                                              PK_FLOAT_Coefs_t* pCoefficients);

LVM_INT32 LVEQNB_BypassMixerCallBack(void* hInstance, void* pGeneralPurpose,
                                     LVM_INT16 CallbackParam);

#endif /* __LVEQNB_PRIVATE_H__ */
