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
/*    Header file for the private layer interface of Dynamic Bass Enhancement module    */
/*                                                                                      */
/*  This files includes all definitions, types, structures and function                 */
/*  prototypes required by the execution layer.                                         */
/*                                                                                      */
/****************************************************************************************/

#ifndef __LVDBE_PRIVATE_H__
#define __LVDBE_PRIVATE_H__

/****************************************************************************************/
/*                                                                                      */
/*    Includes                                                                          */
/*                                                                                      */
/****************************************************************************************/

#include <audio_utils/BiquadFilter.h>
#include "LVDBE.h" /* Calling or Application layer definitions */
#include "BIQUAD.h"
#include "LVC_Mixer.h"
#include "AGC.h"

/****************************************************************************************/
/*                                                                                      */
/*    Defines                                                                           */
/*                                                                                      */
/****************************************************************************************/

/* General */
#define LVDBE_INVALID 0xFFFF /* Invalid init parameter */

#define LVDBE_MIXER_TC 5          /* Mixer time  */
#define LVDBE_BYPASS_MIXER_TC 100 /* Bypass mixer time */

/****************************************************************************************/
/*                                                                                      */
/*    Structures                                                                        */
/*                                                                                      */
/****************************************************************************************/

/* Data structure */
/* Data structure */
typedef struct {
    /* AGC parameters */
    AGC_MIX_VOL_2St1Mon_FLOAT_t AGCInstance; /* AGC instance parameters */

    /* Process variables */
    LVMixer3_1St_FLOAT_st BypassVolume;    /* Bypass volume scaler */
    LVMixer3_2St_FLOAT_st BypassMixer;     /* Bypass Mixer for Click Removal */

} LVDBE_Data_FLOAT_t;


/* Instance structure */
typedef struct {
    /* Public parameters */
    LVDBE_Params_t Params;             /* Instance parameters */
    LVDBE_Capabilities_t Capabilities; /* Instance capabilities */

    /* Data and coefficient pointers */
    LVDBE_Data_FLOAT_t* pData; /* Instance data */
    void* pScratch;            /* scratch pointer */
    std::unique_ptr<android::audio_utils::BiquadFilter<LVM_FLOAT>>
            pHPFBiquad; /* Biquad filter instance for HPF */
    std::unique_ptr<android::audio_utils::BiquadFilter<LVM_FLOAT>>
            pBPFBiquad; /* Biquad filter instance for BPF */
} LVDBE_Instance_t;

/****************************************************************************************/
/*                                                                                      */
/* Function prototypes                                                                  */
/*                                                                                      */
/****************************************************************************************/

void LVDBE_SetAGC(LVDBE_Instance_t* pInstance, LVDBE_Params_t* pParams);

void LVDBE_SetVolume(LVDBE_Instance_t* pInstance, LVDBE_Params_t* pParams);

void LVDBE_SetFilters(LVDBE_Instance_t* pInstance, LVDBE_Params_t* pParams);

#endif /* __LVDBE_PRIVATE_H__ */
