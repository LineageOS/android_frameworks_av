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

#ifndef _BIQUAD_H_
#define _BIQUAD_H_

#include "LVM_Types.h"
/**********************************************************************************
   INSTANCE MEMORY TYPE DEFINITION
***********************************************************************************/
typedef struct {
    /* The memory region created by this structure instance is typecast
     * into another structure containing a pointer and an array of filter
     * coefficients. In one case this memory region is used for storing
     * DC component of channels
     */
    LVM_FLOAT* pStorage;
    LVM_FLOAT Storage[LVM_MAX_CHANNELS];
} Biquad_FLOAT_Instance_t;
/**********************************************************************************
   COEFFICIENT TYPE DEFINITIONS
***********************************************************************************/

/*** Biquad coefficients **********************************************************/
typedef struct {
    LVM_FLOAT A2; /*  a2  */
    LVM_FLOAT A1; /*  a1  */
    LVM_FLOAT A0; /*  a0  */
    LVM_FLOAT B2; /* -b2! */
    LVM_FLOAT B1; /* -b1! */
} BQ_FLOAT_Coefs_t;

/*** First order coefficients *****************************************************/
typedef struct {
    LVM_FLOAT A1; /*  a1  */
    LVM_FLOAT A0; /*  a0  */
    LVM_FLOAT B1; /* -b1! */
} FO_FLOAT_Coefs_t;

/*** First order coefficients with Shift*****************************************************/
typedef struct {
    LVM_FLOAT A1; /*  a1  */
    LVM_FLOAT A0; /*  a0  */
    LVM_FLOAT B1; /* -b1! */
} FO_FLOAT_LShx_Coefs_t;
/*** Band pass coefficients *******************************************************/
typedef struct {
    LVM_FLOAT A0; /*  a0  */
    LVM_FLOAT B2; /* -b2! */
    LVM_FLOAT B1; /* -b1! */
} BP_FLOAT_Coefs_t;

/*** Peaking coefficients *********************************************************/
typedef struct {
    LVM_FLOAT A0; /*  a0  */
    LVM_FLOAT B2; /* -b2! */
    LVM_FLOAT B1; /* -b1! */
    LVM_FLOAT G;  /* Gain */
} PK_FLOAT_Coefs_t;


/**********************************************************************************
   FUNCTION PROTOTYPES: DC REMOVAL FILTERS
***********************************************************************************/

/*** 16 bit data path STEREO ******************************************************/
void DC_Mc_D16_TRC_WRA_01_Init(Biquad_FLOAT_Instance_t* pInstance);

void DC_Mc_D16_TRC_WRA_01(Biquad_FLOAT_Instance_t* pInstance, LVM_FLOAT* pDataIn,
                          LVM_FLOAT* pDataOut, LVM_INT16 NrFrames, LVM_INT16 NrChannels);

/**********************************************************************************/

#endif /** _BIQUAD_H_ **/
