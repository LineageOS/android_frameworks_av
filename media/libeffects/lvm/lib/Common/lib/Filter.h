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

#ifndef _FILTER_H_
#define _FILTER_H_

/**********************************************************************************
   INCLUDES
***********************************************************************************/
#include "LVM_Types.h"
#include "BIQUAD.h"

/**********************************************************************************
   DEFINES
***********************************************************************************/
#define FILTER_LOSS     32730       /* -0.01dB loss to avoid wrapping due to band ripple */
#define FILTER_LOSS_FLOAT    0.998849f
/**********************************************************************************
   FUNCTION PROTOTYPES
***********************************************************************************/

LVM_FLOAT LVM_Power10(   LVM_FLOAT  X);

LVM_FLOAT LVM_Polynomial(LVM_UINT16 N,
                         LVM_FLOAT  *pCoefficients,
                         LVM_FLOAT  X);
LVM_FLOAT   LVM_GetOmega(LVM_UINT32  Fc,
                         LVM_Fs_en   SampleRate);

LVM_FLOAT LVM_FO_LPF(    LVM_FLOAT  w,
                         FO_FLOAT_Coefs_t  *pCoeffs);

LVM_FLOAT LVM_FO_HPF(    LVM_FLOAT  w,
                         FO_FLOAT_Coefs_t  *pCoeffs);
/**********************************************************************************/

#endif  /** _FILTER_H_ **/

