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
/*    Includes                                                                          */
/*                                                                                      */
/****************************************************************************************/

#include "LVEQNB_Private.h"
#include <math.h>

/****************************************************************************************/
/*                                                                                      */
/*    Defines                                                                           */
/*                                                                                      */
/****************************************************************************************/

#define PI 3.14159265358979

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                  LVEQNB_DoublePrecCoefs                                    */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*    Calculate double precision coefficients    for a peaking filter                   */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  Fs                           Sampling frequency index                               */
/*  pFilterDefinition          Pointer to the filter definition                         */
/*  pCoefficients            Pointer to the coefficients                                */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVEQNB_SUCCESS            Always succeeds                                           */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1. The equations used are as follows:                                               */
/*                                                                                      */
/*      G  = 10^(GaindB/20) - 1                                                         */
/*      t0 = 2 * Pi * Fc / Fs                                                           */
/*      D  = 1                  if GaindB >= 0                                          */
/*      D  = 1 / (1 + G)        if GaindB <  0                                          */
/*                                                                                      */
/*      b2 = -0.5 * (2Q - D * t0) / (2Q + D * t0)                                       */
/*      b1 = (0.5 - b2) * (1 - coserr(t0))                                              */
/*      a0 = (0.5 + b2) / 2                                                             */
/*                                                                                      */
/*  Where:                                                                              */
/*      GaindB      is the gain in dBs, range -15dB to +15dB                            */
/*      Fc          is the centre frequency, DC to Fs/50                                */
/*      Fs          is the sample frequency, 8000 to 48000 in descrete steps            */
/*      Q           is the Q factor, 0.25 to 12 (represented by 25 to 1200)             */
/*                                                                                      */
/*  2. The double precision coefficients are only used when fc is less than fs/85, so   */
/*     the cosine of t0 is always close to 1.0. Instead of calculating the cosine       */
/*     itself the difference from the value 1.0 is calculated, this can be done with    */
/*     lower precision maths.                                                           */
/*                                                                                      */
/*  3. The value of the B2 coefficient is only calculated as a single precision value,  */
/*     small errors in this value have a combined effect on the Q and Gain but not the  */
/*     the frequency of the filter.                                                     */
/*                                                                                      */
/****************************************************************************************/

/****************************************************************************************/
/*                                                                                      */
/* FUNCTION:                  LVEQNB_SinglePrecCoefs                                    */
/*                                                                                      */
/* DESCRIPTION:                                                                         */
/*    Calculate single precision coefficients    for a peaking filter                   */
/*                                                                                      */
/* PARAMETERS:                                                                          */
/*  Fs                           Sampling frequency index                               */
/*  pFilterDefinition          Pointer to the filter definition                         */
/*  pCoefficients            Pointer to the coefficients                                */
/*                                                                                      */
/* RETURNS:                                                                             */
/*  LVEQNB_SUCCESS            Always succeeds                                           */
/*                                                                                      */
/* NOTES:                                                                               */
/*  1. The equations used are as follows:                                               */
/*                                                                                      */
/*      G  = 10^(GaindB/20) - 1                                                         */
/*      t0 = 2 * Pi * Fc / Fs                                                           */
/*      D  = 1                  if GaindB >= 0                                          */
/*      D  = 1 / (1 + G)        if GaindB <  0                                          */
/*                                                                                      */
/*      b2 = -0.5 * (2Q - D * t0) / (2Q + D * t0)                                       */
/*      b1 = (0.5 - b2) * cos(t0)                                                       */
/*      a0 = (0.5 + b2) / 2                                                             */
/*                                                                                      */
/*  Where:                                                                              */
/*      GaindB      is the gain in dBs, range -15dB to +15dB                            */
/*      Fc          is the centre frequency, DC to Nyquist                              */
/*      Fs          is the sample frequency, 8000 to 48000 in descrete steps            */
/*      Q           is the Q factor, 0.25 to 12                                         */
/*                                                                                      */
/****************************************************************************************/

LVEQNB_ReturnStatus_en LVEQNB_SinglePrecCoefs(LVM_UINT16        Fs,
                                              LVEQNB_BandDef_t  *pFilterDefinition,
                                              PK_FLOAT_Coefs_t  *pCoefficients)
{

    extern LVM_FLOAT    LVEQNB_GainTable[];
    extern LVM_FLOAT    LVEQNB_TwoPiOnFsTable[];
    extern LVM_FLOAT    LVEQNB_DTable[];

    /*
     * Get the filter definition
     */
    LVM_INT16           Gain        = pFilterDefinition->Gain;
    LVM_UINT16          Frequency   = pFilterDefinition->Frequency;
    /* As mentioned in effectbundle.h */
    LVM_FLOAT           QFactor     = (LVM_FLOAT)pFilterDefinition->QFactor / 100.0f;

    /*
     * Intermediate variables and temporary values
     */
    LVM_FLOAT           T0;
    LVM_FLOAT           D;
    LVM_FLOAT           A0;
    LVM_FLOAT           B1;
    LVM_FLOAT           B2;

    /*
     * Calculating the intermediate values
     */
    T0 = Frequency * LVEQNB_TwoPiOnFsTable[Fs];        /* T0 = 2 * Pi * Fc / Fs */
    if (Gain >= 0)
    {
        D = LVEQNB_DTable[15];                         /* D = 1            if GaindB >= 0 */
    }
    else
    {
        D = LVEQNB_DTable[Gain + 15];                    /* D = 1 / (1 + G)  if GaindB <  0 */
    }

    /*
     * Calculate the B2,B1,A0 coefficients
     */
    B2 = -0.5 * (2 * QFactor - D * T0) / (2 * QFactor + D * T0);
    B1 = (0.5 - B2) * cos(T0);
    A0 = (0.5 + B2) / 2.0;

    /*
     * Write coeff into the data structure
     */
    /* all the coefficients are multiplied with 2 to make them align with fixed point values*/
    pCoefficients->A0 = 2 * A0;
    pCoefficients->B1 = 2 * B1;
    pCoefficients->B2 = 2 * B2;
    pCoefficients->G  = LVEQNB_GainTable[Gain + 15];

    return(LVEQNB_SUCCESS);
}
