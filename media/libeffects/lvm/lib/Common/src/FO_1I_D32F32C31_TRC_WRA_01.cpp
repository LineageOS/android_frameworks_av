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

#include "BIQUAD.h"
#include "FO_1I_D32F32Cll_TRC_WRA_01_Private.h"
#include "LVM_Macros.h"

/**************************************************************************
 ASSUMPTIONS:
 COEFS-
 pBiquadState->coefs[0] is A1,
 pBiquadState->coefs[1] is A0,
 pBiquadState->coefs[2] is -B1, these are in Q31 format

 DELAYS-
 pBiquadState->pDelays[0] is x(n-1)L in Q0 format
 pBiquadState->pDelays[1] is y(n-1)L in Q0 format
***************************************************************************/
void FO_1I_D32F32C31_TRC_WRA_01( Biquad_FLOAT_Instance_t       *pInstance,
                                 LVM_FLOAT               *pDataIn,
                                 LVM_FLOAT               *pDataOut,
                                 LVM_INT16               NrSamples)
    {
        LVM_FLOAT  ynL,templ;
        LVM_INT16  ii;
        PFilter_State_FLOAT pBiquadState = (PFilter_State_FLOAT) pInstance;

        for (ii = NrSamples; ii != 0; ii--)
        {

            /**************************************************************************
                            PROCESSING OF THE LEFT CHANNEL
            ***************************************************************************/
            // ynL=A1  * x(n-1)L
            ynL = pBiquadState->coefs[0] * pBiquadState->pDelays[0];

            // ynL+=A0  * x(n)L
            templ = pBiquadState->coefs[1] * (*pDataIn);
            ynL += templ;

            // ynL+=  (-B1  * y(n-1)L
            templ = pBiquadState->coefs[2] * pBiquadState->pDelays[1];
            ynL += templ;

            /**************************************************************************
                            UPDATING THE DELAYS
            ***************************************************************************/
            pBiquadState->pDelays[1] = ynL; // Update y(n-1)L
            pBiquadState->pDelays[0] = (*pDataIn++); // Update x(n-1)L

            /**************************************************************************
                            WRITING THE OUTPUT
            ***************************************************************************/
            *pDataOut++ = (LVM_FLOAT)ynL; // Write Left output in Q0
        }

    }
