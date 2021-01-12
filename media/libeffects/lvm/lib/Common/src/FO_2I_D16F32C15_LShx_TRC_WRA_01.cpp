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

#ifndef BIQUAD_OPT
#include "BIQUAD.h"
#include "FO_2I_D16F32Css_LShx_TRC_WRA_01_Private.h"
#include "LVM_Macros.h"

/**************************************************************************
ASSUMPTIONS:
COEFS-
pBiquadState->coefs[0] is A1,
pBiquadState->coefs[1] is A0,
pBiquadState->coefs[2] is -B1,
DELAYS-
pBiquadState->pDelays[2*ch + 0] is x(n-1) of the 'ch' - channel
pBiquadState->pDelays[2*ch + 1] is y(n-1) of the 'ch' - channel
The index 'ch' runs from 0 to (NrChannels - 1)

PARAMETERS:
 pInstance        Pointer Instance
 pDataIn          Input/Source
 pDataOut         Output/Destination
 NrFrames         Number of frames
 NrChannels       Number of channels

RETURNS:
 void
***************************************************************************/
void FO_Mc_D16F32C15_LShx_TRC_WRA_01(Biquad_FLOAT_Instance_t* pInstance, LVM_FLOAT* pDataIn,
                                     LVM_FLOAT* pDataOut, LVM_INT16 NrFrames,
                                     LVM_INT16 NrChannels) {
    LVM_FLOAT yn;
    LVM_FLOAT Temp;
    LVM_INT16 ii;
    LVM_INT16 ch;
    PFilter_Float_State pBiquadState = (PFilter_Float_State)pInstance;

    LVM_FLOAT* pDelays = pBiquadState->pDelays;
    LVM_FLOAT* pCoefs = &pBiquadState->coefs[0];
    LVM_FLOAT A0 = pCoefs[1];
    LVM_FLOAT A1 = pCoefs[0];
    LVM_FLOAT B1 = pCoefs[2];

    for (ii = NrFrames; ii != 0; ii--) {
        /**************************************************************************
                        PROCESSING OF THE CHANNELS
        ***************************************************************************/
        for (ch = 0; ch < NrChannels; ch++) {
            // yn =A1  * x(n-1)
            yn = (LVM_FLOAT)A1 * pDelays[0];

            // yn+=A0  * x(n)
            yn += (LVM_FLOAT)A0 * (*pDataIn);

            // yn +=  (-B1  * y(n-1))
            Temp = B1 * pDelays[1];
            yn += Temp;

            /**************************************************************************
                            UPDATING THE DELAYS
            ***************************************************************************/
            pDelays[1] = yn;            // Update y(n-1)
            pDelays[0] = (*pDataIn++);  // Update x(n-1)

            /**************************************************************************
                            WRITING THE OUTPUT
            ***************************************************************************/

            /*Saturate results*/
            if (yn > 1.0f) {
                yn = 1.0f;
            } else if (yn < -1.0f) {
                yn = -1.0f;
            }

            *pDataOut++ = (LVM_FLOAT)yn;
            pDelays += 2;
        }
        pDelays -= NrChannels * 2;
    }
}
#endif
