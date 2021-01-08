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
#include "PK_2I_D32F32CssGss_TRC_WRA_01_Private.h"
#include "LVM_Macros.h"

/**************************************************************************
DELAYS-
pBiquadState->pDelays[0] to
pBiquadState->pDelays[NrChannels - 1] is x(n-1) for all NrChannels

pBiquadState->pDelays[NrChannels] to
pBiquadState->pDelays[2*NrChannels - 1] is x(n-2) for all NrChannels

pBiquadState->pDelays[2*NrChannels] to
pBiquadState->pDelays[3*NrChannels - 1] is y(n-1) for all NrChannels

pBiquadState->pDelays[3*NrChannels] to
pBiquadState->pDelays[4*NrChannels - 1] is y(n-2) for all NrChannels
***************************************************************************/

void PK_Mc_D32F32C14G11_TRC_WRA_01(Biquad_FLOAT_Instance_t* pInstance, LVM_FLOAT* pDataIn,
                                   LVM_FLOAT* pDataOut, LVM_INT16 NrFrames, LVM_INT16 NrChannels) {
    LVM_FLOAT yn, ynO, temp;
    LVM_INT16 ii, jj;
    PFilter_State_Float pBiquadState = (PFilter_State_Float)pInstance;

    for (ii = NrFrames; ii != 0; ii--) {
        for (jj = 0; jj < NrChannels; jj++) {
            /**************************************************************************
                            PROCESSING OF THE jj CHANNEL
            ***************************************************************************/
            /* yn= (A0  * (x(n) - x(n-2)))*/
            temp = (*pDataIn) - pBiquadState->pDelays[NrChannels + jj];
            yn = temp * pBiquadState->coefs[0];

            /* yn+= ((-B2  * y(n-2))) */
            temp = pBiquadState->pDelays[NrChannels * 3 + jj] * pBiquadState->coefs[1];
            yn += temp;

            /* yn+= ((-B1 * y(n-1))) */
            temp = pBiquadState->pDelays[NrChannels * 2 + jj] * pBiquadState->coefs[2];
            yn += temp;

            /* ynO= ((Gain * yn)) */
            ynO = yn * pBiquadState->coefs[3];

            /* ynO=(ynO + x(n))*/
            ynO += (*pDataIn);

            /**************************************************************************
                            UPDATING THE DELAYS
            ***************************************************************************/
            pBiquadState->pDelays[NrChannels * 3 + jj] =
                    pBiquadState->pDelays[NrChannels * 2 + jj]; /* y(n-2)=y(n-1)*/
            pBiquadState->pDelays[NrChannels * 1 + jj] =
                    pBiquadState->pDelays[jj];               /* x(n-2)=x(n-1)*/
            pBiquadState->pDelays[NrChannels * 2 + jj] = yn; /* Update y(n-1) */
            pBiquadState->pDelays[jj] = (*pDataIn);          /* Update x(n-1)*/
            pDataIn++;

            /**************************************************************************
                            WRITING THE OUTPUT
            ***************************************************************************/
            *pDataOut = ynO; /* Write output*/
            pDataOut++;
        }
    }
}
