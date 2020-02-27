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
#include "BQ_2I_D32F32Cll_TRC_WRA_01_Private.h"
#include "LVM_Macros.h"

/**************************************************************************
 ASSUMPTIONS:
 COEFS-
 pBiquadState->coefs[0] is A2, pBiquadState->coefs[1] is A1
 pBiquadState->coefs[2] is A0, pBiquadState->coefs[3] is -B2
 pBiquadState->coefs[4] is -B1, these are in Q30 format

 DELAYS-
 pBiquadState->pDelays[0] is x(n-1)L in Q0 format
 pBiquadState->pDelays[1] is x(n-1)R in Q0 format
 pBiquadState->pDelays[2] is x(n-2)L in Q0 format
 pBiquadState->pDelays[3] is x(n-2)R in Q0 format
 pBiquadState->pDelays[4] is y(n-1)L in Q0 format
 pBiquadState->pDelays[5] is y(n-1)R in Q0 format
 pBiquadState->pDelays[6] is y(n-2)L in Q0 format
 pBiquadState->pDelays[7] is y(n-2)R in Q0 format
***************************************************************************/
void BQ_2I_D32F32C30_TRC_WRA_01 (           Biquad_FLOAT_Instance_t       *pInstance,
                                            LVM_FLOAT                    *pDataIn,
                                            LVM_FLOAT                    *pDataOut,
                                            LVM_INT16                    NrSamples)

    {
        LVM_FLOAT ynL,ynR,templ,tempd;
        LVM_INT16 ii;
        PFilter_State_FLOAT pBiquadState = (PFilter_State_FLOAT) pInstance;

         for (ii = NrSamples; ii != 0; ii--)
         {

            /**************************************************************************
                            PROCESSING OF THE LEFT CHANNEL
            ***************************************************************************/
            /* ynL= ( A2  * x(n-2)L  ) */
            ynL = pBiquadState->coefs[0] * pBiquadState->pDelays[2];

            /* ynL+= ( A1  * x(n-1)L  )*/
            templ = pBiquadState->coefs[1] * pBiquadState->pDelays[0];
            ynL += templ;

            /* ynL+= ( A0  * x(n)L  ) */
            templ = pBiquadState->coefs[2] * (*pDataIn);
            ynL += templ;

             /* ynL+= (-B2  * y(n-2)L  ) */
            templ = pBiquadState->coefs[3] * pBiquadState->pDelays[6];
            ynL += templ;

            /* ynL+= (-B1  * y(n-1)L  )*/
            templ = pBiquadState->coefs[4] * pBiquadState->pDelays[4];
            ynL += templ;

            /**************************************************************************
                            PROCESSING OF THE RIGHT CHANNEL
            ***************************************************************************/
            /* ynR= ( A2  * x(n-2)R  ) */
            ynR = pBiquadState->coefs[0] * pBiquadState->pDelays[3];

            /* ynR+= ( A1  * x(n-1)R  ) */
            templ = pBiquadState->coefs[1] * pBiquadState->pDelays[1];
            ynR += templ;

            /* ynR+= ( A0  * x(n)R  ) */
            tempd =* (pDataIn+1);
            templ = pBiquadState->coefs[2] * tempd;
            ynR += templ;

            /* ynR+= (-B2  * y(n-2)R  ) */
            templ = pBiquadState->coefs[3] * pBiquadState->pDelays[7];
            ynR += templ;

            /* ynR+= (-B1  * y(n-1)R  )  */
            templ = pBiquadState->coefs[4] * pBiquadState->pDelays[5];
            ynR += templ;

            /**************************************************************************
                            UPDATING THE DELAYS
            ***************************************************************************/
            pBiquadState->pDelays[7] = pBiquadState->pDelays[5]; /* y(n-2)R=y(n-1)R*/
            pBiquadState->pDelays[6] = pBiquadState->pDelays[4]; /* y(n-2)L=y(n-1)L*/
            pBiquadState->pDelays[3] = pBiquadState->pDelays[1]; /* x(n-2)R=x(n-1)R*/
            pBiquadState->pDelays[2] = pBiquadState->pDelays[0]; /* x(n-2)L=x(n-1)L*/
            pBiquadState->pDelays[5] = (LVM_FLOAT)ynR; /* Update y(n-1)R */
            pBiquadState->pDelays[4] = (LVM_FLOAT)ynL; /* Update y(n-1)L */
            pBiquadState->pDelays[0] = (*pDataIn); /* Update x(n-1)L */
            pDataIn++;
            pBiquadState->pDelays[1] = (*pDataIn); /* Update x(n-1)R */
            pDataIn++;

            /**************************************************************************
                            WRITING THE OUTPUT
            ***************************************************************************/
            *pDataOut = (LVM_FLOAT)ynL; /* Write Left output */
            pDataOut++;
            *pDataOut = (LVM_FLOAT)ynR; /* Write Right ouput */
            pDataOut++;

        }

    }

#ifdef SUPPORT_MC
/**************************************************************************
 ASSUMPTIONS:
 COEFS-
 pBiquadState->coefs[0] is A2, pBiquadState->coefs[1] is A1
 pBiquadState->coefs[2] is A0, pBiquadState->coefs[3] is -B2
 pBiquadState->coefs[4] is -B1

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
void BQ_MC_D32F32C30_TRC_WRA_01 (           Biquad_FLOAT_Instance_t      *pInstance,
                                            LVM_FLOAT                    *pDataIn,
                                            LVM_FLOAT                    *pDataOut,
                                            LVM_INT16                    NrFrames,
                                            LVM_INT16                    NrChannels)

    {
        LVM_FLOAT yn, temp;
        LVM_INT16 ii, jj;
        PFilter_State_FLOAT pBiquadState = (PFilter_State_FLOAT) pInstance;

         for (ii = NrFrames; ii != 0; ii--)
         {
            /**************************************************************************
                            PROCESSING CHANNEL-WISE
            ***************************************************************************/
            for (jj = 0; jj < NrChannels; jj++)
            {
                /* yn= (A2  * x(n-2)) */
                yn = pBiquadState->coefs[0] * pBiquadState->pDelays[NrChannels + jj];

                /* yn+= (A1  * x(n-1)) */
                temp = pBiquadState->coefs[1] * pBiquadState->pDelays[jj];
                yn += temp;

                /* yn+= (A0  * x(n)) */
                temp = pBiquadState->coefs[2] * (*pDataIn);
                yn += temp;

                 /* yn+= (-B2  * y(n-2)) */
                temp = pBiquadState->coefs[3] * pBiquadState->pDelays[NrChannels*3 + jj];
                yn += temp;

                /* yn+= (-B1  * y(n-1)) */
                temp = pBiquadState->coefs[4] * pBiquadState->pDelays[NrChannels*2 + jj];
                yn += temp;

                /**************************************************************************
                                UPDATING THE DELAYS
                ***************************************************************************/
                pBiquadState->pDelays[NrChannels * 3 + jj] =
                    pBiquadState->pDelays[NrChannels * 2 + jj]; /* y(n-2)=y(n-1)*/
                pBiquadState->pDelays[NrChannels * 1 + jj] =
                    pBiquadState->pDelays[jj]; /* x(n-2)=x(n-1)*/
                pBiquadState->pDelays[NrChannels * 2 + jj] = (LVM_FLOAT)yn; /* Update y(n-1)*/
                pBiquadState->pDelays[jj] = (*pDataIn); /* Update x(n-1)*/
                pDataIn++;
                /**************************************************************************
                                WRITING THE OUTPUT
                ***************************************************************************/
                *pDataOut = (LVM_FLOAT)yn; /* Write jj Channel output */
                pDataOut++;
            }
        }

    }
#endif /*SUPPORT_MC*/

