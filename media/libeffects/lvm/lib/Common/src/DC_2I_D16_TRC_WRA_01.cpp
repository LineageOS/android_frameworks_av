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
#include "DC_2I_D16_TRC_WRA_01_Private.h"
#include "LVM_Macros.h"
#include "ScalarArithmetic.h"
/*
 * FUNCTION:       DC_Mc_D16_TRC_WRA_01
 *
 * DESCRIPTION:
 *  DC removal from all channels of a multichannel input
 *
 * PARAMETERS:
 *  pInstance      Instance pointer
 *  pDataIn        Input/Source
 *  pDataOut       Output/Destination
 *  NrFrames       Number of frames
 *  NrChannels     Number of channels
 *
 * RETURNS:
 *  void
 *
 */
void DC_Mc_D16_TRC_WRA_01(Biquad_FLOAT_Instance_t* pInstance, LVM_FLOAT* pDataIn,
                          LVM_FLOAT* pDataOut, LVM_INT16 NrFrames, LVM_INT16 NrChannels) {
    LVM_FLOAT* ChDC;
    LVM_FLOAT Diff;
    LVM_INT32 j;
    LVM_INT32 i;
    PFilter_FLOAT_State_Mc pBiquadState = (PFilter_FLOAT_State_Mc)pInstance;

    ChDC = &pBiquadState->ChDC[0];
    for (j = NrFrames - 1; j >= 0; j--) {
        /* Subtract DC and saturate */
        for (i = NrChannels - 1; i >= 0; i--) {
            Diff = *(pDataIn++) - (ChDC[i]);
            *(pDataOut++) = LVM_Clamp(Diff);
            if (Diff < 0) {
                ChDC[i] -= DC_FLOAT_STEP;
            } else {
                ChDC[i] += DC_FLOAT_STEP;
            }
        }
    }
}
