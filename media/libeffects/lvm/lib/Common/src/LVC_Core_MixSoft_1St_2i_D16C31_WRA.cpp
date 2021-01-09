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

/**********************************************************************************
   INCLUDE FILES
***********************************************************************************/
#include <algorithm>
#include "LVC_Mixer_Private.h"
#include "ScalarArithmetic.h"
#include "LVM_Macros.h"

static inline LVM_FLOAT ADD2_SAT_FLOAT(LVM_FLOAT a, LVM_FLOAT b) {
    return std::clamp(a + b, -1.0f, 1.0f);
}
void LVC_Core_MixSoft_1St_MC_float_WRA(Mix_Private_FLOAT_st** ptrInstance, const LVM_FLOAT* src,
                                       LVM_FLOAT* dst, LVM_INT16 NrFrames, LVM_INT16 NrChannels) {
    LVM_INT32 ii, ch;
    LVM_FLOAT tempCurrent[NrChannels];
    for (ch = 0; ch < NrChannels; ch++) {
        tempCurrent[ch] = ptrInstance[ch]->Current;
    }
    for (ii = NrFrames; ii > 0; ii--) {
        for (ch = 0; ch < NrChannels; ch++) {
            Mix_Private_FLOAT_st* pInstance = ptrInstance[ch];
            const LVM_FLOAT Delta = pInstance->Delta;
            LVM_FLOAT Current = tempCurrent[ch];
            const LVM_FLOAT Target = pInstance->Target;
            if (Current < Target) {
                Current = ADD2_SAT_FLOAT(Current, Delta);
                if (Current > Target) Current = Target;
            } else {
                Current -= Delta;
                if (Current < Target) Current = Target;
            }
            *dst++ = *src++ * Current;
            tempCurrent[ch] = Current;
        }
    }
    for (ch = 0; ch < NrChannels; ch++) {
        ptrInstance[ch]->Current = tempCurrent[ch];
    }
}
