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

/*######################################################################################*/
/*  Include files                                                                       */
/*######################################################################################*/

#include "ScalarArithmetic.h"

LVM_FLOAT Abs_Float(LVM_FLOAT input) {
    if (input < 0) {
        /* Negative input, so invert */
        input = (LVM_FLOAT)(-input);
    }
    return input;
}
