/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef __LVEQNB_TABLES_H__
#define __LVEQNB_TABLES_H__

/************************************************************************************/
/*                                                                                  */
/*    Sample rate table                                                             */
/*                                                                                  */
/************************************************************************************/

/*
 * Sample rate table for converting between the enumerated type and the actual
 * frequency
 */
extern const LVM_UINT32    LVEQNB_SampleRateTab[];

/************************************************************************************/
/*                                                                                  */
/*    Coefficient calculation tables                                                */
/*                                                                                  */
/************************************************************************************/

/*
 * Table for 2 * Pi / Fs
 */
extern const LVM_FLOAT     LVEQNB_TwoPiOnFsTable[];

/*
 * Gain table
 */
extern const LVM_FLOAT     LVEQNB_GainTable[];

/*
 * D table for 100 / (Gain + 1)
 */
extern const LVM_FLOAT     LVEQNB_DTable[];

/************************************************************************************/
/*                                                                                  */
/*    Filter polynomial coefficients                                                */
/*                                                                                  */
/************************************************************************************/

/*
 * Coefficients for calculating the cosine with the equation:
 *
 *  Cos(x) = (2^Shifts)*(a0 + a1*x + a2*x^2 + a3*x^3 + a4*x^4 + a5*x^5)
 *
 * These coefficients expect the input, x, to be in the range 0 to 32768 respresenting
 * a range of 0 to Pi. The output is in the range 32767 to -32768 representing the range
 * +1.0 to -1.0
 */
extern const LVM_INT16     LVEQNB_CosCoef[];

/*
 * Coefficients for calculating the cosine error with the equation:
 *
 *  CosErr(x) = (2^Shifts)*(a0 + a1*x + a2*x^2 + a3*x^3)
 *
 * These coefficients expect the input, x, to be in the range 0 to 32768 respresenting
 * a range of 0 to Pi/25. The output is in the range 0 to 32767 representing the range
 * 0.0 to 0.0078852986
 *
 * This is used to give a double precision cosine over the range 0 to Pi/25 using the
 * the equation:
 *
 * Cos(x) = 1.0 - CosErr(x)
 */
extern const LVM_INT16     LVEQNB_DPCosCoef[];

#endif /* __LVEQNB_TABLES_H__ */
