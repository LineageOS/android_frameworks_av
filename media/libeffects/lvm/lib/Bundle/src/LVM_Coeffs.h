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

#ifndef __LVM_COEFFS_H__
#define __LVM_COEFFS_H__

/************************************************************************************/
/*                                                                                  */
/* High Pass Shelving Filter coefficients                                           */
/*                                                                                  */
/************************************************************************************/

#define TrebleBoostCorner                                  8000
#define TrebleBoostMinRate                                    4
#define TrebleBoostSteps                                     15

/* Coefficients for sample rate 22050Hz */
                                                                    /* Gain =  1.000000 dB */
#define HPF_Fs22050_Gain1_A0                            1.038434
#define HPF_Fs22050_Gain1_A1                            0.331599
#define HPF_Fs22050_Gain1_A2                            0.000000
#define HPF_Fs22050_Gain1_B1                            0.370033
#define HPF_Fs22050_Gain1_B2                            0.000000
                                                                    /* Gain =  2.000000 dB */
#define HPF_Fs22050_Gain2_A0                            1.081557
#define HPF_Fs22050_Gain2_A1                            0.288475
#define HPF_Fs22050_Gain2_A2                            0.000000
#define HPF_Fs22050_Gain2_B1                            0.370033
#define HPF_Fs22050_Gain2_B2                            0.000000
                                                                    /* Gain =  3.000000 dB */
#define HPF_Fs22050_Gain3_A0                            1.129943
#define HPF_Fs22050_Gain3_A1                            0.240090
#define HPF_Fs22050_Gain3_A2                            0.000000
#define HPF_Fs22050_Gain3_B1                            0.370033
#define HPF_Fs22050_Gain3_B2                            0.000000
                                                                    /* Gain =  4.000000 dB */
#define HPF_Fs22050_Gain4_A0                            1.184232
#define HPF_Fs22050_Gain4_A1                            0.185801
#define HPF_Fs22050_Gain4_A2                            0.000000
#define HPF_Fs22050_Gain4_B1                            0.370033
#define HPF_Fs22050_Gain4_B2                            0.000000
                                                                    /* Gain =  5.000000 dB */
#define HPF_Fs22050_Gain5_A0                            1.245145
#define HPF_Fs22050_Gain5_A1                            0.124887
#define HPF_Fs22050_Gain5_A2                            0.000000
#define HPF_Fs22050_Gain5_B1                            0.370033
#define HPF_Fs22050_Gain5_B2                            0.000000
                                                                    /* Gain =  6.000000 dB */
#define HPF_Fs22050_Gain6_A0                            1.313491
#define HPF_Fs22050_Gain6_A1                            0.056541
#define HPF_Fs22050_Gain6_A2                            0.000000
#define HPF_Fs22050_Gain6_B1                            0.370033
#define HPF_Fs22050_Gain6_B2                            0.000000
                                                                    /* Gain =  7.000000 dB */
#define HPF_Fs22050_Gain7_A0                            1.390177
#define HPF_Fs22050_Gain7_A1                            (-0.020144)
#define HPF_Fs22050_Gain7_A2                            0.000000
#define HPF_Fs22050_Gain7_B1                            0.370033
#define HPF_Fs22050_Gain7_B2                            0.000000
                                                                    /* Gain =  8.000000 dB */
#define HPF_Fs22050_Gain8_A0                            1.476219
#define HPF_Fs22050_Gain8_A1                            (-0.106187)
#define HPF_Fs22050_Gain8_A2                            0.000000
#define HPF_Fs22050_Gain8_B1                            0.370033
#define HPF_Fs22050_Gain8_B2                            0.000000
                                                                    /* Gain =  9.000000 dB */
#define HPF_Fs22050_Gain9_A0                            1.572761
#define HPF_Fs22050_Gain9_A1                            (-0.202728)
#define HPF_Fs22050_Gain9_A2                            0.000000
#define HPF_Fs22050_Gain9_B1                            0.370033
#define HPF_Fs22050_Gain9_B2                            0.000000
                                                                    /* Gain =  10.000000 dB */
#define HPF_Fs22050_Gain10_A0                           1.681082
#define HPF_Fs22050_Gain10_A1                           (-0.311049)
#define HPF_Fs22050_Gain10_A2                           0.000000
#define HPF_Fs22050_Gain10_B1                           0.370033
#define HPF_Fs22050_Gain10_B2                           0.000000
                                                                    /* Gain =  11.000000 dB */
#define HPF_Fs22050_Gain11_A0                           1.802620
#define HPF_Fs22050_Gain11_A1                           (-0.432588)
#define HPF_Fs22050_Gain11_A2                           0.000000
#define HPF_Fs22050_Gain11_B1                           0.370033
#define HPF_Fs22050_Gain11_B2                           0.000000
                                                                    /* Gain =  12.000000 dB */
#define HPF_Fs22050_Gain12_A0                           1.938989
#define HPF_Fs22050_Gain12_A1                           (-0.568956)
#define HPF_Fs22050_Gain12_A2                           0.000000
#define HPF_Fs22050_Gain12_B1                           0.370033
#define HPF_Fs22050_Gain12_B2                           0.000000
                                                                    /* Gain =  13.000000 dB */
#define HPF_Fs22050_Gain13_A0                           2.091997
#define HPF_Fs22050_Gain13_A1                           (-0.721964)
#define HPF_Fs22050_Gain13_A2                           0.000000
#define HPF_Fs22050_Gain13_B1                           0.370033
#define HPF_Fs22050_Gain13_B2                           0.000000
                                                                    /* Gain =  14.000000 dB */
#define HPF_Fs22050_Gain14_A0                           2.263674
#define HPF_Fs22050_Gain14_A1                           (-0.893641)
#define HPF_Fs22050_Gain14_A2                           0.000000
#define HPF_Fs22050_Gain14_B1                           0.370033
#define HPF_Fs22050_Gain14_B2                           0.000000
                                                                    /* Gain =  15.000000 dB */
#define HPF_Fs22050_Gain15_A0                           2.456300
#define HPF_Fs22050_Gain15_A1                           (-1.086267)
#define HPF_Fs22050_Gain15_A2                           0.000000
#define HPF_Fs22050_Gain15_B1                           0.370033
#define HPF_Fs22050_Gain15_B2                           0.000000
/* Coefficients for sample rate 24000Hz */
                                                                    /* Gain =  1.000000 dB */
#define HPF_Fs24000_Gain1_A0                            1.044662
#define HPF_Fs24000_Gain1_A1                            0.223287
#define HPF_Fs24000_Gain1_A2                            0.000000
#define HPF_Fs24000_Gain1_B1                            0.267949
#define HPF_Fs24000_Gain1_B2                            0.000000
                                                                    /* Gain =  2.000000 dB */
#define HPF_Fs24000_Gain2_A0                            1.094773
#define HPF_Fs24000_Gain2_A1                            0.173176
#define HPF_Fs24000_Gain2_A2                            0.000000
#define HPF_Fs24000_Gain2_B1                            0.267949
#define HPF_Fs24000_Gain2_B2                            0.000000
                                                                    /* Gain =  3.000000 dB */
#define HPF_Fs24000_Gain3_A0                            1.150999
#define HPF_Fs24000_Gain3_A1                            0.116950
#define HPF_Fs24000_Gain3_A2                            0.000000
#define HPF_Fs24000_Gain3_B1                            0.267949
#define HPF_Fs24000_Gain3_B2                            0.000000
                                                                    /* Gain =  4.000000 dB */
#define HPF_Fs24000_Gain4_A0                            1.214086
#define HPF_Fs24000_Gain4_A1                            0.053863
#define HPF_Fs24000_Gain4_A2                            0.000000
#define HPF_Fs24000_Gain4_B1                            0.267949
#define HPF_Fs24000_Gain4_B2                            0.000000
                                                                    /* Gain =  5.000000 dB */
#define HPF_Fs24000_Gain5_A0                            1.284870
#define HPF_Fs24000_Gain5_A1                            (-0.016921)
#define HPF_Fs24000_Gain5_A2                            0.000000
#define HPF_Fs24000_Gain5_B1                            0.267949
#define HPF_Fs24000_Gain5_B2                            0.000000
                                                                    /* Gain =  6.000000 dB */
#define HPF_Fs24000_Gain6_A0                           1.364291
#define HPF_Fs24000_Gain6_A1                           (-0.096342)
#define HPF_Fs24000_Gain6_A2                           0.000000
#define HPF_Fs24000_Gain6_B1                           0.267949
#define HPF_Fs24000_Gain6_B2                           0.000000
                                                                    /* Gain =  7.000000 dB */
#define HPF_Fs24000_Gain7_A0                            1.453403
#define HPF_Fs24000_Gain7_A1                            (-0.185454)
#define HPF_Fs24000_Gain7_A2                            0.000000
#define HPF_Fs24000_Gain7_B1                            0.267949
#define HPF_Fs24000_Gain7_B2                            0.000000
                                                                    /* Gain =  8.000000 dB */
#define HPF_Fs24000_Gain8_A0                            1.553389
#define HPF_Fs24000_Gain8_A1                            (-0.285440)
#define HPF_Fs24000_Gain8_A2                            0.000000
#define HPF_Fs24000_Gain8_B1                            0.267949
#define HPF_Fs24000_Gain8_B2                            0.000000
                                                                    /* Gain =  9.000000 dB */
#define HPF_Fs24000_Gain9_A0                            1.665574
#define HPF_Fs24000_Gain9_A1                            (-0.397625)
#define HPF_Fs24000_Gain9_A2                            0.000000
#define HPF_Fs24000_Gain9_B1                            0.267949
#define HPF_Fs24000_Gain9_B2                            0.000000
                                                                    /* Gain =  10.000000 dB */
#define HPF_Fs24000_Gain10_A0                           1.791449
#define HPF_Fs24000_Gain10_A1                           (-0.523499)
#define HPF_Fs24000_Gain10_A2                           0.000000
#define HPF_Fs24000_Gain10_B1                           0.267949
#define HPF_Fs24000_Gain10_B2                           0.000000
                                                                    /* Gain =  11.000000 dB */
#define HPF_Fs24000_Gain11_A0                           1.932682
#define HPF_Fs24000_Gain11_A1                           (-0.664733)
#define HPF_Fs24000_Gain11_A2                           0.000000
#define HPF_Fs24000_Gain11_B1                           0.267949
#define HPF_Fs24000_Gain11_B2                           0.000000
                                                                    /* Gain =  12.000000 dB */
#define HPF_Fs24000_Gain12_A0                           2.091148
#define HPF_Fs24000_Gain12_A1                           (-0.823199)
#define HPF_Fs24000_Gain12_A2                           0.000000
#define HPF_Fs24000_Gain12_B1                           0.267949
#define HPF_Fs24000_Gain12_B2                           0.000000
                                                                    /* Gain =  13.000000 dB */
#define HPF_Fs24000_Gain13_A0                           2.268950
#define HPF_Fs24000_Gain13_A1                           (-1.001001)
#define HPF_Fs24000_Gain13_A2                           0.000000
#define HPF_Fs24000_Gain13_B1                           0.267949
#define HPF_Fs24000_Gain13_B2                           0.000000
                                                                    /* Gain =  14.000000 dB */
#define HPF_Fs24000_Gain14_A0                           2.468447
#define HPF_Fs24000_Gain14_A1                           (-1.200498)
#define HPF_Fs24000_Gain14_A2                           0.000000
#define HPF_Fs24000_Gain14_B1                           0.267949
#define HPF_Fs24000_Gain14_B2                           0.000000
                                                                    /* Gain =  15.000000 dB */
#define HPF_Fs24000_Gain15_A0                           2.692287
#define HPF_Fs24000_Gain15_A1                           (-1.424338)
#define HPF_Fs24000_Gain15_A2                           0.000000
#define HPF_Fs24000_Gain15_B1                           0.267949
#define HPF_Fs24000_Gain15_B2                           0.000000
/* Coefficients for sample rate 32000Hz */
                                                                    /* Gain =  1.000000 dB */
#define HPF_Fs32000_Gain1_A0                            1.061009
#define HPF_Fs32000_Gain1_A1                            (-0.061009)
#define HPF_Fs32000_Gain1_A2                            0.000000
#define HPF_Fs32000_Gain1_B1                            (-0.000000)
#define HPF_Fs32000_Gain1_B2                            0.000000
                                                                    /* Gain =  2.000000 dB */
#define HPF_Fs32000_Gain2_A0                             1.129463
#define HPF_Fs32000_Gain2_A1                             (-0.129463)
#define HPF_Fs32000_Gain2_A2                             0.000000
#define HPF_Fs32000_Gain2_B1                             (-0.000000)
#define HPF_Fs32000_Gain2_B2                             0.000000
                                                                    /* Gain =  3.000000 dB */
#define HPF_Fs32000_Gain3_A0                             1.206267
#define HPF_Fs32000_Gain3_A1                             (-0.206267)
#define HPF_Fs32000_Gain3_A2                             0.000000
#define HPF_Fs32000_Gain3_B1                             (-0.000000)
#define HPF_Fs32000_Gain3_B2                             0.000000
                                                                    /* Gain =  4.000000 dB */
#define HPF_Fs32000_Gain4_A0                            1.292447
#define HPF_Fs32000_Gain4_A1                            (-0.292447)
#define HPF_Fs32000_Gain4_A2                            0.000000
#define HPF_Fs32000_Gain4_B1                            (-0.000000)
#define HPF_Fs32000_Gain4_B2                            0.000000
                                                                    /* Gain =  5.000000 dB */
#define HPF_Fs32000_Gain5_A0                            1.389140
#define HPF_Fs32000_Gain5_A1                            (-0.389140)
#define HPF_Fs32000_Gain5_A2                            0.000000
#define HPF_Fs32000_Gain5_B1                            (-0.000000)
#define HPF_Fs32000_Gain5_B2                            0.000000
                                                                    /* Gain =  6.000000 dB */
#define HPF_Fs32000_Gain6_A0                             1.497631
#define HPF_Fs32000_Gain6_A1                             (-0.497631)
#define HPF_Fs32000_Gain6_A2                             0.000000
#define HPF_Fs32000_Gain6_B1                             (-0.000000)
#define HPF_Fs32000_Gain6_B2                             0.000000
                                                                    /* Gain =  7.000000 dB */
#define HPF_Fs32000_Gain7_A0                             1.619361
#define HPF_Fs32000_Gain7_A1                             (-0.619361)
#define HPF_Fs32000_Gain7_A2                             0.000000
#define HPF_Fs32000_Gain7_B1                             (-0.000000)
#define HPF_Fs32000_Gain7_B2                             0.000000
                                                                    /* Gain =  8.000000 dB */
#define HPF_Fs32000_Gain8_A0                             1.755943
#define HPF_Fs32000_Gain8_A1                             (-0.755943)
#define HPF_Fs32000_Gain8_A2                             0.000000
#define HPF_Fs32000_Gain8_B1                             (-0.000000)
#define HPF_Fs32000_Gain8_B2                             0.000000
                                                                    /* Gain =  9.000000 dB */
#define HPF_Fs32000_Gain9_A0                             1.909191
#define HPF_Fs32000_Gain9_A1                             (-0.909191)
#define HPF_Fs32000_Gain9_A2                             0.000000
#define HPF_Fs32000_Gain9_B1                             (-0.000000)
#define HPF_Fs32000_Gain9_B2                             0.000000
                                                                    /* Gain =  10.000000 dB */
#define HPF_Fs32000_Gain10_A0                            2.081139
#define HPF_Fs32000_Gain10_A1                            (-1.081139)
#define HPF_Fs32000_Gain10_A2                            0.000000
#define HPF_Fs32000_Gain10_B1                            (-0.000000)
#define HPF_Fs32000_Gain10_B2                            0.000000
                                                                    /* Gain =  11.000000 dB */
#define HPF_Fs32000_Gain11_A0                           2.274067
#define HPF_Fs32000_Gain11_A1                           (-1.274067)
#define HPF_Fs32000_Gain11_A2                           0.000000
#define HPF_Fs32000_Gain11_B1                           (-0.000000)
#define HPF_Fs32000_Gain11_B2                           0.000000
                                                                    /* Gain =  12.000000 dB */
#define HPF_Fs32000_Gain12_A0                          2.490536
#define HPF_Fs32000_Gain12_A1                          (-1.490536)
#define HPF_Fs32000_Gain12_A2                          0.000000
#define HPF_Fs32000_Gain12_B1                          (-0.000000)
#define HPF_Fs32000_Gain12_B2                          0.000000
                                                                    /* Gain =  13.000000 dB */
#define HPF_Fs32000_Gain13_A0                           2.733418
#define HPF_Fs32000_Gain13_A1                           (-1.733418)
#define HPF_Fs32000_Gain13_A2                           0.000000
#define HPF_Fs32000_Gain13_B1                           (-0.000000)
#define HPF_Fs32000_Gain13_B2                           0.000000
                                                                    /* Gain =  14.000000 dB */
#define HPF_Fs32000_Gain14_A0                           3.005936
#define HPF_Fs32000_Gain14_A1                           (-2.005936)
#define HPF_Fs32000_Gain14_A2                           0.000000
#define HPF_Fs32000_Gain14_B1                           (-0.000000)
#define HPF_Fs32000_Gain14_B2                           0.000000
                                                                    /* Gain =  15.000000 dB */
#define HPF_Fs32000_Gain15_A0                          3.311707
#define HPF_Fs32000_Gain15_A1                          (-2.311707)
#define HPF_Fs32000_Gain15_A2                          0.000000
#define HPF_Fs32000_Gain15_B1                          (-0.000000)
#define HPF_Fs32000_Gain15_B2                          0.000000
/* Coefficients for sample rate 44100Hz */
                                                                    /* Gain =  1.000000 dB */
#define HPF_Fs44100_Gain1_A0                            1.074364
#define HPF_Fs44100_Gain1_A1                            (-0.293257)
#define HPF_Fs44100_Gain1_A2                            0.000000
#define HPF_Fs44100_Gain1_B1                            (-0.218894)
#define HPF_Fs44100_Gain1_B2                            0.000000
                                                                    /* Gain =  2.000000 dB */
#define HPF_Fs44100_Gain2_A0                            1.157801
#define HPF_Fs44100_Gain2_A1                            (-0.376695)
#define HPF_Fs44100_Gain2_A2                            0.000000
#define HPF_Fs44100_Gain2_B1                            (-0.218894)
#define HPF_Fs44100_Gain2_B2                            0.000000
                                                                    /* Gain =  3.000000 dB */
#define HPF_Fs44100_Gain3_A0                           1.251420
#define HPF_Fs44100_Gain3_A1                           (-0.470313)
#define HPF_Fs44100_Gain3_A2                           0.000000
#define HPF_Fs44100_Gain3_B1                           (-0.218894)
#define HPF_Fs44100_Gain3_B2                           0.000000
                                                                    /* Gain =  4.000000 dB */
#define HPF_Fs44100_Gain4_A0                            1.356461
#define HPF_Fs44100_Gain4_A1                            (-0.575355)
#define HPF_Fs44100_Gain4_A2                            0.000000
#define HPF_Fs44100_Gain4_B1                            (-0.218894)
#define HPF_Fs44100_Gain4_B2                            0.000000
                                                                    /* Gain =  5.000000 dB */
#define HPF_Fs44100_Gain5_A0                            1.474320
#define HPF_Fs44100_Gain5_A1                            (-0.693213)
#define HPF_Fs44100_Gain5_A2                            0.000000
#define HPF_Fs44100_Gain5_B1                            (-0.218894)
#define HPF_Fs44100_Gain5_B2                            0.000000
                                                                    /* Gain =  6.000000 dB */
#define HPF_Fs44100_Gain6_A0                           1.606559
#define HPF_Fs44100_Gain6_A1                           (-0.825453)
#define HPF_Fs44100_Gain6_A2                           0.000000
#define HPF_Fs44100_Gain6_B1                           (-0.218894)
#define HPF_Fs44100_Gain6_B2                           0.000000
                                                                    /* Gain =  7.000000 dB */
#define HPF_Fs44100_Gain7_A0                           1.754935
#define HPF_Fs44100_Gain7_A1                           (-0.973828)
#define HPF_Fs44100_Gain7_A2                           0.000000
#define HPF_Fs44100_Gain7_B1                           (-0.218894)
#define HPF_Fs44100_Gain7_B2                           0.000000
                                                                    /* Gain =  8.000000 dB */
#define HPF_Fs44100_Gain8_A0                            1.921414
#define HPF_Fs44100_Gain8_A1                            (-1.140308)
#define HPF_Fs44100_Gain8_A2                            0.000000
#define HPF_Fs44100_Gain8_B1                            (-0.218894)
#define HPF_Fs44100_Gain8_B2                            0.000000
                                                                    /* Gain =  9.000000 dB */
#define HPF_Fs44100_Gain9_A0                            2.108208
#define HPF_Fs44100_Gain9_A1                            (-1.327101)
#define HPF_Fs44100_Gain9_A2                            0.000000
#define HPF_Fs44100_Gain9_B1                            (-0.218894)
#define HPF_Fs44100_Gain9_B2                            0.000000
                                                                    /* Gain =  10.000000 dB */
#define HPF_Fs44100_Gain10_A0                          2.317793
#define HPF_Fs44100_Gain10_A1                          (-1.536687)
#define HPF_Fs44100_Gain10_A2                          0.000000
#define HPF_Fs44100_Gain10_B1                          (-0.218894)
#define HPF_Fs44100_Gain10_B2                          0.000000
                                                                    /* Gain =  11.000000 dB */
#define HPF_Fs44100_Gain11_A0                          2.552952
#define HPF_Fs44100_Gain11_A1                          (-1.771846)
#define HPF_Fs44100_Gain11_A2                          0.000000
#define HPF_Fs44100_Gain11_B1                          (-0.218894)
#define HPF_Fs44100_Gain11_B2                          0.000000
                                                                    /* Gain =  12.000000 dB */
#define HPF_Fs44100_Gain12_A0                          2.816805
#define HPF_Fs44100_Gain12_A1                          (-2.035698)
#define HPF_Fs44100_Gain12_A2                          0.000000
#define HPF_Fs44100_Gain12_B1                          (-0.218894)
#define HPF_Fs44100_Gain12_B2                          0.000000
                                                                    /* Gain =  13.000000 dB */
#define HPF_Fs44100_Gain13_A0                           3.112852
#define HPF_Fs44100_Gain13_A1                           (-2.331746)
#define HPF_Fs44100_Gain13_A2                           0.000000
#define HPF_Fs44100_Gain13_B1                           (-0.218894)
#define HPF_Fs44100_Gain13_B2                           0.000000
                                                                    /* Gain =  14.000000 dB */
#define HPF_Fs44100_Gain14_A0                          3.445023
#define HPF_Fs44100_Gain14_A1                          (-2.663916)
#define HPF_Fs44100_Gain14_A2                          0.000000
#define HPF_Fs44100_Gain14_B1                          (-0.218894)
#define HPF_Fs44100_Gain14_B2                          0.000000
                                                                    /* Gain =  15.000000 dB */
#define HPF_Fs44100_Gain15_A0                          3.817724
#define HPF_Fs44100_Gain15_A1                          (-3.036618)
#define HPF_Fs44100_Gain15_A2                          0.000000
#define HPF_Fs44100_Gain15_B1                          (-0.218894)
#define HPF_Fs44100_Gain15_B2                          0.000000
/* Coefficients for sample rate 48000Hz */
                                                                    /* Gain =  1.000000 dB */
#define HPF_Fs48000_Gain1_A0                          1.077357
#define HPF_Fs48000_Gain1_A1                          (-0.345306)
#define HPF_Fs48000_Gain1_A2                          0.000000
#define HPF_Fs48000_Gain1_B1                          (-0.267949)
#define HPF_Fs48000_Gain1_B2                          0.000000
                                                                    /* Gain =  2.000000 dB */
#define HPF_Fs48000_Gain2_A0                          1.164152
#define HPF_Fs48000_Gain2_A1                          (-0.432101)
#define HPF_Fs48000_Gain2_A2                          0.000000
#define HPF_Fs48000_Gain2_B1                          (-0.267949)
#define HPF_Fs48000_Gain2_B2                          0.000000
                                                                    /* Gain =  3.000000 dB */
#define HPF_Fs48000_Gain3_A0                          1.261538
#define HPF_Fs48000_Gain3_A1                          (-0.529488)
#define HPF_Fs48000_Gain3_A2                          0.000000
#define HPF_Fs48000_Gain3_B1                          (-0.267949)
#define HPF_Fs48000_Gain3_B2                          0.000000
                                                                    /* Gain =  4.000000 dB */
#define HPF_Fs48000_Gain4_A0                           1.370807
#define HPF_Fs48000_Gain4_A1                           (-0.638757)
#define HPF_Fs48000_Gain4_A2                           0.000000
#define HPF_Fs48000_Gain4_B1                           (-0.267949)
#define HPF_Fs48000_Gain4_B2                           0.000000
                                                                    /* Gain =  5.000000 dB */
#define HPF_Fs48000_Gain5_A0                           1.493409
#define HPF_Fs48000_Gain5_A1                           (-0.761359)
#define HPF_Fs48000_Gain5_A2                           0.000000
#define HPF_Fs48000_Gain5_B1                           (-0.267949)
#define HPF_Fs48000_Gain5_B2                           0.000000
                                                                    /* Gain =  6.000000 dB */
#define HPF_Fs48000_Gain6_A0                            1.630971
#define HPF_Fs48000_Gain6_A1                            (-0.898920)
#define HPF_Fs48000_Gain6_A2                            0.000000
#define HPF_Fs48000_Gain6_B1                            (-0.267949)
#define HPF_Fs48000_Gain6_B2                            0.000000
                                                                    /* Gain =  7.000000 dB */
#define HPF_Fs48000_Gain7_A0                            1.785318
#define HPF_Fs48000_Gain7_A1                            (-1.053267)
#define HPF_Fs48000_Gain7_A2                            0.000000
#define HPF_Fs48000_Gain7_B1                            (-0.267949)
#define HPF_Fs48000_Gain7_B2                            0.000000
                                                                    /* Gain =  8.000000 dB */
#define HPF_Fs48000_Gain8_A0                           1.958498
#define HPF_Fs48000_Gain8_A1                           (-1.226447)
#define HPF_Fs48000_Gain8_A2                           0.000000
#define HPF_Fs48000_Gain8_B1                           (-0.267949)
#define HPF_Fs48000_Gain8_B2                           0.000000
                                                                    /* Gain =  9.000000 dB */
#define HPF_Fs48000_Gain9_A0                          2.152809
#define HPF_Fs48000_Gain9_A1                          (-1.420758)
#define HPF_Fs48000_Gain9_A2                          0.000000
#define HPF_Fs48000_Gain9_B1                          (-0.267949)
#define HPF_Fs48000_Gain9_B2                          0.000000
                                                                    /* Gain =  10.000000 dB */
#define HPF_Fs48000_Gain10_A0                         2.370829
#define HPF_Fs48000_Gain10_A1                         (-1.638778)
#define HPF_Fs48000_Gain10_A2                         0.000000
#define HPF_Fs48000_Gain10_B1                         (-0.267949)
#define HPF_Fs48000_Gain10_B2                         0.000000
                                                                    /* Gain =  11.000000 dB */
#define HPF_Fs48000_Gain11_A0                          2.615452
#define HPF_Fs48000_Gain11_A1                          (-1.883401)
#define HPF_Fs48000_Gain11_A2                          0.000000
#define HPF_Fs48000_Gain11_B1                          (-0.267949)
#define HPF_Fs48000_Gain11_B2                          0.000000
                                                                    /* Gain =  12.000000 dB */
#define HPF_Fs48000_Gain12_A0                          2.889924
#define HPF_Fs48000_Gain12_A1                          (-2.157873)
#define HPF_Fs48000_Gain12_A2                          0.000000
#define HPF_Fs48000_Gain12_B1                          (-0.267949)
#define HPF_Fs48000_Gain12_B2                          0.000000
                                                                    /* Gain =  13.000000 dB */
#define HPF_Fs48000_Gain13_A0                           3.197886
#define HPF_Fs48000_Gain13_A1                           (-2.465835)
#define HPF_Fs48000_Gain13_A2                           0.000000
#define HPF_Fs48000_Gain13_B1                           (-0.267949)
#define HPF_Fs48000_Gain13_B2                           0.000000
                                                                    /* Gain =  14.000000 dB */
#define HPF_Fs48000_Gain14_A0                          3.543425
#define HPF_Fs48000_Gain14_A1                          (-2.811374)
#define HPF_Fs48000_Gain14_A2                          0.000000
#define HPF_Fs48000_Gain14_B1                          (-0.267949)
#define HPF_Fs48000_Gain14_B2                          0.000000
                                                                    /* Gain =  15.000000 dB */
#define HPF_Fs48000_Gain15_A0                         3.931127
#define HPF_Fs48000_Gain15_A1                         (-3.199076)
#define HPF_Fs48000_Gain15_A2                         0.000000
#define HPF_Fs48000_Gain15_B1                         (-0.267949)
#define HPF_Fs48000_Gain15_B2                         0.000000

/* Coefficients for sample rate 88200 */
/* Gain = 1.000000 dB */
#define HPF_Fs88200_Gain1_A0                          1.094374f
#define HPF_Fs88200_Gain1_A1                          (-0.641256f)
#define HPF_Fs88200_Gain1_A2                          0.000000f
#define HPF_Fs88200_Gain1_B1                          (-0.546882f)
#define HPF_Fs88200_Gain1_B2                          0.000000f
/* Gain = 2.000000 dB */
#define HPF_Fs88200_Gain2_A0                          1.200264f
#define HPF_Fs88200_Gain2_A1                          (-0.747146f)
#define HPF_Fs88200_Gain2_A2                          0.000000f
#define HPF_Fs88200_Gain2_B1                          (-0.546882f)
#define HPF_Fs88200_Gain2_B2                          0.000000f
/* Gain = 3.000000 dB */
#define HPF_Fs88200_Gain3_A0                          1.319074f
#define HPF_Fs88200_Gain3_A1                          (-0.865956f)
#define HPF_Fs88200_Gain3_A2                          0.000000f
#define HPF_Fs88200_Gain3_B1                          (-0.546882f)
#define HPF_Fs88200_Gain3_B2                          0.000000f
/* Gain = 4.000000 dB */
#define HPF_Fs88200_Gain4_A0                          1.452380f
#define HPF_Fs88200_Gain4_A1                          (-0.999263f)
#define HPF_Fs88200_Gain4_A2                          0.000000f
#define HPF_Fs88200_Gain4_B1                          (-0.546882f)
#define HPF_Fs88200_Gain4_B2                          0.000000f
/* Gain = 5.000000 dB */
#define HPF_Fs88200_Gain5_A0                          1.601953f
#define HPF_Fs88200_Gain5_A1                          (-1.148836f)
#define HPF_Fs88200_Gain5_A2                          0.000000f
#define HPF_Fs88200_Gain5_B1                          (-0.546882f)
#define HPF_Fs88200_Gain5_B2                          0.000000f
/* Gain = 6.000000 dB */
#define HPF_Fs88200_Gain6_A0                          1.769777f
#define HPF_Fs88200_Gain6_A1                          (-1.316659f)
#define HPF_Fs88200_Gain6_A2                          0.000000f
#define HPF_Fs88200_Gain6_B1                          (-0.546882f)
#define HPF_Fs88200_Gain6_B2                          0.000000f
/* Gain = 7.000000 dB */
#define HPF_Fs88200_Gain7_A0                          1.958078f
#define HPF_Fs88200_Gain7_A1                          (-1.504960f)
#define HPF_Fs88200_Gain7_A2                          0.000000f
#define HPF_Fs88200_Gain7_B1                          (-0.546882f)
#define HPF_Fs88200_Gain7_B2                          0.000000f
/* Gain = 8.000000 dB */
#define HPF_Fs88200_Gain8_A0                          2.169355f
#define HPF_Fs88200_Gain8_A1                          (-1.716238f)
#define HPF_Fs88200_Gain8_A2                          0.000000f
#define HPF_Fs88200_Gain8_B1                          (-0.546882f)
#define HPF_Fs88200_Gain8_B2                          0.000000f
/* Gain = 9.000000 dB */
#define HPF_Fs88200_Gain9_A0                          2.406412f
#define HPF_Fs88200_Gain9_A1                          (-1.953295f)
#define HPF_Fs88200_Gain9_A2                          0.000000f
#define HPF_Fs88200_Gain9_B1                          (-0.546882f)
#define HPF_Fs88200_Gain9_B2                          0.000000f
/* Gain = 10.000000 dB */
#define HPF_Fs88200_Gain10_A0                          2.672395f
#define HPF_Fs88200_Gain10_A1                          (-2.219277f)
#define HPF_Fs88200_Gain10_A2                          0.000000f
#define HPF_Fs88200_Gain10_B1                          (-0.546882f)
#define HPF_Fs88200_Gain10_B2                          0.000000f
/* Gain = 11.000000 dB */
#define HPF_Fs88200_Gain11_A0                          2.970832f
#define HPF_Fs88200_Gain11_A1                          (-2.517714f)
#define HPF_Fs88200_Gain11_A2                          0.000000f
#define HPF_Fs88200_Gain11_B1                          (-0.546882f)
#define HPF_Fs88200_Gain11_B2                          0.000000f
/* Gain = 12.000000 dB */
#define HPF_Fs88200_Gain12_A0                          3.305684f
#define HPF_Fs88200_Gain12_A1                          (-2.852566f)
#define HPF_Fs88200_Gain12_A2                          0.000000f
#define HPF_Fs88200_Gain12_B1                          (-0.546882f)
#define HPF_Fs88200_Gain12_B2                          0.000000f
/* Gain = 13.000000 dB */
#define HPF_Fs88200_Gain13_A0                          3.681394f
#define HPF_Fs88200_Gain13_A1                          (-3.228276f)
#define HPF_Fs88200_Gain13_A2                          0.000000f
#define HPF_Fs88200_Gain13_B1                          (-0.546882f)
#define HPF_Fs88200_Gain13_B2                          0.000000f
/* Gain = 14.000000 dB */
#define HPF_Fs88200_Gain14_A0                          4.102947f
#define HPF_Fs88200_Gain14_A1                          (-3.649830f)
#define HPF_Fs88200_Gain14_A2                          0.000000f
#define HPF_Fs88200_Gain14_B1                          (-0.546882f)
#define HPF_Fs88200_Gain14_B2                          0.000000f
/* Gain = 15.000000 dB */
#define HPF_Fs88200_Gain15_A0                          4.575938f
#define HPF_Fs88200_Gain15_A1                          (-4.122820f)
#define HPF_Fs88200_Gain15_A2                          0.000000f
#define HPF_Fs88200_Gain15_B1                          (-0.546882f)
#define HPF_Fs88200_Gain15_B2                          0.000000f

/* Coefficients for sample rate 96000Hz */
                                                                 /* Gain =  1.000000 dB */
#define HPF_Fs96000_Gain1_A0                          1.096233
#define HPF_Fs96000_Gain1_A1                          (-0.673583)
#define HPF_Fs96000_Gain1_A2                          0.000000
#define HPF_Fs96000_Gain1_B1                          (-0.577350)
#define HPF_Fs96000_Gain1_B2                          0.000000
                                                                 /* Gain =  2.000000 dB */
#define HPF_Fs96000_Gain2_A0                          1.204208
#define HPF_Fs96000_Gain2_A1                          (-0.781558)
#define HPF_Fs96000_Gain2_A2                          0.000000
#define HPF_Fs96000_Gain2_B1                          (-0.577350)
#define HPF_Fs96000_Gain2_B2                          0.000000
                                                                 /* Gain =  3.000000 dB */
#define HPF_Fs96000_Gain3_A0                          1.325358
#define HPF_Fs96000_Gain3_A1                          (-0.902708)
#define HPF_Fs96000_Gain3_A2                          0.000000
#define HPF_Fs96000_Gain3_B1                          (-0.577350)
#define HPF_Fs96000_Gain3_B2                          0.000000
                                                                 /* Gain =  4.000000 dB */
#define HPF_Fs96000_Gain4_A0                           1.461291
#define HPF_Fs96000_Gain4_A1                           (-1.038641)
#define HPF_Fs96000_Gain4_A2                           0.000000
#define HPF_Fs96000_Gain4_B1                           (-0.577350)
#define HPF_Fs96000_Gain4_B2                           0.000000
                                                                 /* Gain =  5.000000 dB */
#define HPF_Fs96000_Gain5_A0                           1.613810
#define HPF_Fs96000_Gain5_A1                           (-1.191160)
#define HPF_Fs96000_Gain5_A2                           0.000000
#define HPF_Fs96000_Gain5_B1                           (-0.577350)
#define HPF_Fs96000_Gain5_B2                           0.000000
                                                                 /* Gain =  6.000000 dB */
#define HPF_Fs96000_Gain6_A0                            1.784939
#define HPF_Fs96000_Gain6_A1                            (-1.362289)
#define HPF_Fs96000_Gain6_A2                            0.000000
#define HPF_Fs96000_Gain6_B1                            (-0.577350)
#define HPF_Fs96000_Gain6_B2                            0.000000
                                                                /* Gain =  7.000000 dB */
#define HPF_Fs96000_Gain7_A0                            1.976949
#define HPF_Fs96000_Gain7_A1                            (-1.554299)
#define HPF_Fs96000_Gain7_A2                            0.000000
#define HPF_Fs96000_Gain7_B1                            (-0.577350)
#define HPF_Fs96000_Gain7_B2                            0.000000
                                                                 /* Gain =  8.000000 dB */
#define HPF_Fs96000_Gain8_A0                           2.192387
#define HPF_Fs96000_Gain8_A1                           (-1.769738)
#define HPF_Fs96000_Gain8_A2                           0.000000
#define HPF_Fs96000_Gain8_B1                           (-0.577350)
#define HPF_Fs96000_Gain8_B2                           0.000000
                                                                /* Gain =  9.000000 dB */
#define HPF_Fs96000_Gain9_A0                          2.434113
#define HPF_Fs96000_Gain9_A1                          (-2.011464)
#define HPF_Fs96000_Gain9_A2                          0.000000
#define HPF_Fs96000_Gain9_B1                          (-0.577350)
#define HPF_Fs96000_Gain9_B2                          0.000000
                                                               /* Gain =  10.000000 dB */
#define HPF_Fs96000_Gain10_A0                        2.705335
#define HPF_Fs96000_Gain10_A1                        (-2.282685)
#define HPF_Fs96000_Gain10_A2                         0.000000
#define HPF_Fs96000_Gain10_B1                         (-0.577350)
#define HPF_Fs96000_Gain10_B2                         0.000000
                                                              /* Gain =  11.000000 dB */
#define HPF_Fs96000_Gain11_A0                          3.009650
#define HPF_Fs96000_Gain11_A1                          (-2.587000)
#define HPF_Fs96000_Gain11_A2                          0.000000
#define HPF_Fs96000_Gain11_B1                          (-0.577350)
#define HPF_Fs96000_Gain11_B2                          0.000000
                                                                  /* Gain =  12.000000 dB */
#define HPF_Fs96000_Gain12_A0                          3.351097
#define HPF_Fs96000_Gain12_A1                          (-2.928447)
#define HPF_Fs96000_Gain12_A2                          0.000000
#define HPF_Fs96000_Gain12_B1                          (-0.577350)
#define HPF_Fs96000_Gain12_B2                          0.000000
                                                                /* Gain =  13.000000 dB */
#define HPF_Fs96000_Gain13_A0                           3.734207
#define HPF_Fs96000_Gain13_A1                           (-3.311558)
#define HPF_Fs96000_Gain13_A2                           0.000000
#define HPF_Fs96000_Gain13_B1                           (-0.577350)
#define HPF_Fs96000_Gain13_B2                           0.000000
                                                                 /* Gain =  14.000000 dB */
#define HPF_Fs96000_Gain14_A0                         4.164064
#define HPF_Fs96000_Gain14_A1                         (-3.741414)
#define HPF_Fs96000_Gain14_A2                          0.000000
#define HPF_Fs96000_Gain14_B1                          (-0.577350)
#define HPF_Fs96000_Gain14_B2                          0.000000
                                                                 /* Gain =  15.000000 dB */
#define HPF_Fs96000_Gain15_A0                         4.646371
#define HPF_Fs96000_Gain15_A1                         (-4.223721)
#define HPF_Fs96000_Gain15_A2                         0.000000
#define HPF_Fs96000_Gain15_B1                         (-0.577350)
#define HPF_Fs96000_Gain15_B2                         0.000000

/* Coefficients for sample rate 176400 */
/* Gain = 1.000000 dB */
#define HPF_Fs176400_Gain1_A0                          1.106711f
#define HPF_Fs176400_Gain1_A1                          (-0.855807f)
#define HPF_Fs176400_Gain1_A2                          0.000000f
#define HPF_Fs176400_Gain1_B1                          (-0.749096f)
#define HPF_Fs176400_Gain1_B2                          0.000000f
/* Gain = 2.000000 dB */
#define HPF_Fs176400_Gain2_A0                          1.226443f
#define HPF_Fs176400_Gain2_A1                          (-0.975539f)
#define HPF_Fs176400_Gain2_A2                          0.000000f
#define HPF_Fs176400_Gain2_B1                          (-0.749096f)
#define HPF_Fs176400_Gain2_B2                          0.000000f
/* Gain = 3.000000 dB */
#define HPF_Fs176400_Gain3_A0                          1.360784f
#define HPF_Fs176400_Gain3_A1                          (-1.109880f)
#define HPF_Fs176400_Gain3_A2                          0.000000f
#define HPF_Fs176400_Gain3_B1                          (-0.749096f)
#define HPF_Fs176400_Gain3_B2                          0.000000f
/* Gain = 4.000000 dB */
#define HPF_Fs176400_Gain4_A0                          1.511517f
#define HPF_Fs176400_Gain4_A1                          (-1.260613f)
#define HPF_Fs176400_Gain4_A2                          0.000000f
#define HPF_Fs176400_Gain4_B1                          (-0.749096f)
#define HPF_Fs176400_Gain4_B2                          0.000000f
/* Gain = 5.000000 dB */
#define HPF_Fs176400_Gain5_A0                          1.680643f
#define HPF_Fs176400_Gain5_A1                          (-1.429739f)
#define HPF_Fs176400_Gain5_A2                          0.000000f
#define HPF_Fs176400_Gain5_B1                          (-0.749096f)
#define HPF_Fs176400_Gain5_B2                          0.000000f
/* Gain = 6.000000 dB */
#define HPF_Fs176400_Gain6_A0                          1.870405f
#define HPF_Fs176400_Gain6_A1                          (-1.619501f)
#define HPF_Fs176400_Gain6_A2                          0.000000f
#define HPF_Fs176400_Gain6_B1                          (-0.749096f)
#define HPF_Fs176400_Gain6_B2                          0.000000f
/* Gain = 7.000000 dB */
#define HPF_Fs176400_Gain7_A0                          2.083321f
#define HPF_Fs176400_Gain7_A1                          (-1.832417f)
#define HPF_Fs176400_Gain7_A2                          0.000000f
#define HPF_Fs176400_Gain7_B1                          (-0.749096f)
#define HPF_Fs176400_Gain7_B2                          0.000000f
/* Gain = 8.000000 dB */
#define HPF_Fs176400_Gain8_A0                          2.322217f
#define HPF_Fs176400_Gain8_A1                          (-2.071313f)
#define HPF_Fs176400_Gain8_A2                          0.000000f
#define HPF_Fs176400_Gain8_B1                          (-0.749096f)
#define HPF_Fs176400_Gain8_B2                          0.000000f
/* Gain = 9.000000 dB */
#define HPF_Fs176400_Gain9_A0                          2.590263f
#define HPF_Fs176400_Gain9_A1                          (-2.339359f)
#define HPF_Fs176400_Gain9_A2                          0.000000f
#define HPF_Fs176400_Gain9_B1                          (-0.749096f)
#define HPF_Fs176400_Gain9_B2                          0.000000f
/* Gain = 10.000000 dB */
#define HPF_Fs176400_Gain10_A0                          2.891016f
#define HPF_Fs176400_Gain10_A1                          (-2.640112f)
#define HPF_Fs176400_Gain10_A2                          0.000000f
#define HPF_Fs176400_Gain10_B1                          (-0.749096f)
#define HPF_Fs176400_Gain10_B2                          0.000000f
/* Gain = 11.000000 dB */
#define HPF_Fs176400_Gain11_A0                          3.228465f
#define HPF_Fs176400_Gain11_A1                          (-2.977561f)
#define HPF_Fs176400_Gain11_A2                          0.000000f
#define HPF_Fs176400_Gain11_B1                          (-0.749096f)
#define HPF_Fs176400_Gain11_B2                          0.000000f
/* Gain = 12.000000 dB */
#define HPF_Fs176400_Gain12_A0                          3.607090f
#define HPF_Fs176400_Gain12_A1                          (-3.356186f)
#define HPF_Fs176400_Gain12_A2                          0.000000f
#define HPF_Fs176400_Gain12_B1                          (-0.749096f)
#define HPF_Fs176400_Gain12_B2                          0.000000f
/* Gain = 13.000000 dB */
#define HPF_Fs176400_Gain13_A0                          4.031914f
#define HPF_Fs176400_Gain13_A1                          (-3.781010f)
#define HPF_Fs176400_Gain13_A2                          0.000000f
#define HPF_Fs176400_Gain13_B1                          (-0.749096f)
#define HPF_Fs176400_Gain13_B2                          0.000000f
/* Gain = 14.000000 dB */
#define HPF_Fs176400_Gain14_A0                          4.508575f
#define HPF_Fs176400_Gain14_A1                          (-4.257671f)
#define HPF_Fs176400_Gain14_A2                          0.000000f
#define HPF_Fs176400_Gain14_B1                          (-0.749096f)
#define HPF_Fs176400_Gain14_B2                          0.000000f
/* Gain = 15.000000 dB */
#define HPF_Fs176400_Gain15_A0                          5.043397f
#define HPF_Fs176400_Gain15_A1                          (-4.792493f)
#define HPF_Fs176400_Gain15_A2                          0.000000f
#define HPF_Fs176400_Gain15_B1                          (-0.749096f)
#define HPF_Fs176400_Gain15_B2                          0.000000f

/* Coefficients for sample rate 192000Hz */
                                                                  /* Gain =  1.000000 dB */
#define HPF_Fs192000_Gain1_A0                          1.107823
#define HPF_Fs192000_Gain1_A1                          (-0.875150)
#define HPF_Fs192000_Gain1_A2                          0.000000
#define HPF_Fs192000_Gain1_B1                          (-0.767327)
#define HPF_Fs192000_Gain1_B2                          0.000000
                                                                  /* Gain =  2.000000 dB */
#define HPF_Fs192000_Gain2_A0                          1.228803
#define HPF_Fs192000_Gain2_A1                          (-0.996130)
#define HPF_Fs192000_Gain2_A2                          0.000000
#define HPF_Fs192000_Gain2_B1                          (-0.767327)
#define HPF_Fs192000_Gain2_B2                          0.000000
                                                                   /* Gain =  3.000000 dB */
#define HPF_Fs192000_Gain3_A0                          1.364544
#define HPF_Fs192000_Gain3_A1                          (-1.131871)
#define HPF_Fs192000_Gain3_A2                          0.000000
#define HPF_Fs192000_Gain3_B1                          (-0.767327)
#define HPF_Fs192000_Gain3_B2                          0.000000
                                                                   /* Gain =  4.000000 dB */
#define HPF_Fs192000_Gain4_A0                          1.516849
#define HPF_Fs192000_Gain4_A1                          (-1.284176)
#define HPF_Fs192000_Gain4_A2                           0.000000
#define HPF_Fs192000_Gain4_B1                           (-0.767327)
#define HPF_Fs192000_Gain4_B2                           0.000000
                                                                   /* Gain =  5.000000 dB */
#define HPF_Fs192000_Gain5_A0                           1.687737
#define HPF_Fs192000_Gain5_A1                           (-1.455064)
#define HPF_Fs192000_Gain5_A2                           0.000000
#define HPF_Fs192000_Gain5_B1                           (-0.767327)
#define HPF_Fs192000_Gain5_B2                           0.000000
                                                                   /* Gain =  6.000000 dB */
#define HPF_Fs192000_Gain6_A0                            1.879477
#define HPF_Fs192000_Gain6_A1                            (-1.646804)
#define HPF_Fs192000_Gain6_A2                            0.000000
#define HPF_Fs192000_Gain6_B1                            (-0.767327)
#define HPF_Fs192000_Gain6_B2                            0.000000
                                                                 /* Gain =  7.000000 dB */
#define HPF_Fs192000_Gain7_A0                            2.094613
#define HPF_Fs192000_Gain7_A1                            (-1.861940)
#define HPF_Fs192000_Gain7_A2                            0.000000
#define HPF_Fs192000_Gain7_B1                            (-0.767327)
#define HPF_Fs192000_Gain7_B2                            0.000000
                                                                   /* Gain =  8.000000 dB */
#define HPF_Fs192000_Gain8_A0                           2.335999
#define HPF_Fs192000_Gain8_A1                           (-2.103326)
#define HPF_Fs192000_Gain8_A2                           0.000000
#define HPF_Fs192000_Gain8_B1                           (-0.767327)
#define HPF_Fs192000_Gain8_B2                           0.000000
                                                                   /* Gain =  9.000000 dB */
#define HPF_Fs192000_Gain9_A0                          2.606839
#define HPF_Fs192000_Gain9_A1                          (-2.374166)
#define HPF_Fs192000_Gain9_A2                          0.000000
#define HPF_Fs192000_Gain9_B1                          (-0.767327)
#define HPF_Fs192000_Gain9_B2                          0.000000
                                                                 /* Gain =  10.000000 dB */
#define HPF_Fs192000_Gain10_A0                        2.910726
#define HPF_Fs192000_Gain10_A1                        (-2.678053)
#define HPF_Fs192000_Gain10_A2                         0.000000
#define HPF_Fs192000_Gain10_B1                         (-0.767327)
#define HPF_Fs192000_Gain10_B2                         0.000000
                                                                  /* Gain =  11.000000 dB */
#define HPF_Fs192000_Gain11_A0                          3.251693
#define HPF_Fs192000_Gain11_A1                          (-3.019020)
#define HPF_Fs192000_Gain11_A2                          0.000000
#define HPF_Fs192000_Gain11_B1                          (-0.767327)
#define HPF_Fs192000_Gain11_B2                          0.000000
                                                                  /* Gain =  12.000000 dB */
#define HPF_Fs192000_Gain12_A0                          3.634264
#define HPF_Fs192000_Gain12_A1                          (-3.401591)
#define HPF_Fs192000_Gain12_A2                          0.000000
#define HPF_Fs192000_Gain12_B1                          (-0.767327)
#define HPF_Fs192000_Gain12_B2                          0.000000
                                                                /* Gain =  13.000000 dB */
#define HPF_Fs192000_Gain13_A0                           4.063516
#define HPF_Fs192000_Gain13_A1                           (-3.830843)
#define HPF_Fs192000_Gain13_A2                           0.000000
#define HPF_Fs192000_Gain13_B1                           (-0.767327)
#define HPF_Fs192000_Gain13_B2                           0.000000
                                                                /* Gain =  14.000000 dB */
#define HPF_Fs192000_Gain14_A0                          4.545145
#define HPF_Fs192000_Gain14_A1                          (-4.312472)
#define HPF_Fs192000_Gain14_A2                          0.000000
#define HPF_Fs192000_Gain14_B1                          (-0.767327)
#define HPF_Fs192000_Gain14_B2                          0.000000
                                                                  /* Gain =  15.000000 dB */
#define HPF_Fs192000_Gain15_A0                         5.085542
#define HPF_Fs192000_Gain15_A1                         (-4.852868)
#define HPF_Fs192000_Gain15_A2                         0.000000
#define HPF_Fs192000_Gain15_B1                         (-0.767327)
#define HPF_Fs192000_Gain15_B2                         0.000000

#endif
