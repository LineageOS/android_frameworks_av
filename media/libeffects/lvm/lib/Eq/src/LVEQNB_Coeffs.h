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

#ifndef __LVEQNB_COEFFS_H__
#define __LVEQNB_COEFFS_H__

/************************************************************************************/
/*                                                                                  */
/* Gain table for (10^(Gain/20) - 1)                                                */
/*                                                                                  */
/************************************************************************************/
#define LVEQNB_Gain_Neg15_dB                             (-0.822172f)
#define LVEQNB_Gain_Neg14_dB                             (-0.800474f)
#define LVEQNB_Gain_Neg13_dB                             (-0.776128f)
#define LVEQNB_Gain_Neg12_dB                             (-0.748811f)
#define LVEQNB_Gain_Neg11_dB                             (-0.718162f)
#define LVEQNB_Gain_Neg10_dB                             (-0.683772f)
#define LVEQNB_Gain_Neg9_dB                              (-0.645187f)
#define LVEQNB_Gain_Neg8_dB                              (-0.601893f)
#define LVEQNB_Gain_Neg7_dB                              (-0.553316f)
#define LVEQNB_Gain_Neg6_dB                              (-0.498813f)
#define LVEQNB_Gain_Neg5_dB                              (-0.437659f)
#define LVEQNB_Gain_Neg4_dB                              (-0.369043f)
#define LVEQNB_Gain_Neg3_dB                              (-0.292054f)
#define LVEQNB_Gain_Neg2_dB                              (-0.205672f)
#define LVEQNB_Gain_Neg1_dB                              (-0.108749f)
#define LVEQNB_Gain_0_dB                                  0.000000f
#define LVEQNB_Gain_1_dB                                  0.122018f
#define LVEQNB_Gain_2_dB                                  0.258925f
#define LVEQNB_Gain_3_dB                                  0.412538f
#define LVEQNB_Gain_4_dB                                  0.584893f
#define LVEQNB_Gain_5_dB                                  0.778279f
#define LVEQNB_Gain_6_dB                                  0.995262f
#define LVEQNB_Gain_7_dB                                  1.238721f
#define LVEQNB_Gain_8_dB                                  1.511886f
#define LVEQNB_Gain_9_dB                                  1.818383f
#define LVEQNB_Gain_10_dB                                 2.162278f
#define LVEQNB_Gain_11_dB                                 2.548134f
#define LVEQNB_Gain_12_dB                                 2.981072f
#define LVEQNB_Gain_13_dB                                 3.466836f
#define LVEQNB_Gain_14_dB                                 4.011872f
#define LVEQNB_Gain_15_dB                                 4.623413f

/************************************************************************************/
/*                                                                                  */
/* Frequency table for 2*Pi/Fs                                                      */
/*                                                                                  */
/************************************************************************************/
#define LVEQNB_2PiOn_8000                                0.000785f
#define LVEQNB_2PiOn_11025                               0.000570f
#define LVEQNB_2PiOn_12000                               0.000524f
#define LVEQNB_2PiOn_16000                               0.000393f
#define LVEQNB_2PiOn_22050                               0.000285f
#define LVEQNB_2PiOn_24000                               0.000262f
#define LVEQNB_2PiOn_32000                               0.000196f
#define LVEQNB_2PiOn_44100                               0.000142f
#define LVEQNB_2PiOn_48000                               0.000131f

#define LVEQNB_2PiOn_88200                               0.000071f
#define LVEQNB_2PiOn_96000                               0.000065f
#define LVEQNB_2PiOn_176400                              0.000036f
#define LVEQNB_2PiOn_192000                              0.000033f

/************************************************************************************/
/*                                                                                  */
/* 50D table for 50 / ( 1 + Gain )                                                  */
/*                                                                                  */
/************************************************************************************/
#define LVEQNB_100D_Neg15_dB                             5.623413f
#define LVEQNB_100D_Neg14_dB                             5.011872f
#define LVEQNB_100D_Neg13_dB                             4.466836f
#define LVEQNB_100D_Neg12_dB                             3.981072f
#define LVEQNB_100D_Neg11_dB                             3.548134f
#define LVEQNB_100D_Neg10_dB                             3.162278f
#define LVEQNB_100D_Neg9_dB                              2.818383f
#define LVEQNB_100D_Neg8_dB                              2.511886f
#define LVEQNB_100D_Neg7_dB                              2.238721f
#define LVEQNB_100D_Neg6_dB                              1.995262f
#define LVEQNB_100D_Neg5_dB                              1.778279f
#define LVEQNB_100D_Neg4_dB                              1.584893f
#define LVEQNB_100D_Neg3_dB                              1.412538f
#define LVEQNB_100D_Neg2_dB                              1.258925f
#define LVEQNB_100D_Neg1_dB                              1.122018f
#define LVEQNB_100D_0_dB                                 1.000000f

#endif
