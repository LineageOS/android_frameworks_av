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

#ifndef __LVCS_HEADPHONE_COEFFS_H__
#define __LVCS_HEADPHONE_COEFFS_H__

/************************************************************************************/
/*                                                                                  */
/* The Stereo Enhancer                                                              */
/*                                                                                  */
/************************************************************************************/
/* Stereo Enhancer coefficients for 8000 Hz sample rate, scaled with 0.161258 */
#define CS_MIDDLE_8000_A0                           0.227720
#define CS_MIDDLE_8000_A1                          (-0.215125)
#define CS_MIDDLE_8000_A2                           0.000000
#define CS_MIDDLE_8000_B1                          (-0.921899)
#define CS_MIDDLE_8000_B2                           0.000000
#define CS_MIDDLE_8000_SCALE                        15
#define CS_SIDE_8000_A0                             0.611441
#define CS_SIDE_8000_A1                            (-0.380344)
#define CS_SIDE_8000_A2                            (-0.231097)
#define CS_SIDE_8000_B1                            (-0.622470)
#define CS_SIDE_8000_B2                            (-0.130759)
#define CS_SIDE_8000_SCALE                         15

/* Stereo Enhancer coefficients for 11025Hz sample rate, scaled with 0.162943 */
#define CS_MIDDLE_11025_A0                       0.230838
#define CS_MIDDLE_11025_A1                      (-0.221559)
#define CS_MIDDLE_11025_A2                       0.000000
#define CS_MIDDLE_11025_B1                      (-0.943056)
#define CS_MIDDLE_11025_B2                       0.000000
#define CS_MIDDLE_11025_SCALE                    15
#define CS_SIDE_11025_A0                         0.557372
#define CS_SIDE_11025_A1                        (-0.391490)
#define CS_SIDE_11025_A2                        (-0.165881)
#define CS_SIDE_11025_B1                        (-0.880608)
#define CS_SIDE_11025_B2                         0.032397
#define CS_SIDE_11025_SCALE                      15

/* Stereo Enhancer coefficients for 12000Hz sample rate, scaled with 0.162191 */
#define CS_MIDDLE_12000_A0                        0.229932
#define CS_MIDDLE_12000_A1                       (-0.221436)
#define CS_MIDDLE_12000_A2                        0.000000
#define CS_MIDDLE_12000_B1                       (-0.947616)
#define CS_MIDDLE_12000_B2                        0.000000
#define CS_MIDDLE_12000_SCALE                        15
#define CS_SIDE_12000_A0                         0.558398
#define CS_SIDE_12000_A1                        (-0.392211)
#define CS_SIDE_12000_A2                        (-0.166187)
#define CS_SIDE_12000_B1                        (-0.892550)
#define CS_SIDE_12000_B2                         0.032856
#define CS_SIDE_12000_SCALE                          15

/* Stereo Enhancer coefficients for 16000Hz sample rate, scaled with 0.162371 */
#define CS_MIDDLE_16000_A0                       0.230638
#define CS_MIDDLE_16000_A1                      (-0.224232)
#define CS_MIDDLE_16000_A2                       0.000000
#define CS_MIDDLE_16000_B1                      (-0.960550)
#define CS_MIDDLE_16000_B2                       0.000000
#define CS_MIDDLE_16000_SCALE                        15
#define CS_SIDE_16000_A0                         0.499695
#define CS_SIDE_16000_A1                        (-0.355543)
#define CS_SIDE_16000_A2                        (-0.144152)
#define CS_SIDE_16000_B1                        (-1.050788)
#define CS_SIDE_16000_B2                         0.144104
#define CS_SIDE_16000_SCALE                          14

/* Stereo Enhancer coefficients for 22050Hz sample rate, scaled with 0.160781 */
#define CS_MIDDLE_22050_A0                       0.228749
#define CS_MIDDLE_22050_A1                      (-0.224128)
#define CS_MIDDLE_22050_A2                       0.000000
#define CS_MIDDLE_22050_B1                      (-0.971262)
#define CS_MIDDLE_22050_B2                       0.000000
#define CS_MIDDLE_22050_SCALE                        15
#define CS_SIDE_22050_A0                          0.440112
#define CS_SIDE_22050_A1                         (-0.261096)
#define CS_SIDE_22050_A2                         (-0.179016)
#define CS_SIDE_22050_B1                         (-1.116786)
#define CS_SIDE_22050_B2                          0.182507
#define CS_SIDE_22050_SCALE                          14

/* Stereo Enhancer coefficients for 24000Hz sample rate, scaled with 0.161882 */
#define CS_MIDDLE_24000_A0                         0.230395
#define CS_MIDDLE_24000_A1                        (-0.226117)
#define CS_MIDDLE_24000_A2                         0.000000
#define CS_MIDDLE_24000_B1                        (-0.973573)
#define CS_MIDDLE_24000_B2                         0.000000
#define CS_MIDDLE_24000_SCALE                        15
#define CS_SIDE_24000_A0                           0.414770
#define CS_SIDE_24000_A1                          (-0.287182)
#define CS_SIDE_24000_A2                          (-0.127588)
#define CS_SIDE_24000_B1                          (-1.229648)
#define CS_SIDE_24000_B2                           0.282177
#define CS_SIDE_24000_SCALE                          14

/* Stereo Enhancer coefficients for 32000Hz sample rate, scaled with 0.160322 */
#define CS_MIDDLE_32000_A0                          0.228400
#define CS_MIDDLE_32000_A1                         (-0.225214)
#define CS_MIDDLE_32000_A2                          0.000000
#define CS_MIDDLE_32000_B1                         (-0.980126)
#define CS_MIDDLE_32000_B2                          0.000000
#define CS_MIDDLE_32000_SCALE                        15
#define CS_SIDE_32000_A0                            0.364579
#define CS_SIDE_32000_A1                           (-0.207355)
#define CS_SIDE_32000_A2                           (-0.157224)
#define CS_SIDE_32000_B1                           (-1.274231)
#define CS_SIDE_32000_B2                            0.312495
#define CS_SIDE_32000_SCALE                          14

/* Stereo Enhancer coefficients for 44100Hz sample rate, scaled with 0.163834 */
#define CS_MIDDLE_44100_A0                     0.233593
#define CS_MIDDLE_44100_A1                    (-0.231225)
#define CS_MIDDLE_44100_A2                     0.000000
#define CS_MIDDLE_44100_B1                    (-0.985545)
#define CS_MIDDLE_44100_B2                     0.000000
#define CS_MIDDLE_44100_SCALE                        15
#define CS_SIDE_44100_A0                       0.284573
#define CS_SIDE_44100_A1                      (-0.258910)
#define CS_SIDE_44100_A2                      (-0.025662)
#define CS_SIDE_44100_B1                      (-1.572248)
#define CS_SIDE_44100_B2                       0.588399
#define CS_SIDE_44100_SCALE                  14

/* Stereo Enhancer coefficients for 48000Hz sample rate, scaled with 0.164402 */
#define CS_MIDDLE_48000_A0                     0.234445
#define CS_MIDDLE_48000_A1                    (-0.232261)
#define CS_MIDDLE_48000_A2                     0.000000
#define CS_MIDDLE_48000_B1                    (-0.986713)
#define CS_MIDDLE_48000_B2                     0.000000
#define CS_MIDDLE_48000_SCALE                        15
#define CS_SIDE_48000_A0                     0.272606
#define CS_SIDE_48000_A1                    (-0.266952)
#define CS_SIDE_48000_A2                    (-0.005654)
#define CS_SIDE_48000_B1                    (-1.617141)
#define CS_SIDE_48000_B2                     0.630405
#define CS_SIDE_48000_SCALE                          14

/* Coefficients for 88200Hz sample rate.
 * The filter coefficients are obtained by carrying out
 * state-space analysis using the coefficients available
 * for 44100Hz.
 */
#define CS_MIDDLE_88200_A0                     0.233846f
#define CS_MIDDLE_88200_A1                     (-0.232657f)
#define CS_MIDDLE_88200_A2                     0.000000f
#define CS_MIDDLE_88200_B1                     (-0.992747f)
#define CS_MIDDLE_88200_B2                     0.000000f
#define CS_MIDDLE_88200_SCALE                  15
#define CS_SIDE_88200_A0                       0.231541f
#define CS_SIDE_88200_A1                       (-0.289586f)
#define CS_SIDE_88200_A2                       0.058045f
#define CS_SIDE_88200_B1                       (-1.765300f)
#define CS_SIDE_88200_B2                       0.769816f
#define CS_SIDE_88200_SCALE                    14

/* Stereo Enhancer coefficients for 96000Hz sample rate, scaled with  0.165*/
/* high pass filter with cutoff frequency 102.18 Hz*/
#define CS_MIDDLE_96000_A0                     0.235532
#define CS_MIDDLE_96000_A1                    (-0.234432)
#define CS_MIDDLE_96000_A2                     0.000000
#define CS_MIDDLE_96000_B1                    (-0.993334)
#define CS_MIDDLE_96000_B2                     0.000000
#define CS_MIDDLE_96000_SCALE                        15
/* Coefficients calculated using tf2ss and ss2tf functions based on
 * coefficients available for 48000Hz sampling frequency
 */
#define CS_SIDE_96000_A0                     0.224326f
#define CS_SIDE_96000_A1                     (-0.294937f)
#define CS_SIDE_96000_A2                     0.070611f
#define CS_SIDE_96000_B1                     (-1.792166f)
#define CS_SIDE_96000_B2                     0.795830f
#define CS_SIDE_96000_SCALE                  14

/* Stereo Enhancer coefficients for 176400Hz sample rate.
 * The filter coefficients are obtained by carrying out
 * state-space analysis using the coefficients available
 * for 44100Hz.
 */
#define CS_MIDDLE_176400_A0                     0.233973f
#define CS_MIDDLE_176400_A1                     (-0.233378f)
#define CS_MIDDLE_176400_A2                     0.000000f
#define CS_MIDDLE_176400_B1                     (-0.996367f)
#define CS_MIDDLE_176400_B2                     0.000000f
#define CS_MIDDLE_176400_SCALE                  15
#define CS_SIDE_176400_A0                       0.199836f
#define CS_SIDE_176400_A1                       (-0.307544f)
#define CS_SIDE_176400_A2                       0.107708f
#define CS_SIDE_176400_B1                       (-1.876572f)
#define CS_SIDE_176400_B2                       0.877771f
#define CS_SIDE_176400_SCALE                    14

/* Stereo Enhancer coefficients for 192000Hz sample rate, scaled with  0.1689*/
#define CS_MIDDLE_192000_A0                     0.241219
#define CS_MIDDLE_192000_A1                    (-0.240656)
#define CS_MIDDLE_192000_A2                     0.000000
#define CS_MIDDLE_192000_B1                    (-0.996661)
#define CS_MIDDLE_192000_B2                     0.000000
#define CS_MIDDLE_192000_SCALE                        15
/* Coefficients calculated using tf2ss and ss2tf functions based on
 * coefficients available for 48000Hz sampling frequency
 */
#define CS_SIDE_192000_A0                    0.196039f
#define CS_SIDE_192000_A1                    (-0.311027f)
#define CS_SIDE_192000_A2                    0.114988f
#define CS_SIDE_192000_B1                    (-1.891380f)
#define CS_SIDE_192000_B2                    0.8923460f
#define CS_SIDE_192000_SCALE                 14

/************************************************************************************/
/*                                                                                  */
/* The Reverb Unit                                                                  */
/*                                                                                  */
/************************************************************************************/

/* Reverb delay settings in samples */
#define LVCS_STEREODELAY_CS_8KHZ                     93         /* Sample rate 8kS/s */
#define LVCS_STEREODELAY_CS_11KHZ                   128         /* Sample rate 11kS/s */
#define LVCS_STEREODELAY_CS_12KHZ                   139         /* Sample rate 12kS/s */
#define LVCS_STEREODELAY_CS_16KHZ                   186         /* Sample rate 16kS/s */
#define LVCS_STEREODELAY_CS_22KHZ                   256         /* Sample rate 22kS/s */
#define LVCS_STEREODELAY_CS_24KHZ                   279         /* Sample rate 24kS/s */
#define LVCS_STEREODELAY_CS_32KHZ                   372         /* Sample rate 32kS/s */
#define LVCS_STEREODELAY_CS_44KHZ                   512         /* Sample rate 44kS/s */
#define LVCS_STEREODELAY_CS_48KHZ                   557         /* Sample rate 48kS/s */
#define LVCS_STEREODELAY_CS_88KHZ                   1024        /* Sample rate 88.2kS/s */
#define LVCS_STEREODELAY_CS_96KHZ                   1115        /* Sample rate 96kS/s */
#define LVCS_STEREODELAY_CS_176KHZ                  2048        /* Sample rate 176.4kS/s */
#define LVCS_STEREODELAY_CS_192KHZ                  2229        /* Sample rate 196kS/s */
#define LVCS_STEREODELAY_CS_MAX_VAL                 LVCS_STEREODELAY_CS_192KHZ

/* Reverb coefficients for 8000 Hz sample rate, scaled with 1.038030 */
#define CS_REVERB_8000_A0                          0.667271
#define CS_REVERB_8000_A1                         (-0.667271)
#define CS_REVERB_8000_A2                          0.000000
#define CS_REVERB_8000_B1                         (-0.668179)
#define CS_REVERB_8000_B2                          0.000000
#define CS_REVERB_8000_SCALE                         15

/* Reverb coefficients for 11025Hz sample rate, scaled with 1.038030 */
#define CS_REVERB_11025_A0                     0.699638
#define CS_REVERB_11025_A1                    (-0.699638)
#define CS_REVERB_11025_A2                     0.000000
#define CS_REVERB_11025_B1                    (-0.749096)
#define CS_REVERB_11025_B2                     0.000000
#define CS_REVERB_11025_SCALE                  15

/* Reverb coefficients for 12000Hz sample rate, scaled with 1.038030 */
#define CS_REVERB_12000_A0                   0.706931
#define CS_REVERB_12000_A1                  (-0.706931)
#define CS_REVERB_12000_A2                   0.000000
#define CS_REVERB_12000_B1                  (-0.767327)
#define CS_REVERB_12000_B2                   0.000000
#define CS_REVERB_12000_SCALE                15

/* Reverb coefficients for 16000Hz sample rate, scaled with 1.038030 */
#define CS_REVERB_16000_A0                      0.728272
#define CS_REVERB_16000_A1                     (-0.728272)
#define CS_REVERB_16000_A2                      0.000000
#define CS_REVERB_16000_B1                     (-0.820679)
#define CS_REVERB_16000_B2                      0.000000
#define CS_REVERB_16000_SCALE                        15

/* Reverb coefficients for 22050Hz sample rate, scaled with 1.038030 */
#define CS_REVERB_22050_A0                     0.516396
#define CS_REVERB_22050_A1                     0.000000
#define CS_REVERB_22050_A2                    (-0.516396)
#define CS_REVERB_22050_B1                    (-0.518512)
#define CS_REVERB_22050_B2                    (-0.290990)
#define CS_REVERB_22050_SCALE                        15

/* Reverb coefficients for 24000Hz sample rate, scaled with 1.038030 */
#define CS_REVERB_24000_A0                       0.479565
#define CS_REVERB_24000_A1                       0.000000
#define CS_REVERB_24000_A2                      (-0.479565)
#define CS_REVERB_24000_B1                      (-0.637745)
#define CS_REVERB_24000_B2                      (-0.198912)
#define CS_REVERB_24000_SCALE                        15

/* Reverb coefficients for 32000Hz sample rate, scaled with 1.038030 */
#define CS_REVERB_32000_A0                      0.380349
#define CS_REVERB_32000_A1                      0.000000
#define CS_REVERB_32000_A2                     (-0.380349)
#define CS_REVERB_32000_B1                     (-0.950873)
#define CS_REVERB_32000_B2                      0.049127
#define CS_REVERB_32000_SCALE                        15

/* Reverb coefficients for 44100Hz sample rate, scaled with 1.038030 */
#define CS_REVERB_44100_A0                         0.297389
#define CS_REVERB_44100_A1                         0.000000
#define CS_REVERB_44100_A2                        (-0.297389)
#define CS_REVERB_44100_B1                        (-1.200423)
#define CS_REVERB_44100_B2                         0.256529
#define CS_REVERB_44100_SCALE                        14

/* Reverb coefficients for 48000Hz sample rate, scaled with 1.038030 */
#define CS_REVERB_48000_A0                       0.278661
#define CS_REVERB_48000_A1                       0.000000
#define CS_REVERB_48000_A2                      (-0.278661)
#define CS_REVERB_48000_B1                      (-1.254993)
#define CS_REVERB_48000_B2                       0.303347
#define CS_REVERB_48000_SCALE                        14

/* Reverb coefficients for 88200Hz sample rate, scaled with 0.8 */
/* Band pass filter with fc1=500 and fc2=8000 */
#define CS_REVERB_88200_A0                       0.171901f
#define CS_REVERB_88200_A1                       0.000000f
#define CS_REVERB_88200_A2                      (-0.171901f)
#define CS_REVERB_88200_B1                      (-1.553948f)
#define CS_REVERB_88200_B2                      (0.570248f)
#define CS_REVERB_88200_SCALE                      14
/* Reverb coefficients for 96000Hz sample rate, scaled with 0.8 */
/* Band pass filter with fc1=500 and fc2=8000*/
#define CS_REVERB_96000_A0                       0.1602488
#define CS_REVERB_96000_A1                       0.000000
#define CS_REVERB_96000_A2                      (-0.1602488)
#define CS_REVERB_96000_B1                      (-1.585413)
#define CS_REVERB_96000_B2                       0.599377
#define CS_REVERB_96000_SCALE                        14

/* Reverb coefficients for 176400Hz sample rate, scaled with 0.8 */
/* Band pass filter with fc1=500 and fc2=8000 */
#define CS_REVERB_176400_A0                       0.094763f
#define CS_REVERB_176400_A1                       0.000000f
#define CS_REVERB_176400_A2                      (-0.094763f)
#define CS_REVERB_176400_B1                      (-1.758593f)
#define CS_REVERB_176400_B2                      (0.763091f)
#define CS_REVERB_176400_SCALE                      14
/* Reverb coefficients for 192000Hz sample rate, scaled with 0.8 */
/* Band pass filter with fc1=500 and fc2=8000*/
#define CS_REVERB_192000_A0                       0.0878369
#define CS_REVERB_192000_A1                       0.000000
#define CS_REVERB_192000_A2                      (-0.0878369)
#define CS_REVERB_192000_B1                      (-1.7765764)
#define CS_REVERB_192000_B2                       0.7804076
#define CS_REVERB_192000_SCALE                        14

/* Reverb Gain Settings */
#define LVCS_HEADPHONE_DELAYGAIN               0.800000         /* Algorithm delay path gain */
#define LVCS_HEADPHONE_OUTPUTGAIN              1.000000         /* Algorithm output gain */
#define LVCS_HEADPHONE_PROCGAIN                   18403         /* Processed path gain */
#define LVCS_HEADPHONE_UNPROCGAIN                 18403         /* Unprocessed path gain */
#define LVCS_HEADPHONE_GAINCORRECT             1.009343         /* Delay mixer gain correction */

/************************************************************************************/
/*                                                                                  */
/* The Equaliser                                                                    */
/*                                                                                  */
/************************************************************************************/

/* Equaliser coefficients for 8000 Hz sample rate, \
   CS scaled with 1.038497 and CSEX scaled with 0.775480 */
#define CS_EQUALISER_8000_A0                     1.263312
#define CS_EQUALISER_8000_A1                    (-0.601748)
#define CS_EQUALISER_8000_A2                    (-0.280681)
#define CS_EQUALISER_8000_B1                    (-0.475865)
#define CS_EQUALISER_8000_B2                    (-0.408154)
#define CS_EQUALISER_8000_SCALE                      14
#define CSEX_EQUALISER_8000_A0                    0.943357
#define CSEX_EQUALISER_8000_A1                   (-0.449345)
#define CSEX_EQUALISER_8000_A2                   (-0.209594)
#define CSEX_EQUALISER_8000_B1                   (-0.475865)
#define CSEX_EQUALISER_8000_B2                   (-0.408154)
#define CSEX_EQUALISER_8000_SCALE                    15

/* Equaliser coefficients for 11025Hz sample rate, \
   CS scaled with 1.027761 and CSEX scaled with 0.767463 */
#define CS_EQUALISER_11025_A0                    1.101145
#define CS_EQUALISER_11025_A1                    0.139020
#define CS_EQUALISER_11025_A2                   (-0.864423)
#define CS_EQUALISER_11025_B1                    0.024541
#define CS_EQUALISER_11025_B2                   (-0.908930)
#define CS_EQUALISER_11025_SCALE                     14
#define CSEX_EQUALISER_11025_A0                    0.976058
#define CSEX_EQUALISER_11025_A1                   (-0.695326)
#define CSEX_EQUALISER_11025_A2                   (-0.090809)
#define CSEX_EQUALISER_11025_B1                   (-0.610594)
#define CSEX_EQUALISER_11025_B2                   (-0.311149)
#define CSEX_EQUALISER_11025_SCALE                   15

/* Equaliser coefficients for 12000Hz sample rate, \
   CS scaled with 1.032521 and CSEX scaled with 0.771017 */
#define CS_EQUALISER_12000_A0                      1.276661
#define CS_EQUALISER_12000_A1                     (-1.017519)
#define CS_EQUALISER_12000_A2                     (-0.044128)
#define CS_EQUALISER_12000_B1                     (-0.729616)
#define CS_EQUALISER_12000_B2                     (-0.204532)
#define CS_EQUALISER_12000_SCALE                     14
#define CSEX_EQUALISER_12000_A0                 1.007095
#define CSEX_EQUALISER_12000_A1                (-0.871912)
#define CSEX_EQUALISER_12000_A2                 0.023232
#define CSEX_EQUALISER_12000_B1                (-0.745857)
#define CSEX_EQUALISER_12000_B2                (-0.189171)
#define CSEX_EQUALISER_12000_SCALE                   14

/* Equaliser coefficients for 16000Hz sample rate, \
   CS scaled with 1.031378 and CSEX scaled with 0.770164 */
#define CS_EQUALISER_16000_A0                     1.281629
#define CS_EQUALISER_16000_A1                    (-1.075872)
#define CS_EQUALISER_16000_A2                    (-0.041365)
#define CS_EQUALISER_16000_B1                    (-0.725239)
#define CS_EQUALISER_16000_B2                    (-0.224358)
#define CS_EQUALISER_16000_SCALE                     14
#define CSEX_EQUALISER_16000_A0                  1.081091
#define CSEX_EQUALISER_16000_A1                 (-0.867183)
#define CSEX_EQUALISER_16000_A2                 (-0.070247)
#define CSEX_EQUALISER_16000_B1                 (-0.515121)
#define CSEX_EQUALISER_16000_B2                 (-0.425893)
#define CSEX_EQUALISER_16000_SCALE                   14

/* Equaliser coefficients for 22050Hz sample rate, \
   CS scaled with 1.041576 and CSEX scaled with 0.777779 */
#define CS_EQUALISER_22050_A0                   1.388605
#define CS_EQUALISER_22050_A1                  (-1.305799)
#define CS_EQUALISER_22050_A2                   0.039922
#define CS_EQUALISER_22050_B1                  (-0.719494)
#define CS_EQUALISER_22050_B2                  (-0.243245)
#define CS_EQUALISER_22050_SCALE                     14
#define CSEX_EQUALISER_22050_A0                   1.272910
#define CSEX_EQUALISER_22050_A1                  (-1.341014)
#define CSEX_EQUALISER_22050_A2                   0.167462
#define CSEX_EQUALISER_22050_B1                  (-0.614219)
#define CSEX_EQUALISER_22050_B2                  (-0.345384)
#define CSEX_EQUALISER_22050_SCALE                   14

/* Equaliser coefficients for 24000Hz sample rate, \
   CS scaled with 1.034495 and CSEX scaled with 0.772491 */
#define CS_EQUALISER_24000_A0                    1.409832
#define CS_EQUALISER_24000_A1                   (-1.456506)
#define CS_EQUALISER_24000_A2                    0.151410
#define CS_EQUALISER_24000_B1                   (-0.804201)
#define CS_EQUALISER_24000_B2                   (-0.163783)
#define CS_EQUALISER_24000_SCALE                     14
#define CSEX_EQUALISER_24000_A0                  1.299198
#define CSEX_EQUALISER_24000_A1                 (-1.452447)
#define CSEX_EQUALISER_24000_A2                  0.240489
#define CSEX_EQUALISER_24000_B1                 (-0.669303)
#define CSEX_EQUALISER_24000_B2                 (-0.294984)
#define CSEX_EQUALISER_24000_SCALE                   14

/* Equaliser coefficients for 32000Hz sample rate, \
   CS scaled with 1.044559 and CSEX scaled with 0.780006 */
#define CS_EQUALISER_32000_A0                     1.560988
#define CS_EQUALISER_32000_A1                    (-1.877724)
#define CS_EQUALISER_32000_A2                     0.389741
#define CS_EQUALISER_32000_B1                    (-0.907410)
#define CS_EQUALISER_32000_B2                    (-0.070489)
#define CS_EQUALISER_32000_SCALE                     14
#define CSEX_EQUALISER_32000_A0                  1.785049
#define CSEX_EQUALISER_32000_A1                 (-2.233497)
#define CSEX_EQUALISER_32000_A2                  0.526431
#define CSEX_EQUALISER_32000_B1                 (-0.445939)
#define CSEX_EQUALISER_32000_B2                 (-0.522446)
#define CSEX_EQUALISER_32000_SCALE                   13

/* Equaliser coefficients for 44100Hz sample rate, \
   CS scaled with 1.022170 and CSEX scaled with 0.763288 */
#define CS_EQUALISER_44100_A0                  1.623993
#define CS_EQUALISER_44100_A1                 (-2.270743)
#define CS_EQUALISER_44100_A2                  0.688829
#define CS_EQUALISER_44100_B1                 (-1.117190)
#define CS_EQUALISER_44100_B2                  0.130208
#define CS_EQUALISER_44100_SCALE                     13
#define CSEX_EQUALISER_44100_A0                   2.028315
#define CSEX_EQUALISER_44100_A1                  (-2.882459)
#define CSEX_EQUALISER_44100_A2                   0.904535
#define CSEX_EQUALISER_44100_B1                  (-0.593308)
#define CSEX_EQUALISER_44100_B2                  (-0.385816)
#define CSEX_EQUALISER_44100_SCALE                   13

/* Equaliser coefficients for 48000Hz sample rate, \
   CS scaled with 1.018635 and CSEX scaled with 0.760648 */
#define CS_EQUALISER_48000_A0                    1.641177
#define CS_EQUALISER_48000_A1                   (-2.364687)
#define CS_EQUALISER_48000_A2                    0.759910
#define CS_EQUALISER_48000_B1                   (-1.166774)
#define CS_EQUALISER_48000_B2                    0.178074
#define CS_EQUALISER_48000_SCALE                     13
#define CSEX_EQUALISER_48000_A0                  2.099655
#define CSEX_EQUALISER_48000_A1                 (-3.065220)
#define CSEX_EQUALISER_48000_A2                  1.010417
#define CSEX_EQUALISER_48000_B1                 (-0.634021)
#define CSEX_EQUALISER_48000_B2                 (-0.347332)
#define CSEX_EQUALISER_48000_SCALE                   13

/* Equaliser coefficients for 88200Hz sample rate.
 * The filter coefficients are obtained by carrying out
 * state-space analysis using the coefficients available
 * for 44100Hz.
 */
#define CS_EQUALISER_88200_A0                   1.771899f
#define CS_EQUALISER_88200_A1                   (-2.930762f)
#define CS_EQUALISER_88200_A2                   1.172175f
#define CS_EQUALISER_88200_B1                   (-1.438349f)
#define CS_EQUALISER_88200_B2                   0.442520f
#define CS_EQUALISER_88200_SCALE                13
#define CSEX_EQUALISER_88200_A0                 2.675241f
#define CSEX_EQUALISER_88200_A1                 (-4.466154f)
#define CSEX_EQUALISER_88200_A2                 1.810305f
#define CSEX_EQUALISER_88200_B1                 (-0.925350f)
#define CSEX_EQUALISER_88200_B2                 (-0.066616f)
#define CSEX_EQUALISER_88200_SCALE              13

#define CS_EQUALISER_96000_A0                    1.784497
#define CS_EQUALISER_96000_A1                   (-3.001435)
#define CS_EQUALISER_96000_A2                    1.228422
#define CS_EQUALISER_96000_B1                   (-1.477804)
#define CS_EQUALISER_96000_B2                    0.481369
#define CS_EQUALISER_96000_SCALE                     13
#define CSEX_EQUALISER_96000_A0                  2.7573
#define CSEX_EQUALISER_96000_A1                 (-4.6721)
#define CSEX_EQUALISER_96000_A2                  1.9317
#define CSEX_EQUALISER_96000_B1                 (-0.971718)
#define CSEX_EQUALISER_96000_B2                 (-0.021216)
#define CSEX_EQUALISER_96000_SCALE                   13
/* Equaliser coefficients for 176400Hz sample rate.
 * The filter coefficients are obtained by carrying out
 * state-space analysis using the coefficients available
 * for 44100Hz.
 */
#define CS_EQUALISER_176400_A0                  1.883440f
#define CS_EQUALISER_176400_A1                  (-3.414272f)
#define CS_EQUALISER_176400_A2                  1.534702f
#define CS_EQUALISER_176400_B1                  (-1.674614f)
#define CS_EQUALISER_176400_B2                  0.675827f
#define CS_EQUALISER_176400_SCALE               13
#define CSEX_EQUALISER_176400_A0                3.355068f
#define CSEX_EQUALISER_176400_A1                (-6.112578f)
#define CSEX_EQUALISER_176400_A2                2.764135f
#define CSEX_EQUALISER_176400_B1                (-1.268533f)
#define CSEX_EQUALISER_176400_B2                0.271277f
#define CSEX_EQUALISER_176400_SCALE             13

#define CS_EQUALISER_192000_A0                    1.889582
#define CS_EQUALISER_192000_A1                   (-3.456140)
#define CS_EQUALISER_192000_A2                    1.569864
#define CS_EQUALISER_192000_B1                   (-1.700798)
#define CS_EQUALISER_192000_B2                    0.701824
#define CS_EQUALISER_192000_SCALE                     13
#define CSEX_EQUALISER_192000_A0                  3.4273
#define CSEX_EQUALISER_192000_A1                 (-6.2936)
#define CSEX_EQUALISER_192000_A2                  2.8720
#define CSEX_EQUALISER_192000_B1                 (-1.31074)
#define CSEX_EQUALISER_192000_B2                 0.31312
#define CSEX_EQUALISER_192000_SCALE                   13

#define LVCS_HEADPHONE_SHIFT                          2              /* Output Shift */
#define LVCS_HEADPHONE_SHIFTLOSS                  0.8477735          /* Output Shift loss */
#define LVCS_HEADPHONE_GAIN                       0.2087465          /* Unprocessed path gain */
#define LVCS_EX_HEADPHONE_SHIFT                       3              /* EX Output Shift */
#define LVCS_EX_HEADPHONE_SHIFTLOSS               0.569225           /* EX Output Shift loss */
#define LVCS_EX_HEADPHONE_GAIN                    0.07794425         /* EX Unprocessed path gain */
#endif

