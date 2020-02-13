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

#ifndef __LVDBE_COEFFS_H__
#define __LVDBE_COEFFS_H__

/************************************************************************************/
/*                                                                                  */
/* General                                                                          */
/*                                                                                  */
/************************************************************************************/

#define LVDBE_SCALESHIFT                                    10         /* As a power of 2 */

/************************************************************************************/
/*                                                                                  */
/* High Pass Filter coefficients                                                    */
/*                                                                                  */
/************************************************************************************/

 /* Coefficients for centre frequency 55Hz */
#define HPF_Fs8000_Fc55_A0                        0.958849f
#define HPF_Fs8000_Fc55_A1                        (-1.917698f)
#define HPF_Fs8000_Fc55_A2                        0.958849f
#define HPF_Fs8000_Fc55_B1                        (-1.939001f)
#define HPF_Fs8000_Fc55_B2                        0.940807f
#define HPF_Fs11025_Fc55_A0                       0.966909f
#define HPF_Fs11025_Fc55_A1                       (-1.933818f)
#define HPF_Fs11025_Fc55_A2                       0.966909f
#define HPF_Fs11025_Fc55_B1                       (-1.955732f)
#define HPF_Fs11025_Fc55_B2                       0.956690f
#define HPF_Fs12000_Fc55_A0                       0.968650f
#define HPF_Fs12000_Fc55_A1                       (-1.937300f)
#define HPF_Fs12000_Fc55_A2                       0.968650f
#define HPF_Fs12000_Fc55_B1                       (-1.959327f)
#define HPF_Fs12000_Fc55_B2                       0.960138f
#define HPF_Fs16000_Fc55_A0                       0.973588f
#define HPF_Fs16000_Fc55_A1                       (-1.947176f)
#define HPF_Fs16000_Fc55_A2                       0.973588f
#define HPF_Fs16000_Fc55_B1                       (-1.969494f)
#define HPF_Fs16000_Fc55_B2                       0.969952f
#define HPF_Fs22050_Fc55_A0                       0.977671f
#define HPF_Fs22050_Fc55_A1                       (-1.955343f)
#define HPF_Fs22050_Fc55_A2                       0.977671f
#define HPF_Fs22050_Fc55_B1                       (-1.977863f)
#define HPF_Fs22050_Fc55_B2                       0.978105f
#define HPF_Fs24000_Fc55_A0                       0.978551f
#define HPF_Fs24000_Fc55_A1                       (-1.957102f)
#define HPF_Fs24000_Fc55_A2                       0.978551f
#define HPF_Fs24000_Fc55_B1                       (-1.979662f)
#define HPF_Fs24000_Fc55_B2                       0.979866f
#define HPF_Fs32000_Fc55_A0                       0.981042f
#define HPF_Fs32000_Fc55_A1                       (-1.962084f)
#define HPF_Fs32000_Fc55_A2                       0.981042f
#define HPF_Fs32000_Fc55_B1                       (-1.984746f)
#define HPF_Fs32000_Fc55_B2                       0.984861f
#define HPF_Fs44100_Fc55_A0                       0.983097f
#define HPF_Fs44100_Fc55_A1                       (-1.966194f)
#define HPF_Fs44100_Fc55_A2                       0.983097f
#define HPF_Fs44100_Fc55_B1                       (-1.988931f)
#define HPF_Fs44100_Fc55_B2                       0.988992f
#define HPF_Fs48000_Fc55_A0                       0.983539f
#define HPF_Fs48000_Fc55_A1                       (-1.967079f)
#define HPF_Fs48000_Fc55_A2                       0.983539f
#define HPF_Fs48000_Fc55_B1                       (-1.989831f)
#define HPF_Fs48000_Fc55_B2                       0.989882f

#define HPF_Fs88200_Fc55_A0                       0.985818f
#define HPF_Fs88200_Fc55_A1                       (-1.971636f)
#define HPF_Fs88200_Fc55_A2                       0.985818f
#define HPF_Fs88200_Fc55_B1                       (-1.994466f)
#define HPF_Fs88200_Fc55_B2                       0.994481f

#define HPF_Fs96000_Fc55_A0                       0.986040f
#define HPF_Fs96000_Fc55_A1                       (-1.972080f)
#define HPF_Fs96000_Fc55_A2                       0.986040f
#define HPF_Fs96000_Fc55_B1                       (-1.994915f)
#define HPF_Fs96000_Fc55_B2                       0.994928f

#define HPF_Fs176400_Fc55_A0                      0.987183f
#define HPF_Fs176400_Fc55_A1                      (-1.974366f)
#define HPF_Fs176400_Fc55_A2                      0.987183f
#define HPF_Fs176400_Fc55_B1                      (-1.997233f)
#define HPF_Fs176400_Fc55_B2                      0.997237f

#define HPF_Fs192000_Fc55_A0                      0.987294f
#define HPF_Fs192000_Fc55_A1                      (-1.974588f)
#define HPF_Fs192000_Fc55_A2                      0.987294f
#define HPF_Fs192000_Fc55_B1                      (-1.997458f)
#define HPF_Fs192000_Fc55_B2                      0.997461f

 /* Coefficients for centre frequency 66Hz */
#define HPF_Fs8000_Fc66_A0                        0.953016f
#define HPF_Fs8000_Fc66_A1                        (-1.906032f)
#define HPF_Fs8000_Fc66_A2                        0.953016f
#define HPF_Fs8000_Fc66_B1                        (-1.926810f)
#define HPF_Fs8000_Fc66_B2                        0.929396f
#define HPF_Fs11025_Fc66_A0                       0.962638f
#define HPF_Fs11025_Fc66_A1                       (-1.925275f)
#define HPF_Fs11025_Fc66_A2                       0.962638f
#define HPF_Fs11025_Fc66_B1                       (-1.946881f)
#define HPF_Fs11025_Fc66_B2                       0.948256f
#define HPF_Fs12000_Fc66_A0                       0.964718f
#define HPF_Fs12000_Fc66_A1                       (-1.929435f)
#define HPF_Fs12000_Fc66_A2                       0.964718f
#define HPF_Fs12000_Fc66_B1                       (-1.951196f)
#define HPF_Fs12000_Fc66_B2                       0.952359f
#define HPF_Fs16000_Fc66_A0                       0.970622f
#define HPF_Fs16000_Fc66_A1                       (-1.941244f)
#define HPF_Fs16000_Fc66_A2                       0.970622f
#define HPF_Fs16000_Fc66_B1                       (-1.963394f)
#define HPF_Fs16000_Fc66_B2                       0.964052f
#define HPF_Fs22050_Fc66_A0                       0.975509f
#define HPF_Fs22050_Fc66_A1                       (-1.951019f)
#define HPF_Fs22050_Fc66_A2                       0.975509f
#define HPF_Fs22050_Fc66_B1                       (-1.973436f)
#define HPF_Fs22050_Fc66_B2                       0.973784f
#define HPF_Fs24000_Fc66_A0                       0.976563f
#define HPF_Fs24000_Fc66_A1                       (-1.953125f)
#define HPF_Fs24000_Fc66_A2                       0.976563f
#define HPF_Fs24000_Fc66_B1                       (-1.975594f)
#define HPF_Fs24000_Fc66_B2                       0.975889f
#define HPF_Fs32000_Fc66_A0                       0.979547f
#define HPF_Fs32000_Fc66_A1                       (-1.959093f)
#define HPF_Fs32000_Fc66_A2                       0.979547f
#define HPF_Fs32000_Fc66_B1                       (-1.981695f)
#define HPF_Fs32000_Fc66_B2                       0.981861f
#define HPF_Fs44100_Fc66_A0                       0.982010f
#define HPF_Fs44100_Fc66_A1                       (-1.964019f)
#define HPF_Fs44100_Fc66_A2                       0.982010f
#define HPF_Fs44100_Fc66_B1                       (-1.986718f)
#define HPF_Fs44100_Fc66_B2                       0.986805f
#define HPF_Fs48000_Fc66_A0                       0.982540f
#define HPF_Fs48000_Fc66_A1                       (-1.965079f)
#define HPF_Fs48000_Fc66_A2                       0.982540f
#define HPF_Fs48000_Fc66_B1                       (-1.987797f)
#define HPF_Fs48000_Fc66_B2                       0.987871f

#define HPF_Fs88200_Fc66_A0                       0.985273f
#define HPF_Fs88200_Fc66_A1                       (-1.970546f)
#define HPF_Fs88200_Fc66_A2                       0.985273f
#define HPF_Fs88200_Fc66_B1                       (-1.993359f)
#define HPF_Fs88200_Fc66_B2                       0.993381f

#define HPF_Fs96000_Fc66_A0                       0.985539f
#define HPF_Fs96000_Fc66_A1                       (-1.971077f)
#define HPF_Fs96000_Fc66_A2                       0.985539f
#define HPF_Fs96000_Fc66_B1                       (-1.993898f)
#define HPF_Fs96000_Fc66_B2                       0.993917f

#define HPF_Fs176400_Fc66_A0                      0.986910f
#define HPF_Fs176400_Fc66_A1                      (-1.973820f)
#define HPF_Fs176400_Fc66_A2                      0.986910f
#define HPF_Fs176400_Fc66_B1                      (-1.996679f)
#define HPF_Fs176400_Fc66_B2                      0.996685f

#define HPF_Fs192000_Fc66_A0                      0.987043f
#define HPF_Fs192000_Fc66_A1                      (-1.974086f)
#define HPF_Fs192000_Fc66_A2                      0.987043f
#define HPF_Fs192000_Fc66_B1                      (-1.996949f)
#define HPF_Fs192000_Fc66_B2                      0.996954f

/* Coefficients for centre frequency 78Hz */
#define HPF_Fs8000_Fc78_A0                        0.946693f
#define HPF_Fs8000_Fc78_A1                        (-1.893387f)
#define HPF_Fs8000_Fc78_A2                        0.946693f
#define HPF_Fs8000_Fc78_B1                        (-1.913517f)
#define HPF_Fs8000_Fc78_B2                        0.917105f
#define HPF_Fs11025_Fc78_A0                       0.957999f
#define HPF_Fs11025_Fc78_A1                       (-1.915998f)
#define HPF_Fs11025_Fc78_A2                       0.957999f
#define HPF_Fs11025_Fc78_B1                       (-1.937229f)
#define HPF_Fs11025_Fc78_B2                       0.939140f
#define HPF_Fs12000_Fc78_A0                       0.960446f
#define HPF_Fs12000_Fc78_A1                       (-1.920892f)
#define HPF_Fs12000_Fc78_A2                       0.960446f
#define HPF_Fs12000_Fc78_B1                       (-1.942326f)
#define HPF_Fs12000_Fc78_B2                       0.943944f
#define HPF_Fs16000_Fc78_A0                       0.967397f
#define HPF_Fs16000_Fc78_A1                       (-1.934794f)
#define HPF_Fs16000_Fc78_A2                       0.967397f
#define HPF_Fs16000_Fc78_B1                       (-1.956740f)
#define HPF_Fs16000_Fc78_B2                       0.957656f
#define HPF_Fs22050_Fc78_A0                       0.973156f
#define HPF_Fs22050_Fc78_A1                       (-1.946313f)
#define HPF_Fs22050_Fc78_A2                       0.973156f
#define HPF_Fs22050_Fc78_B1                       (-1.968607f)
#define HPF_Fs22050_Fc78_B2                       0.969092f
#define HPF_Fs24000_Fc78_A0                       0.974398f
#define HPF_Fs24000_Fc78_A1                       (-1.948797f)
#define HPF_Fs24000_Fc78_A2                       0.974398f
#define HPF_Fs24000_Fc78_B1                       (-1.971157f)
#define HPF_Fs24000_Fc78_B2                       0.971568f
#define HPF_Fs32000_Fc78_A0                       0.977918f
#define HPF_Fs32000_Fc78_A1                       (-1.955836f)
#define HPF_Fs32000_Fc78_A2                       0.977918f
#define HPF_Fs32000_Fc78_B1                       (-1.978367f)
#define HPF_Fs32000_Fc78_B2                       0.978599f
#define HPF_Fs44100_Fc78_A0                       0.980824f
#define HPF_Fs44100_Fc78_A1                       (-1.961649f)
#define HPF_Fs44100_Fc78_A2                       0.980824f
#define HPF_Fs44100_Fc78_B1                       (-1.984303f)
#define HPF_Fs44100_Fc78_B2                       0.984425f
#define HPF_Fs48000_Fc78_A0                       0.981450f
#define HPF_Fs48000_Fc78_A1                       (-1.962900f)
#define HPF_Fs48000_Fc78_A2                       0.981450f
#define HPF_Fs48000_Fc78_B1                       (-1.985578f)
#define HPF_Fs48000_Fc78_B2                       0.985681f

#define HPF_Fs88200_Fc78_A0                       0.984678f
#define HPF_Fs88200_Fc78_A1                       (-1.969356f)
#define HPF_Fs88200_Fc78_A2                       0.984678f
#define HPF_Fs88200_Fc78_B1                       (-1.992151f)
#define HPF_Fs88200_Fc78_B2                       0.992182f

#define HPF_Fs96000_Fc78_A0                       0.984992f
#define HPF_Fs96000_Fc78_A1                       (-1.969984f)
#define HPF_Fs96000_Fc78_A2                       0.984992f
#define HPF_Fs96000_Fc78_B1                       (-1.992789f)
#define HPF_Fs96000_Fc78_B2                       0.992815f

#define HPF_Fs176400_Fc78_A0                      0.986612f
#define HPF_Fs176400_Fc78_A1                      (-1.973224f)
#define HPF_Fs176400_Fc78_A2                      0.986612f
#define HPF_Fs176400_Fc78_B1                      (-1.996076f)
#define HPF_Fs176400_Fc78_B2                      0.996083f

#define HPF_Fs192000_Fc78_A0                      0.986769f
#define HPF_Fs192000_Fc78_A1                      (-1.973539f)
#define HPF_Fs192000_Fc78_A2                      0.986769f
#define HPF_Fs192000_Fc78_B1                      (-1.996394f)
#define HPF_Fs192000_Fc78_B2                      0.996401f

/* Coefficients for centre frequency 90Hz */
#define HPF_Fs8000_Fc90_A0                       0.940412f
#define HPF_Fs8000_Fc90_A1                       (-1.880825f)
#define HPF_Fs8000_Fc90_A2                       0.940412f
#define HPF_Fs8000_Fc90_B1                       (-1.900231f)
#define HPF_Fs8000_Fc90_B2                       0.904977f
#define HPF_Fs11025_Fc90_A0                      0.953383f
#define HPF_Fs11025_Fc90_A1                      (-1.906766f)
#define HPF_Fs11025_Fc90_A2                      0.953383f
#define HPF_Fs11025_Fc90_B1                      (-1.927579f)
#define HPF_Fs11025_Fc90_B2                      0.930111f
#define HPF_Fs12000_Fc90_A0                      0.956193f
#define HPF_Fs12000_Fc90_A1                      (-1.912387f)
#define HPF_Fs12000_Fc90_A2                      0.956193f
#define HPF_Fs12000_Fc90_B1                      (-1.933459f)
#define HPF_Fs12000_Fc90_B2                      0.935603f
#define HPF_Fs16000_Fc90_A0                      0.964183f
#define HPF_Fs16000_Fc90_A1                      (-1.928365f)
#define HPF_Fs16000_Fc90_A2                      0.964183f
#define HPF_Fs16000_Fc90_B1                      (-1.950087f)
#define HPF_Fs16000_Fc90_B2                      0.951303f
#define HPF_Fs22050_Fc90_A0                      0.970809f
#define HPF_Fs22050_Fc90_A1                      (-1.941618f)
#define HPF_Fs22050_Fc90_A2                      0.970809f
#define HPF_Fs22050_Fc90_B1                      (-1.963778f)
#define HPF_Fs22050_Fc90_B2                      0.964423f
#define HPF_Fs24000_Fc90_A0                      0.972239f
#define HPF_Fs24000_Fc90_A1                      (-1.944477f)
#define HPF_Fs24000_Fc90_A2                      0.972239f
#define HPF_Fs24000_Fc90_B1                      (-1.966721f)
#define HPF_Fs24000_Fc90_B2                      0.967266f
#define HPF_Fs32000_Fc90_A0                      0.976292f
#define HPF_Fs32000_Fc90_A1                      (-1.952584f)
#define HPF_Fs32000_Fc90_A2                      0.976292f
#define HPF_Fs32000_Fc90_B1                      (-1.975040f)
#define HPF_Fs32000_Fc90_B2                      0.975347f
#define HPF_Fs44100_Fc90_A0                      0.979641f
#define HPF_Fs44100_Fc90_A1                      (-1.959282f)
#define HPF_Fs44100_Fc90_A2                      0.979641f
#define HPF_Fs44100_Fc90_B1                      (-1.981888f)
#define HPF_Fs44100_Fc90_B2                      0.982050f
#define HPF_Fs48000_Fc90_A0                      0.980362f
#define HPF_Fs48000_Fc90_A1                      (-1.960724f)
#define HPF_Fs48000_Fc90_A2                      0.980362f
#define HPF_Fs48000_Fc90_B1                      (-1.983359f)
#define HPF_Fs48000_Fc90_B2                      0.983497f

#define HPF_Fs88200_Fc90_A0                       0.984084f
#define HPF_Fs88200_Fc90_A1                       (-1.968168f)
#define HPF_Fs88200_Fc90_A2                       0.984084f
#define HPF_Fs88200_Fc90_B1                       (-1.990944f)
#define HPF_Fs88200_Fc90_B2                       0.990985f

#define HPF_Fs96000_Fc90_A0                       0.984446f
#define HPF_Fs96000_Fc90_A1                       (-1.968892f)
#define HPF_Fs96000_Fc90_A2                       0.984446f
#define HPF_Fs96000_Fc90_B1                       (-1.991680f)
#define HPF_Fs96000_Fc90_B2                       0.991714f

#define HPF_Fs176400_Fc90_A0                      0.986314f
#define HPF_Fs176400_Fc90_A1                      (-1.972629f)
#define HPF_Fs176400_Fc90_A2                      0.986314f
#define HPF_Fs176400_Fc90_B1                      (-1.995472f)
#define HPF_Fs176400_Fc90_B2                      0.995482f

#define HPF_Fs192000_Fc90_A0                      0.986496f
#define HPF_Fs192000_Fc90_A1                      (-1.972992f)
#define HPF_Fs192000_Fc90_A2                      0.986496f
#define HPF_Fs192000_Fc90_B1                      (-1.995840f)
#define HPF_Fs192000_Fc90_B2                      0.995848f

/************************************************************************************/
/*                                                                                  */
/* Band Pass Filter coefficients                                                    */
/*                                                                                  */
/************************************************************************************/

/* Coefficients for centre frequency 55Hz */
#define BPF_Fs8000_Fc55_A0                       0.009197f
#define BPF_Fs8000_Fc55_A1                       0.000000f
#define BPF_Fs8000_Fc55_A2                       (-0.009197f)
#define BPF_Fs8000_Fc55_B1                       (-1.979545f)
#define BPF_Fs8000_Fc55_B2                       0.981393f
#define BPF_Fs11025_Fc55_A0                      0.006691f
#define BPF_Fs11025_Fc55_A1                      0.000000f
#define BPF_Fs11025_Fc55_A2                      (-0.006691f)
#define BPF_Fs11025_Fc55_B1                      (-1.985488f)
#define BPF_Fs11025_Fc55_B2                      0.986464f
#define BPF_Fs12000_Fc55_A0                      0.006150f
#define BPF_Fs12000_Fc55_A1                      0.000000f
#define BPF_Fs12000_Fc55_A2                      (-0.006150f)
#define BPF_Fs12000_Fc55_B1                      (-1.986733f)
#define BPF_Fs12000_Fc55_B2                      0.987557f
#define BPF_Fs16000_Fc55_A0                      0.004620f
#define BPF_Fs16000_Fc55_A1                      0.000000f
#define BPF_Fs16000_Fc55_A2                      (-0.004620f)
#define BPF_Fs16000_Fc55_B1                      (-1.990189f)
#define BPF_Fs16000_Fc55_B2                      0.990653f
#define BPF_Fs22050_Fc55_A0                      0.003357f
#define BPF_Fs22050_Fc55_A1                      0.000000f
#define BPF_Fs22050_Fc55_A2                      (-0.003357f)
#define BPF_Fs22050_Fc55_B1                      (-1.992964f)
#define BPF_Fs22050_Fc55_B2                      0.993209f
#define BPF_Fs24000_Fc55_A0                      0.003085f
#define BPF_Fs24000_Fc55_A1                      0.000000f
#define BPF_Fs24000_Fc55_A2                      (-0.003085f)
#define BPF_Fs24000_Fc55_B1                      (-1.993552f)
#define BPF_Fs24000_Fc55_B2                      0.993759f
#define BPF_Fs32000_Fc55_A0                      0.002315f
#define BPF_Fs32000_Fc55_A1                      0.000000f
#define BPF_Fs32000_Fc55_A2                      (-0.002315f)
#define BPF_Fs32000_Fc55_B1                      (-1.995199f)
#define BPF_Fs32000_Fc55_B2                      0.995316f
#define BPF_Fs44100_Fc55_A0                      0.001681f
#define BPF_Fs44100_Fc55_A1                      0.000000f
#define BPF_Fs44100_Fc55_A2                      (-0.001681f)
#define BPF_Fs44100_Fc55_B1                      (-1.996537f)
#define BPF_Fs44100_Fc55_B2                      0.996599f
#define BPF_Fs48000_Fc55_A0                      0.001545f
#define BPF_Fs48000_Fc55_A1                      0.000000f
#define BPF_Fs48000_Fc55_A2                      (-0.001545f)
#define BPF_Fs48000_Fc55_B1                      (-1.996823f)
#define BPF_Fs48000_Fc55_B2                      0.996875f

#define BPF_Fs88200_Fc55_A0                      0.000831f
#define BPF_Fs88200_Fc55_A1                      0.000000f
#define BPF_Fs88200_Fc55_A2                      (-0.000831f)
#define BPF_Fs88200_Fc55_B1                      (-1.998321f)
#define BPF_Fs88200_Fc55_B2                      0.998338f

#define BPF_Fs96000_Fc55_A0                      0.000762f
#define BPF_Fs96000_Fc55_A1                      0.000000f
#define BPF_Fs96000_Fc55_A2                      (-0.000762f)
#define BPF_Fs96000_Fc55_B1                      (-1.998461f)
#define BPF_Fs96000_Fc55_B2                      0.998477f

#define BPF_Fs176400_Fc55_A0                     0.000416f
#define BPF_Fs176400_Fc55_A1                     0.000000f
#define BPF_Fs176400_Fc55_A2                     (-0.000416f)
#define BPF_Fs176400_Fc55_B1                     (-1.999164f)
#define BPF_Fs176400_Fc55_B2                     0.999169f

#define BPF_Fs192000_Fc55_A0                     0.000381f
#define BPF_Fs192000_Fc55_A1                     0.000000f
#define BPF_Fs192000_Fc55_A2                     (-0.000381f)
#define BPF_Fs192000_Fc55_B1                     (-1.999234f)
#define BPF_Fs192000_Fc55_B2                     0.999238f

/* Coefficients for centre frequency 66Hz */
#define BPF_Fs8000_Fc66_A0                      0.012648f
#define BPF_Fs8000_Fc66_A1                      0.000000f
#define BPF_Fs8000_Fc66_A2                      (-0.012648f)
#define BPF_Fs8000_Fc66_B1                      (-1.971760f)
#define BPF_Fs8000_Fc66_B2                      0.974412f
#define BPF_Fs11025_Fc66_A0                     0.009209f
#define BPF_Fs11025_Fc66_A1                     0.000000f
#define BPF_Fs11025_Fc66_A2                     (-0.009209f)
#define BPF_Fs11025_Fc66_B1                     (-1.979966f)
#define BPF_Fs11025_Fc66_B2                     0.981368f
#define BPF_Fs12000_Fc66_A0                     0.008468f
#define BPF_Fs12000_Fc66_A1                     0.000000f
#define BPF_Fs12000_Fc66_A2                     (-0.008468f)
#define BPF_Fs12000_Fc66_B1                     (-1.981685f)
#define BPF_Fs12000_Fc66_B2                     0.982869f
#define BPF_Fs16000_Fc66_A0                     0.006364f
#define BPF_Fs16000_Fc66_A1                     0.000000f
#define BPF_Fs16000_Fc66_A2                     (-0.006364f)
#define BPF_Fs16000_Fc66_B1                     (-1.986457f)
#define BPF_Fs16000_Fc66_B2                     0.987124f
#define BPF_Fs22050_Fc66_A0                     0.004626f
#define BPF_Fs22050_Fc66_A1                     0.000000f
#define BPF_Fs22050_Fc66_A2                     (-0.004626f)
#define BPF_Fs22050_Fc66_B1                     (-1.990288f)
#define BPF_Fs22050_Fc66_B2                     0.990641f
#define BPF_Fs24000_Fc66_A0                     0.004252f
#define BPF_Fs24000_Fc66_A1                     0.000000f
#define BPF_Fs24000_Fc66_A2                     (-0.004252f)
#define BPF_Fs24000_Fc66_B1                     (-1.991100f)
#define BPF_Fs24000_Fc66_B2                     0.991398f
#define BPF_Fs32000_Fc66_A0                     0.003192f
#define BPF_Fs32000_Fc66_A1                     0.000000f
#define BPF_Fs32000_Fc66_A2                     (-0.003192f)
#define BPF_Fs32000_Fc66_B1                     (-1.993374f)
#define BPF_Fs32000_Fc66_B2                     0.993541f
#define BPF_Fs44100_Fc66_A0                     0.002318f
#define BPF_Fs44100_Fc66_A1                     0.000000f
#define BPF_Fs44100_Fc66_A2                     (-0.002318f)
#define BPF_Fs44100_Fc66_B1                     (-1.995221f)
#define BPF_Fs44100_Fc66_B2                     0.995309f
#define BPF_Fs48000_Fc66_A0                     0.002131f
#define BPF_Fs48000_Fc66_A1                     0.000000f
#define BPF_Fs48000_Fc66_A2                     (-0.002131f)
#define BPF_Fs48000_Fc66_B1                     (-1.995615f)
#define BPF_Fs48000_Fc66_B2                     0.995690f

#define BPF_Fs88200_Fc66_A0                     0.001146f
#define BPF_Fs88200_Fc66_A1                     0.000000f
#define BPF_Fs88200_Fc66_A2                     (-0.001146f)
#define BPF_Fs88200_Fc66_B1                     (-1.997684f)
#define BPF_Fs88200_Fc66_B2                     0.997708f

#define BPF_Fs96000_Fc66_A0                     0.001055f
#define BPF_Fs96000_Fc66_A1                     0.000000f
#define BPF_Fs96000_Fc66_A2                     (-0.001055f)
#define BPF_Fs96000_Fc66_B1                     (-1.997868f)
#define BPF_Fs96000_Fc66_B2                     0.997891f

#define BPF_Fs176400_Fc66_A0                    0.000573f
#define BPF_Fs176400_Fc66_A1                    0.000000f
#define BPF_Fs176400_Fc66_A2                    (-0.000573f)
#define BPF_Fs176400_Fc66_B1                    (-1.998847f)
#define BPF_Fs176400_Fc66_B2                    0.998853f

#define BPF_Fs192000_Fc66_A0                    0.000528f
#define BPF_Fs192000_Fc66_A1                    0.000000f
#define BPF_Fs192000_Fc66_A2                   (-0.000528f)
#define BPF_Fs192000_Fc66_B1                   (-1.998939f)
#define BPF_Fs192000_Fc66_B2                    0.998945f

/* Coefficients for centre frequency 78Hz */
#define BPF_Fs8000_Fc78_A0                      0.018572f
#define BPF_Fs8000_Fc78_A1                      0.000000f
#define BPF_Fs8000_Fc78_A2                      (-0.018572f)
#define BPF_Fs8000_Fc78_B1                      (-1.958745f)
#define BPF_Fs8000_Fc78_B2                      0.962427f
#define BPF_Fs11025_Fc78_A0                     0.013545f
#define BPF_Fs11025_Fc78_A1                     0.000000f
#define BPF_Fs11025_Fc78_A2                     (-0.013545f)
#define BPF_Fs11025_Fc78_B1                     (-1.970647f)
#define BPF_Fs11025_Fc78_B2                     0.972596f
#define BPF_Fs12000_Fc78_A0                     0.012458f
#define BPF_Fs12000_Fc78_A1                     0.000000f
#define BPF_Fs12000_Fc78_A2                     (-0.012458f)
#define BPF_Fs12000_Fc78_B1                     (-1.973148f)
#define BPF_Fs12000_Fc78_B2                     0.974795f
#define BPF_Fs16000_Fc78_A0                     0.009373f
#define BPF_Fs16000_Fc78_A1                     0.000000f
#define BPF_Fs16000_Fc78_A2                     (-0.009373f)
#define BPF_Fs16000_Fc78_B1                     (-1.980108f)
#define BPF_Fs16000_Fc78_B2                     0.981037f
#define BPF_Fs22050_Fc78_A0                     0.006819f
#define BPF_Fs22050_Fc78_A1                     0.000000f
#define BPF_Fs22050_Fc78_A2                     (-0.006819f)
#define BPF_Fs22050_Fc78_B1                     (-1.985714f)
#define BPF_Fs22050_Fc78_B2                     0.986204f
#define BPF_Fs24000_Fc78_A0                     0.006268f
#define BPF_Fs24000_Fc78_A1                     0.000000f
#define BPF_Fs24000_Fc78_A2                     (-0.006268f)
#define BPF_Fs24000_Fc78_B1                     (-1.986904f)
#define BPF_Fs24000_Fc78_B2                     0.987318f
#define BPF_Fs32000_Fc78_A0                     0.004709f
#define BPF_Fs32000_Fc78_A1                     0.000000f
#define BPF_Fs32000_Fc78_A2                     (-0.004709f)
#define BPF_Fs32000_Fc78_B1                     (-1.990240f)
#define BPF_Fs32000_Fc78_B2                     0.990473f
#define BPF_Fs44100_Fc78_A0                     0.003421f
#define BPF_Fs44100_Fc78_A1                     0.000000f
#define BPF_Fs44100_Fc78_A2                     (-0.003421f)
#define BPF_Fs44100_Fc78_B1                     (-1.992955f)
#define BPF_Fs44100_Fc78_B2                     0.993078f
#define BPF_Fs48000_Fc78_A0                     0.003144f
#define BPF_Fs48000_Fc78_A1                     0.000000f
#define BPF_Fs48000_Fc78_A2                     (-0.003144f)
#define BPF_Fs48000_Fc78_B1                     (-1.993535f)
#define BPF_Fs48000_Fc78_B2                     0.993639f

#define BPF_Fs88200_Fc78_A0                    0.001693f
#define BPF_Fs88200_Fc78_A1                    0.000000f
#define BPF_Fs88200_Fc78_A2                    (-0.001693f)
#define BPF_Fs88200_Fc78_B1                    (-1.996582f)
#define BPF_Fs88200_Fc78_B2                    0.996615f

#define BPF_Fs96000_Fc78_A0                     0.001555f
#define BPF_Fs96000_Fc78_A1                     0.000000f
#define BPF_Fs96000_Fc78_A2                    (-0.0015555f)
#define BPF_Fs96000_Fc78_B1                    (-1.996860f)
#define BPF_Fs96000_Fc78_B2                     0.996891f

#define BPF_Fs176400_Fc78_A0                    0.000847f
#define BPF_Fs176400_Fc78_A1                    0.000000f
#define BPF_Fs176400_Fc78_A2                    (-0.000847f)
#define BPF_Fs176400_Fc78_B1                    (-1.998298f)
#define BPF_Fs176400_Fc78_B2                    0.998306f

#define BPF_Fs192000_Fc78_A0                    0.000778f
#define BPF_Fs192000_Fc78_A1                    0.000000f
#define BPF_Fs192000_Fc78_A2                   (-0.000778f)
#define BPF_Fs192000_Fc78_B1                   (-1.998437f)
#define BPF_Fs192000_Fc78_B2                    0.998444f

/* Coefficients for centre frequency 90Hz */
#define BPF_Fs8000_Fc90_A0                       0.022760f
#define BPF_Fs8000_Fc90_A1                       0.000000f
#define BPF_Fs8000_Fc90_A2                       (-0.022760f)
#define BPF_Fs8000_Fc90_B1                       (-1.949073f)
#define BPF_Fs8000_Fc90_B2                       0.953953f
#define BPF_Fs11025_Fc90_A0                      0.016619f
#define BPF_Fs11025_Fc90_A1                      0.000000f
#define BPF_Fs11025_Fc90_A2                      (-0.016619f)
#define BPF_Fs11025_Fc90_B1                      (-1.963791f)
#define BPF_Fs11025_Fc90_B2                      0.966377f
#define BPF_Fs12000_Fc90_A0                      0.015289f
#define BPF_Fs12000_Fc90_A1                      0.000000f
#define BPF_Fs12000_Fc90_A2                      (-0.015289f)
#define BPF_Fs12000_Fc90_B1                      (-1.966882f)
#define BPF_Fs12000_Fc90_B2                      0.969067f
#define BPF_Fs16000_Fc90_A0                      0.011511f
#define BPF_Fs16000_Fc90_A1                      0.000000f
#define BPF_Fs16000_Fc90_A2                      (-0.011511f)
#define BPF_Fs16000_Fc90_B1                      (-1.975477f)
#define BPF_Fs16000_Fc90_B2                      0.976711f
#define BPF_Fs22050_Fc90_A0                      0.008379f
#define BPF_Fs22050_Fc90_A1                      0.000000f
#define BPF_Fs22050_Fc90_A2                      (-0.008379f)
#define BPF_Fs22050_Fc90_B1                      (-1.982395f)
#define BPF_Fs22050_Fc90_B2                      0.983047f
#define BPF_Fs24000_Fc90_A0                      0.007704f
#define BPF_Fs24000_Fc90_A1                      0.000000f
#define BPF_Fs24000_Fc90_A2                      (-0.007704f)
#define BPF_Fs24000_Fc90_B1                      (-1.983863f)
#define BPF_Fs24000_Fc90_B2                      0.984414f
#define BPF_Fs32000_Fc90_A0                      0.005789f
#define BPF_Fs32000_Fc90_A1                      0.000000f
#define BPF_Fs32000_Fc90_A2                      (-0.005789f)
#define BPF_Fs32000_Fc90_B1                      (-1.987977f)
#define BPF_Fs32000_Fc90_B2                      0.988288f
#define BPF_Fs44100_Fc90_A0                      0.004207f
#define BPF_Fs44100_Fc90_A1                      0.000000f
#define BPF_Fs44100_Fc90_A2                      (-0.004207f)
#define BPF_Fs44100_Fc90_B1                      (-1.991324f)
#define BPF_Fs44100_Fc90_B2                      0.991488f
#define BPF_Fs48000_Fc90_A0                      0.003867f
#define BPF_Fs48000_Fc90_A1                      0.000000f
#define BPF_Fs48000_Fc90_A2                      (-0.003867f)
#define BPF_Fs48000_Fc90_B1                      (-1.992038f)
#define BPF_Fs48000_Fc90_B2                      0.992177f

#define BPF_Fs88200_Fc90_A0                      0.002083f
#define BPF_Fs88200_Fc90_A1                      0.000000f
#define BPF_Fs88200_Fc90_A2                      (-0.002083f)
#define BPF_Fs88200_Fc90_B1                      (-1.995791f)
#define BPF_Fs88200_Fc90_B2                      0.995835f

#define BPF_Fs96000_Fc90_A0                      0.001913f
#define BPF_Fs96000_Fc90_A1                      0.000000f
#define BPF_Fs96000_Fc90_A2                     (-0.001913f)
#define BPF_Fs96000_Fc90_B1                     (-1.996134f)
#define BPF_Fs96000_Fc90_B2                      0.996174f

#define BPF_Fs176400_Fc90_A0                     0.001042f
#define BPF_Fs176400_Fc90_A1                     0.000000f
#define BPF_Fs176400_Fc90_A2                     (-0.001042f)
#define BPF_Fs176400_Fc90_B1                     (-1.997904f)
#define BPF_Fs176400_Fc90_B2                     0.997915f

#define BPF_Fs192000_Fc90_A0                     0.000958f
#define BPF_Fs192000_Fc90_A1                     0.000000f
#define BPF_Fs192000_Fc90_A2                    (-0.000958f)
#define BPF_Fs192000_Fc90_B1                    (-1.998075f)
#define BPF_Fs192000_Fc90_B2                     0.998085f

/************************************************************************************/
/*                                                                                  */
/* Automatic Gain Control time constants and gain settings                          */
/*                                                                                  */
/************************************************************************************/

/* AGC Time constants */
#define AGC_ATTACK_Fs8000                             0.841395f
#define AGC_ATTACK_Fs11025                            0.882223f
#define AGC_ATTACK_Fs12000                            0.891251f
#define AGC_ATTACK_Fs16000                            0.917276f
#define AGC_ATTACK_Fs22050                            0.939267f
#define AGC_ATTACK_Fs24000                            0.944061f
#define AGC_ATTACK_Fs32000                            0.957745f
#define AGC_ATTACK_Fs44100                            0.969158f
#define AGC_ATTACK_Fs48000                            0.971628f

#define AGC_ATTACK_Fs88200                             0.984458f
#define AGC_ATTACK_Fs96000                             0.985712f
#define AGC_ATTACK_Fs176400                            0.992199f
#define AGC_ATTACK_Fs192000                            0.992830f

#define DECAY_SHIFT                                   10

#define AGC_DECAY_Fs8000                              0.000042f
#define AGC_DECAY_Fs11025                             0.000030f
#define AGC_DECAY_Fs12000                             0.000028f
#define AGC_DECAY_Fs16000                             0.000021f
#define AGC_DECAY_Fs22050                             0.000015f
#define AGC_DECAY_Fs24000                             0.000014f
#define AGC_DECAY_Fs32000                             0.000010f
#define AGC_DECAY_Fs44100                             0.000008f
#define AGC_DECAY_Fs48000                             0.000007f

#define AGC_DECAY_Fs88200                            0.0000038f
#define AGC_DECAY_FS96000                            0.0000035f
#define AGC_DECAY_Fs176400                          0.00000188f
#define AGC_DECAY_FS192000                          0.00000175f

/* AGC Gain settings */
#define AGC_GAIN_SCALE                                        31         /* As a power of 2 */
#define AGC_GAIN_SHIFT                                         4         /* As a power of 2 */
#define AGC_TARGETLEVEL                            0.988553f
#define AGC_HPFGAIN_0dB                            0.412538f
#define AGC_GAIN_0dB                               0.000000f
#define AGC_HPFGAIN_1dB                            0.584893f
#define AGC_GAIN_1dB                               0.122018f
#define AGC_HPFGAIN_2dB                            0.778279f
#define AGC_GAIN_2dB                               0.258925f
#define AGC_HPFGAIN_3dB                            0.995262f
#define AGC_GAIN_3dB                               0.412538f
#define AGC_HPFGAIN_4dB                            1.238721f
#define AGC_GAIN_4dB                               0.584893f
#define AGC_HPFGAIN_5dB                            1.511886f
#define AGC_GAIN_5dB                               0.778279f
#define AGC_HPFGAIN_6dB                            1.818383f
#define AGC_GAIN_6dB                               0.995262f
#define AGC_HPFGAIN_7dB                            2.162278f
#define AGC_GAIN_7dB                               1.238721f
#define AGC_HPFGAIN_8dB                            2.548134f
#define AGC_GAIN_8dB                               1.511886f
#define AGC_HPFGAIN_9dB                            2.981072f
#define AGC_GAIN_9dB                               1.818383f
#define AGC_HPFGAIN_10dB                           3.466836f
#define AGC_GAIN_10dB                              2.162278f
#define AGC_HPFGAIN_11dB                           4.011872f
#define AGC_GAIN_11dB                              2.548134f
#define AGC_HPFGAIN_12dB                           4.623413f
#define AGC_GAIN_12dB                              2.981072f
#define AGC_HPFGAIN_13dB                           5.309573f
#define AGC_GAIN_13dB                              3.466836f
#define AGC_HPFGAIN_14dB                           6.079458f
#define AGC_GAIN_14dB                              4.011872f
#define AGC_HPFGAIN_15dB                           6.943282f
#define AGC_GAIN_15dB                              4.623413f

/************************************************************************************/
/*                                                                                  */
/* Volume control                                                                   */
/*                                                                                  */
/************************************************************************************/

/* Volume control gain */
#define VOLUME_MAX                                          0         /* In dBs */
#define VOLUME_SHIFT                                        0         /* In dBs */

/* Volume control time constants */
#define VOL_TC_SHIFT                                       21         /* As a power of 2 */
#define VOL_TC_Fs8000                                   0.024690f
#define VOL_TC_Fs11025                                  0.017977f
#define VOL_TC_Fs12000                                  0.016529f
#define VOL_TC_Fs16000                                  0.012422f
#define VOL_TC_Fs22050                                  0.009029f
#define VOL_TC_Fs24000                                  0.008299f
#define VOL_TC_Fs32000                                  0.006231f
#define VOL_TC_Fs44100                                  0.004525f
#define VOL_TC_Fs48000                                  0.004158f
#define VOL_TC_Fs88200                                  0.002263f
#define VOL_TC_Fs96000                                  0.002079f
#define VOL_TC_Fs176400                                 0.001131f
#define VOL_TC_Fs192000                                 0.001039f
#define MIX_TC_Fs8000                                   29365         /* Floating point value 0.896151 */
#define MIX_TC_Fs11025                                  30230         /* Floating point value 0.922548 */
#define MIX_TC_Fs12000                                  30422         /* Floating point value 0.928415 */
#define MIX_TC_Fs16000                                  30978         /* Floating point value 0.945387 */
#define MIX_TC_Fs22050                                  31451         /* Floating point value 0.959804 */
#define MIX_TC_Fs24000                                  31554         /* Floating point value 0.962956 */
#define MIX_TC_Fs32000                                  31850         /* Floating point value 0.971973 */
#define MIX_TC_Fs44100                                  32097         /* Floating point value 0.979515 */
#define MIX_TC_Fs48000                                  32150         /* Floating point value 0.981150 */
/* Floating point value 0.989704 */
#define MIX_TC_Fs88200                                  32430
#define MIX_TC_Fs96000                                  32456         /* Floating point value 0.990530 */
/* Floating point value 0.994838 */
#define MIX_TC_Fs176400                                 32598
#define MIX_TC_Fs192000                                 32611         /* Floating point value 0.992524 */

#endif
