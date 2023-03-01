/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include <aidl/android/media/audio/common/AudioUuid.h>

namespace android {
namespace effect {

using ::aidl::android::media::audio::common::AudioUuid;

// 7b491460-8d4d-11e0-bd61-0002a5d5c51b.
static const AudioUuid kAcousticEchoCancelerTypeUUID = {static_cast<int32_t>(0x7b491460),
                                                        0x8d4d,
                                                        0x11e0,
                                                        0xbd61,
                                                        {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
// ae3c653b-be18-4ab8-8938-418f0a7f06ac
static const AudioUuid kAutomaticGainControl1TypeUUID = {static_cast<int32_t>(0xae3c653b),
                                                         0xbe18,
                                                         0x4ab8,
                                                         0x8938,
                                                         {0x41, 0x8f, 0x0a, 0x7f, 0x06, 0xac}};
// 0xae3c653b-be18-4ab8-8938-418f0a7f06ac
static const AudioUuid kAutomaticGainControl2TypeUUID = {static_cast<int32_t>(0xae3c653b),
                                                         0xbe18,
                                                         0x4ab8,
                                                         0x8938,
                                                         {0x41, 0x8f, 0x0a, 0x7f, 0x06, 0xac}};
// 0634f220-ddd4-11db-a0fc-0002a5d5c51b
static const AudioUuid kBassBoostTypeUUID = {static_cast<int32_t>(0x0634f220),
                                             0xddd4,
                                             0x11db,
                                             0xa0fc,
                                             {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
// fa81862a-588b-11ed-9b6a-0242ac120002
static const AudioUuid kDownmixTypeUUID = {static_cast<int32_t>(0x381e49cc),
                                           0xa858,
                                           0x4aa2,
                                           0x87f6,
                                           {0xe8, 0x38, 0x8e, 0x76, 0x01, 0xb2}};
// 7261676f-6d75-7369-6364-28e2fd3ac39e
static const AudioUuid kDynamicsProcessingTypeUUID = {static_cast<int32_t>(0x7261676f),
                                                      0x6d75,
                                                      0x7369,
                                                      0x6364,
                                                      {0x28, 0xe2, 0xfd, 0x3a, 0xc3, 0x9e}};
// 0bed4300-ddd6-11db-8f34-0002a5d5c51b.
static const AudioUuid kEqualizerTypeUUID = {static_cast<int32_t>(0x0bed4300),
                                             0xddd6,
                                             0x11db,
                                             0x8f34,
                                             {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
// 1411e6d6-aecd-4021-a1cf-a6aceb0d71e5
static const AudioUuid kHapticGeneratorTypeUUID = {static_cast<int32_t>(0x1411e6d6),
                                                   0xaecd,
                                                   0x4021,
                                                   0xa1cf,
                                                   {0xa6, 0xac, 0xeb, 0x0d, 0x71, 0xe5}};
// fe3199be-aed0-413f-87bb-11260eb63cf1
static const AudioUuid kLoudnessEnhancerTypeUUID = {static_cast<int32_t>(0xfe3199be),
                                                    0xaed0,
                                                    0x413f,
                                                    0x87bb,
                                                    {0x11, 0x26, 0x0e, 0xb6, 0x3c, 0xf1}};
// c2e5d5f0-94bd-4763-9cac-4e234d06839e
static const AudioUuid kEnvReverbTypeUUID = {static_cast<int32_t>(0xc2e5d5f0),
                                             0x94bd,
                                             0x4763,
                                             0x9cac,
                                             {0x4e, 0x23, 0x4d, 0x06, 0x83, 0x9e}};
// 58b4b260-8e06-11e0-aa8e-0002a5d5c51b
static const AudioUuid kNoiseSuppressionTypeUUID = {static_cast<int32_t>(0x58b4b260),
                                                    0x8e06,
                                                    0x11e0,
                                                    0xaa8e,
                                                    {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
// 47382d60-ddd8-11db-bf3a-0002a5d5c51b
static const AudioUuid kPresetReverbTypeUUID = {static_cast<int32_t>(0x47382d60),
                                                0xddd8,
                                                0x11db,
                                                0xbf3a,
                                                {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
// ccd4cf09-a79d-46c2-9aae-06a1698d6c8f
static const AudioUuid kSpatializerTypeUUID = {static_cast<int32_t>(0xccd4cf09),
                                                0xa79d,
                                                0x46c2,
                                                0x9aae,
                                                {0x06, 0xa1, 0x69, 0x8d, 0x6c, 0x8f}};
// 37cc2c00-dddd-11db-8577-0002a5d5c51b
static const AudioUuid kVirtualizerTypeUUID = {static_cast<int32_t>(0x37cc2c00),
                                               0xdddd,
                                               0x11db,
                                               0x8577,
                                               {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
// e46b26a0-dddd-11db-8afd-0002a5d5c51b
static const AudioUuid kVisualizerTypeUUID = {static_cast<int32_t>(0xe46b26a0),
                                              0xdddd,
                                              0x11db,
                                              0x8afd,
                                              {0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b}};
// fa81a2b8-588b-11ed-9b6a-0242ac120002
static const AudioUuid kVolumeTypeUUID = {static_cast<int32_t>(0xfa81a2b8),
                                          0x588b,
                                          0x11ed,
                                          0x9b6a,
                                          {0x02, 0x42, 0xac, 0x12, 0x00, 0x02}};

}  // namespace effect
}  // namespace android
