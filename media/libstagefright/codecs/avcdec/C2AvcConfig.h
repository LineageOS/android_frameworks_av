/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef C2AVCCONFIG_H_
#define C2AVCCONFIG_H_

#include <C2Config.h>

namespace android {

enum : uint32_t {
    kParamIndexAvcProfile = kParamIndexParamStart + 1,
    kParamIndexAvcLevel,
    kParamIndexBlockSize,
    kParamIndexAlignment,
    kParamIndexFramerate,
    kParamIndexBlocksPerSecond,
};

enum C2AvcProfileIdc : uint32_t {
    kAvcProfileUnknown  = 0,
    kAvcProfileBaseline = 66,
    kAvcProfileMain     = 77,
    kAvcProfileExtended = 88,
    kAvcProfileHigh     = 100,
    kAvcProfileHigh10   = 110,
    kAvcProfileHigh422  = 122,
    kAvcProfileHigh444  = 144,
};

enum C2AvcLevelIdc : uint32_t {
    kAvcLevelUnknown = 0,
    kAvcLevel10      = 10,
    kAvcLevel1b      = 9,
    kAvcLevel11      = 11,
    kAvcLevel12      = 12,
    kAvcLevel13      = 13,
    kAvcLevel20      = 20,
    kAvcLevel21      = 21,
    kAvcLevel22      = 22,
    kAvcLevel30      = 30,
    kAvcLevel31      = 31,
    kAvcLevel32      = 32,
    kAvcLevel40      = 40,
    kAvcLevel41      = 41,
    kAvcLevel42      = 42,
    kAvcLevel50      = 50,
    kAvcLevel51      = 51,
    kAvcLevel52      = 52,
};

// profile for AVC video decoder [IN]
typedef C2StreamParam<C2Info, C2SimpleValueStruct<C2AvcProfileIdc>, kParamIndexAvcProfile>
    C2AvcProfileInfo;

// level for AVC video decoder [IN]
typedef C2StreamParam<C2Info, C2SimpleValueStruct<C2AvcLevelIdc>, kParamIndexAvcLevel>
    C2AvcLevelInfo;

// block size [OUT]
typedef C2StreamParam<C2Info, C2VideoSizeStruct, kParamIndexBlockSize> C2BlockSizeInfo;

// alignment [OUT]
typedef C2StreamParam<C2Info, C2VideoSizeStruct, kParamIndexAlignment> C2AlignmentInfo;

// frame rate [OUT, hint]
typedef C2StreamParam<C2Info, C2Uint32Value, kParamIndexFramerate> C2FrameRateInfo;

// blocks-per-second [OUT, hint]
typedef C2StreamParam<C2Info, C2Uint32Value, kParamIndexBlocksPerSecond> C2BlocksPerSecondInfo;

} // namespace android

#endif  // C2AVCCONFIG_H_
