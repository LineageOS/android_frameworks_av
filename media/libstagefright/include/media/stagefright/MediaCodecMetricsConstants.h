/*
 * Copyright 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef MEDIA_CODEC_METRICS_CONSTANTS_H_
#define MEDIA_CODEC_METRICS_CONSTANTS_H_

namespace android {

// key for media statistics
// Other keys are in MediaCodec.cpp
// NB: These are not yet exposed as public Java API constants.
inline constexpr char kCodecPixelFormat[] =
        "android.media.mediacodec.pixel-format";

}

#endif  // MEDIA_CODEC_METRICS_CONSTANTS_H_