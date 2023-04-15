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

/**
 * Can only handle conversion between AIDL (NDK backend) and legacy type.
 */
#include <aidl/android/hardware/audio/core/IStreamIn.h>
#include <media/AidlConversionUtil.h>
#include <system/audio.h>

namespace aidl {
namespace android {

ConversionResult<audio_microphone_direction_t>
aidl2legacy_MicrophoneDirection_audio_microphone_direction_t(
        hardware::audio::core::IStreamIn::MicrophoneDirection aidl);
ConversionResult<hardware::audio::core::IStreamIn::MicrophoneDirection>
legacy2aidl_audio_microphone_direction_t_MicrophoneDirection(audio_microphone_direction_t legacy);

}  // namespace android
}  // namespace aidl
