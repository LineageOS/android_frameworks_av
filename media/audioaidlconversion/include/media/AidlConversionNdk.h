/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <android/binder_auto_utils.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

/**
 * Can only handle conversion between AIDL (NDK backend) and legacy type.
 */
#include <hardware/audio_effect.h>
#include <media/AidlConversionUtil.h>
#include <system/audio_effect.h>

#include <aidl/android/hardware/audio/effect/IEffect.h>

namespace aidl {
namespace android {

ConversionResult<uint32_t> aidl2legacy_Flags_Type_uint32(
        ::aidl::android::hardware::audio::effect::Flags::Type type);
ConversionResult<uint32_t> aidl2legacy_Flags_Insert_uint32(
        ::aidl::android::hardware::audio::effect::Flags::Insert insert);
ConversionResult<uint32_t> aidl2legacy_Flags_Volume_uint32(
        ::aidl::android::hardware::audio::effect::Flags::Volume volume);
ConversionResult<uint32_t> aidl2legacy_Flags_HardwareAccelerator_uint32(
        ::aidl::android::hardware::audio::effect::Flags::HardwareAccelerator hwAcceleratorMode);
ConversionResult<uint32_t> aidl2legacy_Flags_uint32(
        const ::aidl::android::hardware::audio::effect::Flags aidl);

ConversionResult<::aidl::android::hardware::audio::effect::Flags::Type>
legacy2aidl_uint32_Flags_Type(uint32_t legacy);
ConversionResult<::aidl::android::hardware::audio::effect::Flags::Insert>
legacy2aidl_uint32_Flags_Insert(uint32_t legacy);
ConversionResult<::aidl::android::hardware::audio::effect::Flags::Volume>
legacy2aidl_uint32_Flags_Volume(uint32_t legacy);
ConversionResult<::aidl::android::hardware::audio::effect::Flags::HardwareAccelerator>
legacy2aidl_uint32_Flags_HardwareAccelerator(uint32_t legacy);
ConversionResult<::aidl::android::hardware::audio::effect::Flags> legacy2aidl_uint32_Flags(
        uint32_t hal);

ConversionResult<effect_descriptor_t> aidl2legacy_Descriptor_effect_descriptor(
        const ::aidl::android::hardware::audio::effect::Descriptor& aidl);
ConversionResult<::aidl::android::hardware::audio::effect::Descriptor>
legacy2aidl_effect_descriptor_Descriptor(const effect_descriptor_t& hal);

ConversionResult<buffer_config_t> aidl2legacy_AudioConfigBase_buffer_config_t(
        const media::audio::common::AudioConfigBase& aidl, bool isInput);
ConversionResult<media::audio::common::AudioConfigBase> legacy2aidl_AudioConfigBase_buffer_config_t(
        const buffer_config_t& legacy, bool isInput);

}  // namespace android
}  // namespace aidl
