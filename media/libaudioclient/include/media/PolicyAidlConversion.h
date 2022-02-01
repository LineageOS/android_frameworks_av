/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <limits>
#include <type_traits>

#include <system/audio.h>

#include <android/media/AudioMix.h>
#include <android/media/AudioMixCallbackFlag.h>
#include <android/media/AudioMixLatencyClass.h>
#include <android/media/AudioMixRouteFlag.h>
#include <android/media/AudioMixType.h>
#include <android/media/AudioMode.h>
#include <android/media/AudioOffloadMode.h>
#include <android/media/AudioPolicyForceUse.h>
#include <android/media/AudioPolicyForcedConfig.h>
#include <android/media/DeviceRole.h>

#include <media/AidlConversionUtil.h>
#include <media/AudioCommonTypes.h>
#include <media/AudioPolicy.h>
#include <android/media/AudioPolicyDeviceState.h>

namespace android {

ConversionResult<product_strategy_t>
aidl2legacy_int32_t_product_strategy_t(int32_t aidl);
ConversionResult<int32_t>
legacy2aidl_product_strategy_t_int32_t(product_strategy_t legacy);

ConversionResult<uint32_t>
aidl2legacy_AudioMixType_uint32_t(media::AudioMixType aidl);
ConversionResult<media::AudioMixType>
legacy2aidl_uint32_t_AudioMixType(uint32_t legacy);

ConversionResult<uint32_t>
aidl2legacy_AudioMixCallbackFlag_uint32_t(media::AudioMixCallbackFlag aidl);
ConversionResult<media::AudioMixCallbackFlag>
legacy2aidl_uint32_t_AudioMixCallbackFlag(uint32_t legacy);

ConversionResult<uint32_t>
aidl2legacy_AudioMixCallbackFlag_uint32_t_mask(int32_t aidl);
ConversionResult<int32_t>
legacy2aidl_uint32_t_AudioMixCallbackFlag_mask(uint32_t legacy);

ConversionResult<uint32_t>
aidl2legacy_AudioMixRouteFlag_uint32_t(media::AudioMixRouteFlag aidl);
ConversionResult<media::AudioMixRouteFlag>
legacy2aidl_uint32_t_AudioMixRouteFlag(uint32_t legacy);

ConversionResult<uint32_t>
aidl2legacy_AudioMixRouteFlag_uint32_t_mask(int32_t aidl);
ConversionResult<int32_t>
legacy2aidl_uint32_t_AudioMixRouteFlag_mask(uint32_t legacy);

ConversionResult<AudioMixMatchCriterion>
aidl2legacy_AudioMixMatchCriterion(const media::AudioMixMatchCriterion& aidl);
ConversionResult<media::AudioMixMatchCriterion>
legacy2aidl_AudioMixMatchCriterion(const AudioMixMatchCriterion& legacy);

ConversionResult<AudioMix>
aidl2legacy_AudioMix(const media::AudioMix& aidl);
ConversionResult<media::AudioMix>
legacy2aidl_AudioMix(const AudioMix& legacy);

ConversionResult<audio_policy_dev_state_t>
aidl2legacy_AudioPolicyDeviceState_audio_policy_dev_state_t(media::AudioPolicyDeviceState aidl);
ConversionResult<media::AudioPolicyDeviceState>
legacy2aidl_audio_policy_dev_state_t_AudioPolicyDeviceState(audio_policy_dev_state_t legacy);

ConversionResult<audio_policy_force_use_t>
aidl2legacy_AudioPolicyForceUse_audio_policy_force_use_t(media::AudioPolicyForceUse aidl);
ConversionResult<media::AudioPolicyForceUse>
legacy2aidl_audio_policy_force_use_t_AudioPolicyForceUse(audio_policy_force_use_t legacy);

ConversionResult<audio_policy_forced_cfg_t>
aidl2legacy_AudioPolicyForcedConfig_audio_policy_forced_cfg_t(media::AudioPolicyForcedConfig aidl);
ConversionResult<media::AudioPolicyForcedConfig>
legacy2aidl_audio_policy_forced_cfg_t_AudioPolicyForcedConfig(audio_policy_forced_cfg_t legacy);

ConversionResult<device_role_t>
aidl2legacy_DeviceRole_device_role_t(media::DeviceRole aidl);
ConversionResult<media::DeviceRole>
legacy2aidl_device_role_t_DeviceRole(device_role_t legacy);

ConversionResult<audio_offload_mode_t>
aidl2legacy_AudioOffloadMode_audio_offload_mode_t(media::AudioOffloadMode aidl);
ConversionResult<media::AudioOffloadMode>
legacy2aidl_audio_offload_mode_t_AudioOffloadMode(audio_offload_mode_t legacy);

}  // namespace android
