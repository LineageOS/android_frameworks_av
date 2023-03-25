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

/**
 * Can only handle conversion between AIDL (NDK backend) and legacy types.
 */

#include <string>
#include <vector>

#include <hardware/audio_effect.h>
#include <system/audio_effect.h>

#include <aidl/android/hardware/audio/common/PlaybackTrackMetadata.h>
#include <aidl/android/hardware/audio/common/RecordTrackMetadata.h>
#include <aidl/android/media/audio/common/AudioConfig.h>
#include <media/AidlConversionUtil.h>

namespace aidl {
namespace android {

ConversionResult<buffer_config_t> aidl2legacy_AudioConfig_buffer_config_t(
        const media::audio::common::AudioConfig& aidl, bool isInput);
ConversionResult<media::audio::common::AudioConfig> legacy2aidl_buffer_config_t_AudioConfig(
        const buffer_config_t& legacy, bool isInput);

::android::status_t aidl2legacy_AudioAttributesTags(
        const std::vector<std::string>& aidl, char* legacy);
ConversionResult<std::vector<std::string>> legacy2aidl_AudioAttributesTags(const char* legacy);

ConversionResult<playback_track_metadata_v7>
aidl2legacy_PlaybackTrackMetadata_playback_track_metadata_v7(
        const hardware::audio::common::PlaybackTrackMetadata& aidl);
ConversionResult<hardware::audio::common::PlaybackTrackMetadata>
legacy2aidl_playback_track_metadata_v7_PlaybackTrackMetadata(
        const playback_track_metadata_v7& legacy);

ConversionResult<record_track_metadata_v7>
aidl2legacy_RecordTrackMetadata_record_track_metadata_v7(
        const hardware::audio::common::RecordTrackMetadata& aidl);
ConversionResult<hardware::audio::common::RecordTrackMetadata>
legacy2aidl_record_track_metadata_v7_RecordTrackMetadata(const record_track_metadata_v7& legacy);

}  // namespace android
}  // namespace aidl
