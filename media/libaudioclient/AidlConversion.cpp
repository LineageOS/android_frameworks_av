/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <algorithm>
#include <unordered_map>
#include <utility>
#include <vector>

#define LOG_TAG "AidlConversion"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include "media/AidlConversion.h"

#include <media/ShmemCompat.h>
#include <media/stagefright/foundation/MediaDefs.h>

////////////////////////////////////////////////////////////////////////////////////////////////////
// Utilities

namespace android {

using base::unexpected;
using media::audio::common::AudioChannelLayout;
using media::audio::common::AudioConfig;
using media::audio::common::AudioConfigBase;
using media::audio::common::AudioContentType;
using media::audio::common::AudioDevice;
using media::audio::common::AudioDeviceAddress;
using media::audio::common::AudioDeviceDescription;
using media::audio::common::AudioDeviceType;
using media::audio::common::AudioFormatDescription;
using media::audio::common::AudioFormatType;
using media::audio::common::AudioGain;
using media::audio::common::AudioGainConfig;
using media::audio::common::AudioGainMode;
using media::audio::common::AudioInputFlags;
using media::audio::common::AudioIoFlags;
using media::audio::common::AudioMode;
using media::audio::common::AudioOffloadInfo;
using media::audio::common::AudioOutputFlags;
using media::audio::common::AudioPortDeviceExt;
using media::audio::common::AudioPortExt;
using media::audio::common::AudioPortMixExt;
using media::audio::common::AudioPortMixExtUseCase;
using media::audio::common::AudioProfile;
using media::audio::common::AudioSource;
using media::audio::common::AudioStandard;
using media::audio::common::AudioStreamType;
using media::audio::common::AudioUsage;
using media::audio::common::AudioUuid;
using media::audio::common::ExtraAudioDescriptor;
using media::audio::common::Int;
using media::audio::common::PcmType;

ConversionResult<audio_port_role_t> aidl2legacy_AudioPortRole_audio_port_role_t(
        media::AudioPortRole aidl) {
    switch (aidl) {
        case media::AudioPortRole::NONE:
            return AUDIO_PORT_ROLE_NONE;
        case media::AudioPortRole::SOURCE:
            return AUDIO_PORT_ROLE_SOURCE;
        case media::AudioPortRole::SINK:
            return AUDIO_PORT_ROLE_SINK;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioPortRole> legacy2aidl_audio_port_role_t_AudioPortRole(
        audio_port_role_t legacy) {
    switch (legacy) {
        case AUDIO_PORT_ROLE_NONE:
            return media::AudioPortRole::NONE;
        case AUDIO_PORT_ROLE_SOURCE:
            return media::AudioPortRole::SOURCE;
        case AUDIO_PORT_ROLE_SINK:
            return media::AudioPortRole::SINK;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_port_type_t> aidl2legacy_AudioPortType_audio_port_type_t(
        media::AudioPortType aidl) {
    switch (aidl) {
        case media::AudioPortType::NONE:
            return AUDIO_PORT_TYPE_NONE;
        case media::AudioPortType::DEVICE:
            return AUDIO_PORT_TYPE_DEVICE;
        case media::AudioPortType::MIX:
            return AUDIO_PORT_TYPE_MIX;
        case media::AudioPortType::SESSION:
            return AUDIO_PORT_TYPE_SESSION;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioPortType> legacy2aidl_audio_port_type_t_AudioPortType(
        audio_port_type_t legacy) {
    switch (legacy) {
        case AUDIO_PORT_TYPE_NONE:
            return media::AudioPortType::NONE;
        case AUDIO_PORT_TYPE_DEVICE:
            return media::AudioPortType::DEVICE;
        case AUDIO_PORT_TYPE_MIX:
            return media::AudioPortType::MIX;
        case AUDIO_PORT_TYPE_SESSION:
            return media::AudioPortType::SESSION;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<AudioPortDirection> portDirection(
        media::AudioPortRole role, media::AudioPortType type) {
    audio_port_role_t legacyRole = VALUE_OR_RETURN(
            aidl2legacy_AudioPortRole_audio_port_role_t(role));
    audio_port_type_t legacyType = VALUE_OR_RETURN(
            aidl2legacy_AudioPortType_audio_port_type_t(type));
    return portDirection(legacyRole, legacyType);
}

ConversionResult<audio_io_config_event_t> aidl2legacy_AudioIoConfigEvent_audio_io_config_event_t(
        media::AudioIoConfigEvent aidl) {
    switch (aidl) {
        case media::AudioIoConfigEvent::OUTPUT_REGISTERED:
            return AUDIO_OUTPUT_REGISTERED;
        case media::AudioIoConfigEvent::OUTPUT_OPENED:
            return AUDIO_OUTPUT_OPENED;
        case media::AudioIoConfigEvent::OUTPUT_CLOSED:
            return AUDIO_OUTPUT_CLOSED;
        case media::AudioIoConfigEvent::OUTPUT_CONFIG_CHANGED:
            return AUDIO_OUTPUT_CONFIG_CHANGED;
        case media::AudioIoConfigEvent::INPUT_REGISTERED:
            return AUDIO_INPUT_REGISTERED;
        case media::AudioIoConfigEvent::INPUT_OPENED:
            return AUDIO_INPUT_OPENED;
        case media::AudioIoConfigEvent::INPUT_CLOSED:
            return AUDIO_INPUT_CLOSED;
        case media::AudioIoConfigEvent::INPUT_CONFIG_CHANGED:
            return AUDIO_INPUT_CONFIG_CHANGED;
        case media::AudioIoConfigEvent::CLIENT_STARTED:
            return AUDIO_CLIENT_STARTED;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioIoConfigEvent> legacy2aidl_audio_io_config_event_t_AudioIoConfigEvent(
        audio_io_config_event_t legacy) {
    switch (legacy) {
        case AUDIO_OUTPUT_REGISTERED:
            return media::AudioIoConfigEvent::OUTPUT_REGISTERED;
        case AUDIO_OUTPUT_OPENED:
            return media::AudioIoConfigEvent::OUTPUT_OPENED;
        case AUDIO_OUTPUT_CLOSED:
            return media::AudioIoConfigEvent::OUTPUT_CLOSED;
        case AUDIO_OUTPUT_CONFIG_CHANGED:
            return media::AudioIoConfigEvent::OUTPUT_CONFIG_CHANGED;
        case AUDIO_INPUT_REGISTERED:
            return media::AudioIoConfigEvent::INPUT_REGISTERED;
        case AUDIO_INPUT_OPENED:
            return media::AudioIoConfigEvent::INPUT_OPENED;
        case AUDIO_INPUT_CLOSED:
            return media::AudioIoConfigEvent::INPUT_CLOSED;
        case AUDIO_INPUT_CONFIG_CHANGED:
            return media::AudioIoConfigEvent::INPUT_CONFIG_CHANGED;
        case AUDIO_CLIENT_STARTED:
            return media::AudioIoConfigEvent::CLIENT_STARTED;
    }
    return unexpected(BAD_VALUE);
}
ConversionResult<audio_port_config_mix_ext_usecase> aidl2legacy_AudioPortMixExtUseCase(
        const AudioPortMixExtUseCase& aidl, media::AudioPortRole role) {
    switch (role) {
        case media::AudioPortRole::NONE: {
            audio_port_config_mix_ext_usecase legacy;
            // Just verify that the union is empty.
            VALUE_OR_RETURN(UNION_GET(aidl, unspecified));
            return legacy;
        }
        case media::AudioPortRole::SOURCE:
            return aidl2legacy_AudioPortMixExtUseCase_audio_port_config_mix_ext_usecase(
                    aidl, false /*isInput*/);
        case media::AudioPortRole::SINK:
            return aidl2legacy_AudioPortMixExtUseCase_audio_port_config_mix_ext_usecase(
                    aidl, true /*isInput*/);
    }
    LOG_ALWAYS_FATAL("Shouldn't get here"); // with -Werror,-Wswitch may compile-time fail
}

ConversionResult<AudioPortMixExtUseCase> legacy2aidl_AudioPortMixExtUseCase(
        const audio_port_config_mix_ext_usecase& legacy, audio_port_role_t role) {
    switch (role) {
        case AUDIO_PORT_ROLE_NONE: {
            AudioPortMixExtUseCase aidl;
            UNION_SET(aidl, unspecified, false);
            return aidl;
        }
        case AUDIO_PORT_ROLE_SOURCE:
            return legacy2aidl_audio_port_config_mix_ext_usecase_AudioPortMixExtUseCase(
                    legacy, false /*isInput*/);
        case AUDIO_PORT_ROLE_SINK:
            return legacy2aidl_audio_port_config_mix_ext_usecase_AudioPortMixExtUseCase(
                    legacy, true /*isInput*/);
    }
    LOG_ALWAYS_FATAL("Shouldn't get here"); // with -Werror,-Wswitch may compile-time fail
}

ConversionResult<audio_port_config_mix_ext> aidl2legacy_AudioPortMixExt(
        const AudioPortMixExt& aidl, media::AudioPortRole role,
        const media::AudioPortMixExtSys& aidlMixExt) {
    // Not using HAL-level 'aidl2legacy_AudioPortMixExt' as it does not support
    // 'media::AudioPortRole::NONE'.
    audio_port_config_mix_ext legacy;
    legacy.hw_module = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_module_handle_t(aidlMixExt.hwModule));
    legacy.handle = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_io_handle_t(aidl.handle));
    legacy.usecase = VALUE_OR_RETURN(aidl2legacy_AudioPortMixExtUseCase(aidl.usecase, role));
    return legacy;
}

status_t legacy2aidl_AudioPortMixExt(
        const audio_port_config_mix_ext& legacy, audio_port_role_t role,
        AudioPortMixExt* aidl, media::AudioPortMixExtSys* aidlMixExt) {
    // Not using HAL-level 'legacy2aidl_AudioPortMixExt' as it does not support
    // 'AUDIO_PORT_ROLE_NONE'.
    aidlMixExt->hwModule = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_module_handle_t_int32_t(legacy.hw_module));
    aidl->handle = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(legacy.handle));
    aidl->usecase = VALUE_OR_RETURN_STATUS(
            legacy2aidl_AudioPortMixExtUseCase(legacy.usecase, role));
    return OK;
}

ConversionResult<audio_port_config_session_ext>
aidl2legacy_int32_t_audio_port_config_session_ext(int32_t aidl) {
    audio_port_config_session_ext legacy;
    legacy.session = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_session_t(aidl));
    return legacy;
}

ConversionResult<int32_t>
legacy2aidl_audio_port_config_session_ext_int32_t(
        const audio_port_config_session_ext& legacy) {
    return legacy2aidl_audio_session_t_int32_t(legacy.session);
}

ConversionResult<audio_port_config_device_ext>
aidl2legacy_AudioPortDeviceExt_audio_port_config_device_ext(
        const AudioPortDeviceExt& aidl, const media::AudioPortDeviceExtSys& aidlDeviceExt) {
    audio_port_config_device_ext legacy = VALUE_OR_RETURN(
            aidl2legacy_AudioPortDeviceExt_audio_port_config_device_ext(aidl));
    legacy.hw_module = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_module_handle_t(aidlDeviceExt.hwModule));
    return legacy;
}

status_t legacy2aidl_audio_port_config_device_ext_AudioPortDeviceExt(
        const audio_port_config_device_ext& legacy,
        AudioPortDeviceExt* aidl, media::AudioPortDeviceExtSys* aidlDeviceExt) {
    *aidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_port_config_device_ext_AudioPortDeviceExt(legacy));
    aidlDeviceExt->hwModule = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_module_handle_t_int32_t(legacy.hw_module));
    return OK;
}

// This type is unnamed in the original definition, thus we name it here.
using audio_port_config_ext = decltype(audio_port_config::ext);

ConversionResult<audio_port_config_ext> aidl2legacy_AudioPortExt_audio_port_config_ext(
        const AudioPortExt& aidl, media::AudioPortType type,
        media::AudioPortRole role, const media::AudioPortExtSys& aidlSys) {
    // Not using HAL-level 'aidl2legacy_AudioPortExt_audio_port_config_ext' as it does not support
    // 'media::AudioPortType::SESSION'.
    audio_port_config_ext legacy;
    switch (type) {
        case media::AudioPortType::NONE:
            // Just verify that the union is empty.
            VALUE_OR_RETURN(UNION_GET(aidl, unspecified));
            return legacy;
        case media::AudioPortType::DEVICE:
            legacy.device = VALUE_OR_RETURN(
                    aidl2legacy_AudioPortDeviceExt_audio_port_config_device_ext(
                            VALUE_OR_RETURN(UNION_GET(aidl, device)),
                            VALUE_OR_RETURN(UNION_GET(aidlSys, device))));
            return legacy;
        case media::AudioPortType::MIX:
            legacy.mix = VALUE_OR_RETURN(
                    aidl2legacy_AudioPortMixExt(
                            VALUE_OR_RETURN(UNION_GET(aidl, mix)), role,
                            VALUE_OR_RETURN(UNION_GET(aidlSys, mix))));
            return legacy;
        case media::AudioPortType::SESSION:
            legacy.session = VALUE_OR_RETURN(
                    aidl2legacy_int32_t_audio_port_config_session_ext(
                            VALUE_OR_RETURN(UNION_GET(aidlSys, session))));
            return legacy;

    }
    LOG_ALWAYS_FATAL("Shouldn't get here"); // with -Werror,-Wswitch may compile-time fail
}

status_t legacy2aidl_AudioPortExt(
        const audio_port_config_ext& legacy, audio_port_type_t type, audio_port_role_t role,
        AudioPortExt* aidl, media::AudioPortExtSys* aidlSys) {
    // Not using HAL-level 'aidl2legacy_AudioPortExt_audio_port_config_ext' as it does not support
    // 'AUDIO_PORT_TYPE_SESSION'.
    switch (type) {
        case AUDIO_PORT_TYPE_NONE:
            UNION_SET(*aidl, unspecified, false);
            UNION_SET(*aidlSys, unspecified, false);
            return OK;
        case AUDIO_PORT_TYPE_DEVICE: {
            AudioPortDeviceExt device;
            media::AudioPortDeviceExtSys deviceSys;
            RETURN_STATUS_IF_ERROR(
                    legacy2aidl_audio_port_config_device_ext_AudioPortDeviceExt(
                            legacy.device, &device, &deviceSys));
            UNION_SET(*aidl, device, device);
            UNION_SET(*aidlSys, device, deviceSys);
            return OK;
        }
        case AUDIO_PORT_TYPE_MIX: {
            AudioPortMixExt mix;
            media::AudioPortMixExtSys mixSys;
            RETURN_STATUS_IF_ERROR(legacy2aidl_AudioPortMixExt(legacy.mix, role, &mix, &mixSys));
            UNION_SET(*aidl, mix, mix);
            UNION_SET(*aidlSys, mix, mixSys);
            return OK;
        }
        case AUDIO_PORT_TYPE_SESSION:
            UNION_SET(*aidl, unspecified, false);
            UNION_SET(*aidlSys, session, VALUE_OR_RETURN_STATUS(
                            legacy2aidl_audio_port_config_session_ext_int32_t(legacy.session)));
            return OK;
    }
    LOG_ALWAYS_FATAL("Shouldn't get here"); // with -Werror,-Wswitch may compile-time fail
}

ConversionResult<audio_port_config> aidl2legacy_AudioPortConfigFw_audio_port_config(
        const media::AudioPortConfigFw& aidl, int32_t* aidlPortId) {
    const bool isInput = VALUE_OR_RETURN(
            portDirection(aidl.sys.role, aidl.sys.type)) == AudioPortDirection::INPUT;
    audio_port_config legacy;
    int32_t aidlPortIdHolder;
    RETURN_IF_ERROR(aidl2legacy_AudioPortConfig_audio_port_config(
                    aidl.hal, isInput, &legacy, &aidlPortIdHolder));
    if (aidlPortId != nullptr) *aidlPortId = aidlPortIdHolder;
    legacy.role = VALUE_OR_RETURN(aidl2legacy_AudioPortRole_audio_port_role_t(aidl.sys.role));
    legacy.type = VALUE_OR_RETURN(aidl2legacy_AudioPortType_audio_port_type_t(aidl.sys.type));
    legacy.ext = VALUE_OR_RETURN(
            aidl2legacy_AudioPortExt_audio_port_config_ext(
                    aidl.hal.ext, aidl.sys.type, aidl.sys.role, aidl.sys.ext));
    return legacy;
}

ConversionResult<media::AudioPortConfigFw> legacy2aidl_audio_port_config_AudioPortConfigFw(
        const audio_port_config& legacy, int32_t portId) {
    const bool isInput = VALUE_OR_RETURN(
            portDirection(legacy.role, legacy.type)) == AudioPortDirection::INPUT;
    media::AudioPortConfigFw aidl;
    aidl.hal = VALUE_OR_RETURN(
            legacy2aidl_audio_port_config_AudioPortConfig(legacy, isInput, portId));
    aidl.sys.role = VALUE_OR_RETURN(legacy2aidl_audio_port_role_t_AudioPortRole(legacy.role));
    aidl.sys.type = VALUE_OR_RETURN(legacy2aidl_audio_port_type_t_AudioPortType(legacy.type));
    RETURN_IF_ERROR(legacy2aidl_AudioPortExt(legacy.ext, legacy.type, legacy.role,
                    &aidl.hal.ext, &aidl.sys.ext));
    return aidl;
}

ConversionResult<struct audio_patch> aidl2legacy_AudioPatchFw_audio_patch(
        const media::AudioPatchFw& aidl) {
    struct audio_patch legacy;
    legacy.id = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_patch_handle_t(aidl.id));
    legacy.num_sinks = VALUE_OR_RETURN(convertIntegral<unsigned int>(aidl.sinks.size()));
    if (legacy.num_sinks > AUDIO_PATCH_PORTS_MAX) {
        return unexpected(BAD_VALUE);
    }
    for (size_t i = 0; i < legacy.num_sinks; ++i) {
        legacy.sinks[i] =
                VALUE_OR_RETURN(aidl2legacy_AudioPortConfigFw_audio_port_config(aidl.sinks[i]));
    }
    legacy.num_sources = VALUE_OR_RETURN(convertIntegral<unsigned int>(aidl.sources.size()));
    if (legacy.num_sources > AUDIO_PATCH_PORTS_MAX) {
        return unexpected(BAD_VALUE);
    }
    for (size_t i = 0; i < legacy.num_sources; ++i) {
        legacy.sources[i] =
                VALUE_OR_RETURN(aidl2legacy_AudioPortConfigFw_audio_port_config(aidl.sources[i]));
    }
    return legacy;
}

ConversionResult<media::AudioPatchFw> legacy2aidl_audio_patch_AudioPatchFw(
        const struct audio_patch& legacy) {
    media::AudioPatchFw aidl;
    aidl.id = VALUE_OR_RETURN(legacy2aidl_audio_patch_handle_t_int32_t(legacy.id));

    if (legacy.num_sinks > AUDIO_PATCH_PORTS_MAX) {
        return unexpected(BAD_VALUE);
    }
    for (unsigned int i = 0; i < legacy.num_sinks; ++i) {
        aidl.sinks.push_back(
                VALUE_OR_RETURN(legacy2aidl_audio_port_config_AudioPortConfigFw(legacy.sinks[i])));
    }
    if (legacy.num_sources > AUDIO_PATCH_PORTS_MAX) {
        return unexpected(BAD_VALUE);
    }
    for (unsigned int i = 0; i < legacy.num_sources; ++i) {
        aidl.sources.push_back(
                VALUE_OR_RETURN(legacy2aidl_audio_port_config_AudioPortConfigFw(legacy.sources[i])));
    }
    return aidl;
}

ConversionResult<sp<AudioIoDescriptor>> aidl2legacy_AudioIoDescriptor_AudioIoDescriptor(
        const media::AudioIoDescriptor& aidl) {
    const audio_io_handle_t io_handle = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_io_handle_t(aidl.ioHandle));
    const struct audio_patch patch = VALUE_OR_RETURN(
            aidl2legacy_AudioPatchFw_audio_patch(aidl.patch));
    const bool isInput = aidl.isInput;
    const uint32_t sampling_rate = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.samplingRate));
    const audio_format_t format = VALUE_OR_RETURN(
            aidl2legacy_AudioFormatDescription_audio_format_t(aidl.format));
    const audio_channel_mask_t channel_mask = VALUE_OR_RETURN(
            aidl2legacy_AudioChannelLayout_audio_channel_mask_t(aidl.channelMask, isInput));
    const size_t frame_count = VALUE_OR_RETURN(convertIntegral<size_t>(aidl.frameCount));
    const size_t frame_count_hal = VALUE_OR_RETURN(convertIntegral<size_t>(aidl.frameCountHAL));
    const uint32_t latency = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.latency));
    const audio_port_handle_t port_id = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_port_handle_t(aidl.portId));
    return sp<AudioIoDescriptor>::make(io_handle, patch, isInput, sampling_rate, format,
            channel_mask, frame_count, frame_count_hal, latency, port_id);
}

ConversionResult<media::AudioIoDescriptor> legacy2aidl_AudioIoDescriptor_AudioIoDescriptor(
        const sp<AudioIoDescriptor>& legacy) {
    media::AudioIoDescriptor aidl;
    aidl.ioHandle = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(legacy->getIoHandle()));
    aidl.patch = VALUE_OR_RETURN(legacy2aidl_audio_patch_AudioPatchFw(legacy->getPatch()));
    aidl.isInput = legacy->getIsInput();
    aidl.samplingRate = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy->getSamplingRate()));
    aidl.format = VALUE_OR_RETURN(
            legacy2aidl_audio_format_t_AudioFormatDescription(legacy->getFormat()));
    aidl.channelMask = VALUE_OR_RETURN(legacy2aidl_audio_channel_mask_t_AudioChannelLayout(
                    legacy->getChannelMask(), legacy->getIsInput()));
    aidl.frameCount = VALUE_OR_RETURN(convertIntegral<int64_t>(legacy->getFrameCount()));
    aidl.frameCountHAL = VALUE_OR_RETURN(convertIntegral<int64_t>(legacy->getFrameCountHAL()));
    aidl.latency = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy->getLatency()));
    aidl.portId = VALUE_OR_RETURN(legacy2aidl_audio_port_handle_t_int32_t(legacy->getPortId()));
    return aidl;
}

ConversionResult<AudioClient> aidl2legacy_AudioClient_AudioClient(
        const media::AudioClient& aidl) {
    AudioClient legacy;
    legacy.clientTid = VALUE_OR_RETURN(aidl2legacy_int32_t_pid_t(aidl.clientTid));
    legacy.attributionSource = aidl.attributionSource;
    return legacy;
}

ConversionResult<media::AudioClient> legacy2aidl_AudioClient_AudioClient(
        const AudioClient& legacy) {
    media::AudioClient aidl;
    aidl.clientTid = VALUE_OR_RETURN(legacy2aidl_pid_t_int32_t(legacy.clientTid));
    aidl.attributionSource = legacy.attributionSource;
    return aidl;
}

ConversionResult<sp<IMemory>>
aidl2legacy_SharedFileRegion_IMemory(const media::SharedFileRegion& aidl) {
    sp<IMemory> legacy;
    if (!convertSharedFileRegionToIMemory(aidl, &legacy)) {
        return unexpected(BAD_VALUE);
    }
    return legacy;
}

ConversionResult<media::SharedFileRegion>
legacy2aidl_IMemory_SharedFileRegion(const sp<IMemory>& legacy) {
    media::SharedFileRegion aidl;
    if (!convertIMemoryToSharedFileRegion(legacy, &aidl)) {
        return unexpected(BAD_VALUE);
    }
    return aidl;
}

ConversionResult<sp<IMemory>> aidl2legacy_NullableSharedFileRegion_IMemory(
        const std::optional<media::SharedFileRegion>& aidl) {
    sp<IMemory> legacy;
    if (!convertNullableSharedFileRegionToIMemory(aidl, &legacy)) {
        return unexpected(BAD_VALUE);
    }
    return legacy;
}

ConversionResult<std::optional<media::SharedFileRegion>>
legacy2aidl_NullableIMemory_SharedFileRegion(const sp<IMemory>& legacy) {
    std::optional<media::SharedFileRegion> aidl;
    if (!convertNullableIMemoryToSharedFileRegion(legacy, &aidl)) {
        return unexpected(BAD_VALUE);
    }
    return aidl;
}

ConversionResult<AudioTimestamp>
aidl2legacy_AudioTimestampInternal_AudioTimestamp(const media::AudioTimestampInternal& aidl) {
    AudioTimestamp legacy;
    legacy.mPosition = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.position));
    legacy.mTime.tv_sec = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.sec));
    legacy.mTime.tv_nsec = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.nsec));
    return legacy;
}

ConversionResult<media::AudioTimestampInternal>
legacy2aidl_AudioTimestamp_AudioTimestampInternal(const AudioTimestamp& legacy) {
    media::AudioTimestampInternal aidl;
    aidl.position = VALUE_OR_RETURN(convertIntegral<int64_t>(legacy.mPosition));
    aidl.sec = VALUE_OR_RETURN(convertIntegral<int64_t>(legacy.mTime.tv_sec));
    aidl.nsec = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.mTime.tv_nsec));
    return aidl;
}

ConversionResult<effect_descriptor_t>
aidl2legacy_EffectDescriptor_effect_descriptor_t(const media::EffectDescriptor& aidl) {
    effect_descriptor_t legacy;
    legacy.type = VALUE_OR_RETURN(aidl2legacy_AudioUuid_audio_uuid_t(aidl.type));
    legacy.uuid = VALUE_OR_RETURN(aidl2legacy_AudioUuid_audio_uuid_t(aidl.uuid));
    legacy.apiVersion = VALUE_OR_RETURN(convertReinterpret<uint32_t>(aidl.apiVersion));
    legacy.flags = VALUE_OR_RETURN(convertReinterpret<uint32_t>(aidl.flags));
    legacy.cpuLoad = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.cpuLoad));
    legacy.memoryUsage = VALUE_OR_RETURN(convertIntegral<uint16_t>(aidl.memoryUsage));
    RETURN_IF_ERROR(aidl2legacy_string(aidl.name, legacy.name, sizeof(legacy.name)));
    RETURN_IF_ERROR(
            aidl2legacy_string(aidl.implementor, legacy.implementor, sizeof(legacy.implementor)));
    return legacy;
}

ConversionResult<media::EffectDescriptor>
legacy2aidl_effect_descriptor_t_EffectDescriptor(const effect_descriptor_t& legacy) {
    media::EffectDescriptor aidl;
    aidl.type = VALUE_OR_RETURN(legacy2aidl_audio_uuid_t_AudioUuid(legacy.type));
    aidl.uuid = VALUE_OR_RETURN(legacy2aidl_audio_uuid_t_AudioUuid(legacy.uuid));
    aidl.apiVersion = VALUE_OR_RETURN(convertReinterpret<int32_t>(legacy.apiVersion));
    aidl.flags = VALUE_OR_RETURN(convertReinterpret<int32_t>(legacy.flags));
    aidl.cpuLoad = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.cpuLoad));
    aidl.memoryUsage = VALUE_OR_RETURN(convertIntegral<int32_t>(legacy.memoryUsage));
    aidl.name = VALUE_OR_RETURN(legacy2aidl_string(legacy.name, sizeof(legacy.name)));
    aidl.implementor = VALUE_OR_RETURN(
            legacy2aidl_string(legacy.implementor, sizeof(legacy.implementor)));
    return aidl;
}

ConversionResult<audio_port_mix_ext>
aidl2legacy_AudioPortMixExt_audio_port_mix_ext(
        const AudioPortMixExt& aidl, const media::AudioPortMixExtSys& aidlSys) {
    audio_port_mix_ext legacy = VALUE_OR_RETURN(
            aidl2legacy_AudioPortMixExt_audio_port_mix_ext(aidl));
    legacy.hw_module = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_module_handle_t(aidlSys.hwModule));
    return legacy;
}

status_t
legacy2aidl_audio_port_mix_ext_AudioPortMixExt(const audio_port_mix_ext& legacy,
        AudioPortMixExt* aidl, media::AudioPortMixExtSys* aidlMixExt) {
    *aidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_port_mix_ext_AudioPortMixExt(legacy));
    aidlMixExt->hwModule = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_module_handle_t_int32_t(legacy.hw_module));
    return OK;
}

ConversionResult<audio_port_session_ext>
aidl2legacy_int32_t_audio_port_session_ext(int32_t aidl) {
    audio_port_session_ext legacy;
    legacy.session = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_session_t(aidl));
    return legacy;
}

ConversionResult<int32_t>
legacy2aidl_audio_port_session_ext_int32_t(const audio_port_session_ext& legacy) {
    return legacy2aidl_audio_session_t_int32_t(legacy.session);
}

ConversionResult<audio_port_device_ext>
aidl2legacy_AudioPortDeviceExt_audio_port_device_ext(
        const AudioPortDeviceExt& aidl, const media::AudioPortDeviceExtSys& aidlSys) {
    audio_port_device_ext legacy = VALUE_OR_RETURN(
            aidl2legacy_AudioPortDeviceExt_audio_port_device_ext(aidl));
    legacy.hw_module = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_module_handle_t(aidlSys.hwModule));
    return legacy;
}

status_t legacy2aidl_audio_port_device_ext_AudioPortDeviceExt(
        const audio_port_device_ext& legacy,
        AudioPortDeviceExt* aidl, media::AudioPortDeviceExtSys* aidlDeviceExt) {
    *aidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_port_device_ext_AudioPortDeviceExt(legacy));
    aidlDeviceExt->hwModule = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_module_handle_t_int32_t(legacy.hw_module));
    return OK;
}

// This type is unnamed in the original definition, thus we name it here.
using audio_port_v7_ext = decltype(audio_port_v7::ext);

ConversionResult<audio_port_v7_ext> aidl2legacy_AudioPortExt_audio_port_v7_ext(
        const AudioPortExt& aidl, media::AudioPortType type,
        const media::AudioPortExtSys& aidlSys) {
    audio_port_v7_ext legacy;
    switch (type) {
        case media::AudioPortType::NONE:
            // Just verify that the union is empty.
            VALUE_OR_RETURN(UNION_GET(aidl, unspecified));
            return legacy;
        case media::AudioPortType::DEVICE:
            legacy.device = VALUE_OR_RETURN(
                    aidl2legacy_AudioPortDeviceExt_audio_port_device_ext(
                            VALUE_OR_RETURN(UNION_GET(aidl, device)),
                            VALUE_OR_RETURN(UNION_GET(aidlSys, device))));
            return legacy;
        case media::AudioPortType::MIX:
            legacy.mix = VALUE_OR_RETURN(
                    aidl2legacy_AudioPortMixExt_audio_port_mix_ext(
                            VALUE_OR_RETURN(UNION_GET(aidl, mix)),
                            VALUE_OR_RETURN(UNION_GET(aidlSys, mix))));
            return legacy;
        case media::AudioPortType::SESSION:
            legacy.session = VALUE_OR_RETURN(
                    aidl2legacy_int32_t_audio_port_session_ext(
                            VALUE_OR_RETURN(UNION_GET(aidlSys, session))));
            return legacy;

    }
    LOG_ALWAYS_FATAL("Shouldn't get here"); // with -Werror,-Wswitch may compile-time fail
}

status_t legacy2aidl_AudioPortExt(
        const audio_port_v7_ext& legacy, audio_port_type_t type,
        AudioPortExt* aidl, media::AudioPortExtSys* aidlSys) {
    switch (type) {
        case AUDIO_PORT_TYPE_NONE:
            UNION_SET(*aidl, unspecified, false);
            UNION_SET(*aidlSys, unspecified, false);
            return OK;
        case AUDIO_PORT_TYPE_DEVICE: {
            AudioPortDeviceExt device;
            media::AudioPortDeviceExtSys deviceSys;
            RETURN_STATUS_IF_ERROR(
                    legacy2aidl_audio_port_device_ext_AudioPortDeviceExt(
                            legacy.device, &device, &deviceSys));
            UNION_SET(*aidl, device, device);
            UNION_SET(*aidlSys, device, deviceSys);
            return OK;
        }
        case AUDIO_PORT_TYPE_MIX: {
            AudioPortMixExt mix;
            media::AudioPortMixExtSys mixSys;
            RETURN_STATUS_IF_ERROR(
                    legacy2aidl_audio_port_mix_ext_AudioPortMixExt(
                            legacy.mix, &mix, &mixSys));
            UNION_SET(*aidl, mix, mix);
            UNION_SET(*aidlSys, mix, mixSys);
            return OK;
        }
        case AUDIO_PORT_TYPE_SESSION:
            UNION_SET(*aidl, unspecified, false);
            UNION_SET(*aidlSys, session, VALUE_OR_RETURN_STATUS(
                            legacy2aidl_audio_port_session_ext_int32_t(legacy.session)));
            return OK;
    }
    LOG_ALWAYS_FATAL("Shouldn't get here"); // with -Werror,-Wswitch may compile-time fail
}

ConversionResult<audio_port_v7>
aidl2legacy_AudioPortFw_audio_port_v7(const media::AudioPortFw& aidl) {
    const bool isInput = VALUE_OR_RETURN(
            portDirection(aidl.sys.role, aidl.sys.type)) == AudioPortDirection::INPUT;
    audio_port_v7 legacy = VALUE_OR_RETURN(aidl2legacy_AudioPort_audio_port_v7(aidl.hal, isInput));
    legacy.role = VALUE_OR_RETURN(aidl2legacy_AudioPortRole_audio_port_role_t(aidl.sys.role));
    legacy.type = VALUE_OR_RETURN(aidl2legacy_AudioPortType_audio_port_type_t(aidl.sys.type));

    legacy.active_config = VALUE_OR_RETURN(
            aidl2legacy_AudioPortConfigFw_audio_port_config(aidl.sys.activeConfig));
    legacy.ext = VALUE_OR_RETURN(
            aidl2legacy_AudioPortExt_audio_port_v7_ext(aidl.hal.ext, aidl.sys.type, aidl.sys.ext));
    return legacy;
}

ConversionResult<media::AudioPortFw>
legacy2aidl_audio_port_v7_AudioPortFw(const audio_port_v7& legacy) {
    const bool isInput = VALUE_OR_RETURN(
            portDirection(legacy.role, legacy.type)) == AudioPortDirection::INPUT;
    media::AudioPortFw aidl;
    aidl.hal = VALUE_OR_RETURN(legacy2aidl_audio_port_v7_AudioPort(legacy, isInput));
    aidl.sys.role = VALUE_OR_RETURN(legacy2aidl_audio_port_role_t_AudioPortRole(legacy.role));
    aidl.sys.type = VALUE_OR_RETURN(legacy2aidl_audio_port_type_t_AudioPortType(legacy.type));
    // These get filled by the call to 'legacy2aidl_AudioPortExt' below.
    aidl.sys.profiles.resize(legacy.num_audio_profiles);
    aidl.sys.gains.resize(legacy.num_gains);
    aidl.sys.activeConfig = VALUE_OR_RETURN(
            legacy2aidl_audio_port_config_AudioPortConfigFw(legacy.active_config, legacy.id));
    aidl.sys.activeConfig.hal.portId = aidl.hal.id;
    RETURN_IF_ERROR(
            legacy2aidl_AudioPortExt(legacy.ext, legacy.type, &aidl.hal.ext, &aidl.sys.ext));
    return aidl;
}

ConversionResult<audio_unique_id_use_t>
aidl2legacy_AudioUniqueIdUse_audio_unique_id_use_t(media::AudioUniqueIdUse aidl) {
    switch (aidl) {
        case media::AudioUniqueIdUse::UNSPECIFIED:
            return AUDIO_UNIQUE_ID_USE_UNSPECIFIED;
        case media::AudioUniqueIdUse::SESSION:
            return AUDIO_UNIQUE_ID_USE_SESSION;
        case media::AudioUniqueIdUse::MODULE:
            return AUDIO_UNIQUE_ID_USE_MODULE;
        case media::AudioUniqueIdUse::EFFECT:
            return AUDIO_UNIQUE_ID_USE_EFFECT;
        case media::AudioUniqueIdUse::PATCH:
            return AUDIO_UNIQUE_ID_USE_PATCH;
        case media::AudioUniqueIdUse::OUTPUT:
            return AUDIO_UNIQUE_ID_USE_OUTPUT;
        case media::AudioUniqueIdUse::INPUT:
            return AUDIO_UNIQUE_ID_USE_INPUT;
        case media::AudioUniqueIdUse::CLIENT:
            return AUDIO_UNIQUE_ID_USE_CLIENT;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<media::AudioUniqueIdUse>
legacy2aidl_audio_unique_id_use_t_AudioUniqueIdUse(audio_unique_id_use_t legacy) {
    switch (legacy) {
        case AUDIO_UNIQUE_ID_USE_UNSPECIFIED:
            return media::AudioUniqueIdUse::UNSPECIFIED;
        case AUDIO_UNIQUE_ID_USE_SESSION:
            return media::AudioUniqueIdUse::SESSION;
        case AUDIO_UNIQUE_ID_USE_MODULE:
            return media::AudioUniqueIdUse::MODULE;
        case AUDIO_UNIQUE_ID_USE_EFFECT:
            return media::AudioUniqueIdUse::EFFECT;
        case AUDIO_UNIQUE_ID_USE_PATCH:
            return media::AudioUniqueIdUse::PATCH;
        case AUDIO_UNIQUE_ID_USE_OUTPUT:
            return media::AudioUniqueIdUse::OUTPUT;
        case AUDIO_UNIQUE_ID_USE_INPUT:
            return media::AudioUniqueIdUse::INPUT;
        case AUDIO_UNIQUE_ID_USE_CLIENT:
            return media::AudioUniqueIdUse::CLIENT;
        case AUDIO_UNIQUE_ID_USE_MAX:
            break;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<volume_group_t>
aidl2legacy_int32_t_volume_group_t(int32_t aidl) {
    return convertReinterpret<volume_group_t>(aidl);
}

ConversionResult<int32_t>
legacy2aidl_volume_group_t_int32_t(volume_group_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<product_strategy_t>
aidl2legacy_int32_t_product_strategy_t(int32_t aidl) {
    return convertReinterpret<product_strategy_t>(aidl);
}

ConversionResult<int32_t>
legacy2aidl_product_strategy_t_int32_t(product_strategy_t legacy) {
    return convertReinterpret<int32_t>(legacy);
}

ConversionResult<TrackSecondaryOutputInfoPair>
aidl2legacy_TrackSecondaryOutputInfo_TrackSecondaryOutputInfoPair(
        const media::TrackSecondaryOutputInfo& aidl) {
    TrackSecondaryOutputInfoPair trackSecondaryOutputInfoPair;
    trackSecondaryOutputInfoPair.first =
            VALUE_OR_RETURN(aidl2legacy_int32_t_audio_port_handle_t(aidl.portId));
    trackSecondaryOutputInfoPair.second =
            VALUE_OR_RETURN(convertContainer<std::vector<audio_port_handle_t>>(
                    aidl.secondaryOutputIds, aidl2legacy_int32_t_audio_io_handle_t));
    return trackSecondaryOutputInfoPair;
}

ConversionResult<media::TrackSecondaryOutputInfo>
legacy2aidl_TrackSecondaryOutputInfoPair_TrackSecondaryOutputInfo(
        const TrackSecondaryOutputInfoPair& legacy) {
    media::TrackSecondaryOutputInfo trackSecondaryOutputInfo;
    trackSecondaryOutputInfo.portId =
            VALUE_OR_RETURN(legacy2aidl_audio_port_handle_t_int32_t(legacy.first));
    trackSecondaryOutputInfo.secondaryOutputIds =
            VALUE_OR_RETURN(convertContainer<std::vector<int32_t>>(
                    legacy.second, legacy2aidl_audio_io_handle_t_int32_t));
    return trackSecondaryOutputInfo;
}

ConversionResult<audio_direct_mode_t>
aidl2legacy_AudioDirectMode_audio_direct_mode_t(media::AudioDirectMode aidl) {
    switch (aidl) {
        case media::AudioDirectMode::NONE:
            return AUDIO_DIRECT_NOT_SUPPORTED;
        case media::AudioDirectMode::OFFLOAD:
            return AUDIO_DIRECT_OFFLOAD_SUPPORTED;
        case media::AudioDirectMode::OFFLOAD_GAPLESS:
            return AUDIO_DIRECT_OFFLOAD_GAPLESS_SUPPORTED;
        case media::AudioDirectMode::BITSTREAM:
            return AUDIO_DIRECT_BITSTREAM_SUPPORTED;
    }
    return unexpected(BAD_VALUE);
}
ConversionResult<media::AudioDirectMode>
legacy2aidl_audio_direct_mode_t_AudioDirectMode(audio_direct_mode_t legacy) {
    switch (legacy) {
        case AUDIO_DIRECT_NOT_SUPPORTED:
            return media::AudioDirectMode::NONE;
        case AUDIO_DIRECT_OFFLOAD_SUPPORTED:
            return media::AudioDirectMode::OFFLOAD;
        case AUDIO_DIRECT_OFFLOAD_GAPLESS_SUPPORTED:
            return media::AudioDirectMode::OFFLOAD_GAPLESS;
        case AUDIO_DIRECT_BITSTREAM_SUPPORTED:
            return media::AudioDirectMode::BITSTREAM;
    }
    return unexpected(BAD_VALUE);
}

ConversionResult<audio_direct_mode_t> aidl2legacy_int32_t_audio_direct_mode_t_mask(int32_t aidl) {
    using LegacyMask = std::underlying_type_t<audio_direct_mode_t>;

    LegacyMask converted = VALUE_OR_RETURN(
            (convertBitmask<LegacyMask, int32_t, audio_direct_mode_t, media::AudioDirectMode>(
                    aidl, aidl2legacy_AudioDirectMode_audio_direct_mode_t,
                    indexToEnum_index<media::AudioDirectMode>,
                    enumToMask_bitmask<LegacyMask, audio_direct_mode_t>)));
    return static_cast<audio_direct_mode_t>(converted);
}
ConversionResult<int32_t> legacy2aidl_audio_direct_mode_t_int32_t_mask(audio_direct_mode_t legacy) {
    using LegacyMask = std::underlying_type_t<audio_direct_mode_t>;

    LegacyMask legacyMask = static_cast<LegacyMask>(legacy);
    return convertBitmask<int32_t, LegacyMask, media::AudioDirectMode, audio_direct_mode_t>(
            legacyMask, legacy2aidl_audio_direct_mode_t_AudioDirectMode,
            indexToEnum_bitmask<audio_direct_mode_t>,
            enumToMask_index<int32_t, media::AudioDirectMode>);
}

ConversionResult<audio_microphone_characteristic_t>
aidl2legacy_MicrophoneInfoFw_audio_microphone_characteristic_t(
        const media::MicrophoneInfoFw& aidl) {
    audio_microphone_characteristic_t legacy =
            VALUE_OR_RETURN(aidl2legacy_MicrophoneInfos_audio_microphone_characteristic_t(
                            aidl.info, aidl.dynamic));
    legacy.id = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_port_handle_t(aidl.portId));
    return legacy;
}
ConversionResult<media::MicrophoneInfoFw>
legacy2aidl_audio_microphone_characteristic_t_MicrophoneInfoFw(
        const audio_microphone_characteristic_t& legacy) {
    media::MicrophoneInfoFw aidl;
    RETURN_IF_ERROR(legacy2aidl_audio_microphone_characteristic_t_MicrophoneInfos(
                    legacy, &aidl.info, &aidl.dynamic));
    aidl.portId = VALUE_OR_RETURN(legacy2aidl_audio_port_handle_t_int32_t(legacy.id));
    return aidl;
}

}  // namespace android
