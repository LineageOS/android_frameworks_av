/*
 * Copyright (C) 2009 The Android Open Source Project
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

#define LOG_TAG "AudioPolicyClientImpl"
//#define LOG_NDEBUG 0

#include "AudioPolicyService.h"

#include <utils/Log.h>

#include "BinderProxy.h"

namespace android {

/* implementation of the client interface from the policy manager */

audio_module_handle_t AudioPolicyService::AudioPolicyClient::loadHwModule(const char *name)
{
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == 0) {
        ALOGW("%s: could not get AudioFlinger", __func__);
        return AUDIO_MODULE_HANDLE_NONE;
    }

    return af->loadHwModule(name);
}

status_t AudioPolicyService::AudioPolicyClient::openOutput(audio_module_handle_t module,
                                                           audio_io_handle_t *output,
                                                           audio_config_t *halConfig,
                                                           audio_config_base_t *mixerConfig,
                                                           const sp<DeviceDescriptorBase>& device,
                                                           uint32_t *latencyMs,
                                                           audio_output_flags_t flags)
{
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == 0) {
        ALOGW("%s: could not get AudioFlinger", __func__);
        return PERMISSION_DENIED;
    }

    media::OpenOutputRequest request;
    media::OpenOutputResponse response;

    request.module = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_module_handle_t_int32_t(module));
    request.halConfig = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_config_t_AudioConfig(*halConfig, false /*isInput*/));
    request.mixerConfig = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_config_base_t_AudioConfigBase(*mixerConfig, false /*isInput*/));
    request.device = VALUE_OR_RETURN_STATUS(legacy2aidl_DeviceDescriptorBase(device));
    request.flags = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_output_flags_t_int32_t_mask(flags));

    status_t status = af->openOutput(request, &response);
    if (status == OK) {
        *output = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_io_handle_t(response.output));
        *halConfig = VALUE_OR_RETURN_STATUS(
                aidl2legacy_AudioConfig_audio_config_t(response.config, false /*isInput*/));
        *latencyMs = VALUE_OR_RETURN_STATUS(convertIntegral<uint32_t>(response.latencyMs));
    }
    return status;
}

audio_io_handle_t AudioPolicyService::AudioPolicyClient::openDuplicateOutput(
                                                                audio_io_handle_t output1,
                                                                audio_io_handle_t output2)
{
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == 0) {
        ALOGW("%s: could not get AudioFlinger", __func__);
        return 0;
    }
    return af->openDuplicateOutput(output1, output2);
}

status_t AudioPolicyService::AudioPolicyClient::closeOutput(audio_io_handle_t output)
{
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == 0) {
        return PERMISSION_DENIED;
    }

    return af->closeOutput(output);
}

status_t AudioPolicyService::AudioPolicyClient::suspendOutput(audio_io_handle_t output)
{
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == 0) {
        ALOGW("%s: could not get AudioFlinger", __func__);
        return PERMISSION_DENIED;
    }

    return af->suspendOutput(output);
}

status_t AudioPolicyService::AudioPolicyClient::restoreOutput(audio_io_handle_t output)
{
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == 0) {
        ALOGW("%s: could not get AudioFlinger", __func__);
        return PERMISSION_DENIED;
    }

    return af->restoreOutput(output);
}

status_t AudioPolicyService::AudioPolicyClient::openInput(audio_module_handle_t module,
                                                          audio_io_handle_t *input,
                                                          audio_config_t *config,
                                                          audio_devices_t *device,
                                                          const String8& address,
                                                          audio_source_t source,
                                                          audio_input_flags_t flags)
{
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == 0) {
        ALOGW("%s: could not get AudioFlinger", __func__);
        return PERMISSION_DENIED;
    }

    AudioDeviceTypeAddr deviceTypeAddr(*device, address.c_str());

    media::OpenInputRequest request;
    request.module = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_module_handle_t_int32_t(module));
    request.input = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(*input));
    request.config = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_config_t_AudioConfig(*config, true /*isInput*/));
    request.device = VALUE_OR_RETURN_STATUS(legacy2aidl_AudioDeviceTypeAddress(deviceTypeAddr));
    request.source = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_source_t_AudioSource(source));
    request.flags = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_input_flags_t_int32_t_mask(flags));

    media::OpenInputResponse response;
    status_t status = af->openInput(request, &response);
    if (status == OK) {
        *input = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_module_handle_t(response.input));
    }
    return status;
}

status_t AudioPolicyService::AudioPolicyClient::closeInput(audio_io_handle_t input)
{
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == 0) {
        return PERMISSION_DENIED;
    }

    return af->closeInput(input);
}

status_t AudioPolicyService::AudioPolicyClient::setStreamVolume(audio_stream_type_t stream,
                     float volume, audio_io_handle_t output,
                     int delay_ms)
{
    return mAudioPolicyService->setStreamVolume(stream, volume, output,
                                               delay_ms);
}

status_t AudioPolicyService::AudioPolicyClient::invalidateStream(audio_stream_type_t stream)
{
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == 0) {
        return PERMISSION_DENIED;
    }

    return af->invalidateStream(stream);
}

void AudioPolicyService::AudioPolicyClient::setParameters(audio_io_handle_t io_handle,
                   const String8& keyValuePairs,
                   int delay_ms)
{
    mAudioPolicyService->setParameters(io_handle, keyValuePairs.string(), delay_ms);
}

String8 AudioPolicyService::AudioPolicyClient::getParameters(audio_io_handle_t io_handle,
                      const String8& keys)
{
    String8 result = AudioSystem::getParameters(io_handle, keys);
    return result;
}

status_t AudioPolicyService::AudioPolicyClient::setVoiceVolume(float volume, int delay_ms)
{
    return mAudioPolicyService->setVoiceVolume(volume, delay_ms);
}

status_t AudioPolicyService::AudioPolicyClient::moveEffects(audio_session_t session,
                        audio_io_handle_t src_output,
                        audio_io_handle_t dst_output)
{
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == 0) {
        return PERMISSION_DENIED;
    }

    return af->moveEffects(session, src_output, dst_output);
}

void AudioPolicyService::AudioPolicyClient::setEffectSuspended(int effectId,
                                audio_session_t sessionId,
                                bool suspended)
{
    mAudioPolicyService->setEffectSuspended(effectId, sessionId, suspended);
}

status_t AudioPolicyService::AudioPolicyClient::createAudioPatch(const struct audio_patch *patch,
                                                                  audio_patch_handle_t *handle,
                                                                  int delayMs)
{
    return mAudioPolicyService->clientCreateAudioPatch(patch, handle, delayMs);
}

status_t AudioPolicyService::AudioPolicyClient::releaseAudioPatch(audio_patch_handle_t handle,
                                                                  int delayMs)
{
    return mAudioPolicyService->clientReleaseAudioPatch(handle, delayMs);
}

status_t AudioPolicyService::AudioPolicyClient::setAudioPortConfig(
                                                        const struct audio_port_config *config,
                                                        int delayMs)
{
    return mAudioPolicyService->clientSetAudioPortConfig(config, delayMs);
}

void AudioPolicyService::AudioPolicyClient::onAudioPortListUpdate()
{
    mAudioPolicyService->onAudioPortListUpdate();
}

void AudioPolicyService::AudioPolicyClient::onAudioPatchListUpdate()
{
    mAudioPolicyService->onAudioPatchListUpdate();
}

void AudioPolicyService::AudioPolicyClient::onDynamicPolicyMixStateUpdate(
        String8 regId, int32_t state)
{
    mAudioPolicyService->onDynamicPolicyMixStateUpdate(regId, state);
}

void AudioPolicyService::AudioPolicyClient::onRecordingConfigurationUpdate(
                                                    int event,
                                                    const record_client_info_t *clientInfo,
                                                    const audio_config_base_t *clientConfig,
                                                    std::vector<effect_descriptor_t> clientEffects,
                                                    const audio_config_base_t *deviceConfig,
                                                    std::vector<effect_descriptor_t> effects,
                                                    audio_patch_handle_t patchHandle,
                                                    audio_source_t source)
{
    mAudioPolicyService->onRecordingConfigurationUpdate(event, clientInfo,
            clientConfig, clientEffects, deviceConfig, effects, patchHandle, source);
}

void AudioPolicyService::AudioPolicyClient::onAudioVolumeGroupChanged(volume_group_t group,
                                                                      int flags)
{
    mAudioPolicyService->onAudioVolumeGroupChanged(group, flags);
}

void AudioPolicyService::AudioPolicyClient::onRoutingUpdated()
{
    mAudioPolicyService->onRoutingUpdated();
}

void AudioPolicyService::AudioPolicyClient::onVolumeRangeInitRequest()
{
    mAudioPolicyService->onVolumeRangeInitRequest();
}

audio_unique_id_t AudioPolicyService::AudioPolicyClient::newAudioUniqueId(audio_unique_id_use_t use)
{
    return AudioSystem::newAudioUniqueId(use);
}

void AudioPolicyService::AudioPolicyClient::setSoundTriggerCaptureState(bool active)
{
    mAudioPolicyService->mCaptureStateNotifier.setCaptureState(active);
}

status_t AudioPolicyService::AudioPolicyClient::getAudioPort(struct audio_port_v7 *port)
{
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == 0) {
        ALOGW("%s: could not get AudioFlinger", __func__);
        return PERMISSION_DENIED;
    }
    return af->getAudioPort(port);
}

status_t AudioPolicyService::AudioPolicyClient::updateSecondaryOutputs(
        const TrackSecondaryOutputsMap& trackSecondaryOutputs) {
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == nullptr) {
        ALOGW("%s: could not get AudioFlinger", __func__);
        return PERMISSION_DENIED;
    }
    return af->updateSecondaryOutputs(trackSecondaryOutputs);
}

status_t AudioPolicyService::AudioPolicyClient::setDeviceConnectedState(
        const struct audio_port_v7 *port, bool connected) {
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af == nullptr) {
        ALOGW("%s: could not get AudioFlinger", __func__);
        return PERMISSION_DENIED;
    }
    return af->setDeviceConnectedState(port, connected);
}


} // namespace android
