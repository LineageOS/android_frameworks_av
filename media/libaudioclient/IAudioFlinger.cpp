/*
**
** Copyright 2007, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define LOG_TAG "IAudioFlinger"
//#define LOG_NDEBUG 0

#include <utils/Log.h>

#include <stdint.h>
#include <sys/types.h>
#include "IAudioFlinger.h"
#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <system/thread_defs.h>

namespace android {

using aidl_utils::statusTFromBinderStatus;
using binder::Status;
using media::audio::common::AudioChannelLayout;
using media::audio::common::AudioFormatDescription;
using media::audio::common::AudioMMapPolicyInfo;
using media::audio::common::AudioMMapPolicyType;
using media::audio::common::AudioMode;
using media::audio::common::AudioStreamType;
using media::audio::common::AudioUuid;

#define MAX_ITEMS_PER_LIST 1024

#define VALUE_OR_RETURN_BINDER(x)                                 \
    ({                                                            \
       auto _tmp = (x);                                           \
       if (!_tmp.ok()) return Status::fromStatusT(_tmp.error());  \
       std::move(_tmp.value()); \
     })

#define RETURN_BINDER_IF_ERROR(x)                         \
    {                                                     \
       auto _tmp = (x);                                   \
       if (_tmp != OK) return Status::fromStatusT(_tmp);  \
    }

ConversionResult<media::CreateTrackRequest> IAudioFlinger::CreateTrackInput::toAidl() const {
    media::CreateTrackRequest aidl;
    aidl.attr = VALUE_OR_RETURN(legacy2aidl_audio_attributes_t_AudioAttributes(attr));
    // Do not be mislead by 'Input'--this is an input to 'createTrack', which creates output tracks.
    aidl.config = VALUE_OR_RETURN(legacy2aidl_audio_config_t_AudioConfig(
                    config, false /*isInput*/));
    aidl.clientInfo = VALUE_OR_RETURN(legacy2aidl_AudioClient_AudioClient(clientInfo));
    aidl.sharedBuffer = VALUE_OR_RETURN(legacy2aidl_NullableIMemory_SharedFileRegion(sharedBuffer));
    aidl.notificationsPerBuffer = VALUE_OR_RETURN(convertIntegral<int32_t>(notificationsPerBuffer));
    aidl.speed = speed;
    aidl.audioTrackCallback = audioTrackCallback;
    aidl.flags = VALUE_OR_RETURN(legacy2aidl_audio_output_flags_t_int32_t_mask(flags));
    aidl.frameCount = VALUE_OR_RETURN(convertIntegral<int64_t>(frameCount));
    aidl.notificationFrameCount = VALUE_OR_RETURN(convertIntegral<int64_t>(notificationFrameCount));
    aidl.selectedDeviceId = VALUE_OR_RETURN(
            legacy2aidl_audio_port_handle_t_int32_t(selectedDeviceId));
    aidl.sessionId = VALUE_OR_RETURN(legacy2aidl_audio_session_t_int32_t(sessionId));
    return aidl;
}

ConversionResult<IAudioFlinger::CreateTrackInput>
IAudioFlinger::CreateTrackInput::fromAidl(const media::CreateTrackRequest& aidl) {
    IAudioFlinger::CreateTrackInput legacy;
    legacy.attr = VALUE_OR_RETURN(aidl2legacy_AudioAttributes_audio_attributes_t(aidl.attr));
    // Do not be mislead by 'Input'--this is an input to 'createTrack', which creates output tracks.
    legacy.config = VALUE_OR_RETURN(
            aidl2legacy_AudioConfig_audio_config_t(aidl.config, false /*isInput*/));
    legacy.clientInfo = VALUE_OR_RETURN(aidl2legacy_AudioClient_AudioClient(aidl.clientInfo));
    legacy.sharedBuffer = VALUE_OR_RETURN(aidl2legacy_NullableSharedFileRegion_IMemory(aidl.sharedBuffer));
    legacy.notificationsPerBuffer = VALUE_OR_RETURN(
            convertIntegral<uint32_t>(aidl.notificationsPerBuffer));
    legacy.speed = aidl.speed;
    legacy.audioTrackCallback = aidl.audioTrackCallback;
    legacy.flags = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_output_flags_t_mask(aidl.flags));
    legacy.frameCount = VALUE_OR_RETURN(convertIntegral<size_t>(aidl.frameCount));
    legacy.notificationFrameCount = VALUE_OR_RETURN(
            convertIntegral<size_t>(aidl.notificationFrameCount));
    legacy.selectedDeviceId = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_port_handle_t(aidl.selectedDeviceId));
    legacy.sessionId = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_session_t(aidl.sessionId));
    return legacy;
}

ConversionResult<media::CreateTrackResponse>
IAudioFlinger::CreateTrackOutput::toAidl() const {
    media::CreateTrackResponse aidl;
    aidl.flags = VALUE_OR_RETURN(legacy2aidl_audio_output_flags_t_int32_t_mask(flags));
    aidl.frameCount = VALUE_OR_RETURN(convertIntegral<int64_t>(frameCount));
    aidl.notificationFrameCount = VALUE_OR_RETURN(convertIntegral<int64_t>(notificationFrameCount));
    aidl.selectedDeviceId = VALUE_OR_RETURN(
            legacy2aidl_audio_port_handle_t_int32_t(selectedDeviceId));
    aidl.sessionId = VALUE_OR_RETURN(legacy2aidl_audio_session_t_int32_t(sessionId));
    aidl.sampleRate = VALUE_OR_RETURN(convertIntegral<int32_t>(sampleRate));
    aidl.streamType =  VALUE_OR_RETURN(
            legacy2aidl_audio_stream_type_t_AudioStreamType(streamType));
    aidl.afFrameCount = VALUE_OR_RETURN(convertIntegral<int64_t>(afFrameCount));
    aidl.afSampleRate = VALUE_OR_RETURN(convertIntegral<int32_t>(afSampleRate));
    aidl.afLatencyMs = VALUE_OR_RETURN(convertIntegral<int32_t>(afLatencyMs));
    aidl.afChannelMask = VALUE_OR_RETURN(
            legacy2aidl_audio_channel_mask_t_AudioChannelLayout(afChannelMask, false /*isInput*/));
    aidl.afFormat = VALUE_OR_RETURN(
            legacy2aidl_audio_format_t_AudioFormatDescription(afFormat));
    aidl.outputId = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(outputId));
    aidl.portId = VALUE_OR_RETURN(legacy2aidl_audio_port_handle_t_int32_t(portId));
    aidl.audioTrack = audioTrack;
    return aidl;
}

ConversionResult<IAudioFlinger::CreateTrackOutput>
IAudioFlinger::CreateTrackOutput::fromAidl(
        const media::CreateTrackResponse& aidl) {
    IAudioFlinger::CreateTrackOutput legacy;
    legacy.flags = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_output_flags_t_mask(aidl.flags));
    legacy.frameCount = VALUE_OR_RETURN(convertIntegral<size_t>(aidl.frameCount));
    legacy.notificationFrameCount = VALUE_OR_RETURN(
            convertIntegral<size_t>(aidl.notificationFrameCount));
    legacy.selectedDeviceId = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_port_handle_t(aidl.selectedDeviceId));
    legacy.sessionId = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_session_t(aidl.sessionId));
    legacy.sampleRate = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.sampleRate));
    legacy.streamType = VALUE_OR_RETURN(
            aidl2legacy_AudioStreamType_audio_stream_type_t(aidl.streamType));
    legacy.afFrameCount = VALUE_OR_RETURN(convertIntegral<size_t>(aidl.afFrameCount));
    legacy.afSampleRate = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.afSampleRate));
    legacy.afLatencyMs = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.afLatencyMs));
    legacy.afChannelMask = VALUE_OR_RETURN(
            aidl2legacy_AudioChannelLayout_audio_channel_mask_t(aidl.afChannelMask,
                                                                false /*isInput*/));
    legacy.afFormat = VALUE_OR_RETURN(
            aidl2legacy_AudioFormatDescription_audio_format_t(aidl.afFormat));
    legacy.outputId = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_io_handle_t(aidl.outputId));
    legacy.portId = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_port_handle_t(aidl.portId));
    legacy.audioTrack = aidl.audioTrack;
    return legacy;
}

ConversionResult<media::CreateRecordRequest>
IAudioFlinger::CreateRecordInput::toAidl() const {
    media::CreateRecordRequest aidl;
    aidl.attr = VALUE_OR_RETURN(legacy2aidl_audio_attributes_t_AudioAttributes(attr));
    aidl.config = VALUE_OR_RETURN(
            legacy2aidl_audio_config_base_t_AudioConfigBase(config, true /*isInput*/));
    aidl.clientInfo = VALUE_OR_RETURN(legacy2aidl_AudioClient_AudioClient(clientInfo));
    aidl.riid = VALUE_OR_RETURN(legacy2aidl_audio_unique_id_t_int32_t(riid));
    aidl.maxSharedAudioHistoryMs = VALUE_OR_RETURN(
            convertIntegral<int32_t>(maxSharedAudioHistoryMs));
    aidl.flags = VALUE_OR_RETURN(legacy2aidl_audio_input_flags_t_int32_t_mask(flags));
    aidl.frameCount = VALUE_OR_RETURN(convertIntegral<int64_t>(frameCount));
    aidl.notificationFrameCount = VALUE_OR_RETURN(convertIntegral<int64_t>(notificationFrameCount));
    aidl.selectedDeviceId = VALUE_OR_RETURN(
            legacy2aidl_audio_port_handle_t_int32_t(selectedDeviceId));
    aidl.sessionId = VALUE_OR_RETURN(legacy2aidl_audio_session_t_int32_t(sessionId));
    return aidl;
}

ConversionResult<IAudioFlinger::CreateRecordInput>
IAudioFlinger::CreateRecordInput::fromAidl(
        const media::CreateRecordRequest& aidl) {
    IAudioFlinger::CreateRecordInput legacy;
    legacy.attr = VALUE_OR_RETURN(
            aidl2legacy_AudioAttributes_audio_attributes_t(aidl.attr));
    legacy.config = VALUE_OR_RETURN(
            aidl2legacy_AudioConfigBase_audio_config_base_t(aidl.config, true /*isInput*/));
    legacy.clientInfo = VALUE_OR_RETURN(aidl2legacy_AudioClient_AudioClient(aidl.clientInfo));
    legacy.riid = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_unique_id_t(aidl.riid));
    legacy.maxSharedAudioHistoryMs = VALUE_OR_RETURN(
            convertIntegral<int32_t>(aidl.maxSharedAudioHistoryMs));
    legacy.flags = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_input_flags_t_mask(aidl.flags));
    legacy.frameCount = VALUE_OR_RETURN(convertIntegral<size_t>(aidl.frameCount));
    legacy.notificationFrameCount = VALUE_OR_RETURN(
            convertIntegral<size_t>(aidl.notificationFrameCount));
    legacy.selectedDeviceId = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_port_handle_t(aidl.selectedDeviceId));
    legacy.sessionId = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_session_t(aidl.sessionId));
    return legacy;
}

ConversionResult<media::CreateRecordResponse>
IAudioFlinger::CreateRecordOutput::toAidl() const {
    media::CreateRecordResponse aidl;
    aidl.flags = VALUE_OR_RETURN(legacy2aidl_audio_input_flags_t_int32_t_mask(flags));
    aidl.frameCount = VALUE_OR_RETURN(convertIntegral<int64_t>(frameCount));
    aidl.notificationFrameCount = VALUE_OR_RETURN(convertIntegral<int64_t>(notificationFrameCount));
    aidl.selectedDeviceId = VALUE_OR_RETURN(
            legacy2aidl_audio_port_handle_t_int32_t(selectedDeviceId));
    aidl.sessionId = VALUE_OR_RETURN(legacy2aidl_audio_session_t_int32_t(sessionId));
    aidl.sampleRate = VALUE_OR_RETURN(convertIntegral<int32_t>(sampleRate));
    aidl.inputId = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(inputId));
    aidl.cblk = VALUE_OR_RETURN(legacy2aidl_NullableIMemory_SharedFileRegion(cblk));
    aidl.buffers = VALUE_OR_RETURN(legacy2aidl_NullableIMemory_SharedFileRegion(buffers));
    aidl.portId = VALUE_OR_RETURN(legacy2aidl_audio_port_handle_t_int32_t(portId));
    aidl.audioRecord = audioRecord;
    aidl.serverConfig = VALUE_OR_RETURN(
            legacy2aidl_audio_config_base_t_AudioConfigBase(serverConfig, true /*isInput*/));
    aidl.halConfig = VALUE_OR_RETURN(
        legacy2aidl_audio_config_base_t_AudioConfigBase(halConfig, true /*isInput*/));
    return aidl;
}

ConversionResult<IAudioFlinger::CreateRecordOutput>
IAudioFlinger::CreateRecordOutput::fromAidl(
        const media::CreateRecordResponse& aidl) {
    IAudioFlinger::CreateRecordOutput legacy;
    legacy.flags = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_input_flags_t_mask(aidl.flags));
    legacy.frameCount = VALUE_OR_RETURN(convertIntegral<size_t>(aidl.frameCount));
    legacy.notificationFrameCount = VALUE_OR_RETURN(
            convertIntegral<size_t>(aidl.notificationFrameCount));
    legacy.selectedDeviceId = VALUE_OR_RETURN(
            aidl2legacy_int32_t_audio_port_handle_t(aidl.selectedDeviceId));
    legacy.sessionId = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_session_t(aidl.sessionId));
    legacy.sampleRate = VALUE_OR_RETURN(convertIntegral<uint32_t>(aidl.sampleRate));
    legacy.inputId = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_io_handle_t(aidl.inputId));
    legacy.cblk = VALUE_OR_RETURN(aidl2legacy_NullableSharedFileRegion_IMemory(aidl.cblk));
    legacy.buffers = VALUE_OR_RETURN(aidl2legacy_NullableSharedFileRegion_IMemory(aidl.buffers));
    legacy.portId = VALUE_OR_RETURN(aidl2legacy_int32_t_audio_port_handle_t(aidl.portId));
    legacy.audioRecord = aidl.audioRecord;
    legacy.serverConfig = VALUE_OR_RETURN(
            aidl2legacy_AudioConfigBase_audio_config_base_t(aidl.serverConfig, true /*isInput*/));
    legacy.halConfig = VALUE_OR_RETURN(
        aidl2legacy_AudioConfigBase_audio_config_base_t(aidl.halConfig, true /*isInput*/));
    return legacy;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// AudioFlingerClientAdapter

AudioFlingerClientAdapter::AudioFlingerClientAdapter(
        const sp<media::IAudioFlingerService> delegate) : mDelegate(delegate) {}

status_t AudioFlingerClientAdapter::createTrack(const media::CreateTrackRequest& input,
                                                media::CreateTrackResponse& output) {
    return statusTFromBinderStatus(mDelegate->createTrack(input, &output));
}

status_t AudioFlingerClientAdapter::createRecord(const media::CreateRecordRequest& input,
                                                 media::CreateRecordResponse& output) {
    return statusTFromBinderStatus(mDelegate->createRecord(input, &output));
}

uint32_t AudioFlingerClientAdapter::sampleRate(audio_io_handle_t ioHandle) const {
    auto result = [&]() -> ConversionResult<uint32_t> {
        int32_t ioHandleAidl = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(ioHandle));
        int32_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(mDelegate->sampleRate(ioHandleAidl, &aidlRet)));
        return convertIntegral<uint32_t>(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(0);
}

audio_format_t AudioFlingerClientAdapter::format(audio_io_handle_t output) const {
    auto result = [&]() -> ConversionResult<audio_format_t> {
        int32_t outputAidl = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(output));
        AudioFormatDescription aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(mDelegate->format(outputAidl, &aidlRet)));
        return aidl2legacy_AudioFormatDescription_audio_format_t(aidlRet);
    }();
    return result.value_or(AUDIO_FORMAT_INVALID);
}

size_t AudioFlingerClientAdapter::frameCount(audio_io_handle_t ioHandle) const {
    auto result = [&]() -> ConversionResult<size_t> {
        int32_t ioHandleAidl = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(ioHandle));
        int64_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(mDelegate->frameCount(ioHandleAidl, &aidlRet)));
        return convertIntegral<size_t>(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(0);
}

uint32_t AudioFlingerClientAdapter::latency(audio_io_handle_t output) const {
    auto result = [&]() -> ConversionResult<uint32_t> {
        int32_t outputAidl = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(output));
        int32_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(mDelegate->latency(outputAidl, &aidlRet)));
        return convertIntegral<uint32_t>(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(0);
}

status_t AudioFlingerClientAdapter::setMasterVolume(float value) {
    return statusTFromBinderStatus(mDelegate->setMasterVolume(value));
}

status_t AudioFlingerClientAdapter::setMasterMute(bool muted) {
    return statusTFromBinderStatus(mDelegate->setMasterMute(muted));
}

float AudioFlingerClientAdapter::masterVolume() const {
    auto result = [&]() -> ConversionResult<float> {
        float aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(mDelegate->masterVolume(&aidlRet)));
        return aidlRet;
    }();
    // Failure is ignored.
    return result.value_or(0.f);
}

bool AudioFlingerClientAdapter::masterMute() const {
    auto result = [&]() -> ConversionResult<bool> {
        bool aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(mDelegate->masterMute(&aidlRet)));
        return aidlRet;
    }();
    // Failure is ignored.
    return result.value_or(false);
}

status_t AudioFlingerClientAdapter::setMasterBalance(float balance) {
    return statusTFromBinderStatus(mDelegate->setMasterBalance(balance));
}

status_t AudioFlingerClientAdapter::getMasterBalance(float* balance) const{
    return statusTFromBinderStatus(mDelegate->getMasterBalance(balance));
}

status_t AudioFlingerClientAdapter::setStreamVolume(audio_stream_type_t stream, float value,
                                                    audio_io_handle_t output) {
    AudioStreamType streamAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_stream_type_t_AudioStreamType(stream));
    int32_t outputAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(output));
    return statusTFromBinderStatus(mDelegate->setStreamVolume(streamAidl, value, outputAidl));
}

status_t AudioFlingerClientAdapter::setStreamMute(audio_stream_type_t stream, bool muted) {
    AudioStreamType streamAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_stream_type_t_AudioStreamType(stream));
    return statusTFromBinderStatus(mDelegate->setStreamMute(streamAidl, muted));
}

float AudioFlingerClientAdapter::streamVolume(audio_stream_type_t stream,
                                              audio_io_handle_t output) const {
    auto result = [&]() -> ConversionResult<float> {
        AudioStreamType streamAidl = VALUE_OR_RETURN_STATUS(
                legacy2aidl_audio_stream_type_t_AudioStreamType(stream));
        int32_t outputAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(output));
        float aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->streamVolume(streamAidl, outputAidl, &aidlRet)));
        return aidlRet;
    }();
    // Failure is ignored.
    return result.value_or(0.f);
}

bool AudioFlingerClientAdapter::streamMute(audio_stream_type_t stream) const {
    auto result = [&]() -> ConversionResult<bool> {
        AudioStreamType streamAidl = VALUE_OR_RETURN_STATUS(
                legacy2aidl_audio_stream_type_t_AudioStreamType(stream));
        bool aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->streamMute(streamAidl, &aidlRet)));
        return aidlRet;
    }();
    // Failure is ignored.
    return result.value_or(false);
}

status_t AudioFlingerClientAdapter::setMode(audio_mode_t mode) {
    AudioMode modeAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_mode_t_AudioMode(mode));
    return statusTFromBinderStatus(mDelegate->setMode(modeAidl));
}

status_t AudioFlingerClientAdapter::setMicMute(bool state) {
    return statusTFromBinderStatus(mDelegate->setMicMute(state));
}

bool AudioFlingerClientAdapter::getMicMute() const {
    auto result = [&]() -> ConversionResult<bool> {
        bool aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->getMicMute(&aidlRet)));
        return aidlRet;
    }();
    // Failure is ignored.
    return result.value_or(false);
}

void AudioFlingerClientAdapter::setRecordSilenced(audio_port_handle_t portId, bool silenced) {
    auto result = [&]() -> status_t {
        int32_t portIdAidl = VALUE_OR_RETURN_STATUS(
                legacy2aidl_audio_port_handle_t_int32_t(portId));
        return statusTFromBinderStatus(mDelegate->setRecordSilenced(portIdAidl, silenced));
    }();
    // Failure is ignored.
    (void) result;
}

status_t AudioFlingerClientAdapter::setParameters(audio_io_handle_t ioHandle,
                                                  const String8& keyValuePairs) {
    int32_t ioHandleAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(ioHandle));
    std::string keyValuePairsAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_String8_string(keyValuePairs));
    return statusTFromBinderStatus(mDelegate->setParameters(ioHandleAidl, keyValuePairsAidl));
}

String8 AudioFlingerClientAdapter::getParameters(audio_io_handle_t ioHandle, const String8& keys)
const {
    auto result = [&]() -> ConversionResult<String8> {
        int32_t ioHandleAidl = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(ioHandle));
        std::string keysAidl = VALUE_OR_RETURN(legacy2aidl_String8_string(keys));
        std::string aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->getParameters(ioHandleAidl, keysAidl, &aidlRet)));
        return aidl2legacy_string_view_String8(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(String8());
}

void AudioFlingerClientAdapter::registerClient(const sp<media::IAudioFlingerClient>& client) {
    mDelegate->registerClient(client);
    // Failure is ignored.
}

size_t AudioFlingerClientAdapter::getInputBufferSize(uint32_t sampleRate, audio_format_t format,
                                                     audio_channel_mask_t channelMask) const {
    auto result = [&]() -> ConversionResult<size_t> {
        int32_t sampleRateAidl = VALUE_OR_RETURN(convertIntegral<int32_t>(sampleRate));
        AudioFormatDescription formatAidl = VALUE_OR_RETURN(
                legacy2aidl_audio_format_t_AudioFormatDescription(format));
        AudioChannelLayout channelMaskAidl = VALUE_OR_RETURN(
                legacy2aidl_audio_channel_mask_t_AudioChannelLayout(channelMask, true /*isInput*/));
        int64_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->getInputBufferSize(sampleRateAidl, formatAidl, channelMaskAidl,
                                              &aidlRet)));
        return convertIntegral<size_t>(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(0);
}

status_t AudioFlingerClientAdapter::openOutput(const media::OpenOutputRequest& request,
                                               media::OpenOutputResponse* response) {
    return statusTFromBinderStatus(mDelegate->openOutput(request, response));
}

audio_io_handle_t AudioFlingerClientAdapter::openDuplicateOutput(audio_io_handle_t output1,
                                                                 audio_io_handle_t output2) {
    auto result = [&]() -> ConversionResult<audio_io_handle_t> {
        int32_t output1Aidl = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(output1));
        int32_t output2Aidl = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(output2));
        int32_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->openDuplicateOutput(output1Aidl, output2Aidl, &aidlRet)));
        return aidl2legacy_int32_t_audio_io_handle_t(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(0);
}

status_t AudioFlingerClientAdapter::closeOutput(audio_io_handle_t output) {
    int32_t outputAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(output));
    return statusTFromBinderStatus(mDelegate->closeOutput(outputAidl));
}

status_t AudioFlingerClientAdapter::suspendOutput(audio_io_handle_t output) {
    int32_t outputAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(output));
    return statusTFromBinderStatus(mDelegate->suspendOutput(outputAidl));
}

status_t AudioFlingerClientAdapter::restoreOutput(audio_io_handle_t output) {
    int32_t outputAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(output));
    return statusTFromBinderStatus(mDelegate->restoreOutput(outputAidl));
}

status_t AudioFlingerClientAdapter::openInput(const media::OpenInputRequest& request,
                                              media::OpenInputResponse* response) {
    return statusTFromBinderStatus(mDelegate->openInput(request, response));
}

status_t AudioFlingerClientAdapter::closeInput(audio_io_handle_t input) {
    int32_t inputAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(input));
    return statusTFromBinderStatus(mDelegate->closeInput(inputAidl));
}

status_t AudioFlingerClientAdapter::setVoiceVolume(float volume) {
    return statusTFromBinderStatus(mDelegate->setVoiceVolume(volume));
}

status_t AudioFlingerClientAdapter::getRenderPosition(uint32_t* halFrames, uint32_t* dspFrames,
                                                      audio_io_handle_t output) const {
    int32_t outputAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(output));
    media::RenderPosition aidlRet;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mDelegate->getRenderPosition(outputAidl, &aidlRet)));
    if (halFrames != nullptr) {
        *halFrames = VALUE_OR_RETURN_STATUS(convertIntegral<uint32_t>(aidlRet.halFrames));
    }
    if (dspFrames != nullptr) {
        *dspFrames = VALUE_OR_RETURN_STATUS(convertIntegral<uint32_t>(aidlRet.dspFrames));
    }
    return OK;
}

uint32_t AudioFlingerClientAdapter::getInputFramesLost(audio_io_handle_t ioHandle) const {
    auto result = [&]() -> ConversionResult<uint32_t> {
        int32_t ioHandleAidl = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(ioHandle));
        int32_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->getInputFramesLost(ioHandleAidl, &aidlRet)));
        return convertIntegral<uint32_t>(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(0);
}

audio_unique_id_t AudioFlingerClientAdapter::newAudioUniqueId(audio_unique_id_use_t use) {
    auto result = [&]() -> ConversionResult<audio_unique_id_t> {
        media::AudioUniqueIdUse useAidl = VALUE_OR_RETURN(
                legacy2aidl_audio_unique_id_use_t_AudioUniqueIdUse(use));
        int32_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->newAudioUniqueId(useAidl, &aidlRet)));
        return aidl2legacy_int32_t_audio_unique_id_t(aidlRet);
    }();
    return result.value_or(AUDIO_UNIQUE_ID_ALLOCATE);
}

void AudioFlingerClientAdapter::acquireAudioSessionId(audio_session_t audioSession, pid_t pid,
                                                      uid_t uid) {
    [&]() -> status_t {
        int32_t audioSessionAidl = VALUE_OR_RETURN_STATUS(
                legacy2aidl_audio_session_t_int32_t(audioSession));
        int32_t pidAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_pid_t_int32_t(pid));
        int32_t uidAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_pid_t_int32_t(uid));
        return statusTFromBinderStatus(
                mDelegate->acquireAudioSessionId(audioSessionAidl, pidAidl, uidAidl));
    }();
    // Failure is ignored.
}

void AudioFlingerClientAdapter::releaseAudioSessionId(audio_session_t audioSession, pid_t pid) {
    [&]() -> status_t {
        int32_t audioSessionAidl = VALUE_OR_RETURN_STATUS(
                legacy2aidl_audio_session_t_int32_t(audioSession));
        int32_t pidAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_pid_t_int32_t(pid));
        return statusTFromBinderStatus(
                mDelegate->releaseAudioSessionId(audioSessionAidl, pidAidl));
    }();
    // Failure is ignored.
}

status_t AudioFlingerClientAdapter::queryNumberEffects(uint32_t* numEffects) const {
    int32_t aidlRet;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mDelegate->queryNumberEffects(&aidlRet)));
    if (numEffects != nullptr) {
        *numEffects = VALUE_OR_RETURN_STATUS(convertIntegral<uint32_t>(aidlRet));
    }
    return OK;
}

status_t
AudioFlingerClientAdapter::queryEffect(uint32_t index, effect_descriptor_t* pDescriptor) const {
    int32_t indexAidl = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(index));
    media::EffectDescriptor aidlRet;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mDelegate->queryEffect(indexAidl, &aidlRet)));
    if (pDescriptor != nullptr) {
        *pDescriptor = VALUE_OR_RETURN_STATUS(
                aidl2legacy_EffectDescriptor_effect_descriptor_t(aidlRet));
    }
    return OK;
}

status_t AudioFlingerClientAdapter::getEffectDescriptor(const effect_uuid_t* pEffectUUID,
                                                        const effect_uuid_t* pTypeUUID,
                                                        uint32_t preferredTypeFlag,
                                                        effect_descriptor_t* pDescriptor) const {
    AudioUuid effectUuidAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_uuid_t_AudioUuid(*pEffectUUID));
    AudioUuid typeUuidAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_uuid_t_AudioUuid(*pTypeUUID));
    int32_t preferredTypeFlagAidl = VALUE_OR_RETURN_STATUS(
            convertReinterpret<int32_t>(preferredTypeFlag));
    media::EffectDescriptor aidlRet;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mDelegate->getEffectDescriptor(effectUuidAidl, typeUuidAidl, preferredTypeFlagAidl,
                                           &aidlRet)));
    if (pDescriptor != nullptr) {
        *pDescriptor = VALUE_OR_RETURN_STATUS(
                aidl2legacy_EffectDescriptor_effect_descriptor_t(aidlRet));
    }
    return OK;
}

status_t AudioFlingerClientAdapter::createEffect(const media::CreateEffectRequest& request,
                                                 media::CreateEffectResponse* response) {
    return statusTFromBinderStatus(mDelegate->createEffect(request, response));
}

status_t
AudioFlingerClientAdapter::moveEffects(audio_session_t session, audio_io_handle_t srcOutput,
                                       audio_io_handle_t dstOutput) {
    int32_t sessionAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_session_t_int32_t(session));
    int32_t srcOutputAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_io_handle_t_int32_t(srcOutput));
    int32_t dstOutputAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_io_handle_t_int32_t(dstOutput));
    return statusTFromBinderStatus(
            mDelegate->moveEffects(sessionAidl, srcOutputAidl, dstOutputAidl));
}

void AudioFlingerClientAdapter::setEffectSuspended(int effectId,
                                                   audio_session_t sessionId,
                                                   bool suspended) {
    [&]() -> status_t {
        int32_t effectIdAidl = VALUE_OR_RETURN_STATUS(convertReinterpret<int32_t>(effectId));
        int32_t sessionIdAidl = VALUE_OR_RETURN_STATUS(
                legacy2aidl_audio_session_t_int32_t(sessionId));
        return statusTFromBinderStatus(
                mDelegate->setEffectSuspended(effectIdAidl, sessionIdAidl, suspended));
    }();
    // Failure is ignored.
}

audio_module_handle_t AudioFlingerClientAdapter::loadHwModule(const char* name) {
    auto result = [&]() -> ConversionResult<audio_module_handle_t> {
        std::string nameAidl(name);
        int32_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->loadHwModule(nameAidl, &aidlRet)));
        return aidl2legacy_int32_t_audio_module_handle_t(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(0);
}

uint32_t AudioFlingerClientAdapter::getPrimaryOutputSamplingRate() {
    auto result = [&]() -> ConversionResult<uint32_t> {
        int32_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->getPrimaryOutputSamplingRate(&aidlRet)));
        return convertIntegral<uint32_t>(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(0);
}

size_t AudioFlingerClientAdapter::getPrimaryOutputFrameCount() {
    auto result = [&]() -> ConversionResult<size_t> {
        int64_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->getPrimaryOutputFrameCount(&aidlRet)));
        return convertIntegral<size_t>(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(0);
}

status_t AudioFlingerClientAdapter::setLowRamDevice(bool isLowRamDevice, int64_t totalMemory) {
    return statusTFromBinderStatus(mDelegate->setLowRamDevice(isLowRamDevice, totalMemory));
}

status_t AudioFlingerClientAdapter::getAudioPort(struct audio_port_v7* port) {
    media::AudioPortFw portAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_port_v7_AudioPortFw(*port));
    media::AudioPortFw aidlRet;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mDelegate->getAudioPort(portAidl, &aidlRet)));
    *port = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioPortFw_audio_port_v7(aidlRet));
    return OK;
}

status_t AudioFlingerClientAdapter::createAudioPatch(const struct audio_patch* patch,
                                                     audio_patch_handle_t* handle) {
    media::AudioPatchFw patchAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_patch_AudioPatchFw(*patch));
    int32_t aidlRet = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_patch_handle_t_int32_t(
                    AUDIO_PATCH_HANDLE_NONE));
    if (handle != nullptr) {
        aidlRet = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_patch_handle_t_int32_t(*handle));
    }
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mDelegate->createAudioPatch(patchAidl, &aidlRet)));
    if (handle != nullptr) {
        *handle = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_patch_handle_t(aidlRet));
    }
    return OK;
}

status_t AudioFlingerClientAdapter::releaseAudioPatch(audio_patch_handle_t handle) {
    int32_t handleAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_patch_handle_t_int32_t(handle));
    return statusTFromBinderStatus(mDelegate->releaseAudioPatch(handleAidl));
}

status_t AudioFlingerClientAdapter::listAudioPatches(unsigned int* num_patches,
                                                     struct audio_patch* patches) {
    std::vector<media::AudioPatchFw> aidlRet;
    int32_t maxPatches = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(*num_patches));
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mDelegate->listAudioPatches(maxPatches, &aidlRet)));
    *num_patches = VALUE_OR_RETURN_STATUS(convertIntegral<unsigned int>(aidlRet.size()));
    return convertRange(aidlRet.begin(), aidlRet.end(), patches,
                        aidl2legacy_AudioPatchFw_audio_patch);
}

status_t AudioFlingerClientAdapter::setAudioPortConfig(const struct audio_port_config* config) {
    media::AudioPortConfigFw configAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_port_config_AudioPortConfigFw(*config));
    return statusTFromBinderStatus(mDelegate->setAudioPortConfig(configAidl));
}

audio_hw_sync_t AudioFlingerClientAdapter::getAudioHwSyncForSession(audio_session_t sessionId) {
    auto result = [&]() -> ConversionResult<audio_hw_sync_t> {
        int32_t sessionIdAidl = VALUE_OR_RETURN(legacy2aidl_audio_session_t_int32_t(sessionId));
        int32_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->getAudioHwSyncForSession(sessionIdAidl, &aidlRet)));
        return aidl2legacy_int32_t_audio_hw_sync_t(aidlRet);
    }();
    return result.value_or(AUDIO_HW_SYNC_INVALID);
}

status_t AudioFlingerClientAdapter::systemReady() {
    return statusTFromBinderStatus(mDelegate->systemReady());
}

status_t AudioFlingerClientAdapter::audioPolicyReady() {
    return statusTFromBinderStatus(mDelegate->audioPolicyReady());
}

size_t AudioFlingerClientAdapter::frameCountHAL(audio_io_handle_t ioHandle) const {
    auto result = [&]() -> ConversionResult<size_t> {
        int32_t ioHandleAidl = VALUE_OR_RETURN(legacy2aidl_audio_io_handle_t_int32_t(ioHandle));
        int64_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->frameCountHAL(ioHandleAidl, &aidlRet)));
        return convertIntegral<size_t>(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(0);
}

status_t
AudioFlingerClientAdapter::getMicrophones(std::vector<media::MicrophoneInfoFw>* microphones) {
    std::vector<media::MicrophoneInfoFw> aidlRet;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mDelegate->getMicrophones(&aidlRet)));
    if (microphones != nullptr) {
        *microphones = std::move(aidlRet);
    }
    return OK;
}

status_t AudioFlingerClientAdapter::setAudioHalPids(const std::vector<pid_t>& pids) {
    std::vector<int32_t> pidsAidl = VALUE_OR_RETURN_STATUS(
            convertContainer<std::vector<int32_t>>(pids, legacy2aidl_pid_t_int32_t));
    return statusTFromBinderStatus(mDelegate->setAudioHalPids(pidsAidl));
}

status_t AudioFlingerClientAdapter::setVibratorInfos(
        const std::vector<media::AudioVibratorInfo>& vibratorInfos) {
    return statusTFromBinderStatus(mDelegate->setVibratorInfos(vibratorInfos));
}

status_t AudioFlingerClientAdapter::updateSecondaryOutputs(
        const TrackSecondaryOutputsMap& trackSecondaryOutputs) {
    std::vector<media::TrackSecondaryOutputInfo> trackSecondaryOutputInfos =
            VALUE_OR_RETURN_STATUS(
                    convertContainer<std::vector<media::TrackSecondaryOutputInfo>>(
                            trackSecondaryOutputs,
                            legacy2aidl_TrackSecondaryOutputInfoPair_TrackSecondaryOutputInfo));
    return statusTFromBinderStatus(mDelegate->updateSecondaryOutputs(trackSecondaryOutputInfos));
}

status_t AudioFlingerClientAdapter::getMmapPolicyInfos(
        AudioMMapPolicyType policyType, std::vector<AudioMMapPolicyInfo> *policyInfos) {
    return statusTFromBinderStatus(mDelegate->getMmapPolicyInfos(policyType, policyInfos));
}

int32_t AudioFlingerClientAdapter::getAAudioMixerBurstCount() {
    auto result = [&]() -> ConversionResult<int32_t> {
        int32_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(mDelegate->getAAudioMixerBurstCount(&aidlRet)));
        return convertIntegral<int32_t>(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(0);
}

int32_t AudioFlingerClientAdapter::getAAudioHardwareBurstMinUsec() {
    auto result = [&]() -> ConversionResult<int32_t> {
        int32_t aidlRet;
        RETURN_IF_ERROR(statusTFromBinderStatus(
                mDelegate->getAAudioHardwareBurstMinUsec(&aidlRet)));
        return convertIntegral<int32_t>(aidlRet);
    }();
    // Failure is ignored.
    return result.value_or(0);
}

status_t AudioFlingerClientAdapter::setDeviceConnectedState(
        const struct audio_port_v7 *port, media::DeviceConnectedState state) {
    media::AudioPortFw aidlPort = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_port_v7_AudioPortFw(*port));
    return statusTFromBinderStatus(mDelegate->setDeviceConnectedState(aidlPort, state));
}

status_t AudioFlingerClientAdapter::setSimulateDeviceConnections(bool enabled) {
    return statusTFromBinderStatus(mDelegate->setSimulateDeviceConnections(enabled));
}

status_t AudioFlingerClientAdapter::setRequestedLatencyMode(
        audio_io_handle_t output, audio_latency_mode_t mode) {
    int32_t outputAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(output));
    media::audio::common::AudioLatencyMode modeAidl  = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_latency_mode_t_AudioLatencyMode(mode));
    return statusTFromBinderStatus(mDelegate->setRequestedLatencyMode(outputAidl, modeAidl));
}

status_t AudioFlingerClientAdapter::getSupportedLatencyModes(
        audio_io_handle_t output, std::vector<audio_latency_mode_t>* modes) {
    if (modes == nullptr) {
        return BAD_VALUE;
    }

    int32_t outputAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(output));
    std::vector<media::audio::common::AudioLatencyMode> modesAidl;

    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mDelegate->getSupportedLatencyModes(outputAidl, &modesAidl)));

    *modes = VALUE_OR_RETURN_STATUS(
            convertContainer<std::vector<audio_latency_mode_t>>(modesAidl,
                     aidl2legacy_AudioLatencyMode_audio_latency_mode_t));

    return NO_ERROR;
}

status_t AudioFlingerClientAdapter::setBluetoothVariableLatencyEnabled(bool enabled) {
    return statusTFromBinderStatus(mDelegate->setBluetoothVariableLatencyEnabled(enabled));
}

status_t AudioFlingerClientAdapter::isBluetoothVariableLatencyEnabled(bool* enabled) {
    if (enabled == nullptr) {
        return BAD_VALUE;
    }

    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mDelegate->isBluetoothVariableLatencyEnabled(enabled)));

    return NO_ERROR;
}

status_t AudioFlingerClientAdapter::supportsBluetoothVariableLatency(bool* support) {
    if (support == nullptr) {
        return BAD_VALUE;
    }

    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mDelegate->supportsBluetoothVariableLatency(support)));

    return NO_ERROR;
}

status_t AudioFlingerClientAdapter::getSoundDoseInterface(
        const sp<media::ISoundDoseCallback> &callback,
        sp<media::ISoundDose>* soundDose) {
    return statusTFromBinderStatus(mDelegate->getSoundDoseInterface(callback, soundDose));
}

status_t AudioFlingerClientAdapter::invalidateTracks(
        const std::vector<audio_port_handle_t>& portIds) {
    std::vector<int32_t> portIdsAidl = VALUE_OR_RETURN_STATUS(
            convertContainer<std::vector<int32_t>>(
                    portIds, legacy2aidl_audio_port_handle_t_int32_t));
    return statusTFromBinderStatus(mDelegate->invalidateTracks(portIdsAidl));
}

status_t AudioFlingerClientAdapter::getAudioPolicyConfig(media::AudioPolicyConfig *config) {
    if (config == nullptr) {
        return BAD_VALUE;
    }

    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mDelegate->getAudioPolicyConfig(config)));

    return NO_ERROR;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// AudioFlingerServerAdapter
AudioFlingerServerAdapter::AudioFlingerServerAdapter(
        const sp<AudioFlingerServerAdapter::Delegate>& delegate) : mDelegate(delegate) {
    setMinSchedulerPolicy(SCHED_NORMAL, ANDROID_PRIORITY_AUDIO);
}

status_t AudioFlingerServerAdapter::onTransact(uint32_t code,
                                               const Parcel& data,
                                               Parcel* reply,
                                               uint32_t flags) {
    return mDelegate->onTransactWrapper(static_cast<Delegate::TransactionCode>(code),
                                        data,
                                        flags,
                                        [&] {
                                            return BnAudioFlingerService::onTransact(
                                                    code,
                                                    data,
                                                    reply,
                                                    flags);
                                        });
}

status_t AudioFlingerServerAdapter::dump(int fd, const Vector<String16>& args) {
    return mDelegate->dump(fd, args);
}

Status AudioFlingerServerAdapter::createTrack(const media::CreateTrackRequest& request,
                                              media::CreateTrackResponse* _aidl_return) {
    return Status::fromStatusT(mDelegate->createTrack(request, *_aidl_return));
}

Status AudioFlingerServerAdapter::createRecord(const media::CreateRecordRequest& request,
                                               media::CreateRecordResponse* _aidl_return) {
    return Status::fromStatusT(mDelegate->createRecord(request, *_aidl_return));
}

Status AudioFlingerServerAdapter::sampleRate(int32_t ioHandle, int32_t* _aidl_return) {
    audio_io_handle_t ioHandleLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(ioHandle));
    *_aidl_return = VALUE_OR_RETURN_BINDER(
            convertIntegral<int32_t>(mDelegate->sampleRate(ioHandleLegacy)));
    return Status::ok();
}

Status AudioFlingerServerAdapter::format(int32_t output,
                                         AudioFormatDescription* _aidl_return) {
    audio_io_handle_t outputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(output));
    *_aidl_return = VALUE_OR_RETURN_BINDER(
            legacy2aidl_audio_format_t_AudioFormatDescription(mDelegate->format(outputLegacy)));
    return Status::ok();
}

Status AudioFlingerServerAdapter::frameCount(int32_t ioHandle, int64_t* _aidl_return) {
    audio_io_handle_t ioHandleLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(ioHandle));
    *_aidl_return = VALUE_OR_RETURN_BINDER(
            convertIntegral<int64_t>(mDelegate->frameCount(ioHandleLegacy)));
    return Status::ok();
}

Status AudioFlingerServerAdapter::latency(int32_t output, int32_t* _aidl_return) {
    audio_io_handle_t outputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(output));
    *_aidl_return = VALUE_OR_RETURN_BINDER(
            convertIntegral<int32_t>(mDelegate->latency(outputLegacy)));
    return Status::ok();
}

Status AudioFlingerServerAdapter::setMasterVolume(float value) {
    return Status::fromStatusT(mDelegate->setMasterVolume(value));
}

Status AudioFlingerServerAdapter::setMasterMute(bool muted) {
    return Status::fromStatusT(mDelegate->setMasterMute(muted));
}

Status AudioFlingerServerAdapter::masterVolume(float* _aidl_return) {
    *_aidl_return = mDelegate->masterVolume();
    return Status::ok();
}

Status AudioFlingerServerAdapter::masterMute(bool* _aidl_return) {
    *_aidl_return = mDelegate->masterMute();
    return Status::ok();
}

Status AudioFlingerServerAdapter::setMasterBalance(float balance) {
    return Status::fromStatusT(mDelegate->setMasterBalance(balance));
}

Status AudioFlingerServerAdapter::getMasterBalance(float* _aidl_return) {
    return Status::fromStatusT(mDelegate->getMasterBalance(_aidl_return));
}

Status AudioFlingerServerAdapter::setStreamVolume(AudioStreamType stream, float value,
                                                  int32_t output) {
    audio_stream_type_t streamLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_AudioStreamType_audio_stream_type_t(stream));
    audio_io_handle_t outputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(output));
    return Status::fromStatusT(mDelegate->setStreamVolume(streamLegacy, value, outputLegacy));
}

Status AudioFlingerServerAdapter::setStreamMute(AudioStreamType stream, bool muted) {
    audio_stream_type_t streamLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_AudioStreamType_audio_stream_type_t(stream));
    return Status::fromStatusT(mDelegate->setStreamMute(streamLegacy, muted));
}

Status AudioFlingerServerAdapter::streamVolume(AudioStreamType stream, int32_t output,
                                               float* _aidl_return) {
    audio_stream_type_t streamLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_AudioStreamType_audio_stream_type_t(stream));
    audio_io_handle_t outputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(output));
    *_aidl_return = mDelegate->streamVolume(streamLegacy, outputLegacy);
    return Status::ok();
}

Status AudioFlingerServerAdapter::streamMute(AudioStreamType stream, bool* _aidl_return) {
    audio_stream_type_t streamLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_AudioStreamType_audio_stream_type_t(stream));
    *_aidl_return = mDelegate->streamMute(streamLegacy);
    return Status::ok();
}

Status AudioFlingerServerAdapter::setMode(AudioMode mode) {
    audio_mode_t modeLegacy = VALUE_OR_RETURN_BINDER(aidl2legacy_AudioMode_audio_mode_t(mode));
    return Status::fromStatusT(mDelegate->setMode(modeLegacy));
}

Status AudioFlingerServerAdapter::setMicMute(bool state) {
    return Status::fromStatusT(mDelegate->setMicMute(state));
}

Status AudioFlingerServerAdapter::getMicMute(bool* _aidl_return) {
    *_aidl_return = mDelegate->getMicMute();
    return Status::ok();
}

Status AudioFlingerServerAdapter::setRecordSilenced(int32_t portId, bool silenced) {
    audio_port_handle_t portIdLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_port_handle_t(portId));
    mDelegate->setRecordSilenced(portIdLegacy, silenced);
    return Status::ok();
}

Status
AudioFlingerServerAdapter::setParameters(int32_t ioHandle, const std::string& keyValuePairs) {
    audio_io_handle_t ioHandleLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(ioHandle));
    String8 keyValuePairsLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_string_view_String8(keyValuePairs));
    return Status::fromStatusT(mDelegate->setParameters(ioHandleLegacy, keyValuePairsLegacy));
}

Status AudioFlingerServerAdapter::getParameters(int32_t ioHandle, const std::string& keys,
                                                std::string* _aidl_return) {
    audio_io_handle_t ioHandleLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(ioHandle));
    String8 keysLegacy = VALUE_OR_RETURN_BINDER(aidl2legacy_string_view_String8(keys));
    *_aidl_return = VALUE_OR_RETURN_BINDER(
            legacy2aidl_String8_string(mDelegate->getParameters(ioHandleLegacy, keysLegacy)));
    return Status::ok();
}

Status AudioFlingerServerAdapter::registerClient(const sp<media::IAudioFlingerClient>& client) {
    mDelegate->registerClient(client);
    return Status::ok();
}

Status AudioFlingerServerAdapter::getInputBufferSize(int32_t sampleRate,
                                                     const AudioFormatDescription& format,
                                                     const AudioChannelLayout& channelMask,
                                                     int64_t* _aidl_return) {
    uint32_t sampleRateLegacy = VALUE_OR_RETURN_BINDER(convertIntegral<uint32_t>(sampleRate));
    audio_format_t formatLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_AudioFormatDescription_audio_format_t(format));
    audio_channel_mask_t channelMaskLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_AudioChannelLayout_audio_channel_mask_t(channelMask, true /*isInput*/));
    size_t size = mDelegate->getInputBufferSize(sampleRateLegacy, formatLegacy, channelMaskLegacy);
    *_aidl_return = VALUE_OR_RETURN_BINDER(convertIntegral<int64_t>(size));
    return Status::ok();
}

Status AudioFlingerServerAdapter::openOutput(const media::OpenOutputRequest& request,
                                             media::OpenOutputResponse* _aidl_return) {
    return Status::fromStatusT(mDelegate->openOutput(request, _aidl_return));
}

Status AudioFlingerServerAdapter::openDuplicateOutput(int32_t output1, int32_t output2,
                                                      int32_t* _aidl_return) {
    audio_io_handle_t output1Legacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(output1));
    audio_io_handle_t output2Legacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(output2));
    audio_io_handle_t result = mDelegate->openDuplicateOutput(output1Legacy, output2Legacy);
    *_aidl_return = VALUE_OR_RETURN_BINDER(legacy2aidl_audio_io_handle_t_int32_t(result));
    return Status::ok();
}

Status AudioFlingerServerAdapter::closeOutput(int32_t output) {
    audio_io_handle_t outputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(output));
    return Status::fromStatusT(mDelegate->closeOutput(outputLegacy));
}

Status AudioFlingerServerAdapter::suspendOutput(int32_t output) {
    audio_io_handle_t outputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(output));
    return Status::fromStatusT(mDelegate->suspendOutput(outputLegacy));
}

Status AudioFlingerServerAdapter::restoreOutput(int32_t output) {
    audio_io_handle_t outputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(output));
    return Status::fromStatusT(mDelegate->restoreOutput(outputLegacy));
}

Status AudioFlingerServerAdapter::openInput(const media::OpenInputRequest& request,
                                            media::OpenInputResponse* _aidl_return) {
    return Status::fromStatusT(mDelegate->openInput(request, _aidl_return));
}

Status AudioFlingerServerAdapter::closeInput(int32_t input) {
    audio_io_handle_t inputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(input));
    return Status::fromStatusT(mDelegate->closeInput(inputLegacy));
}

Status AudioFlingerServerAdapter::setVoiceVolume(float volume) {
    return Status::fromStatusT(mDelegate->setVoiceVolume(volume));
}

Status
AudioFlingerServerAdapter::getRenderPosition(int32_t output, media::RenderPosition* _aidl_return) {
    audio_io_handle_t outputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(output));
    uint32_t halFramesLegacy;
    uint32_t dspFramesLegacy;
    RETURN_BINDER_IF_ERROR(
            mDelegate->getRenderPosition(&halFramesLegacy, &dspFramesLegacy, outputLegacy));
    _aidl_return->halFrames = VALUE_OR_RETURN_BINDER(convertIntegral<int32_t>(halFramesLegacy));
    _aidl_return->dspFrames = VALUE_OR_RETURN_BINDER(convertIntegral<int32_t>(dspFramesLegacy));
    return Status::ok();
}

Status AudioFlingerServerAdapter::getInputFramesLost(int32_t ioHandle, int32_t* _aidl_return) {
    audio_io_handle_t ioHandleLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(ioHandle));
    uint32_t result = mDelegate->getInputFramesLost(ioHandleLegacy);
    *_aidl_return = VALUE_OR_RETURN_BINDER(convertIntegral<int32_t>(result));
    return Status::ok();
}

Status
AudioFlingerServerAdapter::newAudioUniqueId(media::AudioUniqueIdUse use, int32_t* _aidl_return) {
    audio_unique_id_use_t useLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_AudioUniqueIdUse_audio_unique_id_use_t(use));
    audio_unique_id_t result = mDelegate->newAudioUniqueId(useLegacy);
    *_aidl_return = VALUE_OR_RETURN_BINDER(legacy2aidl_audio_unique_id_t_int32_t(result));
    return Status::ok();
}

Status
AudioFlingerServerAdapter::acquireAudioSessionId(int32_t audioSession, int32_t pid, int32_t uid) {
    audio_session_t audioSessionLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_session_t(audioSession));
    pid_t pidLegacy = VALUE_OR_RETURN_BINDER(aidl2legacy_int32_t_pid_t(pid));
    uid_t uidLegacy = VALUE_OR_RETURN_BINDER(aidl2legacy_int32_t_uid_t(uid));
    mDelegate->acquireAudioSessionId(audioSessionLegacy, pidLegacy, uidLegacy);
    return Status::ok();
}

Status AudioFlingerServerAdapter::releaseAudioSessionId(int32_t audioSession, int32_t pid) {
    audio_session_t audioSessionLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_session_t(audioSession));
    pid_t pidLegacy = VALUE_OR_RETURN_BINDER(aidl2legacy_int32_t_pid_t(pid));
    mDelegate->releaseAudioSessionId(audioSessionLegacy, pidLegacy);
    return Status::ok();
}

Status AudioFlingerServerAdapter::queryNumberEffects(int32_t* _aidl_return) {
    uint32_t result;
    RETURN_BINDER_IF_ERROR(mDelegate->queryNumberEffects(&result));
    *_aidl_return = VALUE_OR_RETURN_BINDER(convertIntegral<uint32_t>(result));
    return Status::ok();
}

Status
AudioFlingerServerAdapter::queryEffect(int32_t index, media::EffectDescriptor* _aidl_return) {
    uint32_t indexLegacy = VALUE_OR_RETURN_BINDER(convertIntegral<uint32_t>(index));
    effect_descriptor_t result;
    RETURN_BINDER_IF_ERROR(mDelegate->queryEffect(indexLegacy, &result));
    *_aidl_return = VALUE_OR_RETURN_BINDER(
            legacy2aidl_effect_descriptor_t_EffectDescriptor(result));
    return Status::ok();
}

Status AudioFlingerServerAdapter::getEffectDescriptor(const AudioUuid& effectUUID,
                                                      const AudioUuid& typeUUID,
                                                      int32_t preferredTypeFlag,
                                                      media::EffectDescriptor* _aidl_return) {
    effect_uuid_t effectUuidLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_AudioUuid_audio_uuid_t(effectUUID));
    effect_uuid_t typeUuidLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_AudioUuid_audio_uuid_t(typeUUID));
    uint32_t preferredTypeFlagLegacy = VALUE_OR_RETURN_BINDER(
            convertReinterpret<uint32_t>(preferredTypeFlag));
    effect_descriptor_t result;
    RETURN_BINDER_IF_ERROR(mDelegate->getEffectDescriptor(&effectUuidLegacy, &typeUuidLegacy,
                                                          preferredTypeFlagLegacy, &result));
    *_aidl_return = VALUE_OR_RETURN_BINDER(
            legacy2aidl_effect_descriptor_t_EffectDescriptor(result));
    return Status::ok();
}

Status AudioFlingerServerAdapter::createEffect(const media::CreateEffectRequest& request,
                                               media::CreateEffectResponse* _aidl_return) {
    return Status::fromStatusT(mDelegate->createEffect(request, _aidl_return));
}

Status
AudioFlingerServerAdapter::moveEffects(int32_t session, int32_t srcOutput, int32_t dstOutput) {
    audio_session_t sessionLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_session_t(session));
    audio_io_handle_t srcOutputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(srcOutput));
    audio_io_handle_t dstOutputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(dstOutput));
    return Status::fromStatusT(
            mDelegate->moveEffects(sessionLegacy, srcOutputLegacy, dstOutputLegacy));
}

Status AudioFlingerServerAdapter::setEffectSuspended(int32_t effectId, int32_t sessionId,
                                                     bool suspended) {
    int effectIdLegacy = VALUE_OR_RETURN_BINDER(convertReinterpret<int>(effectId));
    audio_session_t sessionIdLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_session_t(sessionId));
    mDelegate->setEffectSuspended(effectIdLegacy, sessionIdLegacy, suspended);
    return Status::ok();
}

Status AudioFlingerServerAdapter::loadHwModule(const std::string& name, int32_t* _aidl_return) {
    audio_module_handle_t result = mDelegate->loadHwModule(name.c_str());
    *_aidl_return = VALUE_OR_RETURN_BINDER(legacy2aidl_audio_module_handle_t_int32_t(result));
    return Status::ok();
}

Status AudioFlingerServerAdapter::getPrimaryOutputSamplingRate(int32_t* _aidl_return) {
    *_aidl_return = VALUE_OR_RETURN_BINDER(
            convertIntegral<int32_t>(mDelegate->getPrimaryOutputSamplingRate()));
    return Status::ok();
}

Status AudioFlingerServerAdapter::getPrimaryOutputFrameCount(int64_t* _aidl_return) {
    *_aidl_return = VALUE_OR_RETURN_BINDER(
            convertIntegral<int64_t>(mDelegate->getPrimaryOutputFrameCount()));
    return Status::ok();

}

Status AudioFlingerServerAdapter::setLowRamDevice(bool isLowRamDevice, int64_t totalMemory) {
    return Status::fromStatusT(mDelegate->setLowRamDevice(isLowRamDevice, totalMemory));
}

Status AudioFlingerServerAdapter::getAudioPort(const media::AudioPortFw& port,
                                               media::AudioPortFw* _aidl_return) {
    audio_port_v7 portLegacy = VALUE_OR_RETURN_BINDER(aidl2legacy_AudioPortFw_audio_port_v7(port));
    RETURN_BINDER_IF_ERROR(mDelegate->getAudioPort(&portLegacy));
    *_aidl_return = VALUE_OR_RETURN_BINDER(legacy2aidl_audio_port_v7_AudioPortFw(portLegacy));
    return Status::ok();
}

Status AudioFlingerServerAdapter::createAudioPatch(const media::AudioPatchFw& patch,
                                                   int32_t* _aidl_return) {
    audio_patch patchLegacy = VALUE_OR_RETURN_BINDER(aidl2legacy_AudioPatchFw_audio_patch(patch));
    audio_patch_handle_t handleLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_patch_handle_t(*_aidl_return));
    RETURN_BINDER_IF_ERROR(mDelegate->createAudioPatch(&patchLegacy, &handleLegacy));
    *_aidl_return = VALUE_OR_RETURN_BINDER(legacy2aidl_audio_patch_handle_t_int32_t(handleLegacy));
    return Status::ok();
}

Status AudioFlingerServerAdapter::releaseAudioPatch(int32_t handle) {
    audio_patch_handle_t handleLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_patch_handle_t(handle));
    return Status::fromStatusT(mDelegate->releaseAudioPatch(handleLegacy));
}

Status AudioFlingerServerAdapter::listAudioPatches(int32_t maxCount,
                            std::vector<media::AudioPatchFw>* _aidl_return) {
    unsigned int count = VALUE_OR_RETURN_BINDER(convertIntegral<unsigned int>(maxCount));
    count = std::min(count, static_cast<unsigned int>(MAX_ITEMS_PER_LIST));
    std::unique_ptr<audio_patch[]> patchesLegacy(new audio_patch[count]);
    RETURN_BINDER_IF_ERROR(mDelegate->listAudioPatches(&count, patchesLegacy.get()));
    RETURN_BINDER_IF_ERROR(convertRange(&patchesLegacy[0],
                           &patchesLegacy[count],
                           std::back_inserter(*_aidl_return),
                           legacy2aidl_audio_patch_AudioPatchFw));
    return Status::ok();
}

Status AudioFlingerServerAdapter::setAudioPortConfig(const media::AudioPortConfigFw& config) {
    audio_port_config configLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_AudioPortConfigFw_audio_port_config(config));
    return Status::fromStatusT(mDelegate->setAudioPortConfig(&configLegacy));
}

Status AudioFlingerServerAdapter::getAudioHwSyncForSession(int32_t sessionId,
                                                           int32_t* _aidl_return) {
    audio_session_t sessionIdLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_session_t(sessionId));
    audio_hw_sync_t result = mDelegate->getAudioHwSyncForSession(sessionIdLegacy);
    *_aidl_return = VALUE_OR_RETURN_BINDER(legacy2aidl_audio_hw_sync_t_int32_t(result));
    return Status::ok();
}

Status AudioFlingerServerAdapter::systemReady() {
    return Status::fromStatusT(mDelegate->systemReady());
}

Status AudioFlingerServerAdapter::audioPolicyReady() {
    mDelegate->audioPolicyReady();
    return Status::ok();
}

Status AudioFlingerServerAdapter::frameCountHAL(int32_t ioHandle, int64_t* _aidl_return) {
    audio_io_handle_t ioHandleLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(ioHandle));
    size_t result = mDelegate->frameCountHAL(ioHandleLegacy);
    *_aidl_return = VALUE_OR_RETURN_BINDER(convertIntegral<int64_t>(result));
    return Status::ok();
}

Status AudioFlingerServerAdapter::getMicrophones(
        std::vector<media::MicrophoneInfoFw>* _aidl_return) {
    RETURN_BINDER_IF_ERROR(mDelegate->getMicrophones(_aidl_return));
    return Status::ok();
}

Status AudioFlingerServerAdapter::setAudioHalPids(const std::vector<int32_t>& pids) {
    std::vector<pid_t> pidsLegacy = VALUE_OR_RETURN_BINDER(
            convertContainer<std::vector<pid_t>>(pids, aidl2legacy_int32_t_pid_t));
    RETURN_BINDER_IF_ERROR(mDelegate->setAudioHalPids(pidsLegacy));
    return Status::ok();
}

Status AudioFlingerServerAdapter::setVibratorInfos(
        const std::vector<media::AudioVibratorInfo>& vibratorInfos) {
    return Status::fromStatusT(mDelegate->setVibratorInfos(vibratorInfos));
}

Status AudioFlingerServerAdapter::updateSecondaryOutputs(
        const std::vector<media::TrackSecondaryOutputInfo>& trackSecondaryOutputInfos) {
    TrackSecondaryOutputsMap trackSecondaryOutputs =
            VALUE_OR_RETURN_BINDER(convertContainer<TrackSecondaryOutputsMap>(
                    trackSecondaryOutputInfos,
                    aidl2legacy_TrackSecondaryOutputInfo_TrackSecondaryOutputInfoPair));
    return Status::fromStatusT(mDelegate->updateSecondaryOutputs(trackSecondaryOutputs));
}

Status AudioFlingerServerAdapter::getMmapPolicyInfos(
        AudioMMapPolicyType policyType, std::vector<AudioMMapPolicyInfo> *_aidl_return) {
    return Status::fromStatusT(mDelegate->getMmapPolicyInfos(policyType, _aidl_return));
}

Status AudioFlingerServerAdapter::getAAudioMixerBurstCount(int32_t* _aidl_return) {
    *_aidl_return = VALUE_OR_RETURN_BINDER(
            convertIntegral<int32_t>(mDelegate->getAAudioMixerBurstCount()));
    return Status::ok();
}

Status AudioFlingerServerAdapter::getAAudioHardwareBurstMinUsec(int32_t* _aidl_return) {
    *_aidl_return = VALUE_OR_RETURN_BINDER(
            convertIntegral<int32_t>(mDelegate->getAAudioHardwareBurstMinUsec()));
    return Status::ok();
}

Status AudioFlingerServerAdapter::setDeviceConnectedState(
        const media::AudioPortFw& port, media::DeviceConnectedState state) {
    audio_port_v7 portLegacy = VALUE_OR_RETURN_BINDER(aidl2legacy_AudioPortFw_audio_port_v7(port));
    return Status::fromStatusT(mDelegate->setDeviceConnectedState(&portLegacy, state));
}

Status AudioFlingerServerAdapter::setSimulateDeviceConnections(bool enabled) {
    return Status::fromStatusT(mDelegate->setSimulateDeviceConnections(enabled));
}

Status AudioFlingerServerAdapter::setRequestedLatencyMode(
        int32_t output, media::audio::common::AudioLatencyMode modeAidl) {
    audio_io_handle_t outputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(output));
    audio_latency_mode_t modeLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_AudioLatencyMode_audio_latency_mode_t(modeAidl));
    return Status::fromStatusT(mDelegate->setRequestedLatencyMode(
            outputLegacy, modeLegacy));
}

Status AudioFlingerServerAdapter::getSupportedLatencyModes(
        int output, std::vector<media::audio::common::AudioLatencyMode>* _aidl_return) {
    audio_io_handle_t outputLegacy = VALUE_OR_RETURN_BINDER(
            aidl2legacy_int32_t_audio_io_handle_t(output));
    std::vector<audio_latency_mode_t> modesLegacy;

    RETURN_BINDER_IF_ERROR(mDelegate->getSupportedLatencyModes(outputLegacy, &modesLegacy));

    *_aidl_return = VALUE_OR_RETURN_BINDER(
            convertContainer<std::vector<media::audio::common::AudioLatencyMode>>(
                    modesLegacy, legacy2aidl_audio_latency_mode_t_AudioLatencyMode));
    return Status::ok();
}

Status AudioFlingerServerAdapter::setBluetoothVariableLatencyEnabled(bool enabled) {
    return Status::fromStatusT(mDelegate->setBluetoothVariableLatencyEnabled(enabled));
}

Status AudioFlingerServerAdapter::isBluetoothVariableLatencyEnabled(bool *enabled) {
    return Status::fromStatusT(mDelegate->isBluetoothVariableLatencyEnabled(enabled));
}

Status AudioFlingerServerAdapter::supportsBluetoothVariableLatency(bool *support) {
    return Status::fromStatusT(mDelegate->supportsBluetoothVariableLatency(support));
}

Status AudioFlingerServerAdapter::getSoundDoseInterface(
        const sp<media::ISoundDoseCallback>& callback,
        sp<media::ISoundDose>* soundDose)
{
    return Status::fromStatusT(mDelegate->getSoundDoseInterface(callback, soundDose));
}

Status AudioFlingerServerAdapter::invalidateTracks(const std::vector<int32_t>& portIds) {
    std::vector<audio_port_handle_t> portIdsLegacy = VALUE_OR_RETURN_BINDER(
            convertContainer<std::vector<audio_port_handle_t>>(
                    portIds, aidl2legacy_int32_t_audio_port_handle_t));
    RETURN_BINDER_IF_ERROR(mDelegate->invalidateTracks(portIdsLegacy));
    return Status::ok();
}

Status AudioFlingerServerAdapter::getAudioPolicyConfig(media::AudioPolicyConfig* _aidl_return) {
    return Status::fromStatusT(mDelegate->getAudioPolicyConfig(_aidl_return));
}

} // namespace android
