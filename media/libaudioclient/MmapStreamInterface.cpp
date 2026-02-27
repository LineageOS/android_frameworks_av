/*
 * Copyright (C) 2025 The Android Open Source Project
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

#define LOG_TAG "MmapStreamInterface"

#include <android/media/BnMmapStreamCallback.h>
#include <media/AidlConversion.h>
#include <media/AudioSystem.h>
#include <media/IAudioFlinger.h>
#include <media/MmapStreamCallback.h>
#include <media/MmapStreamInterface.h>

namespace android {

using media::IMmapStream;
using media::audio::common::AudioPlaybackRate;
using aidl_utils::statusTFromBinderStatus;

class MmapStreamCallbackAdapter : public android::media::BnMmapStreamCallback {
public:
    explicit MmapStreamCallbackAdapter(const sp<MmapStreamCallback>& callback)
    : mCallback(callback) {}

    ::android::binder::Status onTearDown(int32_t portId) final {
        const audio_port_handle_t handle = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portId));
        if (const auto callback = mCallback.promote()) {
            callback->onTearDown(handle);
        } else {
            ALOGW_IF(mCallbackWarn++ < kSpamLimit, "%s: null callback", __func__);
        }
        return binder::Status::ok();
    }

    ::android::binder::Status onVolumeChanged(float volume) final {
        if (const auto callback = mCallback.promote()) {
            callback->onVolumeChanged(volume);
        } else {
            ALOGW_IF(mCallbackWarn++ < kSpamLimit, "%s: null callback", __func__);
        }
        return binder::Status::ok();
    }

    ::android::binder::Status onRoutingChanged(const ::std::vector<int32_t>& deviceIds) final {
        const std::vector<audio_port_handle_t> legacyDeviceIds = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<audio_port_handle_t>>(
                    deviceIds, aidl2legacy_int32_t_audio_port_handle_t));
        if (const auto callback = mCallback.promote()) {
            callback->onRoutingChanged(legacyDeviceIds);
        } else {
            ALOGW_IF(mCallbackWarn++ < kSpamLimit, "%s: null callback", __func__);
        }
        return binder::Status::ok();
    }

    ::android::binder::Status onSoundDoseChanged(bool active) final {
        if (const auto callback = mCallback.promote()) {
            callback->onSoundDoseChanged(active);
        } else {
            ALOGW_IF(mCallbackWarn++ < kSpamLimit, "%s: null callback", __func__);
        }
        return binder::Status::ok();
    }

    ::android::binder::Status onWakeUp(const media::TimerQueueHandle& handle) final {
        if (const auto callback = mCallback.promote()) {
            audio_utils::TimerQueue::handle_t legacy = VALUE_OR_RETURN_BINDER_STATUS(
                    aidl2legacy_TimerQueueHandle_timer_queue_handle_t(handle));
            callback->onWakeUp(legacy);
        } else {
            ALOGW_IF(mCallbackWarn++ < kSpamLimit, "%s: null callback", __func__);
        }
        return binder::Status::ok();
    }

private:
    static constexpr uint32_t kSpamLimit = 30;
    const wp<MmapStreamCallback> mCallback;
    std::atomic_uint32_t mCallbackWarn = 0;
};


// static
status_t MmapStreamInterface::buildRequest(bool isOutput,
                                           const audio_attributes_t& attr,
                                           const audio_config_base_t& config,
                                           const AudioClient& client,
                                           const DeviceIdVector& deviceIds,
                                           audio_session_t sessionId,
                                           const sp<MmapStreamCallback>& callback,
                                           const audio_offload_info_t* offloadInfo,
                                           media::OpenMmapRequest* request)
{
    request->isOutput = isOutput;
    request->attr = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_attributes_t_AudioAttributes(attr));
    request->config = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_config_base_t_AudioConfigBase(
                    config, !isOutput));
    request->client = VALUE_OR_RETURN_STATUS(
            legacy2aidl_AudioClient_AudioClient(client));
    request->deviceIds = VALUE_OR_RETURN_STATUS(
            convertContainer<std::vector<int32_t>>(
                    deviceIds, legacy2aidl_audio_port_handle_t_int32_t));
    request->sessionId = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_session_t_int32_t(sessionId));
    request->callback = sp<MmapStreamCallbackAdapter>::make(callback);
    request->offloadInfo = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_offload_info_t_AudioOffloadInfo(
                    offloadInfo ? *offloadInfo : AUDIO_INFO_INITIALIZER));
    return NO_ERROR;
}

// static
status_t MmapStreamInterface::parseResponse(const media::OpenMmapResponse& response,
                                            bool isOutput,
                                            audio_config_base_t* config,
                                            DeviceIdVector* deviceIds,
                                            audio_session_t* sessionId,
                                            audio_port_handle_t* handle)
{
    *config = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioConfigBase_audio_config_base_t(
                    response.config, !isOutput));
    *deviceIds = VALUE_OR_RETURN_STATUS(
            convertContainer<std::vector<audio_port_handle_t>>(
                    response.deviceIds, aidl2legacy_int32_t_audio_port_handle_t));
    *sessionId = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_session_t(response.sessionId));
    *handle = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(response.portId));
    return NO_ERROR;
}

// static
status_t MmapStreamInterface::openMmapStream(bool isOutput,
                                             const audio_attributes_t& attr,
                                             audio_config_base_t* config,
                                             const AudioClient& client,
                                             DeviceIdVector* deviceIds,
                                             audio_session_t* sessionId,
                                             const sp<MmapStreamCallback>& callback,
                                             const audio_offload_info_t* offloadInfo,
                                             sp<MmapStreamInterface>& interface,
                                             audio_port_handle_t* handle)
{
    const sp<IAudioFlinger>& af = AudioSystem::get_audio_flinger();
    if (af == nullptr) {
        return NO_INIT;
    }
    media::OpenMmapRequest request;
    sp<MmapStreamCallbackAdapter> callbackAdapter;
    status_t status = buildRequest(isOutput, attr, *config, client, *deviceIds,
            *sessionId, callback, offloadInfo, &request);
    if (status != NO_ERROR) {
        ALOGW("%s: buildRequest failed with status: %d", __func__, status);
        return status;
    }

    media::OpenMmapResponse response;
    status = af->openMmapStream(request, &response);

    // we always parse the response to fill config to permit retry on error.
    const status_t responseStatus = parseResponse(
            response, isOutput, config, deviceIds, sessionId, handle);

    if (status != NO_ERROR) {
        ALOGW("%s: openMmapStream failed with status: %d", __func__, status);
        return status;
    }
    if (responseStatus != NO_ERROR) {
        ALOGW("%s: parseResponse failed with status: %d", __func__, status);
        return responseStatus;
    }
    interface = sp<MmapStreamInterface>::make(*config, response.stream, request.callback);
    return NO_ERROR;
}

// static
status_t MmapStreamInterface::parseRequest(const media::OpenMmapRequest& request,
                                           bool* isOutput,
                                           audio_attributes_t* attr,
                                           audio_config_base_t* config,
                                           AudioClient* client,
                                           DeviceIdVector* deviceIds,
                                           audio_session_t* sessionId,
                                           sp<media::IMmapStreamCallback>* callback,
                                           audio_offload_info_t* offloadInfo) {
    *isOutput = request.isOutput;
    *attr = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(request.attr));
    *config = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioConfigBase_audio_config_base_t(
                    request.config, !*isOutput));
    *client = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioClient_AudioClient(request.client));
    *deviceIds = VALUE_OR_RETURN_STATUS(
            convertContainer<DeviceIdVector>(
                    request.deviceIds, aidl2legacy_int32_t_audio_port_handle_t));
    *sessionId = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_session_t(request.sessionId));
    *callback = request.callback;
    if (offloadInfo != nullptr) {
        *offloadInfo = VALUE_OR_RETURN_STATUS(
                aidl2legacy_AudioOffloadInfo_audio_offload_info_t(request.offloadInfo));
    }
    return NO_ERROR;
}

// static
status_t MmapStreamInterface::buildResponse(bool isOutput,
                                            const audio_config_base_t& config,
                                            const DeviceIdVector& deviceIds,
                                            audio_session_t sessionId,
                                            const sp<IMmapStream>& interface,
                                            audio_port_handle_t portId,
                                            media::OpenMmapResponse* response) {
    response->config = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_config_base_t_AudioConfigBase(
                    config, !isOutput));
    response->deviceIds = VALUE_OR_RETURN_STATUS(
            convertContainer<std::vector<int32_t>>(
                    deviceIds, legacy2aidl_audio_port_handle_t_int32_t));
    response->sessionId = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_session_t_int32_t(sessionId));
    response->stream = interface;
    response->portId = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_port_handle_t_int32_t(portId));
    return NO_ERROR;
}

MmapStreamInterface::MmapStreamInterface(const audio_config_base_t& config,
        const sp<media::IMmapStream>& stream,
        const sp<media::IMmapStreamCallback>& callback)
    : mConfig(config),
      mStream(stream),
      mCallback(callback)
    {}

status_t MmapStreamInterface::createMmapBuffer(
        int32_t minSizeFrames, struct audio_mmap_buffer_info* info) {
    media::MmapBufferInfo bufferInfo;
    RETURN_STATUS_IF_ERROR(
            statusTFromBinderStatus(mStream->createMmapBuffer(minSizeFrames, &bufferInfo)));
    info->shared_memory_address = nullptr; // local only
    binder::unique_fd ufd(bufferInfo.sharedFd.release());
    info->shared_memory_fd = ufd.release();
    info->buffer_size_frames = bufferInfo.bufferSizeFrames;
    info->burst_size_frames = bufferInfo.burstSizeFrames;
    info->flags = (audio_mmap_buffer_flag)bufferInfo.flags;
    ALOGD("%s:  bptr: %p  buffer_size_frames: %d  burst_size_frames: %d  flags:%#x",
            __func__,  &bufferInfo, bufferInfo.bufferSizeFrames,
            bufferInfo.burstSizeFrames, bufferInfo.flags);
    return NO_ERROR;
}

status_t MmapStreamInterface::getMmapPosition(struct audio_mmap_position* position) {
    media::IMmapStream::MmapStreamPosition aidlPosition;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->getMmapPosition(&aidlPosition)));
    position->time_nanoseconds = aidlPosition.timeNanos;
    position->position_frames = aidlPosition.positionFrames;
    return NO_ERROR;
}

status_t MmapStreamInterface::getObservablePosition(uint64_t* position, int64_t* timeNanos) {
    media::IMmapStream::MmapObservablePosition observablePosition;
    RETURN_STATUS_IF_ERROR(
            statusTFromBinderStatus(mStream->getObservablePosition(&observablePosition)));
    *position = observablePosition.positionFrames;
    *timeNanos = observablePosition.timeNanos;
    return NO_ERROR;
}

status_t MmapStreamInterface::createTrack(
        const AudioClient& client, const audio_attributes_t& attr,
        audio_port_handle_t* portId, audio_io_handle_t* ioHandle) {
    const auto aidlClient = VALUE_OR_RETURN_STATUS(legacy2aidl_AudioClient_AudioClient(client));
    android::media::audio::common::AudioAttributes aidlAttr =
            VALUE_OR_RETURN_STATUS(legacy2aidl_audio_attributes_t_AudioAttributes(attr));
    media::IMmapStream::MmapCreateTrackResponse response;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mStream->createTrack(aidlClient, aidlAttr, &response)));
    *portId = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_port_handle_t(response.portId));
    *ioHandle = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_io_handle_t(response.ioHandle));
    return NO_ERROR;
}

status_t MmapStreamInterface::startTrack(audio_port_handle_t portId) {
    const int32_t aidlPortId =
            VALUE_OR_RETURN_STATUS(legacy2aidl_audio_port_handle_t_int32_t(portId));

    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->startTrack(aidlPortId)));
    return NO_ERROR;
}

status_t MmapStreamInterface::stopTrack(audio_port_handle_t portId) {
    const int32_t aidlPortId =
            VALUE_OR_RETURN_STATUS(legacy2aidl_audio_port_handle_t_int32_t(portId));
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->stopTrack(aidlPortId)));
    return NO_ERROR;
}

status_t MmapStreamInterface::releaseTrack(audio_port_handle_t portId) {
    const int32_t aidlPortId =
            VALUE_OR_RETURN_STATUS(legacy2aidl_audio_port_handle_t_int32_t(portId));
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->releaseTrack(aidlPortId)));
    return NO_ERROR;
}

status_t MmapStreamInterface::standby() {
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->standby()));
    return NO_ERROR;
}

status_t MmapStreamInterface::reportData(const void* buffer, size_t frameCount) {
    const auto* const begin = static_cast<const uint8_t*>(buffer);
    std::vector<uint8_t> aidlBuffer(
            begin, begin + frameCount * audio_bytes_per_sample(mConfig.format));
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->reportData(aidlBuffer)));
    return NO_ERROR;
}

status_t MmapStreamInterface::drain(int64_t wakeUpNanos, bool allowSoftWakeUp,
                                    android::audio_utils::TimerQueue::handle_t* handle) {
    media::TimerQueueHandle aidl;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            mStream->drain(wakeUpNanos, allowSoftWakeUp, &aidl)));
    *handle = VALUE_OR_RETURN_STATUS(
            aidl2legacy_TimerQueueHandle_timer_queue_handle_t(aidl));
    return NO_ERROR;
}

status_t MmapStreamInterface::activate(android::audio_utils::TimerQueue::handle_t handle) {
    media::TimerQueueHandle aidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_timer_queue_handle_t_TimerQueueHandle(handle));
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->activate(aidl)));
    return NO_ERROR;
}

status_t MmapStreamInterface::setPlaybackParameters(const AudioPlaybackRate& rate) {
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->setPlaybackParameters(rate)));
    return NO_ERROR;
}

status_t MmapStreamInterface::getPlaybackParameters(AudioPlaybackRate* rate) {
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mStream->getPlaybackParameters(rate)));
    return NO_ERROR;
}

} // namespace android
