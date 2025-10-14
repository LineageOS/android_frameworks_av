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

#include "AAudioBinderAdapter.h"

// go/keep-sorted start
#include <android/media/audio/common/AudioPlaybackRate.h>
#include <media/AidlConversion.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionUtil.h>
#include <utility/AAudioUtilities.h>
// go/keep-sorted end

namespace aaudio {

using android::aidl_utils::statusTFromBinderStatus;
using android::audio_utils::TimerQueue;
using android::binder::Status;

AAudioBinderAdapter::AAudioBinderAdapter(IAAudioService* delegate,
                                         int32_t serviceLifetimeId)
        : mDelegate(delegate), mServiceLifetimeId(serviceLifetimeId) {}

void AAudioBinderAdapter::registerClient(const android::sp<IAAudioClient>& client) {
    mDelegate->registerClient(client);
}

AAudioHandleInfo AAudioBinderAdapter::openStream(const AAudioStreamRequest& request,
                                                 AAudioStreamConfiguration& config) {
    aaudio_handle_t result;
    StreamParameters params;
    Status status = mDelegate->openStream(request.parcelable(),
                                          &params,
                                          &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    config = params;
    return {mServiceLifetimeId, result};
}

aaudio_result_t AAudioBinderAdapter::closeStream(const AAudioHandleInfo& streamHandleInfo) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    aaudio_result_t result;
    Status status = mDelegate->closeStream(streamHandleInfo.getHandle(), &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::getStreamDescription(const AAudioHandleInfo& streamHandleInfo,
                                                          AudioEndpointParcelable& endpointOut) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    aaudio_result_t result;
    Endpoint endpoint;
    Status status = mDelegate->getStreamDescription(streamHandleInfo.getHandle(),
                                                    &endpoint,
                                                    &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    endpointOut = std::move(endpoint);
    return result;
}

aaudio_result_t AAudioBinderAdapter::startStream(const AAudioHandleInfo& streamHandleInfo) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    aaudio_result_t result;
    Status status = mDelegate->startStream(streamHandleInfo.getHandle(), &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::pauseStream(const AAudioHandleInfo& streamHandleInfo) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    aaudio_result_t result;
    Status status = mDelegate->pauseStream(streamHandleInfo.getHandle(), &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::stopStream(const AAudioHandleInfo& streamHandleInfo) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    aaudio_result_t result;
    Status status = mDelegate->stopStream(streamHandleInfo.getHandle(), &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::flushStream(const AAudioHandleInfo& streamHandleInfo) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    aaudio_result_t result;
    Status status = mDelegate->flushStream(streamHandleInfo.getHandle(), &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::registerAudioThread(const AAudioHandleInfo& streamHandleInfo,
                                                         pid_t clientThreadId,
                                                         int64_t periodNanoseconds) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    aaudio_result_t result;
    Status status = mDelegate->registerAudioThread(
            streamHandleInfo.getHandle(), clientThreadId, periodNanoseconds, &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::unregisterAudioThread(const AAudioHandleInfo& streamHandleInfo,
                                                           pid_t clientThreadId) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    aaudio_result_t result;
    Status status = mDelegate->unregisterAudioThread(
            streamHandleInfo.getHandle(), clientThreadId, &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::exitStandby(const AAudioHandleInfo& streamHandleInfo,
                                                 AudioEndpointParcelable &endpointOut) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    aaudio_result_t result;
    Endpoint endpoint;
    Status status = mDelegate->exitStandby(streamHandleInfo.getHandle(), &endpoint, &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    endpointOut = std::move(endpoint);
    return result;
}

aaudio_result_t AAudioBinderAdapter::updateTimestamp(
        const aaudio::AAudioHandleInfo &streamHandleInfo) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    aaudio_result_t result;
    Status status = mDelegate->updateTimestamp(streamHandleInfo.getHandle(), &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::drainStream(const aaudio::AAudioHandleInfo &streamHandleInfo,
                                                 int64_t wakeUpNanos,
                                                 DrainType drainType,
                                                 TimerQueue::handle_t* handle) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    aaudio_result_t result;
    android::media::TimerQueueHandle aidlHandle;
    Status status = mDelegate->drainStream(
            streamHandleInfo.getHandle(), wakeUpNanos, drainType, &aidlHandle, &result);
    if (!status.isOk()) {
        return AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    auto legacy = android::aidl2legacy_TimerQueueHandle_timer_queue_handle_t(aidlHandle);
    if (!legacy.ok()) {
        return AAudioConvert_androidToAAudioResult(legacy.error());
    }
    *handle = legacy.value();
    return result;
}

aaudio_result_t AAudioBinderAdapter::activateStream(
        const aaudio::AAudioHandleInfo &streamHandleInfo, TimerQueue::handle_t handle) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    aaudio_result_t result;
    auto aidl = android::legacy2aidl_timer_queue_handle_t_TimerQueueHandle(handle);
    if (!aidl.ok()) {
        return AAudioConvert_androidToAAudioResult(aidl.error());
    }
    Status status = mDelegate->activateStream(streamHandleInfo.getHandle(), aidl.value(), &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::setPlaybackParameters(
    const AAudioHandleInfo& streamHandleInfo, const android::AudioPlaybackRate& rate) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    auto aidl = android::legacy2aidl_audio_playback_rate_t_AudioPlaybackRate(rate);
    if (!aidl.ok()) {
        return AAudioConvert_androidToAAudioResult(aidl.error());
    }
    aaudio_result_t result;
    Status status = mDelegate->setPlaybackParameters(
            streamHandleInfo.getHandle(), aidl.value(), &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::getPlaybackParameters(
    const AAudioHandleInfo& streamHandleInfo, android::AudioPlaybackRate* rate) {
    if (streamHandleInfo.getServiceLifetimeId() != mServiceLifetimeId) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    android::media::audio::common::AudioPlaybackRate aidlRate;
    aaudio_result_t result;
    Status status = mDelegate->getPlaybackParameters(
            streamHandleInfo.getHandle(), &aidlRate, &result);
    if (!status.isOk()) {
        return AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    if (result != AAUDIO_OK) {
        return result;
    }
    auto legacy = android::aidl2legacy_AudioPlaybackRate_audio_playback_rate_t(aidlRate);
    if (!legacy.ok()) {
        return AAudioConvert_androidToAAudioResult(legacy.error());
    }
    *rate = legacy.value();
    return result;
}

}  // namespace aaudio
