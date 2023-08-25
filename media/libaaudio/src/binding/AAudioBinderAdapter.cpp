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

#include <binding/AAudioBinderAdapter.h>
#include <media/AidlConversionUtil.h>
#include <utility/AAudioUtilities.h>

namespace aaudio {

using android::aidl_utils::statusTFromBinderStatus;
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

}  // namespace aaudio
