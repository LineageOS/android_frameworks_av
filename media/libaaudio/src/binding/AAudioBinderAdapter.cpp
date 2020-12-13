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

AAudioBinderAdapter::AAudioBinderAdapter(IAAudioService* delegate)
        : mDelegate(delegate) {}

void AAudioBinderAdapter::registerClient(const android::sp<IAAudioClient>& client) {
    mDelegate->registerClient(client);
}

aaudio_handle_t AAudioBinderAdapter::openStream(const AAudioStreamRequest& request,
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
    return result;
}

aaudio_result_t AAudioBinderAdapter::closeStream(aaudio_handle_t streamHandle) {
    aaudio_result_t result;
    Status status = mDelegate->closeStream(streamHandle, &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::getStreamDescription(aaudio_handle_t streamHandle,
                                                          AudioEndpointParcelable& endpointOut) {
    aaudio_result_t result;
    Endpoint endpoint;
    Status status = mDelegate->getStreamDescription(streamHandle,
                                                    &endpoint,
                                                    &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    endpointOut = std::move(endpoint);
    return result;
}

aaudio_result_t AAudioBinderAdapter::startStream(aaudio_handle_t streamHandle) {
    aaudio_result_t result;
    Status status = mDelegate->startStream(streamHandle, &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::pauseStream(aaudio_handle_t streamHandle) {
    aaudio_result_t result;
    Status status = mDelegate->pauseStream(streamHandle, &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::stopStream(aaudio_handle_t streamHandle) {
    aaudio_result_t result;
    Status status = mDelegate->stopStream(streamHandle, &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::flushStream(aaudio_handle_t streamHandle) {
    aaudio_result_t result;
    Status status = mDelegate->flushStream(streamHandle, &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::registerAudioThread(aaudio_handle_t streamHandle,
                                                         pid_t clientThreadId,
                                                         int64_t periodNanoseconds) {
    aaudio_result_t result;
    Status status = mDelegate->registerAudioThread(streamHandle, clientThreadId, periodNanoseconds, &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

aaudio_result_t AAudioBinderAdapter::unregisterAudioThread(aaudio_handle_t streamHandle,
                                                           pid_t clientThreadId) {
    aaudio_result_t result;
    Status status = mDelegate->unregisterAudioThread(streamHandle, clientThreadId, &result);
    if (!status.isOk()) {
        result = AAudioConvert_androidToAAudioResult(statusTFromBinderStatus(status));
    }
    return result;
}

}  // namespace aaudio
