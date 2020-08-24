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

namespace aaudio {

AAudioBinderAdapter::AAudioBinderAdapter(android::IAAudioService *delegate)
        : mDelegate(delegate) {}

void AAudioBinderAdapter::registerClient(const android::sp<aaudio::IAAudioClient> &client) {
    mDelegate->registerClient(client);
}

aaudio_handle_t AAudioBinderAdapter::openStream(const AAudioStreamRequest &request,
                                                AAudioStreamConfiguration &configuration) {
    return mDelegate->openStream(request, configuration);
}

aaudio_result_t AAudioBinderAdapter::closeStream(aaudio_handle_t streamHandle) {
    return mDelegate->closeStream(streamHandle);
}

aaudio_result_t AAudioBinderAdapter::getStreamDescription(aaudio_handle_t streamHandle,
                                                          AudioEndpointParcelable &parcelable) {
    return mDelegate->getStreamDescription(streamHandle, parcelable);
}

aaudio_result_t AAudioBinderAdapter::startStream(aaudio_handle_t streamHandle) {
    return mDelegate->startStream(streamHandle);
}

aaudio_result_t AAudioBinderAdapter::pauseStream(aaudio_handle_t streamHandle) {
    return mDelegate->pauseStream(streamHandle);
}

aaudio_result_t AAudioBinderAdapter::stopStream(aaudio_handle_t streamHandle) {
    return mDelegate->stopStream(streamHandle);
}

aaudio_result_t AAudioBinderAdapter::flushStream(aaudio_handle_t streamHandle) {
    return mDelegate->flushStream(streamHandle);
}

aaudio_result_t AAudioBinderAdapter::registerAudioThread(aaudio_handle_t streamHandle,
                                                         pid_t clientThreadId,
                                                         int64_t periodNanoseconds) {
    return mDelegate->registerAudioThread(streamHandle, clientThreadId, periodNanoseconds);
}

aaudio_result_t AAudioBinderAdapter::unregisterAudioThread(aaudio_handle_t streamHandle,
                                                           pid_t clientThreadId) {
    return mDelegate->unregisterAudioThread(streamHandle, clientThreadId);
}

}  // namespace aaudio
