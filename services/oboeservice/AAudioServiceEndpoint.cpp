/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "AAudioServiceEndpoint"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <algorithm>
#include <assert.h>
#include <map>
#include <mutex>
#include <sstream>
#include <vector>

#include <utils/Singleton.h>


#include "core/AudioStreamBuilder.h"

#include "AAudioEndpointManager.h"
#include "AAudioClientTracker.h"
#include "AAudioServiceEndpoint.h"
#include "AAudioServiceStreamShared.h"

using namespace android;  // TODO just import names needed
using namespace aaudio;   // TODO just import names needed

std::string AAudioServiceEndpoint::dump() const {
    std::stringstream result;

    const bool isLocked = AAudio_tryUntilTrue(
            [this]()->bool { return mLockStreams.try_lock(); } /* f */,
            50 /* times */,
            20 /* sleepMs */);
    if (!isLocked) {
        result << "AAudioServiceEndpoint may be deadlocked\n";
    }

    result << "    Direction:            " << ((getDirection() == AAUDIO_DIRECTION_OUTPUT)
                                   ? "OUTPUT" : "INPUT") << "\n";
    result << "    Requested Device Id:  " << mRequestedDeviceId << "\n";
    result << "    Device Id:            " << getDeviceId() << "\n";
    result << "    Sample Rate:          " << getSampleRate() << "\n";
    result << "    Channel Count:        " << getSamplesPerFrame() << "\n";
    result << "    Format:               " << getFormat() << "\n";
    result << "    Frames Per Burst:     " << mFramesPerBurst << "\n";
    result << "    Usage:                " << getUsage() << "\n";
    result << "    ContentType:          " << getContentType() << "\n";
    result << "    InputPreset:          " << getInputPreset() << "\n";
    result << "    Reference Count:      " << mOpenCount << "\n";
    result << "    Session Id:           " << getSessionId() << "\n";
    result << "    Privacy Sensitive:    " << isPrivacySensitive() << "\n";
    result << "    Connected:            " << mConnected.load() << "\n";
    result << "    Registered Streams:" << "\n";
    result << AAudioServiceStreamShared::dumpHeader() << "\n";
    for (const auto& stream : mRegisteredStreams) {
        result << stream->dump() << "\n";
    }

    if (isLocked) {
        mLockStreams.unlock();
    }
    return result.str();
}

// @return true if stream found
bool AAudioServiceEndpoint::isStreamRegistered(audio_port_handle_t portHandle) {
    std::lock_guard<std::mutex> lock(mLockStreams);
    for (const auto& stream : mRegisteredStreams) {
        if (stream->getPortHandle() == portHandle) {
            return true;
        }
    }
    return false;
}

std::vector<android::sp<AAudioServiceStreamBase>>
        AAudioServiceEndpoint::disconnectRegisteredStreams() {
    std::vector<android::sp<AAudioServiceStreamBase>> streamsDisconnected;
    {
        std::lock_guard<std::mutex> lock(mLockStreams);
        mRegisteredStreams.swap(streamsDisconnected);
    }
    mConnected.store(false);
    // We need to stop all the streams before we disconnect them.
    // Otherwise there is a race condition where the first disconnected app
    // tries to reopen a stream as MMAP but is blocked by the second stream,
    // which hasn't stopped yet. Then the first app ends up with a Legacy stream.
    for (const auto &stream : streamsDisconnected) {
        ALOGD("%s() - stop(), port = %d", __func__, stream->getPortHandle());
        stream->stop();
    }
    for (const auto &stream : streamsDisconnected) {
        ALOGD("%s() - disconnect(), port = %d", __func__, stream->getPortHandle());
        stream->disconnect();
    }
    return streamsDisconnected;
}

void AAudioServiceEndpoint::releaseRegisteredStreams() {
    // List of streams to be closed after we disconnect everything.
    std::vector<android::sp<AAudioServiceStreamBase>> streamsToClose
            = disconnectRegisteredStreams();

    // Close outside the lock to avoid recursive locks.
    AAudioService *aaudioService = AAudioClientTracker::getInstance().getAAudioService();
    for (const auto& serviceStream : streamsToClose) {
        ALOGD("%s() - close stream 0x%08X", __func__, serviceStream->getHandle());
        aaudioService->closeStream(serviceStream);
    }
}

aaudio_result_t AAudioServiceEndpoint::registerStream(sp<AAudioServiceStreamBase>stream) {
    std::lock_guard<std::mutex> lock(mLockStreams);
    mRegisteredStreams.push_back(stream);
    return AAUDIO_OK;
}

aaudio_result_t AAudioServiceEndpoint::unregisterStream(sp<AAudioServiceStreamBase>stream) {
    std::lock_guard<std::mutex> lock(mLockStreams);
    mRegisteredStreams.erase(std::remove(
            mRegisteredStreams.begin(), mRegisteredStreams.end(), stream),
                             mRegisteredStreams.end());
    return AAUDIO_OK;
}

bool AAudioServiceEndpoint::matches(const AAudioStreamConfiguration& configuration) {
    if (!mConnected.load()) {
        return false; // Only use an endpoint if it is connected to a device.
    }
    if (configuration.getDirection() != getDirection()) {
        return false;
    }
    if (configuration.getDeviceId() != AAUDIO_UNSPECIFIED &&
        configuration.getDeviceId() != getDeviceId()) {
        return false;
    }
    if (configuration.getSessionId() != AAUDIO_SESSION_ID_ALLOCATE &&
        configuration.getSessionId() != getSessionId()) {
        return false;
    }
    if (configuration.getSampleRate() != AAUDIO_UNSPECIFIED &&
        configuration.getSampleRate() != getSampleRate()) {
        return false;
    }
    if (configuration.getSamplesPerFrame() != AAUDIO_UNSPECIFIED &&
        configuration.getSamplesPerFrame() != getSamplesPerFrame()) {
        return false;
    }
    return true;
}

// static
audio_attributes_t AAudioServiceEndpoint::getAudioAttributesFrom(
        const AAudioStreamParameters *params) {
    if (params == nullptr) {
        return {};
    }
    const aaudio_direction_t direction = params->getDirection();

    const audio_content_type_t contentType =
            AAudioConvert_contentTypeToInternal(params->getContentType());
    // Usage only used for OUTPUT
    const audio_usage_t usage = (direction == AAUDIO_DIRECTION_OUTPUT)
            ? AAudioConvert_usageToInternal(params->getUsage())
            : AUDIO_USAGE_UNKNOWN;
    const audio_source_t source = (direction == AAUDIO_DIRECTION_INPUT)
            ? AAudioConvert_inputPresetToAudioSource(params->getInputPreset())
            : AUDIO_SOURCE_DEFAULT;
    audio_flags_mask_t flags;
    if (direction == AAUDIO_DIRECTION_OUTPUT) {
        flags = AUDIO_FLAG_LOW_LATENCY
            | AAudioConvert_allowCapturePolicyToAudioFlagsMask(params->getAllowedCapturePolicy());
    } else {
        flags = AUDIO_FLAG_LOW_LATENCY
            | AAudioConvert_privacySensitiveToAudioFlagsMask(params->isPrivacySensitive());
    }
    return {
            .content_type = contentType,
            .usage = usage,
            .source = source,
            .flags = flags,
            .tags = "" };
}
