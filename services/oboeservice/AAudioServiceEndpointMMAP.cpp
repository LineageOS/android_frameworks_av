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

#define LOG_TAG "AAudioServiceEndpointMMAP"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <algorithm>
#include <assert.h>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>
#include <utils/Singleton.h>
#include <vector>

#include "AAudioEndpointManager.h"
#include "AAudioServiceEndpoint.h"

#include "core/AudioStreamBuilder.h"
#include "AAudioServiceEndpoint.h"
#include "AAudioServiceStreamShared.h"
#include "AAudioServiceEndpointPlay.h"
#include "AAudioServiceEndpointMMAP.h"

#include <android_media_audio.h>
#include <com_android_media_aaudio.h>

#define AAUDIO_BUFFER_CAPACITY_MIN    (4 * 512)
#define AAUDIO_SAMPLE_RATE_DEFAULT    48000

// This is an estimate of the time difference between the HW and the MMAP time.
// TODO Get presentation timestamps from the HAL instead of using these estimates.
#define OUTPUT_ESTIMATED_HARDWARE_OFFSET_NANOS  (3 * AAUDIO_NANOS_PER_MILLISECOND)
#define INPUT_ESTIMATED_HARDWARE_OFFSET_NANOS   (-1 * AAUDIO_NANOS_PER_MILLISECOND)

#define AAUDIO_MAX_OPEN_ATTEMPTS    10

using namespace android;  // TODO just import names needed
using namespace aaudio;   // TODO just import names needed

AAudioServiceEndpointMMAP::AAudioServiceEndpointMMAP(AAudioService &audioService)
        : mMmapStream(nullptr)
        , mAAudioService(audioService) {}

std::string AAudioServiceEndpointMMAP::dump() const {
    std::stringstream result;

    result << "  MMAP: framesTransferred = " << mFramesTransferred.get();
    result << ", HW nanos = " << mHardwareTimeOffsetNanos;
    result << ", port handle = " << mPortHandle;
    result << ", audio data FD = " << mAudioDataWrapper->getDataFileDescriptor();
    result << "\n";

    result << "    HW Offset Micros:     " <<
                                      (getHardwareTimeOffsetNanos()
                                       / AAUDIO_NANOS_PER_MICROSECOND) << "\n";

    result << AAudioServiceEndpoint::dump();
    return result.str();
}

namespace {

const static std::map<audio_format_t, audio_format_t> NEXT_FORMAT_TO_TRY = {
        {AUDIO_FORMAT_PCM_FLOAT,         AUDIO_FORMAT_PCM_32_BIT},
        {AUDIO_FORMAT_PCM_32_BIT,        AUDIO_FORMAT_PCM_24_BIT_PACKED},
        {AUDIO_FORMAT_PCM_24_BIT_PACKED, AUDIO_FORMAT_PCM_8_24_BIT},
        {AUDIO_FORMAT_PCM_8_24_BIT,      AUDIO_FORMAT_PCM_16_BIT}
};

audio_format_t getNextFormatToTry(audio_format_t curFormat) {
    const auto it = NEXT_FORMAT_TO_TRY.find(curFormat);
    return it != NEXT_FORMAT_TO_TRY.end() ? it->second : curFormat;
}

struct configComp {
    bool operator() (const audio_config_base_t& lhs, const audio_config_base_t& rhs) const {
        if (lhs.sample_rate != rhs.sample_rate) {
            return lhs.sample_rate < rhs.sample_rate;
        } else if (lhs.channel_mask != rhs.channel_mask) {
            return lhs.channel_mask < rhs.channel_mask;
        } else {
            return lhs.format < rhs.format;
        }
    }
};

} // namespace

aaudio_result_t AAudioServiceEndpointMMAP::open(const aaudio::AAudioStreamRequest &request) {
    aaudio_result_t result = AAUDIO_OK;
    mAudioDataWrapper = std::make_unique<SharedMemoryWrapper>();
    copyFrom(request.getConstantConfiguration());
    mRequestedDeviceId = android::getFirstDeviceId(getDeviceIds());

    mMmapClient.attributionSource = request.getAttributionSource();
    // TODO b/182392769: use attribution source util
    mMmapClient.attributionSource.uid = VALUE_OR_FATAL(
        legacy2aidl_uid_t_int32_t(IPCThreadState::self()->getCallingUid()));
    mMmapClient.attributionSource.pid = VALUE_OR_FATAL(
        legacy2aidl_pid_t_int32_t(IPCThreadState::self()->getCallingPid()));

    audio_format_t audioFormat = getFormat();
    int32_t sampleRate = getSampleRate();
    if (sampleRate == AAUDIO_UNSPECIFIED) {
        sampleRate = AAUDIO_SAMPLE_RATE_DEFAULT;
    }

    const aaudio_direction_t direction = getDirection();
    audio_config_base_t config;
    config.format = audioFormat;
    config.sample_rate = sampleRate;
    config.channel_mask = AAudio_getChannelMaskForOpen(
            getChannelMask(), getSamplesPerFrame(), direction == AAUDIO_DIRECTION_INPUT);

    std::set<audio_config_base_t, configComp> configsTried;
    int32_t numberOfAttempts = 0;
    while (numberOfAttempts < AAUDIO_MAX_OPEN_ATTEMPTS) {
        if (configsTried.find(config) != configsTried.end()) {
            // APM returning something that has already tried.
            ALOGW("Have already tried to open with format=%#x and sr=%d, but failed before",
                  config.format, config.sample_rate);
            break;
        }
        configsTried.insert(config);

        audio_config_base_t previousConfig = config;
        result = openWithConfig(&config);
        if (result != AAUDIO_ERROR_UNAVAILABLE) {
            // Return if it is successful or there is an error that is not
            // AAUDIO_ERROR_UNAVAILABLE happens.
            ALOGI("Opened format=%#x sr=%d, with result=%d", previousConfig.format,
                    previousConfig.sample_rate, result);
            break;
        }

        // Try other formats if the config from APM is the same as our current config.
        // Some HALs may report its format support incorrectly.
        if ((previousConfig.format == config.format) &&
                (previousConfig.sample_rate == config.sample_rate)) {
            config.format = getNextFormatToTry(config.format);
        }

        ALOGD("%s() %#x %d failed, perhaps due to format or sample rate. Try again with %#x %d",
                __func__, previousConfig.format, previousConfig.sample_rate, config.format,
                config.sample_rate);
        numberOfAttempts++;
    }
    return result;
}

aaudio_result_t AAudioServiceEndpointMMAP::openWithConfig(
        audio_config_base_t* config) {
    aaudio_result_t result = AAUDIO_OK;
    audio_config_base_t currentConfig = *config;
    android::DeviceIdVector deviceIds;

    const audio_attributes_t attributes = getAudioAttributesFrom(this);

    if (mRequestedDeviceId != AAUDIO_UNSPECIFIED) {
        deviceIds.push_back(mRequestedDeviceId);
    }

    const aaudio_direction_t direction = getDirection();

    if (direction == AAUDIO_DIRECTION_OUTPUT) {
        mHardwareTimeOffsetNanos = OUTPUT_ESTIMATED_HARDWARE_OFFSET_NANOS; // frames at DAC later

    } else if (direction == AAUDIO_DIRECTION_INPUT) {
        mHardwareTimeOffsetNanos = INPUT_ESTIMATED_HARDWARE_OFFSET_NANOS; // frames at ADC earlier

    } else {
        ALOGE("%s() invalid direction = %d", __func__, direction);
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }

    const bool isOutput = direction == AAUDIO_DIRECTION_OUTPUT;

    const aaudio_session_id_t requestedSessionId = getSessionId();
    audio_session_t sessionId = AAudioConvert_aaudioToAndroidSessionId(requestedSessionId);

    // Open HAL stream. Set mMmapStream
    ALOGD("%s trying to open MMAP stream with format=%#x, "
          "sample_rate=%u, channel_mask=%#x, device=%s",
          __func__, config->format, config->sample_rate,
          config->channel_mask, android::toString(deviceIds).c_str());

    audio_offload_info_t* info = nullptr;
    audio_offload_info_t offloadInfo = AUDIO_INFO_INITIALIZER;
    if (getPerformanceMode() == AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
        offloadInfo.format = config->format;
        offloadInfo.sample_rate = config->sample_rate;
        offloadInfo.channel_mask = config->channel_mask;
        offloadInfo.stream_type = AUDIO_STREAM_MUSIC;
        offloadInfo.has_video = false;
        info = &offloadInfo;
    }

    const std::lock_guard<std::mutex> lock(mMmapStreamLock);
    const status_t status = MmapStreamInterface::openMmapStream(
            isOutput,
            attributes,
            config,
            mMmapClient,
            &deviceIds,
            &sessionId,
            this, // callback
            info,
            mMmapStream,
            &mPortHandle);
    ALOGD("%s() mMapClient.attributionSource = %s => portHandle = %d\n",
          __func__, mMmapClient.attributionSource.toString().c_str(), mPortHandle);
    if (status != OK) {
        // This can happen if the resource is busy or the config does
        // not match the hardware.
        ALOGD("%s() - openMmapStream() returned status=%d, suggested format=%#x, sample_rate=%u, "
              "channel_mask=%#x",
              __func__, status, config->format, config->sample_rate, config->channel_mask);
        // Keep the channel mask of the current config
        config->channel_mask = currentConfig.channel_mask;
        return AAUDIO_ERROR_UNAVAILABLE;
    }

    if (deviceIds.empty()) {
        ALOGW("%s() - openMmapStream() failed to set deviceIds", __func__);
    }
    setDeviceIds(deviceIds);

    if (sessionId == AUDIO_SESSION_ALLOCATE) {
        ALOGW("%s() - openMmapStream() failed to set sessionId", __func__);
    }

    const aaudio_session_id_t actualSessionId =
            (requestedSessionId == AAUDIO_SESSION_ID_NONE)
            ? AAUDIO_SESSION_ID_NONE
            : (aaudio_session_id_t) sessionId;
    setSessionId(actualSessionId);

    ALOGD("%s(format = 0x%X) deviceIds = %s, sessionId = %d",
          __func__, config->format, android::toString(getDeviceIds()).c_str(), getSessionId());

    ALOGD("%s bufferCapacity = %d, deviceSampleRate = %d, requestedSampleRate = %d",
          __func__, getBufferCapacity(), config->sample_rate, getSampleRate());

    const int32_t requestedSampleRate = getSampleRate();
    const int32_t deviceSampleRate = config->sample_rate;

    // When sample rate conversion is needed, we use the device sample rate and the
    // requested sample rate to scale the capacity in configureDataInformation().
    // Thus, we should scale the capacity here to cancel out the
    // (requestedSampleRate / deviceSampleRate) scaling there.
    if (requestedSampleRate != AAUDIO_UNSPECIFIED && requestedSampleRate != deviceSampleRate) {
        setBufferCapacity(static_cast<int64_t>(getBufferCapacity()) * deviceSampleRate /
                          requestedSampleRate);
    }

    // Create MMAP/NOIRQ buffer.
    result = createMmapBuffer_l();
    if (result != AAUDIO_OK) {
        goto error;
    }

    // Get information about the stream and pass it back to the caller.
    setChannelMask(AAudioConvert_androidToAAudioChannelMask(
            config->channel_mask, getDirection() == AAUDIO_DIRECTION_INPUT,
            AAudio_isChannelIndexMask(config->channel_mask)));

    setFormat(config->format);
    setSampleRate(config->sample_rate);
    setHardwareSampleRate(getSampleRate());
    setHardwareFormat(getFormat());
    setHardwareSamplesPerFrame(AAudioConvert_channelMaskToCount(getChannelMask()));

    // If the position is not updated while the timestamp is updated for more than a certain amount,
    // the timestamp reported from the HAL may not be accurate. Here, a timestamp grace period is
    // set as 5 burst size. We may want to update this value if there is any report from OEMs saying
    // that is too short.
    static constexpr int kTimestampGraceBurstCount = 5;
    mTimestampGracePeriodMs = ((int64_t) kTimestampGraceBurstCount * mFramesPerBurst
            * AAUDIO_MILLIS_PER_SECOND) / getSampleRate();

    mDataReportOffsetNanos = ((int64_t)mTimestampGracePeriodMs) * AAUDIO_NANOS_PER_MILLISECOND;

    ALOGD("%s() got rate = %d, channels = %d channelMask = %#x, deviceIds = %s, capacity = %d\n",
          __func__, getSampleRate(), getSamplesPerFrame(), getChannelMask(),
          android::toString(deviceIds).c_str(), getBufferCapacity());

    ALOGD("%s() got format = 0x%X = %s, frame size = %d, burst size = %d",
          __func__, getFormat(), audio_format_to_string(getFormat()),
          calculateBytesPerFrame(), mFramesPerBurst);

    return result;

error:
    close_l();
    // restore original requests
    android::DeviceIdVector requestedDeviceIds;
    if (mRequestedDeviceId != AAUDIO_UNSPECIFIED) {
        requestedDeviceIds.push_back(mRequestedDeviceId);
    }
    setDeviceIds(requestedDeviceIds);
    setSessionId(requestedSessionId);
    return result;
}

void AAudioServiceEndpointMMAP::close() {
    bool closedIt = false;
    {
        const std::lock_guard<std::mutex> lock(mMmapStreamLock);
        closedIt = close_l();
    }
    if (closedIt) {
        // TODO Why is this needed?
        AudioClock::sleepForNanos(100 * AAUDIO_NANOS_PER_MILLISECOND);
    }
}

bool AAudioServiceEndpointMMAP::close_l() { // requires mMmapStreamLock
    bool closedIt = false;
    if (mMmapStream != nullptr) {
        // Needs to be explicitly cleared or CTS will fail but it is not clear why.
        ALOGD("%s() clear mMmapStream", __func__);
        mMmapStream.clear();
        closedIt = true;
    }
    return closedIt;
}

aaudio_result_t AAudioServiceEndpointMMAP::startStream(sp<AAudioServiceStreamBase> stream,
                                                       audio_port_handle_t /*clientHandle*/) {
    // Start the client on behalf of the AAudio service.
    // Use the port handle that was provided by openMmapStream().
    audio_attributes_t attr = {};
    if (stream != nullptr) {
        attr = getAudioAttributesFrom(stream.get());
    }
    const aaudio_result_t result = startClient(mPortHandle);
    ALOGV("%s() mPortHandle = %d", __func__, mPortHandle);
    if (result == AAUDIO_OK) {
        std::lock_guard _l(mMmapStreamLock);
        mNeedToCatchUp = true;
    }
    return result;
}

aaudio_result_t AAudioServiceEndpointMMAP::stopStream(sp<AAudioServiceStreamBase> /*stream*/,
                                                      audio_port_handle_t clientHandle) {
    // Round 64-bit counter up to a multiple of the buffer capacity.
    // This is required because the 64-bit counter is used as an index
    // into a circular buffer and the actual HW position is reset to zero
    // when the stream is stopped.
    mFramesTransferred.roundUp64(getBufferCapacity());

    // Use the port handle that was provided by openMmapStream().
    aaudio_result_t result = stopClient(mPortHandle);
    ALOGD("%s(%d): called stopClient(%d=mPortHandle), returning %d", __func__,
          (int)clientHandle, mPortHandle, result);
    return result;
}

aaudio_result_t AAudioServiceEndpointMMAP::createClient(const android::AudioClient& client,
                                                        const audio_attributes_t& attr,
                                                        audio_port_handle_t* clientHandle,
                                                        audio_io_handle_t* ioHandle) {
    const std::lock_guard<std::mutex> lock(mMmapStreamLock);
    if (mMmapStream == nullptr) {
        ALOGW("%s(): called after mMmapStream set to NULL", __func__);
        return AAUDIO_ERROR_NULL;
    } else if (!isConnected()) {
        ALOGD("%s(): MMAP stream was disconnected", __func__);
        return AAUDIO_ERROR_DISCONNECTED;
    }
    return AAudioConvert_androidToAAudioResult(
            mMmapStream->createTrack(client, attr, clientHandle, ioHandle));
}

aaudio_result_t AAudioServiceEndpointMMAP::startClient(audio_port_handle_t clientHandle) {
    const std::lock_guard<std::mutex> lock(mMmapStreamLock);
    if (mMmapStream == nullptr) {
        ALOGW("%s(): called after mMmapStream set to NULL", __func__);
        return AAUDIO_ERROR_NULL;
    } else if (!isConnected()) {
        ALOGD("%s(): MMAP stream was disconnected", __func__);
        return AAUDIO_ERROR_DISCONNECTED;
    } else {
        aaudio_result_t result =
                AAudioConvert_androidToAAudioResult(mMmapStream->startTrack(clientHandle));
        if (!isConnected()) {
            ALOGD("%s(): MMAP stream DISCONNECTED after starting port %d, will stop it",
                  __func__, clientHandle);
            mMmapStream->stopTrack(clientHandle);
            result = AAUDIO_ERROR_DISCONNECTED;
        }
        ALOGD("%s(%d): returning result %d", __func__, clientHandle, result);
        return result;
    }
}

aaudio_result_t AAudioServiceEndpointMMAP::stopClient(audio_port_handle_t clientHandle) {
    const std::lock_guard<std::mutex> lock(mMmapStreamLock);
    if (mMmapStream == nullptr) {
        ALOGE("%s(%d): called after mMmapStream set to NULL", __func__, clientHandle);
        return AAUDIO_ERROR_NULL;
    } else {
        aaudio_result_t result = AAudioConvert_androidToAAudioResult(
                mMmapStream->stopTrack(clientHandle));
        ALOGD("%s(%d): returning %d", __func__, clientHandle, result);
        return result;
    }
}

aaudio_result_t AAudioServiceEndpointMMAP::releaseClient(audio_port_handle_t clientHandle) {
    const std::lock_guard<std::mutex> lock(mMmapStreamLock);
    if (mMmapStream == nullptr) {
        ALOGE("%s(%d): called after mMmapStream set to NULL", __func__, clientHandle);
        return AAUDIO_ERROR_NULL;
    } else {
        aaudio_result_t result = AAudioConvert_androidToAAudioResult(
                mMmapStream->releaseTrack(clientHandle));
        ALOGD("%s(%d): returning %d", __func__, clientHandle, result);
        return result;
    }
}

void AAudioServiceEndpointMMAP::releaseClientWhenWakeUp(audio_port_handle_t /*clientHandle*/) {
    // For MMAP endpoint, there should only be one client. Using a boolean value to record if
    // the client should be released when wake up.
    std::lock_guard _l(mLockStreams);
    mShouldReleaseClientWhenWakeUp = true;
}

aaudio_result_t AAudioServiceEndpointMMAP::standby() {
    const std::lock_guard<std::mutex> lock(mMmapStreamLock);
    if (mMmapStream == nullptr) {
        ALOGW("%s(): called after mMmapStream set to NULL", __func__);
        return AAUDIO_ERROR_NULL;
    } else {
        return AAudioConvert_androidToAAudioResult(mMmapStream->standby());
    }
}

aaudio_result_t AAudioServiceEndpointMMAP::exitStandby(AudioEndpointParcelable* parcelable) {
    const std::lock_guard<std::mutex> lock(mMmapStreamLock);
    if (mMmapStream == nullptr) {
        return AAUDIO_ERROR_NULL;
    }
    mAudioDataWrapper->reset();
    const aaudio_result_t result = createMmapBuffer_l();
    if (result == AAUDIO_OK) {
        getDownDataDescription(parcelable);
    }
    return result;
}

aaudio_result_t AAudioServiceEndpointMMAP::drain(
        int64_t wakeUpNanos, bool allowSoftWakeUp,
        android::audio_utils::TimerQueue::handle_t* handle) {
    std::lock_guard<std::mutex> lock(mMmapStreamLock);
    if (mMmapStream == nullptr) {
        return AAUDIO_ERROR_NULL;
    }
    return AAudioConvert_androidToAAudioResult(
            mMmapStream->drain(wakeUpNanos, allowSoftWakeUp, handle));
}

aaudio_result_t AAudioServiceEndpointMMAP::activate(
        android::audio_utils::TimerQueue::handle_t handle) {
    const std::lock_guard lock(mMmapStreamLock);
    if (mMmapStream == nullptr) {
        return AAUDIO_ERROR_NULL;
    }
    return AAudioConvert_androidToAAudioResult(mMmapStream->activate(handle));
}

namespace {

[[clang::no_destroy]] static const std::map<android::status_t, aaudio_result_t>
        kPlaybackParametersResultMap = {
        {android::INVALID_OPERATION, AAUDIO_ERROR_UNIMPLEMENTED},
};

} // namespace

aaudio_result_t AAudioServiceEndpointMMAP::setPlaybackParameters(
        const android::media::audio::common::AudioPlaybackRate& rate) {
    const std::lock_guard lock(mMmapStreamLock);
    if (mMmapStream == nullptr) {
        return AAUDIO_ERROR_NULL;
    }
    const status_t status = mMmapStream->setPlaybackParameters(rate);
    ALOGW_IF(status != NO_ERROR, "%s, returned status=%d", __func__, status);
    // The internal conversion will convert INVALID_OPERATION to AAUDIO_ERROR_INVALID_STATE.
    // When INVALID_OPERATION is returned, it indicates the HAL doesn't support playback parameters.
    // In that case, use a customized map to convert INVALID_OPERATION to
    // AAUDIO_ERROR_UNIMPLEMENTED.
    return AAudioConvert_androidToAAudioResult(status, kPlaybackParametersResultMap);
}

aaudio_result_t AAudioServiceEndpointMMAP::getPlaybackParameters(
        android::media::audio::common::AudioPlaybackRate* rate) {
    const std::lock_guard lock(mMmapStreamLock);
    if (mMmapStream == nullptr) {
        return AAUDIO_ERROR_NULL;
    }
    const status_t status = mMmapStream->getPlaybackParameters(rate);
    ALOGW_IF(status != NO_ERROR, "%s, returned status=%d", __func__, status);
    // The internal conversion will convert INVALID_OPERATION to AAUDIO_ERROR_INVALID_STATE.
    // When INVALID_OPERATION is returned, it indicates the HAL doesn't support playback parameters.
    // In that case, use a customized map to convert INVALID_OPERATION to
    // AAUDIO_ERROR_UNIMPLEMENTED.
    return AAudioConvert_androidToAAudioResult(status, kPlaybackParametersResultMap);
}

// Get free-running DSP or DMA hardware position from the HAL.
aaudio_result_t AAudioServiceEndpointMMAP::getFreeRunningPosition(int64_t *positionFrames,
                                                                int64_t *timeNanos) {
    const std::lock_guard<std::mutex> lock(mMmapStreamLock);
    if (mMmapStream == nullptr) {
        ALOGW("%s(): called after mMmapStream set to NULL", __func__);
        return AAUDIO_ERROR_NULL;
    }
    struct audio_mmap_position position;
    const status_t status = mMmapStream->getMmapPosition(&position);
    ALOGV("%s() status= %d, pos = %d, nanos = %lld\n",
          __func__, status, position.position_frames, (long long) position.time_nanoseconds);

    const aaudio_result_t result = AAudioConvert_androidToAAudioResult(status);
    if (result == AAUDIO_ERROR_UNAVAILABLE) {
        ALOGW("%s(): getMmapPosition() has no position data available", __func__);
    } else if (result != AAUDIO_OK) {
        ALOGE("%s(): getMmapPosition() returned status %d", __func__, status);
    } else {
        if (mNeedToCatchUp) {
            // This only happens for the first position report from HAL. The HAL is supposed to
            // report the position increasing monotonically. But this may not always be true
            // especially when the stream is in standby and release the mmap buffer. In that case,
            // for the first position report, make sure the position is offset correctly as the
            // hardware is reading from the returned position.
            const int pos = position.position_frames % getBufferCapacity();
            // The position reported from the HAL is the where the DSP read position is. The mmap
            // buffer is a circular buffer. mFramesTransferred is rounded up to multiple times of
            // buffer capacity when stopping the stream. mFramesTransferred is used to send as the
            // read position to the client side. In that case, it is needed to increment `pos` so
            // that it represents the right DSP reading position.
            mFramesTransferred.increment(pos);
            mFramesTransferred.set32(position.position_frames);
            mNeedToCatchUp = false;
        } else {
            // Convert 32-bit position to 64-bit position.
            mFramesTransferred.update32(position.position_frames);
        }
        *positionFrames = mFramesTransferred.get();
        *timeNanos = position.time_nanoseconds;
    }
    return result;
}

aaudio_result_t AAudioServiceEndpointMMAP::getTimestamp(int64_t* /*positionFrames*/,
                                                        int64_t* /*timeNanos*/) {
    return 0; // TODO
}

// This is called by onTearDown() in a separate thread to avoid deadlocks.
void AAudioServiceEndpointMMAP::handleTearDownAsync(audio_port_handle_t portHandle) {
    // Are we tearing down the EXCLUSIVE MMAP stream?
    if (isStreamRegistered(portHandle)) {
        ALOGD("%s(%d) tearing down this entire MMAP endpoint", __func__, portHandle);
        disconnectRegisteredStreams();
    } else {
        // Must be a SHARED stream?
        ALOGD("%s(%d) disconnect a specific stream", __func__, portHandle);
        const aaudio_result_t result = mAAudioService.disconnectStreamByPortHandle(portHandle);
        ALOGD("%s(%d) disconnectStreamByPortHandle returned %d", __func__, portHandle, result);
    }
}

// This is called by AudioFlinger when it wants to destroy a stream.
void AAudioServiceEndpointMMAP::onTearDown(audio_port_handle_t portHandle) {
    ALOGD("%s(portHandle = %d) called", __func__, portHandle);
    const android::sp<AAudioServiceEndpointMMAP> holdEndpoint(this);
    AAudioThread::getAsyncCommandThread().add("EndpointMMAP::onTearDown",
                                        [holdEndpoint, portHandle]() {
        holdEndpoint->handleTearDownAsync(portHandle);
    });
}

void AAudioServiceEndpointMMAP::onVolumeChanged(float volume) {
    ALOGD("%s() volume = %f", __func__, volume);
    if (std::isnan(volume)) {
        ALOGE("%s reject to set volume as nan", __func__);
        return;
    }
    const std::lock_guard<std::mutex> lock(mLockStreams);
    for (const auto& stream : mRegisteredStreams) {
        stream->onVolumeChanged(volume);
    }
}

void AAudioServiceEndpointMMAP::onRoutingChanged(const android::DeviceIdVector& deviceIds) {
    ALOGD("%s() called with dev %s, old = %s", __func__, android::toString(deviceIds).c_str(),
          android::toString(getDeviceIds()).c_str());
    if (!android::areDeviceIdsEqual(getDeviceIds(), deviceIds)) {
        if (!getDeviceIds().empty()) {
            if (android_media_audio_partial_flush_for_pcm_offload() &&
                getPerformanceMode() == AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED) {
                // Just set the device ids if the performance mode is power saving offload instead
                // of release all registered streams as there is nothing particular different for
                // offload playback when device is changed. The client side will receive a routing
                // changed callback and notify apps if they register a routing changed callback.
                // Note for low latency mode, the HAL may be late reporting position which may cause
                // the client side timeout on reading/writing and get disconnected from the client
                // side.
                setDeviceIds(deviceIds);
            } else {
                // When there is a routing changed, mmap stream should be disconnected. Set
                // `mConnected` as false here so that there won't be a new stream connected
                // to this endpoint.
                mConnected.store(false);
                const android::sp<AAudioServiceEndpointMMAP> holdEndpoint(this);
                AAudioThread::getAsyncCommandThread().add("EndpointMMAP::onRoutingChanged",
                                                    [holdEndpoint, deviceIds]() {
                    ALOGD("onRoutingChanged() asyncTask launched");
                    // When routing changed, the stream is disconnected and cannot be used except
                    // for closing. In that case, it should be safe to release all registered
                    // streams. This can help release service side resource in case the client
                    // doesn't close the stream after receiving disconnect event.
                    holdEndpoint->releaseRegisteredStreams();
                    holdEndpoint->setDeviceIds(deviceIds);
                });
            }
        } else {
            setDeviceIds(deviceIds);
        }
    }
}

void AAudioServiceEndpointMMAP::onSoundDoseChanged(bool active) {
    ALOGD("%s() active = %s", __func__, active ? "true" : "false");
    const std::lock_guard lock(mLockStreams);
    for (const auto& stream : mRegisteredStreams) {
        stream->onSoundDoseChanged(active);
    }
}

void AAudioServiceEndpointMMAP::onWakeUp(android::audio_utils::TimerQueue::handle_t handle) {
    const std::lock_guard<std::mutex> lock(mLockStreams);
    for (const auto& stream : mRegisteredStreams) {
        stream->onWakeUp(handle);
    }
    if (mShouldReleaseClientWhenWakeUp) {
        // When the client is pending to wake up to release, it indicates the client side has
        // called close and it has gone. It was previously pending to drain all written data.
        // Here, a thread is spawned to release the stream to avoid dead lock.
        const android::sp<AAudioServiceEndpointMMAP> holdEndpoint(this);
        AAudioThread::getAsyncCommandThread().add("EndpointMMAP::onWakeUp",
                                            [holdEndpoint]() {
            ALOGD("onWakeUp() asyncTask to release client");
            holdEndpoint->releaseRegisteredStreams();
        });
    }
}

/**
 * Get an immutable description of the data queue from the HAL.
 */
aaudio_result_t AAudioServiceEndpointMMAP::getDownDataDescription(
        AudioEndpointParcelable* parcelable)
{
    if (mAudioDataWrapper->setupFifoBuffer(calculateBytesPerFrame(), getBufferCapacity())
        != AAUDIO_OK) {
        ALOGE("Failed to setup audio data wrapper, will not be able to "
              "set data for sound dose computation");
        // This will not affect the audio processing capability
    }
    // Gather information on the data queue based on HAL info.
    mAudioDataWrapper->fillParcelable(parcelable, parcelable->mDownDataQueueParcelable,
                                      calculateBytesPerFrame(), mFramesPerBurst,
                                      getBufferCapacity(),
                                      getDirection() == AAUDIO_DIRECTION_OUTPUT
                                              ? SharedMemoryWrapper::WRITE
                                              : SharedMemoryWrapper::NONE);
    return AAUDIO_OK;
}

aaudio_result_t AAudioServiceEndpointMMAP::getObservablePosition(
        uint64_t *positionFrames, int64_t *timeNanos)
{
    const std::lock_guard<std::mutex> lock(mMmapStreamLock);
    if (mHalExternalPositionStatus != AAUDIO_OK) {
        return mHalExternalPositionStatus;
    }
    if (mMmapStream == nullptr) {
        ALOGW("%s(): called after mMmapStream set to NULL", __func__);
        return AAUDIO_ERROR_NULL;
    }
    uint64_t tempPositionFrames;
    int64_t tempTimeNanos;
    const status_t status = mMmapStream->getObservablePosition(
            &tempPositionFrames, &tempTimeNanos);
    if (status != OK) {
        // getObservablePosition reports error. The HAL may not support the API. Cache the result
        // so that the call will not go to the HAL next time.
        mHalExternalPositionStatus = AAudioConvert_androidToAAudioResult(status);
        return mHalExternalPositionStatus;
    }

    // If the HAL keeps reporting the same position or timestamp, the HAL may be having some issues
    // to report correct external position. In that case, we will not trust the values reported from
    // the HAL. Ideally, we may want to stop querying external position if the HAL cannot report
    // correct position within a period. But it may not be a good idea to get system time too often.
    // In that case, a maximum number of frozen external position is defined so that if the
    // count of the same timestamp or position is reported by the HAL continuously, the values from
    // the HAL will no longer be trusted.
    static constexpr int kMaxFrozenCount = 20;
    // If the HAL version is less than 7.0, the getPresentationPosition is an optional API.
    // If the HAL version is 7.0 or later, the getPresentationPosition is a mandatory API.
    // In that case, even the returned status is NO_ERROR, it doesn't indicate the returned
    // position is a valid one. Do a simple validation, which is checking if the position is
    // forward within half a second or not, here so that this function can return error if
    // the validation fails. Note that we don't only apply this validation logic to HAL API
    // less than 7.0. The reason is that there is a chance the HAL is not reporting the
    // timestamp and position correctly.
    if (mLastPositionFrames > tempPositionFrames) {
        // If the position is going backwards, there must be something wrong with the HAL.
        // In that case, we do not trust the values reported by the HAL.
        ALOGW("%s position is going backwards, last position(%jd) current position(%jd)",
              __func__, mLastPositionFrames, tempPositionFrames);
        mHalExternalPositionStatus = AAUDIO_ERROR_INTERNAL;
        return mHalExternalPositionStatus;
    } else if (mLastPositionFrames == tempPositionFrames) {
        if (tempTimeNanos - mTimestampNanosForLastPosition >
                AAUDIO_NANOS_PER_MILLISECOND * mTimestampGracePeriodMs) {
            ALOGW("%s, the reported position is not changed within %d msec. "
                  "Set the external position as not supported", __func__, mTimestampGracePeriodMs);
            mHalExternalPositionStatus = AAUDIO_ERROR_INTERNAL;
            return mHalExternalPositionStatus;
        }
        mFrozenPositionCount++;
    } else {
        mFrozenPositionCount = 0;
    }

    if (mTimestampNanosForLastPosition > tempTimeNanos) {
        // If the timestamp is going backwards, there must be something wrong with the HAL.
        // In that case, we do not trust the values reported by the HAL.
        ALOGW("%s timestamp is going backwards, last timestamp(%jd), current timestamp(%jd)",
              __func__, mTimestampNanosForLastPosition, tempTimeNanos);
        mHalExternalPositionStatus = AAUDIO_ERROR_INTERNAL;
        return mHalExternalPositionStatus;
    } else if (mTimestampNanosForLastPosition == tempTimeNanos) {
        mFrozenTimestampCount++;
    } else {
        mFrozenTimestampCount = 0;
    }

    if (mFrozenTimestampCount + mFrozenPositionCount > kMaxFrozenCount) {
        ALOGW("%s too many frozen external position from HAL.", __func__);
        mHalExternalPositionStatus = AAUDIO_ERROR_INTERNAL;
        return mHalExternalPositionStatus;
    }

    mLastPositionFrames = tempPositionFrames;
    mTimestampNanosForLastPosition = tempTimeNanos;

    // Only update the timestamp and position when they looks valid.
    *positionFrames = tempPositionFrames;
    *timeNanos = tempTimeNanos;
    return mHalExternalPositionStatus;
}

// mMmapStreamLock should be held when calling this function.
aaudio_result_t AAudioServiceEndpointMMAP::createMmapBuffer_l()
{
    memset(&mMmapBufferinfo, 0, sizeof(struct audio_mmap_buffer_info));
    int32_t minSizeFrames = getBufferCapacity();
    if (minSizeFrames <= 0) { // zero will get rejected
        minSizeFrames = AAUDIO_BUFFER_CAPACITY_MIN;
    }

    if (mMmapStream == nullptr) {
        ALOGW("%s(): called after mMmapStream set to NULL", __func__);
        return AAUDIO_ERROR_NULL;
    }

    const status_t status = mMmapStream->createMmapBuffer(minSizeFrames, &mMmapBufferinfo);
    const bool isBufferShareable = mMmapBufferinfo.flags & AUDIO_MMAP_APPLICATION_SHAREABLE;
    if (status != OK) {
        ALOGE("%s() - createMmapBuffer() failed with status %d %s",
              __func__, status, strerror(-status));
        return AAUDIO_ERROR_UNAVAILABLE;
    } else {
        ALOGD("%s() createMmapBuffer() buffer_size = %d fr, burst_size %d fr"
                      ", Sharable FD: %s",
              __func__,
              mMmapBufferinfo.buffer_size_frames,
              mMmapBufferinfo.burst_size_frames,
              isBufferShareable ? "Yes" : "No");
    }

    setBufferCapacity(mMmapBufferinfo.buffer_size_frames);
    if (!isBufferShareable) {
        // Exclusive mode can only be used by the service because the FD cannot be shared.
        const int32_t audioServiceUid =
            VALUE_OR_FATAL(legacy2aidl_uid_t_int32_t(getuid()));
        if ((mMmapClient.attributionSource.uid != audioServiceUid) &&
            getSharingMode() == AAUDIO_SHARING_MODE_EXCLUSIVE) {
            ::close(mMmapBufferinfo.shared_memory_fd);  // must close the fd as no new owner.
            ALOGW("%s() - exclusive FD cannot be used by client", __func__);
            return AAUDIO_ERROR_UNAVAILABLE;
        }
    }

    // AAudio uses the copy of the shared_memory_fd transferred through the
    // parcel. There is no need to dup the descriptor.
    mAudioDataWrapper->getDataFileDescriptor().reset(mMmapBufferinfo.shared_memory_fd);
    if (mAudioDataWrapper->getDataFileDescriptor().get() == -1) {
        ALOGE("%s() - could not dup shared_memory_fd", __func__);
        return AAUDIO_ERROR_INTERNAL;
    }

    // Call to HAL to make sure the transport FD was able to be closed by binder.
    // This is a tricky workaround for a problem in Binder.
    // TODO:[b/192048842] When that problem is fixed we may be able to remove or change this code.
    ALOGD("%s() - call getMmapPosition() as a hack to clear FD stuck in Binder", __func__);
    struct audio_mmap_position position;
    mMmapStream->getMmapPosition(&position);

    mFramesPerBurst = mMmapBufferinfo.burst_size_frames;

    mFramesTransferred.reset32();

    return AAUDIO_OK;
}

int64_t AAudioServiceEndpointMMAP::nextDataReportTime() {
    return getDirection() == AAUDIO_DIRECTION_OUTPUT
            ? AudioClock::getNanoseconds() + mDataReportOffsetNanos
            : std::numeric_limits<int64_t>::max();
}

void AAudioServiceEndpointMMAP::reportData() {
    const std::lock_guard<std::mutex> lock(mMmapStreamLock);

    if (mMmapStream == nullptr) {
        // This must not happen
        ALOGE("%s() invalid state, mmap stream is not initialized", __func__);
        return;
    }

    auto fifo = mAudioDataWrapper->getFifoBuffer();
    if (fifo == nullptr) {
        ALOGE("%s() fifo buffer is not initialized, cannot report data", __func__);
        return;
    }

    WrappingBuffer wrappingBuffer;
    fifo_frames_t framesAvailable = fifo->getFullDataAvailable(&wrappingBuffer);
    for (size_t i = 0; i < WrappingBuffer::SIZE; ++i) {
        if (wrappingBuffer.numFrames[i] > 0) {
            mMmapStream->reportData(wrappingBuffer.data[i], wrappingBuffer.numFrames[i]);
        }
    }
    fifo->advanceReadIndex(framesAvailable);
}
