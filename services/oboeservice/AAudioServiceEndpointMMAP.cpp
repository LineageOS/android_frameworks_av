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
    mRequestedDeviceId = getDeviceId();

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
        if (previousConfig.format == config.format) {
            if (previousConfig.sample_rate == config.sample_rate) {
                config.format = getNextFormatToTry(config.format);
            } else if (!com::android::media::aaudio::sample_rate_conversion()) {
                ALOGI("%s() - AAudio SRC feature not enabled, different rates! %d != %d",
                      __func__, previousConfig.sample_rate, config.sample_rate);
                result = AAUDIO_ERROR_INVALID_RATE;
                break;
            }
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
    audio_port_handle_t deviceId;

    const audio_attributes_t attributes = getAudioAttributesFrom(this);

    deviceId = mRequestedDeviceId;

    const aaudio_direction_t direction = getDirection();

    if (direction == AAUDIO_DIRECTION_OUTPUT) {
        mHardwareTimeOffsetNanos = OUTPUT_ESTIMATED_HARDWARE_OFFSET_NANOS; // frames at DAC later

    } else if (direction == AAUDIO_DIRECTION_INPUT) {
        mHardwareTimeOffsetNanos = INPUT_ESTIMATED_HARDWARE_OFFSET_NANOS; // frames at ADC earlier

    } else {
        ALOGE("%s() invalid direction = %d", __func__, direction);
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }

    const MmapStreamInterface::stream_direction_t streamDirection =
            (direction == AAUDIO_DIRECTION_OUTPUT)
            ? MmapStreamInterface::DIRECTION_OUTPUT
            : MmapStreamInterface::DIRECTION_INPUT;

    const aaudio_session_id_t requestedSessionId = getSessionId();
    audio_session_t sessionId = AAudioConvert_aaudioToAndroidSessionId(requestedSessionId);

    // Open HAL stream. Set mMmapStream
    ALOGD("%s trying to open MMAP stream with format=%#x, "
          "sample_rate=%u, channel_mask=%#x, device=%d",
          __func__, config->format, config->sample_rate,
          config->channel_mask, deviceId);
    const status_t status = MmapStreamInterface::openMmapStream(streamDirection,
                                                                &attributes,
                                                                config,
                                                                mMmapClient,
                                                                &deviceId,
                                                                &sessionId,
                                                                this, // callback
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

    if (deviceId == AAUDIO_UNSPECIFIED) {
        ALOGW("%s() - openMmapStream() failed to set deviceId", __func__);
    }
    setDeviceId(deviceId);

    if (sessionId == AUDIO_SESSION_ALLOCATE) {
        ALOGW("%s() - openMmapStream() failed to set sessionId", __func__);
    }

    const aaudio_session_id_t actualSessionId =
            (requestedSessionId == AAUDIO_SESSION_ID_NONE)
            ? AAUDIO_SESSION_ID_NONE
            : (aaudio_session_id_t) sessionId;
    setSessionId(actualSessionId);

    ALOGD("%s(format = 0x%X) deviceId = %d, sessionId = %d",
          __func__, config->format, getDeviceId(), getSessionId());

    // Create MMAP/NOIRQ buffer.
    result = createMmapBuffer();
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

    ALOGD("%s() got rate = %d, channels = %d channelMask = %#x, deviceId = %d, capacity = %d\n",
          __func__, getSampleRate(), getSamplesPerFrame(), getChannelMask(),
          deviceId, getBufferCapacity());

    ALOGD("%s() got format = 0x%X = %s, frame size = %d, burst size = %d",
          __func__, getFormat(), audio_format_to_string(getFormat()),
          calculateBytesPerFrame(), mFramesPerBurst);

    return result;

error:
    close();
    // restore original requests
    setDeviceId(mRequestedDeviceId);
    setSessionId(requestedSessionId);
    return result;
}

void AAudioServiceEndpointMMAP::close() {
    if (mMmapStream != nullptr) {
        // Needs to be explicitly cleared or CTS will fail but it is not clear why.
        mMmapStream.clear();
        AudioClock::sleepForNanos(100 * AAUDIO_NANOS_PER_MILLISECOND);
    }
}

aaudio_result_t AAudioServiceEndpointMMAP::startStream(sp<AAudioServiceStreamBase> stream,
                                                   audio_port_handle_t *clientHandle __unused) {
    // Start the client on behalf of the AAudio service.
    // Use the port handle that was provided by openMmapStream().
    audio_port_handle_t tempHandle = mPortHandle;
    audio_attributes_t attr = {};
    if (stream != nullptr) {
        attr = getAudioAttributesFrom(stream.get());
    }
    const aaudio_result_t result = startClient(
            mMmapClient, stream == nullptr ? nullptr : &attr, &tempHandle);
    // When AudioFlinger is passed a valid port handle then it should not change it.
    LOG_ALWAYS_FATAL_IF(tempHandle != mPortHandle,
                        "%s() port handle not expected to change from %d to %d",
                        __func__, mPortHandle, tempHandle);
    ALOGV("%s() mPortHandle = %d", __func__, mPortHandle);
    return result;
}

aaudio_result_t AAudioServiceEndpointMMAP::stopStream(sp<AAudioServiceStreamBase> /*stream*/,
                                                      audio_port_handle_t /*clientHandle*/) {
    mFramesTransferred.reset32();

    // Round 64-bit counter up to a multiple of the buffer capacity.
    // This is required because the 64-bit counter is used as an index
    // into a circular buffer and the actual HW position is reset to zero
    // when the stream is stopped.
    mFramesTransferred.roundUp64(getBufferCapacity());

    // Use the port handle that was provided by openMmapStream().
    ALOGV("%s() mPortHandle = %d", __func__, mPortHandle);
    return stopClient(mPortHandle);
}

aaudio_result_t AAudioServiceEndpointMMAP::startClient(const android::AudioClient& client,
                                                       const audio_attributes_t *attr,
                                                       audio_port_handle_t *clientHandle) {
    return mMmapStream == nullptr
            ? AAUDIO_ERROR_NULL
            : AAudioConvert_androidToAAudioResult(mMmapStream->start(client, attr, clientHandle));
}

aaudio_result_t AAudioServiceEndpointMMAP::stopClient(audio_port_handle_t clientHandle) {
    return mMmapStream == nullptr
            ? AAUDIO_ERROR_NULL
            : AAudioConvert_androidToAAudioResult(mMmapStream->stop(clientHandle));
}

aaudio_result_t AAudioServiceEndpointMMAP::standby() {
    return mMmapStream == nullptr
            ? AAUDIO_ERROR_NULL
            : AAudioConvert_androidToAAudioResult(mMmapStream->standby());
}

aaudio_result_t AAudioServiceEndpointMMAP::exitStandby(AudioEndpointParcelable* parcelable) {
    if (mMmapStream == nullptr) {
        return AAUDIO_ERROR_NULL;
    }
    mAudioDataWrapper->reset();
    const aaudio_result_t result = createMmapBuffer();
    if (result == AAUDIO_OK) {
        getDownDataDescription(parcelable);
    }
    return result;
}

// Get free-running DSP or DMA hardware position from the HAL.
aaudio_result_t AAudioServiceEndpointMMAP::getFreeRunningPosition(int64_t *positionFrames,
                                                                int64_t *timeNanos) {
    struct audio_mmap_position position;
    if (mMmapStream == nullptr) {
        return AAUDIO_ERROR_NULL;
    }
    const status_t status = mMmapStream->getMmapPosition(&position);
    ALOGV("%s() status= %d, pos = %d, nanos = %lld\n",
          __func__, status, position.position_frames, (long long) position.time_nanoseconds);
    const aaudio_result_t result = AAudioConvert_androidToAAudioResult(status);
    if (result == AAUDIO_ERROR_UNAVAILABLE) {
        ALOGW("%s(): getMmapPosition() has no position data available", __func__);
    } else if (result != AAUDIO_OK) {
        ALOGE("%s(): getMmapPosition() returned status %d", __func__, status);
    } else {
        // Convert 32-bit position to 64-bit position.
        mFramesTransferred.update32(position.position_frames);
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
};

// This is called by AudioFlinger when it wants to destroy a stream.
void AAudioServiceEndpointMMAP::onTearDown(audio_port_handle_t portHandle) {
    ALOGD("%s(portHandle = %d) called", __func__, portHandle);
    const android::sp<AAudioServiceEndpointMMAP> holdEndpoint(this);
    std::thread asyncTask([holdEndpoint, portHandle]() {
        holdEndpoint->handleTearDownAsync(portHandle);
    });
    asyncTask.detach();
}

void AAudioServiceEndpointMMAP::onVolumeChanged(float volume) {
    ALOGD("%s() volume = %f", __func__, volume);
    const std::lock_guard<std::mutex> lock(mLockStreams);
    for(const auto& stream : mRegisteredStreams) {
        stream->onVolumeChanged(volume);
    }
};

void AAudioServiceEndpointMMAP::onRoutingChanged(audio_port_handle_t portHandle) {
    const auto deviceId = static_cast<int32_t>(portHandle);
    ALOGD("%s() called with dev %d, old = %d", __func__, deviceId, getDeviceId());
    if (getDeviceId() != deviceId) {
        if (getDeviceId() != AUDIO_PORT_HANDLE_NONE) {
            // When there is a routing changed, mmap stream should be disconnected. Set `mConnected`
            // as false here so that there won't be a new stream connect to this endpoint.
            mConnected.store(false);
            const android::sp<AAudioServiceEndpointMMAP> holdEndpoint(this);
            std::thread asyncTask([holdEndpoint, deviceId]() {
                ALOGD("onRoutingChanged() asyncTask launched");
                // When routing changed, the stream is disconnected and cannot be used except for
                // closing. In that case, it should be safe to release all registered streams.
                // This can help release service side resource in case the client doesn't close
                // the stream after receiving disconnect event.
                holdEndpoint->releaseRegisteredStreams();
                holdEndpoint->setDeviceId(deviceId);
            });
            asyncTask.detach();
        } else {
            setDeviceId(deviceId);
        }
    }
};

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

aaudio_result_t AAudioServiceEndpointMMAP::getExternalPosition(uint64_t *positionFrames,
                                                               int64_t *timeNanos)
{
    if (mHalExternalPositionStatus != AAUDIO_OK) {
        return mHalExternalPositionStatus;
    }
    uint64_t tempPositionFrames;
    int64_t tempTimeNanos;
    const status_t status = mMmapStream->getExternalPosition(&tempPositionFrames, &tempTimeNanos);
    if (status != OK) {
        // getExternalPosition reports error. The HAL may not support the API. Cache the result
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

aaudio_result_t AAudioServiceEndpointMMAP::createMmapBuffer()
{
    memset(&mMmapBufferinfo, 0, sizeof(struct audio_mmap_buffer_info));
    int32_t minSizeFrames = getBufferCapacity();
    if (minSizeFrames <= 0) { // zero will get rejected
        minSizeFrames = AAUDIO_BUFFER_CAPACITY_MIN;
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
            ALOGW("%s() - exclusive FD cannot be used by client", __func__);
            return AAUDIO_ERROR_UNAVAILABLE;
        }
    }

    // AAudio creates a copy of this FD and retains ownership of the copy.
    // Assume that AudioFlinger will close the original shared_memory_fd.

    mAudioDataWrapper->getDataFileDescriptor().reset(dup(mMmapBufferinfo.shared_memory_fd));
    if (mAudioDataWrapper->getDataFileDescriptor().get() == -1) {
        ALOGE("%s() - could not dup shared_memory_fd", __func__);
        return AAUDIO_ERROR_INTERNAL;
    }

    // Call to HAL to make sure the transport FD was able to be closed by binder.
    // This is a tricky workaround for a problem in Binder.
    // TODO:[b/192048842] When that problem is fixed we may be able to remove or change this code.
    struct audio_mmap_position position;
    mMmapStream->getMmapPosition(&position);

    mFramesPerBurst = mMmapBufferinfo.burst_size_frames;

    return AAUDIO_OK;
}

int64_t AAudioServiceEndpointMMAP::nextDataReportTime() {
    return getDirection() == AAUDIO_DIRECTION_OUTPUT
            ? AudioClock::getNanoseconds() + mDataReportOffsetNanos
            : std::numeric_limits<int64_t>::max();
}

void AAudioServiceEndpointMMAP::reportData() {
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
