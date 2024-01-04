/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "AudioStreamInternal"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#define ATRACE_TAG ATRACE_TAG_AUDIO

#include <stdint.h>

#include <binder/IServiceManager.h>

#include <aaudio/AAudio.h>
#include <cutils/properties.h>

#include <media/AudioParameter.h>
#include <media/AudioSystem.h>
#include <media/MediaMetricsItem.h>
#include <utils/Trace.h>

#include "AudioEndpointParcelable.h"
#include "binding/AAudioBinderClient.h"
#include "binding/AAudioStreamRequest.h"
#include "binding/AAudioStreamConfiguration.h"
#include "binding/AAudioServiceMessage.h"
#include "core/AudioGlobal.h"
#include "core/AudioStreamBuilder.h"
#include "fifo/FifoBuffer.h"
#include "utility/AudioClock.h"
#include <media/AidlConversion.h>
#include <com_android_media_aaudio.h>

#include "AudioStreamInternal.h"

// We do this after the #includes because if a header uses ALOG.
// it would fail on the reference to mInService.
#undef LOG_TAG
// This file is used in both client and server processes.
// This is needed to make sense of the logs more easily.
#define LOG_TAG (mInService ? "AudioStreamInternal_Service" : "AudioStreamInternal_Client")

using android::content::AttributionSourceState;

using namespace aaudio;

#define MIN_TIMEOUT_NANOS        (1000 * AAUDIO_NANOS_PER_MILLISECOND)

// Wait at least this many times longer than the operation should take.
#define MIN_TIMEOUT_OPERATIONS    4

#define LOG_TIMESTAMPS            0

// Minimum number of bursts to use when sample rate conversion is used.
#define MIN_SAMPLE_RATE_CONVERSION_NUM_BURSTS    3

AudioStreamInternal::AudioStreamInternal(AAudioServiceInterface  &serviceInterface, bool inService)
        : AudioStream()
        , mClockModel()
        , mInService(inService)
        , mServiceInterface(serviceInterface)
        , mAtomicInternalTimestamp()
        , mWakeupDelayNanos(AAudioProperty_getWakeupDelayMicros() * AAUDIO_NANOS_PER_MICROSECOND)
        , mMinimumSleepNanos(AAudioProperty_getMinimumSleepMicros() * AAUDIO_NANOS_PER_MICROSECOND)
        {

}

AudioStreamInternal::~AudioStreamInternal() {
    ALOGD("%s() %p called", __func__, this);
}

aaudio_result_t AudioStreamInternal::open(const AudioStreamBuilder &builder) {

    aaudio_result_t result = AAUDIO_OK;
    AAudioStreamRequest request;
    AAudioStreamConfiguration configurationOutput;

    if (getState() != AAUDIO_STREAM_STATE_UNINITIALIZED) {
        ALOGE("%s - already open! state = %d", __func__, getState());
        return AAUDIO_ERROR_INVALID_STATE;
    }

    // Copy requested parameters to the stream.
    result = AudioStream::open(builder);
    if (result < 0) {
        return result;
    }

    const audio_format_t requestedFormat = getFormat();
    // We have to do volume scaling. So we prefer FLOAT format.
    if (requestedFormat == AUDIO_FORMAT_DEFAULT) {
        setFormat(AUDIO_FORMAT_PCM_FLOAT);
    }
    // Request FLOAT for the shared mixer or the device.
    request.getConfiguration().setFormat(AUDIO_FORMAT_PCM_FLOAT);

    // TODO b/182392769: use attribution source util
    AttributionSourceState attributionSource;
    attributionSource.uid = VALUE_OR_FATAL(android::legacy2aidl_uid_t_int32_t(getuid()));
    attributionSource.pid = VALUE_OR_FATAL(android::legacy2aidl_pid_t_int32_t(getpid()));
    attributionSource.packageName = builder.getOpPackageName();
    attributionSource.attributionTag = builder.getAttributionTag();
    attributionSource.token = sp<android::BBinder>::make();

    // Build the request to send to the server.
    request.setAttributionSource(attributionSource);
    request.setSharingModeMatchRequired(isSharingModeMatchRequired());
    request.setInService(isInService());

    request.getConfiguration().setDeviceId(getDeviceId());
    request.getConfiguration().setSampleRate(getSampleRate());
    request.getConfiguration().setDirection(getDirection());
    request.getConfiguration().setSharingMode(getSharingMode());
    request.getConfiguration().setChannelMask(getChannelMask());

    request.getConfiguration().setUsage(getUsage());
    request.getConfiguration().setContentType(getContentType());
    request.getConfiguration().setSpatializationBehavior(getSpatializationBehavior());
    request.getConfiguration().setIsContentSpatialized(isContentSpatialized());
    request.getConfiguration().setInputPreset(getInputPreset());
    request.getConfiguration().setPrivacySensitive(isPrivacySensitive());

    request.getConfiguration().setBufferCapacity(builder.getBufferCapacity());

    mServiceStreamHandleInfo = mServiceInterface.openStream(request, configurationOutput);
    if (getServiceHandle() < 0
            && (request.getConfiguration().getSamplesPerFrame() == 1
                    || request.getConfiguration().getChannelMask() == AAUDIO_CHANNEL_MONO)
            && getDirection() == AAUDIO_DIRECTION_OUTPUT
            && !isInService()) {
        // if that failed then try switching from mono to stereo if OUTPUT.
        // Only do this in the client. Otherwise we end up with a mono mixer in the service
        // that writes to a stereo MMAP stream.
        ALOGD("%s() - openStream() returned %d, try switching from MONO to STEREO",
              __func__, getServiceHandle());
        request.getConfiguration().setChannelMask(AAUDIO_CHANNEL_STEREO);
        mServiceStreamHandleInfo = mServiceInterface.openStream(request, configurationOutput);
    }
    if (getServiceHandle() < 0) {
        return getServiceHandle();
    }

    // This must match the key generated in oboeservice/AAudioServiceStreamBase.cpp
    // so the client can have permission to log.
    if (!mInService) {
        // No need to log if it is from service side.
        mMetricsId = std::string(AMEDIAMETRICS_KEY_PREFIX_AUDIO_STREAM)
                     + std::to_string(getServiceHandle());
    }

    android::mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_PERFORMANCEMODE,
                 AudioGlobal_convertPerformanceModeToText(builder.getPerformanceMode()))
            .set(AMEDIAMETRICS_PROP_SHARINGMODE,
                 AudioGlobal_convertSharingModeToText(builder.getSharingMode()))
            .set(AMEDIAMETRICS_PROP_ENCODINGCLIENT,
                 android::toString(requestedFormat).c_str()).record();

    result = configurationOutput.validate();
    if (result != AAUDIO_OK) {
        goto error;
    }
    // Save results of the open.
    if (getChannelMask() == AAUDIO_UNSPECIFIED) {
        setChannelMask(configurationOutput.getChannelMask());
    }

    setDeviceId(configurationOutput.getDeviceId());
    setSessionId(configurationOutput.getSessionId());
    setSharingMode(configurationOutput.getSharingMode());

    setUsage(configurationOutput.getUsage());
    setContentType(configurationOutput.getContentType());
    setSpatializationBehavior(configurationOutput.getSpatializationBehavior());
    setIsContentSpatialized(configurationOutput.isContentSpatialized());
    setInputPreset(configurationOutput.getInputPreset());

    setDeviceSampleRate(configurationOutput.getSampleRate());

    if (getSampleRate() == AAUDIO_UNSPECIFIED) {
        setSampleRate(configurationOutput.getSampleRate());
    }

    if (!com::android::media::aaudio::sample_rate_conversion()) {
        if (getSampleRate() != getDeviceSampleRate()) {
            ALOGD("%s - skipping sample rate converter. SR = %d, Device SR = %d", __func__,
                    getSampleRate(), getDeviceSampleRate());
            result = AAUDIO_ERROR_INVALID_RATE;
            goto error;
        }
    }

    // Save device format so we can do format conversion and volume scaling together.
    setDeviceFormat(configurationOutput.getFormat());
    setDeviceSamplesPerFrame(configurationOutput.getSamplesPerFrame());

    setHardwareSamplesPerFrame(configurationOutput.getHardwareSamplesPerFrame());
    setHardwareSampleRate(configurationOutput.getHardwareSampleRate());
    setHardwareFormat(configurationOutput.getHardwareFormat());

    result = mServiceInterface.getStreamDescription(mServiceStreamHandleInfo, mEndPointParcelable);
    if (result != AAUDIO_OK) {
        goto error;
    }

    // Resolve parcelable into a descriptor.
    result = mEndPointParcelable.resolve(&mEndpointDescriptor);
    if (result != AAUDIO_OK) {
        goto error;
    }

    // Configure endpoint based on descriptor.
    mAudioEndpoint = std::make_unique<AudioEndpoint>();
    result = mAudioEndpoint->configure(&mEndpointDescriptor, getDirection());
    if (result != AAUDIO_OK) {
        goto error;
    }

    if ((result = configureDataInformation(builder.getFramesPerDataCallback())) != AAUDIO_OK) {
        goto error;
    }

    setState(AAUDIO_STREAM_STATE_OPEN);

    return result;

error:
    safeReleaseClose();
    return result;
}

aaudio_result_t AudioStreamInternal::configureDataInformation(int32_t callbackFrames) {
    int32_t originalFramesPerBurst = mEndpointDescriptor.dataQueueDescriptor.framesPerBurst;
    int32_t deviceFramesPerBurst = originalFramesPerBurst;

    // Scale up the burst size to meet the minimum equivalent in microseconds.
    // This is to avoid waking the CPU too often when the HW burst is very small
    // or at high sample rates. The actual number of frames that we call back to
    // the app with will be 0 < N <= framesPerBurst so round up the division.
    int32_t burstMicros = 0;
    const int32_t burstMinMicros = android::AudioSystem::getAAudioHardwareBurstMinUsec();
    do {
        if (burstMicros > 0) {  // skip first loop
            deviceFramesPerBurst *= 2;
        }
        burstMicros = deviceFramesPerBurst * static_cast<int64_t>(1000000) / getDeviceSampleRate();
    } while (burstMicros < burstMinMicros);
    ALOGD("%s() original HW burst = %d, minMicros = %d => SW burst = %d\n",
          __func__, originalFramesPerBurst, burstMinMicros, deviceFramesPerBurst);

    // Validate final burst size.
    if (deviceFramesPerBurst < MIN_FRAMES_PER_BURST
            || deviceFramesPerBurst > MAX_FRAMES_PER_BURST) {
        ALOGE("%s - deviceFramesPerBurst out of range = %d", __func__, deviceFramesPerBurst);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }

    // Calculate the application framesPerBurst from the deviceFramesPerBurst
    int32_t framesPerBurst = (static_cast<int64_t>(deviceFramesPerBurst) * getSampleRate() +
             getDeviceSampleRate() - 1) / getDeviceSampleRate();

    setDeviceFramesPerBurst(deviceFramesPerBurst);
    setFramesPerBurst(framesPerBurst); // only save good value

    mDeviceBufferCapacityInFrames = mEndpointDescriptor.dataQueueDescriptor.capacityInFrames;

    mBufferCapacityInFrames = static_cast<int64_t>(mDeviceBufferCapacityInFrames)
            * getSampleRate() / getDeviceSampleRate();
    if (mBufferCapacityInFrames < getFramesPerBurst()
            || mBufferCapacityInFrames > MAX_BUFFER_CAPACITY_IN_FRAMES) {
        ALOGE("%s - bufferCapacity out of range = %d", __func__, mBufferCapacityInFrames);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }

    mClockModel.setSampleRate(getDeviceSampleRate());
    mClockModel.setFramesPerBurst(deviceFramesPerBurst);

    if (isDataCallbackSet()) {
        mCallbackFrames = callbackFrames;
        if (mCallbackFrames > getBufferCapacity() / 2) {
            ALOGW("%s - framesPerCallback too big = %d, capacity = %d",
                  __func__, mCallbackFrames, getBufferCapacity());
            return AAUDIO_ERROR_OUT_OF_RANGE;
        } else if (mCallbackFrames < 0) {
            ALOGW("%s - framesPerCallback negative", __func__);
            return AAUDIO_ERROR_OUT_OF_RANGE;
        }
        if (mCallbackFrames == AAUDIO_UNSPECIFIED) {
            mCallbackFrames = getFramesPerBurst();
        }

        const int32_t callbackBufferSize = mCallbackFrames * getBytesPerFrame();
        mCallbackBuffer = std::make_unique<uint8_t[]>(callbackBufferSize);
    }

    // Exclusive output streams should combine channels when mono audio adjustment
    // is enabled. They should also adjust for audio balance.
    if ((getDirection() == AAUDIO_DIRECTION_OUTPUT) &&
        (getSharingMode() == AAUDIO_SHARING_MODE_EXCLUSIVE)) {
        bool isMasterMono = false;
        android::AudioSystem::getMasterMono(&isMasterMono);
        setRequireMonoBlend(isMasterMono);
        float audioBalance = 0;
        android::AudioSystem::getMasterBalance(&audioBalance);
        setAudioBalance(audioBalance);
    }

    // For debugging and analyzing the distribution of MMAP timestamps.
    // For OUTPUT, use a NEGATIVE offset to move the CPU writes further BEFORE the HW reads.
    // For INPUT, use a POSITIVE offset to move the CPU reads further AFTER the HW writes.
    // You can use this offset to reduce glitching.
    // You can also use this offset to force glitching. By iterating over multiple
    // values you can reveal the distribution of the hardware timing jitter.
    if (mAudioEndpoint->isFreeRunning()) { // MMAP?
        int32_t offsetMicros = (getDirection() == AAUDIO_DIRECTION_OUTPUT)
                ? AAudioProperty_getOutputMMapOffsetMicros()
                : AAudioProperty_getInputMMapOffsetMicros();
        // This log is used to debug some tricky glitch issues. Please leave.
        ALOGD_IF(offsetMicros, "%s() - %s mmap offset = %d micros",
                __func__,
                (getDirection() == AAUDIO_DIRECTION_OUTPUT) ? "output" : "input",
                offsetMicros);
        mTimeOffsetNanos = offsetMicros * AAUDIO_NANOS_PER_MICROSECOND;
    }

    // Default buffer size to match Q
    setBufferSize(mBufferCapacityInFrames / 2);
    return AAUDIO_OK;
}

// This must be called under mStreamLock.
aaudio_result_t AudioStreamInternal::release_l() {
    aaudio_result_t result = AAUDIO_OK;
    ALOGD("%s(): mServiceStreamHandle = 0x%08X", __func__, getServiceHandle());
    if (getServiceHandle() != AAUDIO_HANDLE_INVALID) {
        // Don't release a stream while it is running. Stop it first.
        // If DISCONNECTED then we should still try to stop in case the
        // error callback is still running.
        if (isActive() || isDisconnected()) {
            requestStop_l();
        }

        logReleaseBufferState();

        setState(AAUDIO_STREAM_STATE_CLOSING);
        auto serviceStreamHandleInfo = mServiceStreamHandleInfo;
        mServiceStreamHandleInfo = AAudioHandleInfo();

        mServiceInterface.closeStream(serviceStreamHandleInfo);
        mCallbackBuffer.reset();

        // Update local frame counters so we can query them after releasing the endpoint.
        getFramesRead();
        getFramesWritten();
        mAudioEndpoint.reset();
        result = mEndPointParcelable.close();
        aaudio_result_t result2 = AudioStream::release_l();
        return (result != AAUDIO_OK) ? result : result2;
    } else {
        return AAUDIO_ERROR_INVALID_HANDLE;
    }
}

static void *aaudio_callback_thread_proc(void *context)
{
    AudioStreamInternal *stream = (AudioStreamInternal *)context;
    //LOGD("oboe_callback_thread, stream = %p", stream);
    if (stream != nullptr) {
        return stream->callbackLoop();
    } else {
        return nullptr;
    }
}

aaudio_result_t AudioStreamInternal::exitStandby_l() {
    AudioEndpointParcelable endpointParcelable;
    // The stream is in standby mode, copy all available data and then close the duplicated
    // shared file descriptor so that it won't cause issue when the HAL try to reallocate new
    // shared file descriptor when exiting from standby.
    // Cache current read counter, which will be reset to new read and write counter
    // when the new data queue and endpoint are reconfigured.
    const android::fifo_counter_t readCounter = mAudioEndpoint->getDataReadCounter();
    // Cache the buffer size which may be from client.
    const int32_t previousBufferSize = mBufferSizeInFrames;
    // Copy all available data from current data queue.
    uint8_t buffer[getDeviceBufferCapacity() * getBytesPerFrame()];
    android::fifo_frames_t fullFramesAvailable = mAudioEndpoint->read(buffer,
            getDeviceBufferCapacity());
    // Before releasing the data queue, update the frames read and written.
    getFramesRead();
    getFramesWritten();
    // Call freeDataQueue() here because the following call to
    // closeDataFileDescriptor() will invalidate the pointers used by the data queue.
    mAudioEndpoint->freeDataQueue();
    mEndPointParcelable.closeDataFileDescriptor();
    aaudio_result_t result = mServiceInterface.exitStandby(
            mServiceStreamHandleInfo, endpointParcelable);
    if (result != AAUDIO_OK) {
        ALOGE("Failed to exit standby, error=%d", result);
        goto exit;
    }
    // Reconstruct data queue descriptor using new shared file descriptor.
    result = mEndPointParcelable.updateDataFileDescriptor(&endpointParcelable);
    if (result != AAUDIO_OK) {
        ALOGE("%s failed to update data file descriptor, error=%d", __func__, result);
        goto exit;
    }
    result = mEndPointParcelable.resolveDataQueue(&mEndpointDescriptor.dataQueueDescriptor);
    if (result != AAUDIO_OK) {
        ALOGE("Failed to resolve data queue after exiting standby, error=%d", result);
        goto exit;
    }
    // Reconfigure audio endpoint with new data queue descriptor.
    mAudioEndpoint->configureDataQueue(
            mEndpointDescriptor.dataQueueDescriptor, getDirection());
    // Set read and write counters with previous read counter, the later write action
    // will make the counter at the correct place.
    mAudioEndpoint->setDataReadCounter(readCounter);
    mAudioEndpoint->setDataWriteCounter(readCounter);
    result = configureDataInformation(mCallbackFrames);
    if (result != AAUDIO_OK) {
        ALOGE("Failed to configure data information after exiting standby, error=%d", result);
        goto exit;
    }
    // Write data from previous data buffer to new endpoint.
    if (const android::fifo_frames_t framesWritten =
                mAudioEndpoint->write(buffer, fullFramesAvailable);
            framesWritten != fullFramesAvailable) {
        ALOGW("Some data lost after exiting standby, frames written: %d, "
              "frames to write: %d", framesWritten, fullFramesAvailable);
    }
    // Reset previous buffer size as it may be requested by the client.
    setBufferSize(previousBufferSize);

exit:
    return result;
}

/*
 * It normally takes about 20-30 msec to start a stream on the server.
 * But the first time can take as much as 200-300 msec. The HW
 * starts right away so by the time the client gets a chance to write into
 * the buffer, it is already in a deep underflow state. That can cause the
 * XRunCount to be non-zero, which could lead an app to tune its latency higher.
 * To avoid this problem, we set a request for the processing code to start the
 * client stream at the same position as the server stream.
 * The processing code will then save the current offset
 * between client and server and apply that to any position given to the app.
 */
aaudio_result_t AudioStreamInternal::requestStart_l()
{
    int64_t startTime;
    if (getServiceHandle() == AAUDIO_HANDLE_INVALID) {
        ALOGD("requestStart() mServiceStreamHandle invalid");
        return AAUDIO_ERROR_INVALID_STATE;
    }
    if (isActive()) {
        ALOGD("requestStart() already active");
        return AAUDIO_ERROR_INVALID_STATE;
    }

    if (isDisconnected()) {
        ALOGD("requestStart() but DISCONNECTED");
        return AAUDIO_ERROR_DISCONNECTED;
    }
    const aaudio_stream_state_t originalState = getState();
    setState(AAUDIO_STREAM_STATE_STARTING);

    // Clear any stale timestamps from the previous run.
    drainTimestampsFromService();

    prepareBuffersForStart(); // tell subclasses to get ready

    aaudio_result_t result = mServiceInterface.startStream(mServiceStreamHandleInfo);
    if (result == AAUDIO_ERROR_STANDBY) {
        // The stream is at standby mode. Need to exit standby before starting the stream.
        result = exitStandby_l();
        if (result == AAUDIO_OK) {
            result = mServiceInterface.startStream(mServiceStreamHandleInfo);
        }
    }
    if (result != AAUDIO_OK) {
        ALOGD("%s() error = %d, stream was probably stolen", __func__, result);
        // Stealing was added in R. Coerce result to improve backward compatibility.
        result = AAUDIO_ERROR_DISCONNECTED;
        setDisconnected();
    }

    startTime = AudioClock::getNanoseconds();
    mClockModel.start(startTime);
    mNeedCatchUp.request();  // Ask data processing code to catch up when first timestamp received.

    // Start data callback thread.
    if (result == AAUDIO_OK && isDataCallbackSet()) {
        // Launch the callback loop thread.
        int64_t periodNanos = mCallbackFrames
                              * AAUDIO_NANOS_PER_SECOND
                              / getSampleRate();
        mCallbackEnabled.store(true);
        result = createThread_l(periodNanos, aaudio_callback_thread_proc, this);
    }
    if (result != AAUDIO_OK) {
        setState(originalState);
    }
    return result;
}

int64_t AudioStreamInternal::calculateReasonableTimeout(int32_t framesPerOperation) {

    // Wait for at least a second or some number of callbacks to join the thread.
    int64_t timeoutNanoseconds = (MIN_TIMEOUT_OPERATIONS
                                  * framesPerOperation
                                  * AAUDIO_NANOS_PER_SECOND)
                                  / getSampleRate();
    if (timeoutNanoseconds < MIN_TIMEOUT_NANOS) { // arbitrary number of seconds
        timeoutNanoseconds = MIN_TIMEOUT_NANOS;
    }
    return timeoutNanoseconds;
}

int64_t AudioStreamInternal::calculateReasonableTimeout() {
    return calculateReasonableTimeout(getFramesPerBurst());
}

// This must be called under mStreamLock.
aaudio_result_t AudioStreamInternal::stopCallback_l()
{
    if (isDataCallbackSet() && (isActive() || isDisconnected())) {
        mCallbackEnabled.store(false);
        aaudio_result_t result = joinThread_l(nullptr); // may temporarily unlock mStreamLock
        if (result == AAUDIO_ERROR_INVALID_HANDLE) {
            ALOGD("%s() INVALID_HANDLE, stream was probably stolen", __func__);
            result = AAUDIO_OK;
        }
        return result;
    } else {
        ALOGD("%s() skipped, isDataCallbackSet() = %d, isActive() = %d, getState()  = %d", __func__,
            isDataCallbackSet(), isActive(), getState());
        return AAUDIO_OK;
    }
}

aaudio_result_t AudioStreamInternal::requestStop_l() {
    aaudio_result_t result = stopCallback_l();
    if (result != AAUDIO_OK) {
        ALOGW("%s() stop callback returned %d, returning early", __func__, result);
        return result;
    }
    // The stream may have been unlocked temporarily to let a callback finish
    // and the callback may have stopped the stream.
    // Check to make sure the stream still needs to be stopped.
    // See also AudioStream::safeStop_l().
    if (!(isActive() || isDisconnected())) {
        ALOGD("%s() returning early, not active or disconnected", __func__);
        return AAUDIO_OK;
    }

    if (getServiceHandle() == AAUDIO_HANDLE_INVALID) {
        ALOGW("%s() mServiceStreamHandle invalid = 0x%08X",
              __func__, getServiceHandle());
        return AAUDIO_ERROR_INVALID_STATE;
    }

    mClockModel.stop(AudioClock::getNanoseconds());
    setState(AAUDIO_STREAM_STATE_STOPPING);
    mAtomicInternalTimestamp.clear();

    result = mServiceInterface.stopStream(mServiceStreamHandleInfo);
    if (result == AAUDIO_ERROR_INVALID_HANDLE) {
        ALOGD("%s() INVALID_HANDLE, stream was probably stolen", __func__);
        result = AAUDIO_OK;
    }
    return result;
}

aaudio_result_t AudioStreamInternal::registerThread() {
    if (getServiceHandle() == AAUDIO_HANDLE_INVALID) {
        ALOGW("%s() mServiceStreamHandle invalid", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }
    return mServiceInterface.registerAudioThread(mServiceStreamHandleInfo,
                                                 gettid(),
                                                 getPeriodNanoseconds());
}

aaudio_result_t AudioStreamInternal::unregisterThread() {
    if (getServiceHandle() == AAUDIO_HANDLE_INVALID) {
        ALOGW("%s() mServiceStreamHandle invalid", __func__);
        return AAUDIO_ERROR_INVALID_STATE;
    }
    return mServiceInterface.unregisterAudioThread(mServiceStreamHandleInfo, gettid());
}

aaudio_result_t AudioStreamInternal::startClient(const android::AudioClient& client,
                                                 const audio_attributes_t *attr,
                                                 audio_port_handle_t *portHandle) {
    ALOGV("%s() called", __func__);
    if (getServiceHandle() == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    aaudio_result_t result =  mServiceInterface.startClient(mServiceStreamHandleInfo,
                                                            client, attr, portHandle);
    ALOGV("%s(%d) returning %d", __func__, *portHandle, result);
    return result;
}

aaudio_result_t AudioStreamInternal::stopClient(audio_port_handle_t portHandle) {
    ALOGV("%s(%d) called", __func__, portHandle);
    if (getServiceHandle() == AAUDIO_HANDLE_INVALID) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    aaudio_result_t result = mServiceInterface.stopClient(mServiceStreamHandleInfo, portHandle);
    ALOGV("%s(%d) returning %d", __func__, portHandle, result);
    return result;
}

aaudio_result_t AudioStreamInternal::getTimestamp(clockid_t /*clockId*/,
                           int64_t *framePosition,
                           int64_t *timeNanoseconds) {
    // Generated in server and passed to client. Return latest.
    if (mAtomicInternalTimestamp.isValid()) {
        Timestamp timestamp = mAtomicInternalTimestamp.read();
        // This should not overflow as timestamp.getPosition() should be a position in a buffer and
        // not the actual timestamp. timestamp.getNanoseconds() below uses the actual timestamp.
        // At 48000 Hz we can run for over 100 years before overflowing the int64_t.
        int64_t position = (timestamp.getPosition() + mFramesOffsetFromService) * getSampleRate() /
                getDeviceSampleRate();
        if (position >= 0) {
            *framePosition = position;
            *timeNanoseconds = timestamp.getNanoseconds();
            return AAUDIO_OK;
        }
    }
    return AAUDIO_ERROR_INVALID_STATE;
}

void AudioStreamInternal::logTimestamp(AAudioServiceMessage &command) {
    static int64_t oldPosition = 0;
    static int64_t oldTime = 0;
    int64_t framePosition = command.timestamp.position;
    int64_t nanoTime = command.timestamp.timestamp;
    ALOGD("logTimestamp: timestamp says framePosition = %8lld at nanoTime %lld",
         (long long) framePosition,
         (long long) nanoTime);
    int64_t nanosDelta = nanoTime - oldTime;
    if (nanosDelta > 0 && oldTime > 0) {
        int64_t framesDelta = framePosition - oldPosition;
        int64_t rate = (framesDelta * AAUDIO_NANOS_PER_SECOND) / nanosDelta;
        ALOGD("logTimestamp:     framesDelta = %8lld, nanosDelta = %8lld, rate = %lld",
              (long long) framesDelta, (long long) nanosDelta, (long long) rate);
    }
    oldPosition = framePosition;
    oldTime = nanoTime;
}

aaudio_result_t AudioStreamInternal::onTimestampService(AAudioServiceMessage *message) {
#if LOG_TIMESTAMPS
    logTimestamp(*message);
#endif
    processTimestamp(message->timestamp.position,
            message->timestamp.timestamp + mTimeOffsetNanos);
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamInternal::onTimestampHardware(AAudioServiceMessage *message) {
    Timestamp timestamp(message->timestamp.position, message->timestamp.timestamp);
    mAtomicInternalTimestamp.write(timestamp);
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamInternal::onEventFromServer(AAudioServiceMessage *message) {
    aaudio_result_t result = AAUDIO_OK;
    switch (message->event.event) {
        case AAUDIO_SERVICE_EVENT_STARTED:
            ALOGD("%s - got AAUDIO_SERVICE_EVENT_STARTED", __func__);
            if (getState() == AAUDIO_STREAM_STATE_STARTING) {
                setState(AAUDIO_STREAM_STATE_STARTED);
            }
            mPlayerBase->triggerPortIdUpdate(static_cast<audio_port_handle_t>(
                                                 message->event.dataLong));
            break;
        case AAUDIO_SERVICE_EVENT_PAUSED:
            ALOGD("%s - got AAUDIO_SERVICE_EVENT_PAUSED", __func__);
            if (getState() == AAUDIO_STREAM_STATE_PAUSING) {
                setState(AAUDIO_STREAM_STATE_PAUSED);
            }
            break;
        case AAUDIO_SERVICE_EVENT_STOPPED:
            ALOGD("%s - got AAUDIO_SERVICE_EVENT_STOPPED", __func__);
            if (getState() == AAUDIO_STREAM_STATE_STOPPING) {
                setState(AAUDIO_STREAM_STATE_STOPPED);
            }
            break;
        case AAUDIO_SERVICE_EVENT_FLUSHED:
            ALOGD("%s - got AAUDIO_SERVICE_EVENT_FLUSHED", __func__);
            if (getState() == AAUDIO_STREAM_STATE_FLUSHING) {
                setState(AAUDIO_STREAM_STATE_FLUSHED);
                onFlushFromServer();
            }
            break;
        case AAUDIO_SERVICE_EVENT_DISCONNECTED:
            // Prevent hardware from looping on old data and making buzzing sounds.
            if (getDirection() == AAUDIO_DIRECTION_OUTPUT) {
                mAudioEndpoint->eraseDataMemory();
            }
            result = AAUDIO_ERROR_DISCONNECTED;
            setDisconnected();
            ALOGW("%s - AAUDIO_SERVICE_EVENT_DISCONNECTED - FIFO cleared", __func__);
            break;
        case AAUDIO_SERVICE_EVENT_VOLUME:
            ALOGD("%s - AAUDIO_SERVICE_EVENT_VOLUME %lf", __func__, message->event.dataDouble);
            mStreamVolume = (float)message->event.dataDouble;
            doSetVolume();
            break;
        case AAUDIO_SERVICE_EVENT_XRUN:
            mXRunCount = static_cast<int32_t>(message->event.dataLong);
            break;
        default:
            ALOGE("%s - Unrecognized event = %d", __func__, (int) message->event.event);
            break;
    }
    return result;
}

aaudio_result_t AudioStreamInternal::drainTimestampsFromService() {
    aaudio_result_t result = AAUDIO_OK;

    while (result == AAUDIO_OK) {
        AAudioServiceMessage message;
        if (!mAudioEndpoint) {
            break;
        }
        if (mAudioEndpoint->readUpCommand(&message) != 1) {
            break; // no command this time, no problem
        }
        switch (message.what) {
            // ignore most messages
            case AAudioServiceMessage::code::TIMESTAMP_SERVICE:
            case AAudioServiceMessage::code::TIMESTAMP_HARDWARE:
                break;

            case AAudioServiceMessage::code::EVENT:
                result = onEventFromServer(&message);
                break;

            default:
                ALOGE("%s - unrecognized message.what = %d", __func__, (int) message.what);
                result = AAUDIO_ERROR_INTERNAL;
                break;
        }
    }
    return result;
}

// Process all the commands coming from the server.
aaudio_result_t AudioStreamInternal::processCommands() {
    aaudio_result_t result = AAUDIO_OK;

    while (result == AAUDIO_OK) {
        AAudioServiceMessage message;
        if (!mAudioEndpoint) {
            break;
        }
        if (mAudioEndpoint->readUpCommand(&message) != 1) {
            break; // no command this time, no problem
        }
        switch (message.what) {
        case AAudioServiceMessage::code::TIMESTAMP_SERVICE:
            result = onTimestampService(&message);
            break;

        case AAudioServiceMessage::code::TIMESTAMP_HARDWARE:
            result = onTimestampHardware(&message);
            break;

        case AAudioServiceMessage::code::EVENT:
            result = onEventFromServer(&message);
            break;

        default:
            ALOGE("%s - unrecognized message.what = %d", __func__, (int) message.what);
            result = AAUDIO_ERROR_INTERNAL;
            break;
        }
    }
    return result;
}

// Read or write the data, block if needed and timeoutMillis > 0
aaudio_result_t AudioStreamInternal::processData(void *buffer, int32_t numFrames,
                                                 int64_t timeoutNanoseconds)
{
    if (isDisconnected()) {
        return AAUDIO_ERROR_DISCONNECTED;
    }
    if (!mInService &&
        AAudioBinderClient::getInstance().getServiceLifetimeId() != getServiceLifetimeId()) {
        // The service lifetime id will be changed whenever the binder died. In that case, if
        // the service lifetime id from AAudioBinderClient is different from the cached one,
        // returns AAUDIO_ERROR_DISCONNECTED.
        // Note that only compare the service lifetime id if it is not in service as the streams
        // in service will all be gone when aaudio service dies.
        mClockModel.stop(AudioClock::getNanoseconds());
        // Set the stream as disconnected as the service lifetime id will only change when
        // the binder dies.
        setDisconnected();
        return AAUDIO_ERROR_DISCONNECTED;
    }
    const char * traceName = "aaProc";
    const char * fifoName = "aaRdy";
    ATRACE_BEGIN(traceName);
    if (ATRACE_ENABLED()) {
        int32_t fullFrames = mAudioEndpoint->getFullFramesAvailable();
        ATRACE_INT(fifoName, fullFrames);
    }

    aaudio_result_t result = AAUDIO_OK;
    int32_t loopCount = 0;
    uint8_t* audioData = (uint8_t*)buffer;
    int64_t currentTimeNanos = AudioClock::getNanoseconds();
    const int64_t entryTimeNanos = currentTimeNanos;
    const int64_t deadlineNanos = currentTimeNanos + timeoutNanoseconds;
    int32_t framesLeft = numFrames;

    // Loop until all the data has been processed or until a timeout occurs.
    while (framesLeft > 0) {
        // The call to processDataNow() will not block. It will just process as much as it can.
        int64_t wakeTimeNanos = 0;
        aaudio_result_t framesProcessed = processDataNow(audioData, framesLeft,
                                                  currentTimeNanos, &wakeTimeNanos);
        if (framesProcessed < 0) {
            result = framesProcessed;
            break;
        }
        framesLeft -= (int32_t) framesProcessed;
        audioData += framesProcessed * getBytesPerFrame();

        // Should we block?
        if (timeoutNanoseconds == 0) {
            break; // don't block
        } else if (wakeTimeNanos != 0) {
            if (!mAudioEndpoint->isFreeRunning()) {
                // If there is software on the other end of the FIFO then it may get delayed.
                // So wake up just a little after we expect it to be ready.
                wakeTimeNanos += mWakeupDelayNanos;
            }

            currentTimeNanos = AudioClock::getNanoseconds();
            int64_t earliestWakeTime = currentTimeNanos + mMinimumSleepNanos;
            // Guarantee a minimum sleep time.
            if (wakeTimeNanos < earliestWakeTime) {
                wakeTimeNanos = earliestWakeTime;
            }

            if (wakeTimeNanos > deadlineNanos) {
                // If we time out, just return the framesWritten so far.
                ALOGW("processData(): entered at %lld nanos, currently %lld",
                      (long long) entryTimeNanos, (long long) currentTimeNanos);
                ALOGW("processData(): TIMEOUT after %lld nanos",
                      (long long) timeoutNanoseconds);
                ALOGW("processData(): wakeTime = %lld, deadline = %lld nanos",
                      (long long) wakeTimeNanos, (long long) deadlineNanos);
                ALOGW("processData(): past deadline by %d micros",
                      (int)((wakeTimeNanos - deadlineNanos) / AAUDIO_NANOS_PER_MICROSECOND));
                mClockModel.dump();
                mAudioEndpoint->dump();
                break;
            }

            if (ATRACE_ENABLED()) {
                int32_t fullFrames = mAudioEndpoint->getFullFramesAvailable();
                ATRACE_INT(fifoName, fullFrames);
                int64_t sleepForNanos = wakeTimeNanos - currentTimeNanos;
                ATRACE_INT("aaSlpNs", (int32_t)sleepForNanos);
            }

            AudioClock::sleepUntilNanoTime(wakeTimeNanos);
            currentTimeNanos = AudioClock::getNanoseconds();
        }
    }

    if (ATRACE_ENABLED()) {
        int32_t fullFrames = mAudioEndpoint->getFullFramesAvailable();
        ATRACE_INT(fifoName, fullFrames);
    }

    // return error or framesProcessed
    (void) loopCount;
    ATRACE_END();
    return (result < 0) ? result : numFrames - framesLeft;
}

void AudioStreamInternal::processTimestamp(uint64_t position, int64_t time) {
    mClockModel.processTimestamp(position, time);
}

aaudio_result_t AudioStreamInternal::setBufferSize(int32_t requestedFrames) {
    const int32_t maximumSize = getBufferCapacity() - getFramesPerBurst();
    int32_t adjustedFrames = std::min(requestedFrames, maximumSize);
    // Buffer sizes should always be a multiple of framesPerBurst.
    int32_t numBursts = (static_cast<int64_t>(adjustedFrames) + getFramesPerBurst() - 1) /
        getFramesPerBurst();

    // Use at least one burst
    if (numBursts == 0) {
        numBursts = 1;
    }

    // Set a minimum number of bursts if sample rate conversion is used.
    if ((getSampleRate() != getDeviceSampleRate()) &&
            (numBursts < MIN_SAMPLE_RATE_CONVERSION_NUM_BURSTS)) {
        numBursts = MIN_SAMPLE_RATE_CONVERSION_NUM_BURSTS;
    }

    if (mAudioEndpoint) {
        // Clip against the actual size from the endpoint.
        int32_t actualFramesDevice = 0;
        int32_t maximumFramesDevice = getDeviceBufferCapacity() - getDeviceFramesPerBurst();
        // Set to maximum size so we can write extra data when ready in order to reduce glitches.
        // The amount we keep in the buffer is controlled by mBufferSizeInFrames.
        mAudioEndpoint->setBufferSizeInFrames(maximumFramesDevice, &actualFramesDevice);
        int32_t actualNumBursts = actualFramesDevice / getDeviceFramesPerBurst();
        numBursts = std::min(numBursts, actualNumBursts);
    }

    const int32_t bufferSizeInFrames = numBursts * getFramesPerBurst();
    const int32_t deviceBufferSizeInFrames = numBursts * getDeviceFramesPerBurst();

    if (deviceBufferSizeInFrames != mDeviceBufferSizeInFrames) {
        android::mediametrics::LogItem(mMetricsId)
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_SETBUFFERSIZE)
                .set(AMEDIAMETRICS_PROP_BUFFERSIZEFRAMES, deviceBufferSizeInFrames)
                .set(AMEDIAMETRICS_PROP_UNDERRUN, (int32_t) getXRunCount())
                .record();
    }

    mBufferSizeInFrames = bufferSizeInFrames;
    mDeviceBufferSizeInFrames = deviceBufferSizeInFrames;
    ALOGV("%s(%d) returns %d", __func__, requestedFrames, adjustedFrames);
    return (aaudio_result_t) adjustedFrames;
}

int32_t AudioStreamInternal::getBufferSize() const {
    return mBufferSizeInFrames;
}

int32_t AudioStreamInternal::getDeviceBufferSize() const {
    return mDeviceBufferSizeInFrames;
}

int32_t AudioStreamInternal::getBufferCapacity() const {
    return mBufferCapacityInFrames;
}

int32_t AudioStreamInternal::getDeviceBufferCapacity() const {
    return mDeviceBufferCapacityInFrames;
}

bool AudioStreamInternal::isClockModelInControl() const {
    return isActive() && mAudioEndpoint->isFreeRunning() && mClockModel.isRunning();
}
