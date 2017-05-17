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

#define LOG_TAG "AAudioService"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <atomic>
#include <stdint.h>

#include <utils/String16.h>
#include <media/nbaio/AudioStreamOutSink.h>
#include <media/MmapStreamInterface.h>

#include "AAudioServiceStreamBase.h"
#include "AAudioServiceStreamMMAP.h"
#include "binding/AudioEndpointParcelable.h"
#include "SharedMemoryProxy.h"
#include "utility/AAudioUtilities.h"

using namespace android;
using namespace aaudio;

#define AAUDIO_BUFFER_CAPACITY_MIN    4 * 512
#define AAUDIO_SAMPLE_RATE_DEFAULT    48000

/**
 * Stream that uses an MMAP buffer.
 */

AAudioServiceStreamMMAP::AAudioServiceStreamMMAP()
        : AAudioServiceStreamBase()
        , mMmapStreamCallback(new MyMmapStreamCallback(*this))
        , mPreviousFrameCounter(0)
        , mMmapStream(nullptr) {
}

AAudioServiceStreamMMAP::~AAudioServiceStreamMMAP() {
    close();
}

aaudio_result_t AAudioServiceStreamMMAP::close() {
    ALOGD("AAudioServiceStreamMMAP::close() called, %p", mMmapStream.get());
    mMmapStream.clear(); // TODO review. Is that all we have to do?
    // Apparently the above close is asynchronous. An attempt to open a new device
    // right after a close can fail. Also some callbacks may still be in flight!
    // FIXME Make closing synchronous.
    AudioClock::sleepForNanos(100 * AAUDIO_NANOS_PER_MILLISECOND);

    if (mAudioDataFileDescriptor != -1) {
        ALOGV("AAudioServiceStreamMMAP: LEAK? close(mAudioDataFileDescriptor = %d)\n",
              mAudioDataFileDescriptor);
        ::close(mAudioDataFileDescriptor);
        mAudioDataFileDescriptor = -1;
    }

    return AAudioServiceStreamBase::close();
}

// Open stream on HAL and pass information about the shared memory buffer back to the client.
aaudio_result_t AAudioServiceStreamMMAP::open(const aaudio::AAudioStreamRequest &request,
                                       aaudio::AAudioStreamConfiguration &configurationOutput) {
    const audio_attributes_t attributes = {
        .content_type = AUDIO_CONTENT_TYPE_MUSIC,
        .usage = AUDIO_USAGE_MEDIA,
        .source = AUDIO_SOURCE_DEFAULT,
        .flags = AUDIO_FLAG_LOW_LATENCY,
        .tags = ""
    };
    audio_config_base_t config;

    aaudio_result_t result = AAudioServiceStreamBase::open(request, configurationOutput);
    if (result != AAUDIO_OK) {
        ALOGE("AAudioServiceStreamBase open returned %d", result);
        return result;
    }

    const AAudioStreamConfiguration &configurationInput = request.getConstantConfiguration();
    audio_port_handle_t deviceId = configurationInput.getDeviceId();

    // ALOGI("open request dump()");
    // request.dump();

    mMmapClient.clientUid = request.getUserId();
    mMmapClient.clientPid = request.getProcessId();
    aaudio_direction_t direction = request.getDirection();

    // Fill in config
    aaudio_audio_format_t aaudioFormat = configurationInput.getAudioFormat();
    if (aaudioFormat == AAUDIO_UNSPECIFIED || aaudioFormat == AAUDIO_FORMAT_PCM_FLOAT) {
        ALOGI("open forcing use of AAUDIO_FORMAT_PCM_I16");
        aaudioFormat = AAUDIO_FORMAT_PCM_I16;
    }
    config.format = AAudioConvert_aaudioToAndroidDataFormat(aaudioFormat);

    int32_t aaudioSampleRate = configurationInput.getSampleRate();
    if (aaudioSampleRate == AAUDIO_UNSPECIFIED) {
        aaudioSampleRate = AAUDIO_SAMPLE_RATE_DEFAULT;
    }
    config.sample_rate = aaudioSampleRate;

    int32_t aaudioSamplesPerFrame = configurationInput.getSamplesPerFrame();

    if (direction == AAUDIO_DIRECTION_OUTPUT) {
        config.channel_mask = (aaudioSamplesPerFrame == AAUDIO_UNSPECIFIED)
                            ? AUDIO_CHANNEL_OUT_STEREO
                            : audio_channel_out_mask_from_count(aaudioSamplesPerFrame);
    } else if (direction == AAUDIO_DIRECTION_INPUT) {
        config.channel_mask =  (aaudioSamplesPerFrame == AAUDIO_UNSPECIFIED)
                            ? AUDIO_CHANNEL_IN_STEREO
                            : audio_channel_in_mask_from_count(aaudioSamplesPerFrame);
    } else {
        ALOGE("openMmapStream - invalid direction = %d", direction);
        return AAUDIO_ERROR_ILLEGAL_ARGUMENT;
    }

    mMmapClient.packageName.setTo(String16("aaudio_service")); // FIXME what should we do here?

    MmapStreamInterface::stream_direction_t streamDirection = (direction == AAUDIO_DIRECTION_OUTPUT)
        ? MmapStreamInterface::DIRECTION_OUTPUT : MmapStreamInterface::DIRECTION_INPUT;

    ALOGD("AAudioServiceStreamMMAP::open() request devId = %d, sRate = %d",
          deviceId, config.sample_rate);

    // Open HAL stream.
    status_t status = MmapStreamInterface::openMmapStream(streamDirection,
                                                          &attributes,
                                                          &config,
                                                          mMmapClient,
                                                          &deviceId,
                                                          mMmapStreamCallback,
                                                          mMmapStream);
    if (status != OK) {
        ALOGE("openMmapStream returned status %d", status);
        return AAUDIO_ERROR_UNAVAILABLE;
    }

    // Create MMAP/NOIRQ buffer.
    int32_t minSizeFrames = configurationInput.getBufferCapacity();
    if (minSizeFrames == 0) { // zero will get rejected
        minSizeFrames = AAUDIO_BUFFER_CAPACITY_MIN;
    }
    status = mMmapStream->createMmapBuffer(minSizeFrames, &mMmapBufferinfo);
    if (status != OK) {
        ALOGE("%s: createMmapBuffer() returned status %d, return AAUDIO_ERROR_UNAVAILABLE",
              __FILE__, status);
        return AAUDIO_ERROR_UNAVAILABLE;
    } else {
        ALOGD("createMmapBuffer status %d shared_address = %p buffer_size %d burst_size %d",
              status, mMmapBufferinfo.shared_memory_address,
              mMmapBufferinfo.buffer_size_frames,
              mMmapBufferinfo.burst_size_frames);
    }

    // Get information about the stream and pass it back to the caller.
    mSamplesPerFrame = (direction == AAUDIO_DIRECTION_OUTPUT)
                           ? audio_channel_count_from_out_mask(config.channel_mask)
                           : audio_channel_count_from_in_mask(config.channel_mask);

    mAudioDataFileDescriptor = mMmapBufferinfo.shared_memory_fd;
    ALOGV("AAudioServiceStreamMMAP::open LEAK? mAudioDataFileDescriptor = %d\n",
          mAudioDataFileDescriptor);
    mFramesPerBurst = mMmapBufferinfo.burst_size_frames;
    mCapacityInFrames = mMmapBufferinfo.buffer_size_frames;
    mAudioFormat = AAudioConvert_androidToAAudioDataFormat(config.format);
    mSampleRate = config.sample_rate;

    // Scale up the burst size to meet the minimum equivalent in microseconds.
    // This is to avoid waking the CPU too often when the HW burst is very small
    // or at high sample rates.
    int32_t burstMinMicros = AAudioProperty_getHardwareBurstMinMicros();
    int32_t burstMicros = 0;
    do {
        if (burstMicros > 0) {  // skip first loop
            mFramesPerBurst *= 2;
        }
        burstMicros = mFramesPerBurst * static_cast<int64_t>(1000000) / mSampleRate;
    } while (burstMicros < burstMinMicros);

    ALOGD("AAudioServiceStreamMMAP::open() original burst = %d, minMicros = %d, final burst = %d\n",
          mMmapBufferinfo.burst_size_frames, burstMinMicros, mFramesPerBurst);

    ALOGD("AAudioServiceStreamMMAP::open() got devId = %d, sRate = %d",
          deviceId, config.sample_rate);

    // Fill in AAudioStreamConfiguration
    configurationOutput.setSampleRate(mSampleRate);
    configurationOutput.setSamplesPerFrame(mSamplesPerFrame);
    configurationOutput.setAudioFormat(mAudioFormat);
    configurationOutput.setDeviceId(deviceId);

    return AAUDIO_OK;
}


/**
 * Start the flow of data.
 */
aaudio_result_t AAudioServiceStreamMMAP::start() {
    if (mMmapStream == nullptr) return AAUDIO_ERROR_NULL;
    aaudio_result_t result = mMmapStream->start(mMmapClient, &mPortHandle);
    if (result != AAUDIO_OK) {
        ALOGE("AAudioServiceStreamMMAP::start() mMmapStream->start() returned %d", result);
        processError();
    } else {
        result = AAudioServiceStreamBase::start();
    }
    return result;
}

/**
 * Stop the flow of data such that start() can resume with loss of data.
 */
aaudio_result_t AAudioServiceStreamMMAP::pause() {
    if (mMmapStream == nullptr) return AAUDIO_ERROR_NULL;

    aaudio_result_t result1 = AAudioServiceStreamBase::pause();
    aaudio_result_t result2 = mMmapStream->stop(mPortHandle);
    mFramesRead.reset32();
    return (result1 != AAUDIO_OK) ? result1 : result2;
}

aaudio_result_t AAudioServiceStreamMMAP::stop() {
    if (mMmapStream == nullptr) return AAUDIO_ERROR_NULL;

    aaudio_result_t result1 = AAudioServiceStreamBase::stop();
    aaudio_result_t result2 = mMmapStream->stop(mPortHandle);
    mFramesRead.reset32();
    return (result1 != AAUDIO_OK) ? result1 : result2;
}

/**
 *  Discard any data held by the underlying HAL or Service.
 */
aaudio_result_t AAudioServiceStreamMMAP::flush() {
    if (mMmapStream == nullptr) return AAUDIO_ERROR_NULL;
    // TODO how do we flush an MMAP/NOIRQ buffer? sync pointers?
    ALOGD("AAudioServiceStreamMMAP::flush() send AAUDIO_SERVICE_EVENT_FLUSHED");
    sendServiceEvent(AAUDIO_SERVICE_EVENT_FLUSHED);
    mState = AAUDIO_STREAM_STATE_FLUSHED;
    return AAudioServiceStreamBase::flush();;
}


aaudio_result_t AAudioServiceStreamMMAP::getFreeRunningPosition(int64_t *positionFrames,
                                                                int64_t *timeNanos) {
    struct audio_mmap_position position;
    if (mMmapStream == nullptr) {
        processError();
        return AAUDIO_ERROR_NULL;
    }
    status_t status = mMmapStream->getMmapPosition(&position);
    if (status != OK) {
        ALOGE("sendCurrentTimestamp(): getMmapPosition() returned %d", status);
        processError();
        return AAudioConvert_androidToAAudioResult(status);
    } else {
        mFramesRead.update32(position.position_frames);
        *positionFrames = mFramesRead.get();
        *timeNanos = position.time_nanoseconds;
    }
    return AAUDIO_OK;
}

void AAudioServiceStreamMMAP::onTearDown() {
    ALOGD("AAudioServiceStreamMMAP::onTearDown() called - TODO");
};

void AAudioServiceStreamMMAP::onVolumeChanged(audio_channel_mask_t channels,
                     android::Vector<float> values) {
    // TODO do we really need a different volume for each channel?
    float volume = values[0];
    ALOGD("AAudioServiceStreamMMAP::onVolumeChanged() volume[0] = %f", volume);
    sendServiceEvent(AAUDIO_SERVICE_EVENT_VOLUME, volume);
};

void AAudioServiceStreamMMAP::onRoutingChanged(audio_port_handle_t deviceId) {
    ALOGD("AAudioServiceStreamMMAP::onRoutingChanged() called with %d, old = %d",
          deviceId, mPortHandle);
    if (mPortHandle > 0 && mPortHandle != deviceId) {
        sendServiceEvent(AAUDIO_SERVICE_EVENT_DISCONNECTED);
    }
    mPortHandle = deviceId;
};

/**
 * Get an immutable description of the data queue from the HAL.
 */
aaudio_result_t AAudioServiceStreamMMAP::getDownDataDescription(AudioEndpointParcelable &parcelable)
{
    // Gather information on the data queue based on HAL info.
    int32_t bytesPerFrame = calculateBytesPerFrame();
    int32_t capacityInBytes = mCapacityInFrames * bytesPerFrame;
    int fdIndex = parcelable.addFileDescriptor(mAudioDataFileDescriptor, capacityInBytes);
    parcelable.mDownDataQueueParcelable.setupMemory(fdIndex, 0, capacityInBytes);
    parcelable.mDownDataQueueParcelable.setBytesPerFrame(bytesPerFrame);
    parcelable.mDownDataQueueParcelable.setFramesPerBurst(mFramesPerBurst);
    parcelable.mDownDataQueueParcelable.setCapacityInFrames(mCapacityInFrames);
    return AAUDIO_OK;
}