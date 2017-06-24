/*
 * Copyright 2016 The Android Open Source Project
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

#define LOG_TAG "AAudio"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <media/AudioTrack.h>

#include <aaudio/AAudio.h>
#include "utility/AudioClock.h"
#include "legacy/AudioStreamLegacy.h"
#include "legacy/AudioStreamTrack.h"
#include "utility/FixedBlockReader.h"

using namespace android;
using namespace aaudio;

// Arbitrary and somewhat generous number of bursts.
#define DEFAULT_BURSTS_PER_BUFFER_CAPACITY     8

/*
 * Create a stream that uses the AudioTrack.
 */
AudioStreamTrack::AudioStreamTrack()
    : AudioStreamLegacy()
    , mFixedBlockReader(*this)
{
}

AudioStreamTrack::~AudioStreamTrack()
{
    const aaudio_stream_state_t state = getState();
    bool bad = !(state == AAUDIO_STREAM_STATE_UNINITIALIZED || state == AAUDIO_STREAM_STATE_CLOSED);
    ALOGE_IF(bad, "stream not closed, in state %d", state);
}

aaudio_result_t AudioStreamTrack::open(const AudioStreamBuilder& builder)
{
    aaudio_result_t result = AAUDIO_OK;

    result = AudioStream::open(builder);
    if (result != OK) {
        return result;
    }

    // Try to create an AudioTrack
    // Use stereo if unspecified.
    int32_t samplesPerFrame = (getSamplesPerFrame() == AAUDIO_UNSPECIFIED)
                              ? 2 : getSamplesPerFrame();
    audio_channel_mask_t channelMask = audio_channel_out_mask_from_count(samplesPerFrame);

    audio_output_flags_t flags = AUDIO_OUTPUT_FLAG_NONE;
    aaudio_performance_mode_t perfMode = getPerformanceMode();
    switch(perfMode) {
        case AAUDIO_PERFORMANCE_MODE_LOW_LATENCY:
            // Bypass the normal mixer and go straight to the FAST mixer.
            flags = (audio_output_flags_t)(AUDIO_OUTPUT_FLAG_FAST | AUDIO_OUTPUT_FLAG_RAW);
            break;

        case AAUDIO_PERFORMANCE_MODE_POWER_SAVING:
            // This uses a mixer that wakes up less often than the FAST mixer.
            flags = AUDIO_OUTPUT_FLAG_DEEP_BUFFER;
            break;

        case AAUDIO_PERFORMANCE_MODE_NONE:
        default:
            // No flags. Use a normal mixer in front of the FAST mixer.
            break;
    }

    size_t frameCount = (size_t)builder.getBufferCapacity();

    int32_t notificationFrames = 0;

    audio_format_t format = (getFormat() == AAUDIO_FORMAT_UNSPECIFIED)
            ? AUDIO_FORMAT_PCM_FLOAT
            : AAudioConvert_aaudioToAndroidDataFormat(getFormat());

    // Setup the callback if there is one.
    AudioTrack::callback_t callback = nullptr;
    void *callbackData = nullptr;
    // Note that TRANSFER_SYNC does not allow FAST track
    AudioTrack::transfer_type streamTransferType = AudioTrack::transfer_type::TRANSFER_SYNC;
    if (builder.getDataCallbackProc() != nullptr) {
        streamTransferType = AudioTrack::transfer_type::TRANSFER_CALLBACK;
        callback = getLegacyCallback();
        callbackData = this;

        // If the total buffer size is unspecified then base the size on the burst size.
        if (frameCount == 0
                && ((flags & AUDIO_OUTPUT_FLAG_FAST) != 0)) {
            // Take advantage of a special trick that allows us to create a buffer
            // that is some multiple of the burst size.
            notificationFrames = 0 - DEFAULT_BURSTS_PER_BUFFER_CAPACITY;
        } else {
            notificationFrames = builder.getFramesPerDataCallback();
        }
    }
    mCallbackBufferSize = builder.getFramesPerDataCallback();

    ALOGD("AudioStreamTrack::open(), request notificationFrames = %d, frameCount = %u",
          notificationFrames, (uint)frameCount);
    mAudioTrack = new AudioTrack();
    if (getDeviceId() != AAUDIO_UNSPECIFIED) {
        mAudioTrack->setOutputDevice(getDeviceId());
    }
    mAudioTrack->set(
            (audio_stream_type_t) AUDIO_STREAM_MUSIC,
            getSampleRate(),
            format,
            channelMask,
            frameCount,
            flags,
            callback,
            callbackData,
            notificationFrames,
            0 /*sharedBuffer*/,
            false /*threadCanCallJava*/,
            AUDIO_SESSION_ALLOCATE,
            streamTransferType
            );

    // Did we get a valid track?
    status_t status = mAudioTrack->initCheck();
    if (status != NO_ERROR) {
        close();
        ALOGE("AudioStreamTrack::open(), initCheck() returned %d", status);
        return AAudioConvert_androidToAAudioResult(status);
    }

    //TrackPlayerBase init
    init(mAudioTrack.get(), PLAYER_TYPE_AAUDIO, AUDIO_USAGE_MEDIA);

    // Get the actual values from the AudioTrack.
    setSamplesPerFrame(mAudioTrack->channelCount());
    aaudio_format_t aaudioFormat =
            AAudioConvert_androidToAAudioDataFormat(mAudioTrack->format());
    setFormat(aaudioFormat);

    int32_t actualSampleRate = mAudioTrack->getSampleRate();
    ALOGW_IF(actualSampleRate != getSampleRate(),
             "AudioStreamTrack::open() sampleRate changed from %d to %d",
             getSampleRate(), actualSampleRate);
    setSampleRate(actualSampleRate);

    // We may need to pass the data through a block size adapter to guarantee constant size.
    if (mCallbackBufferSize != AAUDIO_UNSPECIFIED) {
        int callbackSizeBytes = getBytesPerFrame() * mCallbackBufferSize;
        mFixedBlockReader.open(callbackSizeBytes);
        mBlockAdapter = &mFixedBlockReader;
    } else {
        mBlockAdapter = nullptr;
    }

    setState(AAUDIO_STREAM_STATE_OPEN);
    setDeviceId(mAudioTrack->getRoutedDeviceId());
    mAudioTrack->addAudioDeviceCallback(mDeviceCallback);

    // Update performance mode based on the actual stream.
    // For example, if the sample rate is not allowed then you won't get a FAST track.
    audio_output_flags_t actualFlags = mAudioTrack->getFlags();
    aaudio_performance_mode_t actualPerformanceMode = AAUDIO_PERFORMANCE_MODE_NONE;
    if ((actualFlags & (AUDIO_OUTPUT_FLAG_FAST | AUDIO_OUTPUT_FLAG_RAW))
        == (AUDIO_OUTPUT_FLAG_FAST | AUDIO_OUTPUT_FLAG_RAW)) {
        actualPerformanceMode = AAUDIO_PERFORMANCE_MODE_LOW_LATENCY;

    } else if ((actualFlags & AUDIO_OUTPUT_FLAG_DEEP_BUFFER) != 0) {
        actualPerformanceMode = AAUDIO_PERFORMANCE_MODE_POWER_SAVING;
    }
    setPerformanceMode(actualPerformanceMode);
    // Log warning if we did not get what we asked for.
    ALOGW_IF(actualFlags != flags,
             "AudioStreamTrack::open() flags changed from 0x%08X to 0x%08X",
             flags, actualFlags);
    ALOGW_IF(actualPerformanceMode != perfMode,
             "AudioStreamTrack::open() perfMode changed from %d to %d",
             perfMode, actualPerformanceMode);

    return AAUDIO_OK;
}

aaudio_result_t AudioStreamTrack::close()
{
    if (getState() != AAUDIO_STREAM_STATE_CLOSED) {
        destroy();
        setState(AAUDIO_STREAM_STATE_CLOSED);
    }
    mFixedBlockReader.close();
    return AAUDIO_OK;
}

void AudioStreamTrack::processCallback(int event, void *info) {

    switch (event) {
        case AudioTrack::EVENT_MORE_DATA:
            processCallbackCommon(AAUDIO_CALLBACK_OPERATION_PROCESS_DATA, info);
            break;

            // Stream got rerouted so we disconnect.
        case AudioTrack::EVENT_NEW_IAUDIOTRACK:
            processCallbackCommon(AAUDIO_CALLBACK_OPERATION_DISCONNECTED, info);
            break;

        default:
            break;
    }
    return;
}

aaudio_result_t AudioStreamTrack::requestStart()
{
    std::lock_guard<std::mutex> lock(mStreamMutex);

    if (mAudioTrack.get() == nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    // Get current position so we can detect when the track is playing.
    status_t err = mAudioTrack->getPosition(&mPositionWhenStarting);
    if (err != OK) {
        return AAudioConvert_androidToAAudioResult(err);
    }

    err = startWithStatus();
    if (err != OK) {
        return AAudioConvert_androidToAAudioResult(err);
    } else {
        onStart();
        setState(AAUDIO_STREAM_STATE_STARTING);
    }
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamTrack::requestPause()
{
    std::lock_guard<std::mutex> lock(mStreamMutex);

    if (mAudioTrack.get() == nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    } else if (getState() != AAUDIO_STREAM_STATE_STARTING
            && getState() != AAUDIO_STREAM_STATE_STARTED) {
        ALOGE("requestPause(), called when state is %s",
              AAudio_convertStreamStateToText(getState()));
        return AAUDIO_ERROR_INVALID_STATE;
    }
    onStop();
    setState(AAUDIO_STREAM_STATE_PAUSING);
    pause();
    status_t err = mAudioTrack->getPosition(&mPositionWhenPausing);
    if (err != OK) {
        return AAudioConvert_androidToAAudioResult(err);
    }
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamTrack::requestFlush() {
    std::lock_guard<std::mutex> lock(mStreamMutex);

    if (mAudioTrack.get() == nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    } else if (getState() != AAUDIO_STREAM_STATE_PAUSED) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    setState(AAUDIO_STREAM_STATE_FLUSHING);
    incrementFramesRead(getFramesWritten() - getFramesRead());
    mAudioTrack->flush();
    mFramesWritten.reset32();
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamTrack::requestStop() {
    std::lock_guard<std::mutex> lock(mStreamMutex);

    if (mAudioTrack.get() == nullptr) {
        return AAUDIO_ERROR_INVALID_STATE;
    }
    onStop();
    setState(AAUDIO_STREAM_STATE_STOPPING);
    incrementFramesRead(getFramesWritten() - getFramesRead()); // TODO review
    stop();
    mFramesWritten.reset32();
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamTrack::updateStateWhileWaiting()
{
    status_t err;
    aaudio_wrapping_frames_t position;
    switch (getState()) {
    // TODO add better state visibility to AudioTrack
    case AAUDIO_STREAM_STATE_STARTING:
        if (mAudioTrack->hasStarted()) {
            setState(AAUDIO_STREAM_STATE_STARTED);
        }
        break;
    case AAUDIO_STREAM_STATE_PAUSING:
        if (mAudioTrack->stopped()) {
            err = mAudioTrack->getPosition(&position);
            if (err != OK) {
                return AAudioConvert_androidToAAudioResult(err);
            } else if (position == mPositionWhenPausing) {
                // Has stream really stopped advancing?
                setState(AAUDIO_STREAM_STATE_PAUSED);
            }
            mPositionWhenPausing = position;
        }
        break;
    case AAUDIO_STREAM_STATE_FLUSHING:
        {
            err = mAudioTrack->getPosition(&position);
            if (err != OK) {
                return AAudioConvert_androidToAAudioResult(err);
            } else if (position == 0) {
                // TODO Advance frames read to match written.
                setState(AAUDIO_STREAM_STATE_FLUSHED);
            }
        }
        break;
    case AAUDIO_STREAM_STATE_STOPPING:
        if (mAudioTrack->stopped()) {
            setState(AAUDIO_STREAM_STATE_STOPPED);
        }
        break;
    default:
        break;
    }
    return AAUDIO_OK;
}

aaudio_result_t AudioStreamTrack::write(const void *buffer,
                                      int32_t numFrames,
                                      int64_t timeoutNanoseconds)
{
    int32_t bytesPerFrame = getBytesPerFrame();
    int32_t numBytes;
    aaudio_result_t result = AAudioConvert_framesToBytes(numFrames, bytesPerFrame, &numBytes);
    if (result != AAUDIO_OK) {
        return result;
    }

    if (getState() == AAUDIO_STREAM_STATE_DISCONNECTED) {
        return AAUDIO_ERROR_DISCONNECTED;
    }

    // TODO add timeout to AudioTrack
    bool blocking = timeoutNanoseconds > 0;
    ssize_t bytesWritten = mAudioTrack->write(buffer, numBytes, blocking);
    if (bytesWritten == WOULD_BLOCK) {
        return 0;
    } else if (bytesWritten < 0) {
        ALOGE("invalid write, returned %d", (int)bytesWritten);
        // in this context, a DEAD_OBJECT is more likely to be a disconnect notification due to
        // AudioTrack invalidation
        if (bytesWritten == DEAD_OBJECT) {
            setState(AAUDIO_STREAM_STATE_DISCONNECTED);
            return AAUDIO_ERROR_DISCONNECTED;
        }
        return AAudioConvert_androidToAAudioResult(bytesWritten);
    }
    int32_t framesWritten = (int32_t)(bytesWritten / bytesPerFrame);
    incrementFramesWritten(framesWritten);
    return framesWritten;
}

aaudio_result_t AudioStreamTrack::setBufferSize(int32_t requestedFrames)
{
    ssize_t result = mAudioTrack->setBufferSizeInFrames(requestedFrames);
    if (result < 0) {
        return AAudioConvert_androidToAAudioResult(result);
    } else {
        return result;
    }
}

int32_t AudioStreamTrack::getBufferSize() const
{
    return static_cast<int32_t>(mAudioTrack->getBufferSizeInFrames());
}

int32_t AudioStreamTrack::getBufferCapacity() const
{
    return static_cast<int32_t>(mAudioTrack->frameCount());
}

int32_t AudioStreamTrack::getXRunCount() const
{
    return static_cast<int32_t>(mAudioTrack->getUnderrunCount());
}

int32_t AudioStreamTrack::getFramesPerBurst() const
{
    return static_cast<int32_t>(mAudioTrack->getNotificationPeriodInFrames());
}

int64_t AudioStreamTrack::getFramesRead() {
    aaudio_wrapping_frames_t position;
    status_t result;
    switch (getState()) {
    case AAUDIO_STREAM_STATE_STARTING:
    case AAUDIO_STREAM_STATE_STARTED:
    case AAUDIO_STREAM_STATE_STOPPING:
    case AAUDIO_STREAM_STATE_PAUSING:
    case AAUDIO_STREAM_STATE_PAUSED:
        result = mAudioTrack->getPosition(&position);
        if (result == OK) {
            mFramesRead.update32(position);
        }
        break;
    default:
        break;
    }
    return AudioStreamLegacy::getFramesRead();
}

aaudio_result_t AudioStreamTrack::getTimestamp(clockid_t clockId,
                                     int64_t *framePosition,
                                     int64_t *timeNanoseconds) {
    ExtendedTimestamp extendedTimestamp;
    status_t status = mAudioTrack->getTimestamp(&extendedTimestamp);
    if (status != NO_ERROR) {
        return AAudioConvert_androidToAAudioResult(status);
    }
    return getBestTimestamp(clockId, framePosition, timeNanoseconds, &extendedTimestamp);
}
