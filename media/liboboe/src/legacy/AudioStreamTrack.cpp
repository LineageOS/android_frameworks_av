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

#define LOG_TAG "AudioStreamTrack"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <media/AudioTrack.h>

#include <oboe/OboeAudio.h>
#include "AudioClock.h"
#include "AudioStreamTrack.h"


using namespace android;
using namespace oboe;

/*
 * Create a stream that uses the AudioTrack.
 */
AudioStreamTrack::AudioStreamTrack()
    : AudioStream()
{
}

AudioStreamTrack::~AudioStreamTrack()
{
    const oboe_stream_state_t state = getState();
    bool bad = !(state == OBOE_STREAM_STATE_UNINITIALIZED || state == OBOE_STREAM_STATE_CLOSED);
    ALOGE_IF(bad, "stream not closed, in state %d", state);
}

oboe_result_t AudioStreamTrack::open(const AudioStreamBuilder& builder)
{
    oboe_result_t result = OBOE_OK;

    result = AudioStream::open(builder);
    if (result != OK) {
        return result;
    }

    // Try to create an AudioTrack
    // TODO Support UNSPECIFIED in AudioTrack. For now, use stereo if unspecified.
    int32_t samplesPerFrame = (getSamplesPerFrame() == OBOE_UNSPECIFIED)
                              ? 2 : getSamplesPerFrame();
    audio_channel_mask_t channelMask = audio_channel_out_mask_from_count(samplesPerFrame);
    ALOGE("AudioStreamTrack::open(), samplesPerFrame = %d, channelMask = 0x%08x",
            samplesPerFrame, channelMask);

    AudioTrack::callback_t callback = NULL;
    // TODO add more performance options
    audio_output_flags_t flags = (audio_output_flags_t) AUDIO_OUTPUT_FLAG_FAST;
    size_t frameCount = 0;
    // TODO implement an unspecified AudioTrack format then use that.
    audio_format_t format = (getFormat() == OBOE_UNSPECIFIED)
            ? AUDIO_FORMAT_PCM_FLOAT
            : OboeConvert_oboeToAndroidDataFormat(getFormat());

    mAudioTrack = new AudioTrack(
            (audio_stream_type_t) AUDIO_STREAM_MUSIC,
            getSampleRate(),
            format,
            channelMask,
            frameCount,
            flags,
            callback,
            NULL,    // user callback data
            0,       // notificationFrames
            AUDIO_SESSION_ALLOCATE,
            AudioTrack::transfer_type::TRANSFER_SYNC // TODO - this does not allow FAST
            );

    // Did we get a valid track?
    status_t status = mAudioTrack->initCheck();
    // FIXME - this should work - if (status != NO_ERROR) {
    //         But initCheck() is returning 1 !
    if (status < 0) {
        close();
        ALOGE("AudioStreamTrack::open(), initCheck() returned %d", status);
        return OboeConvert_androidToOboeError(status);
    }

    // Get the actual values from the AudioTrack.
    setSamplesPerFrame(mAudioTrack->channelCount());
    setSampleRate(mAudioTrack->getSampleRate());
    setFormat(OboeConvert_androidToOboeDataFormat(mAudioTrack->format()));

    setState(OBOE_STREAM_STATE_OPEN);

    return OBOE_OK;
}

oboe_result_t AudioStreamTrack::close()
{
    // TODO maybe add close() or release() to AudioTrack API then call it from here
    if (getState() != OBOE_STREAM_STATE_CLOSED) {
        mAudioTrack.clear(); // TODO is this right?
        setState(OBOE_STREAM_STATE_CLOSED);
    }
    return OBOE_OK;
}

oboe_result_t AudioStreamTrack::requestStart()
{
    if (mAudioTrack.get() == NULL) {
        return OBOE_ERROR_INVALID_STATE;
    }
    // Get current position so we can detect when the track is playing.
    status_t err = mAudioTrack->getPosition(&mPositionWhenStarting);
    if (err != OK) {
        return OboeConvert_androidToOboeError(err);
    }
    err = mAudioTrack->start();
    if (err != OK) {
        return OboeConvert_androidToOboeError(err);
    } else {
        setState(OBOE_STREAM_STATE_STARTING);
    }
    return OBOE_OK;
}

oboe_result_t AudioStreamTrack::requestPause()
{
    if (mAudioTrack.get() == NULL) {
        return OBOE_ERROR_INVALID_STATE;
    } else if (getState() != OBOE_STREAM_STATE_STARTING
            && getState() != OBOE_STREAM_STATE_STARTED) {
        ALOGE("requestPause(), called when state is %s", Oboe_convertStreamStateToText(getState()));
        return OBOE_ERROR_INVALID_STATE;
    }
    setState(OBOE_STREAM_STATE_PAUSING);
    mAudioTrack->pause();
    status_t err = mAudioTrack->getPosition(&mPositionWhenPausing);
    if (err != OK) {
        return OboeConvert_androidToOboeError(err);
    }
    return OBOE_OK;
}

oboe_result_t AudioStreamTrack::requestFlush() {
    if (mAudioTrack.get() == NULL) {
        return OBOE_ERROR_INVALID_STATE;
    } else if (getState() != OBOE_STREAM_STATE_PAUSED) {
        return OBOE_ERROR_INVALID_STATE;
    }
    setState(OBOE_STREAM_STATE_FLUSHING);
    incrementFramesRead(getFramesWritten() - getFramesRead());
    mAudioTrack->flush();
    mFramesWritten.reset32();
    return OBOE_OK;
}

oboe_result_t AudioStreamTrack::requestStop() {
    if (mAudioTrack.get() == NULL) {
        return OBOE_ERROR_INVALID_STATE;
    }
    setState(OBOE_STREAM_STATE_STOPPING);
    incrementFramesRead(getFramesWritten() - getFramesRead()); // TODO review
    mAudioTrack->stop();
    mFramesWritten.reset32();
    return OBOE_OK;
}

oboe_result_t AudioStreamTrack::updateState()
{
    status_t err;
    oboe_wrapping_frames_t position;
    switch (getState()) {
    // TODO add better state visibility to AudioTrack
    case OBOE_STREAM_STATE_STARTING:
        if (mAudioTrack->hasStarted()) {
            setState(OBOE_STREAM_STATE_STARTED);
        }
        break;
    case OBOE_STREAM_STATE_PAUSING:
        if (mAudioTrack->stopped()) {
            err = mAudioTrack->getPosition(&position);
            if (err != OK) {
                return OboeConvert_androidToOboeError(err);
            } else if (position == mPositionWhenPausing) {
                // Has stream really stopped advancing?
                setState(OBOE_STREAM_STATE_PAUSED);
            }
            mPositionWhenPausing = position;
        }
        break;
    case OBOE_STREAM_STATE_FLUSHING:
        {
            err = mAudioTrack->getPosition(&position);
            if (err != OK) {
                return OboeConvert_androidToOboeError(err);
            } else if (position == 0) {
                // Advance frames read to match written.
                setState(OBOE_STREAM_STATE_FLUSHED);
            }
        }
        break;
    case OBOE_STREAM_STATE_STOPPING:
        if (mAudioTrack->stopped()) {
            setState(OBOE_STREAM_STATE_STOPPED);
        }
        break;
    default:
        break;
    }
    return OBOE_OK;
}

oboe_result_t AudioStreamTrack::write(const void *buffer,
                                      oboe_size_frames_t numFrames,
                                      oboe_nanoseconds_t timeoutNanoseconds)
{
    oboe_size_frames_t bytesPerFrame = getBytesPerFrame();
    oboe_size_bytes_t numBytes;
    oboe_result_t result = OboeConvert_framesToBytes(numFrames, bytesPerFrame, &numBytes);
    if (result != OBOE_OK) {
        return result;
    }

    // TODO add timeout to AudioTrack
    bool blocking = timeoutNanoseconds > 0;
    ssize_t bytesWritten = mAudioTrack->write(buffer, numBytes, blocking);
    if (bytesWritten == WOULD_BLOCK) {
        return 0;
    } else if (bytesWritten < 0) {
        ALOGE("invalid write, returned %d", (int)bytesWritten);
        return OboeConvert_androidToOboeError(bytesWritten);
    }
    oboe_size_frames_t framesWritten = (oboe_size_frames_t)(bytesWritten / bytesPerFrame);
    incrementFramesWritten(framesWritten);
    return framesWritten;
}

oboe_result_t AudioStreamTrack::setBufferSize(oboe_size_frames_t requestedFrames,
                                             oboe_size_frames_t *actualFrames)
{
    ssize_t result = mAudioTrack->setBufferSizeInFrames(requestedFrames);
    if (result != OK) {
        return OboeConvert_androidToOboeError(result);
    } else {
        *actualFrames = result;
        return OBOE_OK;
    }
}

oboe_size_frames_t AudioStreamTrack::getBufferSize() const
{
    return static_cast<oboe_size_frames_t>(mAudioTrack->getBufferSizeInFrames());
}

oboe_size_frames_t AudioStreamTrack::getBufferCapacity() const
{
    return static_cast<oboe_size_frames_t>(mAudioTrack->frameCount());
}

int32_t AudioStreamTrack::getXRunCount() const
{
    return static_cast<int32_t>(mAudioTrack->getUnderrunCount());
}

int32_t AudioStreamTrack::getFramesPerBurst() const
{
    return 192; // TODO add query to AudioTrack.cpp
}

oboe_position_frames_t AudioStreamTrack::getFramesRead() {
    oboe_wrapping_frames_t position;
    status_t result;
    switch (getState()) {
    case OBOE_STREAM_STATE_STARTING:
    case OBOE_STREAM_STATE_STARTED:
    case OBOE_STREAM_STATE_STOPPING:
        result = mAudioTrack->getPosition(&position);
        if (result == OK) {
            mFramesRead.update32(position);
        }
        break;
    default:
        break;
    }
    return AudioStream::getFramesRead();
}
