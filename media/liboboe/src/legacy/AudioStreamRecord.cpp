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

#define LOG_TAG "AudioStreamRecord"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <utils/String16.h>
#include <media/AudioRecord.h>
#include <oboe/OboeAudio.h>

#include "AudioClock.h"
#include "AudioStreamRecord.h"

using namespace android;
using namespace oboe;

AudioStreamRecord::AudioStreamRecord()
    : AudioStream()
{
}

AudioStreamRecord::~AudioStreamRecord()
{
    const oboe_stream_state_t state = getState();
    bool bad = !(state == OBOE_STREAM_STATE_UNINITIALIZED || state == OBOE_STREAM_STATE_CLOSED);
    ALOGE_IF(bad, "stream not closed, in state %d", state);
}

oboe_result_t AudioStreamRecord::open(const AudioStreamBuilder& builder)
{
    oboe_result_t result = OBOE_OK;

    result = AudioStream::open(builder);
    if (result != OBOE_OK) {
        return result;
    }

    // Try to create an AudioRecord

    // TODO Support UNSPECIFIED in AudioTrack. For now, use stereo if unspecified.
    int32_t samplesPerFrame = (getSamplesPerFrame() == OBOE_UNSPECIFIED)
                              ? 2 : getSamplesPerFrame();
    audio_channel_mask_t channelMask = audio_channel_in_mask_from_count(samplesPerFrame);

    AudioRecord::callback_t callback = NULL;
    audio_input_flags_t flags = (audio_input_flags_t) AUDIO_INPUT_FLAG_NONE;

    // TODO implement an unspecified Android format then use that.
    audio_format_t format = (getFormat() == OBOE_UNSPECIFIED)
            ? AUDIO_FORMAT_PCM_FLOAT
            : OboeConvert_oboeToAndroidDataFormat(getFormat());

    mAudioRecord = new AudioRecord(
            AUDIO_SOURCE_DEFAULT,
            getSampleRate(),
            format,
            channelMask,

            mOpPackageName, // const String16& opPackageName TODO does not compile

            0,    //    size_t frameCount = 0,
            callback,
            NULL, //    void* user = NULL,
            0,    //    uint32_t notificationFrames = 0,
            AUDIO_SESSION_ALLOCATE,
            AudioRecord::TRANSFER_DEFAULT,
            flags
             //   int uid = -1,
             //   pid_t pid = -1,
             //   const audio_attributes_t* pAttributes = NULL
             );

    // Did we get a valid track?
    status_t status = mAudioRecord->initCheck();
    if (status != OK) {
        close();
        ALOGE("AudioStreamRecord::open(), initCheck() returned %d", status);
        return OboeConvert_androidToOboeError(status);
    }

    // Get the actual rate.
    setSampleRate(mAudioRecord->getSampleRate());
    setSamplesPerFrame(mAudioRecord->channelCount());
    setFormat(OboeConvert_androidToOboeDataFormat(mAudioRecord->format()));

    setState(OBOE_STREAM_STATE_OPEN);

    return OBOE_OK;
}

oboe_result_t AudioStreamRecord::close()
{
    // TODO add close() or release() to AudioRecord API then call it from here
    if (getState() != OBOE_STREAM_STATE_CLOSED) {
        mAudioRecord.clear();
        setState(OBOE_STREAM_STATE_CLOSED);
    }
    return OBOE_OK;
}

oboe_result_t AudioStreamRecord::requestStart()
{
    if (mAudioRecord.get() == NULL) {
        return OBOE_ERROR_INVALID_STATE;
    }
    // Get current position so we can detect when the track is playing.
    status_t err = mAudioRecord->getPosition(&mPositionWhenStarting);
    if (err != OK) {
        return OboeConvert_androidToOboeError(err);
    }
    err = mAudioRecord->start();
    if (err != OK) {
        return OboeConvert_androidToOboeError(err);
    } else {
        setState(OBOE_STREAM_STATE_STARTING);
    }
    return OBOE_OK;
}

oboe_result_t AudioStreamRecord::requestPause()
{
    return OBOE_ERROR_UNIMPLEMENTED;
}

oboe_result_t AudioStreamRecord::requestFlush() {
    return OBOE_ERROR_UNIMPLEMENTED;
}

oboe_result_t AudioStreamRecord::requestStop() {
    if (mAudioRecord.get() == NULL) {
        return OBOE_ERROR_INVALID_STATE;
    }
    setState(OBOE_STREAM_STATE_STOPPING);
    mAudioRecord->stop();
    return OBOE_OK;
}

oboe_result_t AudioStreamRecord::updateState()
{
    oboe_result_t result = OBOE_OK;
    oboe_wrapping_frames_t position;
    status_t err;
    switch (getState()) {
    // TODO add better state visibility to AudioRecord
    case OBOE_STREAM_STATE_STARTING:
        err = mAudioRecord->getPosition(&position);
        if (err != OK) {
            result = OboeConvert_androidToOboeError(err);
        } else if (position != mPositionWhenStarting) {
            setState(OBOE_STREAM_STATE_STARTED);
        }
        break;
    case OBOE_STREAM_STATE_STOPPING:
        if (mAudioRecord->stopped()) {
            setState(OBOE_STREAM_STATE_STOPPED);
        }
        break;
    default:
        break;
    }
    return result;
}

oboe_result_t AudioStreamRecord::read(void *buffer,
                                      oboe_size_frames_t numFrames,
                                      oboe_nanoseconds_t timeoutNanoseconds)
{
    oboe_size_frames_t bytesPerFrame = getBytesPerFrame();
    oboe_size_bytes_t numBytes;
    oboe_result_t result = OboeConvert_framesToBytes(numFrames, bytesPerFrame, &numBytes);
    if (result != OBOE_OK) {
        return result;
    }

    // TODO add timeout to AudioRecord
    bool blocking = (timeoutNanoseconds > 0);
    ssize_t bytesRead = mAudioRecord->read(buffer, numBytes, blocking);
    if (bytesRead == WOULD_BLOCK) {
        return 0;
    } else if (bytesRead < 0) {
        return OboeConvert_androidToOboeError(bytesRead);
    }
    oboe_size_frames_t framesRead = (oboe_size_frames_t)(bytesRead / bytesPerFrame);
    return (oboe_result_t) framesRead;
}

oboe_result_t AudioStreamRecord::setBufferSize(oboe_size_frames_t requestedFrames,
                                             oboe_size_frames_t *actualFrames)
{
    *actualFrames = getBufferCapacity();
    return OBOE_OK;
}

oboe_size_frames_t AudioStreamRecord::getBufferSize() const
{
    return getBufferCapacity(); // TODO implement in AudioRecord?
}

oboe_size_frames_t AudioStreamRecord::getBufferCapacity() const
{
    return static_cast<oboe_size_frames_t>(mAudioRecord->frameCount());
}

int32_t AudioStreamRecord::getXRunCount() const
{
    return OBOE_ERROR_UNIMPLEMENTED; // TODO implement when AudioRecord supports it
}

oboe_size_frames_t AudioStreamRecord::getFramesPerBurst() const
{
    return 192; // TODO add query to AudioRecord.cpp
}

// TODO implement getTimestamp

