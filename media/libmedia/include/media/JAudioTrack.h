/*
 * Copyright 2018 The Android Open Source Project
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

#ifndef ANDROID_JAUDIOTRACK_H
#define ANDROID_JAUDIOTRACK_H

#include <jni.h>
#include <system/audio.h>

namespace android {

class JAudioTrack {
public:

    /* Creates an JAudioTrack object for non-offload mode.
     * Once created, the track needs to be started before it can be used.
     * Unspecified values are set to appropriate default values.
     *
     * Parameters:
     *
     * streamType:         Select the type of audio stream this track is attached to
     *                     (e.g. AUDIO_STREAM_MUSIC).
     * sampleRate:         Data source sampling rate in Hz.  Zero means to use the sink sample rate.
     *                     A non-zero value must be specified if AUDIO_OUTPUT_FLAG_DIRECT is set.
     *                     0 will not work with current policy implementation for direct output
     *                     selection where an exact match is needed for sampling rate.
     *                     (TODO: Check direct output after flags can be used in Java AudioTrack.)
     * format:             Audio format. For mixed tracks, any PCM format supported by server is OK.
     *                     For direct and offloaded tracks, the possible format(s) depends on the
     *                     output sink.
     *                     (TODO: How can we check whether a format is supported?)
     * channelMask:        Channel mask, such that audio_is_output_channel(channelMask) is true.
     * frameCount:         Minimum size of track PCM buffer in frames. This defines the
     *                     application's contribution to the latency of the track.
     *                     The actual size selected by the JAudioTrack could be larger if the
     *                     requested size is not compatible with current audio HAL configuration.
     *                     Zero means to use a default value.
     * sessionId:          Specific session ID, or zero to use default.
     * pAttributes:        If not NULL, supersedes streamType for use case selection.
     * maxRequiredSpeed:   For PCM tracks, this creates an appropriate buffer size that will allow
     *                     maxRequiredSpeed playback. Values less than 1.0f and greater than
     *                     AUDIO_TIMESTRETCH_SPEED_MAX will be clamped.  For non-PCM tracks
     *                     and direct or offloaded tracks, this parameter is ignored.
     *                     (TODO: Handle this after offload / direct track is supported.)
     *
     * TODO: Revive removed arguments after offload mode is supported.
     */
    JAudioTrack(audio_stream_type_t streamType,
                uint32_t sampleRate,
                audio_format_t format,
                audio_channel_mask_t channelMask,
                size_t frameCount = 0,
                audio_session_t sessionId  = AUDIO_SESSION_ALLOCATE,
                const audio_attributes_t* pAttributes = NULL,
                float maxRequiredSpeed = 1.0f);

    /*
       Temporarily removed constructor arguments:

       // Q. Values are in audio-base.h, but where can we find explanation for them?
       audio_output_flags_t flags,

       // Q. May be used in AudioTrack.setPreferredDevice(AudioDeviceInfo)?
       audio_port_handle_t selectedDeviceId,

       // Should be deleted, since we don't use Binder anymore.
       bool doNotReconnect,

       // Do we need UID and PID?
       uid_t uid,
       pid_t pid,

       // TODO: Uses these values when Java AudioTrack supports the offload mode.
       callback_t cbf,
       void* user,
       int32_t notificationFrames,
       const audio_offload_info_t *offloadInfo,

       // Fixed to false, but what is this?
       threadCanCallJava
    */

    virtual ~JAudioTrack();

    size_t frameCount();
    size_t channelCount();

    /* Return the total number of frames played since playback start.
     * The counter will wrap (overflow) periodically, e.g. every ~27 hours at 44.1 kHz.
     * It is reset to zero by flush(), reload(), and stop().
     *
     * Parameters:
     *
     * position: Address where to return play head position.
     *
     * Returned status (from utils/Errors.h) can be:
     *  - NO_ERROR: successful operation
     *  - BAD_VALUE: position is NULL
     */
    status_t getPosition(uint32_t *position);

    /* Set the send level for this track. An auxiliary effect should be attached
     * to the track with attachAuxEffect(). Level must be >= 0.0 and <= 1.0.
     */
    status_t setAuxEffectSendLevel(float level);

    /* Attach track auxiliary output to specified effect. Use effectId = 0
     * to detach track from effect.
     *
     * Parameters:
     *
     * effectId: effectId obtained from AudioEffect::id().
     *
     * Returned status (from utils/Errors.h) can be:
     *  - NO_ERROR: successful operation
     *  - INVALID_OPERATION: the effect is not an auxiliary effect.
     *  - BAD_VALUE: The specified effect ID is invalid
     */
    status_t attachAuxEffect(int effectId);

    /* Set volume for this track, mostly used for games' sound effects
     * left and right volumes. Levels must be >= 0.0 and <= 1.0.
     * This is the older API.  New applications should use setVolume(float) when possible.
     */
    status_t setVolume(float left, float right);

    /* Set volume for all channels. This is the preferred API for new applications,
     * especially for multi-channel content.
     */
    status_t setVolume(float volume);

    // TODO: Does this comment equally apply to the Java AudioTrack::play()?
    /* After it's created the track is not active. Call start() to
     * make it active. If set, the callback will start being called.
     * If the track was previously paused, volume is ramped up over the first mix buffer.
     */
    status_t start();

    // TODO: Does this comment equally apply to the Java AudioTrack::stop()?
    /* Stop a track.
     * In static buffer mode, the track is stopped immediately.
     * In streaming mode, the callback will cease being called.  Note that obtainBuffer() still
     * works and will fill up buffers until the pool is exhausted, and then will return WOULD_BLOCK.
     * In streaming mode the stop does not occur immediately: any data remaining in the buffer
     * is first drained, mixed, and output, and only then is the track marked as stopped.
     */
    void stop();
    bool stopped() const;

    // TODO: Does this comment equally apply to the Java AudioTrack::flush()?
    /* Flush a stopped or paused track. All previously buffered data is discarded immediately.
     * This has the effect of draining the buffers without mixing or output.
     * Flush is intended for streaming mode, for example before switching to non-contiguous content.
     * This function is a no-op if the track is not stopped or paused, or uses a static buffer.
     */
    void flush();

    // TODO: Does this comment equally apply to the Java AudioTrack::pause()?
    // At least we are not using obtainBuffer.
    /* Pause a track. After pause, the callback will cease being called and
     * obtainBuffer returns WOULD_BLOCK. Note that obtainBuffer() still works
     * and will fill up buffers until the pool is exhausted.
     * Volume is ramped down over the next mix buffer following the pause request,
     * and then the track is marked as paused. It can be resumed with ramp up by start().
     */
    void pause();

    bool isPlaying() const;

    /* Return current source sample rate in Hz.
     * If specified as zero in constructor, this will be the sink sample rate.
     */
    uint32_t getSampleRate();

    audio_format_t format();

private:
    jclass mAudioTrackCls;
    jobject mAudioTrackObj;

    status_t javaToNativeStatus(int javaStatus);
};

}; // namespace android

#endif // ANDROID_JAUDIOTRACK_H
