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

    void stop();

protected:
    jobject mAudioTrackObj;         // Java AudioTrack object

};

}; // namespace android

#endif // ANDROID_JAUDIOTRACK_H
