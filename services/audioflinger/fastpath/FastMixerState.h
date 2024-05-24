/*
 * Copyright (C) 2012 The Android Open Source Project
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

#pragma once

#include <math.h>
#include <type_traits>

#include <audio_utils/minifloat.h>
#include <system/audio.h>
#include <media/AudioMixer.h>
#include <media/ExtendedAudioBufferProvider.h>
#include <media/nbaio/NBAIO.h>
#include <media/nblog/NBLog.h>
#include <vibrator/ExternalVibrationUtils.h>
#include "FastThreadState.h"

namespace android {

struct FastMixerDumpState;

class VolumeProvider {
public:
    // The provider implementation is responsible for validating that the return value is in range.
    virtual gain_minifloat_packed_t getVolumeLR() const = 0;
protected:
    VolumeProvider() = default;
    virtual ~VolumeProvider() = default;
};

// Represents the state of a fast track
struct FastTrack {
    // must be nullptr if inactive, or non-nullptr if active
    ExtendedAudioBufferProvider* mBufferProvider = nullptr;

    // optional: if nullptr then full-scale
    VolumeProvider*         mVolumeProvider = nullptr;

    // AUDIO_CHANNEL_OUT_MONO or AUDIO_CHANNEL_OUT_STEREO
    audio_channel_mask_t    mChannelMask = AUDIO_CHANNEL_OUT_STEREO;
    audio_format_t          mFormat = AUDIO_FORMAT_INVALID;         // track format
    int                     mGeneration = 0;     // increment when any field is assigned
    bool                    mHapticPlaybackEnabled = false; // haptic playback is enabled or not
    os::HapticScale mHapticScale = os::HapticScale::mute(); // scale of haptic data
    float                   mHapticMaxAmplitude = NAN; // max amplitude allowed for haptic data
};

// No virtuals.
static_assert(!std::is_polymorphic_v<FastTrack>);

// Represents a single state of the fast mixer
struct FastMixerState : FastThreadState {
    FastMixerState();

    // These are the minimum, maximum, and default values for maximum number of fast tracks
    static constexpr unsigned kMinFastTracks = 2;
    static constexpr unsigned kMaxFastTracks = 32;
    static constexpr unsigned kDefaultFastTracks = 8;

    static unsigned sMaxFastTracks;             // Configured maximum number of fast tracks
    static pthread_once_t sMaxFastTracksOnce;   // Protects initializer for sMaxFastTracks

    // all pointer fields use raw pointers; objects are owned and ref-counted by the normal mixer
    FastTrack   mFastTracks[kMaxFastTracks];
    int         mFastTracksGen = 0; // increment when any
                                    // mFastTracks[i].mGeneration is incremented
    unsigned    mTrackMask = 0;     // bit i is set if and only if mFastTracks[i] is active
    NBAIO_Sink* mOutputSink = nullptr; // HAL output device, must already be negotiated
    int         mOutputSinkGen = 0; // increment when mOutputSink is assigned
    size_t      mFrameCount = 0;    // number of frames per fast mix buffer
    audio_channel_mask_t mSinkChannelMask; // If not AUDIO_CHANNEL_NONE, specifies sink channel
                                           // mask when it cannot be directly calculated from
                                           // channel count

    // Extends FastThreadState::Command
    static const Command
        // The following commands also process configuration changes, and can be "or"ed:
        MIX = 0x8,              // mix tracks
        WRITE = 0x10,           // write to output sink
        MIX_WRITE = 0x18;       // mix tracks and write to output sink

    // never returns NULL; asserts if command is invalid
    static const char *commandToString(Command command);

    // initialize sMaxFastTracks
    static void sMaxFastTracksInit();

};  // struct FastMixerState

// No virtuals.
static_assert(!std::is_polymorphic_v<FastMixerState>);

}   // namespace android
