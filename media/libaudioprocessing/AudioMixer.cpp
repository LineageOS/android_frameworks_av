/*
**
** Copyright 2007, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define LOG_TAG "AudioMixer"
//#define LOG_NDEBUG 0

#include <sstream>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <utils/Log.h>

#include <system/audio.h>

#include <audio_utils/primitives.h>
#include <audio_utils/format.h>
#include <media/AudioMixer.h>

#include "AudioMixerOps.h"

// The FCC_2 macro refers to the Fixed Channel Count of 2 for the legacy integer mixer.
#ifndef FCC_2
#define FCC_2 2
#endif

// Look for MONO_HACK for any Mono hack involving legacy mono channel to
// stereo channel conversion.

/* VERY_VERY_VERBOSE_LOGGING will show exactly which process hook and track hook is
 * being used. This is a considerable amount of log spam, so don't enable unless you
 * are verifying the hook based code.
 */
//#define VERY_VERY_VERBOSE_LOGGING
#ifdef VERY_VERY_VERBOSE_LOGGING
#define ALOGVV ALOGV
//define ALOGVV printf  // for test-mixer.cpp
#else
#define ALOGVV(a...) do { } while (0)
#endif

// Set to default copy buffer size in frames for input processing.
static constexpr size_t kCopyBufferFrameCount = 256;

namespace android {

// ----------------------------------------------------------------------------

bool AudioMixer::isValidChannelMask(audio_channel_mask_t channelMask) const {
    return audio_channel_mask_is_valid(channelMask); // the RemixBufferProvider is flexible.
}

// Called when channel masks have changed for a track name
// TODO: Fix DownmixerBufferProvider not to (possibly) change mixer input format,
// which will simplify this logic.
bool AudioMixer::setChannelMasks(int name,
        audio_channel_mask_t trackChannelMask, audio_channel_mask_t mixerChannelMask) {
    LOG_ALWAYS_FATAL_IF(!exists(name), "invalid name: %d", name);
    const std::shared_ptr<Track> &track = getTrack(name);

    if (trackChannelMask == (track->channelMask | track->mHapticChannelMask)
            && mixerChannelMask == (track->mMixerChannelMask | track->mMixerHapticChannelMask)) {
        return false;  // no need to change
    }
    const audio_channel_mask_t hapticChannelMask = trackChannelMask & AUDIO_CHANNEL_HAPTIC_ALL;
    trackChannelMask &= ~AUDIO_CHANNEL_HAPTIC_ALL;
    const audio_channel_mask_t mixerHapticChannelMask = mixerChannelMask & AUDIO_CHANNEL_HAPTIC_ALL;
    mixerChannelMask &= ~AUDIO_CHANNEL_HAPTIC_ALL;
    // always recompute for both channel masks even if only one has changed.
    const uint32_t trackChannelCount = audio_channel_count_from_out_mask(trackChannelMask);
    const uint32_t mixerChannelCount = audio_channel_count_from_out_mask(mixerChannelMask);
    const uint32_t hapticChannelCount = audio_channel_count_from_out_mask(hapticChannelMask);
    const uint32_t mixerHapticChannelCount =
            audio_channel_count_from_out_mask(mixerHapticChannelMask);

    ALOG_ASSERT((trackChannelCount <= MAX_NUM_CHANNELS_TO_DOWNMIX)
            && trackChannelCount
            && mixerChannelCount);
    track->channelMask = trackChannelMask;
    track->channelCount = trackChannelCount;
    track->mMixerChannelMask = mixerChannelMask;
    track->mMixerChannelCount = mixerChannelCount;
    track->mHapticChannelMask = hapticChannelMask;
    track->mHapticChannelCount = hapticChannelCount;
    track->mMixerHapticChannelMask = mixerHapticChannelMask;
    track->mMixerHapticChannelCount = mixerHapticChannelCount;

    if (track->mHapticChannelCount > 0) {
        track->mAdjustInChannelCount = track->channelCount + track->mHapticChannelCount;
        track->mAdjustOutChannelCount = track->channelCount + track->mMixerHapticChannelCount;
        track->mAdjustNonDestructiveInChannelCount = track->mAdjustOutChannelCount;
        track->mAdjustNonDestructiveOutChannelCount = track->channelCount;
        track->mKeepContractedChannels = track->mHapticPlaybackEnabled;
    } else {
        track->mAdjustInChannelCount = 0;
        track->mAdjustOutChannelCount = 0;
        track->mAdjustNonDestructiveInChannelCount = 0;
        track->mAdjustNonDestructiveOutChannelCount = 0;
        track->mKeepContractedChannels = false;
    }

    // channel masks have changed, does this track need a downmixer?
    // update to try using our desired format (if we aren't already using it)
    const status_t status = track->prepareForDownmix();
    ALOGE_IF(status != OK,
            "prepareForDownmix error %d, track channel mask %#x, mixer channel mask %#x",
            status, track->channelMask, track->mMixerChannelMask);

    // always do reformat since channel mask changed,
    // do it after downmix since track format may change!
    track->prepareForReformat();

    track->prepareForAdjustChannelsNonDestructive(mFrameCount);
    track->prepareForAdjustChannels();

    // Resampler channels may have changed.
    track->recreateResampler(mSampleRate);
    return true;
}

void AudioMixer::Track::unprepareForDownmix() {
    ALOGV("AudioMixer::unprepareForDownmix(%p)", this);

    if (mPostDownmixReformatBufferProvider.get() != nullptr) {
        // release any buffers held by the mPostDownmixReformatBufferProvider
        // before deallocating the mDownmixerBufferProvider.
        mPostDownmixReformatBufferProvider->reset();
    }

    mDownmixRequiresFormat = AUDIO_FORMAT_INVALID;
    if (mDownmixerBufferProvider.get() != nullptr) {
        // this track had previously been configured with a downmixer, delete it
        mDownmixerBufferProvider.reset(nullptr);
        reconfigureBufferProviders();
    } else {
        ALOGV(" nothing to do, no downmixer to delete");
    }
}

status_t AudioMixer::Track::prepareForDownmix()
{
    ALOGV("AudioMixer::prepareForDownmix(%p) with mask 0x%x",
            this, channelMask);

    // discard the previous downmixer if there was one
    unprepareForDownmix();
    // MONO_HACK Only remix (upmix or downmix) if the track and mixer/device channel masks
    // are not the same and not handled internally, as mono for channel position masks is.
    if (channelMask == mMixerChannelMask
            || (channelMask == AUDIO_CHANNEL_OUT_MONO
                    && isAudioChannelPositionMask(mMixerChannelMask))) {
        return NO_ERROR;
    }
    // DownmixerBufferProvider is only used for position masks.
    if (audio_channel_mask_get_representation(channelMask)
                == AUDIO_CHANNEL_REPRESENTATION_POSITION
            && DownmixerBufferProvider::isMultichannelCapable()) {

        // Check if we have a float or int16 downmixer, in that order.
        for (const audio_format_t format : { AUDIO_FORMAT_PCM_FLOAT, AUDIO_FORMAT_PCM_16_BIT }) {
            mDownmixerBufferProvider.reset(new DownmixerBufferProvider(
                    channelMask, mMixerChannelMask,
                    format,
                    sampleRate, sessionId, kCopyBufferFrameCount));
            if (static_cast<DownmixerBufferProvider *>(mDownmixerBufferProvider.get())
                    ->isValid()) {
                mDownmixRequiresFormat = format;
                reconfigureBufferProviders();
                return NO_ERROR;
            }
        }
        // mDownmixerBufferProvider reset below.
    }

    // Effect downmixer does not accept the channel conversion.  Let's use our remixer.
    mDownmixerBufferProvider.reset(new RemixBufferProvider(channelMask,
            mMixerChannelMask, mMixerInFormat, kCopyBufferFrameCount));
    // Remix always finds a conversion whereas Downmixer effect above may fail.
    reconfigureBufferProviders();
    return NO_ERROR;
}

void AudioMixer::Track::unprepareForReformat() {
    ALOGV("AudioMixer::unprepareForReformat(%p)", this);
    bool requiresReconfigure = false;
    if (mReformatBufferProvider.get() != nullptr) {
        mReformatBufferProvider.reset(nullptr);
        requiresReconfigure = true;
    }
    if (mPostDownmixReformatBufferProvider.get() != nullptr) {
        mPostDownmixReformatBufferProvider.reset(nullptr);
        requiresReconfigure = true;
    }
    if (requiresReconfigure) {
        reconfigureBufferProviders();
    }
}

status_t AudioMixer::Track::prepareForReformat()
{
    ALOGV("AudioMixer::prepareForReformat(%p) with format %#x", this, mFormat);
    // discard previous reformatters
    unprepareForReformat();
    // only configure reformatters as needed
    const audio_format_t targetFormat = mDownmixRequiresFormat != AUDIO_FORMAT_INVALID
            ? mDownmixRequiresFormat : mMixerInFormat;
    bool requiresReconfigure = false;
    if (mFormat != targetFormat) {
        mReformatBufferProvider.reset(new ReformatBufferProvider(
                audio_channel_count_from_out_mask(channelMask),
                mFormat,
                targetFormat,
                kCopyBufferFrameCount));
        requiresReconfigure = true;
    } else if (mFormat == AUDIO_FORMAT_PCM_FLOAT) {
        // Input and output are floats, make sure application did not provide > 3db samples
        // that would break volume application (b/68099072)
        // TODO: add a trusted source flag to avoid the overhead
        mReformatBufferProvider.reset(new ClampFloatBufferProvider(
                audio_channel_count_from_out_mask(channelMask),
                kCopyBufferFrameCount));
        requiresReconfigure = true;
    }
    if (targetFormat != mMixerInFormat) {
        mPostDownmixReformatBufferProvider.reset(new ReformatBufferProvider(
                audio_channel_count_from_out_mask(mMixerChannelMask),
                targetFormat,
                mMixerInFormat,
                kCopyBufferFrameCount));
        requiresReconfigure = true;
    }
    if (requiresReconfigure) {
        reconfigureBufferProviders();
    }
    return NO_ERROR;
}

void AudioMixer::Track::unprepareForAdjustChannels()
{
    ALOGV("AUDIOMIXER::unprepareForAdjustChannels");
    if (mAdjustChannelsBufferProvider.get() != nullptr) {
        mAdjustChannelsBufferProvider.reset(nullptr);
        reconfigureBufferProviders();
    }
}

status_t AudioMixer::Track::prepareForAdjustChannels()
{
    ALOGV("AudioMixer::prepareForAdjustChannels(%p) with inChannelCount: %u, outChannelCount: %u",
            this, mAdjustInChannelCount, mAdjustOutChannelCount);
    unprepareForAdjustChannels();
    if (mAdjustInChannelCount != mAdjustOutChannelCount) {
        mAdjustChannelsBufferProvider.reset(new AdjustChannelsBufferProvider(
                mFormat, mAdjustInChannelCount, mAdjustOutChannelCount, kCopyBufferFrameCount));
        reconfigureBufferProviders();
    }
    return NO_ERROR;
}

void AudioMixer::Track::unprepareForAdjustChannelsNonDestructive()
{
    ALOGV("AUDIOMIXER::unprepareForAdjustChannelsNonDestructive");
    if (mContractChannelsNonDestructiveBufferProvider.get() != nullptr) {
        mContractChannelsNonDestructiveBufferProvider.reset(nullptr);
        reconfigureBufferProviders();
    }
}

status_t AudioMixer::Track::prepareForAdjustChannelsNonDestructive(size_t frames)
{
    ALOGV("AudioMixer::prepareForAdjustChannelsNonDestructive(%p) with inChannelCount: %u, "
          "outChannelCount: %u, keepContractedChannels: %d",
            this, mAdjustNonDestructiveInChannelCount, mAdjustNonDestructiveOutChannelCount,
            mKeepContractedChannels);
    unprepareForAdjustChannelsNonDestructive();
    if (mAdjustNonDestructiveInChannelCount != mAdjustNonDestructiveOutChannelCount) {
        uint8_t* buffer = mKeepContractedChannels
                ? (uint8_t*)mainBuffer + frames * audio_bytes_per_frame(
                        mMixerChannelCount, mMixerFormat)
                : NULL;
        mContractChannelsNonDestructiveBufferProvider.reset(
                new AdjustChannelsBufferProvider(
                        mFormat,
                        mAdjustNonDestructiveInChannelCount,
                        mAdjustNonDestructiveOutChannelCount,
                        frames,
                        mKeepContractedChannels ? mMixerFormat : AUDIO_FORMAT_INVALID,
                        buffer));
        reconfigureBufferProviders();
    }
    return NO_ERROR;
}

void AudioMixer::Track::clearContractedBuffer()
{
    if (mContractChannelsNonDestructiveBufferProvider.get() != nullptr) {
        static_cast<AdjustChannelsBufferProvider*>(
                mContractChannelsNonDestructiveBufferProvider.get())->clearContractedFrames();
    }
}

void AudioMixer::Track::reconfigureBufferProviders()
{
    // configure from upstream to downstream buffer providers.
    bufferProvider = mInputBufferProvider;
    if (mAdjustChannelsBufferProvider.get() != nullptr) {
        mAdjustChannelsBufferProvider->setBufferProvider(bufferProvider);
        bufferProvider = mAdjustChannelsBufferProvider.get();
    }
    if (mContractChannelsNonDestructiveBufferProvider.get() != nullptr) {
        mContractChannelsNonDestructiveBufferProvider->setBufferProvider(bufferProvider);
        bufferProvider = mContractChannelsNonDestructiveBufferProvider.get();
    }
    if (mReformatBufferProvider.get() != nullptr) {
        mReformatBufferProvider->setBufferProvider(bufferProvider);
        bufferProvider = mReformatBufferProvider.get();
    }
    if (mDownmixerBufferProvider.get() != nullptr) {
        mDownmixerBufferProvider->setBufferProvider(bufferProvider);
        bufferProvider = mDownmixerBufferProvider.get();
    }
    if (mPostDownmixReformatBufferProvider.get() != nullptr) {
        mPostDownmixReformatBufferProvider->setBufferProvider(bufferProvider);
        bufferProvider = mPostDownmixReformatBufferProvider.get();
    }
    if (mTimestretchBufferProvider.get() != nullptr) {
        mTimestretchBufferProvider->setBufferProvider(bufferProvider);
        bufferProvider = mTimestretchBufferProvider.get();
    }
}

void AudioMixer::setParameter(int name, int target, int param, void *value)
{
    LOG_ALWAYS_FATAL_IF(!exists(name), "invalid name: %d", name);
    const std::shared_ptr<Track> &track = getTrack(name);

    int valueInt = static_cast<int>(reinterpret_cast<uintptr_t>(value));
    int32_t *valueBuf = reinterpret_cast<int32_t*>(value);

    switch (target) {

    case TRACK:
        switch (param) {
        case CHANNEL_MASK: {
            const audio_channel_mask_t trackChannelMask =
                static_cast<audio_channel_mask_t>(valueInt);
            if (setChannelMasks(name, trackChannelMask,
                    (track->mMixerChannelMask | track->mMixerHapticChannelMask))) {
                ALOGV("setParameter(TRACK, CHANNEL_MASK, %x)", trackChannelMask);
                invalidate();
            }
            } break;
        case MAIN_BUFFER:
            if (track->mainBuffer != valueBuf) {
                track->mainBuffer = valueBuf;
                ALOGV("setParameter(TRACK, MAIN_BUFFER, %p)", valueBuf);
                if (track->mKeepContractedChannels) {
                    track->prepareForAdjustChannelsNonDestructive(mFrameCount);
                }
                invalidate();
            }
            break;
        case AUX_BUFFER:
            AudioMixerBase::setParameter(name, target, param, value);
            break;
        case FORMAT: {
            audio_format_t format = static_cast<audio_format_t>(valueInt);
            if (track->mFormat != format) {
                ALOG_ASSERT(audio_is_linear_pcm(format), "Invalid format %#x", format);
                track->mFormat = format;
                ALOGV("setParameter(TRACK, FORMAT, %#x)", format);
                track->prepareForReformat();
                invalidate();
            }
            } break;
        // FIXME do we want to support setting the downmix type from AudioFlinger?
        //         for a specific track? or per mixer?
        /* case DOWNMIX_TYPE:
            break          */
        case MIXER_FORMAT: {
            audio_format_t format = static_cast<audio_format_t>(valueInt);
            if (track->mMixerFormat != format) {
                track->mMixerFormat = format;
                ALOGV("setParameter(TRACK, MIXER_FORMAT, %#x)", format);
                if (track->mKeepContractedChannels) {
                    track->prepareForAdjustChannelsNonDestructive(mFrameCount);
                }
            }
            } break;
        case MIXER_CHANNEL_MASK: {
            const audio_channel_mask_t mixerChannelMask =
                    static_cast<audio_channel_mask_t>(valueInt);
            if (setChannelMasks(name, track->channelMask | track->mHapticChannelMask,
                    mixerChannelMask)) {
                ALOGV("setParameter(TRACK, MIXER_CHANNEL_MASK, %#x)", mixerChannelMask);
                invalidate();
            }
            } break;
        case HAPTIC_ENABLED: {
            const bool hapticPlaybackEnabled = static_cast<bool>(valueInt);
            if (track->mHapticPlaybackEnabled != hapticPlaybackEnabled) {
                track->mHapticPlaybackEnabled = hapticPlaybackEnabled;
                track->mKeepContractedChannels = hapticPlaybackEnabled;
                track->prepareForAdjustChannelsNonDestructive(mFrameCount);
                track->prepareForAdjustChannels();
            }
            } break;
        case HAPTIC_INTENSITY: {
            const haptic_intensity_t hapticIntensity = static_cast<haptic_intensity_t>(valueInt);
            if (track->mHapticIntensity != hapticIntensity) {
                track->mHapticIntensity = hapticIntensity;
            }
            } break;
        default:
            LOG_ALWAYS_FATAL("setParameter track: bad param %d", param);
        }
        break;

    case RESAMPLE:
    case RAMP_VOLUME:
    case VOLUME:
        AudioMixerBase::setParameter(name, target, param, value);
        break;
    case TIMESTRETCH:
        switch (param) {
        case PLAYBACK_RATE: {
            const AudioPlaybackRate *playbackRate =
                    reinterpret_cast<AudioPlaybackRate*>(value);
            ALOGW_IF(!isAudioPlaybackRateValid(*playbackRate),
                    "bad parameters speed %f, pitch %f",
                    playbackRate->mSpeed, playbackRate->mPitch);
            if (track->setPlaybackRate(*playbackRate)) {
                ALOGV("setParameter(TIMESTRETCH, PLAYBACK_RATE, STRETCH_MODE, FALLBACK_MODE "
                        "%f %f %d %d",
                        playbackRate->mSpeed,
                        playbackRate->mPitch,
                        playbackRate->mStretchMode,
                        playbackRate->mFallbackMode);
                // invalidate();  (should not require reconfigure)
            }
        } break;
        default:
            LOG_ALWAYS_FATAL("setParameter timestretch: bad param %d", param);
        }
        break;

    default:
        LOG_ALWAYS_FATAL("setParameter: bad target %d", target);
    }
}

bool AudioMixer::Track::setPlaybackRate(const AudioPlaybackRate &playbackRate)
{
    if ((mTimestretchBufferProvider.get() == nullptr &&
            fabs(playbackRate.mSpeed - mPlaybackRate.mSpeed) < AUDIO_TIMESTRETCH_SPEED_MIN_DELTA &&
            fabs(playbackRate.mPitch - mPlaybackRate.mPitch) < AUDIO_TIMESTRETCH_PITCH_MIN_DELTA) ||
            isAudioPlaybackRateEqual(playbackRate, mPlaybackRate)) {
        return false;
    }
    mPlaybackRate = playbackRate;
    if (mTimestretchBufferProvider.get() == nullptr) {
        // TODO: Remove MONO_HACK. Resampler sees #channels after the downmixer
        // but if none exists, it is the channel count (1 for mono).
        const int timestretchChannelCount = getOutputChannelCount();
        mTimestretchBufferProvider.reset(new TimestretchBufferProvider(timestretchChannelCount,
                mMixerInFormat, sampleRate, playbackRate));
        reconfigureBufferProviders();
    } else {
        static_cast<TimestretchBufferProvider*>(mTimestretchBufferProvider.get())
                ->setPlaybackRate(playbackRate);
    }
    return true;
}

void AudioMixer::setBufferProvider(int name, AudioBufferProvider* bufferProvider)
{
    LOG_ALWAYS_FATAL_IF(!exists(name), "invalid name: %d", name);
    const std::shared_ptr<Track> &track = getTrack(name);

    if (track->mInputBufferProvider == bufferProvider) {
        return; // don't reset any buffer providers if identical.
    }
    // reset order from downstream to upstream buffer providers.
    if (track->mTimestretchBufferProvider.get() != nullptr) {
        track->mTimestretchBufferProvider->reset();
    } else if (track->mPostDownmixReformatBufferProvider.get() != nullptr) {
        track->mPostDownmixReformatBufferProvider->reset();
    } else if (track->mDownmixerBufferProvider != nullptr) {
        track->mDownmixerBufferProvider->reset();
    } else if (track->mReformatBufferProvider.get() != nullptr) {
        track->mReformatBufferProvider->reset();
    } else if (track->mContractChannelsNonDestructiveBufferProvider.get() != nullptr) {
        track->mContractChannelsNonDestructiveBufferProvider->reset();
    } else if (track->mAdjustChannelsBufferProvider.get() != nullptr) {
        track->mAdjustChannelsBufferProvider->reset();
    }

    track->mInputBufferProvider = bufferProvider;
    track->reconfigureBufferProviders();
}

/*static*/ pthread_once_t AudioMixer::sOnceControl = PTHREAD_ONCE_INIT;

/*static*/ void AudioMixer::sInitRoutine()
{
    DownmixerBufferProvider::init(); // for the downmixer
}

std::shared_ptr<AudioMixerBase::TrackBase> AudioMixer::preCreateTrack()
{
    return std::make_shared<Track>();
}

status_t AudioMixer::postCreateTrack(TrackBase *track)
{
    Track* t = static_cast<Track*>(track);

    audio_channel_mask_t channelMask = t->channelMask;
    t->mHapticChannelMask = channelMask & AUDIO_CHANNEL_HAPTIC_ALL;
    t->mHapticChannelCount = audio_channel_count_from_out_mask(t->mHapticChannelMask);
    channelMask &= ~AUDIO_CHANNEL_HAPTIC_ALL;
    t->channelCount = audio_channel_count_from_out_mask(channelMask);
    ALOGV_IF(audio_channel_mask_get_bits(channelMask) != AUDIO_CHANNEL_OUT_STEREO,
            "Non-stereo channel mask: %d\n", channelMask);
    t->channelMask = channelMask;
    t->mInputBufferProvider = NULL;
    t->mDownmixRequiresFormat = AUDIO_FORMAT_INVALID; // no format required
    t->mPlaybackRate = AUDIO_PLAYBACK_RATE_DEFAULT;
    // haptic
    t->mHapticPlaybackEnabled = false;
    t->mHapticIntensity = HAPTIC_SCALE_NONE;
    t->mMixerHapticChannelMask = AUDIO_CHANNEL_NONE;
    t->mMixerHapticChannelCount = 0;
    t->mAdjustInChannelCount = t->channelCount + t->mHapticChannelCount;
    t->mAdjustOutChannelCount = t->channelCount + t->mMixerHapticChannelCount;
    t->mAdjustNonDestructiveInChannelCount = t->mAdjustOutChannelCount;
    t->mAdjustNonDestructiveOutChannelCount = t->channelCount;
    t->mKeepContractedChannels = false;
    // Check the downmixing (or upmixing) requirements.
    status_t status = t->prepareForDownmix();
    if (status != OK) {
        ALOGE("AudioMixer::getTrackName invalid channelMask (%#x)", channelMask);
        return BAD_VALUE;
    }
    // prepareForDownmix() may change mDownmixRequiresFormat
    ALOGVV("mMixerFormat:%#x  mMixerInFormat:%#x\n", t->mMixerFormat, t->mMixerInFormat);
    t->prepareForReformat();
    t->prepareForAdjustChannelsNonDestructive(mFrameCount);
    t->prepareForAdjustChannels();
    return OK;
}

void AudioMixer::preProcess()
{
    for (const auto &pair : mTracks) {
        // Clear contracted buffer before processing if contracted channels are saved
        const std::shared_ptr<TrackBase> &tb = pair.second;
        Track *t = static_cast<Track*>(tb.get());
        if (t->mKeepContractedChannels) {
            t->clearContractedBuffer();
        }
    }
}

void AudioMixer::postProcess()
{
    // Process haptic data.
    // Need to keep consistent with VibrationEffect.scale(int, float, int)
    for (const auto &pair : mGroups) {
        // process by group of tracks with same output main buffer.
        const auto &group = pair.second;
        for (const int name : group) {
            const std::shared_ptr<Track> &t = getTrack(name);
            if (t->mHapticPlaybackEnabled) {
                size_t sampleCount = mFrameCount * t->mMixerHapticChannelCount;
                float gamma = t->getHapticScaleGamma();
                float maxAmplitudeRatio = t->getHapticMaxAmplitudeRatio();
                uint8_t* buffer = (uint8_t*)pair.first + mFrameCount * audio_bytes_per_frame(
                        t->mMixerChannelCount, t->mMixerFormat);
                switch (t->mMixerFormat) {
                // Mixer format should be AUDIO_FORMAT_PCM_FLOAT.
                case AUDIO_FORMAT_PCM_FLOAT: {
                    float* fout = (float*) buffer;
                    for (size_t i = 0; i < sampleCount; i++) {
                        float mul = fout[i] >= 0 ? 1.0 : -1.0;
                        fout[i] = powf(fabsf(fout[i] / HAPTIC_MAX_AMPLITUDE_FLOAT), gamma)
                                * maxAmplitudeRatio * HAPTIC_MAX_AMPLITUDE_FLOAT * mul;
                    }
                } break;
                default:
                    LOG_ALWAYS_FATAL("bad mMixerFormat: %#x", t->mMixerFormat);
                    break;
                }
                break;
            }
        }
    }
}

// ----------------------------------------------------------------------------
} // namespace android
