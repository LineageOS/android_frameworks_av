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

#define LOG_TAG "IAudioTrack"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <sys/types.h>

#include <binder/Parcel.h>

#include <media/IAudioTrack.h>

namespace android {

using media::VolumeShaper;

enum {
    GET_CBLK = IBinder::FIRST_CALL_TRANSACTION,
    START,
    STOP,
    FLUSH,
    RESERVED, // was MUTE
    PAUSE,
    ATTACH_AUX_EFFECT,
    SET_PARAMETERS,
    SELECT_PRESENTATION,
    GET_TIMESTAMP,
    SIGNAL,
    APPLY_VOLUME_SHAPER,
    GET_VOLUME_SHAPER_STATE,
    SET_DUAL_MONO_MODE,
    GET_DUAL_MONO_MODE,
    SET_AUDIO_DESCRIPTION_MIX_LEVEL,
    GET_AUDIO_DESCRIPTION_MIX_LEVEL,
    SET_PLAYBACK_RATE_PARAMETERS,
    GET_PLAYBACK_RATE_PARAMETERS,
};

class BpAudioTrack : public BpInterface<IAudioTrack>
{
public:
    explicit BpAudioTrack(const sp<IBinder>& impl)
        : BpInterface<IAudioTrack>(impl)
    {
    }

    virtual sp<IMemory> getCblk() const
    {
        Parcel data, reply;
        sp<IMemory> cblk;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        status_t status = remote()->transact(GET_CBLK, data, &reply);
        if (status == NO_ERROR) {
            cblk = interface_cast<IMemory>(reply.readStrongBinder());
            if (cblk != 0 && cblk->unsecurePointer() == NULL) {
                cblk.clear();
            }
        }
        return cblk;
    }

    virtual status_t start()
    {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        status_t status = remote()->transact(START, data, &reply);
        if (status == NO_ERROR) {
            status = reply.readInt32();
        } else {
            ALOGW("start() error: %s", strerror(-status));
        }
        return status;
    }

    virtual void stop()
    {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        remote()->transact(STOP, data, &reply);
    }

    virtual void flush()
    {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        remote()->transact(FLUSH, data, &reply);
    }

    virtual void pause()
    {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        remote()->transact(PAUSE, data, &reply);
    }

    virtual status_t attachAuxEffect(int effectId)
    {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        data.writeInt32(effectId);
        status_t status = remote()->transact(ATTACH_AUX_EFFECT, data, &reply);
        if (status == NO_ERROR) {
            status = reply.readInt32();
        } else {
            ALOGW("attachAuxEffect() error: %s", strerror(-status));
        }
        return status;
    }

    virtual status_t setParameters(const String8& keyValuePairs) {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        data.writeString8(keyValuePairs);
        status_t status = remote()->transact(SET_PARAMETERS, data, &reply);
        if (status == NO_ERROR) {
            status = reply.readInt32();
        }
        return status;
    }

    /* Selects the presentation (if available) */
    virtual status_t selectPresentation(int presentationId, int programId) {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        data.writeInt32(presentationId);
        data.writeInt32(programId);
        status_t status = remote()->transact(SELECT_PRESENTATION, data, &reply);
        if (status == NO_ERROR) {
            status = reply.readInt32();
        }
        return status;
    }

    virtual status_t getTimestamp(AudioTimestamp& timestamp) {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        status_t status = remote()->transact(GET_TIMESTAMP, data, &reply);
        if (status == NO_ERROR) {
            status = reply.readInt32();
            if (status == NO_ERROR) {
                timestamp.mPosition = reply.readInt32();
                timestamp.mTime.tv_sec = reply.readInt32();
                timestamp.mTime.tv_nsec = reply.readInt32();
            }
        }
        return status;
    }

    virtual void signal() {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        remote()->transact(SIGNAL, data, &reply);
    }

    virtual VolumeShaper::Status applyVolumeShaper(
            const sp<VolumeShaper::Configuration>& configuration,
            const sp<VolumeShaper::Operation>& operation) {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());

        status_t status = configuration.get() == nullptr
                ? data.writeInt32(0)
                :  data.writeInt32(1)
                    ?: configuration->writeToParcel(&data);
        if (status != NO_ERROR) {
            return VolumeShaper::Status(status);
        }

        status = operation.get() == nullptr
                ? status = data.writeInt32(0)
                : data.writeInt32(1)
                    ?: operation->writeToParcel(&data);
        if (status != NO_ERROR) {
            return VolumeShaper::Status(status);
        }

        int32_t remoteVolumeShaperStatus;
        status = remote()->transact(APPLY_VOLUME_SHAPER, data, &reply)
                 ?: reply.readInt32(&remoteVolumeShaperStatus);

        return VolumeShaper::Status(status ?: remoteVolumeShaperStatus);
    }

    virtual sp<VolumeShaper::State> getVolumeShaperState(int id) {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());

        data.writeInt32(id);
        status_t status = remote()->transact(GET_VOLUME_SHAPER_STATE, data, &reply);
        if (status != NO_ERROR) {
            return nullptr;
        }
        sp<VolumeShaper::State> state = new VolumeShaper::State;
        status = state->readFromParcel(&reply);
        if (status != NO_ERROR) {
            return nullptr;
        }
        return state;
    }

    status_t getDualMonoMode(audio_dual_mono_mode_t* mode) override {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        status_t status = remote()->transact(GET_DUAL_MONO_MODE, data, &reply);
        if (status != NO_ERROR) {
            return status;
        }
        status = (status_t)reply.readInt32();
        if (status != NO_ERROR) {
            return status;
        }
        *mode = (audio_dual_mono_mode_t)reply.readInt32();
        return NO_ERROR;
    }

    status_t setDualMonoMode(audio_dual_mono_mode_t mode) override {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        data.writeInt32((int32_t)mode);
        status_t status = remote()->transact(SET_DUAL_MONO_MODE, data, &reply);
        if (status != NO_ERROR) {
            return status;
        }
        return reply.readInt32();
    }

    status_t getAudioDescriptionMixLevel(float* leveldB) override {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        status_t status = remote()->transact(GET_AUDIO_DESCRIPTION_MIX_LEVEL, data, &reply);
        if (status != NO_ERROR) {
            return status;
        }
        status = (status_t)reply.readInt32();
        if (status != NO_ERROR) {
            return status;
        }
        *leveldB = reply.readFloat();
        return NO_ERROR;
    }

    status_t setAudioDescriptionMixLevel(float leveldB) override {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        data.writeFloat(leveldB);
        status_t status = remote()->transact(SET_AUDIO_DESCRIPTION_MIX_LEVEL, data, &reply);
        if (status != NO_ERROR) {
            return status;
        }
        return reply.readInt32();
    }

    status_t getPlaybackRateParameters(audio_playback_rate_t* playbackRate) override {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        status_t status = remote()->transact(GET_PLAYBACK_RATE_PARAMETERS, data, &reply);
        if (status != NO_ERROR) {
            return status;
        }
        status = (status_t)reply.readInt32();
        if (status != NO_ERROR) {
            return status;
        }
        playbackRate->mSpeed = reply.readFloat();
        playbackRate->mPitch = reply.readFloat();
        playbackRate->mStretchMode =
            static_cast<audio_timestretch_stretch_mode_t>(reply.readInt32());
        playbackRate->mFallbackMode =
            static_cast<audio_timestretch_fallback_mode_t>(reply.readInt32());
        return NO_ERROR;
    }

    status_t setPlaybackRateParameters(const audio_playback_rate_t& playbackRate) override {
        Parcel data, reply;
        data.writeInterfaceToken(IAudioTrack::getInterfaceDescriptor());
        data.writeFloat(playbackRate.mSpeed);
        data.writeFloat(playbackRate.mPitch);
        data.writeInt32(playbackRate.mStretchMode);
        data.writeInt32(playbackRate.mFallbackMode);
        status_t status = remote()->transact(SET_PLAYBACK_RATE_PARAMETERS, data, &reply);
        if (status != NO_ERROR) {
            return status;
        }
        return reply.readInt32();
    }
};

IMPLEMENT_META_INTERFACE(AudioTrack, "android.media.IAudioTrack");

// ----------------------------------------------------------------------

status_t BnAudioTrack::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    switch (code) {
        case GET_CBLK: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            reply->writeStrongBinder(IInterface::asBinder(getCblk()));
            return NO_ERROR;
        } break;
        case START: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            reply->writeInt32(start());
            return NO_ERROR;
        } break;
        case STOP: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            stop();
            return NO_ERROR;
        } break;
        case FLUSH: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            flush();
            return NO_ERROR;
        } break;
        case PAUSE: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            pause();
            return NO_ERROR;
        }
        case ATTACH_AUX_EFFECT: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            reply->writeInt32(attachAuxEffect(data.readInt32()));
            return NO_ERROR;
        } break;
        case SET_PARAMETERS: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            String8 keyValuePairs(data.readString8());
            reply->writeInt32(setParameters(keyValuePairs));
            return NO_ERROR;
        } break;
        case SELECT_PRESENTATION: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            reply->writeInt32(selectPresentation(data.readInt32(), data.readInt32()));
            return NO_ERROR;
        } break;
        case GET_TIMESTAMP: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            AudioTimestamp timestamp;
            status_t status = getTimestamp(timestamp);
            reply->writeInt32(status);
            if (status == NO_ERROR) {
                reply->writeInt32(timestamp.mPosition);
                reply->writeInt32(timestamp.mTime.tv_sec);
                reply->writeInt32(timestamp.mTime.tv_nsec);
            }
            return NO_ERROR;
        } break;
        case SIGNAL: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            signal();
            return NO_ERROR;
        } break;
        case APPLY_VOLUME_SHAPER: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            sp<VolumeShaper::Configuration> configuration;
            sp<VolumeShaper::Operation> operation;

            int32_t present;
            status_t status = data.readInt32(&present);
            if (status == NO_ERROR && present != 0) {
                configuration = new VolumeShaper::Configuration();
                status = configuration->readFromParcel(&data);
            }
            status = status ?: data.readInt32(&present);
            if (status == NO_ERROR && present != 0) {
                operation = new VolumeShaper::Operation();
                status = operation->readFromParcel(&data);
            }
            if (status == NO_ERROR) {
                status = (status_t)applyVolumeShaper(configuration, operation);
            }
            reply->writeInt32(status);
            return NO_ERROR;
        } break;
        case GET_VOLUME_SHAPER_STATE: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            int id;
            status_t status = data.readInt32(&id);
            if (status == NO_ERROR) {
                sp<VolumeShaper::State> state = getVolumeShaperState(id);
                if (state.get() != nullptr) {
                     status = state->writeToParcel(reply);
                }
            }
            return NO_ERROR;
        } break;
        case SET_DUAL_MONO_MODE: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            reply->writeInt32( setDualMonoMode((audio_dual_mono_mode_t)data.readInt32()) );
            return NO_ERROR;
        } break;
        case GET_DUAL_MONO_MODE: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            audio_dual_mono_mode_t mode;
            const status_t status = getDualMonoMode(&mode);
            reply->writeInt32((int32_t)status);
            if (status == NO_ERROR) {
                reply->writeInt32(mode);
            }
            return NO_ERROR;
        } break;
        case SET_AUDIO_DESCRIPTION_MIX_LEVEL: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            reply->writeInt32( setAudioDescriptionMixLevel(data.readFloat()) );
            return NO_ERROR;
        } break;
        case GET_AUDIO_DESCRIPTION_MIX_LEVEL: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            float f;
            const status_t status = getAudioDescriptionMixLevel(&f);
            reply->writeInt32((int32_t)status);
            if (status == NO_ERROR) {
                reply->writeFloat(f);
            }
            return NO_ERROR;
        } break;
        case SET_PLAYBACK_RATE_PARAMETERS: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            audio_playback_rate_t playbackRate = {
                data.readFloat(),
                data.readFloat(),
                static_cast<audio_timestretch_stretch_mode_t>(data.readInt32()),
                static_cast<audio_timestretch_fallback_mode_t>(data.readInt32())};
            reply->writeInt32( setPlaybackRateParameters(playbackRate) );
            return NO_ERROR;
        } break;
        case GET_PLAYBACK_RATE_PARAMETERS: {
            CHECK_INTERFACE(IAudioTrack, data, reply);
            audio_playback_rate_t playbackRate;
            const status_t status = getPlaybackRateParameters(&playbackRate);
            reply->writeInt32((int32_t)status);
            if (status == NO_ERROR) {
                reply->writeFloat(playbackRate.mSpeed);
                reply->writeFloat(playbackRate.mPitch);
                reply->writeInt32(playbackRate.mStretchMode);
                reply->writeInt32(playbackRate.mFallbackMode);
            }
            return NO_ERROR;
        } break;
        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

} // namespace android
