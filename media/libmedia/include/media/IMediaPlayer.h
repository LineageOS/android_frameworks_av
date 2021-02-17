/*
 * Copyright (C) 2008 The Android Open Source Project
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

#ifndef ANDROID_IMEDIAPLAYER_H
#define ANDROID_IMEDIAPLAYER_H

#include <utils/RefBase.h>
#include <binder/IInterface.h>
#include <binder/Parcel.h>
#include <utils/KeyedVector.h>
#include <system/audio.h>

#include <media/AudioResamplerPublic.h>
#include <media/stagefright/MediaSource.h>
#include <media/VolumeShaper.h>

// Fwd decl to make sure everyone agrees that the scope of struct sockaddr_in is
// global, and not in android::
struct sockaddr_in;

namespace android {

class Parcel;
class Surface;
class IDataSource;
struct IStreamSource;
class IGraphicBufferProducer;
struct IMediaHTTPService;
struct AVSyncSettings;
struct BufferingSettings;

typedef MediaSource::ReadOptions::SeekMode MediaPlayerSeekMode;

class IMediaPlayer: public IInterface
{
public:
    DECLARE_META_INTERFACE(MediaPlayer);

    virtual void            disconnect() = 0;

    virtual status_t        setDataSource(
            const sp<IMediaHTTPService> &httpService,
            const char *url,
            const KeyedVector<String8, String8>* headers) = 0;

    virtual status_t        setDataSource(int fd, int64_t offset, int64_t length) = 0;
    virtual status_t        setDataSource(const sp<IStreamSource>& source) = 0;
    virtual status_t        setDataSource(const sp<IDataSource>& source) = 0;
    virtual status_t        setDataSource(const String8& rtpParams) = 0;
    virtual status_t        setVideoSurfaceTexture(
                                    const sp<IGraphicBufferProducer>& bufferProducer) = 0;
    virtual status_t        getBufferingSettings(
                                    BufferingSettings* buffering /* nonnull */) = 0;
    virtual status_t        setBufferingSettings(const BufferingSettings& buffering) = 0;
    virtual status_t        prepareAsync() = 0;
    virtual status_t        start() = 0;
    virtual status_t        stop() = 0;
    virtual status_t        pause() = 0;
    virtual status_t        isPlaying(bool* state) = 0;
    virtual status_t        setPlaybackSettings(const AudioPlaybackRate& rate) = 0;
    virtual status_t        getPlaybackSettings(AudioPlaybackRate* rate /* nonnull */) = 0;
    virtual status_t        setSyncSettings(const AVSyncSettings& sync, float videoFpsHint) = 0;
    virtual status_t        getSyncSettings(AVSyncSettings* sync /* nonnull */,
                                            float* videoFps /* nonnull */) = 0;
    virtual status_t        seekTo(
            int msec,
            MediaPlayerSeekMode mode = MediaPlayerSeekMode::SEEK_PREVIOUS_SYNC) = 0;
    virtual status_t        getCurrentPosition(int* msec) = 0;
    virtual status_t        getDuration(int* msec) = 0;
    virtual status_t        notifyAt(int64_t mediaTimeUs) = 0;
    virtual status_t        reset() = 0;
    virtual status_t        setAudioStreamType(audio_stream_type_t type) = 0;
    virtual status_t        setLooping(int loop) = 0;
    virtual status_t        setVolume(float leftVolume, float rightVolume) = 0;
    virtual status_t        setAuxEffectSendLevel(float level) = 0;
    virtual status_t        attachAuxEffect(int effectId) = 0;
    virtual status_t        setParameter(int key, const Parcel& request) = 0;
    virtual status_t        getParameter(int key, Parcel* reply) = 0;
    virtual status_t        setRetransmitEndpoint(const struct sockaddr_in* endpoint) = 0;
    virtual status_t        getRetransmitEndpoint(struct sockaddr_in* endpoint) = 0;
    virtual status_t        setNextPlayer(const sp<IMediaPlayer>& next) = 0;

    virtual media::VolumeShaper::Status applyVolumeShaper(
                                    const sp<media::VolumeShaper::Configuration>& configuration,
                                    const sp<media::VolumeShaper::Operation>& operation) = 0;
    virtual sp<media::VolumeShaper::State> getVolumeShaperState(int id) = 0;

    // Modular DRM
    virtual status_t        prepareDrm(const uint8_t uuid[16],
                                    const Vector<uint8_t>& drmSessionId) = 0;
    virtual status_t        releaseDrm() = 0;

    // Invoke a generic method on the player by using opaque parcels
    // for the request and reply.
    // @param request Parcel that must start with the media player
    // interface token.
    // @param[out] reply Parcel to hold the reply data. Cannot be null.
    // @return OK if the invocation was made successfully.
    virtual status_t        invoke(const Parcel& request, Parcel *reply) = 0;

    // Set a new metadata filter.
    // @param filter A set of allow and drop rules serialized in a Parcel.
    // @return OK if the invocation was made successfully.
    virtual status_t        setMetadataFilter(const Parcel& filter) = 0;

    // Retrieve a set of metadata.
    // @param update_only Include only the metadata that have changed
    //                    since the last invocation of getMetadata.
    //                    The set is built using the unfiltered
    //                    notifications the native player sent to the
    //                    MediaPlayerService during that period of
    //                    time. If false, all the metadatas are considered.
    // @param apply_filter If true, once the metadata set has been built based
    //                     on the value update_only, the current filter is
    //                     applied.
    // @param[out] metadata On exit contains a set (possibly empty) of metadata.
    //                      Valid only if the call returned OK.
    // @return OK if the invocation was made successfully.
    virtual status_t        getMetadata(bool update_only,
                                        bool apply_filter,
                                        Parcel *metadata) = 0;

    // AudioRouting
    virtual status_t        setOutputDevice(audio_port_handle_t deviceId) = 0;
    virtual status_t        getRoutedDeviceId(audio_port_handle_t *deviceId) = 0;
    virtual status_t        enableAudioDeviceCallback(bool enabled) = 0;
protected:

    friend class IMediaPlayerTest;
    enum {
        DISCONNECT = IBinder::FIRST_CALL_TRANSACTION,
        SET_DATA_SOURCE_URL,
        SET_DATA_SOURCE_FD,
        SET_DATA_SOURCE_STREAM,
        SET_DATA_SOURCE_CALLBACK,
        SET_DATA_SOURCE_RTP,
        SET_BUFFERING_SETTINGS,
        GET_BUFFERING_SETTINGS,
        PREPARE_ASYNC,
        START,
        STOP,
        IS_PLAYING,
        SET_PLAYBACK_SETTINGS,
        GET_PLAYBACK_SETTINGS,
        SET_SYNC_SETTINGS,
        GET_SYNC_SETTINGS,
        PAUSE,
        SEEK_TO,
        GET_CURRENT_POSITION,
        GET_DURATION,
        RESET,
        NOTIFY_AT,
        SET_AUDIO_STREAM_TYPE,
        SET_LOOPING,
        SET_VOLUME,
        INVOKE,
        SET_METADATA_FILTER,
        GET_METADATA,
        SET_AUX_EFFECT_SEND_LEVEL,
        ATTACH_AUX_EFFECT,
        SET_VIDEO_SURFACETEXTURE,
        SET_PARAMETER,
        GET_PARAMETER,
        SET_RETRANSMIT_ENDPOINT,
        GET_RETRANSMIT_ENDPOINT,
        SET_NEXT_PLAYER,
        APPLY_VOLUME_SHAPER,
        GET_VOLUME_SHAPER_STATE,
        // Modular DRM
        PREPARE_DRM,
        RELEASE_DRM,
        // AudioRouting
        SET_OUTPUT_DEVICE,
        GET_ROUTED_DEVICE_ID,
        ENABLE_AUDIO_DEVICE_CALLBACK,
    };
};

// ----------------------------------------------------------------------------

class BnMediaPlayer: public BnInterface<IMediaPlayer>
{
public:
    virtual status_t    onTransact( uint32_t code,
                                    const Parcel& data,
                                    Parcel* reply,
                                    uint32_t flags = 0);
};

}; // namespace android

#endif // ANDROID_IMEDIAPLAYER_H
