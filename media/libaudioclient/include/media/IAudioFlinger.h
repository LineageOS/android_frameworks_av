/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef ANDROID_IAUDIOFLINGER_H
#define ANDROID_IAUDIOFLINGER_H

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <utils/RefBase.h>
#include <utils/Errors.h>
#include <binder/IInterface.h>
#include <media/AidlConversion.h>
#include <media/AppVolume.h>
#include <media/AudioClient.h>
#include <media/AudioCommonTypes.h>
#include <media/DeviceDescriptorBase.h>
#include <system/audio.h>
#include <system/audio_effect.h>
#include <system/audio_policy.h>
#include <utils/String8.h>
#include <map>
#include <string>
#include <vector>

#include <android/content/AttributionSourceState.h>
#include <android/media/AudioVibratorInfo.h>
#include <android/media/BnAudioFlingerService.h>
#include <android/media/BpAudioFlingerService.h>
#include <android/media/audio/common/AudioMMapPolicyInfo.h>
#include <android/media/audio/common/AudioMMapPolicyType.h>
#include "android/media/CreateEffectRequest.h"
#include "android/media/CreateEffectResponse.h"
#include "android/media/CreateRecordRequest.h"
#include "android/media/CreateRecordResponse.h"
#include "android/media/CreateTrackRequest.h"
#include "android/media/CreateTrackResponse.h"
#include "android/media/IAudioRecord.h"
#include "android/media/IAudioFlingerClient.h"
#include "android/media/IAudioTrack.h"
#include "android/media/IAudioTrackCallback.h"
#include "android/media/IEffect.h"
#include "android/media/IEffectClient.h"
#include "android/media/ISoundDose.h"
#include "android/media/ISoundDoseCallback.h"
#include "android/media/OpenInputRequest.h"
#include "android/media/OpenInputResponse.h"
#include "android/media/OpenOutputRequest.h"
#include "android/media/OpenOutputResponse.h"
#include "android/media/TrackSecondaryOutputInfo.h"

namespace android {

// ----------------------------------------------------------------------------

class IAudioFlinger : public virtual RefBase {
public:
    static constexpr char DEFAULT_SERVICE_NAME[] = "media.audio_flinger";

    virtual ~IAudioFlinger() = default;

    /* CreateTrackInput contains all input arguments sent by AudioTrack to AudioFlinger
     * when calling createTrack() including arguments that will be updated by AudioFlinger
     * and returned in CreateTrackOutput object
     */
    class CreateTrackInput {
    public:
        /* input */
        audio_attributes_t attr;
        audio_config_t config;
        AudioClient clientInfo;
        sp<IMemory> sharedBuffer;
        uint32_t notificationsPerBuffer;
        float speed;
        sp<media::IAudioTrackCallback> audioTrackCallback;

        /* input/output */
        audio_output_flags_t flags;
        size_t frameCount;
        size_t notificationFrameCount;
        audio_port_handle_t selectedDeviceId;
        audio_session_t sessionId;

        ConversionResult<media::CreateTrackRequest> toAidl() const;
        static ConversionResult<CreateTrackInput> fromAidl(const media::CreateTrackRequest& aidl);
    };

    /* CreateTrackOutput contains all output arguments returned by AudioFlinger to AudioTrack
     * when calling createTrack() including arguments that were passed as I/O for update by
     * CreateTrackInput.
     */
    class CreateTrackOutput {
    public:
        /* input/output */
        audio_output_flags_t flags;
        size_t frameCount;
        size_t notificationFrameCount;
        audio_port_handle_t selectedDeviceId;
        audio_session_t sessionId;

        /* output */
        uint32_t sampleRate;
        audio_stream_type_t streamType;
        size_t   afFrameCount;
        uint32_t afSampleRate;
        uint32_t afLatencyMs;
        audio_channel_mask_t afChannelMask;
        audio_format_t afFormat;
        audio_output_flags_t afTrackFlags;
        audio_io_handle_t outputId;
        audio_port_handle_t portId;
        sp<media::IAudioTrack> audioTrack;

        ConversionResult<media::CreateTrackResponse> toAidl() const;
        static ConversionResult<CreateTrackOutput> fromAidl(const media::CreateTrackResponse& aidl);
    };

    /* CreateRecordInput contains all input arguments sent by AudioRecord to AudioFlinger
     * when calling createRecord() including arguments that will be updated by AudioFlinger
     * and returned in CreateRecordOutput object
     */
    class CreateRecordInput {
    public:
        /* input */
        audio_attributes_t attr;
        audio_config_base_t config;
        AudioClient clientInfo;
        audio_unique_id_t riid;
        int32_t maxSharedAudioHistoryMs;

        /* input/output */
        audio_input_flags_t flags;
        size_t frameCount;
        size_t notificationFrameCount;
        audio_port_handle_t selectedDeviceId;
        audio_session_t sessionId;

        ConversionResult<media::CreateRecordRequest> toAidl() const;
        static ConversionResult<CreateRecordInput> fromAidl(const media::CreateRecordRequest& aidl);
    };

    /* CreateRecordOutput contains all output arguments returned by AudioFlinger to AudioRecord
     * when calling createRecord() including arguments that were passed as I/O for update by
     * CreateRecordInput.
     */
    class CreateRecordOutput {
    public:
        /* input/output */
        audio_input_flags_t flags;
        size_t frameCount;
        size_t notificationFrameCount;
        audio_port_handle_t selectedDeviceId;
        audio_session_t sessionId;

        /* output */
        uint32_t sampleRate;
        audio_io_handle_t inputId;
        sp<IMemory> cblk;
        sp<IMemory> buffers;
        audio_port_handle_t portId;
        sp<media::IAudioRecord> audioRecord;
        audio_config_base_t serverConfig;
        audio_config_base_t halConfig;

        ConversionResult<media::CreateRecordResponse> toAidl() const;
        static ConversionResult<CreateRecordOutput>
        fromAidl(const media::CreateRecordResponse& aidl);
    };

    /* create an audio track and registers it with AudioFlinger.
     * The audioTrack field will be null if the track cannot be created and the status will reflect
     * failure.
     */
    virtual status_t createTrack(const media::CreateTrackRequest& input,
                                 media::CreateTrackResponse& output) = 0;

    /* create an audio record and registers it with AudioFlinger.
     * The audioRecord field will be null if the track cannot be created and the status will reflect
     * failure.
     */
    virtual status_t createRecord(const media::CreateRecordRequest& input,
                                  media::CreateRecordResponse& output) = 0;

    // FIXME Surprisingly, format/latency don't work for input handles

    /* query the audio hardware state. This state never changes,
     * and therefore can be cached.
     */
    virtual     uint32_t    sampleRate(audio_io_handle_t ioHandle) const = 0;

    // reserved; formerly channelCount()

    virtual     audio_format_t format(audio_io_handle_t output) const = 0;
    virtual     size_t      frameCount(audio_io_handle_t ioHandle) const = 0;

    // return estimated latency in milliseconds
    virtual     uint32_t    latency(audio_io_handle_t output) const = 0;

    /* set/get the audio hardware state. This will probably be used by
     * the preference panel, mostly.
     */
    virtual     status_t    setMasterVolume(float value) = 0;
    virtual     status_t    setMasterMute(bool muted) = 0;

    virtual     float       masterVolume() const = 0;
    virtual     bool        masterMute() const = 0;

    virtual     status_t    setMasterBalance(float balance) = 0;
    virtual     status_t    getMasterBalance(float *balance) const = 0;

    /* set/get stream type state. This will probably be used by
     * the preference panel, mostly.
     */
    virtual     status_t    setStreamVolume(audio_stream_type_t stream, float value,
                                    audio_io_handle_t output) = 0;
    virtual     status_t    setStreamMute(audio_stream_type_t stream, bool muted) = 0;

    virtual     float       streamVolume(audio_stream_type_t stream,
                                    audio_io_handle_t output) const = 0;
    virtual     bool        streamMute(audio_stream_type_t stream) const = 0;

    // set audio mode
    virtual     status_t    setMode(audio_mode_t mode) = 0;

    // mic mute/state
    virtual     status_t    setMicMute(bool state) = 0;
    virtual     bool        getMicMute() const = 0;
    virtual     void        setRecordSilenced(audio_port_handle_t portId, bool silenced) = 0;

    virtual     status_t    setParameters(audio_io_handle_t ioHandle,
                                    const String8& keyValuePairs) = 0;
    virtual     String8     getParameters(audio_io_handle_t ioHandle, const String8& keys)
                                    const = 0;

    // Register an object to receive audio input/output change and track notifications.
    // For a given calling pid, AudioFlinger disregards any registrations after the first.
    // Thus the IAudioFlingerClient must be a singleton per process.
    virtual void registerClient(const sp<media::IAudioFlingerClient>& client) = 0;

    // retrieve the audio recording buffer size in bytes
    // FIXME This API assumes a route, and so should be deprecated.
    virtual size_t getInputBufferSize(uint32_t sampleRate, audio_format_t format,
            audio_channel_mask_t channelMask) const = 0;

    virtual status_t openOutput(const media::OpenOutputRequest& request,
                                media::OpenOutputResponse* response) = 0;
    virtual audio_io_handle_t openDuplicateOutput(audio_io_handle_t output1,
                                    audio_io_handle_t output2) = 0;
    virtual status_t closeOutput(audio_io_handle_t output) = 0;
    virtual status_t suspendOutput(audio_io_handle_t output) = 0;
    virtual status_t restoreOutput(audio_io_handle_t output) = 0;

    virtual status_t openInput(const media::OpenInputRequest& request,
                               media::OpenInputResponse* response) = 0;

    virtual status_t closeInput(audio_io_handle_t input) = 0;

    virtual status_t setVoiceVolume(float volume) = 0;

    virtual status_t getRenderPosition(uint32_t *halFrames, uint32_t *dspFrames,
                                    audio_io_handle_t output) const = 0;

    virtual uint32_t getInputFramesLost(audio_io_handle_t ioHandle) const = 0;

    virtual audio_unique_id_t newAudioUniqueId(audio_unique_id_use_t use) = 0;

    virtual void acquireAudioSessionId(audio_session_t audioSession, pid_t pid, uid_t uid) = 0;
    virtual void releaseAudioSessionId(audio_session_t audioSession, pid_t pid) = 0;

    virtual status_t queryNumberEffects(uint32_t *numEffects) const = 0;

    virtual status_t queryEffect(uint32_t index, effect_descriptor_t *pDescriptor) const = 0;

    virtual status_t getEffectDescriptor(const effect_uuid_t *pEffectUUID,
                                         const effect_uuid_t *pTypeUUID,
                                         uint32_t preferredTypeFlag,
                                         effect_descriptor_t *pDescriptor) const = 0;

    virtual status_t createEffect(const media::CreateEffectRequest& request,
                                  media::CreateEffectResponse* response) = 0;

    virtual status_t moveEffects(audio_session_t session, audio_io_handle_t srcOutput,
                                    audio_io_handle_t dstOutput) = 0;

    virtual void setEffectSuspended(int effectId,
                                    audio_session_t sessionId,
                                    bool suspended) = 0;

    virtual audio_module_handle_t loadHwModule(const char *name) = 0;

    // helpers for android.media.AudioManager.getProperty(), see description there for meaning
    // FIXME move these APIs to AudioPolicy to permit a more accurate implementation
    // that looks on primary device for a stream with fast flag, primary flag, or first one.
    virtual uint32_t getPrimaryOutputSamplingRate() const = 0;
    virtual size_t getPrimaryOutputFrameCount() const = 0;

    // Intended for AudioService to inform AudioFlinger of device's low RAM attribute,
    // and should be called at most once.  For a definition of what "low RAM" means, see
    // android.app.ActivityManager.isLowRamDevice().  The totalMemory parameter
    // is obtained from android.app.ActivityManager.MemoryInfo.totalMem.
    virtual status_t setLowRamDevice(bool isLowRamDevice, int64_t totalMemory) = 0;

    /* Get attributes for a given audio port */
    virtual status_t getAudioPort(struct audio_port_v7* port) const = 0;

    /* Create an audio patch between several source and sink ports */
    virtual status_t createAudioPatch(const struct audio_patch *patch,
                                       audio_patch_handle_t *handle) = 0;

    /* Release an audio patch */
    virtual status_t releaseAudioPatch(audio_patch_handle_t handle) = 0;

    /* List existing audio patches */
    virtual status_t listAudioPatches(unsigned int *num_patches,
                                      struct audio_patch* patches) const = 0;
    /* Set audio port configuration */
    virtual status_t setAudioPortConfig(const struct audio_port_config *config) = 0;

    /* Get the HW synchronization source used for an audio session */
    virtual audio_hw_sync_t getAudioHwSyncForSession(audio_session_t sessionId) = 0;

    /* Indicate JAVA services are ready (scheduling, power management ...) */
    virtual status_t systemReady() = 0;

    // Indicate audio policy service is ready
    virtual status_t audioPolicyReady() = 0;

    // Returns the number of frames per audio HAL buffer.
    virtual size_t frameCountHAL(audio_io_handle_t ioHandle) const = 0;

    /* List available microphones and their characteristics */
    virtual status_t getMicrophones(std::vector<media::MicrophoneInfoFw>* microphones) const = 0;

    virtual status_t setAudioHalPids(const std::vector<pid_t>& pids) = 0;

    // Set vibrators' information.
    // The values will be used to initialize HapticGenerator.
    virtual status_t setVibratorInfos(
            const std::vector<media::AudioVibratorInfo>& vibratorInfos) = 0;

    virtual status_t updateSecondaryOutputs(
            const TrackSecondaryOutputsMap& trackSecondaryOutputs) = 0;

    virtual status_t getMmapPolicyInfos(
            media::audio::common::AudioMMapPolicyType policyType,
            std::vector<media::audio::common::AudioMMapPolicyInfo> *policyInfos) = 0;

    virtual int32_t getAAudioMixerBurstCount() const = 0;

    virtual int32_t getAAudioHardwareBurstMinUsec() const = 0;

    virtual status_t setDeviceConnectedState(const struct audio_port_v7 *port,
                                             media::DeviceConnectedState state) = 0;

    virtual status_t setSimulateDeviceConnections(bool enabled) = 0;

    virtual status_t setRequestedLatencyMode(
            audio_io_handle_t output, audio_latency_mode_t mode) = 0;

    virtual status_t getSupportedLatencyModes(audio_io_handle_t output,
            std::vector<audio_latency_mode_t>* modes) const = 0;

    virtual status_t getSoundDoseInterface(const sp<media::ISoundDoseCallback>& callback,
                                           sp<media::ISoundDose>* soundDose) const = 0;

    virtual status_t invalidateTracks(const std::vector<audio_port_handle_t>& portIds) = 0;

    virtual status_t setBluetoothVariableLatencyEnabled(bool enabled) = 0;

    virtual status_t isBluetoothVariableLatencyEnabled(bool* enabled) const = 0;

    virtual status_t supportsBluetoothVariableLatency(bool* support) const = 0;

    virtual status_t getAudioPolicyConfig(media::AudioPolicyConfig* output) = 0;

    virtual status_t getAudioMixPort(const struct audio_port_v7 *devicePort,
                                     struct audio_port_v7 *mixPort) const = 0;

    virtual status_t setAppVolume(const String8& packageName, const float value) = 0;
    virtual status_t setAppMute(const String8& packageName, const bool value) = 0;
    virtual status_t listAppVolumes(std::vector<media::AppVolume> *vols) = 0;
};

/**
 * A client-side adapter, wrapping an IAudioFlingerService instance and presenting it as an
 * IAudioFlinger. Intended to be used by legacy client code that was written against IAudioFlinger,
 * before IAudioFlingerService was introduced as an AIDL service.
 * New clients should not use this adapter, but rather IAudioFlingerService directly, via
 * BpAudioFlingerService.
 */
class AudioFlingerClientAdapter : public IAudioFlinger {
public:
    explicit AudioFlingerClientAdapter(const sp<media::IAudioFlingerService> delegate);

    status_t createTrack(const media::CreateTrackRequest& input,
                         media::CreateTrackResponse& output) override;
    status_t createRecord(const media::CreateRecordRequest& input,
                          media::CreateRecordResponse& output) override;
    uint32_t sampleRate(audio_io_handle_t ioHandle) const override;
    audio_format_t format(audio_io_handle_t output) const override;
    size_t frameCount(audio_io_handle_t ioHandle) const override;
    uint32_t latency(audio_io_handle_t output) const override;
    status_t setMasterVolume(float value) override;
    status_t setMasterMute(bool muted) override;
    float masterVolume() const override;
    bool masterMute() const override;
    status_t setMasterBalance(float balance) override;
    status_t getMasterBalance(float* balance) const override;
    status_t setStreamVolume(audio_stream_type_t stream, float value,
                             audio_io_handle_t output) override;
    status_t setStreamMute(audio_stream_type_t stream, bool muted) override;
    float streamVolume(audio_stream_type_t stream,
                       audio_io_handle_t output) const override;
    bool streamMute(audio_stream_type_t stream) const override;
    status_t setMode(audio_mode_t mode) override;
    status_t setMicMute(bool state) override;
    bool getMicMute() const override;
    void setRecordSilenced(audio_port_handle_t portId, bool silenced) override;
    status_t setParameters(audio_io_handle_t ioHandle,
                           const String8& keyValuePairs) override;
    String8 getParameters(audio_io_handle_t ioHandle, const String8& keys)
    const override;
    void registerClient(const sp<media::IAudioFlingerClient>& client) override;
    size_t getInputBufferSize(uint32_t sampleRate, audio_format_t format,
                              audio_channel_mask_t channelMask) const override;
    status_t openOutput(const media::OpenOutputRequest& request,
                        media::OpenOutputResponse* response) override;
    audio_io_handle_t openDuplicateOutput(audio_io_handle_t output1,
                                          audio_io_handle_t output2) override;
    status_t closeOutput(audio_io_handle_t output) override;
    status_t suspendOutput(audio_io_handle_t output) override;
    status_t restoreOutput(audio_io_handle_t output) override;
    status_t openInput(const media::OpenInputRequest& request,
                       media::OpenInputResponse* response) override;
    status_t closeInput(audio_io_handle_t input) override;
    status_t setVoiceVolume(float volume) override;
    status_t getRenderPosition(uint32_t* halFrames, uint32_t* dspFrames,
                               audio_io_handle_t output) const override;
    uint32_t getInputFramesLost(audio_io_handle_t ioHandle) const override;
    audio_unique_id_t newAudioUniqueId(audio_unique_id_use_t use) override;
    void acquireAudioSessionId(audio_session_t audioSession, pid_t pid, uid_t uid) override;
    void releaseAudioSessionId(audio_session_t audioSession, pid_t pid) override;
    status_t queryNumberEffects(uint32_t* numEffects) const override;
    status_t queryEffect(uint32_t index, effect_descriptor_t* pDescriptor) const override;
    status_t getEffectDescriptor(const effect_uuid_t* pEffectUUID,
                                 const effect_uuid_t* pTypeUUID,
                                 uint32_t preferredTypeFlag,
                                 effect_descriptor_t* pDescriptor) const override;
    status_t createEffect(const media::CreateEffectRequest& request,
                          media::CreateEffectResponse* response) override;
    status_t moveEffects(audio_session_t session, audio_io_handle_t srcOutput,
                         audio_io_handle_t dstOutput) override;
    void setEffectSuspended(int effectId,
                            audio_session_t sessionId,
                            bool suspended) override;
    audio_module_handle_t loadHwModule(const char* name) override;
    uint32_t getPrimaryOutputSamplingRate() const override;
    size_t getPrimaryOutputFrameCount() const override;
    status_t setLowRamDevice(bool isLowRamDevice, int64_t totalMemory) override;
    status_t getAudioPort(struct audio_port_v7* port) const override;
    status_t createAudioPatch(const struct audio_patch* patch,
                              audio_patch_handle_t* handle) override;
    status_t releaseAudioPatch(audio_patch_handle_t handle) override;
    status_t listAudioPatches(unsigned int* num_patches,
                              struct audio_patch* patches) const override;
    status_t setAudioPortConfig(const struct audio_port_config* config) override;
    audio_hw_sync_t getAudioHwSyncForSession(audio_session_t sessionId) override;
    status_t systemReady() override;
    status_t audioPolicyReady() override;

    size_t frameCountHAL(audio_io_handle_t ioHandle) const override;
    status_t getMicrophones(std::vector<media::MicrophoneInfoFw>* microphones) const override;
    status_t setAudioHalPids(const std::vector<pid_t>& pids) override;
    status_t setVibratorInfos(const std::vector<media::AudioVibratorInfo>& vibratorInfos) override;
    status_t updateSecondaryOutputs(
            const TrackSecondaryOutputsMap& trackSecondaryOutputs) override;
    status_t getMmapPolicyInfos(
            media::audio::common::AudioMMapPolicyType policyType,
            std::vector<media::audio::common::AudioMMapPolicyInfo> *policyInfos) override;
    int32_t getAAudioMixerBurstCount() const override;
    int32_t getAAudioHardwareBurstMinUsec() const override;
    status_t setDeviceConnectedState(const struct audio_port_v7 *port,
                                     media::DeviceConnectedState state) override;
    status_t setSimulateDeviceConnections(bool enabled) override;
    status_t setRequestedLatencyMode(audio_io_handle_t output,
            audio_latency_mode_t mode) override;
    status_t getSupportedLatencyModes(
            audio_io_handle_t output, std::vector<audio_latency_mode_t>* modes) const override;
    status_t setBluetoothVariableLatencyEnabled(bool enabled) override;
    status_t isBluetoothVariableLatencyEnabled(bool* enabled) const override;
    status_t supportsBluetoothVariableLatency(bool* support) const override;
    status_t getSoundDoseInterface(const sp<media::ISoundDoseCallback>& callback,
                                   sp<media::ISoundDose>* soundDose) const override;
    status_t invalidateTracks(const std::vector<audio_port_handle_t>& portIds) override;
    status_t getAudioPolicyConfig(media::AudioPolicyConfig* output) override;
    status_t getAudioMixPort(const struct audio_port_v7 *devicePort,
                             struct audio_port_v7 *mixPort) const override;

    status_t setAppVolume(const String8& packageName, const float value) override;
    status_t setAppMute(const String8& packageName, const bool value) override;
    status_t listAppVolumes(std::vector<media::AppVolume> *vols) override;

private:
    const sp<media::IAudioFlingerService> mDelegate;
};

/**
 * A server-side adapter, wrapping an IAudioFlinger instance and presenting it as an
 * IAudioFlingerService. Intended to be used by legacy server code that was written against
 * IAudioFlinger, before IAudioFlingerService was introduced as an AIDL service.
 * New servers should not use this adapter, but rather implement IAudioFlingerService directly, via
 * BnAudioFlingerService.
 */
class AudioFlingerServerAdapter : public media::BnAudioFlingerService {
public:
    using Status = binder::Status;

    /**
     * Legacy server should implement this interface in order to be wrapped.
     */
    class Delegate : public IAudioFlinger {
        friend class AudioFlingerServerAdapter;
    public:
        // expose the TransactionCode enum for TimeCheck purposes.
        enum class TransactionCode {
            CREATE_TRACK = media::BnAudioFlingerService::TRANSACTION_createTrack,
            CREATE_RECORD = media::BnAudioFlingerService::TRANSACTION_createRecord,
            SAMPLE_RATE = media::BnAudioFlingerService::TRANSACTION_sampleRate,
            FORMAT = media::BnAudioFlingerService::TRANSACTION_format,
            FRAME_COUNT = media::BnAudioFlingerService::TRANSACTION_frameCount,
            LATENCY = media::BnAudioFlingerService::TRANSACTION_latency,
            SET_MASTER_VOLUME = media::BnAudioFlingerService::TRANSACTION_setMasterVolume,
            SET_MASTER_MUTE = media::BnAudioFlingerService::TRANSACTION_setMasterMute,
            MASTER_VOLUME = media::BnAudioFlingerService::TRANSACTION_masterVolume,
            MASTER_MUTE = media::BnAudioFlingerService::TRANSACTION_masterMute,
            SET_STREAM_VOLUME = media::BnAudioFlingerService::TRANSACTION_setStreamVolume,
            SET_STREAM_MUTE = media::BnAudioFlingerService::TRANSACTION_setStreamMute,
            STREAM_VOLUME = media::BnAudioFlingerService::TRANSACTION_streamVolume,
            STREAM_MUTE = media::BnAudioFlingerService::TRANSACTION_streamMute,
            SET_MODE = media::BnAudioFlingerService::TRANSACTION_setMode,
            SET_MIC_MUTE = media::BnAudioFlingerService::TRANSACTION_setMicMute,
            GET_MIC_MUTE = media::BnAudioFlingerService::TRANSACTION_getMicMute,
            SET_RECORD_SILENCED = media::BnAudioFlingerService::TRANSACTION_setRecordSilenced,
            SET_PARAMETERS = media::BnAudioFlingerService::TRANSACTION_setParameters,
            GET_PARAMETERS = media::BnAudioFlingerService::TRANSACTION_getParameters,
            REGISTER_CLIENT = media::BnAudioFlingerService::TRANSACTION_registerClient,
            GET_INPUTBUFFERSIZE = media::BnAudioFlingerService::TRANSACTION_getInputBufferSize,
            OPEN_OUTPUT = media::BnAudioFlingerService::TRANSACTION_openOutput,
            OPEN_DUPLICATE_OUTPUT = media::BnAudioFlingerService::TRANSACTION_openDuplicateOutput,
            CLOSE_OUTPUT = media::BnAudioFlingerService::TRANSACTION_closeOutput,
            SUSPEND_OUTPUT = media::BnAudioFlingerService::TRANSACTION_suspendOutput,
            RESTORE_OUTPUT = media::BnAudioFlingerService::TRANSACTION_restoreOutput,
            OPEN_INPUT = media::BnAudioFlingerService::TRANSACTION_openInput,
            CLOSE_INPUT = media::BnAudioFlingerService::TRANSACTION_closeInput,
            SET_VOICE_VOLUME = media::BnAudioFlingerService::TRANSACTION_setVoiceVolume,
            GET_RENDER_POSITION = media::BnAudioFlingerService::TRANSACTION_getRenderPosition,
            GET_INPUT_FRAMES_LOST = media::BnAudioFlingerService::TRANSACTION_getInputFramesLost,
            NEW_AUDIO_UNIQUE_ID = media::BnAudioFlingerService::TRANSACTION_newAudioUniqueId,
            ACQUIRE_AUDIO_SESSION_ID = media::BnAudioFlingerService::TRANSACTION_acquireAudioSessionId,
            RELEASE_AUDIO_SESSION_ID = media::BnAudioFlingerService::TRANSACTION_releaseAudioSessionId,
            QUERY_NUM_EFFECTS = media::BnAudioFlingerService::TRANSACTION_queryNumberEffects,
            QUERY_EFFECT = media::BnAudioFlingerService::TRANSACTION_queryEffect,
            GET_EFFECT_DESCRIPTOR = media::BnAudioFlingerService::TRANSACTION_getEffectDescriptor,
            CREATE_EFFECT = media::BnAudioFlingerService::TRANSACTION_createEffect,
            MOVE_EFFECTS = media::BnAudioFlingerService::TRANSACTION_moveEffects,
            LOAD_HW_MODULE = media::BnAudioFlingerService::TRANSACTION_loadHwModule,
            GET_PRIMARY_OUTPUT_SAMPLING_RATE = media::BnAudioFlingerService::TRANSACTION_getPrimaryOutputSamplingRate,
            GET_PRIMARY_OUTPUT_FRAME_COUNT = media::BnAudioFlingerService::TRANSACTION_getPrimaryOutputFrameCount,
            SET_LOW_RAM_DEVICE = media::BnAudioFlingerService::TRANSACTION_setLowRamDevice,
            GET_AUDIO_PORT = media::BnAudioFlingerService::TRANSACTION_getAudioPort,
            CREATE_AUDIO_PATCH = media::BnAudioFlingerService::TRANSACTION_createAudioPatch,
            RELEASE_AUDIO_PATCH = media::BnAudioFlingerService::TRANSACTION_releaseAudioPatch,
            LIST_AUDIO_PATCHES = media::BnAudioFlingerService::TRANSACTION_listAudioPatches,
            SET_AUDIO_PORT_CONFIG = media::BnAudioFlingerService::TRANSACTION_setAudioPortConfig,
            GET_AUDIO_HW_SYNC_FOR_SESSION = media::BnAudioFlingerService::TRANSACTION_getAudioHwSyncForSession,
            SYSTEM_READY = media::BnAudioFlingerService::TRANSACTION_systemReady,
            AUDIO_POLICY_READY = media::BnAudioFlingerService::TRANSACTION_audioPolicyReady,
            FRAME_COUNT_HAL = media::BnAudioFlingerService::TRANSACTION_frameCountHAL,
            GET_MICROPHONES = media::BnAudioFlingerService::TRANSACTION_getMicrophones,
            SET_MASTER_BALANCE = media::BnAudioFlingerService::TRANSACTION_setMasterBalance,
            GET_MASTER_BALANCE = media::BnAudioFlingerService::TRANSACTION_getMasterBalance,
            SET_EFFECT_SUSPENDED = media::BnAudioFlingerService::TRANSACTION_setEffectSuspended,
            SET_AUDIO_HAL_PIDS = media::BnAudioFlingerService::TRANSACTION_setAudioHalPids,
            SET_VIBRATOR_INFOS = media::BnAudioFlingerService::TRANSACTION_setVibratorInfos,
            UPDATE_SECONDARY_OUTPUTS = media::BnAudioFlingerService::TRANSACTION_updateSecondaryOutputs,
            GET_MMAP_POLICY_INFOS = media::BnAudioFlingerService::TRANSACTION_getMmapPolicyInfos,
            GET_AAUDIO_MIXER_BURST_COUNT = media::BnAudioFlingerService::TRANSACTION_getAAudioMixerBurstCount,
            GET_AAUDIO_HARDWARE_BURST_MIN_USEC = media::BnAudioFlingerService::TRANSACTION_getAAudioHardwareBurstMinUsec,
            SET_DEVICE_CONNECTED_STATE = media::BnAudioFlingerService::TRANSACTION_setDeviceConnectedState,
            SET_SIMULATE_DEVICE_CONNECTIONS = media::BnAudioFlingerService::TRANSACTION_setSimulateDeviceConnections,
            SET_REQUESTED_LATENCY_MODE = media::BnAudioFlingerService::TRANSACTION_setRequestedLatencyMode,
            GET_SUPPORTED_LATENCY_MODES = media::BnAudioFlingerService::TRANSACTION_getSupportedLatencyModes,
            SET_BLUETOOTH_VARIABLE_LATENCY_ENABLED =
                    media::BnAudioFlingerService::TRANSACTION_setBluetoothVariableLatencyEnabled,
            IS_BLUETOOTH_VARIABLE_LATENCY_ENABLED =
                    media::BnAudioFlingerService::TRANSACTION_isBluetoothVariableLatencyEnabled,
            SUPPORTS_BLUETOOTH_VARIABLE_LATENCY =
                    media::BnAudioFlingerService::TRANSACTION_supportsBluetoothVariableLatency,
            GET_SOUND_DOSE_INTERFACE = media::BnAudioFlingerService::TRANSACTION_getSoundDoseInterface,
            INVALIDATE_TRACKS = media::BnAudioFlingerService::TRANSACTION_invalidateTracks,
            GET_AUDIO_POLICY_CONFIG =
                    media::BnAudioFlingerService::TRANSACTION_getAudioPolicyConfig,
            GET_AUDIO_MIX_PORT = media::BnAudioFlingerService::TRANSACTION_getAudioMixPort,
            SET_APP_VOLUME = media::BnAudioFlingerService::TRANSACTION_setAppVolume,
            SET_APP_MUTE = media::BnAudioFlingerService::TRANSACTION_setAppMute,
            LIST_APP_VOLUMES = media::BnAudioFlingerService::TRANSACTION_listAppVolumes,
        };

    protected:
        /**
         * And optional hook, called on every transaction, allowing additional operations to be
         * performed before/after the unparceling  ofthe data and dispatching to the respective
         * method. Useful for bulk operations, such as logging or permission checks.
         * The implementer is responsible to invoke the provided delegate function, which is the
         * actual onTransact(), unless an error occurs.
         * By default, this is just a pass-through to the delegate.
         */
        virtual status_t onTransactWrapper(TransactionCode code,
                                           const Parcel& data,
                                           uint32_t flags,
                                           const std::function<status_t()>& delegate) {
            (void) code;
            (void) data;
            (void) flags;
            return delegate();
        }

        /**
         * An optional hook for implementing diagnostics dumping.
         */
        virtual status_t dump(int fd, const Vector<String16>& args) {
            (void) fd;
            (void) args;
            return OK;
        }
    };

    explicit AudioFlingerServerAdapter(
            const sp<AudioFlingerServerAdapter::Delegate>& delegate);

    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) override;
    status_t dump(int fd, const Vector<String16>& args) override;

    Status createTrack(const media::CreateTrackRequest& request,
                       media::CreateTrackResponse* _aidl_return) override;
    Status createRecord(const media::CreateRecordRequest& request,
                        media::CreateRecordResponse* _aidl_return) override;
    Status sampleRate(int32_t ioHandle, int32_t* _aidl_return) override;
    Status format(int32_t output,
                  media::audio::common::AudioFormatDescription* _aidl_return) override;
    Status frameCount(int32_t ioHandle, int64_t* _aidl_return) override;
    Status latency(int32_t output, int32_t* _aidl_return) override;
    Status setMasterVolume(float value) override;
    Status setMasterMute(bool muted) override;
    Status masterVolume(float* _aidl_return) override;
    Status masterMute(bool* _aidl_return) override;
    Status setMasterBalance(float balance) override;
    Status getMasterBalance(float* _aidl_return) override;
    Status setStreamVolume(media::audio::common::AudioStreamType stream,
                           float value, int32_t output) override;
    Status setStreamMute(media::audio::common::AudioStreamType stream, bool muted) override;
    Status streamVolume(media::audio::common::AudioStreamType stream,
                        int32_t output, float* _aidl_return) override;
    Status streamMute(media::audio::common::AudioStreamType stream, bool* _aidl_return) override;
    Status setMode(media::audio::common::AudioMode mode) override;
    Status setMicMute(bool state) override;
    Status getMicMute(bool* _aidl_return) override;
    Status setRecordSilenced(int32_t portId, bool silenced) override;
    Status setParameters(int32_t ioHandle, const std::string& keyValuePairs) override;
    Status
    getParameters(int32_t ioHandle, const std::string& keys, std::string* _aidl_return) override;
    Status registerClient(const sp<media::IAudioFlingerClient>& client) override;
    Status getInputBufferSize(int32_t sampleRate,
                              const media::audio::common::AudioFormatDescription& format,
                              const media::audio::common::AudioChannelLayout& channelMask,
                              int64_t* _aidl_return) override;
    Status openOutput(const media::OpenOutputRequest& request,
                      media::OpenOutputResponse* _aidl_return) override;
    Status openDuplicateOutput(int32_t output1, int32_t output2, int32_t* _aidl_return) override;
    Status closeOutput(int32_t output) override;
    Status suspendOutput(int32_t output) override;
    Status restoreOutput(int32_t output) override;
    Status openInput(const media::OpenInputRequest& request,
                     media::OpenInputResponse* _aidl_return) override;
    Status closeInput(int32_t input) override;
    Status setVoiceVolume(float volume) override;
    Status getRenderPosition(int32_t output, media::RenderPosition* _aidl_return) override;
    Status getInputFramesLost(int32_t ioHandle, int32_t* _aidl_return) override;
    Status newAudioUniqueId(media::AudioUniqueIdUse use, int32_t* _aidl_return) override;
    Status acquireAudioSessionId(int32_t audioSession, int32_t pid, int32_t uid) override;
    Status releaseAudioSessionId(int32_t audioSession, int32_t pid) override;
    Status queryNumberEffects(int32_t* _aidl_return) override;
    Status queryEffect(int32_t index, media::EffectDescriptor* _aidl_return) override;
    Status getEffectDescriptor(const media::audio::common::AudioUuid& effectUUID,
                               const media::audio::common::AudioUuid& typeUUID,
                               int32_t preferredTypeFlag,
                               media::EffectDescriptor* _aidl_return) override;
    Status createEffect(const media::CreateEffectRequest& request,
                        media::CreateEffectResponse* _aidl_return) override;
    Status moveEffects(int32_t session, int32_t srcOutput, int32_t dstOutput) override;
    Status setEffectSuspended(int32_t effectId, int32_t sessionId, bool suspended) override;
    Status loadHwModule(const std::string& name, int32_t* _aidl_return) override;
    Status getPrimaryOutputSamplingRate(int32_t* _aidl_return) override;
    Status getPrimaryOutputFrameCount(int64_t* _aidl_return) override;
    Status setLowRamDevice(bool isLowRamDevice, int64_t totalMemory) override;
    Status getAudioPort(const media::AudioPortFw& port, media::AudioPortFw* _aidl_return) override;
    Status createAudioPatch(const media::AudioPatchFw& patch, int32_t* _aidl_return) override;
    Status releaseAudioPatch(int32_t handle) override;
    Status listAudioPatches(int32_t maxCount,
                            std::vector<media::AudioPatchFw>* _aidl_return) override;
    Status setAudioPortConfig(const media::AudioPortConfigFw& config) override;
    Status getAudioHwSyncForSession(int32_t sessionId, int32_t* _aidl_return) override;
    Status systemReady() override;
    Status audioPolicyReady() override;
    Status frameCountHAL(int32_t ioHandle, int64_t* _aidl_return) override;
    Status getMicrophones(std::vector<media::MicrophoneInfoFw>* _aidl_return) override;
    Status setAudioHalPids(const std::vector<int32_t>& pids) override;
    Status setVibratorInfos(const std::vector<media::AudioVibratorInfo>& vibratorInfos) override;
    Status updateSecondaryOutputs(
            const std::vector<media::TrackSecondaryOutputInfo>& trackSecondaryOutputInfos) override;
    Status getMmapPolicyInfos(
            media::audio::common::AudioMMapPolicyType policyType,
            std::vector<media::audio::common::AudioMMapPolicyInfo> *_aidl_return) override;
    Status getAAudioMixerBurstCount(int32_t* _aidl_return) override;
    Status getAAudioHardwareBurstMinUsec(int32_t* _aidl_return) override;
    Status setDeviceConnectedState(const media::AudioPortFw& port,
                                   media::DeviceConnectedState state) override;
    Status setSimulateDeviceConnections(bool enabled) override;
    Status setRequestedLatencyMode(
            int output, media::audio::common::AudioLatencyMode mode) override;
    Status getSupportedLatencyModes(int output,
            std::vector<media::audio::common::AudioLatencyMode>* _aidl_return) override;
    Status setBluetoothVariableLatencyEnabled(bool enabled) override;
    Status isBluetoothVariableLatencyEnabled(bool* enabled) override;
    Status supportsBluetoothVariableLatency(bool* support) override;
    Status getSoundDoseInterface(const sp<media::ISoundDoseCallback>& callback,
                                 sp<media::ISoundDose>* _aidl_return) override;
    Status invalidateTracks(const std::vector<int32_t>& portIds) override;
    Status getAudioPolicyConfig(media::AudioPolicyConfig* _aidl_return) override;
    Status getAudioMixPort(const media::AudioPortFw& devicePort,
                           const media::AudioPortFw& mixPort,
                           media::AudioPortFw* _aidl_return) override;

    Status setAppVolume(const std::string& packageName, const float value) override;
    Status setAppMute(const std::string& packageName, const bool value) override;
    Status listAppVolumes(std::vector<media::AppVolumeData> *vols) override;
private:
    const sp<AudioFlingerServerAdapter::Delegate> mDelegate;
};

}; // namespace android

#endif // ANDROID_IAUDIOFLINGER_H
