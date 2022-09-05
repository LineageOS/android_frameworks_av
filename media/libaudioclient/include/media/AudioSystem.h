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

#ifndef ANDROID_AUDIOSYSTEM_H_
#define ANDROID_AUDIOSYSTEM_H_

#include <sys/types.h>

#include <set>
#include <vector>

#include <android/content/AttributionSourceState.h>
#include <android/media/AudioPolicyConfig.h>
#include <android/media/AudioPortFw.h>
#include <android/media/AudioVibratorInfo.h>
#include <android/media/BnAudioFlingerClient.h>
#include <android/media/BnAudioPolicyServiceClient.h>
#include <android/media/EffectDescriptor.h>
#include <android/media/INativeSpatializerCallback.h>
#include <android/media/ISoundDose.h>
#include <android/media/ISoundDoseCallback.h>
#include <android/media/ISpatializer.h>
#include <android/media/MicrophoneInfoFw.h>
#include <android/media/RecordClientInfo.h>
#include <android/media/audio/common/AudioConfigBase.h>
#include <android/media/audio/common/AudioMMapPolicyInfo.h>
#include <android/media/audio/common/AudioMMapPolicyType.h>
#include <android/media/audio/common/AudioPort.h>
#include <media/AidlConversionUtil.h>
#include <media/AppVolume.h>
#include <media/AudioContainers.h>
#include <media/AudioDeviceTypeAddr.h>
#include <media/AudioPolicy.h>
#include <media/AudioProductStrategy.h>
#include <media/AudioVolumeGroup.h>
#include <media/AudioIoDescriptor.h>
#include <system/audio.h>
#include <system/audio_effect.h>
#include <system/audio_policy.h>
#include <utils/Errors.h>
#include <utils/Mutex.h>

using android::content::AttributionSourceState;

namespace android {

struct record_client_info {
    audio_unique_id_t riid;
    uid_t uid;
    audio_session_t session;
    audio_source_t source;
    audio_port_handle_t port_id;
    bool silenced;
};

typedef struct record_client_info record_client_info_t;

// AIDL conversion functions.
ConversionResult<record_client_info_t>
aidl2legacy_RecordClientInfo_record_client_info_t(const media::RecordClientInfo& aidl);
ConversionResult<media::RecordClientInfo>
legacy2aidl_record_client_info_t_RecordClientInfo(const record_client_info_t& legacy);

typedef void (*audio_error_callback)(status_t err);
typedef void (*dynamic_policy_callback)(int event, String8 regId, int val);
typedef void (*record_config_callback)(int event,
                                       const record_client_info_t *clientInfo,
                                       const audio_config_base_t *clientConfig,
                                       std::vector<effect_descriptor_t> clientEffects,
                                       const audio_config_base_t *deviceConfig,
                                       std::vector<effect_descriptor_t> effects,
                                       audio_patch_handle_t patchHandle,
                                       audio_source_t source);
typedef void (*routing_callback)();
typedef void (*vol_range_init_req_callback)();

class IAudioFlinger;
class String8;

namespace media {
class IAudioPolicyService;
}

class AudioSystem
{
public:

    // FIXME Declare in binder opcode order, similarly to IAudioFlinger.h and IAudioFlinger.cpp

    /* These are static methods to control the system-wide AudioFlinger
     * only privileged processes can have access to them
     */

    // mute/unmute microphone
    static status_t muteMicrophone(bool state);
    static status_t isMicrophoneMuted(bool *state);

    // set/get master volume
    static status_t setMasterVolume(float value);
    static status_t getMasterVolume(float* volume);

    // mute/unmute audio outputs
    static status_t setMasterMute(bool mute);
    static status_t getMasterMute(bool* mute);

    // set/get stream volume on specified output
    static status_t setStreamVolume(audio_stream_type_t stream, float value,
                                    audio_io_handle_t output);
    static status_t getStreamVolume(audio_stream_type_t stream, float* volume,
                                    audio_io_handle_t output);

    // mute/unmute stream
    static status_t setStreamMute(audio_stream_type_t stream, bool mute);
    static status_t getStreamMute(audio_stream_type_t stream, bool* mute);

    // set audio mode in audio hardware
    static status_t setMode(audio_mode_t mode);

    // test API: switch HALs into the mode which simulates external device connections
    static status_t setSimulateDeviceConnections(bool enabled);

    // returns true in *state if tracks are active on the specified stream or have been active
    // in the past inPastMs milliseconds
    static status_t isStreamActive(audio_stream_type_t stream, bool *state, uint32_t inPastMs);
    // returns true in *state if tracks are active for what qualifies as remote playback
    // on the specified stream or have been active in the past inPastMs milliseconds. Remote
    // playback isn't mutually exclusive with local playback.
    static status_t isStreamActiveRemotely(audio_stream_type_t stream, bool *state,
            uint32_t inPastMs);
    // returns true in *state if a recorder is currently recording with the specified source
    static status_t isSourceActive(audio_source_t source, bool *state);

    // set/get audio hardware parameters. The function accepts a list of parameters
    // key value pairs in the form: key1=value1;key2=value2;...
    // Some keys are reserved for standard parameters (See AudioParameter class).
    // The versions with audio_io_handle_t are intended for internal media framework use only.
    static status_t setParameters(audio_io_handle_t ioHandle, const String8& keyValuePairs);
    static String8  getParameters(audio_io_handle_t ioHandle, const String8& keys);
    // The versions without audio_io_handle_t are intended for JNI.
    static status_t setParameters(const String8& keyValuePairs);
    static String8  getParameters(const String8& keys);

    // Registers an error callback. When this callback is invoked, it means all
    // state implied by this interface has been reset.
    // Returns a token that can be used for un-registering.
    // Might block while callbacks are being invoked.
    static uintptr_t addErrorCallback(audio_error_callback cb);

    // Un-registers a callback previously added with addErrorCallback.
    // Might block while callbacks are being invoked.
    static void removeErrorCallback(uintptr_t cb);

    static void setDynPolicyCallback(dynamic_policy_callback cb);
    static void setRecordConfigCallback(record_config_callback);
    static void setRoutingCallback(routing_callback cb);
    static void setVolInitReqCallback(vol_range_init_req_callback cb);

    // Sets the binder to use for accessing the AudioFlinger service. This enables the system server
    // to grant specific isolated processes access to the audio system. Currently used only for the
    // HotwordDetectionService.
    static void setAudioFlingerBinder(const sp<IBinder>& audioFlinger);

    // Sets a local AudioFlinger interface to be used by AudioSystem.
    // This is used by audioserver main() to avoid binder AIDL translation.
    static status_t setLocalAudioFlinger(const sp<IAudioFlinger>& af);

    // helper function to obtain AudioFlinger service handle
    static const sp<IAudioFlinger> get_audio_flinger();
    static const sp<IAudioFlinger> get_audio_flinger_for_fuzzer();

    static float linearToLog(int volume);
    static int logToLinear(float volume);
    static size_t calculateMinFrameCount(
            uint32_t afLatencyMs, uint32_t afFrameCount, uint32_t afSampleRate,
            uint32_t sampleRate, float speed /*, uint32_t notificationsPerBufferReq*/);

    // Returned samplingRate and frameCount output values are guaranteed
    // to be non-zero if status == NO_ERROR
    // FIXME This API assumes a route, and so should be deprecated.
    static status_t getOutputSamplingRate(uint32_t* samplingRate,
            audio_stream_type_t stream);
    // FIXME This API assumes a route, and so should be deprecated.
    static status_t getOutputFrameCount(size_t* frameCount,
            audio_stream_type_t stream);
    // FIXME This API assumes a route, and so should be deprecated.
    static status_t getOutputLatency(uint32_t* latency,
            audio_stream_type_t stream);
    // returns the audio HAL sample rate
    static status_t getSamplingRate(audio_io_handle_t ioHandle,
                                          uint32_t* samplingRate);
    // For output threads with a fast mixer, returns the number of frames per normal mixer buffer.
    // For output threads without a fast mixer, or for input, this is same as getFrameCountHAL().
    static status_t getFrameCount(audio_io_handle_t ioHandle,
                                  size_t* frameCount);
    // returns the audio output latency in ms. Corresponds to
    // audio_stream_out->get_latency()
    static status_t getLatency(audio_io_handle_t output,
                               uint32_t* latency);

    // return status NO_ERROR implies *buffSize > 0
    // FIXME This API assumes a route, and so should deprecated.
    static status_t getInputBufferSize(uint32_t sampleRate, audio_format_t format,
        audio_channel_mask_t channelMask, size_t* buffSize);

    static status_t setVoiceVolume(float volume);

    // return the number of audio frames written by AudioFlinger to audio HAL and
    // audio dsp to DAC since the specified output has exited standby.
    // returned status (from utils/Errors.h) can be:
    // - NO_ERROR: successful operation, halFrames and dspFrames point to valid data
    // - INVALID_OPERATION: Not supported on current hardware platform
    // - BAD_VALUE: invalid parameter
    // NOTE: this feature is not supported on all hardware platforms and it is
    // necessary to check returned status before using the returned values.
    static status_t getRenderPosition(audio_io_handle_t output,
                                      uint32_t *halFrames,
                                      uint32_t *dspFrames);

    // return the number of input frames lost by HAL implementation, or 0 if the handle is invalid
    static uint32_t getInputFramesLost(audio_io_handle_t ioHandle);

    // Allocate a new unique ID for use as an audio session ID or I/O handle.
    // If unable to contact AudioFlinger, returns AUDIO_UNIQUE_ID_ALLOCATE instead.
    // FIXME If AudioFlinger were to ever exhaust the unique ID namespace,
    //       this method could fail by returning either a reserved ID like AUDIO_UNIQUE_ID_ALLOCATE
    //       or an unspecified existing unique ID.
    static audio_unique_id_t newAudioUniqueId(audio_unique_id_use_t use);

    static void acquireAudioSessionId(audio_session_t audioSession, pid_t pid, uid_t uid);
    static void releaseAudioSessionId(audio_session_t audioSession, pid_t pid);

    // Get the HW synchronization source used for an audio session.
    // Return a valid source or AUDIO_HW_SYNC_INVALID if an error occurs
    // or no HW sync source is used.
    static audio_hw_sync_t getAudioHwSyncForSession(audio_session_t sessionId);

    // Indicate JAVA services are ready (scheduling, power management ...)
    static status_t systemReady();

    // Indicate audio policy service is ready
    static status_t audioPolicyReady();

    // Returns the number of frames per audio HAL buffer.
    // Corresponds to audio_stream->get_buffer_size()/audio_stream_in_frame_size() for input.
    // See also getFrameCount().
    static status_t getFrameCountHAL(audio_io_handle_t ioHandle,
                                     size_t* frameCount);

    // Events used to synchronize actions between audio sessions.
    // For instance SYNC_EVENT_PRESENTATION_COMPLETE can be used to delay recording start until
    // playback is complete on another audio session.
    // See definitions in MediaSyncEvent.java
    enum sync_event_t {
        SYNC_EVENT_SAME = -1,             // used internally to indicate restart with same event
        SYNC_EVENT_NONE = 0,
        SYNC_EVENT_PRESENTATION_COMPLETE,

        //
        // Define new events here: SYNC_EVENT_START, SYNC_EVENT_STOP, SYNC_EVENT_TIME ...
        //
        SYNC_EVENT_CNT,
    };

    // Timeout for synchronous record start. Prevents from blocking the record thread forever
    // if the trigger event is not fired.
    static const uint32_t kSyncRecordStartTimeOutMs = 30000;

    //
    // IAudioPolicyService interface (see AudioPolicyInterface for method descriptions)
    //
    static void onNewAudioModulesAvailable();
    static status_t setDeviceConnectionState(audio_policy_dev_state_t state,
                                             const android::media::audio::common::AudioPort& port,
                                             audio_format_t encodedFormat);
    static audio_policy_dev_state_t getDeviceConnectionState(audio_devices_t device,
                                                                const char *device_address);
    static status_t handleDeviceConfigChange(audio_devices_t device,
                                             const char *device_address,
                                             const char *device_name,
                                             audio_format_t encodedFormat);
    static status_t setPhoneState(audio_mode_t state, uid_t uid);
    static status_t setForceUse(audio_policy_force_use_t usage, audio_policy_forced_cfg_t config);
    static audio_policy_forced_cfg_t getForceUse(audio_policy_force_use_t usage);

    /**
     * Get output stream for given parameters.
     *
     * @param[in] attr the requested audio attributes
     * @param[in|out] output the io handle of the output for the playback. It is specified when
     *                       starting mmap thread.
     * @param[in] session the session id for the client
     * @param[in|out] stream the stream type used for the playback
     * @param[in] attributionSource a source to which access to permission protected data
     * @param[in|out] config the requested configuration client, the suggested configuration will
     *                       be returned if no proper output is found for requested configuration
     * @param[in] flags the requested output flag from client
     * @param[in|out] selectedDeviceId the requested device id for playback, the actual device id
     *                                 for playback will be returned
     * @param[out] portId the generated port id to identify the client
     * @param[out] secondaryOutputs collection of io handle for secondary outputs
     * @param[out] isSpatialized true if the playback will be spatialized
     * @param[out] isBitPerfect true if the playback will be bit-perfect
     * @return if the call is successful or not
     */
    static status_t getOutputForAttr(audio_attributes_t *attr,
                                     audio_io_handle_t *output,
                                     audio_session_t session,
                                     audio_stream_type_t *stream,
                                     const AttributionSourceState& attributionSource,
                                     audio_config_t *config,
                                     audio_output_flags_t flags,
                                     audio_port_handle_t *selectedDeviceId,
                                     audio_port_handle_t *portId,
                                     std::vector<audio_io_handle_t> *secondaryOutputs,
                                     bool *isSpatialized,
                                     bool *isBitPerfect);
    static status_t startOutput(audio_port_handle_t portId);
    static status_t stopOutput(audio_port_handle_t portId);
    static void releaseOutput(audio_port_handle_t portId);

    /**
     * Get input stream for given parameters.
     * Client must successfully hand off the handle reference to AudioFlinger via createRecord(),
     * or release it with releaseInput().
     *
     * @param[in] attr the requested audio attributes
     * @param[in|out] input the io handle of the input for the capture. It is specified when
     *                      starting mmap thread.
     * @param[in] riid an unique id to identify the record client
     * @param[in] session the session id for the client
     * @param[in] attributionSource a source to which access to permission protected data
     * @param[in|out] config the requested configuration client, the suggested configuration will
     *                       be returned if no proper input is found for requested configuration
     * @param[in] flags the requested input flag from client
     * @param[in|out] selectedDeviceId the requested device id for playback, the actual device id
     *                                 for playback will be returned
     * @param[out] portId the generated port id to identify the client
     * @return if the call is successful or not
     */
    static status_t getInputForAttr(const audio_attributes_t *attr,
                                    audio_io_handle_t *input,
                                    audio_unique_id_t riid,
                                    audio_session_t session,
                                    const AttributionSourceState& attributionSource,
                                    audio_config_base_t *config,
                                    audio_input_flags_t flags,
                                    audio_port_handle_t *selectedDeviceId,
                                    audio_port_handle_t *portId);

    static status_t startInput(audio_port_handle_t portId);
    static status_t stopInput(audio_port_handle_t portId);
    static void releaseInput(audio_port_handle_t portId);
    static status_t initStreamVolume(audio_stream_type_t stream,
                                      int indexMin,
                                      int indexMax);
    static status_t setStreamVolumeIndex(audio_stream_type_t stream,
                                         int index,
                                         audio_devices_t device);
    static status_t getStreamVolumeIndex(audio_stream_type_t stream,
                                         int *index,
                                         audio_devices_t device);

    static status_t setVolumeIndexForAttributes(const audio_attributes_t &attr,
                                                int index,
                                                audio_devices_t device);
    static status_t getVolumeIndexForAttributes(const audio_attributes_t &attr,
                                                int &index,
                                                audio_devices_t device);

    static status_t getMaxVolumeIndexForAttributes(const audio_attributes_t &attr, int &index);

    static status_t getMinVolumeIndexForAttributes(const audio_attributes_t &attr, int &index);

    static product_strategy_t getStrategyForStream(audio_stream_type_t stream);
    static status_t getDevicesForAttributes(const audio_attributes_t &aa,
                                            AudioDeviceTypeAddrVector *devices,
                                            bool forVolume);

    static audio_io_handle_t getOutputForEffect(const effect_descriptor_t *desc);
    static status_t registerEffect(const effect_descriptor_t *desc,
                                    audio_io_handle_t io,
                                    product_strategy_t strategy,
                                    audio_session_t session,
                                    int id);
    static status_t unregisterEffect(int id);
    static status_t setEffectEnabled(int id, bool enabled);
    static status_t moveEffectsToIo(const std::vector<int>& ids, audio_io_handle_t io);

    // clear stream to output mapping cache (gStreamOutputMap)
    // and output configuration cache (gOutputs)
    static void clearAudioConfigCache();

    static const sp<media::IAudioPolicyService> get_audio_policy_service();
    static void clearAudioPolicyService();

    // helpers for android.media.AudioManager.getProperty(), see description there for meaning
    static uint32_t getPrimaryOutputSamplingRate();
    static size_t getPrimaryOutputFrameCount();

    static status_t setLowRamDevice(bool isLowRamDevice, int64_t totalMemory);

    static status_t setSupportedSystemUsages(const std::vector<audio_usage_t>& systemUsages);

    static status_t setAllowedCapturePolicy(uid_t uid, audio_flags_mask_t capturePolicy);

    // Indicate if hw offload is possible for given format, stream type, sample rate,
    // bit rate, duration, video and streaming or offload property is enabled and when possible
    // if gapless transitions are supported.
    static audio_offload_mode_t getOffloadSupport(const audio_offload_info_t& info);

    // check presence of audio flinger service.
    // returns NO_ERROR if binding to service succeeds, DEAD_OBJECT otherwise
    static status_t checkAudioFlinger();

    /* List available audio ports and their attributes */
    static status_t listAudioPorts(audio_port_role_t role,
                                   audio_port_type_t type,
                                   unsigned int *num_ports,
                                   struct audio_port_v7 *ports,
                                   unsigned int *generation);

    static status_t listDeclaredDevicePorts(media::AudioPortRole role,
                                            std::vector<media::AudioPortFw>* result);

    /* Get attributes for a given audio port. On input, the port
     * only needs the 'id' field to be filled in. */
    static status_t getAudioPort(struct audio_port_v7 *port);

    /* Create an audio patch between several source and sink ports */
    static status_t createAudioPatch(const struct audio_patch *patch,
                                       audio_patch_handle_t *handle);

    /* Release an audio patch */
    static status_t releaseAudioPatch(audio_patch_handle_t handle);

    /* List existing audio patches */
    static status_t listAudioPatches(unsigned int *num_patches,
                                      struct audio_patch *patches,
                                      unsigned int *generation);
    /* Set audio port configuration */
    static status_t setAudioPortConfig(const struct audio_port_config *config);


    static status_t acquireSoundTriggerSession(audio_session_t *session,
                                           audio_io_handle_t *ioHandle,
                                           audio_devices_t *device);
    static status_t releaseSoundTriggerSession(audio_session_t session);

    static audio_mode_t getPhoneState();

    static status_t registerPolicyMixes(const Vector<AudioMix>& mixes, bool registration);

    static status_t updatePolicyMixes(
        const std::vector<
                std::pair<AudioMix, std::vector<AudioMixMatchCriterion>>>& mixesWithUpdates);

    static status_t setUidDeviceAffinities(uid_t uid, const AudioDeviceTypeAddrVector& devices);

    static status_t removeUidDeviceAffinities(uid_t uid);

    static status_t setUserIdDeviceAffinities(int userId, const AudioDeviceTypeAddrVector& devices);

    static status_t removeUserIdDeviceAffinities(int userId);

    static status_t startAudioSource(const struct audio_port_config *source,
                                     const audio_attributes_t *attributes,
                                     audio_port_handle_t *portId);
    static status_t stopAudioSource(audio_port_handle_t portId);

    static status_t setMasterMono(bool mono);
    static status_t getMasterMono(bool *mono);

    static status_t setMasterBalance(float balance);
    static status_t getMasterBalance(float *balance);

    static float    getStreamVolumeDB(
            audio_stream_type_t stream, int index, audio_devices_t device);

    static status_t getMicrophones(std::vector<media::MicrophoneInfoFw> *microphones);

    static status_t getHwOffloadFormatsSupportedForBluetoothMedia(
                                    audio_devices_t device, std::vector<audio_format_t> *formats);

    // numSurroundFormats holds the maximum number of formats and bool value allowed in the array.
    // When numSurroundFormats is 0, surroundFormats and surroundFormatsEnabled will not be
    // populated. The actual number of surround formats should be returned at numSurroundFormats.
    static status_t getSurroundFormats(unsigned int *numSurroundFormats,
                                       audio_format_t *surroundFormats,
                                       bool *surroundFormatsEnabled);
    static status_t getReportedSurroundFormats(unsigned int *numSurroundFormats,
                                               audio_format_t *surroundFormats);
    static status_t setSurroundFormatEnabled(audio_format_t audioFormat, bool enabled);

    static status_t setAssistantServicesUids(const std::vector<uid_t>& uids);
    static status_t setActiveAssistantServicesUids(const std::vector<uid_t>& activeUids);

    static status_t setA11yServicesUids(const std::vector<uid_t>& uids);
    static status_t setCurrentImeUid(uid_t uid);

    static bool     isHapticPlaybackSupported();

    static bool     isUltrasoundSupported();

    static status_t listAudioProductStrategies(AudioProductStrategyVector &strategies);
    static status_t getProductStrategyFromAudioAttributes(
            const audio_attributes_t &aa, product_strategy_t &productStrategy,
            bool fallbackOnDefault = true);

    static audio_attributes_t streamTypeToAttributes(audio_stream_type_t stream);
    static audio_stream_type_t attributesToStreamType(const audio_attributes_t &attr);

    static status_t listAudioVolumeGroups(AudioVolumeGroupVector &groups);

    static status_t getVolumeGroupFromAudioAttributes(
            const audio_attributes_t &aa, volume_group_t &volumeGroup,
            bool fallbackOnDefault = true);

    static status_t setRttEnabled(bool enabled);

    static bool     isCallScreenModeSupported();

     /**
     * Send audio HAL server process pids to native audioserver process for use
     * when generating audio HAL servers tombstones
     */
    static status_t setAudioHalPids(const std::vector<pid_t>& pids);

    static status_t setDevicesRoleForStrategy(product_strategy_t strategy,
            device_role_t role, const AudioDeviceTypeAddrVector &devices);

    static status_t removeDevicesRoleForStrategy(product_strategy_t strategy,
            device_role_t role, const AudioDeviceTypeAddrVector &devices);

    static status_t clearDevicesRoleForStrategy(product_strategy_t strategy,
            device_role_t role);

    static status_t getDevicesForRoleAndStrategy(product_strategy_t strategy,
            device_role_t role, AudioDeviceTypeAddrVector &devices);

    static status_t setDevicesRoleForCapturePreset(audio_source_t audioSource,
            device_role_t role, const AudioDeviceTypeAddrVector &devices);

    static status_t addDevicesRoleForCapturePreset(audio_source_t audioSource,
            device_role_t role, const AudioDeviceTypeAddrVector &devices);

    static status_t removeDevicesRoleForCapturePreset(
            audio_source_t audioSource, device_role_t role,
            const AudioDeviceTypeAddrVector& devices);

    static status_t clearDevicesRoleForCapturePreset(
            audio_source_t audioSource, device_role_t role);

    static status_t getDevicesForRoleAndCapturePreset(audio_source_t audioSource,
            device_role_t role, AudioDeviceTypeAddrVector &devices);

    static status_t getDeviceForStrategy(product_strategy_t strategy,
            AudioDeviceTypeAddr &device);


    /**
     * If a spatializer stage effect is present on the platform, this will return an
     * ISpatializer interface to control this feature.
     * If no spatializer stage is present, a null interface is returned.
     * The INativeSpatializerCallback passed must not be null.
     * Only one ISpatializer interface can exist at a given time. The native audio policy
     * service will reject the request if an interface was already acquired and previous owner
     * did not die or call ISpatializer.release().
     * @param callback in: the callback to receive state updates if the ISpatializer
     *        interface is acquired.
     * @param spatializer out: the ISpatializer interface made available to control the
     *        platform spatializer
     * @return NO_ERROR in case of success, DEAD_OBJECT, NO_INIT, PERMISSION_DENIED, BAD_VALUE
     *         in case of error.
     */
    static status_t getSpatializer(const sp<media::INativeSpatializerCallback>& callback,
                                        sp<media::ISpatializer>* spatializer);

    /**
     * Queries if some kind of spatialization will be performed if the audio playback context
     * described by the provided arguments is present.
     * The context is made of:
     * - The audio attributes describing the playback use case.
     * - The audio configuration describing the audio format, channels, sampling rate ...
     * - The devices describing the sink audio device selected for playback.
     * All arguments are optional and only the specified arguments are used to match against
     * supported criteria. For instance, supplying no argument will tell if spatialization is
     * supported or not in general.
     * @param attr audio attributes describing the playback use case
     * @param config audio configuration describing the audio format, channels, sampling rate...
     * @param devices the sink audio device selected for playback
     * @param canBeSpatialized out: true if spatialization is enabled for this context,
     *        false otherwise
     * @return NO_ERROR in case of success, DEAD_OBJECT, NO_INIT, BAD_VALUE
     *         in case of error.
     */
    static status_t canBeSpatialized(const audio_attributes_t *attr,
                                     const audio_config_t *config,
                                     const AudioDeviceTypeAddrVector &devices,
                                     bool *canBeSpatialized);

    /**
     * Registers the sound dose callback with the audio server and returns the ISoundDose
     * interface.
     *
     * \param callback to send messages to the audio server
     * \param soundDose binder to send messages to the AudioService
     **/
    static status_t getSoundDoseInterface(const sp<media::ISoundDoseCallback>& callback,
                                          sp<media::ISoundDose>* soundDose);

    /**
     * Query how the direct playback is currently supported on the device.
     * @param attr audio attributes describing the playback use case
     * @param config audio configuration for the playback
     * @param directMode out: a set of flags describing how the direct playback is currently
     *        supported on the device
     * @return NO_ERROR in case of success, DEAD_OBJECT, NO_INIT, BAD_VALUE, PERMISSION_DENIED
     *         in case of error.
     */
    static status_t getDirectPlaybackSupport(const audio_attributes_t *attr,
                                             const audio_config_t *config,
                                             audio_direct_mode_t *directMode);


    /**
     * Query which direct audio profiles are available for the specified audio attributes.
     * @param attr audio attributes describing the playback use case
     * @param audioProfiles out: a vector of audio profiles
     * @return NO_ERROR in case of success, DEAD_OBJECT, NO_INIT, BAD_VALUE, PERMISSION_DENIED
     *         in case of error.
     */
    static status_t getDirectProfilesForAttributes(const audio_attributes_t* attr,
                                            std::vector<audio_profile>* audioProfiles);

    static status_t setRequestedLatencyMode(
            audio_io_handle_t output, audio_latency_mode_t mode);

    static status_t getSupportedLatencyModes(audio_io_handle_t output,
            std::vector<audio_latency_mode_t>* modes);

    static status_t setBluetoothVariableLatencyEnabled(bool enabled);

    static status_t isBluetoothVariableLatencyEnabled(bool *enabled);

    static status_t supportsBluetoothVariableLatency(bool *support);

    static status_t getSupportedMixerAttributes(audio_port_handle_t portId,
                                                std::vector<audio_mixer_attributes_t> *mixerAttrs);
    static status_t setPreferredMixerAttributes(const audio_attributes_t *attr,
                                                audio_port_handle_t portId,
                                                uid_t uid,
                                                const audio_mixer_attributes_t *mixerAttr);
    static status_t getPreferredMixerAttributes(const audio_attributes_t* attr,
                                                audio_port_handle_t portId,
                                                std::optional<audio_mixer_attributes_t>* mixerAttr);
    static status_t clearPreferredMixerAttributes(const audio_attributes_t* attr,
                                                  audio_port_handle_t portId,
                                                  uid_t uid);

    static status_t getAudioPolicyConfig(media::AudioPolicyConfig *config);

    // A listener for capture state changes.
    class CaptureStateListener : public virtual RefBase {
    public:
        // Called whenever capture state changes.
        virtual void onStateChanged(bool active) = 0;
        // Called whenever the service dies (and hence our listener is no longer
        // registered).
        virtual void onServiceDied() = 0;

        virtual ~CaptureStateListener() = default;
    };

    // Registers a listener for sound trigger capture state changes.
    // There may only be one such listener registered at any point.
    // The listener onStateChanged() method will be invoked synchronously from
    // this call with the initial value.
    // The listener onServiceDied() method will be invoked synchronously from
    // this call if initial attempt to register failed.
    // If the audio policy service cannot be reached, this method will return
    // PERMISSION_DENIED and will not invoke the callback, otherwise, it will
    // return NO_ERROR.
    static status_t registerSoundTriggerCaptureStateListener(
            const sp<CaptureStateListener>& listener);

    // ----------------------------------------------------------------------------

    class AudioVolumeGroupCallback : public virtual RefBase
    {
    public:

        AudioVolumeGroupCallback() {}
        virtual ~AudioVolumeGroupCallback() {}

        virtual void onAudioVolumeGroupChanged(volume_group_t group, int flags) = 0;
        virtual void onServiceDied() = 0;

    };

    static status_t addAudioVolumeGroupCallback(const sp<AudioVolumeGroupCallback>& callback);
    static status_t removeAudioVolumeGroupCallback(const sp<AudioVolumeGroupCallback>& callback);

    class AudioPortCallback : public virtual RefBase
    {
    public:

                AudioPortCallback() {}
        virtual ~AudioPortCallback() {}

        virtual void onAudioPortListUpdate() = 0;
        virtual void onAudioPatchListUpdate() = 0;
        virtual void onServiceDied() = 0;

    };

    static status_t addAudioPortCallback(const sp<AudioPortCallback>& callback);
    static status_t removeAudioPortCallback(const sp<AudioPortCallback>& callback);

    class AudioDeviceCallback : public virtual RefBase
    {
    public:

                AudioDeviceCallback() {}
        virtual ~AudioDeviceCallback() {}

        virtual void onAudioDeviceUpdate(audio_io_handle_t audioIo,
                                         audio_port_handle_t deviceId) = 0;
    };

    static status_t addAudioDeviceCallback(const wp<AudioDeviceCallback>& callback,
                                           audio_io_handle_t audioIo,
                                           audio_port_handle_t portId);
    static status_t removeAudioDeviceCallback(const wp<AudioDeviceCallback>& callback,
                                              audio_io_handle_t audioIo,
                                              audio_port_handle_t portId);

    class SupportedLatencyModesCallback : public virtual RefBase
    {
    public:

                SupportedLatencyModesCallback() = default;
        virtual ~SupportedLatencyModesCallback() = default;

        virtual void onSupportedLatencyModesChanged(
                audio_io_handle_t output, const std::vector<audio_latency_mode_t>& modes) = 0;
    };

    static status_t addSupportedLatencyModesCallback(
            const sp<SupportedLatencyModesCallback>& callback);
    static status_t removeSupportedLatencyModesCallback(
            const sp<SupportedLatencyModesCallback>& callback);

    static audio_port_handle_t getDeviceIdForIo(audio_io_handle_t audioIo);

    static status_t setVibratorInfos(const std::vector<media::AudioVibratorInfo>& vibratorInfos);

    static status_t getMmapPolicyInfo(
            media::audio::common::AudioMMapPolicyType policyType,
            std::vector<media::audio::common::AudioMMapPolicyInfo> *policyInfos);

    static int32_t getAAudioMixerBurstCount();

    static int32_t getAAudioHardwareBurstMinUsec();

    static status_t setAppVolume(const String8& packageName, const float value);
    static status_t setAppMute(const String8& packageName, const bool value);
    static status_t listAppVolumes(std::vector<media::AppVolume> *vols);

private:

    class AudioFlingerClient: public IBinder::DeathRecipient, public media::BnAudioFlingerClient
    {
    public:
        AudioFlingerClient() :
            mInBuffSize(0), mInSamplingRate(0),
            mInFormat(AUDIO_FORMAT_DEFAULT), mInChannelMask(AUDIO_CHANNEL_NONE) {
        }

        void clearIoCache();
        status_t getInputBufferSize(uint32_t sampleRate, audio_format_t format,
                                    audio_channel_mask_t channelMask, size_t* buffSize);
        sp<AudioIoDescriptor> getIoDescriptor(audio_io_handle_t ioHandle);

        // DeathRecipient
        virtual void binderDied(const wp<IBinder>& who);

        // IAudioFlingerClient

        // indicate a change in the configuration of an output or input: keeps the cached
        // values for output/input parameters up-to-date in client process
        binder::Status ioConfigChanged(
                media::AudioIoConfigEvent event,
                const media::AudioIoDescriptor& ioDesc) override;

        binder::Status onSupportedLatencyModesChanged(
                int output,
                const std::vector<media::audio::common::AudioLatencyMode>& latencyModes) override;

        status_t addAudioDeviceCallback(const wp<AudioDeviceCallback>& callback,
                                               audio_io_handle_t audioIo,
                                               audio_port_handle_t portId);
        status_t removeAudioDeviceCallback(const wp<AudioDeviceCallback>& callback,
                                           audio_io_handle_t audioIo,
                                           audio_port_handle_t portId);

        status_t addSupportedLatencyModesCallback(
                        const sp<SupportedLatencyModesCallback>& callback);
        status_t removeSupportedLatencyModesCallback(
                        const sp<SupportedLatencyModesCallback>& callback);

        audio_port_handle_t getDeviceIdForIo(audio_io_handle_t audioIo);

    private:
        Mutex                               mLock;
        DefaultKeyedVector<audio_io_handle_t, sp<AudioIoDescriptor> >   mIoDescriptors;

        std::map<audio_io_handle_t, std::map<audio_port_handle_t, wp<AudioDeviceCallback>>>
                mAudioDeviceCallbacks;

        std::vector<wp<SupportedLatencyModesCallback>>
                mSupportedLatencyModesCallbacks GUARDED_BY(mLock);

        // cached values for recording getInputBufferSize() queries
        size_t                              mInBuffSize;    // zero indicates cache is invalid
        uint32_t                            mInSamplingRate;
        audio_format_t                      mInFormat;
        audio_channel_mask_t                mInChannelMask;
        sp<AudioIoDescriptor> getIoDescriptor_l(audio_io_handle_t ioHandle);
    };

    class AudioPolicyServiceClient: public IBinder::DeathRecipient,
                                    public media::BnAudioPolicyServiceClient
    {
    public:
        AudioPolicyServiceClient() {
        }

        int addAudioPortCallback(const sp<AudioPortCallback>& callback);
        int removeAudioPortCallback(const sp<AudioPortCallback>& callback);
        bool isAudioPortCbEnabled() const { return (mAudioPortCallbacks.size() != 0); }

        int addAudioVolumeGroupCallback(const sp<AudioVolumeGroupCallback>& callback);
        int removeAudioVolumeGroupCallback(const sp<AudioVolumeGroupCallback>& callback);
        bool isAudioVolumeGroupCbEnabled() const { return (mAudioVolumeGroupCallback.size() != 0); }

        // DeathRecipient
        virtual void binderDied(const wp<IBinder>& who);

        // IAudioPolicyServiceClient
        binder::Status onAudioVolumeGroupChanged(int32_t group, int32_t flags) override;
        binder::Status onAudioPortListUpdate() override;
        binder::Status onAudioPatchListUpdate() override;
        binder::Status onDynamicPolicyMixStateUpdate(const std::string& regId,
                                                     int32_t state) override;
        binder::Status onRecordingConfigurationUpdate(
                int32_t event,
                const media::RecordClientInfo& clientInfo,
                const media::audio::common::AudioConfigBase& clientConfig,
                const std::vector<media::EffectDescriptor>& clientEffects,
                const media::audio::common::AudioConfigBase& deviceConfig,
                const std::vector<media::EffectDescriptor>& effects,
                int32_t patchHandle,
                media::audio::common::AudioSource source) override;
        binder::Status onRoutingUpdated();
        binder::Status onVolumeRangeInitRequest();

    private:
        Mutex                               mLock;
        Vector <sp <AudioPortCallback> >    mAudioPortCallbacks;
        Vector <sp <AudioVolumeGroupCallback> > mAudioVolumeGroupCallback;
    };

    static audio_io_handle_t getOutput(audio_stream_type_t stream);
    static const sp<AudioFlingerClient> getAudioFlingerClient();
    static sp<AudioIoDescriptor> getIoDescriptor(audio_io_handle_t ioHandle);
    static const sp<IAudioFlinger> getAudioFlingerImpl(bool canStartThreadPool);

    // Invokes all registered error callbacks with the given error code.
    static void reportError(status_t err);

    static sp<AudioFlingerClient> gAudioFlingerClient;
    static sp<AudioPolicyServiceClient> gAudioPolicyServiceClient;
    friend class AudioFlingerClient;
    friend class AudioPolicyServiceClient;

    static Mutex gLock;      // protects gAudioFlinger
    static Mutex gLockErrorCallbacks;      // protects gAudioErrorCallbacks
    static Mutex gLockAPS;   // protects gAudioPolicyService and gAudioPolicyServiceClient
    static sp<IAudioFlinger> gAudioFlinger;
    static std::set<audio_error_callback> gAudioErrorCallbacks;
    static dynamic_policy_callback gDynPolicyCallback;
    static record_config_callback gRecordConfigCallback;
    static routing_callback gRoutingCallback;
    static vol_range_init_req_callback gVolRangeInitReqCallback;

    static size_t gInBuffSize;
    // previous parameters for recording buffer size queries
    static uint32_t gPrevInSamplingRate;
    static audio_format_t gPrevInFormat;
    static audio_channel_mask_t gPrevInChannelMask;

    static sp<media::IAudioPolicyService> gAudioPolicyService;
};

};  // namespace android

#endif  /*ANDROID_AUDIOSYSTEM_H_*/
