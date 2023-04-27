/*
 * Copyright (C) 2009 The Android Open Source Project
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

#ifndef ANDROID_AUDIOPOLICY_INTERFACE_H
#define ANDROID_AUDIOPOLICY_INTERFACE_H

#include <android/media/DeviceConnectedState.h>
#include <media/AudioCommonTypes.h>
#include <media/AudioContainers.h>
#include <media/AudioDeviceTypeAddr.h>
#include <media/AudioSystem.h>
#include <media/AudioPolicy.h>
#include <media/DeviceDescriptorBase.h>
#include <android/content/AttributionSourceState.h>
#include <utils/String8.h>

namespace android {

using content::AttributionSourceState;

// ----------------------------------------------------------------------------

// The AudioPolicyInterface and AudioPolicyClientInterface classes define the communication
// interfaces between the platform specific audio policy manager and Android generic audio policy
// manager.
// The platform specific audio policy manager must implement methods of the AudioPolicyInterface
// class.
// This implementation makes use of the AudioPolicyClientInterface to control the activity and
// configuration of audio input and output streams.
//
// The platform specific audio policy manager is in charge of the audio routing and volume control
// policies for a given platform.
// The main roles of this module are:
//   - keep track of current system state (removable device connections, phone state,
//   user requests...).
//   System state changes and user actions are notified to audio policy manager with methods of the
//   AudioPolicyInterface.
//   - process getOutput() queries received when AudioTrack objects are created: Those queries
//   return a handler on an output that has been selected, configured and opened by the audio
//   policy manager and that must be used by the AudioTrack when registering to the AudioFlinger
//   with the createTrack() method.
//   When the AudioTrack object is released, a putOutput() query is received and the audio policy
//   manager can decide to close or reconfigure the output depending on other streams using this
//   output and current system state.
//   - similarly process getInput() and putInput() queries received from AudioRecord objects and
//   configure audio inputs.
//   - process volume control requests: the stream volume is converted from an index value
//   (received from UI) to a float value applicable to each output as a function of platform
//   specificsettings and current output route (destination device). It also make sure that streams
//   are not muted if not allowed (e.g. camera shutter sound in some countries).
//
// The platform specific audio policy manager is provided as a shared library by platform vendors
// (as for libaudio.so) and is linked with libaudioflinger.so
//
// NOTE: by convention, the implementation of the AudioPolicyInterface in AudioPolicyManager does
// not have to perform any nullptr check on input arguments: The caller of this API is
// AudioPolicyService running in the same process and in charge of validating arguments received
// from incoming binder calls before calling AudioPolicyManager.

//    Audio Policy Manager Interface
class AudioPolicyInterface
{

public:
    typedef enum {
        API_INPUT_INVALID = -1,
        API_INPUT_LEGACY  = 0,// e.g. audio recording from a microphone
        API_INPUT_MIX_CAPTURE,// used for "remote submix" legacy mode (no DAP),
                              // capture of the media to play it remotely
        API_INPUT_MIX_EXT_POLICY_REROUTE,// used for platform audio rerouting, where mixes are
                                         // handled by external and dynamically installed
                                         // policies which reroute audio mixes
        API_INPUT_MIX_PUBLIC_CAPTURE_PLAYBACK,  // used for playback capture with a MediaProjection
        API_INPUT_TELEPHONY_RX, // used for capture from telephony RX path
    } input_type_t;

    typedef enum {
        API_OUTPUT_INVALID = -1,
        API_OUTPUT_LEGACY  = 0,// e.g. audio playing to speaker
        API_OUT_MIX_PLAYBACK,  // used for "remote submix" playback of audio from remote source
                               // to local capture
        API_OUTPUT_TELEPHONY_TX, // used for playback to telephony TX path
    } output_type_t;

public:
    virtual ~AudioPolicyInterface() {}
    //
    // configuration functions
    //

    // Informs APM that new HAL modules are available. This typically happens
    // due to registration of an audio HAL service.
    virtual void onNewAudioModulesAvailable() = 0;

    // indicate a change in device connection status
    virtual status_t setDeviceConnectionState(audio_policy_dev_state_t state,
                                              const android::media::audio::common::AudioPort& port,
                                              audio_format_t encodedFormat) = 0;
    // retrieve a device connection status
    virtual audio_policy_dev_state_t getDeviceConnectionState(audio_devices_t device,
                                                              const char *device_address) = 0;
    // indicate a change in device configuration
    virtual status_t handleDeviceConfigChange(audio_devices_t device,
                                              const char *device_address,
                                              const char *device_name,
                                              audio_format_t encodedFormat) = 0;
    // indicate a change in phone state. Valid phones states are defined by audio_mode_t
    virtual void setPhoneState(audio_mode_t state) = 0;
    // force using a specific device category for the specified usage
    virtual void setForceUse(audio_policy_force_use_t usage, audio_policy_forced_cfg_t config) = 0;
    // retrieve current device category forced for a given usage
    virtual audio_policy_forced_cfg_t getForceUse(audio_policy_force_use_t usage) = 0;
    // set a system property (e.g. camera sound always audible)
    virtual void setSystemProperty(const char* property, const char* value) = 0;
    // check proper initialization
    virtual status_t initCheck() = 0;

    //
    // Audio routing query functions
    //

    // request an output appropriate for playback of the supplied stream type and parameters
    virtual audio_io_handle_t getOutput(audio_stream_type_t stream) = 0;
    virtual status_t getOutputForAttr(const audio_attributes_t *attr,
                                        audio_io_handle_t *output,
                                        audio_session_t session,
                                        audio_stream_type_t *stream,
                                        const AttributionSourceState& attributionSouce,
                                        const audio_config_t *config,
                                        audio_output_flags_t *flags,
                                        audio_port_handle_t *selectedDeviceId,
                                        audio_port_handle_t *portId,
                                        std::vector<audio_io_handle_t> *secondaryOutputs,
                                        output_type_t *outputType,
                                        bool *isSpatialized) = 0;
    // indicates to the audio policy manager that the output starts being used by corresponding
    // stream.
    virtual status_t startOutput(audio_port_handle_t portId) = 0;
    // indicates to the audio policy manager that the output stops being used by corresponding
    // stream.
    virtual status_t stopOutput(audio_port_handle_t portId) = 0;
    // releases the output, return true if the output descriptor is reopened.
    virtual bool releaseOutput(audio_port_handle_t portId) = 0;

    // request an input appropriate for record from the supplied device with supplied parameters.
    virtual status_t getInputForAttr(const audio_attributes_t *attr,
                                     audio_io_handle_t *input,
                                     audio_unique_id_t riid,
                                     audio_session_t session,
                                     const AttributionSourceState& attributionSouce,
                                     const audio_config_base_t *config,
                                     audio_input_flags_t flags,
                                     audio_port_handle_t *selectedDeviceId,
                                     input_type_t *inputType,
                                     audio_port_handle_t *portId) = 0;
    // indicates to the audio policy manager that the input starts being used.
    virtual status_t startInput(audio_port_handle_t portId) = 0;
    // indicates to the audio policy manager that the input stops being used.
    virtual status_t stopInput(audio_port_handle_t portId) = 0;
    // releases the input.
    virtual void releaseInput(audio_port_handle_t portId) = 0;

    //
    // volume control functions
    //

    // initialises stream volume conversion parameters by specifying volume index range.
    virtual void initStreamVolume(audio_stream_type_t stream,
                                      int indexMin,
                                      int indexMax) = 0;

    // sets the new stream volume at a level corresponding to the supplied index for the
    // supplied device. By convention, specifying AUDIO_DEVICE_OUT_DEFAULT_FOR_VOLUME means
    // setting volume for all devices
    virtual status_t setStreamVolumeIndex(audio_stream_type_t stream,
                                          int index,
                                          audio_devices_t device) = 0;

    // retrieve current volume index for the specified stream and the
    // specified device. By convention, specifying AUDIO_DEVICE_OUT_DEFAULT_FOR_VOLUME means
    // querying the volume of the active device.
    virtual status_t getStreamVolumeIndex(audio_stream_type_t stream,
                                          int *index,
                                          audio_devices_t device) = 0;

    virtual status_t setVolumeIndexForAttributes(const audio_attributes_t &attr,
                                                 int index,
                                                 audio_devices_t device) = 0;
    virtual status_t getVolumeIndexForAttributes(const audio_attributes_t &attr,
                                                 int &index,
                                                 audio_devices_t device) = 0;

    virtual status_t getMaxVolumeIndexForAttributes(const audio_attributes_t &attr,
                                                    int &index) = 0;

    virtual status_t getMinVolumeIndexForAttributes(const audio_attributes_t &attr,
                                                    int &index) = 0;

    // return the strategy corresponding to a given stream type
    virtual product_strategy_t getStrategyForStream(audio_stream_type_t stream) = 0;

    // retrieves the list of enabled output devices for the given audio attributes
    virtual status_t getDevicesForAttributes(const audio_attributes_t &attr,
                                             AudioDeviceTypeAddrVector *devices,
                                             bool forVolume) = 0;

    // Audio effect management
    virtual audio_io_handle_t getOutputForEffect(const effect_descriptor_t *desc) = 0;
    virtual status_t registerEffect(const effect_descriptor_t *desc,
                                    audio_io_handle_t io,
                                    product_strategy_t strategy,
                                    int session,
                                    int id) = 0;
    virtual status_t unregisterEffect(int id) = 0;
    virtual status_t setEffectEnabled(int id, bool enabled) = 0;
    virtual status_t moveEffectsToIo(const std::vector<int>& ids, audio_io_handle_t io) = 0;

    virtual bool isStreamActive(audio_stream_type_t stream, uint32_t inPastMs = 0) const = 0;
    virtual bool isStreamActiveRemotely(audio_stream_type_t stream,
                                        uint32_t inPastMs = 0) const = 0;
    virtual bool isSourceActive(audio_source_t source) const = 0;

    //dump state
    virtual status_t    dump(int fd) = 0;

    virtual status_t setAllowedCapturePolicy(uid_t uid, audio_flags_mask_t flags) = 0;
    virtual audio_offload_mode_t getOffloadSupport(const audio_offload_info_t& offloadInfo) = 0;
    virtual bool isDirectOutputSupported(const audio_config_base_t& config,
                                         const audio_attributes_t& attributes) = 0;

    virtual status_t listAudioPorts(audio_port_role_t role,
                                    audio_port_type_t type,
                                    unsigned int *num_ports,
                                    struct audio_port_v7 *ports,
                                    unsigned int *generation) = 0;
    virtual status_t listDeclaredDevicePorts(media::AudioPortRole role,
                                             std::vector<media::AudioPortFw>* result) = 0;
    virtual status_t getAudioPort(struct audio_port_v7 *port) = 0;
    virtual status_t createAudioPatch(const struct audio_patch *patch,
                                       audio_patch_handle_t *handle,
                                       uid_t uid) = 0;
    virtual status_t releaseAudioPatch(audio_patch_handle_t handle,
                                          uid_t uid) = 0;
    virtual status_t listAudioPatches(unsigned int *num_patches,
                                      struct audio_patch *patches,
                                      unsigned int *generation) = 0;
    virtual status_t setAudioPortConfig(const struct audio_port_config *config) = 0;
    virtual void releaseResourcesForUid(uid_t uid) = 0;

    virtual status_t acquireSoundTriggerSession(audio_session_t *session,
                                           audio_io_handle_t *ioHandle,
                                           audio_devices_t *device) = 0;

    virtual status_t releaseSoundTriggerSession(audio_session_t session) = 0;

    virtual status_t registerPolicyMixes(const Vector<AudioMix>& mixes) = 0;
    virtual status_t unregisterPolicyMixes(Vector<AudioMix> mixes) = 0;

    virtual status_t setUidDeviceAffinities(uid_t uid, const AudioDeviceTypeAddrVector& devices)
            = 0;
    virtual status_t removeUidDeviceAffinities(uid_t uid) = 0;

    virtual status_t setUserIdDeviceAffinities(int userId,
            const AudioDeviceTypeAddrVector& devices) = 0;
    virtual status_t removeUserIdDeviceAffinities(int userId) = 0;

    virtual status_t startAudioSource(const struct audio_port_config *source,
                                      const audio_attributes_t *attributes,
                                      audio_port_handle_t *portId,
                                      uid_t uid) = 0;
    virtual status_t stopAudioSource(audio_port_handle_t portId) = 0;

    virtual status_t setMasterMono(bool mono) = 0;
    virtual status_t getMasterMono(bool *mono) = 0;

    virtual float    getStreamVolumeDB(
                audio_stream_type_t stream, int index, audio_devices_t device) = 0;

    virtual status_t getSurroundFormats(unsigned int *numSurroundFormats,
                                        audio_format_t *surroundFormats,
                                        bool *surroundFormatsEnabled) = 0;

    virtual status_t getReportedSurroundFormats(unsigned int *numSurroundFormats,
                                                audio_format_t *surroundFormats) = 0;

    virtual status_t setSurroundFormatEnabled(audio_format_t audioFormat, bool enabled) = 0;

    virtual bool     isHapticPlaybackSupported() = 0;

    virtual bool     isUltrasoundSupported() = 0;

    virtual status_t getHwOffloadFormatsSupportedForBluetoothMedia(
                audio_devices_t device, std::vector<audio_format_t> *formats) = 0;

    virtual void     setAppState(audio_port_handle_t portId, app_state_t state) = 0;

    virtual status_t listAudioProductStrategies(AudioProductStrategyVector &strategies) = 0;

    virtual status_t getProductStrategyFromAudioAttributes(
            const AudioAttributes &aa, product_strategy_t &productStrategy,
            bool fallbackOnDefault) = 0;

    virtual status_t listAudioVolumeGroups(AudioVolumeGroupVector &groups) = 0;

    virtual status_t getVolumeGroupFromAudioAttributes(
            const AudioAttributes &aa, volume_group_t &volumeGroup, bool fallbackOnDefault) = 0;

    virtual bool     isCallScreenModeSupported() = 0;

    virtual status_t setDevicesRoleForStrategy(product_strategy_t strategy,
                                               device_role_t role,
                                               const AudioDeviceTypeAddrVector &devices) = 0;

    virtual status_t removeDevicesRoleForStrategy(product_strategy_t strategy,
                                                  device_role_t role) = 0;


    virtual status_t getDevicesForRoleAndStrategy(product_strategy_t strategy,
                                                  device_role_t role,
                                                  AudioDeviceTypeAddrVector &devices) = 0;

    virtual status_t setDevicesRoleForCapturePreset(audio_source_t audioSource,
                                                    device_role_t role,
                                                    const AudioDeviceTypeAddrVector &devices) = 0;

    virtual status_t addDevicesRoleForCapturePreset(audio_source_t audioSource,
                                                    device_role_t role,
                                                    const AudioDeviceTypeAddrVector &devices) = 0;

    virtual status_t removeDevicesRoleForCapturePreset(
            audio_source_t audioSource, device_role_t role,
            const AudioDeviceTypeAddrVector& devices) = 0;

    virtual status_t clearDevicesRoleForCapturePreset(audio_source_t audioSource,
                                                      device_role_t role) = 0;

    virtual status_t getDevicesForRoleAndCapturePreset(audio_source_t audioSource,
                                                       device_role_t role,
                                                       AudioDeviceTypeAddrVector &devices) = 0;

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
     * @return true if spatialization is enabled for this context,
     *        false otherwise
     */
     virtual bool canBeSpatialized(const audio_attributes_t *attr,
                                  const audio_config_t *config,
                                  const AudioDeviceTypeAddrVector &devices) const = 0;

    /**
     * Opens a specialized spatializer output if supported by the platform.
     * If several spatializer output profiles exist, the one supporting the sink device
     * corresponding to the provided audio attributes will be selected.
     * Only one spatializer output stream can be opened at a time and an error is returned
     * if one already exists.
     * @param config audio format, channel mask and sampling rate to be used as the mixer
     *        configuration for the spatializer mixer created.
     * @param attr audio attributes describing the playback use case that will drive the
     *        sink device selection
     * @param output the IO handle of the output opened
     * @return NO_ERROR if an output was opened, INVALID_OPERATION or BAD_VALUE otherwise
     */
    virtual status_t getSpatializerOutput(const audio_config_base_t *config,
                                            const audio_attributes_t *attr,
                                            audio_io_handle_t *output) = 0;

    /**
     * Closes a previously opened specialized spatializer output.
     * @param output the IO handle of the output to close.
     * @return NO_ERROR if an output was closed, INVALID_OPERATION or BAD_VALUE otherwise
     */
    virtual status_t releaseSpatializerOutput(audio_io_handle_t output) = 0;

    /**
     * Query how the direct playback is currently supported on the device.
     * @param attr audio attributes describing the playback use case
     * @param config audio configuration for the playback
     * @param directMode out: a set of flags describing how the direct playback is currently
     *        supported on the device
     * @return NO_ERROR in case of success, DEAD_OBJECT, NO_INIT, BAD_VALUE, PERMISSION_DENIED
     *         in case of error.
     */
    virtual audio_direct_mode_t getDirectPlaybackSupport(const audio_attributes_t *attr,
                                                         const audio_config_t *config) = 0;

    // retrieves the list of available direct audio profiles for the given audio attributes
    virtual status_t getDirectProfilesForAttributes(const audio_attributes_t* attr,
                                                    AudioProfileVector& audioProfiles) = 0;
};

// Audio Policy client Interface
class AudioPolicyClientInterface
{
public:
    virtual ~AudioPolicyClientInterface() {}

    //
    // Audio HW module functions
    //

    // loads a HW module.
    virtual audio_module_handle_t loadHwModule(const char *name) = 0;

    //
    // Audio output Control functions
    //

    // opens an audio output with the requested parameters. The parameter values can indicate to
    // use the default values in case the audio policy manager has no specific requirements for the
    // output being opened.
    // When the function returns, the parameter values reflect the actual values used by the audio
    // hardware output stream.
    // The audio policy manager can check if the proposed parameters are suitable or not and act
    // accordingly.
    virtual status_t openOutput(audio_module_handle_t module,
                                audio_io_handle_t *output,
                                audio_config_t *halConfig,
                                audio_config_base_t *mixerConfig,
                                const sp<DeviceDescriptorBase>& device,
                                uint32_t *latencyMs,
                                audio_output_flags_t flags) = 0;
    // creates a special output that is duplicated to the two outputs passed as arguments.
    // The duplication is performed by a special mixer thread in the AudioFlinger.
    virtual audio_io_handle_t openDuplicateOutput(audio_io_handle_t output1,
                                                  audio_io_handle_t output2) = 0;
    // closes the output stream
    virtual status_t closeOutput(audio_io_handle_t output) = 0;
    // suspends the output. When an output is suspended, the corresponding audio hardware output
    // stream is placed in standby and the AudioTracks attached to the mixer thread are still
    // processed but the output mix is discarded.
    virtual status_t suspendOutput(audio_io_handle_t output) = 0;
    // restores a suspended output.
    virtual status_t restoreOutput(audio_io_handle_t output) = 0;

    //
    // Audio input Control functions
    //

    // opens an audio input
    virtual status_t openInput(audio_module_handle_t module,
                               audio_io_handle_t *input,
                               audio_config_t *config,
                               audio_devices_t *device,
                               const String8& address,
                               audio_source_t source,
                               audio_input_flags_t flags) = 0;
    // closes an audio input
    virtual status_t closeInput(audio_io_handle_t input) = 0;
    //
    // misc control functions
    //

    // set a stream volume for a particular output. For the same user setting, a given stream type
    // can have different volumes
    // for each output (destination device) it is attached to.
    virtual status_t setStreamVolume(audio_stream_type_t stream, float volume,
                                     audio_io_handle_t output, int delayMs = 0) = 0;

    // invalidate a stream type, causing a reroute to an unspecified new output
    virtual status_t invalidateStream(audio_stream_type_t stream) = 0;

    // function enabling to send proprietary informations directly from audio policy manager to
    // audio hardware interface.
    virtual void setParameters(audio_io_handle_t ioHandle, const String8& keyValuePairs,
                               int delayMs = 0) = 0;
    // function enabling to receive proprietary informations directly from audio hardware interface
    // to audio policy manager.
    virtual String8 getParameters(audio_io_handle_t ioHandle, const String8& keys) = 0;

    // set down link audio volume.
    virtual status_t setVoiceVolume(float volume, int delayMs = 0) = 0;

    // move effect to the specified output
    virtual status_t moveEffects(audio_session_t session,
                                     audio_io_handle_t srcOutput,
                                     audio_io_handle_t dstOutput) = 0;

    virtual void setEffectSuspended(int effectId,
                                    audio_session_t sessionId,
                                    bool suspended) = 0;

    /* Create a patch between several source and sink ports */
    virtual status_t createAudioPatch(const struct audio_patch *patch,
                                       audio_patch_handle_t *handle,
                                       int delayMs) = 0;

    /* Release a patch */
    virtual status_t releaseAudioPatch(audio_patch_handle_t handle,
                                       int delayMs) = 0;

    /* Set audio port configuration */
    virtual status_t setAudioPortConfig(const struct audio_port_config *config, int delayMs) = 0;

    virtual void onAudioPortListUpdate() = 0;

    virtual void onAudioPatchListUpdate() = 0;

    virtual void onAudioVolumeGroupChanged(volume_group_t group, int flags) = 0;

    virtual audio_unique_id_t newAudioUniqueId(audio_unique_id_use_t use) = 0;

    virtual void onDynamicPolicyMixStateUpdate(String8 regId, int32_t state) = 0;

    virtual void onRecordingConfigurationUpdate(int event,
                                                const record_client_info_t *clientInfo,
                                                const audio_config_base_t *clientConfig,
                                                std::vector<effect_descriptor_t> clientEffects,
                                                const audio_config_base_t *deviceConfig,
                                                std::vector<effect_descriptor_t> effects,
                                                audio_patch_handle_t patchHandle,
                                                audio_source_t source) = 0;

    virtual void onRoutingUpdated() = 0;

    // Used to notify AudioService that an error was encountering when reading
    // the volume ranges, and that they should be re-initialized
    virtual void onVolumeRangeInitRequest() = 0;

    // Used to notify the sound trigger module that an audio capture is about to
    // take place. This should typically result in any active recognition
    // sessions to be preempted on modules that do not support sound trigger
    // recognition concurrently with audio capture.
    virtual void setSoundTriggerCaptureState(bool active) = 0;

    virtual status_t getAudioPort(struct audio_port_v7 *port) = 0;

    virtual status_t updateSecondaryOutputs(
            const TrackSecondaryOutputsMap& trackSecondaryOutputs) = 0;

    virtual status_t setDeviceConnectedState(const struct audio_port_v7 *port,
                                             media::DeviceConnectedState state) = 0;
};

    // These are the signatures of createAudioPolicyManager/destroyAudioPolicyManager
    // methods respectively, expected by AudioPolicyService, needs to be exposed by
    // libaudiopolicymanagercustom.
    using CreateAudioPolicyManagerInstance =
            AudioPolicyInterface* (*)(AudioPolicyClientInterface*);
    using DestroyAudioPolicyManagerInstance = void (*)(AudioPolicyInterface*);

} // namespace android

#endif // ANDROID_AUDIOPOLICY_INTERFACE_H
