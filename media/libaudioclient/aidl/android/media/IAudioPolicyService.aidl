/*
 * Copyright (C) 2021 The Android Open Source Project
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

package android.media;

import android.content.AttributionSourceState;

import android.media.AudioDirectMode;
import android.media.AudioMix;
import android.media.AudioMixerAttributesInternal;
import android.media.AudioOffloadMode;
import android.media.AudioPatchFw;
import android.media.AudioPolicyDeviceState;
import android.media.AudioPolicyForcedConfig;
import android.media.AudioPolicyForceUse;
import android.media.AudioPortFw;
import android.media.AudioPortConfigFw;
import android.media.AudioPortRole;
import android.media.AudioPortType;
import android.media.AudioProductStrategy;
import android.media.AudioVolumeGroup;
import android.media.DeviceRole;
import android.media.EffectDescriptor;
import android.media.GetInputForAttrResponse;
import android.media.GetOutputForAttrResponse;
import android.media.GetSpatializerResponse;
import android.media.IAudioPolicyServiceClient;
import android.media.ICaptureStateListener;
import android.media.INativeSpatializerCallback;
import android.media.SoundTriggerSession;
import android.media.audio.common.AudioAttributes;
import android.media.audio.common.AudioConfig;
import android.media.audio.common.AudioConfigBase;
import android.media.audio.common.AudioDevice;
import android.media.audio.common.AudioDeviceDescription;
import android.media.audio.common.AudioFormatDescription;
import android.media.audio.common.AudioMode;
import android.media.audio.common.AudioProfile;
import android.media.audio.common.AudioOffloadInfo;
import android.media.audio.common.AudioPort;
import android.media.audio.common.AudioSource;
import android.media.audio.common.AudioStreamType;
import android.media.audio.common.AudioUsage;
import android.media.audio.common.AudioUuid;
import android.media.audio.common.Int;

/**
 * IAudioPolicyService interface (see AudioPolicyInterface for method descriptions).
 *
 * {@hide}
 */
interface IAudioPolicyService {
    oneway void onNewAudioModulesAvailable();

    void setDeviceConnectionState(in AudioPolicyDeviceState state,
                                  in android.media.audio.common.AudioPort port,
                                  in AudioFormatDescription encodedFormat);

    AudioPolicyDeviceState getDeviceConnectionState(in AudioDevice device);

    void handleDeviceConfigChange(in AudioDevice device,
                                  @utf8InCpp String deviceName,
                                  in AudioFormatDescription encodedFormat);

    void setPhoneState(AudioMode state, int /* uid_t */ uid);

    void setForceUse(AudioPolicyForceUse usage,
                     AudioPolicyForcedConfig config);

    AudioPolicyForcedConfig getForceUse(AudioPolicyForceUse usage);

    int /* audio_io_handle_t */ getOutput(AudioStreamType stream);

    GetOutputForAttrResponse getOutputForAttr(in AudioAttributes attr,
                                              int /* audio_session_t */ session,
                                              in AttributionSourceState attributionSource,
                                              in AudioConfig config,
                                              int /* Bitmask, indexed by AudioOutputFlags */ flags,
                                              int /* audio_port_handle_t */ selectedDeviceId);

    void startOutput(int /* audio_port_handle_t */ portId);

    void stopOutput(int /* audio_port_handle_t */ portId);

    void releaseOutput(int /* audio_port_handle_t */ portId);

    GetInputForAttrResponse getInputForAttr(in AudioAttributes attr,
                                            int /* audio_io_handle_t */ input,
                                            int /* audio_unique_id_t */ riid,
                                            int /* audio_session_t */ session,
                                            in AttributionSourceState attributionSource,
                                            in AudioConfigBase config,
                                            int /* Bitmask, indexed by AudioInputFlags */ flags,
                                            int /* audio_port_handle_t */ selectedDeviceId);


    void startInput(int /* audio_port_handle_t */ portId);

    void stopInput(int /* audio_port_handle_t */ portId);

    void releaseInput(int /* audio_port_handle_t */ portId);

    void initStreamVolume(AudioStreamType stream,
                          int indexMin,
                          int indexMax);

    void setStreamVolumeIndex(AudioStreamType stream,
                              in AudioDeviceDescription device,
                              int index);

    int getStreamVolumeIndex(AudioStreamType stream,
                             in AudioDeviceDescription device);

    void setVolumeIndexForAttributes(in AudioAttributes attr,
                                     in AudioDeviceDescription device,
                                     int index);

    int getVolumeIndexForAttributes(in AudioAttributes attr,
                                    in AudioDeviceDescription device);

    int getMaxVolumeIndexForAttributes(in AudioAttributes attr);

    int getMinVolumeIndexForAttributes(in AudioAttributes attr);

    int /* product_strategy_t */ getStrategyForStream(AudioStreamType stream);

    AudioDevice[] getDevicesForAttributes(in AudioAttributes attr, boolean forVolume);

    int /* audio_io_handle_t */ getOutputForEffect(in EffectDescriptor desc);

    void registerEffect(in EffectDescriptor desc,
                        int /* audio_io_handle_t */ io,
                        int /* product_strategy_t */ strategy,
                        int /* audio_session_t */ session,
                        int id);

    void unregisterEffect(int id);

    void setEffectEnabled(int id, boolean enabled);

    void moveEffectsToIo(in int[] ids, int /* audio_io_handle_t */ io);

    boolean isStreamActive(AudioStreamType stream, int inPastMs);

    boolean isStreamActiveRemotely(AudioStreamType stream, int inPastMs);

    boolean isSourceActive(AudioSource source);

    /**
     * On input, count represents the maximum length of the returned array.
     * On output, count is the total number of elements, which may be larger than the array size.
     * Passing '0' on input and inspecting the value on output is a common way of determining the
     * number of elements without actually retrieving them.
     */
    EffectDescriptor[] queryDefaultPreProcessing(int /* audio_session_t */ audioSession,
                                                 inout Int count);

    int /* audio_unique_id_t */ addSourceDefaultEffect(in AudioUuid type,
                                                       @utf8InCpp String opPackageName,
                                                       in AudioUuid uuid,
                                                       int priority,
                                                       AudioSource source);

    int /* audio_unique_id_t */ addStreamDefaultEffect(in AudioUuid type,
                                                       @utf8InCpp String opPackageName,
                                                       in AudioUuid uuid,
                                                       int priority,
                                                       AudioUsage usage);

    void removeSourceDefaultEffect(int /* audio_unique_id_t */ id);

    void removeStreamDefaultEffect(int /* audio_unique_id_t */ id);

    void setSupportedSystemUsages(in AudioUsage[] systemUsages);

    void setAllowedCapturePolicy(int /* uid_t */ uid,
                                 int /* Bitmask of AudioFlags */ capturePolicy);

    /**
     * Check if offload is possible for given format, stream type, sample rate,
     * bit rate, duration, video and streaming or offload property is enabled.
     */
    AudioOffloadMode getOffloadSupport(in AudioOffloadInfo info);

    /**
     * Check if direct playback is possible for given format, sample rate, channel mask and flags.
     */
    boolean isDirectOutputSupported(in AudioConfigBase config,
                                    in AudioAttributes attributes);

    /**
     * List currently attached audio ports and their attributes. Returns the generation.
     * The generation is incremented each time when anything changes in the ports
     * configuration.
     *
     * On input, count represents the maximum length of the returned array.
     * On output, count is the total number of elements, which may be larger than the array size.
     * Passing '0' on input and inspecting the value on output is a common way of determining the
     * number of elements without actually retrieving them.
     */
    int listAudioPorts(AudioPortRole role,
                       AudioPortType type,
                       inout Int count,
                       out AudioPortFw[] ports);

    /**
     * List all device ports declared in the configuration (including currently detached ones)
     * 'role' can be 'NONE' to get both input and output devices,
     * 'SINK' for output devices, and 'SOURCE' for input devices.
     */
    AudioPortFw[] listDeclaredDevicePorts(AudioPortRole role);

    /** Get attributes for the audio port with the given id (AudioPort.hal.id field). */
    AudioPortFw getAudioPort(int /* audio_port_handle_t */ portId);

    /**
     * Create an audio patch between several source and sink ports.
     * The handle argument is used when updating an existing patch.
     */
    int /* audio_patch_handle_t */ createAudioPatch(in AudioPatchFw patch, int handle);

    /** Release an audio patch. */
    void releaseAudioPatch(int /* audio_patch_handle_t */ handle);

    /**
     * List existing audio patches. Returns the generation.
     *
     * On input, count represents the maximum length of the returned array.
     * On output, count is the total number of elements, which may be larger than the array size.
     * Passing '0' on input and inspecting the value on output is a common way of determining the
     * number of elements without actually retrieving them.
     */
    int listAudioPatches(inout Int count, out AudioPatchFw[] patches);

    /** Set audio port configuration. */
    void setAudioPortConfig(in AudioPortConfigFw config);

    void registerClient(IAudioPolicyServiceClient client);

    void setAudioPortCallbacksEnabled(boolean enabled);

    void setAudioVolumeGroupCallbacksEnabled(boolean enabled);

    SoundTriggerSession acquireSoundTriggerSession();

    void releaseSoundTriggerSession(int /* audio_session_t */ session);

    AudioMode getPhoneState();

    void registerPolicyMixes(in AudioMix[] mixes, boolean registration);

    void setUidDeviceAffinities(int /* uid_t */ uid, in AudioDevice[] devices);

    void removeUidDeviceAffinities(int /* uid_t */ uid);

    void setUserIdDeviceAffinities(int userId, in AudioDevice[] devices);

    void removeUserIdDeviceAffinities(int userId);

    int /* audio_port_handle_t */ startAudioSource(in AudioPortConfigFw source,
                                                   in AudioAttributes attributes);

    void stopAudioSource(int /* audio_port_handle_t */ portId);

    void setMasterMono(boolean mono);

    boolean getMasterMono();

    float getStreamVolumeDB(AudioStreamType stream, int index, in AudioDeviceDescription device);

    /**
     * Populates supported surround formats and their enabled state in formats and formatsEnabled.
     *
     * On input, count represents the maximum length of the returned array.
     * On output, count is the total number of elements, which may be larger than the array size.
     * Passing '0' on input and inspecting the value on output is a common way of determining the
     * number of elements without actually retrieving them.
     */
    void getSurroundFormats(inout Int count,
                            out AudioFormatDescription[] formats,
                            out boolean[] formatsEnabled);

    /**
     * Populates the surround formats reported by the HDMI devices in formats.
     *
     * On input, count represents the maximum length of the returned array.
     * On output, count is the total number of elements, which may be larger than the array size.
     * Passing '0' on input and inspecting the value on output is a common way of determining the
     * number of elements without actually retrieving them.
     */
    void getReportedSurroundFormats(inout Int count,
                                    out AudioFormatDescription[] formats);

    AudioFormatDescription[] getHwOffloadFormatsSupportedForBluetoothMedia(
                                    in AudioDeviceDescription device);

    void setSurroundFormatEnabled(in AudioFormatDescription audioFormat, boolean enabled);

    void setAssistantServicesUids(in int[] /* uid_t[] */ uids);

    void setActiveAssistantServicesUids(in int[] /* uid_t[] */ activeUids);

    void setA11yServicesUids(in int[] /* uid_t[] */ uids);

    void setCurrentImeUid(int /* uid_t */ uid);

    boolean isHapticPlaybackSupported();

    boolean isUltrasoundSupported();

    /**
     * Queries if there is hardware support for requesting audio capture content from
     * the DSP hotword pipeline.
     *
     * @param lookbackAudio true if additionally querying for the ability to capture audio
     *                      from the pipeline prior to capture stream open.
     */
    boolean isHotwordStreamSupported(boolean lookbackAudio);

    AudioProductStrategy[] listAudioProductStrategies();
    int /* product_strategy_t */ getProductStrategyFromAudioAttributes(
            in AudioAttributes aa, boolean fallbackOnDefault);

    AudioVolumeGroup[] listAudioVolumeGroups();
    int /* volume_group_t */ getVolumeGroupFromAudioAttributes(in AudioAttributes aa,
                                                               boolean fallbackOnDefault);

    void setRttEnabled(boolean enabled);

    boolean isCallScreenModeSupported();

    void setDevicesRoleForStrategy(int /* product_strategy_t */ strategy,
                                   DeviceRole role,
                                   in AudioDevice[] devices);

    void removeDevicesRoleForStrategy(int /* product_strategy_t */ strategy,
                                      DeviceRole role,
                                      in AudioDevice[] devices);

    void clearDevicesRoleForStrategy(int /* product_strategy_t */ strategy, DeviceRole role);

    AudioDevice[] getDevicesForRoleAndStrategy(int /* product_strategy_t */ strategy,
                                               DeviceRole role);

    void setDevicesRoleForCapturePreset(AudioSource audioSource,
                                        DeviceRole role,
                                        in AudioDevice[] devices);

    void addDevicesRoleForCapturePreset(AudioSource audioSource,
                                        DeviceRole role,
                                        in AudioDevice[] devices);

    void removeDevicesRoleForCapturePreset(AudioSource audioSource,
                                           DeviceRole role,
                                           in AudioDevice[] devices);

    void clearDevicesRoleForCapturePreset(AudioSource audioSource,
                                          DeviceRole role);

    AudioDevice[] getDevicesForRoleAndCapturePreset(AudioSource audioSource,
                                                    DeviceRole role);

    boolean registerSoundTriggerCaptureStateListener(ICaptureStateListener listener);

    /** If a spatializer stage effect is present on the platform, this will return an
     * ISpatializer interface (see GetSpatializerResponse,aidl) to control this
     * feature.
     * If no spatializer stage is present, a null interface is returned.
     * The INativeSpatializerCallback passed must not be null.
     * Only one ISpatializer interface can exist at a given time. The native audio policy
     * service will reject the request if an interface was already acquired and previous owner
     * did not die or call ISpatializer.release().
     */
    GetSpatializerResponse getSpatializer(INativeSpatializerCallback callback);

    /** Queries if some kind of spatialization will be performed if the audio playback context
     * described by the provided arguments is present.
     * The context is made of:
     * - The audio attributes describing the playback use case.
     * - The audio configuration describing the audio format, channels, sampling rate...
     * - The devices describing the sink audio device selected for playback.
     * All arguments are optional and only the specified arguments are used to match against
     * supported criteria. For instance, supplying no argument will tell if spatialization is
     * supported or not in general.
     */
    boolean canBeSpatialized(in @nullable AudioAttributes attr,
                             in @nullable AudioConfig config,
                             in AudioDevice[] devices);

    /**
     * Query how the direct playback is currently supported on the device.
     */
    AudioDirectMode getDirectPlaybackSupport(in AudioAttributes attr,
                                              in AudioConfig config);

    /**
     * Query audio profiles available for direct playback on the current output device(s)
     * for the specified audio attributes.
     */
    AudioProfile[] getDirectProfilesForAttributes(in AudioAttributes attr);

    /**
     * Return a list of AudioMixerAttributes that can be used to set preferred mixer attributes
     * for the given device.
     */
    AudioMixerAttributesInternal[] getSupportedMixerAttributes(
            int /* audio_port_handle_t */ portId);

    /**
     * Set preferred mixer attributes for a given device on a given audio attributes.
     * When conflicting requests are received, the last request will be honored.
     * The preferred mixer attributes can only be set when 1) the usage is media, 2) the
     * given device is currently available, 3) the given device is usb device, 4) the given mixer
     * attributes is supported by the given device.
     *
     * @param attr the audio attributes whose mixer attributes should be set.
     * @param portId the port id of the device to be routed.
     * @param uid the uid of the request client. The uid will be used to recognize the ownership for
     *            the preferred mixer attributes. All the playback with same audio attributes from
     *            the same uid will be attached to the mixer with the preferred attributes if the
     *            playback is routed to the given device.
     * @param mixerAttr the preferred mixer attributes.
     */
    void setPreferredMixerAttributes(in AudioAttributes attr,
                                     int /* audio_port_handle_t */ portId,
                                     int /* uid_t */ uid,
                                     in AudioMixerAttributesInternal mixerAttr);

    /**
     * Get preferred mixer attributes for a given device on a given audio attributes.
     * Null will be returned if there is no preferred mixer attributes set or it has
     * been cleared.
     *
     * @param attr the audio attributes whose mixer attributes should be set.
     * @param portId the port id of the device to be routed.
     */
    @nullable AudioMixerAttributesInternal getPreferredMixerAttributes(
            in AudioAttributes attr,
            int /* audio_port_handle_t */ portId);

    /**
     * Clear preferred mixer attributes for a given device on a given audio attributes that
     * is previously set via setPreferredMixerAttributes.
     *
     * @param attr the audio attributes whose mixer attributes should be set.
     * @param portId the port id of the device to be routed.
     * @param uid the uid of the request client. The uid is used to identify the ownership for the
     *            preferred mixer attributes. The preferred mixer attributes will only be cleared
     *            if the uid is the same as the owner of current preferred mixer attributes.
     */
    void clearPreferredMixerAttributes(in AudioAttributes attr,
                                       int /* audio_port_handle_t */ portId,
                                       int /* uid_t */ uid);


    // When adding a new method, please review and update
    // AudioPolicyService.cpp AudioPolicyService::onTransact()
    // AudioPolicyService.cpp IAUDIOPOLICYSERVICE_BINDER_METHOD_MACRO_LIST
}
