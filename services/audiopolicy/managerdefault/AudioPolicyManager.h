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

#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <unordered_set>

#include <stdint.h>
#include <sys/types.h>
#include <cutils/config_utils.h>
#include <cutils/misc.h>
#include <utils/Timers.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/SortedVector.h>
#include <media/AudioParameter.h>
#include <media/AudioPolicy.h>
#include <media/AudioProfile.h>
#include <media/PatchBuilder.h>
#include "AudioPolicyInterface.h"

#include <android/media/DeviceConnectedState.h>
#include <android/media/audio/common/AudioPort.h>
#include <AudioPolicyManagerObserver.h>
#include <AudioPolicyConfig.h>
#include <PolicyAudioPort.h>
#include <AudioPatch.h>
#include <DeviceDescriptor.h>
#include <IOProfile.h>
#include <HwModule.h>
#include <AudioInputDescriptor.h>
#include <AudioOutputDescriptor.h>
#include <AudioPolicyMix.h>
#include <EffectDescriptor.h>
#include <PreferredMixerAttributesInfo.h>
#include <SoundTriggerSession.h>
#include "EngineLibrary.h"
#include "TypeConverter.h"

namespace android {

using content::AttributionSourceState;

// ----------------------------------------------------------------------------

// Attenuation applied to STRATEGY_SONIFICATION streams when a headset is connected: 6dB
#define SONIFICATION_HEADSET_VOLUME_FACTOR_DB (-6)
// Min volume for STRATEGY_SONIFICATION streams when limited by music volume: -36dB
#define SONIFICATION_HEADSET_VOLUME_MIN_DB  (-36)
// Max volume difference on A2DP between playing media and STRATEGY_SONIFICATION streams: 12dB
#define SONIFICATION_A2DP_MAX_MEDIA_DIFF_DB (12)

// Time in milliseconds during which we consider that music is still active after a music
// track was stopped - see computeVolume()
#define SONIFICATION_HEADSET_MUSIC_DELAY  5000

// Time in milliseconds during witch some streams are muted while the audio path
// is switched
#define MUTE_TIME_MS 2000

// multiplication factor applied to output latency when calculating a safe mute delay when
// invalidating tracks
#define LATENCY_MUTE_FACTOR 4

#define NUM_TEST_OUTPUTS 5

#define NUM_VOL_CURVE_KNEES 2

// Default minimum length allowed for offloading a compressed track
// Can be overridden by the audio.offload.min.duration.secs property
#define OFFLOAD_DEFAULT_MIN_DURATION_SECS 60

// ----------------------------------------------------------------------------
// AudioPolicyManager implements audio policy manager behavior common to all platforms.
// ----------------------------------------------------------------------------

class AudioPolicyManager : public AudioPolicyInterface, public AudioPolicyManagerObserver
{

public:
        AudioPolicyManager(const sp<const AudioPolicyConfig>& config,
                           EngineInstance&& engine,
                           AudioPolicyClientInterface *clientInterface);
        virtual ~AudioPolicyManager();

        // AudioPolicyInterface
        virtual status_t setDeviceConnectionState(audio_policy_dev_state_t state,
                const android::media::audio::common::AudioPort& port, audio_format_t encodedFormat);
        virtual audio_policy_dev_state_t getDeviceConnectionState(audio_devices_t device,
                                                                              const char *device_address);
        virtual status_t handleDeviceConfigChange(audio_devices_t device,
                                                  const char *device_address,
                                                  const char *device_name,
                                                  audio_format_t encodedFormat);
        virtual void setPhoneState(audio_mode_t state);
        virtual void setForceUse(audio_policy_force_use_t usage,
                                 audio_policy_forced_cfg_t config);
        virtual audio_policy_forced_cfg_t getForceUse(audio_policy_force_use_t usage);

        virtual void setSystemProperty(const char* property, const char* value);
        virtual status_t initCheck();
        virtual audio_io_handle_t getOutput(audio_stream_type_t stream);
        status_t getOutputForAttr(const audio_attributes_t *attr,
                                  audio_io_handle_t *output,
                                  audio_session_t session,
                                  audio_stream_type_t *stream,
                                  const AttributionSourceState& attributionSource,
                                  audio_config_t *config,
                                  audio_output_flags_t *flags,
                                  audio_port_handle_t *selectedDeviceId,
                                  audio_port_handle_t *portId,
                                  std::vector<audio_io_handle_t> *secondaryOutputs,
                                  output_type_t *outputType,
                                  bool *isSpatialized,
                                  bool *isBitPerfect) override;
        virtual status_t startOutput(audio_port_handle_t portId);
        virtual status_t stopOutput(audio_port_handle_t portId);
        virtual bool releaseOutput(audio_port_handle_t portId);
        virtual status_t getInputForAttr(const audio_attributes_t *attr,
                                         audio_io_handle_t *input,
                                         audio_unique_id_t riid,
                                         audio_session_t session,
                                         const AttributionSourceState& attributionSource,
                                         audio_config_base_t *config,
                                         audio_input_flags_t flags,
                                         audio_port_handle_t *selectedDeviceId,
                                         input_type_t *inputType,
                                         audio_port_handle_t *portId);

        // indicates to the audio policy manager that the input starts being used.
        virtual status_t startInput(audio_port_handle_t portId);

        // indicates to the audio policy manager that the input stops being used.
        virtual status_t stopInput(audio_port_handle_t portId);
        virtual void releaseInput(audio_port_handle_t portId);
        virtual void checkCloseInputs();
        /**
         * @brief initStreamVolume: even if the engine volume files provides min and max, keep this
         * api for compatibility reason.
         * AudioServer will get the min and max and may overwrite them if:
         *      -using property (highest priority)
         *      -not defined (-1 by convention), case when still using apm volume tables XML files
         * @param stream to be considered
         * @param indexMin to set
         * @param indexMax to set
         */
        virtual void initStreamVolume(audio_stream_type_t stream, int indexMin, int indexMax);
        virtual status_t setStreamVolumeIndex(audio_stream_type_t stream,
                                              int index,
                                              audio_devices_t device);
        virtual status_t getStreamVolumeIndex(audio_stream_type_t stream,
                                              int *index,
                                              audio_devices_t device);

        virtual status_t setVolumeIndexForAttributes(const audio_attributes_t &attr,
                                                     int index,
                                                     audio_devices_t device);
        virtual status_t getVolumeIndexForAttributes(const audio_attributes_t &attr,
                                                     int &index,
                                                     audio_devices_t device);
        virtual status_t getMaxVolumeIndexForAttributes(const audio_attributes_t &attr, int &index);

        virtual status_t getMinVolumeIndexForAttributes(const audio_attributes_t &attr, int &index);

        status_t setVolumeCurveIndex(int index,
                                     audio_devices_t device,
                                     IVolumeCurves &volumeCurves);

        status_t getVolumeIndex(const IVolumeCurves &curves, int &index,
                                const DeviceTypeSet& deviceTypes) const;

        // return the strategy corresponding to a given stream type
        virtual product_strategy_t getStrategyForStream(audio_stream_type_t stream)
        {
            return streamToStrategy(stream);
        }
        product_strategy_t streamToStrategy(audio_stream_type_t stream) const
        {
            auto attributes = mEngine->getAttributesForStreamType(stream);
            return mEngine->getProductStrategyForAttributes(attributes);
        }

        /**
         * Returns a vector of devices associated with attributes.
         *
         * An AudioTrack opened with specified attributes should play on the returned devices.
         * If forVolume is set to true, the caller is AudioService, determining the proper
         * device volume to adjust.
         *
         * Devices are determined in the following precedence:
         * 1) Devices associated with a dynamic policy matching the attributes.  This is often
         *    a remote submix from MIX_ROUTE_FLAG_LOOP_BACK.  Secondary mixes from a
         *    dynamic policy are not included.
         *
         * If no such dynamic policy then
         * 2) Devices containing an active client using setPreferredDevice
         *    with same strategy as the attributes.
         *    (from the default Engine::getOutputDevicesForAttributes() implementation).
         *
         * If no corresponding active client with setPreferredDevice then
         * 3) Devices associated with the strategy determined by the attributes
         *    (from the default Engine::getOutputDevicesForAttributes() implementation).
         *
         * @param attributes to be considered
         * @param devices    an AudioDeviceTypeAddrVector container passed in that
         *                   will be filled on success.
         * @param forVolume  true if the devices are to be associated with current device volume.
         * @return           NO_ERROR on success.
         */
        virtual status_t getDevicesForAttributes(
                const audio_attributes_t &attributes,
                AudioDeviceTypeAddrVector *devices,
                bool forVolume);

        virtual audio_io_handle_t getOutputForEffect(const effect_descriptor_t *desc = NULL);
        virtual status_t registerEffect(const effect_descriptor_t *desc,
                                        audio_io_handle_t io,
                                        product_strategy_t strategy,
                                        int session,
                                        int id);
        virtual status_t unregisterEffect(int id);
        virtual status_t setEffectEnabled(int id, bool enabled);
        status_t moveEffectsToIo(const std::vector<int>& ids, audio_io_handle_t io) override;

        virtual bool isStreamActive(audio_stream_type_t stream, uint32_t inPastMs = 0) const;
        // return whether a stream is playing remotely, override to change the definition of
        //   local/remote playback, used for instance by notification manager to not make
        //   media players lose audio focus when not playing locally
        //   For the base implementation, "remotely" means playing during screen mirroring which
        //   uses an output for playback with a non-empty, non "0" address.
        virtual bool isStreamActiveRemotely(audio_stream_type_t stream,
                                            uint32_t inPastMs = 0) const;

        virtual bool isSourceActive(audio_source_t source) const;

        // helpers for dump(int fd)
        void dumpManualSurroundFormats(String8 *dst) const;
        void dump(String8 *dst) const;

        status_t dump(int fd) override;

        status_t setAllowedCapturePolicy(uid_t uid, audio_flags_mask_t capturePolicy) override;
        virtual audio_offload_mode_t getOffloadSupport(const audio_offload_info_t& offloadInfo);

        virtual bool isDirectOutputSupported(const audio_config_base_t& config,
                                             const audio_attributes_t& attributes);

        virtual status_t listAudioPorts(audio_port_role_t role,
                                        audio_port_type_t type,
                                        unsigned int *num_ports,
                                        struct audio_port_v7 *ports,
                                        unsigned int *generation);
                status_t listDeclaredDevicePorts(media::AudioPortRole role,
                                                 std::vector<media::AudioPortFw>* result) override;
        virtual status_t getAudioPort(struct audio_port_v7 *port);
        virtual status_t createAudioPatch(const struct audio_patch *patch,
                                           audio_patch_handle_t *handle,
                                           uid_t uid);
        virtual status_t releaseAudioPatch(audio_patch_handle_t handle,
                                              uid_t uid);
        virtual status_t listAudioPatches(unsigned int *num_patches,
                                          struct audio_patch *patches,
                                          unsigned int *generation);
        virtual status_t setAudioPortConfig(const struct audio_port_config *config);

        virtual void releaseResourcesForUid(uid_t uid);

        virtual status_t acquireSoundTriggerSession(audio_session_t *session,
                                               audio_io_handle_t *ioHandle,
                                               audio_devices_t *device);

        virtual status_t releaseSoundTriggerSession(audio_session_t session)
        {
            return mSoundTriggerSessions.releaseSession(session);
        }

        virtual status_t registerPolicyMixes(const Vector<AudioMix>& mixes);
        virtual status_t unregisterPolicyMixes(Vector<AudioMix> mixes);
        virtual status_t setUidDeviceAffinities(uid_t uid,
                const AudioDeviceTypeAddrVector& devices);
        virtual status_t removeUidDeviceAffinities(uid_t uid);
        virtual status_t setUserIdDeviceAffinities(int userId,
                const AudioDeviceTypeAddrVector& devices);
        virtual status_t removeUserIdDeviceAffinities(int userId);

        virtual status_t setDevicesRoleForStrategy(product_strategy_t strategy,
                                                   device_role_t role,
                                                   const AudioDeviceTypeAddrVector &devices);

        virtual status_t removeDevicesRoleForStrategy(product_strategy_t strategy,
                                                      device_role_t role,
                                                      const AudioDeviceTypeAddrVector &devices);

        virtual status_t clearDevicesRoleForStrategy(product_strategy_t strategy,
                                                     device_role_t role);

        virtual status_t getDevicesForRoleAndStrategy(product_strategy_t strategy,
                                                      device_role_t role,
                                                      AudioDeviceTypeAddrVector &devices);

        virtual status_t setDevicesRoleForCapturePreset(audio_source_t audioSource,
                                                        device_role_t role,
                                                        const AudioDeviceTypeAddrVector &devices);

        virtual status_t addDevicesRoleForCapturePreset(audio_source_t audioSource,
                                                        device_role_t role,
                                                        const AudioDeviceTypeAddrVector &devices);

        virtual status_t removeDevicesRoleForCapturePreset(
                audio_source_t audioSource, device_role_t role,
                const AudioDeviceTypeAddrVector& devices);

        virtual status_t clearDevicesRoleForCapturePreset(audio_source_t audioSource,
                                                          device_role_t role);

        virtual status_t getDevicesForRoleAndCapturePreset(audio_source_t audioSource,
                                                           device_role_t role,
                                                           AudioDeviceTypeAddrVector &devices);

        virtual status_t startAudioSource(const struct audio_port_config *source,
                                          const audio_attributes_t *attributes,
                                          audio_port_handle_t *portId,
                                          uid_t uid);
        virtual status_t stopAudioSource(audio_port_handle_t portId);

        virtual status_t setMasterMono(bool mono);
        virtual status_t getMasterMono(bool *mono);
        virtual float    getStreamVolumeDB(
                    audio_stream_type_t stream, int index, audio_devices_t device);

        virtual status_t getSurroundFormats(unsigned int *numSurroundFormats,
                                            audio_format_t *surroundFormats,
                                            bool *surroundFormatsEnabled);
        virtual status_t getReportedSurroundFormats(unsigned int *numSurroundFormats,
                                                    audio_format_t *surroundFormats);
        virtual status_t setSurroundFormatEnabled(audio_format_t audioFormat, bool enabled);

        virtual status_t getHwOffloadFormatsSupportedForBluetoothMedia(
                    audio_devices_t device, std::vector<audio_format_t> *formats);

        virtual void setAppState(audio_port_handle_t portId, app_state_t state);

        virtual bool isHapticPlaybackSupported();

        virtual bool isUltrasoundSupported();

        bool isHotwordStreamSupported(bool lookbackAudio) override;

        virtual status_t listAudioProductStrategies(AudioProductStrategyVector &strategies)
        {
            return mEngine->listAudioProductStrategies(strategies);
        }

        virtual status_t getProductStrategyFromAudioAttributes(
                const audio_attributes_t &aa, product_strategy_t &productStrategy,
                bool fallbackOnDefault)
        {
            productStrategy = mEngine->getProductStrategyForAttributes(aa, fallbackOnDefault);
            return (fallbackOnDefault && productStrategy == PRODUCT_STRATEGY_NONE) ?
                    BAD_VALUE : NO_ERROR;
        }

        virtual status_t listAudioVolumeGroups(AudioVolumeGroupVector &groups)
        {
            return mEngine->listAudioVolumeGroups(groups);
        }

        virtual status_t getVolumeGroupFromAudioAttributes(
                const audio_attributes_t &aa, volume_group_t &volumeGroup, bool fallbackOnDefault)
        {
            volumeGroup = mEngine->getVolumeGroupForAttributes(aa, fallbackOnDefault);
            return (fallbackOnDefault && volumeGroup == VOLUME_GROUP_NONE) ?
                    BAD_VALUE : NO_ERROR;
        }

        virtual bool canBeSpatialized(const audio_attributes_t *attr,
                                      const audio_config_t *config,
                                      const AudioDeviceTypeAddrVector &devices) const {
            return canBeSpatializedInt(attr, config, devices);
        }

        virtual status_t getSpatializerOutput(const audio_config_base_t *config,
                                                const audio_attributes_t *attr,
                                                audio_io_handle_t *output);

        virtual status_t releaseSpatializerOutput(audio_io_handle_t output);

        virtual audio_direct_mode_t getDirectPlaybackSupport(const audio_attributes_t *attr,
                                                             const audio_config_t *config);

        virtual status_t getDirectProfilesForAttributes(const audio_attributes_t* attr,
                                                         AudioProfileVector& audioProfiles);

        status_t getSupportedMixerAttributes(
                audio_port_handle_t portId,
                std::vector<audio_mixer_attributes_t>& mixerAttrs) override;
        status_t setPreferredMixerAttributes(
                const audio_attributes_t* attr,
                audio_port_handle_t portId,
                uid_t uid,
                const audio_mixer_attributes_t* mixerAttributes) override;
        status_t getPreferredMixerAttributes(const audio_attributes_t* attr,
                                             audio_port_handle_t portId,
                                             audio_mixer_attributes_t* mixerAttributes) override;
        status_t clearPreferredMixerAttributes(const audio_attributes_t* attr,
                                               audio_port_handle_t portId,
                                               uid_t uid) override;

        bool isCallScreenModeSupported() override;

        void onNewAudioModulesAvailable() override;

        status_t initialize();

protected:
        const AudioPolicyConfig& getConfig() const { return *(mConfig.get()); }

        // From AudioPolicyManagerObserver
        virtual const AudioPatchCollection &getAudioPatches() const
        {
            return mAudioPatches;
        }
        virtual const SoundTriggerSessionCollection &getSoundTriggerSessionCollection() const
        {
            return mSoundTriggerSessions;
        }
        virtual const AudioPolicyMixCollection &getAudioPolicyMixCollection() const
        {
            return mPolicyMixes;
        }
        virtual const SwAudioOutputCollection &getOutputs() const
        {
            return mOutputs;
        }
        virtual const AudioInputCollection &getInputs() const
        {
            return mInputs;
        }
        virtual const DeviceVector getAvailableOutputDevices() const
        {
            return mAvailableOutputDevices.filterForEngine();
        }
        virtual const DeviceVector getAvailableInputDevices() const
        {
            // legacy and non-legacy remote-submix are managed by the engine, do not filter
            return mAvailableInputDevices;
        }
        virtual const sp<DeviceDescriptor> &getDefaultOutputDevice() const
        {
            return mConfig->getDefaultOutputDevice();
        }

        std::vector<volume_group_t> getVolumeGroups() const
        {
            return mEngine->getVolumeGroups();
        }

        VolumeSource toVolumeSource(volume_group_t volumeGroup) const
        {
            return static_cast<VolumeSource>(volumeGroup);
        }
        /**
         * @brief toVolumeSource converts an audio attributes into a volume source
         * (either a legacy stream or a volume group). If fallback on default is allowed, and if
         * the audio attributes do not follow any specific product strategy's rule, it will be
         * associated to default volume source, e.g. music. Thus, any of call of volume API
         * using this translation function may affect the default volume source.
         * If fallback is not allowed and no matching rule is identified for the given attributes,
         * the volume source will be undefined, thus, no volume will be altered/modified.
         * @param attributes to be considered
         * @param fallbackOnDefault
         * @return volume source associated with given attributes, otherwise either music if
         * fallbackOnDefault is set or none.
         */
        VolumeSource toVolumeSource(
            const audio_attributes_t &attributes, bool fallbackOnDefault = true) const
        {
            return toVolumeSource(mEngine->getVolumeGroupForAttributes(
                attributes, fallbackOnDefault));
        }
        VolumeSource toVolumeSource(
            audio_stream_type_t stream, bool fallbackOnDefault = true) const
        {
            return toVolumeSource(mEngine->getVolumeGroupForStreamType(
                stream, fallbackOnDefault));
        }
        IVolumeCurves &getVolumeCurves(VolumeSource volumeSource)
        {
          auto *curves = mEngine->getVolumeCurvesForVolumeGroup(
              static_cast<volume_group_t>(volumeSource));
          ALOG_ASSERT(curves != nullptr, "No curves for volume source %d", volumeSource);
          return *curves;
        }
        IVolumeCurves &getVolumeCurves(const audio_attributes_t &attr)
        {
            auto *curves = mEngine->getVolumeCurvesForAttributes(attr);
            ALOG_ASSERT(curves != nullptr, "No curves for attributes %s", toString(attr).c_str());
            return *curves;
        }
        IVolumeCurves &getVolumeCurves(audio_stream_type_t stream)
        {
            auto *curves = mEngine->getVolumeCurvesForStreamType(stream);
            ALOG_ASSERT(curves != nullptr, "No curves for stream %s", toString(stream).c_str());
            return *curves;
        }

        void addOutput(audio_io_handle_t output, const sp<SwAudioOutputDescriptor>& outputDesc);
        void removeOutput(audio_io_handle_t output);
        void addInput(audio_io_handle_t input, const sp<AudioInputDescriptor>& inputDesc);

        /**
         * @brief setOutputDevices change the route of the specified output.
         * @param outputDesc to be considered
         * @param device to be considered to route the output
         * @param force if true, force the routing even if no change.
         * @param delayMs if specified, delay to apply for mute/volume op when changing device
         * @param patchHandle if specified, the patch handle this output is connected through.
         * @param requiresMuteCheck if specified, for e.g. when another output is on a shared device
         *        and currently active, allow to have proper drain and avoid pops
         * @param requiresVolumeCheck true if called requires to reapply volume if the routing did
         * not change (but the output is still routed).
         * @param skipMuteDelay if true will skip mute delay when installing audio patch
         * @return the number of ms we have slept to allow new routing to take effect in certain
         *        cases.
         */
        uint32_t setOutputDevices(const sp<SwAudioOutputDescriptor>& outputDesc,
                                  const DeviceVector &device,
                                  bool force = false,
                                  int delayMs = 0,
                                  audio_patch_handle_t *patchHandle = NULL,
                                  bool requiresMuteCheck = true,
                                  bool requiresVolumeCheck = false,
                                  bool skipMuteDelay = false);
        status_t resetOutputDevice(const sp<AudioOutputDescriptor>& outputDesc,
                                   int delayMs = 0,
                                   audio_patch_handle_t *patchHandle = NULL);
        status_t setInputDevice(audio_io_handle_t input,
                                const sp<DeviceDescriptor> &device,
                                bool force = false,
                                audio_patch_handle_t *patchHandle = NULL);
        status_t resetInputDevice(audio_io_handle_t input,
                                  audio_patch_handle_t *patchHandle = NULL);

        // compute the actual volume for a given stream according to the requested index and a particular
        // device
        virtual float computeVolume(IVolumeCurves &curves,
                                    VolumeSource volumeSource,
                                    int index,
                                    const DeviceTypeSet& deviceTypes);

        // rescale volume index from srcStream within range of dstStream
        int rescaleVolumeIndex(int srcIndex,
                               VolumeSource fromVolumeSource,
                               VolumeSource toVolumeSource);
        // check that volume change is permitted, compute and send new volume to audio hardware
        virtual status_t checkAndSetVolume(IVolumeCurves &curves,
                                           VolumeSource volumeSource, int index,
                                           const sp<AudioOutputDescriptor>& outputDesc,
                                           DeviceTypeSet deviceTypes,
                                           int delayMs = 0, bool force = false);

        // apply all stream volumes to the specified output and device
        void applyStreamVolumes(const sp<AudioOutputDescriptor>& outputDesc,
                                const DeviceTypeSet& deviceTypes,
                                int delayMs = 0, bool force = false);

        /**
         * @brief setStrategyMute Mute or unmute all active clients on the considered output
         * following the given strategy.
         * @param strategy to be considered
         * @param on true for mute, false for unmute
         * @param outputDesc to be considered
         * @param delayMs
         * @param device
         */
        void setStrategyMute(product_strategy_t strategy,
                             bool on,
                             const sp<AudioOutputDescriptor>& outputDesc,
                             int delayMs = 0,
                             DeviceTypeSet deviceTypes = DeviceTypeSet());

        /**
         * @brief setVolumeSourceMute Mute or unmute the volume source on the specified output
         * @param volumeSource to be muted/unmute (may host legacy streams or by extension set of
         * audio attributes)
         * @param on true to mute, false to umute
         * @param outputDesc on which the client following the volume group shall be muted/umuted
         * @param delayMs
         * @param device
         */
        void setVolumeSourceMute(VolumeSource volumeSource,
                                 bool on,
                                 const sp<AudioOutputDescriptor>& outputDesc,
                                 int delayMs = 0,
                                 DeviceTypeSet deviceTypes = DeviceTypeSet());

        audio_mode_t getPhoneState();

        // true if device is in a telephony or VoIP call
        virtual bool isInCall() const;
        // true if given state represents a device in a telephony or VoIP call
        virtual bool isStateInCall(int state) const;
        // true if playback to call TX or capture from call RX is possible
        bool isCallAudioAccessible() const;
        // true if device is in a telephony or VoIP call or call screening is active
        bool isInCallOrScreening() const;

        // when a device is connected, checks if an open output can be routed
        // to this device. If none is open, tries to open one of the available outputs.
        // Returns an output suitable to this device or 0.
        // when a device is disconnected, checks if an output is not used any more and
        // returns its handle if any.
        // transfers the audio tracks and effects from one output thread to another accordingly.
        status_t checkOutputsForDevice(const sp<DeviceDescriptor>& device,
                                       audio_policy_dev_state_t state,
                                       SortedVector<audio_io_handle_t>& outputs);

        status_t checkInputsForDevice(const sp<DeviceDescriptor>& device,
                                      audio_policy_dev_state_t state);

        // close an output and its companion duplicating output.
        void closeOutput(audio_io_handle_t output);

        // close an input.
        void closeInput(audio_io_handle_t input);

        // runs all the checks required for accommodating changes in devices and outputs
        // if 'onOutputsChecked' callback is provided, it is executed after the outputs
        // check via 'checkOutputForAllStrategies'. If the callback returns 'true',
        // A2DP suspend status is rechecked.
        void checkForDeviceAndOutputChanges(std::function<bool()> onOutputsChecked = nullptr);

        /**
         * @brief updates routing for all outputs (including call if call in progress).
         * @param delayMs delay for unmuting if required
         * @param skipDelays if true all the delays will be skip while updating routing
         */
        void updateCallAndOutputRouting(bool forceVolumeReeval = true, uint32_t delayMs = 0,
                bool skipDelays = false);

        bool isCallRxAudioSource(const sp<SourceClientDescriptor> &source) {
            return mCallRxSourceClient != nullptr && source == mCallRxSourceClient;
        }

        bool isCallTxAudioSource(const sp<SourceClientDescriptor> &source) {
            return mCallTxSourceClient != nullptr && source == mCallTxSourceClient;
        }

        void connectTelephonyRxAudioSource();

        void disconnectTelephonyAudioSource(sp<SourceClientDescriptor> &clientDesc);

        void connectTelephonyTxAudioSource(const sp<DeviceDescriptor> &srcdevice,
                                           const sp<DeviceDescriptor> &sinkDevice,
                                           uint32_t delayMs);

        bool isTelephonyRxOrTx(const sp<SwAudioOutputDescriptor>& desc) const {
            return (mCallRxSourceClient != nullptr && mCallRxSourceClient->belongsToOutput(desc))
                    || (mCallTxSourceClient != nullptr
                    &&  mCallTxSourceClient->belongsToOutput(desc));
        }

        /**
         * @brief updates routing for all inputs.
         */
        void updateInputRouting();

        /**
         * @brief checkOutputForAttributes checks and if necessary changes outputs used for the
         * given audio attributes.
         * must be called every time a condition that affects the output choice for a given
         * attributes changes: connected device, phone state, force use...
         * Must be called before updateDevicesAndOutputs()
         * @param attr to be considered
         */
        void checkOutputForAttributes(const audio_attributes_t &attr);

        /**
         * @brief checkAudioSourceForAttributes checks if any AudioSource following the same routing
         * as the given audio attributes is not routed and try to connect it.
         * It must be called once checkOutputForAttributes has been called for orphans AudioSource,
         * aka AudioSource not attached to any Audio Output (e.g. AudioSource connected to direct
         * Output which has been disconnected (and output closed) due to sink device unavailable).
         * @param attr to be considered
         */
        void checkAudioSourceForAttributes(const audio_attributes_t &attr);

        bool followsSameRouting(const audio_attributes_t &lAttr,
                                const audio_attributes_t &rAttr) const;

        /**
         * @brief checkOutputForAllStrategies Same as @see checkOutputForAttributes()
         *      but for a all product strategies in order of priority
         */
        void checkOutputForAllStrategies();

        // Same as checkOutputForStrategy but for secondary outputs. Make sure if a secondary
        // output condition changes, the track is properly rerouted
        void checkSecondaryOutputs();

        // manages A2DP output suspend/restore according to phone state and BT SCO usage
        void checkA2dpSuspend();

        // selects the most appropriate device on output for current state
        // must be called every time a condition that affects the device choice for a given output is
        // changed: connected device, phone state, force use, output start, output stop..
        // see getDeviceForStrategy() for the use of fromCache parameter
        DeviceVector getNewOutputDevices(const sp<SwAudioOutputDescriptor>& outputDesc,
                                         bool fromCache);

        /**
         * @brief updateDevicesAndOutputs: updates cache of devices of the engine
         * must be called every time a condition that affects the device choice is changed:
         * connected device, phone state, force use...
         * cached values are used by getOutputDevicesForStream()/getDevicesForAttributes if
         * parameter fromCache is true.
         * Must be called after checkOutputForAllStrategies()
         */
        void updateDevicesAndOutputs();

        // selects the most appropriate device on input for current state
        sp<DeviceDescriptor> getNewInputDevice(const sp<AudioInputDescriptor>& inputDesc);

        virtual uint32_t getMaxEffectsCpuLoad()
        {
            return mEffects.getMaxEffectsCpuLoad();
        }

        virtual uint32_t getMaxEffectsMemory()
        {
            return mEffects.getMaxEffectsMemory();
        }

        SortedVector<audio_io_handle_t> getOutputsForDevices(
                const DeviceVector &devices, const SwAudioOutputCollection& openOutputs);

        /**
         * @brief checkDeviceMuteStrategies mute/unmute strategies
         *      using an incompatible device combination.
         *      if muting, wait for the audio in pcm buffer to be drained before proceeding
         *      if unmuting, unmute only after the specified delay
         * @param outputDesc
         * @param prevDevice
         * @param delayMs
         * @return the number of ms waited
         */
        virtual uint32_t checkDeviceMuteStrategies(const sp<AudioOutputDescriptor>& outputDesc,
                                                   const DeviceVector &prevDevices,
                                                   uint32_t delayMs);

        audio_io_handle_t selectOutput(const SortedVector<audio_io_handle_t>& outputs,
                                       audio_output_flags_t flags = AUDIO_OUTPUT_FLAG_NONE,
                                       audio_format_t format = AUDIO_FORMAT_INVALID,
                                       audio_channel_mask_t channelMask = AUDIO_CHANNEL_NONE,
                                       uint32_t samplingRate = 0,
                                       audio_session_t sessionId = AUDIO_SESSION_NONE);
        // samplingRate, format, channelMask are in/out and so may be modified
        sp<IOProfile> getInputProfile(const sp<DeviceDescriptor> & device,
                                      uint32_t& samplingRate,
                                      audio_format_t& format,
                                      audio_channel_mask_t& channelMask,
                                      audio_input_flags_t flags);
        /**
         * @brief getProfileForOutput
         * @param devices vector of descriptors, may be empty if ignoring the device is required
         * @param samplingRate
         * @param format
         * @param channelMask
         * @param flags
         * @param directOnly
         * @return IOProfile to be used if found, nullptr otherwise
         */
        sp<IOProfile> getProfileForOutput(const DeviceVector &devices,
                                          uint32_t samplingRate,
                                          audio_format_t format,
                                          audio_channel_mask_t channelMask,
                                          audio_output_flags_t flags,
                                          bool directOnly);
        /**
        * Same as getProfileForOutput, but it looks for an MSD profile
        */
        sp<IOProfile> getMsdProfileForOutput(const DeviceVector &devices,
                                           uint32_t samplingRate,
                                           audio_format_t format,
                                           audio_channel_mask_t channelMask,
                                           audio_output_flags_t flags,
                                           bool directOnly);

        audio_io_handle_t selectOutputForMusicEffects();

        virtual status_t addAudioPatch(audio_patch_handle_t handle, const sp<AudioPatch>& patch)
        {
            return mAudioPatches.addAudioPatch(handle, patch);
        }
        virtual status_t removeAudioPatch(audio_patch_handle_t handle)
        {
            return mAudioPatches.removeAudioPatch(handle);
        }

        bool isPrimaryModule(const sp<HwModule> &module) const
        {
            if (module == 0 || !hasPrimaryOutput()) {
                return false;
            }
            return module->getHandle() == mPrimaryOutput->getModuleHandle();
        }
        DeviceVector availablePrimaryOutputDevices() const
        {
            if (!hasPrimaryOutput()) {
                return DeviceVector();
            }
            return mAvailableOutputDevices.filter(mPrimaryOutput->supportedDevices());
        }
        DeviceVector availablePrimaryModuleInputDevices() const
        {
            if (!hasPrimaryOutput()) {
                return DeviceVector();
            }
            return mAvailableInputDevices.getDevicesFromHwModule(
                    mPrimaryOutput->getModuleHandle());
        }
        /**
         * @brief getFirstDeviceId of the Device Vector
         * @return if the collection is not empty, it returns the first device Id,
         *         otherwise AUDIO_PORT_HANDLE_NONE
         */
        audio_port_handle_t getFirstDeviceId(const DeviceVector &devices) const
        {
            return (devices.size() > 0) ? devices.itemAt(0)->getId() : AUDIO_PORT_HANDLE_NONE;
        }
        String8 getFirstDeviceAddress(const DeviceVector &devices) const
        {
            return (devices.size() > 0) ?
                    String8(devices.itemAt(0)->address().c_str()) : String8("");
        }

        status_t updateCallRouting(
                bool fromCache, uint32_t delayMs = 0, uint32_t *waitMs = nullptr);
        status_t updateCallRoutingInternal(
                const DeviceVector &rxDevices, uint32_t delayMs, uint32_t *waitMs);
        sp<AudioPatch> createTelephonyPatch(bool isRx, const sp<DeviceDescriptor> &device,
                                            uint32_t delayMs);
        /**
         * @brief selectBestRxSinkDevicesForCall: if the primary module host both Telephony Rx/Tx
         * devices, and it declares also supporting a HW bridge between the Telephony Rx and the
         * given sink device for Voice Call audio attributes, select this device in prio.
         * Otherwise, getNewOutputDevices() is called on the primary output to select sink device.
         * @param fromCache true to prevent engine reconsidering all product strategies and retrieve
         * from engine cache.
         * @return vector of devices, empty if none is found.
         */
        DeviceVector selectBestRxSinkDevicesForCall(bool fromCache);
        bool isDeviceOfModule(const sp<DeviceDescriptor>& devDesc, const char *moduleId) const;

        status_t startSource(const sp<SwAudioOutputDescriptor>& outputDesc,
                             const sp<TrackClientDescriptor>& client,
                             uint32_t *delayMs);
        status_t stopSource(const sp<SwAudioOutputDescriptor>& outputDesc,
                            const sp<TrackClientDescriptor>& client);

        void clearAudioPatches(uid_t uid);
        void clearSessionRoutes(uid_t uid);

        /**
         * @brief checkStrategyRoute: when an output is beeing rerouted, reconsider each output
         * that may host a strategy playing on the considered output.
         * @param ps product strategy that initiated the rerouting
         * @param ouptutToSkip output that initiated the rerouting
         */
        void checkStrategyRoute(product_strategy_t ps, audio_io_handle_t ouptutToSkip);

        status_t hasPrimaryOutput() const { return mPrimaryOutput != 0; }

        status_t connectAudioSource(const sp<SourceClientDescriptor>& sourceDesc);
        status_t disconnectAudioSource(const sp<SourceClientDescriptor>& sourceDesc);

        status_t connectAudioSourceToSink(const sp<SourceClientDescriptor>& sourceDesc,
                                          const sp<DeviceDescriptor> &sinkDevice,
                                          const struct audio_patch *patch,
                                          audio_patch_handle_t &handle,
                                          uid_t uid, uint32_t delayMs);

        sp<SourceClientDescriptor> getSourceForAttributesOnOutput(audio_io_handle_t output,
                                                                  const audio_attributes_t &attr);
        void clearAudioSourcesForOutput(audio_io_handle_t output);

        void cleanUpForDevice(const sp<DeviceDescriptor>& deviceDesc);

        void clearAudioSources(uid_t uid);

        static bool streamsMatchForvolume(audio_stream_type_t stream1,
                                          audio_stream_type_t stream2);

        void closeActiveClients(const sp<AudioInputDescriptor>& input);
        void closeClient(audio_port_handle_t portId);

        /**
         * @brief isAnyDeviceTypeActive: returns true if at least one active client is routed to
         * one of the specified devices
         * @param deviceTypes list of devices to consider
         */
        bool isAnyDeviceTypeActive(const DeviceTypeSet& deviceTypes) const;
        /**
         * @brief isLeUnicastActive: returns true if a call is active or at least one active client
         * is routed to a LE unicast device
         */
        bool isLeUnicastActive() const;

        void checkLeBroadcastRoutes(bool wasUnicastActive,
                sp<SwAudioOutputDescriptor> ignoredOutput, uint32_t delayMs);

        const uid_t mUidCached;                         // AID_AUDIOSERVER
        sp<const AudioPolicyConfig> mConfig;
        EngineInstance mEngine;                         // Audio Policy Engine instance
        AudioPolicyClientInterface *mpClientInterface;  // audio policy client interface
        sp<SwAudioOutputDescriptor> mPrimaryOutput;     // primary output descriptor
        // list of descriptors for outputs currently opened

        sp<SwAudioOutputDescriptor> mSpatializerOutput;

        SwAudioOutputCollection mOutputs;
        // copy of mOutputs before setDeviceConnectionState() opens new outputs
        // reset to mOutputs when updateDevicesAndOutputs() is called.
        SwAudioOutputCollection mPreviousOutputs;
        AudioInputCollection mInputs;     // list of input descriptors

        DeviceVector  mAvailableOutputDevices; // all available output devices
        DeviceVector  mAvailableInputDevices;  // all available input devices

        bool    mLimitRingtoneVolume;        // limit ringtone volume to music volume if headset connected

        float   mLastVoiceVolume;            // last voice volume value sent to audio HAL
        bool    mA2dpSuspended;  // true if A2DP output is suspended

        EffectDescriptorCollection mEffects;  // list of registered audio effects
        HwModuleCollection mHwModules; // contains modules that have been loaded successfully

        std::atomic<uint32_t> mAudioPortGeneration;

        AudioPatchCollection mAudioPatches;

        SoundTriggerSessionCollection mSoundTriggerSessions;

        HwAudioOutputCollection mHwOutputs;
        SourceClientCollection mAudioSources;

        // for supporting "beacon" streams, i.e. streams that only play on speaker, and never
        // when something other than STREAM_TTS (a.k.a. "Transmitted Through Speaker") is playing
        enum {
            STARTING_OUTPUT,
            STARTING_BEACON,
            STOPPING_OUTPUT,
            STOPPING_BEACON
        };
        uint32_t mBeaconMuteRefCount;   // ref count for stream that would mute beacon
        uint32_t mBeaconPlayingRefCount;// ref count for the playing beacon streams
        bool mBeaconMuted;              // has STREAM_TTS been muted
        // true if a dedicated output for TTS stream or Ultrasound is available
        bool mTtsOutputAvailable;

        bool mMasterMono;               // true if we wish to force all outputs to mono
        AudioPolicyMixCollection mPolicyMixes; // list of registered mixes
        audio_io_handle_t mMusicEffectOutput;     // output selected for music effects

        uint32_t nextAudioPortGeneration();

        // Surround formats that are enabled manually. Taken into account when
        // "encoded surround" is forced into "manual" mode.
        std::unordered_set<audio_format_t> mManualSurroundFormats;

        std::unordered_map<uid_t, audio_flags_mask_t> mAllowedCapturePolicies;

        // The map of device descriptor and formats reported by the device.
        std::map<wp<DeviceDescriptor>, FormatVector> mReportedFormatsMap;

        // Cached product strategy ID corresponding to legacy strategy STRATEGY_PHONE
        product_strategy_t mCommunnicationStrategy;

        // The port handle of the hardware audio source created internally for the Call RX audio
        // end point.
        sp<SourceClientDescriptor> mCallRxSourceClient;
        sp<SourceClientDescriptor> mCallTxSourceClient;

        std::map<audio_port_handle_t,
                 std::map<product_strategy_t,
                          sp<PreferredMixerAttributesInfo>>> mPreferredMixerAttrInfos;

        // Support for Multi-Stream Decoder (MSD) module
        sp<DeviceDescriptor> getMsdAudioInDevice() const;
        DeviceVector getMsdAudioOutDevices() const;
        const AudioPatchCollection getMsdOutputPatches() const;
        status_t getMsdProfiles(bool hwAvSync,
                const InputProfileCollection &inputProfiles,
                const OutputProfileCollection &outputProfiles,
                const sp<DeviceDescriptor> &sourceDevice,
                const sp<DeviceDescriptor> &sinkDevice,
                AudioProfileVector &sourceProfiles,
                AudioProfileVector &sinkProfiles) const;
        status_t getBestMsdConfig(bool hwAvSync,
                const AudioProfileVector &sourceProfiles,
                const AudioProfileVector &sinkProfiles,
                audio_port_config *sourceConfig,
                audio_port_config *sinkConfig) const;
        PatchBuilder buildMsdPatch(bool msdIsSource, const sp<DeviceDescriptor> &device) const;
        status_t setMsdOutputPatches(const DeviceVector *outputDevices = nullptr);
        void releaseMsdOutputPatches(const DeviceVector& devices);
        bool msdHasPatchesToAllDevices(const AudioDeviceTypeAddrVector& devices);

        // Overload of setDeviceConnectionState()
        status_t setDeviceConnectionState(audio_devices_t deviceType,
                                          audio_policy_dev_state_t state,
                                          const char* device_address, const char* device_name,
                                          audio_format_t encodedFormat);

        // Called by setDeviceConnectionState()
        status_t deviceToAudioPort(audio_devices_t deviceType, const char* device_address,
                                   const char* device_name, media::AudioPortFw* aidPort);
        bool isMsdPatch(const audio_patch_handle_t &handle) const;

private:
        sp<SourceClientDescriptor> startAudioSourceInternal(
                const struct audio_port_config *source, const audio_attributes_t *attributes,
                uid_t uid);

        void onNewAudioModulesAvailableInt(DeviceVector *newDevices);

        // Add or remove AC3 DTS encodings based on user preferences.
        void modifySurroundFormats(const sp<DeviceDescriptor>& devDesc, FormatVector *formatsPtr);
        void modifySurroundChannelMasks(ChannelMaskSet *channelMasksPtr);

        // If any, resolve any "dynamic" fields of an Audio Profiles collection
        void updateAudioProfiles(const sp<DeviceDescriptor>& devDesc, audio_io_handle_t ioHandle,
                AudioProfileVector &profiles);

        // Notify the policy client to prepare for disconnecting external device.
        void prepareToDisconnectExternalDevice(const sp<DeviceDescriptor> &device);

        // Notify the policy client of any change of device state with AUDIO_IO_HANDLE_NONE,
        // so that the client interprets it as global to audio hardware interfaces.
        // It can give a chance to HAL implementer to retrieve dynamic capabilities associated
        // to this device for example.
        // TODO avoid opening stream to retrieve capabilities of a profile.
        void broadcastDeviceConnectionState(const sp<DeviceDescriptor> &device,
                                            media::DeviceConnectedState state);

        // updates device caching and output for streams that can influence the
        //    routing of notifications
        void handleNotificationRoutingForStream(audio_stream_type_t stream);
        uint32_t curAudioPortGeneration() const { return mAudioPortGeneration; }
        // internal method, get audio_attributes_t from either a source audio_attributes_t
        // or audio_stream_type_t, respectively.
        status_t getAudioAttributes(audio_attributes_t *dstAttr,
                const audio_attributes_t *srcAttr,
                audio_stream_type_t srcStream);
        // internal method, called by getOutputForAttr() and connectAudioSource.
        status_t getOutputForAttrInt(audio_attributes_t *resultAttr,
                audio_io_handle_t *output,
                audio_session_t session,
                const audio_attributes_t *attr,
                audio_stream_type_t *stream,
                uid_t uid,
                audio_config_t *config,
                audio_output_flags_t *flags,
                audio_port_handle_t *selectedDeviceId,
                bool *isRequestedDeviceForExclusiveUse,
                std::vector<sp<AudioPolicyMix>> *secondaryMixes,
                output_type_t *outputType,
                bool *isSpatialized,
                bool *isBitPerfect);
        // internal method to return the output handle for the given device and format
        audio_io_handle_t getOutputForDevices(
                const DeviceVector &devices,
                audio_session_t session,
                const audio_attributes_t *attr,
                const audio_config_t *config,
                audio_output_flags_t *flags,
                bool *isSpatialized,
                sp<PreferredMixerAttributesInfo> prefMixerAttrInfo = nullptr,
                bool forceMutingHaptic = false);

        // Internal method checking if a direct output can be opened matching the requested
        // attributes, flags, config and devices.
        // If NAME_NOT_FOUND is returned, an attempt can be made to open a mixed output.
        status_t openDirectOutput(
                audio_stream_type_t stream,
                audio_session_t session,
                const audio_config_t *config,
                audio_output_flags_t flags,
                const DeviceVector &devices,
                audio_io_handle_t *output);

        /**
         * @brief Queries if some kind of spatialization will be performed if the audio playback
         * context described by the provided arguments is present.
         * The context is made of:
         * - The audio attributes describing the playback use case.
         * - The audio configuration describing the audio format, channels, sampling rate ...
         * - The devices describing the sink audio device selected for playback.
         * All arguments are optional and only the specified arguments are used to match against
         * supported criteria. For instance, supplying no argument will tell if spatialization is
         * supported or not in general.
         * @param attr audio attributes describing the playback use case
         * @param config audio configuration describing the audio format, channels, sample rate...
         * @param devices the sink audio device selected for playback
         * @return true if spatialization is possible for this context, false otherwise.
         */
        virtual bool canBeSpatializedInt(const audio_attributes_t *attr,
                                      const audio_config_t *config,
                                      const AudioDeviceTypeAddrVector &devices) const;


        /**
         * @brief Gets an IOProfile for a spatializer output with the best match with
         * provided arguments.
         * The caller can have the devices criteria ignored by passing and empty vector, and
         * getSpatializerOutputProfile() will ignore the devices when looking for a match.
         * Otherwise an output profile supporting a spatializer effect that can be routed
         * to the specified devices must exist.
         * @param config audio configuration describing the audio format, channels, sample rate...
         * @param devices the sink audio device selected for playback
         * @return an IOProfile that canbe used to open a spatializer output.
         */
        sp<IOProfile> getSpatializerOutputProfile(const audio_config_t *config,
                                                  const AudioDeviceTypeAddrVector &devices) const;

        void checkVirtualizerClientRoutes();

        /**
         * @brief Returns true if at least one device can only be reached via the output passed
         * as argument. Always returns false for duplicated outputs.
         * This can be used to decide if an output can be closed without forbidding
         * playback to any given device.
         * @param outputDesc the output to consider
         * @return true if at least one device can only be reached via the output.
         */
        bool isOutputOnlyAvailableRouteToSomeDevice(const sp<SwAudioOutputDescriptor>& outputDesc);

        /**
         * @brief getInputForDevice selects an input handle for a given input device and
         * requester context
         * @param device to be used by requester, selected by policy mix rules or engine
         * @param session requester session id
         * @param uid requester uid
         * @param attributes requester audio attributes (e.g. input source and tags matter)
         * @param config requested audio configuration (e.g. sample rate, format, channel mask),
         *               will be updated if current configuration doesn't support but another
         *               one does
         * @param flags requester input flags
         * @param policyMix may be null, policy rules to be followed by the requester
         * @return input io handle aka unique input identifier selected for this device.
         */
        audio_io_handle_t getInputForDevice(const sp<DeviceDescriptor> &device,
                audio_session_t session,
                const audio_attributes_t &attributes,
                audio_config_base_t *config,
                audio_input_flags_t flags,
                const sp<AudioPolicyMix> &policyMix);

        // event is one of STARTING_OUTPUT, STARTING_BEACON, STOPPING_OUTPUT, STOPPING_BEACON
        // returns 0 if no mute/unmute event happened, the largest latency of the device where
        //   the mute/unmute happened
        uint32_t handleEventForBeacon(int event);
        uint32_t setBeaconMute(bool mute);
        bool     isValidAttributes(const audio_attributes_t *paa);

        // Called by setDeviceConnectionState().
        status_t setDeviceConnectionStateInt(audio_policy_dev_state_t state,
                                             const android::media::audio::common::AudioPort& port,
                                             audio_format_t encodedFormat);
        status_t setDeviceConnectionStateInt(audio_devices_t deviceType,
                                             audio_policy_dev_state_t state,
                                             const char *device_address,
                                             const char *device_name,
                                             audio_format_t encodedFormat);
        status_t setDeviceConnectionStateInt(const sp<DeviceDescriptor> &device,
                                             audio_policy_dev_state_t state);

        void setEngineDeviceConnectionState(const sp<DeviceDescriptor> device,
                                      audio_policy_dev_state_t state);

        void updateMono(audio_io_handle_t output) {
            AudioParameter param;
            param.addInt(String8(AudioParameter::keyMonoOutput), (int)mMasterMono);
            mpClientInterface->setParameters(output, param.toString());
        }

        /**
         * @brief createAudioPatchInternal internal function to manage audio patch creation
         * @param[in] patch structure containing sink and source ports configuration
         * @param[out] handle patch handle to be provided if patch installed correctly
         * @param[in] uid of the client
         * @param[in] delayMs if required
         * @param[in] sourceDesc source client to be configured when creating the patch, i.e.
         *            assigning an Output (HW or SW) used for volume control.
         * @return NO_ERROR if patch installed correctly, error code otherwise.
         */
        status_t createAudioPatchInternal(const struct audio_patch *patch,
                                          audio_patch_handle_t *handle,
                                          uid_t uid, uint32_t delayMs,
                                          const sp<SourceClientDescriptor>& sourceDesc);
        /**
         * @brief releaseAudioPatchInternal internal function to remove an audio patch
         * @param[in] handle of the patch to be removed
         * @param[in] delayMs if required
         * @param[in] sourceDesc [optional] in case of external source, source client to be
         * unrouted from the patch, i.e. assigning an Output (HW or SW)
         * @return NO_ERROR if patch removed correctly, error code otherwise.
         */
        status_t releaseAudioPatchInternal(audio_patch_handle_t handle,
                                           uint32_t delayMs = 0,
                                           const sp<SourceClientDescriptor>& sourceDesc = nullptr);

        status_t installPatch(const char *caller,
                audio_patch_handle_t *patchHandle,
                AudioIODescriptorInterface *ioDescriptor,
                const struct audio_patch *patch,
                int delayMs);
        status_t installPatch(const char *caller,
                ssize_t index,
                audio_patch_handle_t *patchHandle,
                const struct audio_patch *patch,
                int delayMs,
                uid_t uid,
                sp<AudioPatch> *patchDescPtr);

        bool areAllDevicesSupported(
                const AudioDeviceTypeAddrVector& devices,
                std::function<bool(audio_devices_t)> predicate,
                const char* context,
                bool matchAddress = true);

        /**
         * @brief changeOutputDevicesMuteState mute/unmute devices using checkDeviceMuteStrategies
         * @param devices devices to mute/unmute
         */
        void changeOutputDevicesMuteState(const AudioDeviceTypeAddrVector& devices);

        /**
         * @brief Returns a vector of software output descriptor that support the queried devices
         * @param devices devices to query
         * @param openOutputs open outputs where the devices are supported as determined by
         *      SwAudioOutputDescriptor::supportsAtLeastOne
         */
        std::vector<sp<SwAudioOutputDescriptor>> getSoftwareOutputsForDevices(
                const AudioDeviceTypeAddrVector& devices) const;

        bool isScoRequestedForComm() const;

        bool isHearingAidUsedForComm() const;

        bool areAllActiveTracksRerouted(const sp<SwAudioOutputDescriptor>& output);

        /**
         * @brief Opens an output stream from the supplied IOProfile and route it to the
         * supplied audio devices. If a mixer config is specified, it is forwarded to audio
         * flinger. If not, a default config is derived from the output stream config.
         * Also opens a duplicating output if needed and queries the audio HAL for supported
         * audio profiles if the IOProfile is dynamic.
         * @param[in] profile IOProfile to use as template
         * @param[in] devices initial route to apply to this output stream
         * @param[in] mixerConfig if not null, use this to configure the mixer
         * @param[in] halConfig if not null, use this to configure the HAL
         * @param[in] flags the flags to be used to open the output
         * @return an output descriptor for the newly opened stream or null in case of error.
         */
        sp<SwAudioOutputDescriptor> openOutputWithProfileAndDevice(
                const sp<IOProfile>& profile, const DeviceVector& devices,
                const audio_config_base_t *mixerConfig = nullptr,
                const audio_config_t *halConfig = nullptr,
                audio_output_flags_t flags = AUDIO_OUTPUT_FLAG_NONE);

        bool isOffloadPossible(const audio_offload_info_t& offloadInfo,
                               bool durationIgnored = false);

        // adds the profiles from the outputProfile to the passed audioProfilesVector
        // without duplicating them if already present
        void addPortProfilesToVector(sp<IOProfile> outputProfile,
                                    AudioProfileVector& audioProfilesVector);

        // Searches for a compatible profile with the sample rate, audio format and channel mask
        // in the list of passed HwModule(s).
        // returns a compatible profile if found, nullptr otherwise
        sp<IOProfile> searchCompatibleProfileHwModules (
                                            const HwModuleCollection& hwModules,
                                            const DeviceVector& devices,
                                            uint32_t samplingRate,
                                            audio_format_t format,
                                            audio_channel_mask_t channelMask,
                                            audio_output_flags_t flags,
                                            bool directOnly);

        // Filters only the relevant flags for getProfileForOutput
        audio_output_flags_t getRelevantFlags (audio_output_flags_t flags, bool directOnly);

        status_t getDevicesForAttributes(const audio_attributes_t &attr,
                                         DeviceVector &devices,
                                         bool forVolume);

        status_t getProfilesForDevices(const DeviceVector& devices,
                                       AudioProfileVector& audioProfiles,
                                       uint32_t flags,
                                       bool isInput);

        /**
         * Returns the preferred mixer attributes info for the given device port id and strategy.
         * Bit-perfect mixer attributes will be returned if it is active and
         * `activeBitPerfectPreferred` is true.
         */
        sp<PreferredMixerAttributesInfo> getPreferredMixerAttributesInfo(
                audio_port_handle_t devicePortId,
                product_strategy_t strategy,
                bool activeBitPerfectPreferred = false);

        sp<SwAudioOutputDescriptor> reopenOutput(
                sp<SwAudioOutputDescriptor> outputDesc,
                const audio_config_t *config,
                audio_output_flags_t flags,
                const char* caller);

        void reopenOutputsWithDevices(
                const std::map<audio_io_handle_t, DeviceVector>& outputsToReopen);

        PortHandleVector getClientsForStream(audio_stream_type_t streamType) const;
        void invalidateStreams(StreamTypeVector streams) const;
};

};
