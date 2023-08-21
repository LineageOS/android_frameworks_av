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

#ifndef ANDROID_AUDIO_FLINGER_H
#define ANDROID_AUDIO_FLINGER_H

#include "Configuration.h"
#include <atomic>
#include <mutex>
#include <chrono>
#include <deque>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <string>
#include <vector>
#include <stdint.h>
#include <sys/types.h>
#include <limits.h>

#include <android/media/BnAudioTrack.h>
#include <android/media/IAudioFlingerClient.h>
#include <android/media/IAudioTrackCallback.h>
#include <android/os/BnExternalVibrationController.h>
#include <android/content/AttributionSourceState.h>


#include <android-base/macros.h>
#include <cutils/atomic.h>
#include <cutils/compiler.h>

#include <cutils/properties.h>
#include <media/IAudioFlinger.h>
#include <media/AudioSystem.h>
#include <media/AudioTrack.h>
#include <media/MmapStreamInterface.h>
#include <media/MmapStreamCallback.h>

#include <utils/Errors.h>
#include <utils/threads.h>
#include <utils/SortedVector.h>
#include <utils/TypeHelpers.h>
#include <utils/Vector.h>

#include <binder/AppOpsManager.h>
#include <binder/BinderService.h>
#include <binder/IAppOpsCallback.h>
#include <binder/MemoryDealer.h>

#include <system/audio.h>
#include <system/audio_policy.h>

#include <media/audiohal/EffectBufferHalInterface.h>
#include <media/audiohal/StreamHalInterface.h>
#include <media/AudioBufferProvider.h>
#include <media/AudioContainers.h>
#include <media/AudioDeviceTypeAddr.h>
#include <media/AudioMixer.h>
#include <media/DeviceDescriptorBase.h>
#include <media/ExtendedAudioBufferProvider.h>
#include <media/VolumeShaper.h>
#include <mediautils/ServiceUtilities.h>
#include <mediautils/SharedMemoryAllocator.h>
#include <mediautils/Synchronization.h>
#include <mediautils/ThreadSnapshot.h>

#include <afutils/AllocatorFactory.h>
#include <afutils/AudioWatchdog.h>
#include <afutils/NBAIO_Tee.h>

#include <audio_utils/clock.h>
#include <audio_utils/FdToString.h>
#include <audio_utils/LinearMap.h>
#include <audio_utils/MelAggregator.h>
#include <audio_utils/MelProcessor.h>
#include <audio_utils/SimpleLog.h>
#include <audio_utils/TimestampVerifier.h>

#include <sounddose/SoundDoseManager.h>
#include <timing/MonotonicFrameCounter.h>
#include <timing/SyncEvent.h>
#include <timing/SynchronizedRecordState.h>

#include <datapath/AudioHwDevice.h>
#include <datapath/AudioStreamIn.h>
#include <datapath/AudioStreamOut.h>
#include <datapath/SpdifStreamOut.h>
#include <datapath/ThreadMetrics.h>
#include <datapath/TrackMetrics.h>
#include <datapath/VolumeInterface.h>
#include <fastpath/FastCapture.h>
#include <fastpath/FastMixer.h>
#include <media/nbaio/NBAIO.h>

#include <android/os/IPowerManager.h>

#include <media/nblog/NBLog.h>
#include <private/media/AudioEffectShared.h>
#include <private/media/AudioTrackShared.h>

#include <vibrator/ExternalVibration.h>
#include <vibrator/ExternalVibrationUtils.h>

#include "android/media/BnAudioRecord.h"
#include "android/media/BnEffect.h"

#include "Client.h"
#include "ResamplerBufferProvider.h"

// include AudioFlinger component interfaces
#include "IAfPatchPanel.h"  // this should be listed before other IAf* interfaces.
#include "IAfEffect.h"
#include "IAfThread.h"
#include "IAfTrack.h"

// Classes that depend on IAf* interfaces but are not cross-dependent.
#include "PatchCommandThread.h"
#include "DeviceEffectManager.h"
#include "MelReporter.h"

namespace android {

class AudioMixer;
class AudioBuffer;
class AudioResampler;
class DeviceHalInterface;
class DevicesFactoryHalCallback;
class DevicesFactoryHalInterface;
class EffectsFactoryHalInterface;
class FastMixer;
class IAudioManager;
class PassthruBufferProvider;
class ServerProxy;

// ----------------------------------------------------------------------------

static const nsecs_t kDefaultStandbyTimeInNsecs = seconds(3);

using android::content::AttributionSourceState;

struct stream_type_t {
    float volume = 1.f;
    bool mute = false;
};

class AudioFlinger
    : public AudioFlingerServerAdapter::Delegate  // IAudioFlinger client interface
{
    friend class sp<AudioFlinger>;
    // TODO(b/291319167) Create interface and remove friends.
    friend class Client; // removeClient_l();
    friend class DeviceEffectManager;
    friend class DeviceEffectManagerCallback;
    friend class MelReporter;
    friend class PatchPanel;
    // TODO(b/291012167) replace the Thread friends with an interface.
    friend class DirectOutputThread;
    friend class MixerThread;
    friend class MmapPlaybackThread;
    friend class MmapThread;
    friend class PlaybackThread;
    friend class RecordThread;
    friend class ThreadBase;

public:
    static void instantiate() ANDROID_API;

    static AttributionSourceState checkAttributionSourcePackage(
        const AttributionSourceState& attributionSource);

    // ---- begin IAudioFlinger interface

    status_t dump(int fd, const Vector<String16>& args) final;

    status_t createTrack(const media::CreateTrackRequest& input,
                         media::CreateTrackResponse& output) final;

    status_t createRecord(const media::CreateRecordRequest& input,
                          media::CreateRecordResponse& output) final;

    uint32_t sampleRate(audio_io_handle_t ioHandle) const final;
    audio_format_t format(audio_io_handle_t output) const final;
    size_t frameCount(audio_io_handle_t ioHandle) const final;
    size_t frameCountHAL(audio_io_handle_t ioHandle) const final;
    uint32_t latency(audio_io_handle_t output) const final;

    status_t setMasterVolume(float value) final;
    status_t setMasterMute(bool muted) final;
    float masterVolume() const final;
    bool masterMute() const final;

    // Balance value must be within -1.f (left only) to 1.f (right only) inclusive.
    status_t setMasterBalance(float balance) final;
    status_t getMasterBalance(float* balance) const final;

    status_t setStreamVolume(audio_stream_type_t stream, float value,
            audio_io_handle_t output) final;
    status_t setStreamMute(audio_stream_type_t stream, bool muted) final;

    float streamVolume(audio_stream_type_t stream,
            audio_io_handle_t output) const final;
    bool streamMute(audio_stream_type_t stream) const final;

    status_t setMode(audio_mode_t mode) final;

    status_t setMicMute(bool state) final;
    bool getMicMute() const final;

    void setRecordSilenced(audio_port_handle_t portId, bool silenced) final;

    status_t setParameters(audio_io_handle_t ioHandle, const String8& keyValuePairs) final;
    String8 getParameters(audio_io_handle_t ioHandle, const String8& keys) const final;

    void registerClient(const sp<media::IAudioFlingerClient>& client) final;
    size_t getInputBufferSize(uint32_t sampleRate, audio_format_t format,
            audio_channel_mask_t channelMask) const final;

    status_t openOutput(const media::OpenOutputRequest& request,
            media::OpenOutputResponse* response) final;

    audio_io_handle_t openDuplicateOutput(audio_io_handle_t output1,
            audio_io_handle_t output2) final;

    status_t closeOutput(audio_io_handle_t output) final;

    status_t suspendOutput(audio_io_handle_t output) final;

    status_t restoreOutput(audio_io_handle_t output) final;

    status_t openInput(const media::OpenInputRequest& request,
            media::OpenInputResponse* response) final;

    status_t closeInput(audio_io_handle_t input) final;

    status_t setVoiceVolume(float volume) final;

    status_t getRenderPosition(uint32_t* halFrames, uint32_t* dspFrames,
            audio_io_handle_t output) const final;

    uint32_t getInputFramesLost(audio_io_handle_t ioHandle) const final;

    // This is the binder API.  For the internal API see nextUniqueId().
    audio_unique_id_t newAudioUniqueId(audio_unique_id_use_t use) final;

    void acquireAudioSessionId(audio_session_t audioSession, pid_t pid, uid_t uid) final;

    void releaseAudioSessionId(audio_session_t audioSession, pid_t pid) final;

    status_t queryNumberEffects(uint32_t* numEffects) const final;

    status_t queryEffect(uint32_t index, effect_descriptor_t* descriptor) const final;

    status_t getEffectDescriptor(const effect_uuid_t* pUuid,
            const effect_uuid_t* pTypeUuid,
            uint32_t preferredTypeFlag,
            effect_descriptor_t* descriptor) const final;

    status_t createEffect(const media::CreateEffectRequest& request,
            media::CreateEffectResponse* response) final;

    status_t moveEffects(audio_session_t sessionId, audio_io_handle_t srcOutput,
            audio_io_handle_t dstOutput) final;

    void setEffectSuspended(int effectId,
            audio_session_t sessionId,
            bool suspended) final;

    audio_module_handle_t loadHwModule(const char* name) final;

    uint32_t getPrimaryOutputSamplingRate() const final;
    size_t getPrimaryOutputFrameCount() const final;

    status_t setLowRamDevice(bool isLowRamDevice, int64_t totalMemory) final;

    /* Get attributes for a given audio port */
    status_t getAudioPort(struct audio_port_v7* port) const final;

    /* Create an audio patch between several source and sink ports */
    status_t createAudioPatch(const struct audio_patch *patch,
            audio_patch_handle_t* handle) final;

    /* Release an audio patch */
    status_t releaseAudioPatch(audio_patch_handle_t handle) final;

    /* List existing audio patches */
    status_t listAudioPatches(unsigned int* num_patches,
            struct audio_patch* patches) const final;

    /* Set audio port configuration */
    status_t setAudioPortConfig(const struct audio_port_config* config) final;

    /* Get the HW synchronization source used for an audio session */
    audio_hw_sync_t getAudioHwSyncForSession(audio_session_t sessionId) final;

    /* Indicate JAVA services are ready (scheduling, power management ...) */
    status_t systemReady() final;
    status_t audioPolicyReady() final { mAudioPolicyReady.store(true); return NO_ERROR; }

    status_t getMicrophones(std::vector<media::MicrophoneInfoFw>* microphones) const final;

    status_t setAudioHalPids(const std::vector<pid_t>& pids) final;

    status_t setVibratorInfos(const std::vector<media::AudioVibratorInfo>& vibratorInfos) final;

    status_t updateSecondaryOutputs(
            const TrackSecondaryOutputsMap& trackSecondaryOutputs) final;

    status_t getMmapPolicyInfos(
            media::audio::common::AudioMMapPolicyType policyType,
            std::vector<media::audio::common::AudioMMapPolicyInfo>* policyInfos) override;

    int32_t getAAudioMixerBurstCount() const final;

    int32_t getAAudioHardwareBurstMinUsec() const final;

    status_t setDeviceConnectedState(const struct audio_port_v7* port,
            media::DeviceConnectedState state) final;

    status_t setSimulateDeviceConnections(bool enabled) final;

    status_t setRequestedLatencyMode(
            audio_io_handle_t output, audio_latency_mode_t mode) final;

    status_t getSupportedLatencyModes(audio_io_handle_t output,
            std::vector<audio_latency_mode_t>* modes) const final;

    status_t setBluetoothVariableLatencyEnabled(bool enabled) final;

    status_t isBluetoothVariableLatencyEnabled(bool* enabled) const final;

    status_t supportsBluetoothVariableLatency(bool* support) const final;

    status_t getSoundDoseInterface(const sp<media::ISoundDoseCallback>& callback,
            sp<media::ISoundDose>* soundDose) const final;

    status_t invalidateTracks(const std::vector<audio_port_handle_t>& portIds) final;

    status_t getAudioPolicyConfig(media::AudioPolicyConfig* config) final;

    status_t onTransactWrapper(TransactionCode code, const Parcel& data, uint32_t flags,
            const std::function<status_t()>& delegate) final;

    // ---- end of IAudioFlinger interface

    bool isAudioPolicyReady() const { return mAudioPolicyReady.load(); }

    /* List available audio ports and their attributes */
    status_t listAudioPorts(unsigned int* num_ports, struct audio_port* ports) const;

    sp<NBLog::Writer>   newWriter_l(size_t size, const char *name);
    void                unregisterWriter(const sp<NBLog::Writer>& writer);
    sp<EffectsFactoryHalInterface> getEffectsFactory();

    status_t openMmapStream(MmapStreamInterface::stream_direction_t direction,
                            const audio_attributes_t *attr,
                            audio_config_base_t *config,
                            const AudioClient& client,
                            audio_port_handle_t *deviceId,
                            audio_session_t *sessionId,
                            const sp<MmapStreamCallback>& callback,
                            sp<MmapStreamInterface>& interface,
                            audio_port_handle_t *handle);

    static os::HapticScale onExternalVibrationStart(
        const sp<os::ExternalVibration>& externalVibration);
    static void onExternalVibrationStop(const sp<os::ExternalVibration>& externalVibration);

    status_t addEffectToHal(
            const struct audio_port_config *device, const sp<EffectHalInterface>& effect);
    status_t removeEffectFromHal(
            const struct audio_port_config *device, const sp<EffectHalInterface>& effect);

    void updateDownStreamPatches_l(const struct audio_patch *patch,
                                   const std::set<audio_io_handle_t>& streams);

    std::optional<media::AudioVibratorInfo> getDefaultVibratorInfo_l();

private:
    // FIXME The 400 is temporarily too high until a leak of writers in media.log is fixed.
    static const size_t kLogMemorySize = 400 * 1024;
    sp<MemoryDealer>    mLogMemoryDealer;   // == 0 when NBLog is disabled
    // When a log writer is unregistered, it is done lazily so that media.log can continue to see it
    // for as long as possible.  The memory is only freed when it is needed for another log writer.
    Vector< sp<NBLog::Writer> > mUnregisteredWriters;
    Mutex               mUnregisteredWritersLock;

public:
    // Life cycle of gAudioFlinger and AudioFlinger:
    //
    // AudioFlinger is created once and survives until audioserver crashes
    // irrespective of sp<> and wp<> as it is refcounted by ServiceManager and we
    // don't issue a ServiceManager::tryUnregisterService().
    //
    // gAudioFlinger is an atomic pointer set on AudioFlinger::onFirstRef().
    // After this is set, it is safe to obtain a wp<> or sp<> from it as the
    // underlying object does not go away.
    //
    // Note: For most inner classes, it is acceptable to hold a reference to the outer
    // AudioFlinger instance as creation requires AudioFlinger to exist in the first place.
    //
    // An atomic here ensures underlying writes have completed before setting
    // the pointer. Access by memory_order_seq_cst.
    //

    static inline std::atomic<AudioFlinger *> gAudioFlinger = nullptr;

    sp<audioflinger::SyncEvent> createSyncEvent(AudioSystem::sync_event_t type,
                                        audio_session_t triggerSession,
                                        audio_session_t listenerSession,
                                        const audioflinger::SyncEventCallback& callBack,
                                        const wp<IAfTrackBase>& cookie);

    bool        btNrecIsOff() const { return mBtNrecIsOff.load(); }

    void             lock() ACQUIRE(mLock) { mLock.lock(); }
    void             unlock() RELEASE(mLock) { mLock.unlock(); }

private:

               audio_mode_t getMode() const { return mMode; }

                            AudioFlinger() ANDROID_API;
    ~AudioFlinger() override;

    // call in any IAudioFlinger method that accesses mPrimaryHardwareDev
    status_t                initCheck() const { return mPrimaryHardwareDev == NULL ?
                                                        NO_INIT : NO_ERROR; }

    // RefBase
    void onFirstRef() override;

    AudioHwDevice*          findSuitableHwDev_l(audio_module_handle_t module,
                                                audio_devices_t deviceType);

    // Set kEnableExtendedChannels to true to enable greater than stereo output
    // for the MixerThread and device sink.  Number of channels allowed is
    // FCC_2 <= channels <= AudioMixer::MAX_NUM_CHANNELS.
    static const bool kEnableExtendedChannels = true;

    // Returns true if channel mask is permitted for the PCM sink in the MixerThread
    static inline bool isValidPcmSinkChannelMask(audio_channel_mask_t channelMask) {
        switch (audio_channel_mask_get_representation(channelMask)) {
        case AUDIO_CHANNEL_REPRESENTATION_POSITION: {
            // Haptic channel mask is only applicable for channel position mask.
            const uint32_t channelCount = audio_channel_count_from_out_mask(
                    static_cast<audio_channel_mask_t>(channelMask & ~AUDIO_CHANNEL_HAPTIC_ALL));
            const uint32_t maxChannelCount = kEnableExtendedChannels
                    ? AudioMixer::MAX_NUM_CHANNELS : FCC_2;
            if (channelCount < FCC_2 // mono is not supported at this time
                    || channelCount > maxChannelCount) {
                return false;
            }
            // check that channelMask is the "canonical" one we expect for the channelCount.
            return audio_channel_position_mask_is_out_canonical(channelMask);
            }
        case AUDIO_CHANNEL_REPRESENTATION_INDEX:
            if (kEnableExtendedChannels) {
                const uint32_t channelCount = audio_channel_count_from_out_mask(channelMask);
                if (channelCount >= FCC_2 // mono is not supported at this time
                        && channelCount <= AudioMixer::MAX_NUM_CHANNELS) {
                    return true;
                }
            }
            return false;
        default:
            return false;
        }
    }

    // Set kEnableExtendedPrecision to true to use extended precision in MixerThread
    static const bool kEnableExtendedPrecision = true;

    // Returns true if format is permitted for the PCM sink in the MixerThread
    static inline bool isValidPcmSinkFormat(audio_format_t format) {
        switch (format) {
        case AUDIO_FORMAT_PCM_16_BIT:
            return true;
        case AUDIO_FORMAT_PCM_FLOAT:
        case AUDIO_FORMAT_PCM_24_BIT_PACKED:
        case AUDIO_FORMAT_PCM_32_BIT:
        case AUDIO_FORMAT_PCM_8_24_BIT:
            return kEnableExtendedPrecision;
        default:
            return false;
        }
    }

    // standby delay for MIXER and DUPLICATING playback threads is read from property
    // ro.audio.flinger_standbytime_ms or defaults to kDefaultStandbyTimeInNsecs
    static nsecs_t          mStandbyTimeInNsecs;

    // incremented by 2 when screen state changes, bit 0 == 1 means "off"
    // AudioFlinger::setParameters() updates, other threads read w/o lock
    static uint32_t         mScreenState;

    // Internal dump utilities.
    static const int kDumpLockTimeoutNs = 1 * NANOS_PER_SECOND;
public:
    // TODO(b/291319167) extract to afutils
    static bool dumpTryLock(Mutex& mutex);
private:
    void dumpPermissionDenial(int fd, const Vector<String16>& args);
    void dumpClients(int fd, const Vector<String16>& args);
    void dumpInternals(int fd, const Vector<String16>& args);

    SimpleLog mThreadLog{16}; // 16 Thread history limit

    void dumpToThreadLog_l(const sp<IAfThreadBase>& thread);

    // --- Notification Client ---
    class NotificationClient : public IBinder::DeathRecipient {
    public:
                            NotificationClient(const sp<AudioFlinger>& audioFlinger,
                                                const sp<media::IAudioFlingerClient>& client,
                                                pid_t pid,
                                                uid_t uid);
        virtual             ~NotificationClient();

                sp<media::IAudioFlingerClient> audioFlingerClient() const { return mAudioFlingerClient; }
                pid_t getPid() const { return mPid; }
                uid_t getUid() const { return mUid; }

                // IBinder::DeathRecipient
                virtual     void        binderDied(const wp<IBinder>& who);

    private:
        DISALLOW_COPY_AND_ASSIGN(NotificationClient);

        const sp<AudioFlinger>  mAudioFlinger;
        const pid_t             mPid;
        const uid_t             mUid;
        const sp<media::IAudioFlingerClient> mAudioFlingerClient;
    };

    // --- MediaLogNotifier ---
    // Thread in charge of notifying MediaLogService to start merging.
    // Receives requests from AudioFlinger's binder activity. It is used to reduce the amount of
    // binder calls to MediaLogService in case of bursts of AudioFlinger binder calls.
    class MediaLogNotifier : public Thread {
    public:
        MediaLogNotifier();

        // Requests a MediaLogService notification. It's ignored if there has recently been another
        void requestMerge();
    private:
        // Every iteration blocks waiting for a request, then interacts with MediaLogService to
        // start merging.
        // As every MediaLogService binder call is expensive, once it gets a request it ignores the
        // following ones for a period of time.
        virtual bool threadLoop() override;

        bool mPendingRequests;

        // Mutex and condition variable around mPendingRequests' value
        Mutex       mMutex;
        Condition   mCond;

        // Duration of the sleep period after a processed request
        static const int kPostTriggerSleepPeriod = 1000000;
    };

    const sp<MediaLogNotifier> mMediaLogNotifier;

    // This is a helper that is called during incoming binder calls.
    // Requests media.log to start merging log buffers
    void requestLogMerge();

    // Find io handle by session id.
    // Preference is given to an io handle with a matching effect chain to session id.
    // If none found, AUDIO_IO_HANDLE_NONE is returned.
    template <typename T>
    static audio_io_handle_t findIoHandleBySessionId_l(
            audio_session_t sessionId, const T& threads) {
        audio_io_handle_t io = AUDIO_IO_HANDLE_NONE;

        for (size_t i = 0; i < threads.size(); i++) {
            const uint32_t sessionType = threads.valueAt(i)->hasAudioSession(sessionId);
            if (sessionType != 0) {
                io = threads.keyAt(i);
                if ((sessionType & IAfThreadBase::EFFECT_SESSION) != 0) {
                    break; // effect chain here.
                }
            }
        }
        return io;
    }

    IAfThreadBase* checkThread_l(audio_io_handle_t ioHandle) const;
    sp<IAfThreadBase> checkOutputThread_l(audio_io_handle_t ioHandle) const REQUIRES(mLock);
    IAfPlaybackThread* checkPlaybackThread_l(audio_io_handle_t output) const;
    IAfPlaybackThread* checkMixerThread_l(audio_io_handle_t output) const;
    IAfRecordThread* checkRecordThread_l(audio_io_handle_t input) const;
    IAfMmapThread* checkMmapThread_l(audio_io_handle_t io) const;
              sp<VolumeInterface> getVolumeInterface_l(audio_io_handle_t output) const;
              std::vector<sp<VolumeInterface>> getAllVolumeInterfaces_l() const;

    sp<IAfThreadBase> openInput_l(audio_module_handle_t module,
                                           audio_io_handle_t *input,
                                           audio_config_t *config,
                                           audio_devices_t device,
                                           const char* address,
                                           audio_source_t source,
                                           audio_input_flags_t flags,
                                           audio_devices_t outputDevice,
                                           const String8& outputDeviceAddress);
    sp<IAfThreadBase> openOutput_l(audio_module_handle_t module,
                                          audio_io_handle_t *output,
                                          audio_config_t *halConfig,
                                          audio_config_base_t *mixerConfig,
                                          audio_devices_t deviceType,
                                          const String8& address,
                                          audio_output_flags_t flags);

    void closeOutputFinish(const sp<IAfPlaybackThread>& thread);
    void closeInputFinish(const sp<IAfRecordThread>& thread);

              // no range check, AudioFlinger::mLock held
              bool streamMute_l(audio_stream_type_t stream) const
                                { return mStreamTypes[stream].mute; }
              void ioConfigChanged(audio_io_config_event_t event,
                                   const sp<AudioIoDescriptor>& ioDesc,
                                   pid_t pid = 0);
              void onSupportedLatencyModesChanged(
                    audio_io_handle_t output, const std::vector<audio_latency_mode_t>& modes);

              // Allocate an audio_unique_id_t.
              // Specific types are audio_io_handle_t, audio_session_t, effect ID (int),
              // audio_module_handle_t, and audio_patch_handle_t.
              // They all share the same ID space, but the namespaces are actually independent
              // because there are separate KeyedVectors for each kind of ID.
              // The return value is cast to the specific type depending on how the ID will be used.
              // FIXME This API does not handle rollover to zero (for unsigned IDs),
              //       or from positive to negative (for signed IDs).
              //       Thus it may fail by returning an ID of the wrong sign,
              //       or by returning a non-unique ID.
              // This is the internal API.  For the binder API see newAudioUniqueId().
              audio_unique_id_t nextUniqueId(audio_unique_id_use_t use);

              status_t moveEffectChain_l(audio_session_t sessionId,
            IAfPlaybackThread* srcThread, IAfPlaybackThread* dstThread);

public:
    // TODO(b/291319167) cluster together
              status_t moveAuxEffectToIo(int EffectId,
            const sp<IAfPlaybackThread>& dstThread, sp<IAfPlaybackThread>* srcThread);
private:

              // return thread associated with primary hardware device, or NULL
              IAfPlaybackThread* primaryPlaybackThread_l() const;
              DeviceTypeSet primaryOutputDevice_l() const;

              // return the playback thread with smallest HAL buffer size, and prefer fast
              IAfPlaybackThread* fastPlaybackThread_l() const;

              sp<IAfThreadBase> getEffectThread_l(audio_session_t sessionId, int effectId);

              IAfThreadBase* hapticPlaybackThread_l() const;

              void updateSecondaryOutputsForTrack_l(
                      IAfTrack* track,
                      IAfPlaybackThread* thread,
                      const std::vector<audio_io_handle_t>& secondaryOutputs) const;


                void        removeClient_l(pid_t pid);
                void        removeNotificationClient(pid_t pid);
public:
    // TODO(b/291319167) cluster together
                bool isNonOffloadableGlobalEffectEnabled_l();
private:
                void onNonOffloadableGlobalEffectEnable();
                bool isSessionAcquired_l(audio_session_t audioSession);

                // Store an effect chain to mOrphanEffectChains keyed vector.
                // Called when a thread exits and effects are still attached to it.
                // If effects are later created on the same session, they will reuse the same
                // effect chain and same instances in the effect library.
                // return ALREADY_EXISTS if a chain with the same session already exists in
                // mOrphanEffectChains. Note that this should never happen as there is only one
                // chain for a given session and it is attached to only one thread at a time.
                status_t putOrphanEffectChain_l(const sp<IAfEffectChain>& chain);
                // Get an effect chain for the specified session in mOrphanEffectChains and remove
                // it if found. Returns 0 if not found (this is the most common case).
                sp<IAfEffectChain> getOrphanEffectChain_l(audio_session_t session);
                // Called when the last effect handle on an effect instance is removed. If this
                // effect belongs to an effect chain in mOrphanEffectChains, the chain is updated
                // and removed from mOrphanEffectChains if it does not contain any effect.
                // Return true if the effect was found in mOrphanEffectChains, false otherwise.
public:
// TODO(b/291319167) suggest better grouping
                bool updateOrphanEffectChains(const sp<IAfEffectModule>& effect);
private:
                std::vector< sp<IAfEffectModule> > purgeStaleEffects_l();

                void broadcastParametersToRecordThreads_l(const String8& keyValuePairs);
                void updateOutDevicesForRecordThreads_l(const DeviceDescriptorBaseVector& devices);
                void forwardParametersToDownstreamPatches_l(
                        audio_io_handle_t upStream, const String8& keyValuePairs,
            const std::function<bool(const sp<IAfPlaybackThread>&)>& useThread = nullptr);

    // for mAudioSessionRefs only
    struct AudioSessionRef {
        AudioSessionRef(audio_session_t sessionid, pid_t pid, uid_t uid) :
            mSessionid(sessionid), mPid(pid), mUid(uid), mCnt(1) {}
        const audio_session_t mSessionid;
        const pid_t mPid;
        const uid_t mUid;
        int         mCnt;
    };

public:
    // TODO(b/291319167) access by getter,
    mutable     Mutex                               mLock;
                // protects mClients and mNotificationClients.
                // must be locked after mLock and ThreadBase::mLock if both must be locked
                // avoids acquiring AudioFlinger::mLock from inside thread loop.

    // TODO(b/291319167) access by getter,
    mutable     Mutex                               mClientLock;
private:
                // protected by mClientLock
                DefaultKeyedVector< pid_t, wp<Client> >     mClients;   // see ~Client()

                mutable     Mutex                   mHardwareLock;
                // NOTE: If both mLock and mHardwareLock mutexes must be held,
                // always take mLock before mHardwareLock

                // guarded by mHardwareLock
                AudioHwDevice* mPrimaryHardwareDev;
                DefaultKeyedVector<audio_module_handle_t, AudioHwDevice*>  mAudioHwDevs;

                // These two fields are immutable after onFirstRef(), so no lock needed to access
                sp<DevicesFactoryHalInterface> mDevicesFactoryHal;
                sp<DevicesFactoryHalCallback> mDevicesFactoryHalCallback;

    // for dump, indicates which hardware operation is currently in progress (but not stream ops)
    enum hardware_call_state {
        AUDIO_HW_IDLE = 0,              // no operation in progress
        AUDIO_HW_INIT,                  // init_check
        AUDIO_HW_OUTPUT_OPEN,           // open_output_stream
        AUDIO_HW_OUTPUT_CLOSE,          // unused
        AUDIO_HW_INPUT_OPEN,            // unused
        AUDIO_HW_INPUT_CLOSE,           // unused
        AUDIO_HW_STANDBY,               // unused
        AUDIO_HW_SET_MASTER_VOLUME,     // set_master_volume
        AUDIO_HW_GET_ROUTING,           // unused
        AUDIO_HW_SET_ROUTING,           // unused
        AUDIO_HW_GET_MODE,              // unused
        AUDIO_HW_SET_MODE,              // set_mode
        AUDIO_HW_GET_MIC_MUTE,          // get_mic_mute
        AUDIO_HW_SET_MIC_MUTE,          // set_mic_mute
        AUDIO_HW_SET_VOICE_VOLUME,      // set_voice_volume
        AUDIO_HW_SET_PARAMETER,         // set_parameters
        AUDIO_HW_GET_INPUT_BUFFER_SIZE, // get_input_buffer_size
        AUDIO_HW_GET_MASTER_VOLUME,     // get_master_volume
        AUDIO_HW_GET_PARAMETER,         // get_parameters
        AUDIO_HW_SET_MASTER_MUTE,       // set_master_mute
        AUDIO_HW_GET_MASTER_MUTE,       // get_master_mute
        AUDIO_HW_GET_MICROPHONES,       // getMicrophones
        AUDIO_HW_SET_CONNECTED_STATE,   // setConnectedState
        AUDIO_HW_SET_SIMULATE_CONNECTIONS, // setSimulateDeviceConnections
    };

    mutable     hardware_call_state                 mHardwareStatus;    // for dump only


    DefaultKeyedVector<audio_io_handle_t, sp<IAfPlaybackThread>> mPlaybackThreads;
                stream_type_t                       mStreamTypes[AUDIO_STREAM_CNT];

                // member variables below are protected by mLock
                float                               mMasterVolume;
                bool                                mMasterMute;
                float                               mMasterBalance = 0.f;
                // end of variables protected by mLock

    DefaultKeyedVector<audio_io_handle_t, sp<IAfRecordThread>> mRecordThreads;

                // protected by mClientLock
                DefaultKeyedVector< pid_t, sp<NotificationClient> >    mNotificationClients;

                // updated by atomic_fetch_add_explicit
                volatile atomic_uint_fast32_t       mNextUniqueIds[AUDIO_UNIQUE_ID_USE_MAX];

                audio_mode_t                        mMode;
                std::atomic_bool                    mBtNrecIsOff;

                // protected by mLock
                Vector<AudioSessionRef*> mAudioSessionRefs;

                float       masterVolume_l() const;
                float       getMasterBalance_l() const;
                bool        masterMute_l() const;
                AudioHwDevice* loadHwModule_l(const char *name);

                // sync events awaiting for a session to be created.
                std::list<sp<audioflinger::SyncEvent>> mPendingSyncEvents;

                // Effect chains without a valid thread
                DefaultKeyedVector<audio_session_t, sp<IAfEffectChain>> mOrphanEffectChains;

                // list of sessions for which a valid HW A/V sync ID was retrieved from the HAL
                DefaultKeyedVector< audio_session_t , audio_hw_sync_t >mHwAvSyncIds;

                // list of MMAP stream control threads. Those threads allow for wake lock, routing
                // and volume control for activity on the associated MMAP stream at the HAL.
                // Audio data transfer is directly handled by the client creating the MMAP stream
    DefaultKeyedVector<audio_io_handle_t, sp<IAfMmapThread>> mMmapThreads;

private:
    sp<Client>  registerPid(pid_t pid);    // always returns non-0

    // for use from destructor
    status_t    closeOutput_nonvirtual(audio_io_handle_t output);
    void closeThreadInternal_l(const sp<IAfPlaybackThread>& thread);
    status_t    closeInput_nonvirtual(audio_io_handle_t input);
    void closeThreadInternal_l(const sp<IAfRecordThread>& thread);
    void setAudioHwSyncForSession_l(IAfPlaybackThread* thread, audio_session_t sessionId);

    status_t    checkStreamType(audio_stream_type_t stream) const;

    void        filterReservedParameters(String8& keyValuePairs, uid_t callingUid);
    void        logFilteredParameters(size_t originalKVPSize, const String8& originalKVPs,
                                      size_t rejectedKVPSize, const String8& rejectedKVPs,
                                      uid_t callingUid);

public:
    sp<IAudioManager> getOrCreateAudioManager();

    // These methods read variables atomically without mLock,
    // though the variables are updated with mLock.
    bool    isLowRamDevice() const { return mIsLowRamDevice; }
    size_t getClientSharedHeapSize() const;

private:
    std::atomic<bool> mIsLowRamDevice;
    bool    mIsDeviceTypeKnown;
    int64_t mTotalMemory;
    std::atomic<size_t> mClientSharedHeapSize;
    static constexpr size_t kMinimumClientSharedHeapSizeBytes = 1024 * 1024; // 1MB

    nsecs_t mGlobalEffectEnableTime;  // when a global effect was last enabled

    // protected by mLock
    const sp<IAfPatchPanel> mPatchPanel = IAfPatchPanel::create(this);

public:
    // TODO(b/291319167) access by getter.
    sp<EffectsFactoryHalInterface> mEffectsFactoryHal;
private:

    const sp<PatchCommandThread> mPatchCommandThread;
    sp<DeviceEffectManager> mDeviceEffectManager;
    sp<MelReporter> mMelReporter;

    bool       mSystemReady;
    std::atomic_bool mAudioPolicyReady{};

    mediautils::UidInfo mUidInfo;

    SimpleLog  mRejectedSetParameterLog;
    SimpleLog  mAppSetParameterLog;
    SimpleLog  mSystemSetParameterLog;

    std::vector<media::AudioVibratorInfo> mAudioVibratorInfos;

    static inline constexpr const char *mMetricsId = AMEDIAMETRICS_KEY_AUDIO_FLINGER;

    // Keep in sync with java definition in media/java/android/media/AudioRecord.java
    static constexpr int32_t kMaxSharedAudioHistoryMs = 5000;

    std::map<media::audio::common::AudioMMapPolicyType,
             std::vector<media::audio::common::AudioMMapPolicyInfo>> mPolicyInfos;
    int32_t mAAudioBurstsPerBuffer = 0;
    int32_t mAAudioHwBurstMinMicros = 0;

    /** Interface for interacting with the AudioService. */
    mediautils::atomic_sp<IAudioManager>       mAudioManager;

    // Bluetooth Variable latency control logic is enabled or disabled
    std::atomic_bool mBluetoothLatencyModesEnabled;
};

std::string formatToString(audio_format_t format);
std::string inputFlagsToString(audio_input_flags_t flags);
std::string outputFlagsToString(audio_output_flags_t flags);
std::string devicesToString(audio_devices_t devices);
const char *sourceToString(audio_source_t source);

// ----------------------------------------------------------------------------

} // namespace android

#endif // ANDROID_AUDIO_FLINGER_H
