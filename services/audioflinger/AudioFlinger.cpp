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

#define LOG_TAG "AudioFlinger"
//#define LOG_NDEBUG 0

// Define AUDIO_ARRAYS_STATIC_CHECK to check all audio arrays are correct
#define AUDIO_ARRAYS_STATIC_CHECK 1

#include "Configuration.h"
#include "AudioFlinger.h"
#include "EffectConfiguration.h"

//#define BUFLOG_NDEBUG 0
#include <afutils/BufLog.h>
#include <afutils/DumpTryLock.h>
#include <afutils/Permission.h>
#include <afutils/PropertyUtils.h>
#include <afutils/TypedLogger.h>
#include <android-base/stringprintf.h>
#include <android/media/IAudioPolicyService.h>
#include <audiomanager/IAudioManager.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <cutils/properties.h>
#include <media/AidlConversion.h>
#include <media/AudioParameter.h>
#include <media/AudioValidator.h>
#include <media/IMediaLogService.h>
#include <media/MediaMetricsItem.h>
#include <media/TypeConverter.h>
#include <mediautils/BatteryNotifier.h>
#include <mediautils/MemoryLeakTrackUtil.h>
#include <mediautils/MethodStatistics.h>
#include <mediautils/ServiceUtilities.h>
#include <mediautils/TimeCheck.h>
#include <memunreachable/memunreachable.h>
// required for effect matching
#include <system/audio_effects/effect_aec.h>
#include <system/audio_effects/effect_ns.h>
#include <system/audio_effects/effect_spatializer.h>
#include <system/audio_effects/effect_visualizer.h>
#include <utils/Log.h>

// not needed with the includes above, added to prevent transitive include dependency.
#include <chrono>
#include <thread>

// ----------------------------------------------------------------------------

// Note: the following macro is used for extremely verbose logging message.  In
// order to run with ALOG_ASSERT turned on, we need to have LOG_NDEBUG set to
// 0; but one side effect of this is to turn all LOGV's as well.  Some messages
// are so verbose that we want to suppress them even when we have ALOG_ASSERT
// turned on.  Do not uncomment the #def below unless you really know what you
// are doing and want to see all of the extremely verbose messages.
//#define VERY_VERY_VERBOSE_LOGGING
#ifdef VERY_VERY_VERBOSE_LOGGING
#define ALOGVV ALOGV
#else
#define ALOGVV(a...) do { } while(0)
#endif

namespace android {

using ::android::base::StringPrintf;
using media::IEffectClient;
using media::audio::common::AudioMMapPolicyInfo;
using media::audio::common::AudioMMapPolicyType;
using media::audio::common::AudioMode;
using android::content::AttributionSourceState;
using android::detail::AudioHalVersionInfo;

static const AudioHalVersionInfo kMaxAAudioPropertyDeviceHalVersion =
        AudioHalVersionInfo(AudioHalVersionInfo::Type::HIDL, 7, 1);

static constexpr char kDeadlockedString[] = "AudioFlinger may be deadlocked\n";
static constexpr char kHardwareLockedString[] = "Hardware lock is taken\n";
static constexpr char kClientLockedString[] = "Client lock is taken\n";
static constexpr char kNoEffectsFactory[] = "Effects Factory is absent\n";

static constexpr char kAudioServiceName[] = "audio";

// In order to avoid invalidating offloaded tracks each time a Visualizer is turned on and off
// we define a minimum time during which a global effect is considered enabled.
static const nsecs_t kMinGlobalEffectEnabletimeNs = seconds(7200);

// Keep a strong reference to media.log service around forever.
// The service is within our parent process so it can never die in a way that we could observe.
// These two variables are const after initialization.
static sp<IBinder> sMediaLogServiceAsBinder;
static sp<IMediaLogService> sMediaLogService;

static pthread_once_t sMediaLogOnce = PTHREAD_ONCE_INIT;

static void sMediaLogInit()
{
    sMediaLogServiceAsBinder = defaultServiceManager()->getService(String16("media.log"));
    if (sMediaLogServiceAsBinder != 0) {
        sMediaLogService = interface_cast<IMediaLogService>(sMediaLogServiceAsBinder);
    }
}

// Creates association between Binder code to name for IAudioFlinger.
#define IAUDIOFLINGER_BINDER_METHOD_MACRO_LIST \
BINDER_METHOD_ENTRY(createTrack) \
BINDER_METHOD_ENTRY(createRecord) \
BINDER_METHOD_ENTRY(sampleRate) \
BINDER_METHOD_ENTRY(format) \
BINDER_METHOD_ENTRY(frameCount) \
BINDER_METHOD_ENTRY(latency) \
BINDER_METHOD_ENTRY(setMasterVolume) \
BINDER_METHOD_ENTRY(setMasterMute) \
BINDER_METHOD_ENTRY(masterVolume) \
BINDER_METHOD_ENTRY(masterMute) \
BINDER_METHOD_ENTRY(setStreamVolume) \
BINDER_METHOD_ENTRY(setStreamMute) \
BINDER_METHOD_ENTRY(streamVolume) \
BINDER_METHOD_ENTRY(streamMute) \
BINDER_METHOD_ENTRY(setMode) \
BINDER_METHOD_ENTRY(setMicMute) \
BINDER_METHOD_ENTRY(getMicMute) \
BINDER_METHOD_ENTRY(setRecordSilenced) \
BINDER_METHOD_ENTRY(setParameters) \
BINDER_METHOD_ENTRY(getParameters) \
BINDER_METHOD_ENTRY(registerClient) \
BINDER_METHOD_ENTRY(getInputBufferSize) \
BINDER_METHOD_ENTRY(openOutput) \
BINDER_METHOD_ENTRY(openDuplicateOutput) \
BINDER_METHOD_ENTRY(closeOutput) \
BINDER_METHOD_ENTRY(suspendOutput) \
BINDER_METHOD_ENTRY(restoreOutput) \
BINDER_METHOD_ENTRY(openInput) \
BINDER_METHOD_ENTRY(closeInput) \
BINDER_METHOD_ENTRY(setVoiceVolume) \
BINDER_METHOD_ENTRY(getRenderPosition) \
BINDER_METHOD_ENTRY(getInputFramesLost) \
BINDER_METHOD_ENTRY(newAudioUniqueId) \
BINDER_METHOD_ENTRY(acquireAudioSessionId) \
BINDER_METHOD_ENTRY(releaseAudioSessionId) \
BINDER_METHOD_ENTRY(queryNumberEffects) \
BINDER_METHOD_ENTRY(queryEffect) \
BINDER_METHOD_ENTRY(getEffectDescriptor) \
BINDER_METHOD_ENTRY(createEffect) \
BINDER_METHOD_ENTRY(moveEffects) \
BINDER_METHOD_ENTRY(loadHwModule) \
BINDER_METHOD_ENTRY(getPrimaryOutputSamplingRate) \
BINDER_METHOD_ENTRY(getPrimaryOutputFrameCount) \
BINDER_METHOD_ENTRY(setLowRamDevice) \
BINDER_METHOD_ENTRY(getAudioPort) \
BINDER_METHOD_ENTRY(createAudioPatch) \
BINDER_METHOD_ENTRY(releaseAudioPatch) \
BINDER_METHOD_ENTRY(listAudioPatches) \
BINDER_METHOD_ENTRY(setAudioPortConfig) \
BINDER_METHOD_ENTRY(getAudioHwSyncForSession) \
BINDER_METHOD_ENTRY(systemReady) \
BINDER_METHOD_ENTRY(audioPolicyReady) \
BINDER_METHOD_ENTRY(frameCountHAL) \
BINDER_METHOD_ENTRY(getMicrophones) \
BINDER_METHOD_ENTRY(setMasterBalance) \
BINDER_METHOD_ENTRY(getMasterBalance) \
BINDER_METHOD_ENTRY(setEffectSuspended) \
BINDER_METHOD_ENTRY(setAudioHalPids) \
BINDER_METHOD_ENTRY(setVibratorInfos) \
BINDER_METHOD_ENTRY(updateSecondaryOutputs) \
BINDER_METHOD_ENTRY(getMmapPolicyInfos) \
BINDER_METHOD_ENTRY(getAAudioMixerBurstCount) \
BINDER_METHOD_ENTRY(getAAudioHardwareBurstMinUsec) \
BINDER_METHOD_ENTRY(setDeviceConnectedState) \
BINDER_METHOD_ENTRY(setSimulateDeviceConnections) \
BINDER_METHOD_ENTRY(setRequestedLatencyMode) \
BINDER_METHOD_ENTRY(getSupportedLatencyModes) \
BINDER_METHOD_ENTRY(setBluetoothVariableLatencyEnabled) \
BINDER_METHOD_ENTRY(isBluetoothVariableLatencyEnabled) \
BINDER_METHOD_ENTRY(supportsBluetoothVariableLatency) \
BINDER_METHOD_ENTRY(getSoundDoseInterface) \
BINDER_METHOD_ENTRY(getAudioPolicyConfig) \

// singleton for Binder Method Statistics for IAudioFlinger
static auto& getIAudioFlingerStatistics() {
    using Code = android::AudioFlingerServerAdapter::Delegate::TransactionCode;

#pragma push_macro("BINDER_METHOD_ENTRY")
#undef BINDER_METHOD_ENTRY
#define BINDER_METHOD_ENTRY(ENTRY) \
    {(Code)media::BnAudioFlingerService::TRANSACTION_##ENTRY, #ENTRY},

    static mediautils::MethodStatistics<Code> methodStatistics{
        IAUDIOFLINGER_BINDER_METHOD_MACRO_LIST
        METHOD_STATISTICS_BINDER_CODE_NAMES(Code)
    };
#pragma pop_macro("BINDER_METHOD_ENTRY")

    return methodStatistics;
}

class DevicesFactoryHalCallbackImpl : public DevicesFactoryHalCallback {
  public:
    void onNewDevicesAvailable() override {
        // Start a detached thread to execute notification in parallel.
        // This is done to prevent mutual blocking of audio_flinger and
        // audio_policy services during system initialization.
        std::thread notifier([]() {
            AudioSystem::onNewAudioModulesAvailable();
        });
        notifier.detach();
    }
};

// ----------------------------------------------------------------------------

void AudioFlinger::instantiate() {
    sp<IServiceManager> sm(defaultServiceManager());
    sm->addService(String16(IAudioFlinger::DEFAULT_SERVICE_NAME),
                   new AudioFlingerServerAdapter(new AudioFlinger()), false,
                   IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT);
}

AudioFlinger::AudioFlinger()
    : mMediaLogNotifier(new AudioFlinger::MediaLogNotifier()),
      mPrimaryHardwareDev(NULL),
      mAudioHwDevs(NULL),
      mHardwareStatus(AUDIO_HW_IDLE),
      mMasterVolume(1.0f),
      mMasterMute(false),
      // mNextUniqueId(AUDIO_UNIQUE_ID_USE_MAX),
      mMode(AUDIO_MODE_INVALID),
      mBtNrecIsOff(false),
      mIsLowRamDevice(true),
      mIsDeviceTypeKnown(false),
      mTotalMemory(0),
      mClientSharedHeapSize(kMinimumClientSharedHeapSizeBytes),
      mGlobalEffectEnableTime(0),
      mPatchCommandThread(sp<PatchCommandThread>::make()),
      mSystemReady(false),
      mBluetoothLatencyModesEnabled(true)
{
    // Move the audio session unique ID generator start base as time passes to limit risk of
    // generating the same ID again after an audioserver restart.
    // This is important because clients will reuse previously allocated audio session IDs
    // when reconnecting after an audioserver restart and newly allocated IDs may conflict with
    // active clients.
    // Moving the base by 1 for each elapsed second is a good compromise between avoiding overlap
    // between allocation ranges and not reaching wrap around too soon.
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    // zero ID has a special meaning, so start allocation at least at AUDIO_UNIQUE_ID_USE_MAX
    uint32_t movingBase = (uint32_t)std::max((long)1, ts.tv_sec);
    // unsigned instead of audio_unique_id_use_t, because ++ operator is unavailable for enum
    for (unsigned use = AUDIO_UNIQUE_ID_USE_UNSPECIFIED; use < AUDIO_UNIQUE_ID_USE_MAX; use++) {
        mNextUniqueIds[use] =
                ((use == AUDIO_UNIQUE_ID_USE_SESSION || use == AUDIO_UNIQUE_ID_USE_CLIENT) ?
                        movingBase : 1) * AUDIO_UNIQUE_ID_USE_MAX;
    }

#if 1
    // FIXME See bug 165702394 and bug 168511485
    const bool doLog = false;
#else
    const bool doLog = property_get_bool("ro.test_harness", false);
#endif
    if (doLog) {
        mLogMemoryDealer = new MemoryDealer(kLogMemorySize, "LogWriters",
                MemoryHeapBase::READ_ONLY);
        (void) pthread_once(&sMediaLogOnce, sMediaLogInit);
    }

    // reset battery stats.
    // if the audio service has crashed, battery stats could be left
    // in bad state, reset the state upon service start.
    BatteryNotifier::getInstance().noteResetAudio();

    mDevicesFactoryHal = DevicesFactoryHalInterface::create();
    mEffectsFactoryHal = audioflinger::EffectConfiguration::getEffectsFactoryHal();

    mMediaLogNotifier->run("MediaLogNotifier");
    std::vector<pid_t> halPids;
    mDevicesFactoryHal->getHalPids(&halPids);
    mediautils::TimeCheck::setAudioHalPids(halPids);

    // Notify that we have started (also called when audioserver service restarts)
    mediametrics::LogItem(mMetricsId)
        .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_CTOR)
        .record();
}

void AudioFlinger::onFirstRef()
{
    Mutex::Autolock _l(mLock);

    mMode = AUDIO_MODE_NORMAL;

    gAudioFlinger = this;  // we are already refcounted, store into atomic pointer.
    mDeviceEffectManager = sp<DeviceEffectManager>::make(
            sp<IAfDeviceEffectManagerCallback>::fromExisting(this)),
    mDevicesFactoryHalCallback = new DevicesFactoryHalCallbackImpl;
    mDevicesFactoryHal->setCallbackOnce(mDevicesFactoryHalCallback);

    if (mDevicesFactoryHal->getHalVersion() <= kMaxAAudioPropertyDeviceHalVersion) {
        mAAudioBurstsPerBuffer = getAAudioMixerBurstCountFromSystemProperty();
        mAAudioHwBurstMinMicros = getAAudioHardwareBurstMinUsecFromSystemProperty();
    }

    mPatchPanel = IAfPatchPanel::create(sp<IAfPatchPanelCallback>::fromExisting(this));
    mMelReporter = sp<MelReporter>::make(sp<IAfMelReporterCallback>::fromExisting(this));
}

status_t AudioFlinger::setAudioHalPids(const std::vector<pid_t>& pids) {
  mediautils::TimeCheck::setAudioHalPids(pids);
  return NO_ERROR;
}

status_t AudioFlinger::setVibratorInfos(
        const std::vector<media::AudioVibratorInfo>& vibratorInfos) {
    Mutex::Autolock _l(mLock);
    mAudioVibratorInfos = vibratorInfos;
    return NO_ERROR;
}

status_t AudioFlinger::updateSecondaryOutputs(
        const TrackSecondaryOutputsMap& trackSecondaryOutputs) {
    Mutex::Autolock _l(mLock);
    for (const auto& [trackId, secondaryOutputs] : trackSecondaryOutputs) {
        size_t i = 0;
        for (; i < mPlaybackThreads.size(); ++i) {
            IAfPlaybackThread* thread = mPlaybackThreads.valueAt(i).get();
            Mutex::Autolock _tl(thread->mutex());
            sp<IAfTrack> track = thread->getTrackById_l(trackId);
            if (track != nullptr) {
                ALOGD("%s trackId: %u", __func__, trackId);
                updateSecondaryOutputsForTrack_l(track.get(), thread, secondaryOutputs);
                break;
            }
        }
        ALOGW_IF(i >= mPlaybackThreads.size(),
                 "%s cannot find track with id %u", __func__, trackId);
    }
    return NO_ERROR;
}

status_t AudioFlinger::getMmapPolicyInfos(
            AudioMMapPolicyType policyType, std::vector<AudioMMapPolicyInfo> *policyInfos) {
    Mutex::Autolock _l(mLock);
    if (const auto it = mPolicyInfos.find(policyType); it != mPolicyInfos.end()) {
        *policyInfos = it->second;
        return NO_ERROR;
    }
    if (mDevicesFactoryHal->getHalVersion() > kMaxAAudioPropertyDeviceHalVersion) {
        AutoMutex lock(mHardwareLock);
        for (size_t i = 0; i < mAudioHwDevs.size(); ++i) {
            AudioHwDevice *dev = mAudioHwDevs.valueAt(i);
            std::vector<AudioMMapPolicyInfo> infos;
            status_t status = dev->getMmapPolicyInfos(policyType, &infos);
            if (status != NO_ERROR) {
                ALOGE("Failed to query mmap policy info of %d, error %d",
                      mAudioHwDevs.keyAt(i), status);
                continue;
            }
            policyInfos->insert(policyInfos->end(), infos.begin(), infos.end());
        }
        mPolicyInfos[policyType] = *policyInfos;
    } else {
        getMmapPolicyInfosFromSystemProperty(policyType, policyInfos);
        mPolicyInfos[policyType] = *policyInfos;
    }
    return NO_ERROR;
}

int32_t AudioFlinger::getAAudioMixerBurstCount() const {
    Mutex::Autolock _l(mLock);
    return mAAudioBurstsPerBuffer;
}

int32_t AudioFlinger::getAAudioHardwareBurstMinUsec() const {
    Mutex::Autolock _l(mLock);
    return mAAudioHwBurstMinMicros;
}

status_t AudioFlinger::setDeviceConnectedState(const struct audio_port_v7 *port,
                                               media::DeviceConnectedState state) {
    status_t final_result = NO_INIT;
    Mutex::Autolock _l(mLock);
    AutoMutex lock(mHardwareLock);
    mHardwareStatus = AUDIO_HW_SET_CONNECTED_STATE;
    for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
        sp<DeviceHalInterface> dev = mAudioHwDevs.valueAt(i)->hwDevice();
        status_t result = state == media::DeviceConnectedState::PREPARE_TO_DISCONNECT
                ? dev->prepareToDisconnectExternalDevice(port)
                : dev->setConnectedState(port, state == media::DeviceConnectedState::CONNECTED);
        // Same logic as with setParameter: it's a success if at least one
        // HAL module accepts the update.
        if (final_result != NO_ERROR) {
            final_result = result;
        }
    }
    mHardwareStatus = AUDIO_HW_IDLE;
    return final_result;
}

status_t AudioFlinger::setSimulateDeviceConnections(bool enabled) {
    bool at_least_one_succeeded = false;
    status_t last_error = INVALID_OPERATION;
    Mutex::Autolock _l(mLock);
    AutoMutex lock(mHardwareLock);
    mHardwareStatus = AUDIO_HW_SET_SIMULATE_CONNECTIONS;
    for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
        sp<DeviceHalInterface> dev = mAudioHwDevs.valueAt(i)->hwDevice();
        status_t result = dev->setSimulateDeviceConnections(enabled);
        if (result == OK) {
            at_least_one_succeeded = true;
        } else {
            last_error = result;
        }
    }
    mHardwareStatus = AUDIO_HW_IDLE;
    return at_least_one_succeeded ? OK : last_error;
}

// getDefaultVibratorInfo_l must be called with AudioFlinger lock held.
std::optional<media::AudioVibratorInfo> AudioFlinger::getDefaultVibratorInfo_l() const {
    if (mAudioVibratorInfos.empty()) {
        return {};
    }
    return mAudioVibratorInfos.front();
}

AudioFlinger::~AudioFlinger()
{
    while (!mRecordThreads.isEmpty()) {
        // closeInput_nonvirtual() will remove specified entry from mRecordThreads
        closeInput_nonvirtual(mRecordThreads.keyAt(0));
    }
    while (!mPlaybackThreads.isEmpty()) {
        // closeOutput_nonvirtual() will remove specified entry from mPlaybackThreads
        closeOutput_nonvirtual(mPlaybackThreads.keyAt(0));
    }
    while (!mMmapThreads.isEmpty()) {
        const audio_io_handle_t io = mMmapThreads.keyAt(0);
        if (mMmapThreads.valueAt(0)->isOutput()) {
            closeOutput_nonvirtual(io); // removes entry from mMmapThreads
        } else {
            closeInput_nonvirtual(io);  // removes entry from mMmapThreads
        }
    }

    for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
        // no mHardwareLock needed, as there are no other references to this
        delete mAudioHwDevs.valueAt(i);
    }

    // Tell media.log service about any old writers that still need to be unregistered
    if (sMediaLogService != 0) {
        for (size_t count = mUnregisteredWriters.size(); count > 0; count--) {
            sp<IMemory> iMemory(mUnregisteredWriters.top()->getIMemory());
            mUnregisteredWriters.pop();
            sMediaLogService->unregisterWriter(iMemory);
        }
    }
}

//static
__attribute__ ((visibility ("default")))
status_t MmapStreamInterface::openMmapStream(MmapStreamInterface::stream_direction_t direction,
                                             const audio_attributes_t *attr,
                                             audio_config_base_t *config,
                                             const AudioClient& client,
                                             audio_port_handle_t *deviceId,
                                             audio_session_t *sessionId,
                                             const sp<MmapStreamCallback>& callback,
                                             sp<MmapStreamInterface>& interface,
                                             audio_port_handle_t *handle)
{
    // TODO(b/292281786): Use ServiceManager to get IAudioFlinger instead of by atomic pointer.
    // This allows moving oboeservice (AAudio) to a separate process in the future.
    sp<AudioFlinger> af = AudioFlinger::gAudioFlinger.load();  // either nullptr or singleton AF.
    status_t ret = NO_INIT;
    if (af != 0) {
        ret = af->openMmapStream(
                direction, attr, config, client, deviceId,
                sessionId, callback, interface, handle);
    }
    return ret;
}

status_t AudioFlinger::openMmapStream(MmapStreamInterface::stream_direction_t direction,
                                      const audio_attributes_t *attr,
                                      audio_config_base_t *config,
                                      const AudioClient& client,
                                      audio_port_handle_t *deviceId,
                                      audio_session_t *sessionId,
                                      const sp<MmapStreamCallback>& callback,
                                      sp<MmapStreamInterface>& interface,
                                      audio_port_handle_t *handle)
{
    status_t ret = initCheck();
    if (ret != NO_ERROR) {
        return ret;
    }
    audio_session_t actualSessionId = *sessionId;
    if (actualSessionId == AUDIO_SESSION_ALLOCATE) {
        actualSessionId = (audio_session_t) newAudioUniqueId(AUDIO_UNIQUE_ID_USE_SESSION);
    }
    audio_stream_type_t streamType = AUDIO_STREAM_DEFAULT;
    audio_io_handle_t io = AUDIO_IO_HANDLE_NONE;
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
    audio_attributes_t localAttr = *attr;

    // TODO b/182392553: refactor or make clearer
    pid_t clientPid =
        VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_pid_t(client.attributionSource.pid));
    bool updatePid = (clientPid == (pid_t)-1);
    const uid_t callingUid = IPCThreadState::self()->getCallingUid();

    AttributionSourceState adjAttributionSource = client.attributionSource;
    if (!isAudioServerOrMediaServerOrSystemServerOrRootUid(callingUid)) {
        uid_t clientUid =
            VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_uid_t(client.attributionSource.uid));
        ALOGW_IF(clientUid != callingUid,
                "%s uid %d tried to pass itself off as %d",
                __FUNCTION__, callingUid, clientUid);
        adjAttributionSource.uid = VALUE_OR_RETURN_STATUS(legacy2aidl_uid_t_int32_t(callingUid));
        updatePid = true;
    }
    if (updatePid) {
        const pid_t callingPid = IPCThreadState::self()->getCallingPid();
        ALOGW_IF(clientPid != (pid_t)-1 && clientPid != callingPid,
                 "%s uid %d pid %d tried to pass itself off as pid %d",
                 __func__, callingUid, callingPid, clientPid);
        adjAttributionSource.pid = VALUE_OR_RETURN_STATUS(legacy2aidl_pid_t_int32_t(callingPid));
    }
    adjAttributionSource = afutils::checkAttributionSourcePackage(
            adjAttributionSource);

    if (direction == MmapStreamInterface::DIRECTION_OUTPUT) {
        audio_config_t fullConfig = AUDIO_CONFIG_INITIALIZER;
        fullConfig.sample_rate = config->sample_rate;
        fullConfig.channel_mask = config->channel_mask;
        fullConfig.format = config->format;
        std::vector<audio_io_handle_t> secondaryOutputs;
        bool isSpatialized;
        bool isBitPerfect;
        ret = AudioSystem::getOutputForAttr(&localAttr, &io,
                                            actualSessionId,
                                            &streamType, adjAttributionSource,
                                            &fullConfig,
                                            (audio_output_flags_t)(AUDIO_OUTPUT_FLAG_MMAP_NOIRQ |
                                                    AUDIO_OUTPUT_FLAG_DIRECT),
                                            deviceId, &portId, &secondaryOutputs, &isSpatialized,
                                            &isBitPerfect);
        if (ret != NO_ERROR) {
            config->sample_rate = fullConfig.sample_rate;
            config->channel_mask = fullConfig.channel_mask;
            config->format = fullConfig.format;
        }
        ALOGW_IF(!secondaryOutputs.empty(),
                 "%s does not support secondary outputs, ignoring them", __func__);
    } else {
        ret = AudioSystem::getInputForAttr(&localAttr, &io,
                                              RECORD_RIID_INVALID,
                                              actualSessionId,
                                              adjAttributionSource,
                                              config,
                                              AUDIO_INPUT_FLAG_MMAP_NOIRQ, deviceId, &portId);
    }
    if (ret != NO_ERROR) {
        return ret;
    }

    // at this stage, a MmapThread was created when openOutput() or openInput() was called by
    // audio policy manager and we can retrieve it
    const sp<IAfMmapThread> thread = mMmapThreads.valueFor(io);
    if (thread != 0) {
        interface = IAfMmapThread::createMmapStreamInterfaceAdapter(thread);
        thread->configure(&localAttr, streamType, actualSessionId, callback, *deviceId, portId);
        *handle = portId;
        *sessionId = actualSessionId;
        config->sample_rate = thread->sampleRate();
        config->channel_mask = thread->channelMask();
        config->format = thread->format();
    } else {
        if (direction == MmapStreamInterface::DIRECTION_OUTPUT) {
            AudioSystem::releaseOutput(portId);
        } else {
            AudioSystem::releaseInput(portId);
        }
        ret = NO_INIT;
    }

    ALOGV("%s done status %d portId %d", __FUNCTION__, ret, portId);

    return ret;
}

status_t AudioFlinger::addEffectToHal(
        const struct audio_port_config *device, const sp<EffectHalInterface>& effect) {
    AutoMutex lock(mHardwareLock);
    AudioHwDevice *audioHwDevice = mAudioHwDevs.valueFor(device->ext.device.hw_module);
    if (audioHwDevice == nullptr) {
        return NO_INIT;
    }
    return audioHwDevice->hwDevice()->addDeviceEffect(device, effect);
}

status_t AudioFlinger::removeEffectFromHal(
        const struct audio_port_config *device, const sp<EffectHalInterface>& effect) {
    AutoMutex lock(mHardwareLock);
    AudioHwDevice *audioHwDevice = mAudioHwDevs.valueFor(device->ext.device.hw_module);
    if (audioHwDevice == nullptr) {
        return NO_INIT;
    }
    return audioHwDevice->hwDevice()->removeDeviceEffect(device, effect);
}

static const char * const audio_interfaces[] = {
    AUDIO_HARDWARE_MODULE_ID_PRIMARY,
    AUDIO_HARDWARE_MODULE_ID_A2DP,
    AUDIO_HARDWARE_MODULE_ID_USB,
};

AudioHwDevice* AudioFlinger::findSuitableHwDev_l(
        audio_module_handle_t module,
        audio_devices_t deviceType)
{
    // if module is 0, the request comes from an old policy manager and we should load
    // well known modules
    AutoMutex lock(mHardwareLock);
    if (module == 0) {
        ALOGW("findSuitableHwDev_l() loading well know audio hw modules");
        for (size_t i = 0; i < arraysize(audio_interfaces); i++) {
            loadHwModule_l(audio_interfaces[i]);
        }
        // then try to find a module supporting the requested device.
        for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
            AudioHwDevice *audioHwDevice = mAudioHwDevs.valueAt(i);
            sp<DeviceHalInterface> dev = audioHwDevice->hwDevice();
            uint32_t supportedDevices;
            if (dev->getSupportedDevices(&supportedDevices) == OK &&
                    (supportedDevices & deviceType) == deviceType) {
                return audioHwDevice;
            }
        }
    } else {
        // check a match for the requested module handle
        AudioHwDevice *audioHwDevice = mAudioHwDevs.valueFor(module);
        if (audioHwDevice != NULL) {
            return audioHwDevice;
        }
    }

    return NULL;
}

void AudioFlinger::dumpClients(int fd, const Vector<String16>& args __unused)
{
    String8 result;

    result.append("Client Allocators:\n");
    for (size_t i = 0; i < mClients.size(); ++i) {
        sp<Client> client = mClients.valueAt(i).promote();
        if (client != 0) {
          result.appendFormat("Client: %d\n", client->pid());
          result.append(client->allocator().dump().c_str());
        }
   }

    result.append("Notification Clients:\n");
    result.append("   pid    uid  name\n");
    for (size_t i = 0; i < mNotificationClients.size(); ++i) {
        const pid_t pid = mNotificationClients[i]->getPid();
        const uid_t uid = mNotificationClients[i]->getUid();
        const mediautils::UidInfo::Info info = mUidInfo.getInfo(uid);
        result.appendFormat("%6d %6u  %s\n", pid, uid, info.package.c_str());
    }

    result.append("Global session refs:\n");
    result.append("  session  cnt     pid    uid  name\n");
    for (size_t i = 0; i < mAudioSessionRefs.size(); i++) {
        AudioSessionRef *r = mAudioSessionRefs[i];
        const mediautils::UidInfo::Info info = mUidInfo.getInfo(r->mUid);
        result.appendFormat("  %7d %4d %7d %6u  %s\n", r->mSessionid, r->mCnt, r->mPid,
                r->mUid, info.package.c_str());
    }
    write(fd, result.c_str(), result.size());
}


void AudioFlinger::dumpInternals(int fd, const Vector<String16>& args __unused)
{
    const size_t SIZE = 256;
    char buffer[SIZE];
    String8 result;
    hardware_call_state hardwareStatus = mHardwareStatus;

    snprintf(buffer, SIZE, "Hardware status: %d\n", hardwareStatus);
    result.append(buffer);
    write(fd, result.c_str(), result.size());

    dprintf(fd, "Vibrator infos(size=%zu):\n", mAudioVibratorInfos.size());
    for (const auto& vibratorInfo : mAudioVibratorInfos) {
        dprintf(fd, "  - %s\n", vibratorInfo.toString().c_str());
    }
    dprintf(fd, "Bluetooth latency modes are %senabled\n",
            mBluetoothLatencyModesEnabled ? "" : "not ");
}

void AudioFlinger::dumpPermissionDenial(int fd, const Vector<String16>& args __unused)
{
    const size_t SIZE = 256;
    char buffer[SIZE];
    String8 result;
    snprintf(buffer, SIZE, "Permission Denial: "
            "can't dump AudioFlinger from pid=%d, uid=%d\n",
            IPCThreadState::self()->getCallingPid(),
            IPCThreadState::self()->getCallingUid());
    result.append(buffer);
    write(fd, result.c_str(), result.size());
}

status_t AudioFlinger::dump(int fd, const Vector<String16>& args)
NO_THREAD_SAFETY_ANALYSIS  // conditional try lock
{
    if (!dumpAllowed()) {
        dumpPermissionDenial(fd, args);
    } else {
        // get state of hardware lock
        const bool hardwareLocked = afutils::dumpTryLock(mHardwareLock);
        if (!hardwareLocked) {
            String8 result(kHardwareLockedString);
            write(fd, result.c_str(), result.size());
        } else {
            mHardwareLock.unlock();
        }

        const bool locked = afutils::dumpTryLock(mLock);

        // failed to lock - AudioFlinger is probably deadlocked
        if (!locked) {
            String8 result(kDeadlockedString);
            write(fd, result.c_str(), result.size());
        }

        const bool clientLocked = afutils::dumpTryLock(mClientLock);
        if (!clientLocked) {
            String8 result(kClientLockedString);
            write(fd, result.c_str(), result.size());
        }

        if (mEffectsFactoryHal != 0) {
            mEffectsFactoryHal->dumpEffects(fd);
        } else {
            String8 result(kNoEffectsFactory);
            write(fd, result.c_str(), result.size());
        }

        dumpClients(fd, args);
        if (clientLocked) {
            mClientLock.unlock();
        }

        dumpInternals(fd, args);

        // dump playback threads
        for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
            mPlaybackThreads.valueAt(i)->dump(fd, args);
        }

        // dump record threads
        for (size_t i = 0; i < mRecordThreads.size(); i++) {
            mRecordThreads.valueAt(i)->dump(fd, args);
        }

        // dump mmap threads
        for (size_t i = 0; i < mMmapThreads.size(); i++) {
            mMmapThreads.valueAt(i)->dump(fd, args);
        }

        // dump orphan effect chains
        if (mOrphanEffectChains.size() != 0) {
            write(fd, "  Orphan Effect Chains\n", strlen("  Orphan Effect Chains\n"));
            for (size_t i = 0; i < mOrphanEffectChains.size(); i++) {
                mOrphanEffectChains.valueAt(i)->dump(fd, args);
            }
        }
        // dump all hardware devs
        for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
            sp<DeviceHalInterface> dev = mAudioHwDevs.valueAt(i)->hwDevice();
            dev->dump(fd, args);
        }

        mPatchPanel->dump(fd);

        mDeviceEffectManager->dump(fd);

        std::string melOutput = mMelReporter->dump();
        write(fd, melOutput.c_str(), melOutput.size());

        // dump external setParameters
        auto dumpLogger = [fd](SimpleLog& logger, const char* name) {
            dprintf(fd, "\n%s setParameters:\n", name);
            logger.dump(fd, "    " /* prefix */);
        };
        dumpLogger(mRejectedSetParameterLog, "Rejected");
        dumpLogger(mAppSetParameterLog, "App");
        dumpLogger(mSystemSetParameterLog, "System");

        // dump historical threads in the last 10 seconds
        const std::string threadLog = mThreadLog.dumpToString(
                "Historical Thread Log ", 0 /* lines */,
                audio_utils_get_real_time_ns() - 10 * 60 * NANOS_PER_SECOND);
        write(fd, threadLog.c_str(), threadLog.size());

        BUFLOG_RESET;

        if (locked) {
            mLock.unlock();
        }

#ifdef TEE_SINK
        // NBAIO_Tee dump is safe to call outside of AF lock.
        NBAIO_Tee::dumpAll(fd, "_DUMP");
#endif
        // append a copy of media.log here by forwarding fd to it, but don't attempt
        // to lookup the service if it's not running, as it will block for a second
        if (sMediaLogServiceAsBinder != 0) {
            dprintf(fd, "\nmedia.log:\n");
            sMediaLogServiceAsBinder->dump(fd, args);
        }

        // check for optional arguments
        bool dumpMem = false;
        bool unreachableMemory = false;
        for (const auto &arg : args) {
            if (arg == String16("-m")) {
                dumpMem = true;
            } else if (arg == String16("--unreachable")) {
                unreachableMemory = true;
            }
        }

        if (dumpMem) {
            dprintf(fd, "\nDumping memory:\n");
            std::string s = dumpMemoryAddresses(100 /* limit */);
            write(fd, s.c_str(), s.size());
        }
        if (unreachableMemory) {
            dprintf(fd, "\nDumping unreachable memory:\n");
            // TODO - should limit be an argument parameter?
            std::string s = GetUnreachableMemoryString(true /* contents */, 100 /* limit */);
            write(fd, s.c_str(), s.size());
        }
        {
            std::string timeCheckStats = getIAudioFlingerStatistics().dump();
            dprintf(fd, "\nIAudioFlinger binder call profile:\n");
            write(fd, timeCheckStats.c_str(), timeCheckStats.size());

            extern mediautils::MethodStatistics<int>& getIEffectStatistics();
            timeCheckStats = getIEffectStatistics().dump();
            dprintf(fd, "\nIEffect binder call profile:\n");
            write(fd, timeCheckStats.c_str(), timeCheckStats.size());

            // Automatically fetch HIDL statistics.
            std::shared_ptr<std::vector<std::string>> hidlClassNames =
                    mediautils::getStatisticsClassesForModule(
                            METHOD_STATISTICS_MODULE_NAME_AUDIO_HIDL);
            if (hidlClassNames) {
                for (const auto& className : *hidlClassNames) {
                    auto stats = mediautils::getStatisticsForClass(className);
                    if (stats) {
                        timeCheckStats = stats->dump();
                        dprintf(fd, "\n%s binder call profile:\n", className.c_str());
                        write(fd, timeCheckStats.c_str(), timeCheckStats.size());
                    }
                }
            }

            timeCheckStats = mediautils::TimeCheck::toString();
            dprintf(fd, "\nTimeCheck:\n");
            write(fd, timeCheckStats.c_str(), timeCheckStats.size());
            dprintf(fd, "\n");
        }
    }
    return NO_ERROR;
}

sp<Client> AudioFlinger::registerPid(pid_t pid)
{
    Mutex::Autolock _cl(mClientLock);
    // If pid is already in the mClients wp<> map, then use that entry
    // (for which promote() is always != 0), otherwise create a new entry and Client.
    sp<Client> client = mClients.valueFor(pid).promote();
    if (client == 0) {
        client = sp<Client>::make(sp<IAfClientCallback>::fromExisting(this), pid);
        mClients.add(pid, client);
    }

    return client;
}

sp<NBLog::Writer> AudioFlinger::newWriter_l(size_t size, const char *name)
{
    // If there is no memory allocated for logs, return a no-op writer that does nothing.
    // Similarly if we can't contact the media.log service, also return a no-op writer.
    if (mLogMemoryDealer == 0 || sMediaLogService == 0) {
        return new NBLog::Writer();
    }
    sp<IMemory> shared = mLogMemoryDealer->allocate(NBLog::Timeline::sharedSize(size));
    // If allocation fails, consult the vector of previously unregistered writers
    // and garbage-collect one or more them until an allocation succeeds
    if (shared == 0) {
        Mutex::Autolock _l(mUnregisteredWritersLock);
        for (size_t count = mUnregisteredWriters.size(); count > 0; count--) {
            {
                // Pick the oldest stale writer to garbage-collect
                sp<IMemory> iMemory(mUnregisteredWriters[0]->getIMemory());
                mUnregisteredWriters.removeAt(0);
                sMediaLogService->unregisterWriter(iMemory);
                // Now the media.log remote reference to IMemory is gone.  When our last local
                // reference to IMemory also drops to zero at end of this block,
                // the IMemory destructor will deallocate the region from mLogMemoryDealer.
            }
            // Re-attempt the allocation
            shared = mLogMemoryDealer->allocate(NBLog::Timeline::sharedSize(size));
            if (shared != 0) {
                goto success;
            }
        }
        // Even after garbage-collecting all old writers, there is still not enough memory,
        // so return a no-op writer
        return new NBLog::Writer();
    }
success:
    NBLog::Shared *sharedRawPtr = (NBLog::Shared *) shared->unsecurePointer();
    new((void *) sharedRawPtr) NBLog::Shared(); // placement new here, but the corresponding
                                                // explicit destructor not needed since it is POD
    sMediaLogService->registerWriter(shared, size, name);
    return new NBLog::Writer(shared, size);
}

void AudioFlinger::unregisterWriter(const sp<NBLog::Writer>& writer)
{
    if (writer == 0) {
        return;
    }
    sp<IMemory> iMemory(writer->getIMemory());
    if (iMemory == 0) {
        return;
    }
    // Rather than removing the writer immediately, append it to a queue of old writers to
    // be garbage-collected later.  This allows us to continue to view old logs for a while.
    Mutex::Autolock _l(mUnregisteredWritersLock);
    mUnregisteredWriters.push(writer);
}

// IAudioFlinger interface

status_t AudioFlinger::createTrack(const media::CreateTrackRequest& _input,
                                   media::CreateTrackResponse& _output)
{
    // Local version of VALUE_OR_RETURN, specific to this method's calling conventions.
    CreateTrackInput input = VALUE_OR_RETURN_STATUS(CreateTrackInput::fromAidl(_input));
    CreateTrackOutput output;

    sp<IAfTrack> track;
    sp<Client> client;
    status_t lStatus;
    audio_stream_type_t streamType;
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
    std::vector<audio_io_handle_t> secondaryOutputs;
    bool isSpatialized = false;
    bool isBitPerfect = false;

    // TODO b/182392553: refactor or make clearer
    pid_t clientPid =
        VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_pid_t(input.clientInfo.attributionSource.pid));
    bool updatePid = (clientPid == (pid_t)-1);
    const uid_t callingUid = IPCThreadState::self()->getCallingUid();
    uid_t clientUid =
        VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_uid_t(input.clientInfo.attributionSource.uid));
    audio_io_handle_t effectThreadId = AUDIO_IO_HANDLE_NONE;
    std::vector<int> effectIds;
    audio_attributes_t localAttr = input.attr;

    AttributionSourceState adjAttributionSource = input.clientInfo.attributionSource;
    if (!isAudioServerOrMediaServerOrSystemServerOrRootUid(callingUid)) {
        ALOGW_IF(clientUid != callingUid,
                "%s uid %d tried to pass itself off as %d",
                __FUNCTION__, callingUid, clientUid);
        adjAttributionSource.uid = VALUE_OR_RETURN_STATUS(legacy2aidl_uid_t_int32_t(callingUid));
        clientUid = callingUid;
        updatePid = true;
    }
    const pid_t callingPid = IPCThreadState::self()->getCallingPid();
    if (updatePid) {
        ALOGW_IF(clientPid != (pid_t)-1 && clientPid != callingPid,
                 "%s uid %d pid %d tried to pass itself off as pid %d",
                 __func__, callingUid, callingPid, clientPid);
        clientPid = callingPid;
        adjAttributionSource.pid = VALUE_OR_RETURN_STATUS(legacy2aidl_pid_t_int32_t(callingPid));
    }
    adjAttributionSource = afutils::checkAttributionSourcePackage(
            adjAttributionSource);

    audio_session_t sessionId = input.sessionId;
    if (sessionId == AUDIO_SESSION_ALLOCATE) {
        sessionId = (audio_session_t) newAudioUniqueId(AUDIO_UNIQUE_ID_USE_SESSION);
    } else if (audio_unique_id_get_use(sessionId) != AUDIO_UNIQUE_ID_USE_SESSION) {
        lStatus = BAD_VALUE;
        goto Exit;
    }

    output.sessionId = sessionId;
    output.outputId = AUDIO_IO_HANDLE_NONE;
    output.selectedDeviceId = input.selectedDeviceId;
    lStatus = AudioSystem::getOutputForAttr(&localAttr, &output.outputId, sessionId, &streamType,
                                            adjAttributionSource, &input.config, input.flags,
                                            &output.selectedDeviceId, &portId, &secondaryOutputs,
                                            &isSpatialized, &isBitPerfect);

    if (lStatus != NO_ERROR || output.outputId == AUDIO_IO_HANDLE_NONE) {
        ALOGE("createTrack() getOutputForAttr() return error %d or invalid output handle", lStatus);
        goto Exit;
    }
    // client AudioTrack::set already implements AUDIO_STREAM_DEFAULT => AUDIO_STREAM_MUSIC,
    // but if someone uses binder directly they could bypass that and cause us to crash
    if (uint32_t(streamType) >= AUDIO_STREAM_CNT) {
        ALOGE("createTrack() invalid stream type %d", streamType);
        lStatus = BAD_VALUE;
        goto Exit;
    }

    // further channel mask checks are performed by createTrack_l() depending on the thread type
    if (!audio_is_output_channel(input.config.channel_mask)) {
        ALOGE("createTrack() invalid channel mask %#x", input.config.channel_mask);
        lStatus = BAD_VALUE;
        goto Exit;
    }

    // further format checks are performed by createTrack_l() depending on the thread type
    if (!audio_is_valid_format(input.config.format)) {
        ALOGE("createTrack() invalid format %#x", input.config.format);
        lStatus = BAD_VALUE;
        goto Exit;
    }

    {
        Mutex::Autolock _l(mLock);
        IAfPlaybackThread* thread = checkPlaybackThread_l(output.outputId);
        if (thread == NULL) {
            ALOGE("no playback thread found for output handle %d", output.outputId);
            lStatus = BAD_VALUE;
            goto Exit;
        }

        client = registerPid(clientPid);

        IAfPlaybackThread* effectThread = nullptr;
        // check if an effect chain with the same session ID is present on another
        // output thread and move it here.
        for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
            sp<IAfPlaybackThread> t = mPlaybackThreads.valueAt(i);
            if (mPlaybackThreads.keyAt(i) != output.outputId) {
                uint32_t sessions = t->hasAudioSession(sessionId);
                if (sessions & IAfThreadBase::EFFECT_SESSION) {
                    effectThread = t.get();
                    break;
                }
            }
        }
        ALOGV("createTrack() sessionId: %d", sessionId);

        output.sampleRate = input.config.sample_rate;
        output.frameCount = input.frameCount;
        output.notificationFrameCount = input.notificationFrameCount;
        output.flags = input.flags;
        output.streamType = streamType;

        track = thread->createTrack_l(client, streamType, localAttr, &output.sampleRate,
                                      input.config.format, input.config.channel_mask,
                                      &output.frameCount, &output.notificationFrameCount,
                                      input.notificationsPerBuffer, input.speed,
                                      input.sharedBuffer, sessionId, &output.flags,
                                      callingPid, adjAttributionSource, input.clientInfo.clientTid,
                                      &lStatus, portId, input.audioTrackCallback, isSpatialized,
                                      isBitPerfect);
        LOG_ALWAYS_FATAL_IF((lStatus == NO_ERROR) && (track == 0));
        // we don't abort yet if lStatus != NO_ERROR; there is still work to be done regardless

        output.afFrameCount = thread->frameCount();
        output.afSampleRate = thread->sampleRate();
        output.afChannelMask = static_cast<audio_channel_mask_t>(thread->channelMask() |
                                                                 thread->hapticChannelMask());
        output.afFormat = thread->format();
        output.afLatencyMs = thread->latency();
        output.portId = portId;

        if (lStatus == NO_ERROR) {
            // no risk of deadlock because AudioFlinger::mLock is held
            Mutex::Autolock _dl(thread->mutex());
            // Connect secondary outputs. Failure on a secondary output must not imped the primary
            // Any secondary output setup failure will lead to a desync between the AP and AF until
            // the track is destroyed.
            updateSecondaryOutputsForTrack_l(track.get(), thread, secondaryOutputs);
            // move effect chain to this output thread if an effect on same session was waiting
            // for a track to be created
            if (effectThread != nullptr) {
                Mutex::Autolock _sl(effectThread->mutex());
                if (moveEffectChain_l(sessionId, effectThread, thread) == NO_ERROR) {
                    effectThreadId = thread->id();
                    effectIds = thread->getEffectIds_l(sessionId);
                }
            }
        }

        // Look for sync events awaiting for a session to be used.
        for (auto it = mPendingSyncEvents.begin(); it != mPendingSyncEvents.end();) {
            if ((*it)->triggerSession() == sessionId) {
                if (thread->isValidSyncEvent(*it)) {
                    if (lStatus == NO_ERROR) {
                        (void) track->setSyncEvent(*it);
                    } else {
                        (*it)->cancel();
                    }
                    it = mPendingSyncEvents.erase(it);
                    continue;
                }
            }
            ++it;
        }
        if ((output.flags & AUDIO_OUTPUT_FLAG_HW_AV_SYNC) == AUDIO_OUTPUT_FLAG_HW_AV_SYNC) {
            setAudioHwSyncForSession_l(thread, sessionId);
        }
    }

    if (lStatus != NO_ERROR) {
        // remove local strong reference to Client before deleting the Track so that the
        // Client destructor is called by the TrackBase destructor with mClientLock held
        // Don't hold mClientLock when releasing the reference on the track as the
        // destructor will acquire it.
        {
            Mutex::Autolock _cl(mClientLock);
            client.clear();
        }
        track.clear();
        goto Exit;
    }

    // effectThreadId is not NONE if an effect chain corresponding to the track session
    // was found on another thread and must be moved on this thread
    if (effectThreadId != AUDIO_IO_HANDLE_NONE) {
        AudioSystem::moveEffectsToIo(effectIds, effectThreadId);
    }

    output.audioTrack = IAfTrack::createIAudioTrackAdapter(track);
    _output = VALUE_OR_FATAL(output.toAidl());

Exit:
    if (lStatus != NO_ERROR && output.outputId != AUDIO_IO_HANDLE_NONE) {
        AudioSystem::releaseOutput(portId);
    }
    return lStatus;
}

uint32_t AudioFlinger::sampleRate(audio_io_handle_t ioHandle) const
{
    Mutex::Autolock _l(mLock);
    IAfThreadBase* const thread = checkThread_l(ioHandle);
    if (thread == NULL) {
        ALOGW("sampleRate() unknown thread %d", ioHandle);
        return 0;
    }
    return thread->sampleRate();
}

audio_format_t AudioFlinger::format(audio_io_handle_t output) const
{
    Mutex::Autolock _l(mLock);
    IAfPlaybackThread* const thread = checkPlaybackThread_l(output);
    if (thread == NULL) {
        ALOGW("format() unknown thread %d", output);
        return AUDIO_FORMAT_INVALID;
    }
    return thread->format();
}

size_t AudioFlinger::frameCount(audio_io_handle_t ioHandle) const
{
    Mutex::Autolock _l(mLock);
    IAfThreadBase* const thread = checkThread_l(ioHandle);
    if (thread == NULL) {
        ALOGW("frameCount() unknown thread %d", ioHandle);
        return 0;
    }
    // FIXME currently returns the normal mixer's frame count to avoid confusing legacy callers;
    //       should examine all callers and fix them to handle smaller counts
    return thread->frameCount();
}

size_t AudioFlinger::frameCountHAL(audio_io_handle_t ioHandle) const
{
    Mutex::Autolock _l(mLock);
    IAfThreadBase* const thread = checkThread_l(ioHandle);
    if (thread == NULL) {
        ALOGW("frameCountHAL() unknown thread %d", ioHandle);
        return 0;
    }
    return thread->frameCountHAL();
}

uint32_t AudioFlinger::latency(audio_io_handle_t output) const
{
    Mutex::Autolock _l(mLock);
    IAfPlaybackThread* const thread = checkPlaybackThread_l(output);
    if (thread == NULL) {
        ALOGW("latency(): no playback thread found for output handle %d", output);
        return 0;
    }
    return thread->latency();
}

status_t AudioFlinger::setMasterVolume(float value)
{
    status_t ret = initCheck();
    if (ret != NO_ERROR) {
        return ret;
    }

    // check calling permissions
    if (!settingsAllowed()) {
        return PERMISSION_DENIED;
    }

    Mutex::Autolock _l(mLock);
    mMasterVolume = value;

    // Set master volume in the HALs which support it.
    {
        AutoMutex lock(mHardwareLock);
        for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
            AudioHwDevice *dev = mAudioHwDevs.valueAt(i);

            mHardwareStatus = AUDIO_HW_SET_MASTER_VOLUME;
            if (dev->canSetMasterVolume()) {
                dev->hwDevice()->setMasterVolume(value);
            }
            mHardwareStatus = AUDIO_HW_IDLE;
        }
    }
    // Now set the master volume in each playback thread.  Playback threads
    // assigned to HALs which do not have master volume support will apply
    // master volume during the mix operation.  Threads with HALs which do
    // support master volume will simply ignore the setting.
    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        if (mPlaybackThreads.valueAt(i)->isDuplicating()) {
            continue;
        }
        mPlaybackThreads.valueAt(i)->setMasterVolume(value);
    }

    return NO_ERROR;
}

status_t AudioFlinger::setMasterBalance(float balance)
{
    status_t ret = initCheck();
    if (ret != NO_ERROR) {
        return ret;
    }

    // check calling permissions
    if (!settingsAllowed()) {
        return PERMISSION_DENIED;
    }

    // check range
    if (isnan(balance) || fabs(balance) > 1.f) {
        return BAD_VALUE;
    }

    Mutex::Autolock _l(mLock);

    // short cut.
    if (mMasterBalance == balance) return NO_ERROR;

    mMasterBalance = balance;

    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        if (mPlaybackThreads.valueAt(i)->isDuplicating()) {
            continue;
        }
        mPlaybackThreads.valueAt(i)->setMasterBalance(balance);
    }

    return NO_ERROR;
}

status_t AudioFlinger::setMode(audio_mode_t mode)
{
    status_t ret = initCheck();
    if (ret != NO_ERROR) {
        return ret;
    }

    // check calling permissions
    if (!settingsAllowed()) {
        return PERMISSION_DENIED;
    }
    if (uint32_t(mode) >= AUDIO_MODE_CNT) {
        ALOGW("Illegal value: setMode(%d)", mode);
        return BAD_VALUE;
    }

    { // scope for the lock
        AutoMutex lock(mHardwareLock);
        if (mPrimaryHardwareDev == nullptr) {
            return INVALID_OPERATION;
        }
        sp<DeviceHalInterface> dev = mPrimaryHardwareDev->hwDevice();
        mHardwareStatus = AUDIO_HW_SET_MODE;
        ret = dev->setMode(mode);
        mHardwareStatus = AUDIO_HW_IDLE;
    }

    if (NO_ERROR == ret) {
        Mutex::Autolock _l(mLock);
        mMode = mode;
        for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
            mPlaybackThreads.valueAt(i)->setMode(mode);
        }
    }

    mediametrics::LogItem(mMetricsId)
        .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_SETMODE)
        .set(AMEDIAMETRICS_PROP_AUDIOMODE, toString(mode))
        .record();
    return ret;
}

status_t AudioFlinger::setMicMute(bool state)
{
    status_t ret = initCheck();
    if (ret != NO_ERROR) {
        return ret;
    }

    // check calling permissions
    if (!settingsAllowed()) {
        return PERMISSION_DENIED;
    }

    AutoMutex lock(mHardwareLock);
    if (mPrimaryHardwareDev == nullptr) {
        return INVALID_OPERATION;
    }
    sp<DeviceHalInterface> primaryDev = mPrimaryHardwareDev->hwDevice();
    if (primaryDev == nullptr) {
        ALOGW("%s: no primary HAL device", __func__);
        return INVALID_OPERATION;
    }
    mHardwareStatus = AUDIO_HW_SET_MIC_MUTE;
    ret = primaryDev->setMicMute(state);
    for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
        sp<DeviceHalInterface> dev = mAudioHwDevs.valueAt(i)->hwDevice();
        if (dev != primaryDev) {
            (void)dev->setMicMute(state);
        }
    }
    mHardwareStatus = AUDIO_HW_IDLE;
    ALOGW_IF(ret != NO_ERROR, "%s: error %d setting state to HAL", __func__, ret);
    return ret;
}

bool AudioFlinger::getMicMute() const
{
    status_t ret = initCheck();
    if (ret != NO_ERROR) {
        return false;
    }
    AutoMutex lock(mHardwareLock);
    if (mPrimaryHardwareDev == nullptr) {
        return false;
    }
    sp<DeviceHalInterface> primaryDev = mPrimaryHardwareDev->hwDevice();
    if (primaryDev == nullptr) {
        ALOGW("%s: no primary HAL device", __func__);
        return false;
    }
    bool state;
    mHardwareStatus = AUDIO_HW_GET_MIC_MUTE;
    ret = primaryDev->getMicMute(&state);
    mHardwareStatus = AUDIO_HW_IDLE;
    ALOGE_IF(ret != NO_ERROR, "%s: error %d getting state from HAL", __func__, ret);
    return (ret == NO_ERROR) && state;
}

void AudioFlinger::setRecordSilenced(audio_port_handle_t portId, bool silenced)
{
    ALOGV("AudioFlinger::setRecordSilenced(portId:%d, silenced:%d)", portId, silenced);

    AutoMutex lock(mLock);
    for (size_t i = 0; i < mRecordThreads.size(); i++) {
        mRecordThreads[i]->setRecordSilenced(portId, silenced);
    }
    for (size_t i = 0; i < mMmapThreads.size(); i++) {
        mMmapThreads[i]->setRecordSilenced(portId, silenced);
    }
}

status_t AudioFlinger::setMasterMute(bool muted)
{
    status_t ret = initCheck();
    if (ret != NO_ERROR) {
        return ret;
    }

    // check calling permissions
    if (!settingsAllowed()) {
        return PERMISSION_DENIED;
    }

    Mutex::Autolock _l(mLock);
    mMasterMute = muted;

    // Set master mute in the HALs which support it.
    {
        AutoMutex lock(mHardwareLock);
        for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
            AudioHwDevice *dev = mAudioHwDevs.valueAt(i);

            mHardwareStatus = AUDIO_HW_SET_MASTER_MUTE;
            if (dev->canSetMasterMute()) {
                dev->hwDevice()->setMasterMute(muted);
            }
            mHardwareStatus = AUDIO_HW_IDLE;
        }
    }

    // Now set the master mute in each playback thread.  Playback threads
    // assigned to HALs which do not have master mute support will apply master mute
    // during the mix operation.  Threads with HALs which do support master mute
    // will simply ignore the setting.
    std::vector<sp<VolumeInterface>> volumeInterfaces = getAllVolumeInterfaces_l();
    for (size_t i = 0; i < volumeInterfaces.size(); i++) {
        volumeInterfaces[i]->setMasterMute(muted);
    }

    return NO_ERROR;
}

float AudioFlinger::masterVolume() const
{
    Mutex::Autolock _l(mLock);
    return masterVolume_l();
}

status_t AudioFlinger::getMasterBalance(float *balance) const
{
    Mutex::Autolock _l(mLock);
    *balance = getMasterBalance_l();
    return NO_ERROR; // if called through binder, may return a transactional error
}

bool AudioFlinger::masterMute() const
{
    Mutex::Autolock _l(mLock);
    return masterMute_l();
}

float AudioFlinger::masterVolume_l() const
{
    return mMasterVolume;
}

float AudioFlinger::getMasterBalance_l() const
{
    return mMasterBalance;
}

bool AudioFlinger::masterMute_l() const
{
    return mMasterMute;
}

status_t AudioFlinger::checkStreamType(audio_stream_type_t stream) const
{
    if (uint32_t(stream) >= AUDIO_STREAM_CNT) {
        ALOGW("checkStreamType() invalid stream %d", stream);
        return BAD_VALUE;
    }
    const uid_t callerUid = IPCThreadState::self()->getCallingUid();
    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT && !isAudioServerUid(callerUid)) {
        ALOGW("checkStreamType() uid %d cannot use internal stream type %d", callerUid, stream);
        return PERMISSION_DENIED;
    }

    return NO_ERROR;
}

status_t AudioFlinger::setStreamVolume(audio_stream_type_t stream, float value,
        audio_io_handle_t output)
{
    // check calling permissions
    if (!settingsAllowed()) {
        return PERMISSION_DENIED;
    }

    status_t status = checkStreamType(stream);
    if (status != NO_ERROR) {
        return status;
    }
    if (output == AUDIO_IO_HANDLE_NONE) {
        return BAD_VALUE;
    }
    LOG_ALWAYS_FATAL_IF(stream == AUDIO_STREAM_PATCH && value != 1.0f,
                        "AUDIO_STREAM_PATCH must have full scale volume");

    AutoMutex lock(mLock);
    sp<VolumeInterface> volumeInterface = getVolumeInterface_l(output);
    if (volumeInterface == NULL) {
        return BAD_VALUE;
    }
    volumeInterface->setStreamVolume(stream, value);

    return NO_ERROR;
}

status_t AudioFlinger::setRequestedLatencyMode(
        audio_io_handle_t output, audio_latency_mode_t mode) {
    if (output == AUDIO_IO_HANDLE_NONE) {
        return BAD_VALUE;
    }
    AutoMutex lock(mLock);
    IAfPlaybackThread* const thread = checkPlaybackThread_l(output);
    if (thread == nullptr) {
        return BAD_VALUE;
    }
    return thread->setRequestedLatencyMode(mode);
}

status_t AudioFlinger::getSupportedLatencyModes(audio_io_handle_t output,
            std::vector<audio_latency_mode_t>* modes) const {
    if (output == AUDIO_IO_HANDLE_NONE) {
        return BAD_VALUE;
    }
    AutoMutex lock(mLock);
    IAfPlaybackThread* const thread = checkPlaybackThread_l(output);
    if (thread == nullptr) {
        return BAD_VALUE;
    }
    return thread->getSupportedLatencyModes(modes);
}

status_t AudioFlinger::setBluetoothVariableLatencyEnabled(bool enabled) {
    Mutex::Autolock _l(mLock);
    status_t status = INVALID_OPERATION;
    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        // Success if at least one PlaybackThread supports Bluetooth latency modes
        if (mPlaybackThreads.valueAt(i)->setBluetoothVariableLatencyEnabled(enabled) == NO_ERROR) {
            status = NO_ERROR;
        }
    }
    if (status == NO_ERROR) {
        mBluetoothLatencyModesEnabled.store(enabled);
    }
    return status;
}

status_t AudioFlinger::isBluetoothVariableLatencyEnabled(bool* enabled) const {
    if (enabled == nullptr) {
        return BAD_VALUE;
    }
    *enabled = mBluetoothLatencyModesEnabled.load();
    return NO_ERROR;
}

status_t AudioFlinger::supportsBluetoothVariableLatency(bool* support) const {
    if (support == nullptr) {
        return BAD_VALUE;
    }
    Mutex::Autolock _l(mLock);
    *support = false;
    for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
        if (mAudioHwDevs.valueAt(i)->supportsBluetoothVariableLatency()) {
             *support = true;
             break;
        }
    }
    return NO_ERROR;
}

status_t AudioFlinger::getSoundDoseInterface(const sp<media::ISoundDoseCallback>& callback,
                                             sp<media::ISoundDose>* soundDose) const {
    if (soundDose == nullptr) {
        return BAD_VALUE;
    }

    *soundDose = mMelReporter->getSoundDoseInterface(callback);
    return NO_ERROR;
}

status_t AudioFlinger::setStreamMute(audio_stream_type_t stream, bool muted)
{
    // check calling permissions
    if (!settingsAllowed()) {
        return PERMISSION_DENIED;
    }

    status_t status = checkStreamType(stream);
    if (status != NO_ERROR) {
        return status;
    }
    ALOG_ASSERT(stream != AUDIO_STREAM_PATCH, "attempt to mute AUDIO_STREAM_PATCH");

    if (uint32_t(stream) == AUDIO_STREAM_ENFORCED_AUDIBLE) {
        ALOGE("setStreamMute() invalid stream %d", stream);
        return BAD_VALUE;
    }

    AutoMutex lock(mLock);
    mStreamTypes[stream].mute = muted;
    std::vector<sp<VolumeInterface>> volumeInterfaces = getAllVolumeInterfaces_l();
    for (size_t i = 0; i < volumeInterfaces.size(); i++) {
        volumeInterfaces[i]->setStreamMute(stream, muted);
    }

    return NO_ERROR;
}

float AudioFlinger::streamVolume(audio_stream_type_t stream, audio_io_handle_t output) const
{
    status_t status = checkStreamType(stream);
    if (status != NO_ERROR) {
        return 0.0f;
    }
    if (output == AUDIO_IO_HANDLE_NONE) {
        return 0.0f;
    }

    AutoMutex lock(mLock);
    sp<VolumeInterface> volumeInterface = getVolumeInterface_l(output);
    if (volumeInterface == NULL) {
        return 0.0f;
    }

    return volumeInterface->streamVolume(stream);
}

bool AudioFlinger::streamMute(audio_stream_type_t stream) const
{
    status_t status = checkStreamType(stream);
    if (status != NO_ERROR) {
        return true;
    }

    AutoMutex lock(mLock);
    return streamMute_l(stream);
}


void AudioFlinger::broadcastParametersToRecordThreads_l(const String8& keyValuePairs)
{
    for (size_t i = 0; i < mRecordThreads.size(); i++) {
        mRecordThreads.valueAt(i)->setParameters(keyValuePairs);
    }
}

void AudioFlinger::updateOutDevicesForRecordThreads_l(const DeviceDescriptorBaseVector& devices)
{
    for (size_t i = 0; i < mRecordThreads.size(); i++) {
        mRecordThreads.valueAt(i)->updateOutDevices(devices);
    }
}

// forwardAudioHwSyncToDownstreamPatches_l() must be called with AudioFlinger::mLock held
void AudioFlinger::forwardParametersToDownstreamPatches_l(
        audio_io_handle_t upStream, const String8& keyValuePairs,
        const std::function<bool(const sp<IAfPlaybackThread>&)>& useThread)
{
    std::vector<SoftwarePatch> swPatches;
    if (mPatchPanel->getDownstreamSoftwarePatches(upStream, &swPatches) != OK) return;
    ALOGV_IF(!swPatches.empty(), "%s found %zu downstream patches for stream ID %d",
            __func__, swPatches.size(), upStream);
    for (const auto& swPatch : swPatches) {
        const sp<IAfPlaybackThread> downStream =
                checkPlaybackThread_l(swPatch.getPlaybackThreadHandle());
        if (downStream != NULL && (useThread == nullptr || useThread(downStream))) {
            downStream->setParameters(keyValuePairs);
        }
    }
}

// Update downstream patches for all playback threads attached to an MSD module
void AudioFlinger::updateDownStreamPatches_l(const struct audio_patch *patch,
                                             const std::set<audio_io_handle_t>& streams)
{
    for (const audio_io_handle_t stream : streams) {
        IAfPlaybackThread* const playbackThread = checkPlaybackThread_l(stream);
        if (playbackThread == nullptr || !playbackThread->isMsdDevice()) {
            continue;
        }
        playbackThread->setDownStreamPatch(patch);
        playbackThread->sendIoConfigEvent(AUDIO_OUTPUT_CONFIG_CHANGED);
    }
}

// Filter reserved keys from setParameters() before forwarding to audio HAL or acting upon.
// Some keys are used for audio routing and audio path configuration and should be reserved for use
// by audio policy and audio flinger for functional, privacy and security reasons.
void AudioFlinger::filterReservedParameters(String8& keyValuePairs, uid_t callingUid)
{
    static const String8 kReservedParameters[] = {
        String8(AudioParameter::keyRouting),
        String8(AudioParameter::keySamplingRate),
        String8(AudioParameter::keyFormat),
        String8(AudioParameter::keyChannels),
        String8(AudioParameter::keyFrameCount),
        String8(AudioParameter::keyInputSource),
        String8(AudioParameter::keyMonoOutput),
        String8(AudioParameter::keyDeviceConnect),
        String8(AudioParameter::keyDeviceDisconnect),
        String8(AudioParameter::keyStreamSupportedFormats),
        String8(AudioParameter::keyStreamSupportedChannels),
        String8(AudioParameter::keyStreamSupportedSamplingRates),
        String8(AudioParameter::keyClosing),
        String8(AudioParameter::keyExiting),
    };

    if (isAudioServerUid(callingUid)) {
        return; // no need to filter if audioserver.
    }

    AudioParameter param = AudioParameter(keyValuePairs);
    String8 value;
    AudioParameter rejectedParam;
    for (auto& key : kReservedParameters) {
        if (param.get(key, value) == NO_ERROR) {
            rejectedParam.add(key, value);
            param.remove(key);
        }
    }
    logFilteredParameters(param.size() + rejectedParam.size(), keyValuePairs,
                          rejectedParam.size(), rejectedParam.toString(), callingUid);
    keyValuePairs = param.toString();
}

void AudioFlinger::logFilteredParameters(size_t originalKVPSize, const String8& originalKVPs,
                                         size_t rejectedKVPSize, const String8& rejectedKVPs,
                                         uid_t callingUid) {
    auto prefix = String8::format("UID %5d", callingUid);
    auto suffix = String8::format("%zu KVP received: %s", originalKVPSize, originalKVPs.c_str());
    if (rejectedKVPSize != 0) {
        auto error = String8::format("%zu KVP rejected: %s", rejectedKVPSize, rejectedKVPs.c_str());
        ALOGW("%s: %s, %s, %s", __func__, prefix.c_str(), error.c_str(), suffix.c_str());
        mRejectedSetParameterLog.log("%s, %s, %s", prefix.c_str(), error.c_str(), suffix.c_str());
    } else {
        auto& logger = (isServiceUid(callingUid) ? mSystemSetParameterLog : mAppSetParameterLog);
        logger.log("%s, %s", prefix.c_str(), suffix.c_str());
    }
}

status_t AudioFlinger::setParameters(audio_io_handle_t ioHandle, const String8& keyValuePairs)
{
    ALOGV("setParameters(): io %d, keyvalue %s, calling pid %d calling uid %d",
            ioHandle, keyValuePairs.c_str(),
            IPCThreadState::self()->getCallingPid(), IPCThreadState::self()->getCallingUid());

    // check calling permissions
    if (!settingsAllowed()) {
        return PERMISSION_DENIED;
    }

    String8 filteredKeyValuePairs = keyValuePairs;
    filterReservedParameters(filteredKeyValuePairs, IPCThreadState::self()->getCallingUid());

    ALOGV("%s: filtered keyvalue %s", __func__, filteredKeyValuePairs.c_str());

    // AUDIO_IO_HANDLE_NONE means the parameters are global to the audio hardware interface
    if (ioHandle == AUDIO_IO_HANDLE_NONE) {
        Mutex::Autolock _l(mLock);
        // result will remain NO_INIT if no audio device is present
        status_t final_result = NO_INIT;
        {
            AutoMutex lock(mHardwareLock);
            mHardwareStatus = AUDIO_HW_SET_PARAMETER;
            for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
                sp<DeviceHalInterface> dev = mAudioHwDevs.valueAt(i)->hwDevice();
                status_t result = dev->setParameters(filteredKeyValuePairs);
                // return success if at least one audio device accepts the parameters as not all
                // HALs are requested to support all parameters. If no audio device supports the
                // requested parameters, the last error is reported.
                if (final_result != NO_ERROR) {
                    final_result = result;
                }
            }
            mHardwareStatus = AUDIO_HW_IDLE;
        }
        // disable AEC and NS if the device is a BT SCO headset supporting those pre processings
        AudioParameter param = AudioParameter(filteredKeyValuePairs);
        String8 value;
        if (param.get(String8(AudioParameter::keyBtNrec), value) == NO_ERROR) {
            bool btNrecIsOff = (value == AudioParameter::valueOff);
            if (mBtNrecIsOff.exchange(btNrecIsOff) != btNrecIsOff) {
                for (size_t i = 0; i < mRecordThreads.size(); i++) {
                    mRecordThreads.valueAt(i)->checkBtNrec();
                }
            }
        }
        String8 screenState;
        if (param.get(String8(AudioParameter::keyScreenState), screenState) == NO_ERROR) {
            bool isOff = (screenState == AudioParameter::valueOff);
            if (isOff != (mScreenState & 1)) {
                mScreenState = ((mScreenState & ~1) + 2) | isOff;
            }
        }
        return final_result;
    }

    // hold a strong ref on thread in case closeOutput() or closeInput() is called
    // and the thread is exited once the lock is released
    sp<IAfThreadBase> thread;
    {
        Mutex::Autolock _l(mLock);
        thread = checkPlaybackThread_l(ioHandle);
        if (thread == 0) {
            thread = checkRecordThread_l(ioHandle);
            if (thread == 0) {
                thread = checkMmapThread_l(ioHandle);
            }
        } else if (thread == primaryPlaybackThread_l()) {
            // indicate output device change to all input threads for pre processing
            AudioParameter param = AudioParameter(filteredKeyValuePairs);
            int value;
            if ((param.getInt(String8(AudioParameter::keyRouting), value) == NO_ERROR) &&
                    (value != 0)) {
                broadcastParametersToRecordThreads_l(filteredKeyValuePairs);
            }
        }
    }
    if (thread != 0) {
        status_t result = thread->setParameters(filteredKeyValuePairs);
        forwardParametersToDownstreamPatches_l(thread->id(), filteredKeyValuePairs);
        return result;
    }
    return BAD_VALUE;
}

String8 AudioFlinger::getParameters(audio_io_handle_t ioHandle, const String8& keys) const
{
    ALOGVV("getParameters() io %d, keys %s, calling pid %d",
            ioHandle, keys.c_str(), IPCThreadState::self()->getCallingPid());

    Mutex::Autolock _l(mLock);

    if (ioHandle == AUDIO_IO_HANDLE_NONE) {
        String8 out_s8;

        AutoMutex lock(mHardwareLock);
        for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
            String8 s;
            mHardwareStatus = AUDIO_HW_GET_PARAMETER;
            sp<DeviceHalInterface> dev = mAudioHwDevs.valueAt(i)->hwDevice();
            status_t result = dev->getParameters(keys, &s);
            mHardwareStatus = AUDIO_HW_IDLE;
            if (result == OK) out_s8 += s;
        }
        return out_s8;
    }

    IAfThreadBase* thread = checkPlaybackThread_l(ioHandle);
    if (thread == NULL) {
        thread = checkRecordThread_l(ioHandle);
        if (thread == NULL) {
            thread = checkMmapThread_l(ioHandle);
            if (thread == NULL) {
                return String8("");
            }
        }
    }
    return thread->getParameters(keys);
}

size_t AudioFlinger::getInputBufferSize(uint32_t sampleRate, audio_format_t format,
        audio_channel_mask_t channelMask) const
{
    status_t ret = initCheck();
    if (ret != NO_ERROR) {
        return 0;
    }
    if ((sampleRate == 0) ||
            !audio_is_valid_format(format) || !audio_has_proportional_frames(format) ||
            !audio_is_input_channel(channelMask)) {
        return 0;
    }

    AutoMutex lock(mHardwareLock);
    if (mPrimaryHardwareDev == nullptr) {
        return 0;
    }
    mHardwareStatus = AUDIO_HW_GET_INPUT_BUFFER_SIZE;

    sp<DeviceHalInterface> dev = mPrimaryHardwareDev->hwDevice();

    std::vector<audio_channel_mask_t> channelMasks = {channelMask};
    if (channelMask != AUDIO_CHANNEL_IN_MONO) {
        channelMasks.push_back(AUDIO_CHANNEL_IN_MONO);
    }
    if (channelMask != AUDIO_CHANNEL_IN_STEREO) {
        channelMasks.push_back(AUDIO_CHANNEL_IN_STEREO);
    }

    std::vector<audio_format_t> formats = {format};
    if (format != AUDIO_FORMAT_PCM_16_BIT) {
        formats.push_back(AUDIO_FORMAT_PCM_16_BIT);
    }

    std::vector<uint32_t> sampleRates = {sampleRate};
    static const uint32_t SR_44100 = 44100;
    static const uint32_t SR_48000 = 48000;
    if (sampleRate != SR_48000) {
        sampleRates.push_back(SR_48000);
    }
    if (sampleRate != SR_44100) {
        sampleRates.push_back(SR_44100);
    }

    mHardwareStatus = AUDIO_HW_IDLE;

    // Change parameters of the configuration each iteration until we find a
    // configuration that the device will support.
    audio_config_t config = AUDIO_CONFIG_INITIALIZER;
    for (auto testChannelMask : channelMasks) {
        config.channel_mask = testChannelMask;
        for (auto testFormat : formats) {
            config.format = testFormat;
            for (auto testSampleRate : sampleRates) {
                config.sample_rate = testSampleRate;

                size_t bytes = 0;
                status_t result = dev->getInputBufferSize(&config, &bytes);
                if (result != OK || bytes == 0) {
                    continue;
                }

                if (config.sample_rate != sampleRate || config.channel_mask != channelMask ||
                    config.format != format) {
                    uint32_t dstChannelCount = audio_channel_count_from_in_mask(channelMask);
                    uint32_t srcChannelCount =
                        audio_channel_count_from_in_mask(config.channel_mask);
                    size_t srcFrames =
                        bytes / audio_bytes_per_frame(srcChannelCount, config.format);
                    size_t dstFrames = destinationFramesPossible(
                        srcFrames, config.sample_rate, sampleRate);
                    bytes = dstFrames * audio_bytes_per_frame(dstChannelCount, format);
                }
                return bytes;
            }
        }
    }

    ALOGW("getInputBufferSize failed with minimum buffer size sampleRate %u, "
              "format %#x, channelMask %#x",sampleRate, format, channelMask);
    return 0;
}

uint32_t AudioFlinger::getInputFramesLost(audio_io_handle_t ioHandle) const
{
    Mutex::Autolock _l(mLock);

    IAfRecordThread* const recordThread = checkRecordThread_l(ioHandle);
    if (recordThread != NULL) {
        return recordThread->getInputFramesLost();
    }
    return 0;
}

status_t AudioFlinger::setVoiceVolume(float value)
{
    status_t ret = initCheck();
    if (ret != NO_ERROR) {
        return ret;
    }

    // check calling permissions
    if (!settingsAllowed()) {
        return PERMISSION_DENIED;
    }

    AutoMutex lock(mHardwareLock);
    if (mPrimaryHardwareDev == nullptr) {
        return INVALID_OPERATION;
    }
    sp<DeviceHalInterface> dev = mPrimaryHardwareDev->hwDevice();
    mHardwareStatus = AUDIO_HW_SET_VOICE_VOLUME;
    ret = dev->setVoiceVolume(value);
    mHardwareStatus = AUDIO_HW_IDLE;

    mediametrics::LogItem(mMetricsId)
        .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_SETVOICEVOLUME)
        .set(AMEDIAMETRICS_PROP_VOICEVOLUME, (double)value)
        .record();
    return ret;
}

status_t AudioFlinger::getRenderPosition(uint32_t *halFrames, uint32_t *dspFrames,
        audio_io_handle_t output) const
{
    Mutex::Autolock _l(mLock);

    IAfPlaybackThread* const playbackThread = checkPlaybackThread_l(output);
    if (playbackThread != NULL) {
        return playbackThread->getRenderPosition(halFrames, dspFrames);
    }

    return BAD_VALUE;
}

void AudioFlinger::registerClient(const sp<media::IAudioFlingerClient>& client)
{
    Mutex::Autolock _l(mLock);
    if (client == 0) {
        return;
    }
    pid_t pid = IPCThreadState::self()->getCallingPid();
    const uid_t uid = IPCThreadState::self()->getCallingUid();
    {
        Mutex::Autolock _cl(mClientLock);
        if (mNotificationClients.indexOfKey(pid) < 0) {
            sp<NotificationClient> notificationClient = new NotificationClient(this,
                                                                                client,
                                                                                pid,
                                                                                uid);
            ALOGV("registerClient() client %p, pid %d, uid %u",
                    notificationClient.get(), pid, uid);

            mNotificationClients.add(pid, notificationClient);

            sp<IBinder> binder = IInterface::asBinder(client);
            binder->linkToDeath(notificationClient);
        }
    }

    // mClientLock should not be held here because ThreadBase::sendIoConfigEvent() will lock the
    // ThreadBase mutex and the locking order is ThreadBase::mLock then AudioFlinger::mClientLock.
    // the config change is always sent from playback or record threads to avoid deadlock
    // with AudioSystem::gLock
    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        mPlaybackThreads.valueAt(i)->sendIoConfigEvent(AUDIO_OUTPUT_REGISTERED, pid);
    }

    for (size_t i = 0; i < mRecordThreads.size(); i++) {
        mRecordThreads.valueAt(i)->sendIoConfigEvent(AUDIO_INPUT_REGISTERED, pid);
    }
}

void AudioFlinger::removeNotificationClient(pid_t pid)
{
    std::vector<sp<IAfEffectModule>> removedEffects;
    {
        Mutex::Autolock _l(mLock);
        {
            Mutex::Autolock _cl(mClientLock);
            mNotificationClients.removeItem(pid);
        }

        ALOGV("%d died, releasing its sessions", pid);
        size_t num = mAudioSessionRefs.size();
        bool removed = false;
        for (size_t i = 0; i < num; ) {
            AudioSessionRef *ref = mAudioSessionRefs.itemAt(i);
            ALOGV(" pid %d @ %zu", ref->mPid, i);
            if (ref->mPid == pid) {
                ALOGV(" removing entry for pid %d session %d", pid, ref->mSessionid);
                mAudioSessionRefs.removeAt(i);
                delete ref;
                removed = true;
                num--;
            } else {
                i++;
            }
        }
        if (removed) {
            removedEffects = purgeStaleEffects_l();
        }
    }
    for (auto& effect : removedEffects) {
        effect->updatePolicyState();
    }
}

void AudioFlinger::ioConfigChanged(audio_io_config_event_t event,
                                   const sp<AudioIoDescriptor>& ioDesc,
                                   pid_t pid) {
    media::AudioIoConfigEvent eventAidl = VALUE_OR_FATAL(
            legacy2aidl_audio_io_config_event_t_AudioIoConfigEvent(event));
    media::AudioIoDescriptor descAidl = VALUE_OR_FATAL(
            legacy2aidl_AudioIoDescriptor_AudioIoDescriptor(ioDesc));

    Mutex::Autolock _l(mClientLock);
    size_t size = mNotificationClients.size();
    for (size_t i = 0; i < size; i++) {
        if ((pid == 0) || (mNotificationClients.keyAt(i) == pid)) {
            mNotificationClients.valueAt(i)->audioFlingerClient()->ioConfigChanged(eventAidl,
                                                                                   descAidl);
        }
    }
}

void AudioFlinger::onSupportedLatencyModesChanged(
        audio_io_handle_t output, const std::vector<audio_latency_mode_t>& modes) {
    int32_t outputAidl = VALUE_OR_FATAL(legacy2aidl_audio_io_handle_t_int32_t(output));
    std::vector<media::audio::common::AudioLatencyMode> modesAidl = VALUE_OR_FATAL(
                convertContainer<std::vector<media::audio::common::AudioLatencyMode>>(
                        modes, legacy2aidl_audio_latency_mode_t_AudioLatencyMode));

    Mutex::Autolock _l(mClientLock);
    size_t size = mNotificationClients.size();
    for (size_t i = 0; i < size; i++) {
        mNotificationClients.valueAt(i)->audioFlingerClient()
                ->onSupportedLatencyModesChanged(outputAidl, modesAidl);
    }
}

// removeClient_l() must be called with AudioFlinger::mClientLock held
void AudioFlinger::removeClient_l(pid_t pid)
{
    ALOGV("removeClient_l() pid %d, calling pid %d", pid,
            IPCThreadState::self()->getCallingPid());
    mClients.removeItem(pid);
}

// getEffectThread_l() must be called with AudioFlinger::mLock held
sp<IAfThreadBase> AudioFlinger::getEffectThread_l(audio_session_t sessionId,
        int effectId)
{
    sp<IAfThreadBase> thread;

    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        if (mPlaybackThreads.valueAt(i)->getEffect(sessionId, effectId) != 0) {
            ALOG_ASSERT(thread == 0);
            thread = mPlaybackThreads.valueAt(i);
        }
    }
    if (thread != nullptr) {
        return thread;
    }
    for (size_t i = 0; i < mRecordThreads.size(); i++) {
        if (mRecordThreads.valueAt(i)->getEffect(sessionId, effectId) != 0) {
            ALOG_ASSERT(thread == 0);
            thread = mRecordThreads.valueAt(i);
        }
    }
    if (thread != nullptr) {
        return thread;
    }
    for (size_t i = 0; i < mMmapThreads.size(); i++) {
        if (mMmapThreads.valueAt(i)->getEffect(sessionId, effectId) != 0) {
            ALOG_ASSERT(thread == 0);
            thread = mMmapThreads.valueAt(i);
        }
    }
    return thread;
}

// ----------------------------------------------------------------------------

AudioFlinger::NotificationClient::NotificationClient(const sp<AudioFlinger>& audioFlinger,
                                                     const sp<media::IAudioFlingerClient>& client,
                                                     pid_t pid,
                                                     uid_t uid)
    : mAudioFlinger(audioFlinger), mPid(pid), mUid(uid), mAudioFlingerClient(client)
{
}

AudioFlinger::NotificationClient::~NotificationClient()
{
}

void AudioFlinger::NotificationClient::binderDied(const wp<IBinder>& who __unused)
{
    sp<NotificationClient> keep(this);
    mAudioFlinger->removeNotificationClient(mPid);
}

// ----------------------------------------------------------------------------
AudioFlinger::MediaLogNotifier::MediaLogNotifier()
    : mPendingRequests(false) {}


void AudioFlinger::MediaLogNotifier::requestMerge() {
    AutoMutex _l(mMutex);
    mPendingRequests = true;
    mCond.signal();
}

bool AudioFlinger::MediaLogNotifier::threadLoop() {
    // Should already have been checked, but just in case
    if (sMediaLogService == 0) {
        return false;
    }
    // Wait until there are pending requests
    {
        AutoMutex _l(mMutex);
        mPendingRequests = false; // to ignore past requests
        while (!mPendingRequests) {
            mCond.wait(mMutex);
            // TODO may also need an exitPending check
        }
        mPendingRequests = false;
    }
    // Execute the actual MediaLogService binder call and ignore extra requests for a while
    sMediaLogService->requestMergeWakeup();
    usleep(kPostTriggerSleepPeriod);
    return true;
}

void AudioFlinger::requestLogMerge() {
    mMediaLogNotifier->requestMerge();
}

// ----------------------------------------------------------------------------

status_t AudioFlinger::createRecord(const media::CreateRecordRequest& _input,
                                    media::CreateRecordResponse& _output)
{
    CreateRecordInput input = VALUE_OR_RETURN_STATUS(CreateRecordInput::fromAidl(_input));
    CreateRecordOutput output;

    sp<IAfRecordTrack> recordTrack;
    sp<Client> client;
    status_t lStatus;
    audio_session_t sessionId = input.sessionId;
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;

    output.cblk.clear();
    output.buffers.clear();
    output.inputId = AUDIO_IO_HANDLE_NONE;

    // TODO b/182392553: refactor or clean up
    AttributionSourceState adjAttributionSource = input.clientInfo.attributionSource;
    bool updatePid = (adjAttributionSource.pid == -1);
    const uid_t callingUid = IPCThreadState::self()->getCallingUid();
    const uid_t currentUid = VALUE_OR_RETURN_STATUS(legacy2aidl_uid_t_int32_t(
           adjAttributionSource.uid));
    if (!isAudioServerOrMediaServerOrSystemServerOrRootUid(callingUid)) {
        ALOGW_IF(currentUid != callingUid,
                "%s uid %d tried to pass itself off as %d",
                __FUNCTION__, callingUid, currentUid);
        adjAttributionSource.uid = VALUE_OR_RETURN_STATUS(legacy2aidl_uid_t_int32_t(callingUid));
        updatePid = true;
    }
    const pid_t callingPid = IPCThreadState::self()->getCallingPid();
    const pid_t currentPid = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_pid_t(
            adjAttributionSource.pid));
    if (updatePid) {
        ALOGW_IF(currentPid != (pid_t)-1 && currentPid != callingPid,
                 "%s uid %d pid %d tried to pass itself off as pid %d",
                 __func__, callingUid, callingPid, currentPid);
        adjAttributionSource.pid = VALUE_OR_RETURN_STATUS(legacy2aidl_pid_t_int32_t(callingPid));
    }
    adjAttributionSource = afutils::checkAttributionSourcePackage(
            adjAttributionSource);
    // we don't yet support anything other than linear PCM
    if (!audio_is_valid_format(input.config.format) || !audio_is_linear_pcm(input.config.format)) {
        ALOGE("createRecord() invalid format %#x", input.config.format);
        lStatus = BAD_VALUE;
        goto Exit;
    }

    // further channel mask checks are performed by createRecordTrack_l()
    if (!audio_is_input_channel(input.config.channel_mask)) {
        ALOGE("createRecord() invalid channel mask %#x", input.config.channel_mask);
        lStatus = BAD_VALUE;
        goto Exit;
    }

    if (sessionId == AUDIO_SESSION_ALLOCATE) {
        sessionId = (audio_session_t) newAudioUniqueId(AUDIO_UNIQUE_ID_USE_SESSION);
    } else if (audio_unique_id_get_use(sessionId) != AUDIO_UNIQUE_ID_USE_SESSION) {
        lStatus = BAD_VALUE;
        goto Exit;
    }

    output.sessionId = sessionId;
    output.selectedDeviceId = input.selectedDeviceId;
    output.flags = input.flags;

    client = registerPid(VALUE_OR_FATAL(aidl2legacy_int32_t_pid_t(adjAttributionSource.pid)));

    // Not a conventional loop, but a retry loop for at most two iterations total.
    // Try first maybe with FAST flag then try again without FAST flag if that fails.
    // Exits loop via break on no error of got exit on error
    // The sp<> references will be dropped when re-entering scope.
    // The lack of indentation is deliberate, to reduce code churn and ease merges.
    for (;;) {
    // release previously opened input if retrying.
    if (output.inputId != AUDIO_IO_HANDLE_NONE) {
        recordTrack.clear();
        AudioSystem::releaseInput(portId);
        output.inputId = AUDIO_IO_HANDLE_NONE;
        output.selectedDeviceId = input.selectedDeviceId;
        portId = AUDIO_PORT_HANDLE_NONE;
    }
    lStatus = AudioSystem::getInputForAttr(&input.attr, &output.inputId,
                                      input.riid,
                                      sessionId,
                                    // FIXME compare to AudioTrack
                                      adjAttributionSource,
                                      &input.config,
                                      output.flags, &output.selectedDeviceId, &portId);
    if (lStatus != NO_ERROR) {
        ALOGE("createRecord() getInputForAttr return error %d", lStatus);
        goto Exit;
    }

    {
        Mutex::Autolock _l(mLock);
        IAfRecordThread* const thread = checkRecordThread_l(output.inputId);
        if (thread == NULL) {
            ALOGW("createRecord() checkRecordThread_l failed, input handle %d", output.inputId);
            lStatus = FAILED_TRANSACTION;
            goto Exit;
        }

        ALOGV("createRecord() lSessionId: %d input %d", sessionId, output.inputId);

        output.sampleRate = input.config.sample_rate;
        output.frameCount = input.frameCount;
        output.notificationFrameCount = input.notificationFrameCount;

        recordTrack = thread->createRecordTrack_l(client, input.attr, &output.sampleRate,
                                                  input.config.format, input.config.channel_mask,
                                                  &output.frameCount, sessionId,
                                                  &output.notificationFrameCount,
                                                  callingPid, adjAttributionSource, &output.flags,
                                                  input.clientInfo.clientTid,
                                                  &lStatus, portId, input.maxSharedAudioHistoryMs);
        LOG_ALWAYS_FATAL_IF((lStatus == NO_ERROR) && (recordTrack == 0));

        // lStatus == BAD_TYPE means FAST flag was rejected: request a new input from
        // audio policy manager without FAST constraint
        if (lStatus == BAD_TYPE) {
            continue;
        }

        if (lStatus != NO_ERROR) {
            goto Exit;
        }

        if (recordTrack->isFastTrack()) {
            output.serverConfig = {
                    thread->sampleRate(),
                    thread->channelMask(),
                    thread->format()
            };
        } else {
            output.serverConfig = {
                    recordTrack->sampleRate(),
                    recordTrack->channelMask(),
                    recordTrack->format()
            };
        }

        output.halConfig = {
                thread->sampleRate(),
                thread->channelMask(),
                thread->format()
        };

        // Check if one effect chain was awaiting for an AudioRecord to be created on this
        // session and move it to this thread.
        sp<IAfEffectChain> chain = getOrphanEffectChain_l(sessionId);
        if (chain != 0) {
            Mutex::Autolock _l2(thread->mutex());
            thread->addEffectChain_l(chain);
        }
        break;
    }
    // End of retry loop.
    // The lack of indentation is deliberate, to reduce code churn and ease merges.
    }

    output.cblk = recordTrack->getCblk();
    output.buffers = recordTrack->getBuffers();
    output.portId = portId;

    output.audioRecord = IAfRecordTrack::createIAudioRecordAdapter(recordTrack);
    _output = VALUE_OR_FATAL(output.toAidl());

Exit:
    if (lStatus != NO_ERROR) {
        // remove local strong reference to Client before deleting the RecordTrack so that the
        // Client destructor is called by the TrackBase destructor with mClientLock held
        // Don't hold mClientLock when releasing the reference on the track as the
        // destructor will acquire it.
        {
            Mutex::Autolock _cl(mClientLock);
            client.clear();
        }
        recordTrack.clear();
        if (output.inputId != AUDIO_IO_HANDLE_NONE) {
            AudioSystem::releaseInput(portId);
        }
    }

    return lStatus;
}



// ----------------------------------------------------------------------------

status_t AudioFlinger::getAudioPolicyConfig(media::AudioPolicyConfig *config)
{
    if (config == nullptr) {
        return BAD_VALUE;
    }
    Mutex::Autolock _l(mLock);
    AutoMutex lock(mHardwareLock);
    RETURN_STATUS_IF_ERROR(
            mDevicesFactoryHal->getSurroundSoundConfig(&config->surroundSoundConfig));
    RETURN_STATUS_IF_ERROR(mDevicesFactoryHal->getEngineConfig(&config->engineConfig));
    std::vector<std::string> hwModuleNames;
    RETURN_STATUS_IF_ERROR(mDevicesFactoryHal->getDeviceNames(&hwModuleNames));
    std::set<AudioMode> allSupportedModes;
    for (const auto& name : hwModuleNames) {
        AudioHwDevice* module = loadHwModule_l(name.c_str());
        if (module == nullptr) continue;
        media::AudioHwModule aidlModule;
        if (module->hwDevice()->getAudioPorts(&aidlModule.ports) == OK &&
                module->hwDevice()->getAudioRoutes(&aidlModule.routes) == OK) {
            aidlModule.handle = module->handle();
            aidlModule.name = module->moduleName();
            config->modules.push_back(std::move(aidlModule));
        }
        std::vector<AudioMode> supportedModes;
        if (module->hwDevice()->getSupportedModes(&supportedModes) == OK) {
            allSupportedModes.insert(supportedModes.begin(), supportedModes.end());
        }
    }
    if (!allSupportedModes.empty()) {
        config->supportedModes.insert(config->supportedModes.end(),
                allSupportedModes.begin(), allSupportedModes.end());
    } else {
        ALOGW("%s: The HAL does not provide telephony functionality", __func__);
        config->supportedModes = { media::audio::common::AudioMode::NORMAL,
            media::audio::common::AudioMode::RINGTONE,
            media::audio::common::AudioMode::IN_CALL,
            media::audio::common::AudioMode::IN_COMMUNICATION };
    }
    return OK;
}

audio_module_handle_t AudioFlinger::loadHwModule(const char *name)
{
    if (name == NULL) {
        return AUDIO_MODULE_HANDLE_NONE;
    }
    if (!settingsAllowed()) {
        return AUDIO_MODULE_HANDLE_NONE;
    }
    Mutex::Autolock _l(mLock);
    AutoMutex lock(mHardwareLock);
    AudioHwDevice* module = loadHwModule_l(name);
    return module != nullptr ? module->handle() : AUDIO_MODULE_HANDLE_NONE;
}

// loadHwModule_l() must be called with AudioFlinger::mLock and AudioFlinger::mHardwareLock held
AudioHwDevice* AudioFlinger::loadHwModule_l(const char *name)
{
    for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
        if (strncmp(mAudioHwDevs.valueAt(i)->moduleName(), name, strlen(name)) == 0) {
            ALOGW("loadHwModule() module %s already loaded", name);
            return mAudioHwDevs.valueAt(i);
        }
    }

    sp<DeviceHalInterface> dev;

    int rc = mDevicesFactoryHal->openDevice(name, &dev);
    if (rc) {
        ALOGE("loadHwModule() error %d loading module %s", rc, name);
        return nullptr;
    }
    if (!mMelReporter->activateHalSoundDoseComputation(name, dev)) {
        ALOGW("loadHwModule() sound dose reporting is not available");
    }

    mHardwareStatus = AUDIO_HW_INIT;
    rc = dev->initCheck();
    mHardwareStatus = AUDIO_HW_IDLE;
    if (rc) {
        ALOGE("loadHwModule() init check error %d for module %s", rc, name);
        return nullptr;
    }

    // Check and cache this HAL's level of support for master mute and master
    // volume.  If this is the first HAL opened, and it supports the get
    // methods, use the initial values provided by the HAL as the current
    // master mute and volume settings.

    AudioHwDevice::Flags flags = static_cast<AudioHwDevice::Flags>(0);
    if (0 == mAudioHwDevs.size()) {
        mHardwareStatus = AUDIO_HW_GET_MASTER_VOLUME;
        float mv;
        if (OK == dev->getMasterVolume(&mv)) {
            mMasterVolume = mv;
        }

        mHardwareStatus = AUDIO_HW_GET_MASTER_MUTE;
        bool mm;
        if (OK == dev->getMasterMute(&mm)) {
            mMasterMute = mm;
        }
    }

    mHardwareStatus = AUDIO_HW_SET_MASTER_VOLUME;
    if (OK == dev->setMasterVolume(mMasterVolume)) {
        flags = static_cast<AudioHwDevice::Flags>(flags |
                AudioHwDevice::AHWD_CAN_SET_MASTER_VOLUME);
    }

    mHardwareStatus = AUDIO_HW_SET_MASTER_MUTE;
    if (OK == dev->setMasterMute(mMasterMute)) {
        flags = static_cast<AudioHwDevice::Flags>(flags |
                AudioHwDevice::AHWD_CAN_SET_MASTER_MUTE);
    }

    mHardwareStatus = AUDIO_HW_IDLE;

    if (strcmp(name, AUDIO_HARDWARE_MODULE_ID_MSD) == 0) {
        // An MSD module is inserted before hardware modules in order to mix encoded streams.
        flags = static_cast<AudioHwDevice::Flags>(flags | AudioHwDevice::AHWD_IS_INSERT);
    }


    if (bool supports = false;
            dev->supportsBluetoothVariableLatency(&supports) == NO_ERROR && supports) {
        flags = static_cast<AudioHwDevice::Flags>(flags |
                AudioHwDevice::AHWD_SUPPORTS_BT_LATENCY_MODES);
    }

    audio_module_handle_t handle = (audio_module_handle_t) nextUniqueId(AUDIO_UNIQUE_ID_USE_MODULE);
    AudioHwDevice *audioDevice = new AudioHwDevice(handle, name, dev, flags);
    if (strcmp(name, AUDIO_HARDWARE_MODULE_ID_PRIMARY) == 0) {
        mPrimaryHardwareDev = audioDevice;
        mHardwareStatus = AUDIO_HW_SET_MODE;
        mPrimaryHardwareDev->hwDevice()->setMode(mMode);
        mHardwareStatus = AUDIO_HW_IDLE;
    }

    if (mDevicesFactoryHal->getHalVersion() > kMaxAAudioPropertyDeviceHalVersion) {
        if (int32_t mixerBursts = dev->getAAudioMixerBurstCount();
            mixerBursts > 0 && mixerBursts > mAAudioBurstsPerBuffer) {
            mAAudioBurstsPerBuffer = mixerBursts;
        }
        if (int32_t hwBurstMinMicros = dev->getAAudioHardwareBurstMinUsec();
            hwBurstMinMicros > 0
            && (hwBurstMinMicros < mAAudioHwBurstMinMicros || mAAudioHwBurstMinMicros == 0)) {
            mAAudioHwBurstMinMicros = hwBurstMinMicros;
        }
    }

    mAudioHwDevs.add(handle, audioDevice);

    ALOGI("loadHwModule() Loaded %s audio interface, handle %d", name, handle);

    return audioDevice;
}

// ----------------------------------------------------------------------------

uint32_t AudioFlinger::getPrimaryOutputSamplingRate() const
{
    Mutex::Autolock _l(mLock);
    IAfPlaybackThread* const thread = fastPlaybackThread_l();
    return thread != NULL ? thread->sampleRate() : 0;
}

size_t AudioFlinger::getPrimaryOutputFrameCount() const
{
    Mutex::Autolock _l(mLock);
    IAfPlaybackThread* const thread = fastPlaybackThread_l();
    return thread != NULL ? thread->frameCountHAL() : 0;
}

// ----------------------------------------------------------------------------

status_t AudioFlinger::setLowRamDevice(bool isLowRamDevice, int64_t totalMemory)
{
    uid_t uid = IPCThreadState::self()->getCallingUid();
    if (!isAudioServerOrSystemServerUid(uid)) {
        return PERMISSION_DENIED;
    }
    Mutex::Autolock _l(mLock);
    if (mIsDeviceTypeKnown) {
        return INVALID_OPERATION;
    }
    mIsLowRamDevice = isLowRamDevice;
    mTotalMemory = totalMemory;
    // mIsLowRamDevice and mTotalMemory are obtained through ActivityManager;
    // see ActivityManager.isLowRamDevice() and ActivityManager.getMemoryInfo().
    // mIsLowRamDevice generally represent devices with less than 1GB of memory,
    // though actual setting is determined through device configuration.
    constexpr int64_t GB = 1024 * 1024 * 1024;
    mClientSharedHeapSize =
            isLowRamDevice ? kMinimumClientSharedHeapSizeBytes
                    : mTotalMemory < 2 * GB ? 4 * kMinimumClientSharedHeapSizeBytes
                    : mTotalMemory < 3 * GB ? 8 * kMinimumClientSharedHeapSizeBytes
                    : mTotalMemory < 4 * GB ? 16 * kMinimumClientSharedHeapSizeBytes
                    : 32 * kMinimumClientSharedHeapSizeBytes;
    mIsDeviceTypeKnown = true;

    // TODO: Cache the client shared heap size in a persistent property.
    // It's possible that a native process or Java service or app accesses audioserver
    // after it is registered by system server, but before AudioService updates
    // the memory info.  This would occur immediately after boot or an audioserver
    // crash and restore. Before update from AudioService, the client would get the
    // minimum heap size.

    ALOGD("isLowRamDevice:%s totalMemory:%lld mClientSharedHeapSize:%zu",
            (isLowRamDevice ? "true" : "false"),
            (long long)mTotalMemory,
            mClientSharedHeapSize.load());
    return NO_ERROR;
}

size_t AudioFlinger::getClientSharedHeapSize() const
{
    size_t heapSizeInBytes = property_get_int32("ro.af.client_heap_size_kbyte", 0) * 1024;
    if (heapSizeInBytes != 0) { // read-only property overrides all.
        return heapSizeInBytes;
    }
    return mClientSharedHeapSize;
}

status_t AudioFlinger::setAudioPortConfig(const struct audio_port_config *config)
{
    ALOGV(__func__);

    status_t status = AudioValidator::validateAudioPortConfig(*config);
    if (status != NO_ERROR) {
        return status;
    }

    audio_module_handle_t module;
    if (config->type == AUDIO_PORT_TYPE_DEVICE) {
        module = config->ext.device.hw_module;
    } else {
        module = config->ext.mix.hw_module;
    }

    Mutex::Autolock _l(mLock);
    AutoMutex lock(mHardwareLock);
    ssize_t index = mAudioHwDevs.indexOfKey(module);
    if (index < 0) {
        ALOGW("%s() bad hw module %d", __func__, module);
        return BAD_VALUE;
    }

    AudioHwDevice *audioHwDevice = mAudioHwDevs.valueAt(index);
    return audioHwDevice->hwDevice()->setAudioPortConfig(config);
}

audio_hw_sync_t AudioFlinger::getAudioHwSyncForSession(audio_session_t sessionId)
{
    Mutex::Autolock _l(mLock);

    ssize_t index = mHwAvSyncIds.indexOfKey(sessionId);
    if (index >= 0) {
        ALOGV("getAudioHwSyncForSession found ID %d for session %d",
              mHwAvSyncIds.valueAt(index), sessionId);
        return mHwAvSyncIds.valueAt(index);
    }

    sp<DeviceHalInterface> dev;
    {
        AutoMutex lock(mHardwareLock);
        if (mPrimaryHardwareDev == nullptr) {
            return AUDIO_HW_SYNC_INVALID;
        }
        dev = mPrimaryHardwareDev->hwDevice();
    }
    if (dev == nullptr) {
        return AUDIO_HW_SYNC_INVALID;
    }

    error::Result<audio_hw_sync_t> result = dev->getHwAvSync();
    if (!result.ok()) {
        ALOGW("getAudioHwSyncForSession error getting sync for session %d", sessionId);
        return AUDIO_HW_SYNC_INVALID;
    }
    audio_hw_sync_t value = VALUE_OR_FATAL(result);

    // allow only one session for a given HW A/V sync ID.
    for (size_t i = 0; i < mHwAvSyncIds.size(); i++) {
        if (mHwAvSyncIds.valueAt(i) == value) {
            ALOGV("getAudioHwSyncForSession removing ID %d for session %d",
                  value, mHwAvSyncIds.keyAt(i));
            mHwAvSyncIds.removeItemsAt(i);
            break;
        }
    }

    mHwAvSyncIds.add(sessionId, value);

    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        const sp<IAfPlaybackThread> thread = mPlaybackThreads.valueAt(i);
        uint32_t sessions = thread->hasAudioSession(sessionId);
        if (sessions & IAfThreadBase::TRACK_SESSION) {
            AudioParameter param = AudioParameter();
            param.addInt(String8(AudioParameter::keyStreamHwAvSync), value);
            String8 keyValuePairs = param.toString();
            thread->setParameters(keyValuePairs);
            forwardParametersToDownstreamPatches_l(thread->id(), keyValuePairs,
                    [](const sp<IAfPlaybackThread>& thread) { return thread->usesHwAvSync(); });
            break;
        }
    }

    ALOGV("getAudioHwSyncForSession adding ID %d for session %d", value, sessionId);
    return (audio_hw_sync_t)value;
}

status_t AudioFlinger::systemReady()
{
    Mutex::Autolock _l(mLock);
    ALOGI("%s", __FUNCTION__);
    if (mSystemReady) {
        ALOGW("%s called twice", __FUNCTION__);
        return NO_ERROR;
    }
    mSystemReady = true;
    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        IAfThreadBase* const thread = mPlaybackThreads.valueAt(i).get();
        thread->systemReady();
    }
    for (size_t i = 0; i < mRecordThreads.size(); i++) {
        IAfThreadBase* const thread = mRecordThreads.valueAt(i).get();
        thread->systemReady();
    }
    for (size_t i = 0; i < mMmapThreads.size(); i++) {
        IAfThreadBase* const thread = mMmapThreads.valueAt(i).get();
        thread->systemReady();
    }

    // Java services are ready, so we can create a reference to AudioService
    getOrCreateAudioManager();

    return NO_ERROR;
}

sp<IAudioManager> AudioFlinger::getOrCreateAudioManager()
{
    if (mAudioManager.load() == nullptr) {
        // use checkService() to avoid blocking
        sp<IBinder> binder =
            defaultServiceManager()->checkService(String16(kAudioServiceName));
        if (binder != nullptr) {
            mAudioManager = interface_cast<IAudioManager>(binder);
        } else {
            ALOGE("%s(): binding to audio service failed.", __func__);
        }
    }
    return mAudioManager.load();
}

status_t AudioFlinger::getMicrophones(std::vector<media::MicrophoneInfoFw>* microphones) const
{
    AutoMutex lock(mHardwareLock);
    status_t status = INVALID_OPERATION;

    for (size_t i = 0; i < mAudioHwDevs.size(); i++) {
        std::vector<audio_microphone_characteristic_t> mics;
        AudioHwDevice *dev = mAudioHwDevs.valueAt(i);
        mHardwareStatus = AUDIO_HW_GET_MICROPHONES;
        status_t devStatus = dev->hwDevice()->getMicrophones(&mics);
        mHardwareStatus = AUDIO_HW_IDLE;
        if (devStatus == NO_ERROR) {
            // report success if at least one HW module supports the function.
            std::transform(mics.begin(), mics.end(), std::back_inserter(*microphones), [](auto& mic)
            {
                auto microphone =
                        legacy2aidl_audio_microphone_characteristic_t_MicrophoneInfoFw(mic);
                return microphone.ok() ? microphone.value() : media::MicrophoneInfoFw{};
            });
            status = NO_ERROR;
        }
    }

    return status;
}

// setAudioHwSyncForSession_l() must be called with AudioFlinger::mLock held
void AudioFlinger::setAudioHwSyncForSession_l(
        IAfPlaybackThread* const thread, audio_session_t sessionId)
{
    ssize_t index = mHwAvSyncIds.indexOfKey(sessionId);
    if (index >= 0) {
        audio_hw_sync_t syncId = mHwAvSyncIds.valueAt(index);
        ALOGV("setAudioHwSyncForSession_l found ID %d for session %d", syncId, sessionId);
        AudioParameter param = AudioParameter();
        param.addInt(String8(AudioParameter::keyStreamHwAvSync), syncId);
        String8 keyValuePairs = param.toString();
        thread->setParameters(keyValuePairs);
        forwardParametersToDownstreamPatches_l(thread->id(), keyValuePairs,
                [](const sp<IAfPlaybackThread>& thread) { return thread->usesHwAvSync(); });
    }
}


// ----------------------------------------------------------------------------


sp<IAfThreadBase> AudioFlinger::openOutput_l(audio_module_handle_t module,
                                                        audio_io_handle_t *output,
                                                        audio_config_t *halConfig,
                                                        audio_config_base_t *mixerConfig,
                                                        audio_devices_t deviceType,
                                                        const String8& address,
                                                        audio_output_flags_t flags)
{
    AudioHwDevice *outHwDev = findSuitableHwDev_l(module, deviceType);
    if (outHwDev == NULL) {
        return nullptr;
    }

    if (*output == AUDIO_IO_HANDLE_NONE) {
        *output = nextUniqueId(AUDIO_UNIQUE_ID_USE_OUTPUT);
    } else {
        // Audio Policy does not currently request a specific output handle.
        // If this is ever needed, see openInput_l() for example code.
        ALOGE("openOutput_l requested output handle %d is not AUDIO_IO_HANDLE_NONE", *output);
        return nullptr;
    }

    mHardwareStatus = AUDIO_HW_OUTPUT_OPEN;
    AudioStreamOut *outputStream = NULL;
    status_t status = outHwDev->openOutputStream(
            &outputStream,
            *output,
            deviceType,
            flags,
            halConfig,
            address.c_str());

    mHardwareStatus = AUDIO_HW_IDLE;

    if (status == NO_ERROR) {
        if (flags & AUDIO_OUTPUT_FLAG_MMAP_NOIRQ) {
            const sp<IAfMmapPlaybackThread> thread = IAfMmapPlaybackThread::create(
                    this, *output, outHwDev, outputStream, mSystemReady);
            mMmapThreads.add(*output, thread);
            ALOGV("openOutput_l() created mmap playback thread: ID %d thread %p",
                  *output, thread.get());
            return thread;
        } else {
            sp<IAfPlaybackThread> thread;
            if (flags & AUDIO_OUTPUT_FLAG_BIT_PERFECT) {
                thread = IAfPlaybackThread::createBitPerfectThread(
                        this, outputStream, *output, mSystemReady);
                ALOGV("%s() created bit-perfect output: ID %d thread %p",
                      __func__, *output, thread.get());
            } else if (flags & AUDIO_OUTPUT_FLAG_SPATIALIZER) {
                thread = IAfPlaybackThread::createSpatializerThread(this, outputStream, *output,
                                                    mSystemReady, mixerConfig);
                ALOGV("openOutput_l() created spatializer output: ID %d thread %p",
                      *output, thread.get());
            } else if (flags & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) {
                thread = IAfPlaybackThread::createOffloadThread(this, outputStream, *output,
                        mSystemReady, halConfig->offload_info);
                ALOGV("openOutput_l() created offload output: ID %d thread %p",
                      *output, thread.get());
            } else if ((flags & AUDIO_OUTPUT_FLAG_DIRECT)
                    || !IAfThreadBase::isValidPcmSinkFormat(halConfig->format)
                    || !IAfThreadBase::isValidPcmSinkChannelMask(halConfig->channel_mask)) {
                thread = IAfPlaybackThread::createDirectOutputThread(this, outputStream, *output,
                        mSystemReady, halConfig->offload_info);
                ALOGV("openOutput_l() created direct output: ID %d thread %p",
                      *output, thread.get());
            } else {
                thread = IAfPlaybackThread::createMixerThread(
                        this, outputStream, *output, mSystemReady);
                ALOGV("openOutput_l() created mixer output: ID %d thread %p",
                      *output, thread.get());
            }
            mPlaybackThreads.add(*output, thread);
            struct audio_patch patch;
            mPatchPanel->notifyStreamOpened(outHwDev, *output, &patch);
            if (thread->isMsdDevice()) {
                thread->setDownStreamPatch(&patch);
            }
            thread->setBluetoothVariableLatencyEnabled(mBluetoothLatencyModesEnabled.load());
            return thread;
        }
    }

    return nullptr;
}

status_t AudioFlinger::openOutput(const media::OpenOutputRequest& request,
                                media::OpenOutputResponse* response)
{
    audio_module_handle_t module = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_module_handle_t(request.module));
    audio_config_t halConfig = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioConfig_audio_config_t(request.halConfig, false /*isInput*/));
    audio_config_base_t mixerConfig = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioConfigBase_audio_config_base_t(request.mixerConfig, false/*isInput*/));
    sp<DeviceDescriptorBase> device = VALUE_OR_RETURN_STATUS(
            aidl2legacy_DeviceDescriptorBase(request.device));
    audio_output_flags_t flags = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_output_flags_t_mask(request.flags));

    audio_io_handle_t output;

    ALOGI("openOutput() this %p, module %d Device %s, SamplingRate %d, Format %#08x, "
              "Channels %#x, flags %#x",
              this, module,
              device->toString().c_str(),
              halConfig.sample_rate,
              halConfig.format,
              halConfig.channel_mask,
              flags);

    audio_devices_t deviceType = device->type();
    const String8 address = String8(device->address().c_str());

    if (deviceType == AUDIO_DEVICE_NONE) {
        return BAD_VALUE;
    }

    Mutex::Autolock _l(mLock);

    const sp<IAfThreadBase> thread = openOutput_l(module, &output, &halConfig,
            &mixerConfig, deviceType, address, flags);
    if (thread != 0) {
        uint32_t latencyMs = 0;
        if ((flags & AUDIO_OUTPUT_FLAG_MMAP_NOIRQ) == 0) {
            const auto playbackThread = thread->asIAfPlaybackThread();
            latencyMs = playbackThread->latency();

            // notify client processes of the new output creation
            playbackThread->ioConfigChanged(AUDIO_OUTPUT_OPENED);

            // the first primary output opened designates the primary hw device if no HW module
            // named "primary" was already loaded.
            AutoMutex lock(mHardwareLock);
            if ((mPrimaryHardwareDev == nullptr) && (flags & AUDIO_OUTPUT_FLAG_PRIMARY)) {
                ALOGI("Using module %d as the primary audio interface", module);
                mPrimaryHardwareDev = playbackThread->getOutput()->audioHwDev;

                mHardwareStatus = AUDIO_HW_SET_MODE;
                mPrimaryHardwareDev->hwDevice()->setMode(mMode);
                mHardwareStatus = AUDIO_HW_IDLE;
            }
        } else {
            thread->ioConfigChanged(AUDIO_OUTPUT_OPENED);
        }
        response->output = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(output));
        response->config = VALUE_OR_RETURN_STATUS(
                legacy2aidl_audio_config_t_AudioConfig(halConfig, false /*isInput*/));
        response->latencyMs = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(latencyMs));
        response->flags = VALUE_OR_RETURN_STATUS(
                legacy2aidl_audio_output_flags_t_int32_t_mask(flags));
        return NO_ERROR;
    }

    return NO_INIT;
}

audio_io_handle_t AudioFlinger::openDuplicateOutput(audio_io_handle_t output1,
        audio_io_handle_t output2)
{
    Mutex::Autolock _l(mLock);
    IAfPlaybackThread* const thread1 = checkMixerThread_l(output1);
    IAfPlaybackThread* const thread2 = checkMixerThread_l(output2);

    if (thread1 == NULL || thread2 == NULL) {
        ALOGW("openDuplicateOutput() wrong output mixer type for output %d or %d", output1,
                output2);
        return AUDIO_IO_HANDLE_NONE;
    }

    audio_io_handle_t id = nextUniqueId(AUDIO_UNIQUE_ID_USE_OUTPUT);
    const sp<IAfDuplicatingThread> thread = IAfDuplicatingThread::create(
            this, thread1, id, mSystemReady);
    thread->addOutputTrack(thread2);
    mPlaybackThreads.add(id, thread);
    // notify client processes of the new output creation
    thread->ioConfigChanged(AUDIO_OUTPUT_OPENED);
    return id;
}

status_t AudioFlinger::closeOutput(audio_io_handle_t output)
{
    return closeOutput_nonvirtual(output);
}

status_t AudioFlinger::closeOutput_nonvirtual(audio_io_handle_t output)
{
    // keep strong reference on the playback thread so that
    // it is not destroyed while exit() is executed
    sp<IAfPlaybackThread> playbackThread;
    sp<IAfMmapPlaybackThread> mmapThread;
    {
        Mutex::Autolock _l(mLock);
        playbackThread = checkPlaybackThread_l(output);
        if (playbackThread != NULL) {
            ALOGV("closeOutput() %d", output);

            dumpToThreadLog_l(playbackThread);

            if (playbackThread->type() == IAfThreadBase::MIXER) {
                for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
                    if (mPlaybackThreads.valueAt(i)->isDuplicating()) {
                        IAfDuplicatingThread* const dupThread =
                                mPlaybackThreads.valueAt(i)->asIAfDuplicatingThread().get();
                        dupThread->removeOutputTrack(playbackThread.get());
                    }
                }
            }


            mPlaybackThreads.removeItem(output);
            // save all effects to the default thread
            if (mPlaybackThreads.size()) {
                IAfPlaybackThread* const dstThread =
                        checkPlaybackThread_l(mPlaybackThreads.keyAt(0));
                if (dstThread != NULL) {
                    // audioflinger lock is held so order of thread lock acquisition doesn't matter
                    Mutex::Autolock _dl(dstThread->mutex());
                    Mutex::Autolock _sl(playbackThread->mutex());
                    Vector<sp<IAfEffectChain>> effectChains = playbackThread->getEffectChains_l();
                    for (size_t i = 0; i < effectChains.size(); i ++) {
                        moveEffectChain_l(effectChains[i]->sessionId(), playbackThread.get(),
                                dstThread);
                    }
                }
            }
        } else {
            const sp<IAfMmapThread> mt = checkMmapThread_l(output);
            mmapThread = mt ? mt->asIAfMmapPlaybackThread().get() : nullptr;
            if (mmapThread == 0) {
                return BAD_VALUE;
            }
            dumpToThreadLog_l(mmapThread);
            mMmapThreads.removeItem(output);
            ALOGD("closing mmapThread %p", mmapThread.get());
        }
        ioConfigChanged(AUDIO_OUTPUT_CLOSED, sp<AudioIoDescriptor>::make(output));
        mPatchPanel->notifyStreamClosed(output);
    }
    // The thread entity (active unit of execution) is no longer running here,
    // but the IAfThreadBase container still exists.

    if (playbackThread != 0) {
        playbackThread->exit();
        if (!playbackThread->isDuplicating()) {
            closeOutputFinish(playbackThread);
        }
    } else if (mmapThread != 0) {
        ALOGD("mmapThread exit()");
        mmapThread->exit();
        AudioStreamOut *out = mmapThread->clearOutput();
        ALOG_ASSERT(out != NULL, "out shouldn't be NULL");
        // from now on thread->mOutput is NULL
        delete out;
    }
    return NO_ERROR;
}

void AudioFlinger::closeOutputFinish(const sp<IAfPlaybackThread>& thread)
{
    AudioStreamOut *out = thread->clearOutput();
    ALOG_ASSERT(out != NULL, "out shouldn't be NULL");
    // from now on thread->mOutput is NULL
    delete out;
}

void AudioFlinger::closeThreadInternal_l(const sp<IAfPlaybackThread>& thread)
{
    mPlaybackThreads.removeItem(thread->id());
    thread->exit();
    closeOutputFinish(thread);
}

status_t AudioFlinger::suspendOutput(audio_io_handle_t output)
{
    Mutex::Autolock _l(mLock);
    IAfPlaybackThread* const thread = checkPlaybackThread_l(output);

    if (thread == NULL) {
        return BAD_VALUE;
    }

    ALOGV("suspendOutput() %d", output);
    thread->suspend();

    return NO_ERROR;
}

status_t AudioFlinger::restoreOutput(audio_io_handle_t output)
{
    Mutex::Autolock _l(mLock);
    IAfPlaybackThread* const thread = checkPlaybackThread_l(output);

    if (thread == NULL) {
        return BAD_VALUE;
    }

    ALOGV("restoreOutput() %d", output);

    thread->restore();

    return NO_ERROR;
}

status_t AudioFlinger::openInput(const media::OpenInputRequest& request,
                                 media::OpenInputResponse* response)
{
    Mutex::Autolock _l(mLock);

    AudioDeviceTypeAddr device = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioDeviceTypeAddress(request.device));
    if (device.mType == AUDIO_DEVICE_NONE) {
        return BAD_VALUE;
    }

    audio_io_handle_t input = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_io_handle_t(request.input));
    audio_config_t config = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioConfig_audio_config_t(request.config, true /*isInput*/));

    const sp<IAfThreadBase> thread = openInput_l(
            VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_module_handle_t(request.module)),
            &input,
            &config,
            device.mType,
            device.address().c_str(),
            VALUE_OR_RETURN_STATUS(aidl2legacy_AudioSource_audio_source_t(request.source)),
            VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_input_flags_t_mask(request.flags)),
            AUDIO_DEVICE_NONE,
            String8{});

    response->input = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(input));
    response->config = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_config_t_AudioConfig(config, true /*isInput*/));
    response->device = request.device;

    if (thread != 0) {
        // notify client processes of the new input creation
        thread->ioConfigChanged(AUDIO_INPUT_OPENED);
        return NO_ERROR;
    }
    return NO_INIT;
}

sp<IAfThreadBase> AudioFlinger::openInput_l(audio_module_handle_t module,
                                                         audio_io_handle_t *input,
                                                         audio_config_t *config,
                                                         audio_devices_t devices,
                                                         const char* address,
                                                         audio_source_t source,
                                                         audio_input_flags_t flags,
                                                         audio_devices_t outputDevice,
                                                         const String8& outputDeviceAddress)
{
    AudioHwDevice *inHwDev = findSuitableHwDev_l(module, devices);
    if (inHwDev == NULL) {
        *input = AUDIO_IO_HANDLE_NONE;
        return 0;
    }

    // Audio Policy can request a specific handle for hardware hotword.
    // The goal here is not to re-open an already opened input.
    // It is to use a pre-assigned I/O handle.
    if (*input == AUDIO_IO_HANDLE_NONE) {
        *input = nextUniqueId(AUDIO_UNIQUE_ID_USE_INPUT);
    } else if (audio_unique_id_get_use(*input) != AUDIO_UNIQUE_ID_USE_INPUT) {
        ALOGE("openInput_l() requested input handle %d is invalid", *input);
        return 0;
    } else if (mRecordThreads.indexOfKey(*input) >= 0) {
        // This should not happen in a transient state with current design.
        ALOGE("openInput_l() requested input handle %d is already assigned", *input);
        return 0;
    }

    audio_config_t halconfig = *config;
    sp<DeviceHalInterface> inHwHal = inHwDev->hwDevice();
    sp<StreamInHalInterface> inStream;
    status_t status = inHwHal->openInputStream(
            *input, devices, &halconfig, flags, address, source,
            outputDevice, outputDeviceAddress, &inStream);
    ALOGV("openInput_l() openInputStream returned input %p, devices %#x, SamplingRate %d"
           ", Format %#x, Channels %#x, flags %#x, status %d addr %s",
            inStream.get(),
            devices,
            halconfig.sample_rate,
            halconfig.format,
            halconfig.channel_mask,
            flags,
            status, address);

    // If the input could not be opened with the requested parameters and we can handle the
    // conversion internally, try to open again with the proposed parameters.
    if (status == BAD_VALUE &&
        audio_is_linear_pcm(config->format) &&
        audio_is_linear_pcm(halconfig.format) &&
        (halconfig.sample_rate <= AUDIO_RESAMPLER_DOWN_RATIO_MAX * config->sample_rate) &&
        (audio_channel_count_from_in_mask(halconfig.channel_mask) <= FCC_LIMIT) &&
        (audio_channel_count_from_in_mask(config->channel_mask) <= FCC_LIMIT)) {
        // FIXME describe the change proposed by HAL (save old values so we can log them here)
        ALOGV("openInput_l() reopening with proposed sampling rate and channel mask");
        inStream.clear();
        status = inHwHal->openInputStream(
                *input, devices, &halconfig, flags, address, source,
                outputDevice, outputDeviceAddress, &inStream);
        // FIXME log this new status; HAL should not propose any further changes
    }

    if (status == NO_ERROR && inStream != 0) {
        AudioStreamIn *inputStream = new AudioStreamIn(inHwDev, inStream, flags);
        if ((flags & AUDIO_INPUT_FLAG_MMAP_NOIRQ) != 0) {
            const sp<IAfMmapCaptureThread> thread =
                    IAfMmapCaptureThread::create(this, *input, inHwDev, inputStream, mSystemReady);
            mMmapThreads.add(*input, thread);
            ALOGV("openInput_l() created mmap capture thread: ID %d thread %p", *input,
                    thread.get());
            return thread;
        } else {
            // Start record thread
            // IAfRecordThread requires both input and output device indication
            // to forward to audio pre processing modules
            const sp<IAfRecordThread> thread =
                    IAfRecordThread::create(this, inputStream, *input, mSystemReady);
            mRecordThreads.add(*input, thread);
            ALOGV("openInput_l() created record thread: ID %d thread %p", *input, thread.get());
            return thread;
        }
    }

    *input = AUDIO_IO_HANDLE_NONE;
    return 0;
}

status_t AudioFlinger::closeInput(audio_io_handle_t input)
{
    return closeInput_nonvirtual(input);
}

status_t AudioFlinger::closeInput_nonvirtual(audio_io_handle_t input)
{
    // keep strong reference on the record thread so that
    // it is not destroyed while exit() is executed
    sp<IAfRecordThread> recordThread;
    sp<IAfMmapCaptureThread> mmapThread;
    {
        Mutex::Autolock _l(mLock);
        recordThread = checkRecordThread_l(input);
        if (recordThread != 0) {
            ALOGV("closeInput() %d", input);

            dumpToThreadLog_l(recordThread);

            // If we still have effect chains, it means that a client still holds a handle
            // on at least one effect. We must either move the chain to an existing thread with the
            // same session ID or put it aside in case a new record thread is opened for a
            // new capture on the same session
            sp<IAfEffectChain> chain;
            {
                Mutex::Autolock _sl(recordThread->mutex());
                const Vector<sp<IAfEffectChain>> effectChains = recordThread->getEffectChains_l();
                // Note: maximum one chain per record thread
                if (effectChains.size() != 0) {
                    chain = effectChains[0];
                }
            }
            if (chain != 0) {
                // first check if a record thread is already opened with a client on same session.
                // This should only happen in case of overlap between one thread tear down and the
                // creation of its replacement
                size_t i;
                for (i = 0; i < mRecordThreads.size(); i++) {
                    const sp<IAfRecordThread> t = mRecordThreads.valueAt(i);
                    if (t == recordThread) {
                        continue;
                    }
                    if (t->hasAudioSession(chain->sessionId()) != 0) {
                        Mutex::Autolock _l2(t->mutex());
                        ALOGV("closeInput() found thread %d for effect session %d",
                              t->id(), chain->sessionId());
                        t->addEffectChain_l(chain);
                        break;
                    }
                }
                // put the chain aside if we could not find a record thread with the same session id
                if (i == mRecordThreads.size()) {
                    putOrphanEffectChain_l(chain);
                }
            }
            mRecordThreads.removeItem(input);
        } else {
            const sp<IAfMmapThread> mt = checkMmapThread_l(input);
            mmapThread = mt ? mt->asIAfMmapCaptureThread().get() : nullptr;
            if (mmapThread == 0) {
                return BAD_VALUE;
            }
            dumpToThreadLog_l(mmapThread);
            mMmapThreads.removeItem(input);
        }
        ioConfigChanged(AUDIO_INPUT_CLOSED, sp<AudioIoDescriptor>::make(input));
    }
    // FIXME: calling thread->exit() without mLock held should not be needed anymore now that
    // we have a different lock for notification client
    if (recordThread != 0) {
        closeInputFinish(recordThread);
    } else if (mmapThread != 0) {
        mmapThread->exit();
        AudioStreamIn *in = mmapThread->clearInput();
        ALOG_ASSERT(in != NULL, "in shouldn't be NULL");
        // from now on thread->mInput is NULL
        delete in;
    }
    return NO_ERROR;
}

void AudioFlinger::closeInputFinish(const sp<IAfRecordThread>& thread)
{
    thread->exit();
    AudioStreamIn *in = thread->clearInput();
    ALOG_ASSERT(in != NULL, "in shouldn't be NULL");
    // from now on thread->mInput is NULL
    delete in;
}

void AudioFlinger::closeThreadInternal_l(const sp<IAfRecordThread>& thread)
{
    mRecordThreads.removeItem(thread->id());
    closeInputFinish(thread);
}

status_t AudioFlinger::invalidateTracks(const std::vector<audio_port_handle_t> &portIds) {
    Mutex::Autolock _l(mLock);
    ALOGV("%s", __func__);

    std::set<audio_port_handle_t> portIdSet(portIds.begin(), portIds.end());
    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        IAfPlaybackThread* const thread = mPlaybackThreads.valueAt(i).get();
        thread->invalidateTracks(portIdSet);
        if (portIdSet.empty()) {
            return NO_ERROR;
        }
    }
    for (size_t i = 0; i < mMmapThreads.size(); i++) {
        mMmapThreads[i]->invalidateTracks(portIdSet);
        if (portIdSet.empty()) {
            return NO_ERROR;
        }
    }
    return NO_ERROR;
}


audio_unique_id_t AudioFlinger::newAudioUniqueId(audio_unique_id_use_t use)
{
    // This is a binder API, so a malicious client could pass in a bad parameter.
    // Check for that before calling the internal API nextUniqueId().
    if ((unsigned) use >= (unsigned) AUDIO_UNIQUE_ID_USE_MAX) {
        ALOGE("newAudioUniqueId invalid use %d", use);
        return AUDIO_UNIQUE_ID_ALLOCATE;
    }
    return nextUniqueId(use);
}

void AudioFlinger::acquireAudioSessionId(
        audio_session_t audioSession, pid_t pid, uid_t uid)
{
    Mutex::Autolock _l(mLock);
    pid_t caller = IPCThreadState::self()->getCallingPid();
    ALOGV("acquiring %d from %d, for %d", audioSession, caller, pid);
    const uid_t callerUid = IPCThreadState::self()->getCallingUid();
    if (pid != (pid_t)-1 && isAudioServerOrMediaServerUid(callerUid)) {
        caller = pid;  // check must match releaseAudioSessionId()
    }
    if (uid == (uid_t)-1 || !isAudioServerOrMediaServerUid(callerUid)) {
        uid = callerUid;
    }

    {
        Mutex::Autolock _cl(mClientLock);
        // Ignore requests received from processes not known as notification client. The request
        // is likely proxied by mediaserver (e.g CameraService) and releaseAudioSessionId() can be
        // called from a different pid leaving a stale session reference.  Also we don't know how
        // to clear this reference if the client process dies.
        if (mNotificationClients.indexOfKey(caller) < 0) {
            ALOGW("acquireAudioSessionId() unknown client %d for session %d", caller, audioSession);
            return;
        }
    }

    size_t num = mAudioSessionRefs.size();
    for (size_t i = 0; i < num; i++) {
        AudioSessionRef *ref = mAudioSessionRefs.editItemAt(i);
        if (ref->mSessionid == audioSession && ref->mPid == caller) {
            ref->mCnt++;
            ALOGV(" incremented refcount to %d", ref->mCnt);
            return;
        }
    }
    mAudioSessionRefs.push(new AudioSessionRef(audioSession, caller, uid));
    ALOGV(" added new entry for %d", audioSession);
}

void AudioFlinger::releaseAudioSessionId(audio_session_t audioSession, pid_t pid)
{
    std::vector<sp<IAfEffectModule>> removedEffects;
    {
        Mutex::Autolock _l(mLock);
        pid_t caller = IPCThreadState::self()->getCallingPid();
        ALOGV("releasing %d from %d for %d", audioSession, caller, pid);
        const uid_t callerUid = IPCThreadState::self()->getCallingUid();
        if (pid != (pid_t)-1 && isAudioServerOrMediaServerUid(callerUid)) {
            caller = pid;  // check must match acquireAudioSessionId()
        }
        size_t num = mAudioSessionRefs.size();
        for (size_t i = 0; i < num; i++) {
            AudioSessionRef *ref = mAudioSessionRefs.itemAt(i);
            if (ref->mSessionid == audioSession && ref->mPid == caller) {
                ref->mCnt--;
                ALOGV(" decremented refcount to %d", ref->mCnt);
                if (ref->mCnt == 0) {
                    mAudioSessionRefs.removeAt(i);
                    delete ref;
                    std::vector<sp<IAfEffectModule>> effects = purgeStaleEffects_l();
                    removedEffects.insert(removedEffects.end(), effects.begin(), effects.end());
                }
                goto Exit;
            }
        }
        // If the caller is audioserver it is likely that the session being released was acquired
        // on behalf of a process not in notification clients and we ignore the warning.
        ALOGW_IF(!isAudioServerUid(callerUid),
                 "session id %d not found for pid %d", audioSession, caller);
    }

Exit:
    for (auto& effect : removedEffects) {
        effect->updatePolicyState();
    }
}

bool AudioFlinger::isSessionAcquired_l(audio_session_t audioSession)
{
    size_t num = mAudioSessionRefs.size();
    for (size_t i = 0; i < num; i++) {
        AudioSessionRef *ref = mAudioSessionRefs.itemAt(i);
        if (ref->mSessionid == audioSession) {
            return true;
        }
    }
    return false;
}

std::vector<sp<IAfEffectModule>> AudioFlinger::purgeStaleEffects_l() {

    ALOGV("purging stale effects");

    Vector<sp<IAfEffectChain>> chains;
    std::vector< sp<IAfEffectModule> > removedEffects;

    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        sp<IAfPlaybackThread> t = mPlaybackThreads.valueAt(i);
        Mutex::Autolock _l(t->mutex());
        const Vector<sp<IAfEffectChain>> threadChains = t->getEffectChains_l();
        for (size_t j = 0; j < threadChains.size(); j++) {
            sp<IAfEffectChain> ec = threadChains[j];
            if (!audio_is_global_session(ec->sessionId())) {
                chains.push(ec);
            }
        }
    }

    for (size_t i = 0; i < mRecordThreads.size(); i++) {
        sp<IAfRecordThread> t = mRecordThreads.valueAt(i);
        Mutex::Autolock _l(t->mutex());
        const Vector<sp<IAfEffectChain>> threadChains = t->getEffectChains_l();
        for (size_t j = 0; j < threadChains.size(); j++) {
            sp<IAfEffectChain> ec = threadChains[j];
            chains.push(ec);
        }
    }

    for (size_t i = 0; i < mMmapThreads.size(); i++) {
        const sp<IAfMmapThread> t = mMmapThreads.valueAt(i);
        Mutex::Autolock _l(t->mutex());
        const Vector<sp<IAfEffectChain>> threadChains = t->getEffectChains_l();
        for (size_t j = 0; j < threadChains.size(); j++) {
            sp<IAfEffectChain> ec = threadChains[j];
            chains.push(ec);
        }
    }

    for (size_t i = 0; i < chains.size(); i++) {
         // clang-tidy suggests const ref
        sp<IAfEffectChain> ec = chains[i];  // NOLINT(performance-unnecessary-copy-initialization)
        int sessionid = ec->sessionId();
        const auto t = ec->thread().promote();
        if (t == 0) {
            continue;
        }
        size_t numsessionrefs = mAudioSessionRefs.size();
        bool found = false;
        for (size_t k = 0; k < numsessionrefs; k++) {
            AudioSessionRef *ref = mAudioSessionRefs.itemAt(k);
            if (ref->mSessionid == sessionid) {
                ALOGV(" session %d still exists for %d with %d refs",
                    sessionid, ref->mPid, ref->mCnt);
                found = true;
                break;
            }
        }
        if (!found) {
            Mutex::Autolock _l(t->mutex());
            // remove all effects from the chain
            while (ec->numberOfEffects()) {
                sp<IAfEffectModule> effect = ec->getEffectModule(0);
                effect->unPin();
                t->removeEffect_l(effect, /*release*/ true);
                if (effect->purgeHandles()) {
                    effect->checkSuspendOnEffectEnabled(false, true /*threadLocked*/);
                }
                removedEffects.push_back(effect);
            }
        }
    }
    return removedEffects;
}

// dumpToThreadLog_l() must be called with AudioFlinger::mLock held
void AudioFlinger::dumpToThreadLog_l(const sp<IAfThreadBase> &thread)
{
    constexpr int THREAD_DUMP_TIMEOUT_MS = 2;
    audio_utils::FdToString fdToString("- ", THREAD_DUMP_TIMEOUT_MS);
    const int fd = fdToString.fd();
    if (fd >= 0) {
        thread->dump(fd, {} /* args */);
        mThreadLog.logs(-1 /* time */, fdToString.getStringAndClose());
    }
}

// checkThread_l() must be called with AudioFlinger::mLock held
IAfThreadBase* AudioFlinger::checkThread_l(audio_io_handle_t ioHandle) const
{
    IAfThreadBase* thread = checkMmapThread_l(ioHandle);
    if (thread == 0) {
        switch (audio_unique_id_get_use(ioHandle)) {
        case AUDIO_UNIQUE_ID_USE_OUTPUT:
            thread = checkPlaybackThread_l(ioHandle);
            break;
        case AUDIO_UNIQUE_ID_USE_INPUT:
            thread = checkRecordThread_l(ioHandle);
            break;
        default:
            break;
        }
    }
    return thread;
}

// checkOutputThread_l() must be called with AudioFlinger::mLock held
sp<IAfThreadBase> AudioFlinger::checkOutputThread_l(audio_io_handle_t ioHandle) const
{
    if (audio_unique_id_get_use(ioHandle) != AUDIO_UNIQUE_ID_USE_OUTPUT) {
        return nullptr;
    }

    sp<IAfThreadBase> thread = mPlaybackThreads.valueFor(ioHandle);
    if (thread == nullptr) {
        thread = mMmapThreads.valueFor(ioHandle);
    }
    return thread;
}

// checkPlaybackThread_l() must be called with AudioFlinger::mLock held
IAfPlaybackThread* AudioFlinger::checkPlaybackThread_l(audio_io_handle_t output) const
{
    return mPlaybackThreads.valueFor(output).get();
}

// checkMixerThread_l() must be called with AudioFlinger::mLock held
IAfPlaybackThread* AudioFlinger::checkMixerThread_l(audio_io_handle_t output) const
{
    IAfPlaybackThread * const thread = checkPlaybackThread_l(output);
    return thread != nullptr && thread->type() != IAfThreadBase::DIRECT ? thread : nullptr;
}

// checkRecordThread_l() must be called with AudioFlinger::mLock held
IAfRecordThread* AudioFlinger::checkRecordThread_l(audio_io_handle_t input) const
{
    return mRecordThreads.valueFor(input).get();
}

// checkMmapThread_l() must be called with AudioFlinger::mLock held
IAfMmapThread* AudioFlinger::checkMmapThread_l(audio_io_handle_t io) const
{
    return mMmapThreads.valueFor(io).get();
}


// checkPlaybackThread_l() must be called with AudioFlinger::mLock held
sp<VolumeInterface> AudioFlinger::getVolumeInterface_l(audio_io_handle_t output) const
{
    sp<VolumeInterface> volumeInterface = mPlaybackThreads.valueFor(output).get();
    if (volumeInterface == nullptr) {
        IAfMmapThread* const mmapThread = mMmapThreads.valueFor(output).get();
        if (mmapThread != nullptr) {
            if (mmapThread->isOutput()) {
                IAfMmapPlaybackThread* const mmapPlaybackThread =
                        mmapThread->asIAfMmapPlaybackThread().get();
                volumeInterface = mmapPlaybackThread;
            }
        }
    }
    return volumeInterface;
}

std::vector<sp<VolumeInterface>> AudioFlinger::getAllVolumeInterfaces_l() const
{
    std::vector<sp<VolumeInterface>> volumeInterfaces;
    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        volumeInterfaces.push_back(mPlaybackThreads.valueAt(i).get());
    }
    for (size_t i = 0; i < mMmapThreads.size(); i++) {
        if (mMmapThreads.valueAt(i)->isOutput()) {
            IAfMmapPlaybackThread* const mmapPlaybackThread =
                    mMmapThreads.valueAt(i)->asIAfMmapPlaybackThread().get();
            volumeInterfaces.push_back(mmapPlaybackThread);
        }
    }
    return volumeInterfaces;
}

audio_unique_id_t AudioFlinger::nextUniqueId(audio_unique_id_use_t use)
{
    // This is the internal API, so it is OK to assert on bad parameter.
    LOG_ALWAYS_FATAL_IF((unsigned) use >= (unsigned) AUDIO_UNIQUE_ID_USE_MAX);
    const int maxRetries = use == AUDIO_UNIQUE_ID_USE_SESSION ? 3 : 1;
    for (int retry = 0; retry < maxRetries; retry++) {
        // The cast allows wraparound from max positive to min negative instead of abort
        uint32_t base = (uint32_t) atomic_fetch_add_explicit(&mNextUniqueIds[use],
                (uint_fast32_t) AUDIO_UNIQUE_ID_USE_MAX, memory_order_acq_rel);
        ALOG_ASSERT(audio_unique_id_get_use(base) == AUDIO_UNIQUE_ID_USE_UNSPECIFIED);
        // allow wrap by skipping 0 and -1 for session ids
        if (!(base == 0 || base == (~0u & ~AUDIO_UNIQUE_ID_USE_MASK))) {
            ALOGW_IF(retry != 0, "unique ID overflow for use %d", use);
            return (audio_unique_id_t) (base | use);
        }
    }
    // We have no way of recovering from wraparound
    LOG_ALWAYS_FATAL("unique ID overflow for use %d", use);
    // TODO Use a floor after wraparound.  This may need a mutex.
}

IAfPlaybackThread* AudioFlinger::primaryPlaybackThread_l() const
{
    AutoMutex lock(mHardwareLock);
    if (mPrimaryHardwareDev == nullptr) {
        return nullptr;
    }
    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        IAfPlaybackThread* const thread = mPlaybackThreads.valueAt(i).get();
        if(thread->isDuplicating()) {
            continue;
        }
        AudioStreamOut *output = thread->getOutput();
        if (output != NULL && output->audioHwDev == mPrimaryHardwareDev) {
            return thread;
        }
    }
    return nullptr;
}

DeviceTypeSet AudioFlinger::primaryOutputDevice_l() const
{
    IAfPlaybackThread* const thread = primaryPlaybackThread_l();

    if (thread == NULL) {
        return {};
    }

    return thread->outDeviceTypes();
}

IAfPlaybackThread* AudioFlinger::fastPlaybackThread_l() const
{
    size_t minFrameCount = 0;
    IAfPlaybackThread* minThread = nullptr;
    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        IAfPlaybackThread* const thread = mPlaybackThreads.valueAt(i).get();
        if (!thread->isDuplicating()) {
            size_t frameCount = thread->frameCountHAL();
            if (frameCount != 0 && (minFrameCount == 0 || frameCount < minFrameCount ||
                    (frameCount == minFrameCount && thread->hasFastMixer() &&
                    /*minThread != NULL &&*/ !minThread->hasFastMixer()))) {
                minFrameCount = frameCount;
                minThread = thread;
            }
        }
    }
    return minThread;
}

IAfThreadBase* AudioFlinger::hapticPlaybackThread_l() const {
    for (size_t i  = 0; i < mPlaybackThreads.size(); ++i) {
        IAfPlaybackThread* const thread = mPlaybackThreads.valueAt(i).get();
        if (thread->hapticChannelMask() != AUDIO_CHANNEL_NONE) {
            return thread;
        }
    }
    return nullptr;
}

void AudioFlinger::updateSecondaryOutputsForTrack_l(
        IAfTrack* track,
        IAfPlaybackThread* thread,
        const std::vector<audio_io_handle_t> &secondaryOutputs) const {
    TeePatches teePatches;
    for (audio_io_handle_t secondaryOutput : secondaryOutputs) {
        IAfPlaybackThread* const secondaryThread = checkPlaybackThread_l(secondaryOutput);
        if (secondaryThread == nullptr) {
            ALOGE("no playback thread found for secondary output %d", thread->id());
            continue;
        }

        size_t sourceFrameCount = thread->frameCount() * track->sampleRate()
                                  / thread->sampleRate();
        size_t sinkFrameCount = secondaryThread->frameCount() * track->sampleRate()
                                  / secondaryThread->sampleRate();
        // If the secondary output has just been opened, the first secondaryThread write
        // will not block as it will fill the empty startup buffer of the HAL,
        // so a second sink buffer needs to be ready for the immediate next blocking write.
        // Additionally, have a margin of one main thread buffer as the scheduling jitter
        // can reorder the writes (eg if thread A&B have the same write intervale,
        // the scheduler could schedule AB...BA)
        size_t frameCountToBeReady = 2 * sinkFrameCount + sourceFrameCount;
        // Total secondary output buffer must be at least as the read frames plus
        // the margin of a few buffers on both sides in case the
        // threads scheduling has some jitter.
        // That value should not impact latency as the secondary track is started before
        // its buffer is full, see frameCountToBeReady.
        size_t frameCount = frameCountToBeReady + 2 * (sourceFrameCount + sinkFrameCount);
        // The frameCount should also not be smaller than the secondary thread min frame
        // count
        size_t minFrameCount = AudioSystem::calculateMinFrameCount(
                    [&] { Mutex::Autolock _l(secondaryThread->mutex());
                          return secondaryThread->latency_l(); }(),
                    secondaryThread->frameCount(), // normal frame count
                    secondaryThread->sampleRate(),
                    track->sampleRate(),
                    track->getSpeed());
        frameCount = std::max(frameCount, minFrameCount);

        using namespace std::chrono_literals;
        auto inChannelMask = audio_channel_mask_out_to_in(track->channelMask());
        if (inChannelMask == AUDIO_CHANNEL_INVALID) {
            // The downstream PatchTrack has the proper output channel mask,
            // so if there is no input channel mask equivalent, we can just
            // use an index mask here to create the PatchRecord.
            inChannelMask = audio_channel_mask_out_to_in_index_mask(track->channelMask());
        }
        sp<IAfPatchRecord> patchRecord = IAfPatchRecord::create(nullptr /* thread */,
                                                       track->sampleRate(),
                                                       inChannelMask,
                                                       track->format(),
                                                       frameCount,
                                                       nullptr /* buffer */,
                                                       (size_t)0 /* bufferSize */,
                                                       AUDIO_INPUT_FLAG_DIRECT,
                                                       0ns /* timeout */);
        status_t status = patchRecord->initCheck();
        if (status != NO_ERROR) {
            ALOGE("Secondary output patchRecord init failed: %d", status);
            continue;
        }

        // TODO: We could check compatibility of the secondaryThread with the PatchTrack
        // for fast usage: thread has fast mixer, sample rate matches, etc.;
        // for now, we exclude fast tracks by removing the Fast flag.
        const audio_output_flags_t outputFlags =
                (audio_output_flags_t)(track->getOutputFlags() & ~AUDIO_OUTPUT_FLAG_FAST);
        sp<IAfPatchTrack> patchTrack = IAfPatchTrack::create(secondaryThread,
                                                       track->streamType(),
                                                       track->sampleRate(),
                                                       track->channelMask(),
                                                       track->format(),
                                                       frameCount,
                                                       patchRecord->buffer(),
                                                       patchRecord->bufferSize(),
                                                       outputFlags,
                                                       0ns /* timeout */,
                                                       frameCountToBeReady);
        status = patchTrack->initCheck();
        if (status != NO_ERROR) {
            ALOGE("Secondary output patchTrack init failed: %d", status);
            continue;
        }
        teePatches.push_back({patchRecord, patchTrack});
        secondaryThread->addPatchTrack(patchTrack);
        // In case the downstream patchTrack on the secondaryThread temporarily outlives
        // our created track, ensure the corresponding patchRecord is still alive.
        patchTrack->setPeerProxy(patchRecord, true /* holdReference */);
        patchRecord->setPeerProxy(patchTrack, false /* holdReference */);
    }
    track->setTeePatchesToUpdate(std::move(teePatches));
}

sp<audioflinger::SyncEvent> AudioFlinger::createSyncEvent(AudioSystem::sync_event_t type,
                                    audio_session_t triggerSession,
                                    audio_session_t listenerSession,
                                    const audioflinger::SyncEventCallback& callBack,
                                    const wp<IAfTrackBase>& cookie)
{
    Mutex::Autolock _l(mLock);

    auto event = sp<audioflinger::SyncEvent>::make(
            type, triggerSession, listenerSession, callBack, cookie);
    status_t playStatus = NAME_NOT_FOUND;
    status_t recStatus = NAME_NOT_FOUND;
    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        playStatus = mPlaybackThreads.valueAt(i)->setSyncEvent(event);
        if (playStatus == NO_ERROR) {
            return event;
        }
    }
    for (size_t i = 0; i < mRecordThreads.size(); i++) {
        recStatus = mRecordThreads.valueAt(i)->setSyncEvent(event);
        if (recStatus == NO_ERROR) {
            return event;
        }
    }
    if (playStatus == NAME_NOT_FOUND || recStatus == NAME_NOT_FOUND) {
        mPendingSyncEvents.emplace_back(event);
    } else {
        ALOGV("createSyncEvent() invalid event %d", event->type());
        event.clear();
    }
    return event;
}

// ----------------------------------------------------------------------------
//  Effect management
// ----------------------------------------------------------------------------

sp<EffectsFactoryHalInterface> AudioFlinger::getEffectsFactory() {
    return mEffectsFactoryHal;
}

status_t AudioFlinger::queryNumberEffects(uint32_t *numEffects) const
{
    Mutex::Autolock _l(mLock);
    if (mEffectsFactoryHal.get()) {
        return mEffectsFactoryHal->queryNumberEffects(numEffects);
    } else {
        return -ENODEV;
    }
}

status_t AudioFlinger::queryEffect(uint32_t index, effect_descriptor_t *descriptor) const
{
    Mutex::Autolock _l(mLock);
    if (mEffectsFactoryHal.get()) {
        return mEffectsFactoryHal->getDescriptor(index, descriptor);
    } else {
        return -ENODEV;
    }
}

status_t AudioFlinger::getEffectDescriptor(const effect_uuid_t *pUuid,
                                           const effect_uuid_t *pTypeUuid,
                                           uint32_t preferredTypeFlag,
                                           effect_descriptor_t *descriptor) const
{
    if (pUuid == NULL || pTypeUuid == NULL || descriptor == NULL) {
        return BAD_VALUE;
    }

    Mutex::Autolock _l(mLock);

    if (!mEffectsFactoryHal.get()) {
        return -ENODEV;
    }

    status_t status = NO_ERROR;
    if (!EffectsFactoryHalInterface::isNullUuid(pUuid)) {
        // If uuid is specified, request effect descriptor from that.
        status = mEffectsFactoryHal->getDescriptor(pUuid, descriptor);
    } else if (!EffectsFactoryHalInterface::isNullUuid(pTypeUuid)) {
        // If uuid is not specified, look for an available implementation
        // of the required type instead.

        // Use a temporary descriptor to avoid modifying |descriptor| in the failure case.
        effect_descriptor_t desc;
        desc.flags = 0; // prevent compiler warning

        uint32_t numEffects = 0;
        status = mEffectsFactoryHal->queryNumberEffects(&numEffects);
        if (status < 0) {
            ALOGW("getEffectDescriptor() error %d from FactoryHal queryNumberEffects", status);
            return status;
        }

        bool found = false;
        for (uint32_t i = 0; i < numEffects; i++) {
            status = mEffectsFactoryHal->getDescriptor(i, &desc);
            if (status < 0) {
                ALOGW("getEffectDescriptor() error %d from FactoryHal getDescriptor", status);
                continue;
            }
            if (memcmp(&desc.type, pTypeUuid, sizeof(effect_uuid_t)) == 0) {
                // If matching type found save effect descriptor.
                found = true;
                *descriptor = desc;

                // If there's no preferred flag or this descriptor matches the preferred
                // flag, success! If this descriptor doesn't match the preferred
                // flag, continue enumeration in case a better matching version of this
                // effect type is available. Note that this means if no effect with a
                // correct flag is found, the descriptor returned will correspond to the
                // last effect that at least had a matching type uuid (if any).
                if (preferredTypeFlag == EFFECT_FLAG_TYPE_MASK ||
                    (desc.flags & EFFECT_FLAG_TYPE_MASK) == preferredTypeFlag) {
                    break;
                }
            }
        }

        if (!found) {
            status = NAME_NOT_FOUND;
            ALOGW("getEffectDescriptor(): Effect not found by type.");
        }
    } else {
        status = BAD_VALUE;
        ALOGE("getEffectDescriptor(): Either uuid or type uuid must be non-null UUIDs.");
    }
    return status;
}

status_t AudioFlinger::createEffect(const media::CreateEffectRequest& request,
                                    media::CreateEffectResponse* response) {
    const sp<IEffectClient>& effectClient = request.client;
    const int32_t priority = request.priority;
    const AudioDeviceTypeAddr device = VALUE_OR_RETURN_STATUS(
            aidl2legacy_AudioDeviceTypeAddress(request.device));
    AttributionSourceState adjAttributionSource = request.attributionSource;
    const audio_session_t sessionId = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_session_t(request.sessionId));
    audio_io_handle_t io = VALUE_OR_RETURN_STATUS(
            aidl2legacy_int32_t_audio_io_handle_t(request.output));
    const effect_descriptor_t descIn = VALUE_OR_RETURN_STATUS(
            aidl2legacy_EffectDescriptor_effect_descriptor_t(request.desc));
    const bool probe = request.probe;

    sp<IAfEffectHandle> handle;
    effect_descriptor_t descOut;
    int enabledOut = 0;
    int idOut = -1;

    status_t lStatus = NO_ERROR;

    // TODO b/182392553: refactor or make clearer
    const uid_t callingUid = IPCThreadState::self()->getCallingUid();
    adjAttributionSource.uid = VALUE_OR_RETURN_STATUS(legacy2aidl_uid_t_int32_t(callingUid));
    pid_t currentPid = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_pid_t(adjAttributionSource.pid));
    if (currentPid == -1 || !isAudioServerOrMediaServerOrSystemServerOrRootUid(callingUid)) {
        const pid_t callingPid = IPCThreadState::self()->getCallingPid();
        ALOGW_IF(currentPid != -1 && currentPid != callingPid,
                 "%s uid %d pid %d tried to pass itself off as pid %d",
                 __func__, callingUid, callingPid, currentPid);
        adjAttributionSource.pid = VALUE_OR_RETURN_STATUS(legacy2aidl_pid_t_int32_t(callingPid));
        currentPid = callingPid;
    }
    adjAttributionSource = afutils::checkAttributionSourcePackage(adjAttributionSource);

    ALOGV("createEffect pid %d, effectClient %p, priority %d, sessionId %d, io %d, factory %p",
          adjAttributionSource.pid, effectClient.get(), priority, sessionId, io,
          mEffectsFactoryHal.get());

    if (mEffectsFactoryHal == 0) {
        ALOGE("%s: no effects factory hal", __func__);
        lStatus = NO_INIT;
        goto Exit;
    }

    // check audio settings permission for global effects
    if (sessionId == AUDIO_SESSION_OUTPUT_MIX) {
        if (!settingsAllowed()) {
            ALOGE("%s: no permission for AUDIO_SESSION_OUTPUT_MIX", __func__);
            lStatus = PERMISSION_DENIED;
            goto Exit;
        }
    } else if (sessionId == AUDIO_SESSION_OUTPUT_STAGE) {
        if (io == AUDIO_IO_HANDLE_NONE) {
            ALOGE("%s: APM must specify output when using AUDIO_SESSION_OUTPUT_STAGE", __func__);
            lStatus = BAD_VALUE;
            goto Exit;
        }
        IAfPlaybackThread* const thread = checkPlaybackThread_l(io);
        if (thread == nullptr) {
            ALOGE("%s: invalid output %d specified for AUDIO_SESSION_OUTPUT_STAGE", __func__, io);
            lStatus = BAD_VALUE;
            goto Exit;
        }
        if (!modifyDefaultAudioEffectsAllowed(adjAttributionSource)
                && !isAudioServerUid(callingUid)) {
            ALOGE("%s: effect on AUDIO_SESSION_OUTPUT_STAGE not granted for uid %d",
                    __func__, callingUid);
            lStatus = PERMISSION_DENIED;
            goto Exit;
        }
    } else if (sessionId == AUDIO_SESSION_DEVICE) {
        if (!modifyDefaultAudioEffectsAllowed(adjAttributionSource)) {
            ALOGE("%s: device effect permission denied for uid %d", __func__, callingUid);
            lStatus = PERMISSION_DENIED;
            goto Exit;
        }
        if (io != AUDIO_IO_HANDLE_NONE) {
            ALOGE("%s: io handle should not be specified for device effect", __func__);
            lStatus = BAD_VALUE;
            goto Exit;
        }
    } else {
        // general sessionId.

        if (audio_unique_id_get_use(sessionId) != AUDIO_UNIQUE_ID_USE_SESSION) {
            ALOGE("%s: invalid sessionId %d", __func__, sessionId);
            lStatus = BAD_VALUE;
            goto Exit;
        }

        // TODO: should we check if the callingUid (limited to pid) is in mAudioSessionRefs
        // to prevent creating an effect when one doesn't actually have track with that session?
    }

    {
        // Get the full effect descriptor from the uuid/type.
        // If the session is the output mix, prefer an auxiliary effect,
        // otherwise no preference.
        uint32_t preferredType = (sessionId == AUDIO_SESSION_OUTPUT_MIX ?
                                  EFFECT_FLAG_TYPE_AUXILIARY : EFFECT_FLAG_TYPE_MASK);
        lStatus = getEffectDescriptor(&descIn.uuid, &descIn.type, preferredType, &descOut);
        if (lStatus < 0) {
            ALOGW("createEffect() error %d from getEffectDescriptor", lStatus);
            goto Exit;
        }

        // Do not allow auxiliary effects on a session different from 0 (output mix)
        if (sessionId != AUDIO_SESSION_OUTPUT_MIX &&
             (descOut.flags & EFFECT_FLAG_TYPE_MASK) == EFFECT_FLAG_TYPE_AUXILIARY) {
            lStatus = INVALID_OPERATION;
            goto Exit;
        }

        // check recording permission for visualizer
        if ((memcmp(&descOut.type, SL_IID_VISUALIZATION, sizeof(effect_uuid_t)) == 0) &&
            // TODO: Do we need to start/stop op - i.e. is there recording being performed?
            !recordingAllowed(adjAttributionSource)) {
            lStatus = PERMISSION_DENIED;
            goto Exit;
        }

        const bool hapticPlaybackRequired = IAfEffectModule::isHapticGenerator(&descOut.type);
        if (hapticPlaybackRequired
                && (sessionId == AUDIO_SESSION_DEVICE
                        || sessionId == AUDIO_SESSION_OUTPUT_MIX
                        || sessionId == AUDIO_SESSION_OUTPUT_STAGE)) {
            // haptic-generating effect is only valid when the session id is a general session id
            lStatus = INVALID_OPERATION;
            goto Exit;
        }

        // Only audio policy service can create a spatializer effect
        if ((memcmp(&descOut.type, FX_IID_SPATIALIZER, sizeof(effect_uuid_t)) == 0) &&
            (callingUid != AID_AUDIOSERVER || currentPid != getpid())) {
            ALOGW("%s: attempt to create a spatializer effect from uid/pid %d/%d",
                    __func__, callingUid, currentPid);
            lStatus = PERMISSION_DENIED;
            goto Exit;
        }

        if (io == AUDIO_IO_HANDLE_NONE && sessionId == AUDIO_SESSION_OUTPUT_MIX) {
            // if the output returned by getOutputForEffect() is removed before we lock the
            // mutex below, the call to checkPlaybackThread_l(io) below will detect it
            // and we will exit safely
            io = AudioSystem::getOutputForEffect(&descOut);
            ALOGV("createEffect got output %d", io);
        }

        Mutex::Autolock _l(mLock);

        if (sessionId == AUDIO_SESSION_DEVICE) {
            sp<Client> client = registerPid(currentPid);
            ALOGV("%s device type %#x address %s", __func__, device.mType, device.getAddress());
            handle = mDeviceEffectManager->createEffect_l(
                    &descOut, device, client, effectClient, mPatchPanel->patches_l(),
                    &enabledOut, &lStatus, probe, request.notifyFramesProcessed);
            if (lStatus != NO_ERROR && lStatus != ALREADY_EXISTS) {
                // remove local strong reference to Client with mClientLock held
                Mutex::Autolock _cl(mClientLock);
                client.clear();
            } else {
                // handle must be valid here, but check again to be safe.
                if (handle.get() != nullptr) idOut = handle->id();
            }
            goto Register;
        }

        // If output is not specified try to find a matching audio session ID in one of the
        // output threads.
        // If output is 0 here, sessionId is neither SESSION_OUTPUT_STAGE nor SESSION_OUTPUT_MIX
        // because of code checking output when entering the function.
        // Note: io is never AUDIO_IO_HANDLE_NONE when creating an effect on an input by APM.
        // An AudioEffect created from the Java API will have io as AUDIO_IO_HANDLE_NONE.
        if (io == AUDIO_IO_HANDLE_NONE) {
            // look for the thread where the specified audio session is present
            io = findIoHandleBySessionId_l(sessionId, mPlaybackThreads);
            if (io == AUDIO_IO_HANDLE_NONE) {
                io = findIoHandleBySessionId_l(sessionId, mRecordThreads);
            }
            if (io == AUDIO_IO_HANDLE_NONE) {
                io = findIoHandleBySessionId_l(sessionId, mMmapThreads);
            }

            // If you wish to create a Record preprocessing AudioEffect in Java,
            // you MUST create an AudioRecord first and keep it alive so it is picked up above.
            // Otherwise it will fail when created on a Playback thread by legacy
            // handling below.  Ditto with Mmap, the associated Mmap track must be created
            // before creating the AudioEffect or the io handle must be specified.
            //
            // Detect if the effect is created after an AudioRecord is destroyed.
            if (getOrphanEffectChain_l(sessionId).get() != nullptr) {
                ALOGE("%s: effect %s with no specified io handle is denied because the AudioRecord"
                      " for session %d no longer exists",
                      __func__, descOut.name, sessionId);
                lStatus = PERMISSION_DENIED;
                goto Exit;
            }

            // Legacy handling of creating an effect on an expired or made-up
            // session id.  We think that it is a Playback effect.
            //
            // If no output thread contains the requested session ID, default to
            // first output. The effect chain will be moved to the correct output
            // thread when a track with the same session ID is created
            if (io == AUDIO_IO_HANDLE_NONE && mPlaybackThreads.size() > 0) {
                io = mPlaybackThreads.keyAt(0);
            }
            ALOGV("createEffect() got io %d for effect %s", io, descOut.name);
        } else if (checkPlaybackThread_l(io) != nullptr
                        && sessionId != AUDIO_SESSION_OUTPUT_STAGE) {
            // allow only one effect chain per sessionId on mPlaybackThreads.
            for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
                const audio_io_handle_t checkIo = mPlaybackThreads.keyAt(i);
                if (io == checkIo) {
                    if (hapticPlaybackRequired
                            && mPlaybackThreads.valueAt(i)
                                    ->hapticChannelMask() == AUDIO_CHANNEL_NONE) {
                        ALOGE("%s: haptic playback thread is required while the required playback "
                              "thread(io=%d) doesn't support", __func__, (int)io);
                        lStatus = BAD_VALUE;
                        goto Exit;
                    }
                    continue;
                }
                const uint32_t sessionType =
                        mPlaybackThreads.valueAt(i)->hasAudioSession(sessionId);
                if ((sessionType & IAfThreadBase::EFFECT_SESSION) != 0) {
                    ALOGE("%s: effect %s io %d denied because session %d effect exists on io %d",
                          __func__, descOut.name, (int) io, (int) sessionId, (int) checkIo);
                    android_errorWriteLog(0x534e4554, "123237974");
                    lStatus = BAD_VALUE;
                    goto Exit;
                }
            }
        }
        IAfThreadBase* thread = checkRecordThread_l(io);
        if (thread == NULL) {
            thread = checkPlaybackThread_l(io);
            if (thread == NULL) {
                thread = checkMmapThread_l(io);
                if (thread == NULL) {
                    ALOGE("createEffect() unknown output thread");
                    lStatus = BAD_VALUE;
                    goto Exit;
                }
            }
        } else {
            // Check if one effect chain was awaiting for an effect to be created on this
            // session and used it instead of creating a new one.
            sp<IAfEffectChain> chain = getOrphanEffectChain_l(sessionId);
            if (chain != 0) {
                Mutex::Autolock _l2(thread->mutex());
                thread->addEffectChain_l(chain);
            }
        }

        sp<Client> client = registerPid(currentPid);

        // create effect on selected output thread
        bool pinned = !audio_is_global_session(sessionId) && isSessionAcquired_l(sessionId);
        IAfThreadBase* oriThread = nullptr;
        if (hapticPlaybackRequired && thread->hapticChannelMask() == AUDIO_CHANNEL_NONE) {
            IAfThreadBase* const hapticThread = hapticPlaybackThread_l();
            if (hapticThread == nullptr) {
                ALOGE("%s haptic thread not found while it is required", __func__);
                lStatus = INVALID_OPERATION;
                goto Exit;
            }
            if (hapticThread != thread) {
                // Force to use haptic thread for haptic-generating effect.
                oriThread = thread;
                thread = hapticThread;
            }
        }
        handle = thread->createEffect_l(client, effectClient, priority, sessionId,
                                        &descOut, &enabledOut, &lStatus, pinned, probe,
                                        request.notifyFramesProcessed);
        if (lStatus != NO_ERROR && lStatus != ALREADY_EXISTS) {
            // remove local strong reference to Client with mClientLock held
            Mutex::Autolock _cl(mClientLock);
            client.clear();
        } else {
            // handle must be valid here, but check again to be safe.
            if (handle.get() != nullptr) idOut = handle->id();
            // Invalidate audio session when haptic playback is created.
            if (hapticPlaybackRequired && oriThread != nullptr) {
                // invalidateTracksForAudioSession will trigger locking the thread.
                oriThread->invalidateTracksForAudioSession(sessionId);
            }
        }
    }

Register:
    if (!probe && (lStatus == NO_ERROR || lStatus == ALREADY_EXISTS)) {
        if (lStatus == ALREADY_EXISTS) {
            response->alreadyExists = true;
            lStatus = NO_ERROR;
        } else {
            response->alreadyExists = false;
        }
        // Check CPU and memory usage
        sp<IAfEffectBase> effect = handle->effect().promote();
        if (effect != nullptr) {
            status_t rStatus = effect->updatePolicyState();
            if (rStatus != NO_ERROR) {
                lStatus = rStatus;
            }
        }
    } else {
        handle.clear();
    }

    response->id = idOut;
    response->enabled = enabledOut != 0;
    response->effect = handle->asIEffect();
    response->desc = VALUE_OR_RETURN_STATUS(
            legacy2aidl_effect_descriptor_t_EffectDescriptor(descOut));

Exit:
    return lStatus;
}

status_t AudioFlinger::moveEffects(audio_session_t sessionId, audio_io_handle_t srcOutput,
        audio_io_handle_t dstOutput)
{
    ALOGV("%s() session %d, srcOutput %d, dstOutput %d",
            __func__, sessionId, srcOutput, dstOutput);
    Mutex::Autolock _l(mLock);
    if (srcOutput == dstOutput) {
        ALOGW("%s() same dst and src outputs %d", __func__, dstOutput);
        return NO_ERROR;
    }
    IAfPlaybackThread* const srcThread = checkPlaybackThread_l(srcOutput);
    if (srcThread == nullptr) {
        ALOGW("%s() bad srcOutput %d", __func__, srcOutput);
        return BAD_VALUE;
    }
    IAfPlaybackThread* const dstThread = checkPlaybackThread_l(dstOutput);
    if (dstThread == nullptr) {
        ALOGW("%s() bad dstOutput %d", __func__, dstOutput);
        return BAD_VALUE;
    }

    Mutex::Autolock _dl(dstThread->mutex());
    Mutex::Autolock _sl(srcThread->mutex());
    return moveEffectChain_l(sessionId, srcThread, dstThread);
}


void AudioFlinger::setEffectSuspended(int effectId,
                                audio_session_t sessionId,
                                bool suspended)
{
    Mutex::Autolock _l(mLock);

    sp<IAfThreadBase> thread = getEffectThread_l(sessionId, effectId);
    if (thread == nullptr) {
      return;
    }
    Mutex::Autolock _sl(thread->mutex());
    sp<IAfEffectModule> effect = thread->getEffect_l(sessionId, effectId);
    thread->setEffectSuspended_l(&effect->desc().type, suspended, sessionId);
}


// moveEffectChain_l must be called with both srcThread and dstThread mLocks held
status_t AudioFlinger::moveEffectChain_l(audio_session_t sessionId,
        IAfPlaybackThread* srcThread, IAfPlaybackThread* dstThread)
NO_THREAD_SAFETY_ANALYSIS // requires srcThread and dstThread locks
{
    ALOGV("moveEffectChain_l() session %d from thread %p to thread %p",
            sessionId, srcThread, dstThread);

    sp<IAfEffectChain> chain = srcThread->getEffectChain_l(sessionId);
    if (chain == 0) {
        ALOGW("moveEffectChain_l() effect chain for session %d not on source thread %p",
                sessionId, srcThread);
        return INVALID_OPERATION;
    }

    // Check whether the destination thread and all effects in the chain are compatible
    if (!chain->isCompatibleWithThread_l(dstThread)) {
        ALOGW("moveEffectChain_l() effect chain failed because"
                " destination thread %p is not compatible with effects in the chain",
                dstThread);
        return INVALID_OPERATION;
    }

    // remove chain first. This is useful only if reconfiguring effect chain on same output thread,
    // so that a new chain is created with correct parameters when first effect is added. This is
    // otherwise unnecessary as removeEffect_l() will remove the chain when last effect is
    // removed.
    // TODO(b/216875016): consider holding the effect chain locks for the duration of the move.
    srcThread->removeEffectChain_l(chain);

    // transfer all effects one by one so that new effect chain is created on new thread with
    // correct buffer sizes and audio parameters and effect engines reconfigured accordingly
    sp<IAfEffectChain> dstChain;
    Vector<sp<IAfEffectModule>> removed;
    status_t status = NO_ERROR;
    std::string errorString;
    // process effects one by one.
    for (sp<IAfEffectModule> effect = chain->getEffectFromId_l(0); effect != nullptr;
            effect = chain->getEffectFromId_l(0)) {
        srcThread->removeEffect_l(effect);
        removed.add(effect);
        status = dstThread->addEffect_l(effect);
        if (status != NO_ERROR) {
            errorString = StringPrintf(
                    "cannot add effect %p to destination thread", effect.get());
            break;
        }
        // if the move request is not received from audio policy manager, the effect must be
        // re-registered with the new strategy and output.

        // We obtain the dstChain once the effect is on the new thread.
        if (dstChain == nullptr) {
            dstChain = effect->getCallback()->chain().promote();
            if (dstChain == nullptr) {
                errorString = StringPrintf("cannot get chain from effect %p", effect.get());
                status = NO_INIT;
                break;
            }
        }
    }

    size_t restored = 0;
    if (status != NO_ERROR) {
        dstChain.clear(); // dstChain is now from the srcThread (could be recreated).
        for (const auto& effect : removed) {
            dstThread->removeEffect_l(effect); // Note: Depending on error location, the last
                                               // effect may not have been placed on dstThread.
            if (srcThread->addEffect_l(effect) == NO_ERROR) {
                ++restored;
                if (dstChain == nullptr) {
                    dstChain = effect->getCallback()->chain().promote();
                }
            }
        }
    }

    // After all the effects have been moved to new thread (or put back) we restart the effects
    // because removeEffect_l() has stopped the effect if it is currently active.
    size_t started = 0;
    if (dstChain != nullptr && !removed.empty()) {
        // If we do not take the dstChain lock, it is possible that processing is ongoing
        // while we are starting the effect.  This can cause glitches with volume,
        // see b/202360137.
        dstChain->lock();
        for (const auto& effect : removed) {
            if (effect->state() == IAfEffectModule::ACTIVE ||
                    effect->state() == IAfEffectModule::STOPPING) {
                ++started;
                effect->start();
            }
        }
        dstChain->unlock();
    }

    if (status != NO_ERROR) {
        if (errorString.empty()) {
            errorString = StringPrintf("%s: failed status %d", __func__, status);
        }
        ALOGW("%s: %s unsuccessful move of session %d from srcThread %p to dstThread %p "
                "(%zu effects removed from srcThread, %zu effects restored to srcThread, "
                "%zu effects started)",
                __func__, errorString.c_str(), sessionId, srcThread, dstThread,
                removed.size(), restored, started);
    } else {
        ALOGD("%s: successful move of session %d from srcThread %p to dstThread %p "
                "(%zu effects moved, %zu effects started)",
                __func__, sessionId, srcThread, dstThread, removed.size(), started);
    }
    return status;
}

status_t AudioFlinger::moveAuxEffectToIo(int EffectId,
        const sp<IAfPlaybackThread>& dstThread, sp<IAfPlaybackThread>* srcThread)
{
    status_t status = NO_ERROR;
    Mutex::Autolock _l(mLock);
    const sp<IAfThreadBase> threadBase = getEffectThread_l(AUDIO_SESSION_OUTPUT_MIX, EffectId);
    const sp<IAfPlaybackThread> thread = threadBase ? threadBase->asIAfPlaybackThread() : nullptr;

    if (EffectId != 0 && thread != 0 && dstThread != thread.get()) {
        Mutex::Autolock _dl(dstThread->mutex());
        Mutex::Autolock _sl(thread->mutex());
        sp<IAfEffectChain> srcChain = thread->getEffectChain_l(AUDIO_SESSION_OUTPUT_MIX);
        sp<IAfEffectChain> dstChain;
        if (srcChain == 0) {
            return INVALID_OPERATION;
        }

        sp<IAfEffectModule> effect = srcChain->getEffectFromId_l(EffectId);
        if (effect == 0) {
            return INVALID_OPERATION;
        }
        thread->removeEffect_l(effect);
        status = dstThread->addEffect_l(effect);
        if (status != NO_ERROR) {
            thread->addEffect_l(effect);
            status = INVALID_OPERATION;
            goto Exit;
        }

        dstChain = effect->getCallback()->chain().promote();
        if (dstChain == 0) {
            thread->addEffect_l(effect);
            status = INVALID_OPERATION;
        }

Exit:
        // removeEffect_l() has stopped the effect if it was active so it must be restarted
        if (effect->state() == IAfEffectModule::ACTIVE ||
            effect->state() == IAfEffectModule::STOPPING) {
            effect->start();
        }
    }

    if (status == NO_ERROR && srcThread != nullptr) {
        *srcThread = thread;
    }
    return status;
}

bool AudioFlinger::isNonOffloadableGlobalEffectEnabled_l() const
NO_THREAD_SAFETY_ANALYSIS  // thread lock for getEffectChain_l.
{
    if (mGlobalEffectEnableTime != 0 &&
            ((systemTime() - mGlobalEffectEnableTime) < kMinGlobalEffectEnabletimeNs)) {
        return true;
    }

    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        sp<IAfEffectChain> ec =
                mPlaybackThreads.valueAt(i)->getEffectChain_l(AUDIO_SESSION_OUTPUT_MIX);
        if (ec != 0 && ec->isNonOffloadableEnabled()) {
            return true;
        }
    }
    return false;
}

void AudioFlinger::onNonOffloadableGlobalEffectEnable()
{
    Mutex::Autolock _l(mLock);

    mGlobalEffectEnableTime = systemTime();

    for (size_t i = 0; i < mPlaybackThreads.size(); i++) {
        const sp<IAfPlaybackThread> t = mPlaybackThreads.valueAt(i);
        if (t->type() == IAfThreadBase::OFFLOAD) {
            t->invalidateTracks(AUDIO_STREAM_MUSIC);
        }
    }

}

status_t AudioFlinger::putOrphanEffectChain_l(const sp<IAfEffectChain>& chain)
{
    // clear possible suspended state before parking the chain so that it starts in default state
    // when attached to a new record thread
    chain->setEffectSuspended_l(FX_IID_AEC, false);
    chain->setEffectSuspended_l(FX_IID_NS, false);

    audio_session_t session = chain->sessionId();
    ssize_t index = mOrphanEffectChains.indexOfKey(session);
    ALOGV("putOrphanEffectChain_l session %d index %zd", session, index);
    if (index >= 0) {
        ALOGW("putOrphanEffectChain_l chain for session %d already present", session);
        return ALREADY_EXISTS;
    }
    mOrphanEffectChains.add(session, chain);
    return NO_ERROR;
}

sp<IAfEffectChain> AudioFlinger::getOrphanEffectChain_l(audio_session_t session)
{
    sp<IAfEffectChain> chain;
    ssize_t index = mOrphanEffectChains.indexOfKey(session);
    ALOGV("getOrphanEffectChain_l session %d index %zd", session, index);
    if (index >= 0) {
        chain = mOrphanEffectChains.valueAt(index);
        mOrphanEffectChains.removeItemsAt(index);
    }
    return chain;
}

bool AudioFlinger::updateOrphanEffectChains(const sp<IAfEffectModule>& effect)
{
    Mutex::Autolock _l(mLock);
    audio_session_t session = effect->sessionId();
    ssize_t index = mOrphanEffectChains.indexOfKey(session);
    ALOGV("updateOrphanEffectChains session %d index %zd", session, index);
    if (index >= 0) {
        sp<IAfEffectChain> chain = mOrphanEffectChains.valueAt(index);
        if (chain->removeEffect_l(effect, true) == 0) {
            ALOGV("updateOrphanEffectChains removing effect chain at index %zd", index);
            mOrphanEffectChains.removeItemsAt(index);
        }
        return true;
    }
    return false;
}

// ----------------------------------------------------------------------------
// from PatchPanel

/* List connected audio ports and their attributes */
status_t AudioFlinger::listAudioPorts(unsigned int* num_ports,
        struct audio_port* ports) const
{
    Mutex::Autolock _l(mLock);
    return mPatchPanel->listAudioPorts(num_ports, ports);
}

/* Get supported attributes for a given audio port */
status_t AudioFlinger::getAudioPort(struct audio_port_v7* port) const {
    const status_t status = AudioValidator::validateAudioPort(*port);
    if (status != NO_ERROR) {
        return status;
    }

    Mutex::Autolock _l(mLock);
    return mPatchPanel->getAudioPort(port);
}

/* Connect a patch between several source and sink ports */
status_t AudioFlinger::createAudioPatch(
        const struct audio_patch* patch, audio_patch_handle_t* handle)
{
    const status_t status = AudioValidator::validateAudioPatch(*patch);
    if (status != NO_ERROR) {
        return status;
    }

    Mutex::Autolock _l(mLock);
    return mPatchPanel->createAudioPatch(patch, handle);
}

/* Disconnect a patch */
status_t AudioFlinger::releaseAudioPatch(audio_patch_handle_t handle)
{
    Mutex::Autolock _l(mLock);
    return mPatchPanel->releaseAudioPatch(handle);
}

/* List connected audio ports and they attributes */
status_t AudioFlinger::listAudioPatches(
        unsigned int* num_patches, struct audio_patch* patches) const
{
    Mutex::Autolock _l(mLock);
    return mPatchPanel->listAudioPatches(num_patches, patches);
}

// ----------------------------------------------------------------------------

status_t AudioFlinger::onTransactWrapper(TransactionCode code,
                                         [[maybe_unused]] const Parcel& data,
                                         [[maybe_unused]] uint32_t flags,
                                         const std::function<status_t()>& delegate) {
    // make sure transactions reserved to AudioPolicyManager do not come from other processes
    switch (code) {
        case TransactionCode::SET_STREAM_VOLUME:
        case TransactionCode::SET_STREAM_MUTE:
        case TransactionCode::OPEN_OUTPUT:
        case TransactionCode::OPEN_DUPLICATE_OUTPUT:
        case TransactionCode::CLOSE_OUTPUT:
        case TransactionCode::SUSPEND_OUTPUT:
        case TransactionCode::RESTORE_OUTPUT:
        case TransactionCode::OPEN_INPUT:
        case TransactionCode::CLOSE_INPUT:
        case TransactionCode::SET_VOICE_VOLUME:
        case TransactionCode::MOVE_EFFECTS:
        case TransactionCode::SET_EFFECT_SUSPENDED:
        case TransactionCode::LOAD_HW_MODULE:
        case TransactionCode::GET_AUDIO_PORT:
        case TransactionCode::CREATE_AUDIO_PATCH:
        case TransactionCode::RELEASE_AUDIO_PATCH:
        case TransactionCode::LIST_AUDIO_PATCHES:
        case TransactionCode::SET_AUDIO_PORT_CONFIG:
        case TransactionCode::SET_RECORD_SILENCED:
        case TransactionCode::AUDIO_POLICY_READY:
        case TransactionCode::SET_DEVICE_CONNECTED_STATE:
        case TransactionCode::SET_REQUESTED_LATENCY_MODE:
        case TransactionCode::GET_SUPPORTED_LATENCY_MODES:
        case TransactionCode::INVALIDATE_TRACKS:
        case TransactionCode::GET_AUDIO_POLICY_CONFIG:
            ALOGW("%s: transaction %d received from PID %d",
                  __func__, code, IPCThreadState::self()->getCallingPid());
            // return status only for non void methods
            switch (code) {
                case TransactionCode::SET_RECORD_SILENCED:
                case TransactionCode::SET_EFFECT_SUSPENDED:
                    break;
                default:
                    return INVALID_OPERATION;
            }
            // Fail silently in these cases.
            return OK;
        default:
            break;
    }

    // make sure the following transactions come from system components
    switch (code) {
        case TransactionCode::SET_MASTER_VOLUME:
        case TransactionCode::SET_MASTER_MUTE:
        case TransactionCode::MASTER_MUTE:
        case TransactionCode::GET_SOUND_DOSE_INTERFACE:
        case TransactionCode::SET_MODE:
        case TransactionCode::SET_MIC_MUTE:
        case TransactionCode::SET_LOW_RAM_DEVICE:
        case TransactionCode::SYSTEM_READY:
        case TransactionCode::SET_AUDIO_HAL_PIDS:
        case TransactionCode::SET_VIBRATOR_INFOS:
        case TransactionCode::UPDATE_SECONDARY_OUTPUTS:
        case TransactionCode::SET_BLUETOOTH_VARIABLE_LATENCY_ENABLED:
        case TransactionCode::IS_BLUETOOTH_VARIABLE_LATENCY_ENABLED:
        case TransactionCode::SUPPORTS_BLUETOOTH_VARIABLE_LATENCY: {
            if (!isServiceUid(IPCThreadState::self()->getCallingUid())) {
                ALOGW("%s: transaction %d received from PID %d unauthorized UID %d",
                      __func__, code, IPCThreadState::self()->getCallingPid(),
                      IPCThreadState::self()->getCallingUid());
                // return status only for non-void methods
                switch (code) {
                    case TransactionCode::SYSTEM_READY:
                        break;
                    default:
                        return INVALID_OPERATION;
                }
                // Fail silently in these cases.
                return OK;
            }
        } break;
        default:
            break;
    }

    // List of relevant events that trigger log merging.
    // Log merging should activate during audio activity of any kind. This are considered the
    // most relevant events.
    // TODO should select more wisely the items from the list
    switch (code) {
        case TransactionCode::CREATE_TRACK:
        case TransactionCode::CREATE_RECORD:
        case TransactionCode::SET_MASTER_VOLUME:
        case TransactionCode::SET_MASTER_MUTE:
        case TransactionCode::SET_MIC_MUTE:
        case TransactionCode::SET_PARAMETERS:
        case TransactionCode::CREATE_EFFECT:
        case TransactionCode::SYSTEM_READY: {
            requestLogMerge();
            break;
        }
        default:
            break;
    }

    const std::string methodName = getIAudioFlingerStatistics().getMethodForCode(code);
    mediautils::TimeCheck check(
            std::string("IAudioFlinger::").append(methodName),
            [code, methodName](bool timeout, float elapsedMs) { // don't move methodName.
        if (timeout) {
            mediametrics::LogItem(mMetricsId)
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_TIMEOUT)
                .set(AMEDIAMETRICS_PROP_METHODCODE, int64_t(code))
                .set(AMEDIAMETRICS_PROP_METHODNAME, methodName.c_str())
                .record();
        } else {
            getIAudioFlingerStatistics().event(code, elapsedMs);
        }
    }, mediautils::TimeCheck::kDefaultTimeoutDuration,
    mediautils::TimeCheck::kDefaultSecondChanceDuration,
    true /* crashOnTimeout */);

    // Make sure we connect to Audio Policy Service before calling into AudioFlinger:
    //  - AudioFlinger can call into Audio Policy Service with its global mutex held
    //  - If this is the first time Audio Policy Service is queried from inside audioserver process
    //  this will trigger Audio Policy Manager initialization.
    //  - Audio Policy Manager initialization calls into AudioFlinger which will try to lock
    //  its global mutex and a deadlock will occur.
    if (IPCThreadState::self()->getCallingPid() != getpid()) {
        AudioSystem::get_audio_policy_service();
    }

    return delegate();
}

} // namespace android
