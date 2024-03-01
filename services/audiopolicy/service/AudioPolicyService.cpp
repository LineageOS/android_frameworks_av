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

#define LOG_TAG "AudioPolicyService"
//#define LOG_NDEBUG 0

#include "Configuration.h"
#undef __STRICT_ANSI__
#define __STDINT_LIMITS
#define __STDC_LIMIT_MACROS
#include <stdint.h>
#include <sys/time.h>
#include <dlfcn.h>

#include <audio_utils/clock.h>
#include <binder/IServiceManager.h>
#include <utils/Log.h>
#include <cutils/properties.h>
#include <binder/IPCThreadState.h>
#include <binder/PermissionController.h>
#include <binder/IResultReceiver.h>
#include <utils/String16.h>
#include <utils/threads.h>
#include "AudioRecordClient.h"
#include "AudioPolicyService.h"
#include <hardware_legacy/power.h>
#include <media/AidlConversion.h>
#include <media/AudioEffect.h>
#include <media/AudioParameter.h>
#include <mediautils/MethodStatistics.h>
#include <mediautils/ServiceUtilities.h>
#include <mediautils/TimeCheck.h>
#include <sensorprivacy/SensorPrivacyManager.h>

#include <system/audio.h>
#include <system/audio_policy.h>
#include <AudioPolicyConfig.h>
#include <AudioPolicyManager.h>

namespace android {
using binder::Status;
using media::audio::common::Spatialization;

static const char kDeadlockedString[] = "AudioPolicyService may be deadlocked\n";
static const char kCmdDeadlockedString[] = "AudioPolicyService command thread may be deadlocked\n";
static const char kAudioPolicyManagerCustomPath[] = "libaudiopolicymanagercustom.so";

static const int kDumpLockTimeoutNs = 1 * NANOS_PER_SECOND;

static const nsecs_t kAudioCommandTimeoutNs = seconds(3); // 3 seconds

static const String16 sManageAudioPolicyPermission("android.permission.MANAGE_AUDIO_POLICY");

// Creates an association between Binder code to name for IAudioPolicyService.
#define IAUDIOPOLICYSERVICE_BINDER_METHOD_MACRO_LIST \
BINDER_METHOD_ENTRY(onNewAudioModulesAvailable) \
BINDER_METHOD_ENTRY(setDeviceConnectionState) \
BINDER_METHOD_ENTRY(getDeviceConnectionState) \
BINDER_METHOD_ENTRY(handleDeviceConfigChange) \
BINDER_METHOD_ENTRY(setPhoneState) \
BINDER_METHOD_ENTRY(setForceUse) \
BINDER_METHOD_ENTRY(getForceUse) \
BINDER_METHOD_ENTRY(getOutput) \
BINDER_METHOD_ENTRY(getOutputForAttr) \
BINDER_METHOD_ENTRY(startOutput) \
BINDER_METHOD_ENTRY(stopOutput) \
BINDER_METHOD_ENTRY(releaseOutput) \
BINDER_METHOD_ENTRY(getInputForAttr) \
BINDER_METHOD_ENTRY(startInput) \
BINDER_METHOD_ENTRY(stopInput) \
BINDER_METHOD_ENTRY(releaseInput) \
BINDER_METHOD_ENTRY(initStreamVolume) \
BINDER_METHOD_ENTRY(setStreamVolumeIndex) \
BINDER_METHOD_ENTRY(getStreamVolumeIndex) \
BINDER_METHOD_ENTRY(setVolumeIndexForAttributes) \
BINDER_METHOD_ENTRY(getVolumeIndexForAttributes) \
BINDER_METHOD_ENTRY(getMaxVolumeIndexForAttributes) \
BINDER_METHOD_ENTRY(getMinVolumeIndexForAttributes) \
BINDER_METHOD_ENTRY(getStrategyForStream) \
BINDER_METHOD_ENTRY(getDevicesForAttributes) \
BINDER_METHOD_ENTRY(getOutputForEffect) \
BINDER_METHOD_ENTRY(registerEffect) \
BINDER_METHOD_ENTRY(unregisterEffect) \
BINDER_METHOD_ENTRY(setEffectEnabled) \
BINDER_METHOD_ENTRY(moveEffectsToIo) \
BINDER_METHOD_ENTRY(isStreamActive) \
BINDER_METHOD_ENTRY(isStreamActiveRemotely) \
BINDER_METHOD_ENTRY(isSourceActive) \
BINDER_METHOD_ENTRY(queryDefaultPreProcessing) \
BINDER_METHOD_ENTRY(addSourceDefaultEffect) \
BINDER_METHOD_ENTRY(addStreamDefaultEffect) \
BINDER_METHOD_ENTRY(removeSourceDefaultEffect) \
BINDER_METHOD_ENTRY(removeStreamDefaultEffect) \
BINDER_METHOD_ENTRY(setSupportedSystemUsages) \
BINDER_METHOD_ENTRY(setAllowedCapturePolicy) \
BINDER_METHOD_ENTRY(getOffloadSupport) \
BINDER_METHOD_ENTRY(isDirectOutputSupported) \
BINDER_METHOD_ENTRY(listAudioPorts) \
BINDER_METHOD_ENTRY(getAudioPort) \
BINDER_METHOD_ENTRY(createAudioPatch) \
BINDER_METHOD_ENTRY(releaseAudioPatch) \
BINDER_METHOD_ENTRY(listAudioPatches) \
BINDER_METHOD_ENTRY(setAudioPortConfig) \
BINDER_METHOD_ENTRY(registerClient) \
BINDER_METHOD_ENTRY(setAudioPortCallbacksEnabled) \
BINDER_METHOD_ENTRY(setAudioVolumeGroupCallbacksEnabled) \
BINDER_METHOD_ENTRY(acquireSoundTriggerSession) \
BINDER_METHOD_ENTRY(releaseSoundTriggerSession) \
BINDER_METHOD_ENTRY(getPhoneState) \
BINDER_METHOD_ENTRY(registerPolicyMixes) \
BINDER_METHOD_ENTRY(updatePolicyMixes) \
BINDER_METHOD_ENTRY(setUidDeviceAffinities) \
BINDER_METHOD_ENTRY(removeUidDeviceAffinities) \
BINDER_METHOD_ENTRY(setUserIdDeviceAffinities) \
BINDER_METHOD_ENTRY(removeUserIdDeviceAffinities) \
BINDER_METHOD_ENTRY(startAudioSource) \
BINDER_METHOD_ENTRY(stopAudioSource) \
BINDER_METHOD_ENTRY(setMasterMono) \
BINDER_METHOD_ENTRY(getMasterMono) \
BINDER_METHOD_ENTRY(getStreamVolumeDB) \
BINDER_METHOD_ENTRY(getSurroundFormats) \
BINDER_METHOD_ENTRY(getReportedSurroundFormats) \
BINDER_METHOD_ENTRY(getHwOffloadFormatsSupportedForBluetoothMedia) \
BINDER_METHOD_ENTRY(setSurroundFormatEnabled) \
BINDER_METHOD_ENTRY(setAssistantServicesUids) \
BINDER_METHOD_ENTRY(setActiveAssistantServicesUids) \
BINDER_METHOD_ENTRY(setA11yServicesUids) \
BINDER_METHOD_ENTRY(setCurrentImeUid) \
BINDER_METHOD_ENTRY(isHapticPlaybackSupported) \
BINDER_METHOD_ENTRY(isUltrasoundSupported) \
BINDER_METHOD_ENTRY(isHotwordStreamSupported) \
BINDER_METHOD_ENTRY(listAudioProductStrategies) \
BINDER_METHOD_ENTRY(getProductStrategyFromAudioAttributes) \
BINDER_METHOD_ENTRY(listAudioVolumeGroups) \
BINDER_METHOD_ENTRY(getVolumeGroupFromAudioAttributes) \
BINDER_METHOD_ENTRY(setRttEnabled) \
BINDER_METHOD_ENTRY(isCallScreenModeSupported) \
BINDER_METHOD_ENTRY(setDevicesRoleForStrategy) \
BINDER_METHOD_ENTRY(removeDevicesRoleForStrategy) \
BINDER_METHOD_ENTRY(clearDevicesRoleForStrategy) \
BINDER_METHOD_ENTRY(getDevicesForRoleAndStrategy) \
BINDER_METHOD_ENTRY(setDevicesRoleForCapturePreset) \
BINDER_METHOD_ENTRY(addDevicesRoleForCapturePreset) \
BINDER_METHOD_ENTRY(removeDevicesRoleForCapturePreset) \
BINDER_METHOD_ENTRY(clearDevicesRoleForCapturePreset) \
BINDER_METHOD_ENTRY(getDevicesForRoleAndCapturePreset) \
BINDER_METHOD_ENTRY(registerSoundTriggerCaptureStateListener) \
BINDER_METHOD_ENTRY(getSpatializer) \
BINDER_METHOD_ENTRY(canBeSpatialized) \
BINDER_METHOD_ENTRY(getDirectPlaybackSupport) \
BINDER_METHOD_ENTRY(getDirectProfilesForAttributes)  \
BINDER_METHOD_ENTRY(getSupportedMixerAttributes) \
BINDER_METHOD_ENTRY(setPreferredMixerAttributes) \
BINDER_METHOD_ENTRY(getPreferredMixerAttributes) \
BINDER_METHOD_ENTRY(clearPreferredMixerAttributes) \
BINDER_METHOD_ENTRY(getRegisteredPolicyMixes) \
                                                     \
// singleton for Binder Method Statistics for IAudioPolicyService
static auto& getIAudioPolicyServiceStatistics() {
    using Code = int;

#pragma push_macro("BINDER_METHOD_ENTRY")
#undef BINDER_METHOD_ENTRY
#define BINDER_METHOD_ENTRY(ENTRY) \
        {(Code)media::BnAudioPolicyService::TRANSACTION_##ENTRY, #ENTRY},

    static mediautils::MethodStatistics<Code> methodStatistics{
        IAUDIOPOLICYSERVICE_BINDER_METHOD_MACRO_LIST
        METHOD_STATISTICS_BINDER_CODE_NAMES(Code)
    };
#pragma pop_macro("BINDER_METHOD_ENTRY")

    return methodStatistics;
}

// ----------------------------------------------------------------------------

static AudioPolicyInterface* createAudioPolicyManager(AudioPolicyClientInterface *clientInterface)
{
    AudioPolicyManager *apm = nullptr;
    media::AudioPolicyConfig apmConfig;
    if (status_t status = clientInterface->getAudioPolicyConfig(&apmConfig); status == OK) {
        auto config = AudioPolicyConfig::loadFromApmAidlConfigWithFallback(apmConfig);
        LOG_ALWAYS_FATAL_IF(config->getEngineLibraryNameSuffix() !=
                AudioPolicyConfig::kDefaultEngineLibraryNameSuffix,
                "Only default engine is currently supported with the AIDL HAL");
        apm = new AudioPolicyManager(config,
                loadApmEngineLibraryAndCreateEngine(
                        config->getEngineLibraryNameSuffix(), apmConfig.engineConfig),
                clientInterface);
    } else {
        auto config = AudioPolicyConfig::loadFromApmXmlConfigWithFallback();  // This can't fail.
        apm = new AudioPolicyManager(config,
                loadApmEngineLibraryAndCreateEngine(config->getEngineLibraryNameSuffix()),
                clientInterface);
    }
    status_t status = apm->initialize();
    if (status != NO_ERROR) {
        delete apm;
        apm = nullptr;
    }
    return apm;
}

static void destroyAudioPolicyManager(AudioPolicyInterface *interface)
{
    delete interface;
}
// ----------------------------------------------------------------------------

AudioPolicyService::AudioPolicyService()
    : BnAudioPolicyService(),
      mAudioPolicyManager(NULL),
      mAudioPolicyClient(NULL),
      mPhoneState(AUDIO_MODE_INVALID),
      mCaptureStateNotifier(false),
      mCreateAudioPolicyManager(createAudioPolicyManager),
      mDestroyAudioPolicyManager(destroyAudioPolicyManager),
      mUsecaseValidator(media::createUsecaseValidator()) {
      setMinSchedulerPolicy(SCHED_NORMAL, ANDROID_PRIORITY_AUDIO);
}

void AudioPolicyService::loadAudioPolicyManager()
{
    mLibraryHandle = dlopen(kAudioPolicyManagerCustomPath, RTLD_NOW);
    if (mLibraryHandle != nullptr) {
        ALOGI("%s loading %s", __func__, kAudioPolicyManagerCustomPath);
        mCreateAudioPolicyManager = reinterpret_cast<CreateAudioPolicyManagerInstance>
                                            (dlsym(mLibraryHandle, "createAudioPolicyManager"));
        const char *lastError = dlerror();
        ALOGW_IF(mCreateAudioPolicyManager == nullptr, "%s createAudioPolicyManager is null %s",
                    __func__, lastError != nullptr ? lastError : "no error");

        mDestroyAudioPolicyManager = reinterpret_cast<DestroyAudioPolicyManagerInstance>(
                                        dlsym(mLibraryHandle, "destroyAudioPolicyManager"));
        lastError = dlerror();
        ALOGW_IF(mDestroyAudioPolicyManager == nullptr, "%s destroyAudioPolicyManager is null %s",
                    __func__, lastError != nullptr ? lastError : "no error");
        if (mCreateAudioPolicyManager == nullptr || mDestroyAudioPolicyManager == nullptr){
            unloadAudioPolicyManager();
            LOG_ALWAYS_FATAL("could not find audiopolicymanager interface methods");
        }
    }
}

void AudioPolicyService::onFirstRef()
{
    // Log an AudioPolicy "constructor" mediametrics event on first ref.
    // This records the time it takes to load the audio modules and devices.
    mediametrics::Defer defer([beginNs = systemTime()] {
        mediametrics::LogItem(AMEDIAMETRICS_KEY_AUDIO_POLICY)
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_CTOR)
            .set(AMEDIAMETRICS_PROP_EXECUTIONTIMENS, (int64_t)(systemTime() - beginNs))
            .record(); });
    {
        audio_utils::lock_guard _l(mMutex);

        // start audio commands thread
        mAudioCommandThread = new AudioCommandThread(String8("ApmAudio"), this);
        // start output activity command thread
        mOutputCommandThread = new AudioCommandThread(String8("ApmOutput"), this);

        mAudioPolicyClient = new AudioPolicyClient(this);

        loadAudioPolicyManager();
        mAudioPolicyManager = mCreateAudioPolicyManager(mAudioPolicyClient);
    }

    // load audio processing modules
    const sp<EffectsFactoryHalInterface> effectsFactoryHal = EffectsFactoryHalInterface::create();
    auto audioPolicyEffects = sp<AudioPolicyEffects>::make(effectsFactoryHal);
    auto uidPolicy = sp<UidPolicy>::make(this);
    auto sensorPrivacyPolicy = sp<SensorPrivacyPolicy>::make(this);
    {
        audio_utils::lock_guard _l(mMutex);
        mAudioPolicyEffects = audioPolicyEffects;
        mUidPolicy = uidPolicy;
        mSensorPrivacyPolicy = sensorPrivacyPolicy;
    }
    uidPolicy->registerSelf();
    sensorPrivacyPolicy->registerSelf();

    // Create spatializer if supported
    if (mAudioPolicyManager != nullptr) {
        audio_utils::lock_guard _l(mMutex);
        const audio_attributes_t attr = attributes_initializer(AUDIO_USAGE_MEDIA);
        AudioDeviceTypeAddrVector devices;
        bool hasSpatializer = mAudioPolicyManager->canBeSpatialized(&attr, nullptr, devices);
        if (hasSpatializer) {
            // Unlock as Spatializer::create() will use the callback and acquire the
            // AudioPolicyService_Mutex.
            mMutex.unlock();
            mSpatializer = Spatializer::create(this, effectsFactoryHal);
            mMutex.lock();
        }
        if (mSpatializer == nullptr) {
            // No spatializer created, signal the reason: NO_INIT a failure, OK means intended.
            const status_t createStatus = hasSpatializer ? NO_INIT : OK;
            Spatializer::sendEmptyCreateSpatializerMetricWithStatus(createStatus);
        }
    }
    AudioSystem::audioPolicyReady();
}

void AudioPolicyService::onAudioSystemReady() {
    sp<AudioPolicyEffects> audioPolicyEffects;
    {
        audio_utils::lock_guard _l(mMutex);

        audioPolicyEffects = mAudioPolicyEffects;
    }
    audioPolicyEffects->initDefaultDeviceEffects();
}

void AudioPolicyService::unloadAudioPolicyManager()
{
    ALOGV("%s ", __func__);
    if (mLibraryHandle != nullptr) {
        dlclose(mLibraryHandle);
    }
    mLibraryHandle = nullptr;
    mCreateAudioPolicyManager = nullptr;
    mDestroyAudioPolicyManager = nullptr;
}

AudioPolicyService::~AudioPolicyService()
{
    mAudioCommandThread->exit();
    mOutputCommandThread->exit();

    mDestroyAudioPolicyManager(mAudioPolicyManager);
    unloadAudioPolicyManager();

    delete mAudioPolicyClient;

    mNotificationClients.clear();
    mAudioPolicyEffects.clear();

    mUidPolicy->unregisterSelf();
    mSensorPrivacyPolicy->unregisterSelf();

    mUidPolicy.clear();
    mSensorPrivacyPolicy.clear();
}

// A notification client is always registered by AudioSystem when the client process
// connects to AudioPolicyService.
Status AudioPolicyService::registerClient(const sp<media::IAudioPolicyServiceClient>& client)
{
    if (client == 0) {
        ALOGW("%s got NULL client", __FUNCTION__);
        return Status::ok();
    }
    audio_utils::lock_guard _l(mNotificationClientsMutex);

    uid_t uid = IPCThreadState::self()->getCallingUid();
    pid_t pid = IPCThreadState::self()->getCallingPid();
    int64_t token = ((int64_t)uid<<32) | pid;

    if (mNotificationClients.indexOfKey(token) < 0) {
        sp<NotificationClient> notificationClient = new NotificationClient(this,
                                                                           client,
                                                                           uid,
                                                                           pid);
        ALOGV("registerClient() client %p, uid %d pid %d", client.get(), uid, pid);

        mNotificationClients.add(token, notificationClient);

        sp<IBinder> binder = IInterface::asBinder(client);
        binder->linkToDeath(notificationClient);
    }
        return Status::ok();
}

Status AudioPolicyService::setAudioPortCallbacksEnabled(bool enabled)
{
    audio_utils::lock_guard _l(mNotificationClientsMutex);

    uid_t uid = IPCThreadState::self()->getCallingUid();
    pid_t pid = IPCThreadState::self()->getCallingPid();
    int64_t token = ((int64_t)uid<<32) | pid;

    if (mNotificationClients.indexOfKey(token) < 0) {
        return Status::ok();
    }
    mNotificationClients.valueFor(token)->setAudioPortCallbacksEnabled(enabled);
    return Status::ok();
}

Status AudioPolicyService::setAudioVolumeGroupCallbacksEnabled(bool enabled)
{
    audio_utils::lock_guard _l(mNotificationClientsMutex);

    uid_t uid = IPCThreadState::self()->getCallingUid();
    pid_t pid = IPCThreadState::self()->getCallingPid();
    int64_t token = ((int64_t)uid<<32) | pid;

    if (mNotificationClients.indexOfKey(token) < 0) {
        return Status::ok();
    }
    mNotificationClients.valueFor(token)->setAudioVolumeGroupCallbacksEnabled(enabled);
    return Status::ok();
}

// removeNotificationClient() is called when the client process dies.
void AudioPolicyService::removeNotificationClient(uid_t uid, pid_t pid)
{
    bool hasSameUid = false;
    {
        audio_utils::lock_guard _l(mNotificationClientsMutex);
        int64_t token = ((int64_t)uid<<32) | pid;
        mNotificationClients.removeItem(token);
        for (size_t i = 0; i < mNotificationClients.size(); i++) {
            if (mNotificationClients.valueAt(i)->uid() == uid) {
                hasSameUid = true;
                break;
            }
        }
    }
    {
        audio_utils::lock_guard _l(mMutex);
        if (mAudioPolicyManager && !hasSameUid) {
            // called from binder death notification: no need to clear caller identity
            mAudioPolicyManager->releaseResourcesForUid(uid);
        }
    }
}

void AudioPolicyService::onAudioPortListUpdate()
{
    mOutputCommandThread->updateAudioPortListCommand();
}

void AudioPolicyService::doOnAudioPortListUpdate()
{
    audio_utils::lock_guard _l(mNotificationClientsMutex);
    for (size_t i = 0; i < mNotificationClients.size(); i++) {
        mNotificationClients.valueAt(i)->onAudioPortListUpdate();
    }
}

void AudioPolicyService::onAudioPatchListUpdate()
{
    mOutputCommandThread->updateAudioPatchListCommand();
}

void AudioPolicyService::doOnAudioPatchListUpdate()
{
    audio_utils::lock_guard _l(mNotificationClientsMutex);
    for (size_t i = 0; i < mNotificationClients.size(); i++) {
        mNotificationClients.valueAt(i)->onAudioPatchListUpdate();
    }
}

void AudioPolicyService::onAudioVolumeGroupChanged(volume_group_t group, int flags)
{
    mOutputCommandThread->changeAudioVolumeGroupCommand(group, flags);
}

void AudioPolicyService::doOnAudioVolumeGroupChanged(volume_group_t group, int flags)
{
    audio_utils::lock_guard _l(mNotificationClientsMutex);
    for (size_t i = 0; i < mNotificationClients.size(); i++) {
        mNotificationClients.valueAt(i)->onAudioVolumeGroupChanged(group, flags);
    }
}

void AudioPolicyService::onDynamicPolicyMixStateUpdate(const String8& regId, int32_t state)
{
    ALOGV("AudioPolicyService::onDynamicPolicyMixStateUpdate(%s, %d)",
            regId.c_str(), state);
    mOutputCommandThread->dynamicPolicyMixStateUpdateCommand(regId, state);
}

void AudioPolicyService::doOnDynamicPolicyMixStateUpdate(const String8& regId, int32_t state)
{
    audio_utils::lock_guard _l(mNotificationClientsMutex);
    for (size_t i = 0; i < mNotificationClients.size(); i++) {
        mNotificationClients.valueAt(i)->onDynamicPolicyMixStateUpdate(regId, state);
    }
}

void AudioPolicyService::onRecordingConfigurationUpdate(
                                                    int event,
                                                    const record_client_info_t *clientInfo,
                                                    const audio_config_base_t *clientConfig,
                                                    std::vector<effect_descriptor_t> clientEffects,
                                                    const audio_config_base_t *deviceConfig,
                                                    std::vector<effect_descriptor_t> effects,
                                                    audio_patch_handle_t patchHandle,
                                                    audio_source_t source)
{
    mOutputCommandThread->recordingConfigurationUpdateCommand(event, clientInfo,
            clientConfig, clientEffects, deviceConfig, effects, patchHandle, source);
}

void AudioPolicyService::doOnRecordingConfigurationUpdate(
                                                  int event,
                                                  const record_client_info_t *clientInfo,
                                                  const audio_config_base_t *clientConfig,
                                                  std::vector<effect_descriptor_t> clientEffects,
                                                  const audio_config_base_t *deviceConfig,
                                                  std::vector<effect_descriptor_t> effects,
                                                  audio_patch_handle_t patchHandle,
                                                  audio_source_t source)
{
    audio_utils::lock_guard _l(mNotificationClientsMutex);
    for (size_t i = 0; i < mNotificationClients.size(); i++) {
        mNotificationClients.valueAt(i)->onRecordingConfigurationUpdate(event, clientInfo,
                clientConfig, clientEffects, deviceConfig, effects, patchHandle, source);
    }
}

void AudioPolicyService::onRoutingUpdated()
{
    mOutputCommandThread->routingChangedCommand();
}

void AudioPolicyService::doOnRoutingUpdated()
{
  audio_utils::lock_guard _l(mNotificationClientsMutex);
    for (size_t i = 0; i < mNotificationClients.size(); i++) {
        mNotificationClients.valueAt(i)->onRoutingUpdated();
    }
}

void AudioPolicyService::onVolumeRangeInitRequest()
{
    mOutputCommandThread->volRangeInitReqCommand();
}

void AudioPolicyService::doOnVolumeRangeInitRequest()
{
    audio_utils::lock_guard _l(mNotificationClientsMutex);
    for (size_t i = 0; i < mNotificationClients.size(); i++) {
        mNotificationClients.valueAt(i)->onVolumeRangeInitRequest();
    }
}

void AudioPolicyService::onCheckSpatializer()
{
    audio_utils::lock_guard _l(mMutex);
    onCheckSpatializer_l();
}

void AudioPolicyService::onCheckSpatializer_l()
{
    if (mSpatializer != nullptr) {
        mOutputCommandThread->checkSpatializerCommand();
    }
}

void AudioPolicyService::doOnCheckSpatializer()
{
    ALOGV("%s mSpatializer %p level %d",
        __func__, mSpatializer.get(), (int)mSpatializer->getLevel());

    if (mSpatializer != nullptr) {
        // Note: mSpatializer != nullptr =>  mAudioPolicyManager != nullptr
        if (mSpatializer->getLevel() != Spatialization::Level::NONE) {
            audio_io_handle_t currentOutput = mSpatializer->getOutput();
            audio_io_handle_t newOutput;
            const audio_attributes_t attr = attributes_initializer(AUDIO_USAGE_MEDIA);
            audio_config_base_t config = mSpatializer->getAudioInConfig();

            audio_utils::lock_guard _l(mMutex);
            status_t status =
                    mAudioPolicyManager->getSpatializerOutput(&config, &attr, &newOutput);
            ALOGV("%s currentOutput %d newOutput %d channel_mask %#x",
                    __func__, currentOutput, newOutput, config.channel_mask);
            if (status == NO_ERROR && currentOutput == newOutput) {
                return;
            }
            size_t numActiveTracks = countActiveClientsOnOutput_l(newOutput);
            mMutex.unlock();
            // It is OK to call detachOutput() is none is already attached.
            mSpatializer->detachOutput();
            if (status == NO_ERROR && newOutput != AUDIO_IO_HANDLE_NONE) {
                status = mSpatializer->attachOutput(newOutput, numActiveTracks);
            }
            mMutex.lock();
            if (status != NO_ERROR) {
                mAudioPolicyManager->releaseSpatializerOutput(newOutput);
            }
        } else if (mSpatializer->getLevel() == Spatialization::Level::NONE &&
                   mSpatializer->getOutput() != AUDIO_IO_HANDLE_NONE) {
            audio_io_handle_t output = mSpatializer->detachOutput();

            if (output != AUDIO_IO_HANDLE_NONE) {
                audio_utils::lock_guard _l(mMutex);
                mAudioPolicyManager->releaseSpatializerOutput(output);
            }
        }
    }
}

size_t AudioPolicyService::countActiveClientsOnOutput_l(
        audio_io_handle_t output, bool spatializedOnly) {
    size_t count = 0;
    for (size_t i = 0; i < mAudioPlaybackClients.size(); i++) {
        auto client = mAudioPlaybackClients.valueAt(i);
        if (client->io == output && client->active
                && (!spatializedOnly || client->isSpatialized)) {
            count++;
        }
    }
    return count;
}

void AudioPolicyService::onUpdateActiveSpatializerTracks_l() {
    if (mSpatializer == nullptr) {
        return;
    }
    mOutputCommandThread->updateActiveSpatializerTracksCommand();
}

void AudioPolicyService::doOnUpdateActiveSpatializerTracks()
{
    if (mSpatializer == nullptr) {
        return;
    }
    audio_io_handle_t output = mSpatializer->getOutput();
    size_t activeClients;
    {
        audio_utils::lock_guard _l(mMutex);
        activeClients = countActiveClientsOnOutput_l(output);
    }
    mSpatializer->updateActiveTracks(activeClients);
}

status_t AudioPolicyService::clientCreateAudioPatch(const struct audio_patch *patch,
                                                audio_patch_handle_t *handle,
                                                int delayMs)
{
    return mAudioCommandThread->createAudioPatchCommand(patch, handle, delayMs);
}

status_t AudioPolicyService::clientReleaseAudioPatch(audio_patch_handle_t handle,
                                                 int delayMs)
{
    return mAudioCommandThread->releaseAudioPatchCommand(handle, delayMs);
}

status_t AudioPolicyService::clientSetAudioPortConfig(const struct audio_port_config *config,
                                                      int delayMs)
{
    return mAudioCommandThread->setAudioPortConfigCommand(config, delayMs);
}

AudioPolicyService::NotificationClient::NotificationClient(
        const sp<AudioPolicyService>& service,
        const sp<media::IAudioPolicyServiceClient>& client,
        uid_t uid,
        pid_t pid)
    : mService(service), mUid(uid), mPid(pid), mAudioPolicyServiceClient(client),
      mAudioPortCallbacksEnabled(false), mAudioVolumeGroupCallbacksEnabled(false)
{
}

AudioPolicyService::NotificationClient::~NotificationClient()
{
}

void AudioPolicyService::NotificationClient::binderDied(const wp<IBinder>& who __unused)
{
    sp<NotificationClient> keep(this);
    sp<AudioPolicyService> service = mService.promote();
    if (service != 0) {
        service->removeNotificationClient(mUid, mPid);
    }
}

void AudioPolicyService::NotificationClient::onAudioPortListUpdate()
{
    if (mAudioPolicyServiceClient != 0 && mAudioPortCallbacksEnabled) {
        mAudioPolicyServiceClient->onAudioPortListUpdate();
    }
}

void AudioPolicyService::NotificationClient::onAudioPatchListUpdate()
{
    if (mAudioPolicyServiceClient != 0 && mAudioPortCallbacksEnabled) {
        mAudioPolicyServiceClient->onAudioPatchListUpdate();
    }
}

void AudioPolicyService::NotificationClient::onAudioVolumeGroupChanged(volume_group_t group,
                                                                      int flags)
{
    if (mAudioPolicyServiceClient != 0 && mAudioVolumeGroupCallbacksEnabled) {
        mAudioPolicyServiceClient->onAudioVolumeGroupChanged(group, flags);
    }
}


void AudioPolicyService::NotificationClient::onDynamicPolicyMixStateUpdate(
        const String8& regId, int32_t state)
{
    if (mAudioPolicyServiceClient != 0 && isServiceUid(mUid)) {
        mAudioPolicyServiceClient->onDynamicPolicyMixStateUpdate(
                legacy2aidl_String8_string(regId).value(), state);
    }
}

void AudioPolicyService::NotificationClient::onRecordingConfigurationUpdate(
                                            int event,
                                            const record_client_info_t *clientInfo,
                                            const audio_config_base_t *clientConfig,
                                            std::vector<effect_descriptor_t> clientEffects,
                                            const audio_config_base_t *deviceConfig,
                                            std::vector<effect_descriptor_t> effects,
                                            audio_patch_handle_t patchHandle,
                                            audio_source_t source)
{
    if (mAudioPolicyServiceClient != 0 && isServiceUid(mUid)) {
        status_t status = [&]() -> status_t {
            int32_t eventAidl = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(event));
            media::RecordClientInfo clientInfoAidl = VALUE_OR_RETURN_STATUS(
                    legacy2aidl_record_client_info_t_RecordClientInfo(*clientInfo));
            AudioConfigBase clientConfigAidl = VALUE_OR_RETURN_STATUS(
                    legacy2aidl_audio_config_base_t_AudioConfigBase(
                            *clientConfig, true /*isInput*/));
            std::vector<media::EffectDescriptor> clientEffectsAidl = VALUE_OR_RETURN_STATUS(
                    convertContainer<std::vector<media::EffectDescriptor>>(
                            clientEffects,
                            legacy2aidl_effect_descriptor_t_EffectDescriptor));
            AudioConfigBase deviceConfigAidl = VALUE_OR_RETURN_STATUS(
                    legacy2aidl_audio_config_base_t_AudioConfigBase(
                            *deviceConfig, true /*isInput*/));
            std::vector<media::EffectDescriptor> effectsAidl = VALUE_OR_RETURN_STATUS(
                    convertContainer<std::vector<media::EffectDescriptor>>(
                            effects,
                            legacy2aidl_effect_descriptor_t_EffectDescriptor));
            int32_t patchHandleAidl = VALUE_OR_RETURN_STATUS(
                    legacy2aidl_audio_patch_handle_t_int32_t(patchHandle));
            media::audio::common::AudioSource sourceAidl = VALUE_OR_RETURN_STATUS(
                    legacy2aidl_audio_source_t_AudioSource(source));
            return aidl_utils::statusTFromBinderStatus(
                    mAudioPolicyServiceClient->onRecordingConfigurationUpdate(eventAidl,
                                                                              clientInfoAidl,
                                                                              clientConfigAidl,
                                                                              clientEffectsAidl,
                                                                              deviceConfigAidl,
                                                                              effectsAidl,
                                                                              patchHandleAidl,
                                                                              sourceAidl));
        }();
        ALOGW_IF(status != OK, "onRecordingConfigurationUpdate() failed: %d", status);
    }
}

void AudioPolicyService::NotificationClient::setAudioPortCallbacksEnabled(bool enabled)
{
    mAudioPortCallbacksEnabled = enabled;
}

void AudioPolicyService::NotificationClient::setAudioVolumeGroupCallbacksEnabled(bool enabled)
{
    mAudioVolumeGroupCallbacksEnabled = enabled;
}

void AudioPolicyService::NotificationClient::onRoutingUpdated()
{
    if (mAudioPolicyServiceClient != 0 && isServiceUid(mUid)) {
        mAudioPolicyServiceClient->onRoutingUpdated();
    }
}

void AudioPolicyService::NotificationClient::onVolumeRangeInitRequest()
{
    if (mAudioPolicyServiceClient != 0 && isServiceUid(mUid)) {
        mAudioPolicyServiceClient->onVolumeRangeInitRequest();
    }
}

void AudioPolicyService::binderDied(const wp<IBinder>& who) {
    ALOGW("binderDied() %p, calling pid %d", who.unsafe_get(),
            IPCThreadState::self()->getCallingPid());
}

static void dumpReleaseLock(audio_utils::mutex& mutex, bool locked)
        RELEASE(mutex) NO_THREAD_SAFETY_ANALYSIS
{
    if (locked) mutex.unlock();
}

status_t AudioPolicyService::dumpInternals(int fd)
{
    const size_t SIZE = 256;
    char buffer[SIZE];
    String8 result;

    snprintf(buffer, SIZE, "Supported System Usages:\n  ");
    result.append(buffer);
    std::stringstream msg;
    size_t i = 0;
    for (auto usage : mSupportedSystemUsages) {
        if (i++ != 0) msg << ", ";
        if (const char* strUsage = audio_usage_to_string(usage); strUsage) {
            msg << strUsage;
        } else {
            msg << usage << " (unknown)";
        }
    }
    if (i == 0) {
        msg << "None";
    }
    msg << std::endl;
    result.append(msg.str().c_str());

    write(fd, result.c_str(), result.size());

    mUidPolicy->dumpInternals(fd);
    return NO_ERROR;
}

void AudioPolicyService::updateUidStates()
{
    audio_utils::lock_guard _l(mMutex);
    updateUidStates_l();
}

void AudioPolicyService::updateUidStates_l()
{
//    Go over all active clients and allow capture (does not force silence) in the
//    following cases:
//    The client is in the active assistant list
//         AND is TOP
//               AND an accessibility service is TOP
//                  AND source is either VOICE_RECOGNITION OR HOTWORD
//               OR there is no active privacy sensitive capture or call
//                          OR client has CAPTURE_AUDIO_OUTPUT privileged permission
//                  AND source is VOICE_RECOGNITION OR HOTWORD
//    The client is an assistant AND active assistant is not being used
//        AND an accessibility service is on TOP or a RTT call is active
//                AND the source is VOICE_RECOGNITION or HOTWORD
//        OR there is no active privacy sensitive capture or call
//                OR client has CAPTURE_AUDIO_OUTPUT privileged permission
//            AND is TOP most recent assistant and uses VOICE_RECOGNITION or HOTWORD
//                OR there is no top recent assistant and source is HOTWORD
//    OR The client is an accessibility service
//        AND Is on TOP
//                AND the source is VOICE_RECOGNITION or HOTWORD
//            OR The assistant is not on TOP
//                AND there is no active privacy sensitive capture or call
//                    OR client has CAPTURE_AUDIO_OUTPUT privileged permission
//        AND is on TOP
//        AND the source is VOICE_RECOGNITION or HOTWORD
//    OR the client source is virtual (remote submix, call audio TX or RX...)
//    OR the client source is HOTWORD
//        AND is on TOP
//            OR all active clients are using HOTWORD source
//        AND no call is active
//            OR client has CAPTURE_AUDIO_OUTPUT privileged permission
//    OR the client is the current InputMethodService
//        AND a RTT call is active AND the source is VOICE_RECOGNITION
//    OR Any client
//        AND The assistant is not on TOP
//        AND is on TOP or latest started
//        AND there is no active privacy sensitive capture or call
//            OR client has CAPTURE_AUDIO_OUTPUT privileged permission


    sp<AudioRecordClient> topActive;
    sp<AudioRecordClient> latestActive;
    sp<AudioRecordClient> topSensitiveActive;
    sp<AudioRecordClient> latestSensitiveActiveOrComm;
    sp<AudioRecordClient> latestActiveAssistant;

    nsecs_t topStartNs = 0;
    nsecs_t latestStartNs = 0;
    nsecs_t topSensitiveStartNs = 0;
    nsecs_t latestSensitiveStartNs = 0;
    nsecs_t latestAssistantStartNs = 0;
    bool isA11yOnTop = mUidPolicy->isA11yOnTop();
    bool isAssistantOnTop = false;
    bool useActiveAssistantList = false;
    bool isSensitiveActive = false;
    bool isInCall = mPhoneState == AUDIO_MODE_IN_CALL;
    bool isInCommunication = mPhoneState == AUDIO_MODE_IN_COMMUNICATION;
    bool rttCallActive = (isInCall || isInCommunication)
            && mUidPolicy->isRttEnabled();
    bool onlyHotwordActive = true;
    bool isPhoneStateOwnerActive = false;

    // if Sensor Privacy is enabled then all recordings should be silenced.
    if (mSensorPrivacyPolicy->isSensorPrivacyEnabled()) {
        silenceAllRecordings_l();
        return;
    }

    for (size_t i =0; i < mAudioRecordClients.size(); i++) {
        sp<AudioRecordClient> current = mAudioRecordClients[i];
        uid_t currentUid = VALUE_OR_FATAL(aidl2legacy_int32_t_uid_t(
                current->attributionSource.uid));
        if (!current->active) {
            continue;
        }

        app_state_t appState = apmStatFromAmState(mUidPolicy->getUidState(currentUid));
        // clients which app is in IDLE state are not eligible for top active or
        // latest active
        if (appState == APP_STATE_IDLE) {
            continue;
        }

        bool isAccessibility = mUidPolicy->isA11yUid(currentUid);
        // Clients capturing for Accessibility services or virtual sources are not considered
        // for top or latest active to avoid masking regular clients started before
        if (!isAccessibility && !isVirtualSource(current->attributes.source)) {
            bool isAssistant = mUidPolicy->isAssistantUid(currentUid);
            bool isActiveAssistant = mUidPolicy->isActiveAssistantUid(currentUid);
            bool isPrivacySensitive =
                    (current->attributes.flags & AUDIO_FLAG_CAPTURE_PRIVATE) != 0;

            if (appState == APP_STATE_TOP) {
                if (isPrivacySensitive) {
                    if (current->startTimeNs > topSensitiveStartNs) {
                        topSensitiveActive = current;
                        topSensitiveStartNs = current->startTimeNs;
                    }
                } else {
                    if (current->startTimeNs > topStartNs) {
                        topActive = current;
                        topStartNs = current->startTimeNs;
                    }
                }
                if (isAssistant) {
                    isAssistantOnTop = true;
                    if (isActiveAssistant) {
                        useActiveAssistantList = true;
                    } else if (!useActiveAssistantList) {
                        if (current->startTimeNs > latestAssistantStartNs) {
                            latestActiveAssistant = current;
                            latestAssistantStartNs = current->startTimeNs;
                        }
                    }
                }
            }
            // Clients capturing for HOTWORD are not considered
            // for latest active to avoid masking regular clients started before
            if (!(current->attributes.source == AUDIO_SOURCE_HOTWORD
                    || ((isA11yOnTop || rttCallActive) && isAssistant))) {
                if (isPrivacySensitive) {
                    // if audio mode is IN_COMMUNICATION, make sure the audio mode owner
                    // is marked latest sensitive active even if another app qualifies.
                    if (current->startTimeNs > latestSensitiveStartNs
                            || (isInCommunication && currentUid == mPhoneStateOwnerUid)) {
                        if (!isInCommunication || latestSensitiveActiveOrComm == nullptr
                                || VALUE_OR_FATAL(aidl2legacy_int32_t_uid_t(
                                    latestSensitiveActiveOrComm->attributionSource.uid))
                                        != mPhoneStateOwnerUid) {
                            latestSensitiveActiveOrComm = current;
                            latestSensitiveStartNs = current->startTimeNs;
                        }
                    }
                    isSensitiveActive = true;
                } else {
                    if (current->startTimeNs > latestStartNs) {
                        latestActive = current;
                        latestStartNs = current->startTimeNs;
                    }
                }
            }
        }
        if (current->attributes.source != AUDIO_SOURCE_HOTWORD &&
                !isVirtualSource(current->attributes.source)) {
            onlyHotwordActive = false;
        }
        if (currentUid == mPhoneStateOwnerUid &&
                !isVirtualSource(current->attributes.source)) {
            isPhoneStateOwnerActive = true;
        }
    }

    // if no active client with UI on Top, consider latest active as top
    if (topActive == nullptr) {
        topActive = latestActive;
        topStartNs = latestStartNs;
    }
    if (topSensitiveActive == nullptr) {
        topSensitiveActive = latestSensitiveActiveOrComm;
        topSensitiveStartNs = latestSensitiveStartNs;
    } else if (latestSensitiveActiveOrComm != nullptr) {
        // if audio mode is IN_COMMUNICATION, favor audio mode owner over an app with
        // foreground UI in case both are capturing with privacy sensitive flag.
        uid_t latestActiveUid = VALUE_OR_FATAL(
            aidl2legacy_int32_t_uid_t(latestSensitiveActiveOrComm->attributionSource.uid));
        if (isInCommunication && latestActiveUid == mPhoneStateOwnerUid) {
            topSensitiveActive = latestSensitiveActiveOrComm;
            topSensitiveStartNs = latestSensitiveStartNs;
        }
    }

    // If both privacy sensitive and regular capture are active:
    //  if the regular capture is privileged
    //    allow concurrency
    //  else
    //    favor the privacy sensitive case
    if (topActive != nullptr && topSensitiveActive != nullptr
            && !topActive->canCaptureOutput) {
        topActive = nullptr;
    }

    for (size_t i =0; i < mAudioRecordClients.size(); i++) {
        sp<AudioRecordClient> current = mAudioRecordClients[i];
        uid_t currentUid = VALUE_OR_FATAL(aidl2legacy_int32_t_uid_t(
            current->attributionSource.uid));
        if (!current->active) {
            continue;
        }

        audio_source_t source = current->attributes.source;
        bool isTopOrLatestActive = topActive == nullptr ? false :
            current->attributionSource.uid == topActive->attributionSource.uid;
        bool isTopOrLatestSensitive = topSensitiveActive == nullptr ? false :
            current->attributionSource.uid == topSensitiveActive->attributionSource.uid;
        bool isTopOrLatestAssistant = latestActiveAssistant == nullptr ? false :
            current->attributionSource.uid == latestActiveAssistant->attributionSource.uid;

        auto canCaptureIfInCallOrCommunication = [&](const auto &recordClient) REQUIRES(mMutex) {
            uid_t recordUid = VALUE_OR_FATAL(aidl2legacy_int32_t_uid_t(
                recordClient->attributionSource.uid));
            bool canCaptureCall = recordClient->canCaptureOutput;
            bool canCaptureCommunication = recordClient->canCaptureOutput
                || !isPhoneStateOwnerActive
                || recordUid == mPhoneStateOwnerUid;
            return !(isInCall && !canCaptureCall)
                && !(isInCommunication && !canCaptureCommunication);
        };

        // By default allow capture if:
        //     The assistant is not on TOP
        //     AND is on TOP or latest started
        //     AND there is no active privacy sensitive capture or call
        //             OR client has CAPTURE_AUDIO_OUTPUT privileged permission
        bool allowSensitiveCapture =
            !isSensitiveActive || isTopOrLatestSensitive || current->canCaptureOutput;
        bool allowCapture = !isAssistantOnTop
                && (isTopOrLatestActive || isTopOrLatestSensitive)
                && allowSensitiveCapture
                && canCaptureIfInCallOrCommunication(current);

        if (!current->hasOp()) {
            // Never allow capture if app op is denied
            allowCapture = false;
        } else if (isVirtualSource(source)) {
            // Allow capture for virtual (remote submix, call audio TX or RX...) sources
            allowCapture = true;
        } else if (!useActiveAssistantList && mUidPolicy->isAssistantUid(currentUid)) {
            // For assistant allow capture if:
            //     Active assistant list is not being used
            //     AND accessibility service is on TOP or a RTT call is active
            //            AND the source is VOICE_RECOGNITION or HOTWORD
            //     OR there is no active privacy sensitive capture or call
            //          OR client has CAPTURE_AUDIO_OUTPUT privileged permission
            //            AND is latest TOP assistant AND
            //               uses VOICE_RECOGNITION OR uses HOTWORD
            //            OR there is no TOP assistant and uses HOTWORD
            if (isA11yOnTop || rttCallActive) {
                if (source == AUDIO_SOURCE_HOTWORD || source == AUDIO_SOURCE_VOICE_RECOGNITION) {
                    allowCapture = true;
                }
            } else if (allowSensitiveCapture
                    && canCaptureIfInCallOrCommunication(current)) {
                if (isTopOrLatestAssistant
                    && (source == AUDIO_SOURCE_VOICE_RECOGNITION
                        || source == AUDIO_SOURCE_HOTWORD)) {
                        allowCapture = true;
                } else if (!isAssistantOnTop && (source == AUDIO_SOURCE_HOTWORD)) {
                    allowCapture = true;
                }
            }
        } else if (useActiveAssistantList && mUidPolicy->isActiveAssistantUid(currentUid)) {
            // For assistant on active list and on top allow capture if:
            //     An accessibility service is on TOP
            //         AND the source is VOICE_RECOGNITION or HOTWORD
            //     OR there is no active privacy sensitive capture or call
            //             OR client has CAPTURE_AUDIO_OUTPUT privileged permission
            //         AND uses VOICE_RECOGNITION OR uses HOTWORD
            if (isA11yOnTop) {
                if (source == AUDIO_SOURCE_HOTWORD || source == AUDIO_SOURCE_VOICE_RECOGNITION) {
                    allowCapture = true;
                }
            } else if (allowSensitiveCapture
                        && canCaptureIfInCallOrCommunication(current)) {
                if ((source == AUDIO_SOURCE_VOICE_RECOGNITION) || (source == AUDIO_SOURCE_HOTWORD))
                {
                    allowCapture = true;
                }
            }
        } else if (mUidPolicy->isA11yUid(currentUid)) {
            // For accessibility service allow capture if:
            //     The assistant is not on TOP
            //         AND there is no active privacy sensitive capture or call
            //             OR client has CAPTURE_AUDIO_OUTPUT privileged permission
            //     OR
            //         Is on TOP AND the source is VOICE_RECOGNITION or HOTWORD
            if (!isAssistantOnTop
                    && allowSensitiveCapture
                    && canCaptureIfInCallOrCommunication(current)) {
                allowCapture = true;
            }
            if (isA11yOnTop) {
                if (source == AUDIO_SOURCE_VOICE_RECOGNITION || source == AUDIO_SOURCE_HOTWORD) {
                    allowCapture = true;
                }
            }
        } else if (source == AUDIO_SOURCE_HOTWORD) {
            // For HOTWORD source allow capture when not on TOP if:
            //     All active clients are using HOTWORD source
            //     AND no call is active
            //         OR client has CAPTURE_AUDIO_OUTPUT privileged permission
            if (onlyHotwordActive
                    && canCaptureIfInCallOrCommunication(current)) {
                allowCapture = true;
            }
        } else if (mUidPolicy->isCurrentImeUid(currentUid)) {
            // For current InputMethodService allow capture if:
            //     A RTT call is active AND the source is VOICE_RECOGNITION
            if (rttCallActive && source == AUDIO_SOURCE_VOICE_RECOGNITION) {
                allowCapture = true;
            }
        }
        setAppState_l(current,
                      allowCapture ? apmStatFromAmState(mUidPolicy->getUidState(currentUid)) :
                                APP_STATE_IDLE);
    }
}

void AudioPolicyService::silenceAllRecordings_l() {
    for (size_t i = 0; i < mAudioRecordClients.size(); i++) {
        sp<AudioRecordClient> current = mAudioRecordClients[i];
        if (!isVirtualSource(current->attributes.source)) {
            setAppState_l(current, APP_STATE_IDLE);
        }
    }
}

/* static */
app_state_t AudioPolicyService::apmStatFromAmState(int amState) {

    if (amState == ActivityManager::PROCESS_STATE_UNKNOWN) {
        return APP_STATE_IDLE;
    } else if (amState <= ActivityManager::PROCESS_STATE_TOP) {
      // include persistent services
      return APP_STATE_TOP;
    }
    return APP_STATE_FOREGROUND;
}

/* static */
bool AudioPolicyService::isVirtualSource(audio_source_t source)
{
    switch (source) {
        case AUDIO_SOURCE_VOICE_UPLINK:
        case AUDIO_SOURCE_VOICE_DOWNLINK:
        case AUDIO_SOURCE_VOICE_CALL:
        case AUDIO_SOURCE_REMOTE_SUBMIX:
        case AUDIO_SOURCE_FM_TUNER:
        case AUDIO_SOURCE_ECHO_REFERENCE:
            return true;
        default:
            break;
    }
    return false;
}

void AudioPolicyService::setAppState_l(sp<AudioRecordClient> client, app_state_t state)
{
    AutoCallerClear acc;

    if (mAudioPolicyManager) {
        mAudioPolicyManager->setAppState(client->portId, state);
    }
    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
    if (af) {
        bool silenced = state == APP_STATE_IDLE;
        if (client->silenced != silenced) {
            if (client->active) {
                if (silenced) {
                    finishRecording(client->attributionSource, client->attributes.source);
                } else {
                    std::stringstream msg;
                    msg << "Audio recording un-silenced on session " << client->session;
                    if (!startRecording(client->attributionSource, String16(msg.str().c_str()),
                            client->attributes.source)) {
                        silenced = true;
                    }
                }
            }
            af->setRecordSilenced(client->portId, silenced);
            client->silenced = silenced;
        }
    }
}

status_t AudioPolicyService::dump(int fd, const Vector<String16>& args __unused)
NO_THREAD_SAFETY_ANALYSIS  // update for trylock.
{
    if (!dumpAllowed()) {
        dumpPermissionDenial(fd);
    } else {
        const bool locked = mMutex.try_lock(kDumpLockTimeoutNs);
        if (!locked) {
            String8 result(kDeadlockedString);
            write(fd, result.c_str(), result.size());
        }

        dumpInternals(fd);

        String8 actPtr = String8::format("AudioCommandThread: %p\n", mAudioCommandThread.get());
        write(fd, actPtr.c_str(), actPtr.size());
        if (mAudioCommandThread != 0) {
            mAudioCommandThread->dump(fd);
        }

        String8 octPtr = String8::format("OutputCommandThread: %p\n", mOutputCommandThread.get());
        write(fd, octPtr.c_str(), octPtr.size());
        if (mOutputCommandThread != 0) {
            mOutputCommandThread->dump(fd);
        }

        if (mAudioPolicyManager) {
            mAudioPolicyManager->dump(fd);
        } else {
            String8 apmPtr = String8::format("AudioPolicyManager: %p\n", mAudioPolicyManager);
            write(fd, apmPtr.c_str(), apmPtr.size());
        }

        mPackageManager.dump(fd);

        dumpReleaseLock(mMutex, locked);

        if (mSpatializer != nullptr) {
            std::string dumpString = mSpatializer->toString(1 /* level */);
            write(fd, dumpString.c_str(), dumpString.size());
        } else {
            String8 spatializerPtr = String8::format("Spatializer no supportted on this device\n");
            write(fd, spatializerPtr.c_str(), spatializerPtr.size());
        }

        {
            std::string timeCheckStats = getIAudioPolicyServiceStatistics().dump();
            dprintf(fd, "\nIAudioPolicyService binder call profile\n");
            write(fd, timeCheckStats.c_str(), timeCheckStats.size());
        }
    }
    return NO_ERROR;
}

status_t AudioPolicyService::dumpPermissionDenial(int fd)
{
    const size_t SIZE = 256;
    char buffer[SIZE];
    String8 result;
    snprintf(buffer, SIZE, "Permission Denial: "
            "can't dump AudioPolicyService from pid=%d, uid=%d\n",
            IPCThreadState::self()->getCallingPid(),
            IPCThreadState::self()->getCallingUid());
    result.append(buffer);
    write(fd, result.c_str(), result.size());
    return NO_ERROR;
}

status_t AudioPolicyService::onTransact(
        uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
    // make sure transactions reserved to AudioFlinger do not come from other processes
    switch (code) {
        case TRANSACTION_startOutput:
        case TRANSACTION_stopOutput:
        case TRANSACTION_releaseOutput:
        case TRANSACTION_getInputForAttr:
        case TRANSACTION_startInput:
        case TRANSACTION_stopInput:
        case TRANSACTION_releaseInput:
        case TRANSACTION_getOutputForEffect:
        case TRANSACTION_registerEffect:
        case TRANSACTION_unregisterEffect:
        case TRANSACTION_setEffectEnabled:
        case TRANSACTION_getStrategyForStream:
        case TRANSACTION_getOutputForAttr:
        case TRANSACTION_moveEffectsToIo:
            ALOGW("%s: transaction %d received from PID %d",
                  __func__, code, IPCThreadState::self()->getCallingPid());
            return INVALID_OPERATION;
        default:
            break;
    }

    // make sure the following transactions come from system components
    switch (code) {
        case TRANSACTION_setDeviceConnectionState:
        case TRANSACTION_handleDeviceConfigChange:
        case TRANSACTION_setPhoneState:
//FIXME: Allow setForceUse calls from system apps until a better use case routing API is available
//      case TRANSACTION_setForceUse:
        case TRANSACTION_initStreamVolume:
        case TRANSACTION_setStreamVolumeIndex:
        case TRANSACTION_setVolumeIndexForAttributes:
        case TRANSACTION_getStreamVolumeIndex:
        case TRANSACTION_getVolumeIndexForAttributes:
        case TRANSACTION_getMinVolumeIndexForAttributes:
        case TRANSACTION_getMaxVolumeIndexForAttributes:
        case TRANSACTION_isStreamActive:
        case TRANSACTION_isStreamActiveRemotely:
        case TRANSACTION_isSourceActive:
        case TRANSACTION_registerPolicyMixes:
        case TRANSACTION_updatePolicyMixes:
        case TRANSACTION_setMasterMono:
        case TRANSACTION_getSurroundFormats:
        case TRANSACTION_getReportedSurroundFormats:
        case TRANSACTION_setSurroundFormatEnabled:
        case TRANSACTION_setAssistantServicesUids:
        case TRANSACTION_setActiveAssistantServicesUids:
        case TRANSACTION_setA11yServicesUids:
        case TRANSACTION_setUidDeviceAffinities:
        case TRANSACTION_removeUidDeviceAffinities:
        case TRANSACTION_setUserIdDeviceAffinities:
        case TRANSACTION_removeUserIdDeviceAffinities:
        case TRANSACTION_getHwOffloadFormatsSupportedForBluetoothMedia:
        case TRANSACTION_listAudioVolumeGroups:
        case TRANSACTION_getVolumeGroupFromAudioAttributes:
        case TRANSACTION_acquireSoundTriggerSession:
        case TRANSACTION_releaseSoundTriggerSession:
        case TRANSACTION_isHotwordStreamSupported:
        case TRANSACTION_setRttEnabled:
        case TRANSACTION_isCallScreenModeSupported:
        case TRANSACTION_setDevicesRoleForStrategy:
        case TRANSACTION_setSupportedSystemUsages:
        case TRANSACTION_removeDevicesRoleForStrategy:
        case TRANSACTION_clearDevicesRoleForStrategy:
        case TRANSACTION_getDevicesForRoleAndStrategy:
        case TRANSACTION_getDevicesForAttributes:
        case TRANSACTION_setAllowedCapturePolicy:
        case TRANSACTION_onNewAudioModulesAvailable:
        case TRANSACTION_setCurrentImeUid:
        case TRANSACTION_registerSoundTriggerCaptureStateListener:
        case TRANSACTION_setDevicesRoleForCapturePreset:
        case TRANSACTION_addDevicesRoleForCapturePreset:
        case TRANSACTION_removeDevicesRoleForCapturePreset:
        case TRANSACTION_clearDevicesRoleForCapturePreset:
        case TRANSACTION_getDevicesForRoleAndCapturePreset:
        case TRANSACTION_getSpatializer:
        case TRANSACTION_setPreferredMixerAttributes:
        case TRANSACTION_clearPreferredMixerAttributes:
        case TRANSACTION_getRegisteredPolicyMixes: {
            if (!isServiceUid(IPCThreadState::self()->getCallingUid())) {
                ALOGW("%s: transaction %d received from PID %d unauthorized UID %d",
                      __func__, code, IPCThreadState::self()->getCallingPid(),
                      IPCThreadState::self()->getCallingUid());
                return INVALID_OPERATION;
            }
        } break;
        default:
            break;
    }

    const std::string methodName = getIAudioPolicyServiceStatistics().getMethodForCode(code);
    mediautils::TimeCheck check(
            std::string("IAudioPolicyService::").append(methodName),
            [code, methodName](bool timeout, float elapsedMs) { // don't move methodName.
        if (timeout) {
            mediametrics::LogItem(AMEDIAMETRICS_KEY_AUDIO_POLICY)
                .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_TIMEOUT)
                .set(AMEDIAMETRICS_PROP_METHODCODE, int64_t(code))
                .set(AMEDIAMETRICS_PROP_METHODNAME, methodName.c_str())
                .record();
        } else {
            getIAudioPolicyServiceStatistics().event(code, elapsedMs);
        }
    }, mediautils::TimeCheck::kDefaultTimeoutDuration,
    mediautils::TimeCheck::kDefaultSecondChanceDuration,
    true /* crashOnTimeout */);

    switch (code) {
        case SHELL_COMMAND_TRANSACTION: {
            int in = data.readFileDescriptor();
            int out = data.readFileDescriptor();
            int err = data.readFileDescriptor();
            int argc = data.readInt32();
            Vector<String16> args;
            for (int i = 0; i < argc && data.dataAvail() > 0; i++) {
               args.add(data.readString16());
            }
            sp<IBinder> unusedCallback;
            sp<IResultReceiver> resultReceiver;
            status_t status;
            if ((status = data.readNullableStrongBinder(&unusedCallback)) != NO_ERROR) {
                return status;
            }
            if ((status = data.readNullableStrongBinder(&resultReceiver)) != NO_ERROR) {
                return status;
            }
            status = shellCommand(in, out, err, args);
            if (resultReceiver != nullptr) {
                resultReceiver->send(status);
            }
            return NO_ERROR;
        }
    }

    return BnAudioPolicyService::onTransact(code, data, reply, flags);
}

// ------------------- Shell command implementation -------------------

// NOTE: This is a remote API - make sure all args are validated
status_t AudioPolicyService::shellCommand(int in, int out, int err, Vector<String16>& args) {
    if (!checkCallingPermission(sManageAudioPolicyPermission, nullptr, nullptr)) {
        return PERMISSION_DENIED;
    }
    if (in == BAD_TYPE || out == BAD_TYPE || err == BAD_TYPE) {
        return BAD_VALUE;
    }
    if (args.size() >= 3 && args[0] == String16("set-uid-state")) {
        return handleSetUidState(args, err);
    } else if (args.size() >= 2 && args[0] == String16("reset-uid-state")) {
        return handleResetUidState(args, err);
    } else if (args.size() >= 2 && args[0] == String16("get-uid-state")) {
        return handleGetUidState(args, out, err);
    } else if (args.size() >= 1 && args[0] == String16("purge_permission-cache")) {
        purgePermissionCache();
        return NO_ERROR;
    } else if (args.size() == 1 && args[0] == String16("help")) {
        printHelp(out);
        return NO_ERROR;
    }
    printHelp(err);
    return BAD_VALUE;
}

static status_t getUidForPackage(String16 packageName, int userId, /*inout*/uid_t& uid, int err) {
    if (userId < 0) {
        ALOGE("Invalid user: %d", userId);
        dprintf(err, "Invalid user: %d\n", userId);
        return BAD_VALUE;
    }

    PermissionController pc;
    uid = pc.getPackageUid(packageName, 0);
    if (uid <= 0) {
        ALOGE("Unknown package: '%s'", String8(packageName).c_str());
        dprintf(err, "Unknown package: '%s'\n", String8(packageName).c_str());
        return BAD_VALUE;
    }

    uid = multiuser_get_uid(userId, uid);
    return NO_ERROR;
}

status_t AudioPolicyService::handleSetUidState(Vector<String16>& args, int err) {
    // Valid arg.size() is 3 or 5, args.size() is 5 with --user option.
    if (!(args.size() == 3 || args.size() == 5)) {
        printHelp(err);
        return BAD_VALUE;
    }

    bool active = false;
    if (args[2] == String16("active")) {
        active = true;
    } else if ((args[2] != String16("idle"))) {
        ALOGE("Expected active or idle but got: '%s'", String8(args[2]).c_str());
        return BAD_VALUE;
    }

    int userId = 0;
    if (args.size() >= 5 && args[3] == String16("--user")) {
        userId = atoi(String8(args[4]));
    }

    uid_t uid;
    if (getUidForPackage(args[1], userId, uid, err) == BAD_VALUE) {
        return BAD_VALUE;
    }

    sp<UidPolicy> uidPolicy;
    {
        audio_utils::lock_guard _l(mMutex);
        uidPolicy = mUidPolicy;
    }
    if (uidPolicy) {
        uidPolicy->addOverrideUid(uid, active);
        return NO_ERROR;
    }
    return NO_INIT;
}

status_t AudioPolicyService::handleResetUidState(Vector<String16>& args, int err) {
    // Valid arg.size() is 2 or 4, args.size() is 4 with --user option.
    if (!(args.size() == 2 || args.size() == 4)) {
        printHelp(err);
        return BAD_VALUE;
    }

    int userId = 0;
    if (args.size() >= 4 && args[2] == String16("--user")) {
        userId = atoi(String8(args[3]));
    }

    uid_t uid;
    if (getUidForPackage(args[1], userId, uid, err) == BAD_VALUE) {
        return BAD_VALUE;
    }

    sp<UidPolicy> uidPolicy;
    {
        audio_utils::lock_guard _l(mMutex);
        uidPolicy = mUidPolicy;
    }
    if (uidPolicy) {
        uidPolicy->removeOverrideUid(uid);
        return NO_ERROR;
    }
    return NO_INIT;
}

status_t AudioPolicyService::handleGetUidState(Vector<String16>& args, int out, int err) {
    // Valid arg.size() is 2 or 4, args.size() is 4 with --user option.
    if (!(args.size() == 2 || args.size() == 4)) {
        printHelp(err);
        return BAD_VALUE;
    }

    int userId = 0;
    if (args.size() >= 4 && args[2] == String16("--user")) {
        userId = atoi(String8(args[3]));
    }

    uid_t uid;
    if (getUidForPackage(args[1], userId, uid, err) == BAD_VALUE) {
        return BAD_VALUE;
    }

    sp<UidPolicy> uidPolicy;
    {
        audio_utils::lock_guard _l(mMutex);
        uidPolicy = mUidPolicy;
    }
    if (uidPolicy) {
        return dprintf(out, uidPolicy->isUidActive(uid) ? "active\n" : "idle\n");
    }
    return NO_INIT;
}

status_t AudioPolicyService::printHelp(int out) {
    return dprintf(out, "Audio policy service commands:\n"
        "  get-uid-state <PACKAGE> [--user USER_ID] gets the uid state\n"
        "  set-uid-state <PACKAGE> <active|idle> [--user USER_ID] overrides the uid state\n"
        "  reset-uid-state <PACKAGE> [--user USER_ID] clears the uid state override\n"
        "  help print this message\n");
}

status_t AudioPolicyService::registerOutput(audio_io_handle_t output,
                        const audio_config_base_t& config,
                        const audio_output_flags_t flags) {
    return mUsecaseValidator->registerStream(output, config, flags);
}

status_t AudioPolicyService::unregisterOutput(audio_io_handle_t output) {
    return mUsecaseValidator->unregisterStream(output);
}

// -----------  AudioPolicyService::UidPolicy implementation ----------

void AudioPolicyService::UidPolicy::registerSelf() {
    status_t res = mAm.linkToDeath(this);
    mAm.registerUidObserver(this, ActivityManager::UID_OBSERVER_GONE
            | ActivityManager::UID_OBSERVER_IDLE
            | ActivityManager::UID_OBSERVER_ACTIVE
            | ActivityManager::UID_OBSERVER_PROCSTATE,
            ActivityManager::PROCESS_STATE_UNKNOWN,
            String16("audioserver"));
    if (!res) {
        audio_utils::lock_guard _l(mMutex);
        mObserverRegistered = true;
    } else {
        ALOGE("UidPolicy::registerSelf linkToDeath failed: %d", res);

        mAm.unregisterUidObserver(this);
    }
}

void AudioPolicyService::UidPolicy::unregisterSelf() {
    mAm.unlinkToDeath(this);
    mAm.unregisterUidObserver(this);
    audio_utils::lock_guard _l(mMutex);
    mObserverRegistered = false;
}

void AudioPolicyService::UidPolicy::binderDied(__unused const wp<IBinder> &who) {
    audio_utils::lock_guard _l(mMutex);
    mCachedUids.clear();
    mObserverRegistered = false;
}

void AudioPolicyService::UidPolicy::checkRegistered() {
    bool needToReregister = false;
    {
        audio_utils::lock_guard _l(mMutex);
        needToReregister = !mObserverRegistered;
    }
    if (needToReregister) {
        // Looks like ActivityManager has died previously, attempt to re-register.
        registerSelf();
    }
}

bool AudioPolicyService::UidPolicy::isUidActive(uid_t uid) {
    if (isServiceUid(uid)) return true;
    checkRegistered();
    {
        audio_utils::lock_guard _l(mMutex);
        auto overrideIter = mOverrideUids.find(uid);
        if (overrideIter != mOverrideUids.end()) {
            return overrideIter->second.first;
        }
        // In an absense of the ActivityManager, assume everything to be active.
        if (!mObserverRegistered) return true;
        auto cacheIter = mCachedUids.find(uid);
        if (cacheIter != mCachedUids.end()) {
            return cacheIter->second.first;
        }
    }
    ActivityManager am;
    bool active = am.isUidActive(uid, String16("audioserver"));
    {
        audio_utils::lock_guard _l(mMutex);
        mCachedUids.insert(std::pair<uid_t,
                           std::pair<bool, int>>(uid, std::pair<bool, int>(active,
                                                      ActivityManager::PROCESS_STATE_UNKNOWN)));
    }
    return active;
}

int AudioPolicyService::UidPolicy::getUidState(uid_t uid) {
    if (isServiceUid(uid)) {
        return ActivityManager::PROCESS_STATE_TOP;
    }
    checkRegistered();
    {
        audio_utils::lock_guard _l(mMutex);
        auto overrideIter = mOverrideUids.find(uid);
        if (overrideIter != mOverrideUids.end()) {
            if (overrideIter->second.first) {
                if (overrideIter->second.second != ActivityManager::PROCESS_STATE_UNKNOWN) {
                    return overrideIter->second.second;
                } else {
                    auto cacheIter = mCachedUids.find(uid);
                    if (cacheIter != mCachedUids.end()) {
                        return cacheIter->second.second;
                    }
                }
            }
            return ActivityManager::PROCESS_STATE_UNKNOWN;
        }
        // In an absense of the ActivityManager, assume everything to be active.
        if (!mObserverRegistered) {
            return ActivityManager::PROCESS_STATE_TOP;
        }
        auto cacheIter = mCachedUids.find(uid);
        if (cacheIter != mCachedUids.end()) {
            if (cacheIter->second.first) {
                return cacheIter->second.second;
            } else {
                return ActivityManager::PROCESS_STATE_UNKNOWN;
            }
        }
    }
    ActivityManager am;
    bool active = am.isUidActive(uid, String16("audioserver"));
    int state = ActivityManager::PROCESS_STATE_UNKNOWN;
    if (active) {
        state = am.getUidProcessState(uid, String16("audioserver"));
    }
    {
        audio_utils::lock_guard _l(mMutex);
        mCachedUids.insert(std::pair<uid_t,
                           std::pair<bool, int>>(uid, std::pair<bool, int>(active, state)));
    }

    return state;
}

void AudioPolicyService::UidPolicy::onUidActive(uid_t uid) {
    updateUid(&mCachedUids, uid, true, ActivityManager::PROCESS_STATE_UNKNOWN, true);
}

void AudioPolicyService::UidPolicy::onUidGone(uid_t uid, __unused bool disabled) {
    updateUid(&mCachedUids, uid, false, ActivityManager::PROCESS_STATE_UNKNOWN, false);
}

void AudioPolicyService::UidPolicy::onUidIdle(uid_t uid, __unused bool disabled) {
    updateUid(&mCachedUids, uid, false, ActivityManager::PROCESS_STATE_UNKNOWN, true);
}

void AudioPolicyService::UidPolicy::onUidStateChanged(uid_t uid,
                                                      int32_t procState,
                                                      int64_t procStateSeq __unused,
                                                      int32_t capability __unused) {
    if (procState != ActivityManager::PROCESS_STATE_UNKNOWN) {
        updateUid(&mCachedUids, uid, true, procState, true);
    }
}

void AudioPolicyService::UidPolicy::onUidProcAdjChanged(uid_t uid __unused, int32_t adj __unused) {
}

void AudioPolicyService::UidPolicy::updateOverrideUid(uid_t uid, bool active, bool insert) {
    updateUid(&mOverrideUids, uid, active, ActivityManager::PROCESS_STATE_UNKNOWN, insert);
}

void AudioPolicyService::UidPolicy::notifyService() {
    sp<AudioPolicyService> service = mService.promote();
    if (service != nullptr) {
        service->updateUidStates();
    }
}

void AudioPolicyService::UidPolicy::updateUid(std::unordered_map<uid_t,
                                              std::pair<bool, int>> *uids,
                                              uid_t uid,
                                              bool active,
                                              int state,
                                              bool insert) {
    if (isServiceUid(uid)) {
        return;
    }
    bool wasActive = isUidActive(uid);
    int previousState = getUidState(uid);
    {
        audio_utils::lock_guard _l(mMutex);
        updateUidLocked(uids, uid, active, state, insert);
    }
    if (wasActive != isUidActive(uid) || state != previousState) {
        notifyService();
    }
}

void AudioPolicyService::UidPolicy::updateUidLocked(std::unordered_map<uid_t,
                                                    std::pair<bool, int>> *uids,
                                                    uid_t uid,
                                                    bool active,
                                                    int state,
                                                    bool insert) {
    auto it = uids->find(uid);
    if (it != uids->end()) {
        if (insert) {
            if (state == ActivityManager::PROCESS_STATE_UNKNOWN) {
                it->second.first = active;
            }
            if (it->second.first) {
                it->second.second = state;
            } else {
                it->second.second = ActivityManager::PROCESS_STATE_UNKNOWN;
            }
        } else {
            uids->erase(it);
        }
    } else if (insert && (state == ActivityManager::PROCESS_STATE_UNKNOWN)) {
        uids->insert(std::pair<uid_t, std::pair<bool, int>>(uid,
                                      std::pair<bool, int>(active, state)));
    }
}

bool AudioPolicyService::UidPolicy::isA11yOnTop() {
    audio_utils::lock_guard _l(mMutex);
    for (const auto &uid : mCachedUids) {
        if (!isA11yUid(uid.first)) {
            continue;
        }
        if (uid.second.second >= ActivityManager::PROCESS_STATE_TOP
                && uid.second.second <= ActivityManager::PROCESS_STATE_BOUND_FOREGROUND_SERVICE) {
            return true;
        }
    }
    return false;
}

bool AudioPolicyService::UidPolicy::isA11yUid(uid_t uid)
{
    std::vector<uid_t>::iterator it = find(mA11yUids.begin(), mA11yUids.end(), uid);
    return it != mA11yUids.end();
}

void AudioPolicyService::UidPolicy::setAssistantUids(const std::vector<uid_t>& uids) {
    mAssistantUids.clear();
    mAssistantUids = uids;
}

bool AudioPolicyService::UidPolicy::isAssistantUid(uid_t uid)
{
    std::vector<uid_t>::iterator it = find(mAssistantUids.begin(), mAssistantUids.end(), uid);
    return it != mAssistantUids.end();
}

void AudioPolicyService::UidPolicy::setActiveAssistantUids(const std::vector<uid_t>& activeUids) {
    mActiveAssistantUids = activeUids;
}

bool AudioPolicyService::UidPolicy::isActiveAssistantUid(uid_t uid)
{
    std::vector<uid_t>::iterator it = find(mActiveAssistantUids.begin(),
            mActiveAssistantUids.end(), uid);
    return it != mActiveAssistantUids.end();
}

void AudioPolicyService::UidPolicy::dumpInternals(int fd) {
    const size_t SIZE = 256;
    char buffer[SIZE];
    String8 result;
    auto appendUidsToResult = [&](const char* title, const std::vector<uid_t> &uids) {
        snprintf(buffer, SIZE, "\t%s: \n", title);
        result.append(buffer);
        int counter = 0;
        if (uids.empty()) {
            snprintf(buffer, SIZE, "\t\tNo UIDs present.\n");
            result.append(buffer);
            return;
        }
        for (const auto &uid : uids) {
            snprintf(buffer, SIZE, "\t\tUID[%d]=%d\n", counter++, uid);
            result.append(buffer);
        }
    };

    snprintf(buffer, SIZE, "UID Policy:\n");
    result.append(buffer);
    snprintf(buffer, SIZE, "\tmObserverRegistered=%s\n",(mObserverRegistered ? "True":"False"));
    result.append(buffer);

    appendUidsToResult("Assistants UIDs", mAssistantUids);
    appendUidsToResult("Active Assistants UIDs", mActiveAssistantUids);

    appendUidsToResult("Accessibility UIDs", mA11yUids);

    snprintf(buffer, SIZE, "\tInput Method Service UID=%d\n", mCurrentImeUid);
    result.append(buffer);

    snprintf(buffer, SIZE, "\tIs RTT Enabled: %s\n", (mRttEnabled ? "True":"False"));
    result.append(buffer);

    write(fd, result.c_str(), result.size());
}

// -----------  AudioPolicyService::SensorPrivacyService implementation ----------
void AudioPolicyService::SensorPrivacyPolicy::registerSelf() {
    SensorPrivacyManager spm;
    mSensorPrivacyEnabled = spm.isSensorPrivacyEnabled();
    spm.addSensorPrivacyListener(this);
}

void AudioPolicyService::SensorPrivacyPolicy::unregisterSelf() {
    SensorPrivacyManager spm;
    spm.removeSensorPrivacyListener(this);
}

bool AudioPolicyService::SensorPrivacyPolicy::isSensorPrivacyEnabled() {
    return mSensorPrivacyEnabled;
}

binder::Status AudioPolicyService::SensorPrivacyPolicy::onSensorPrivacyChanged(
    int toggleType __unused, int sensor __unused, bool enabled) {
    mSensorPrivacyEnabled = enabled;
    sp<AudioPolicyService> service = mService.promote();
    if (service != nullptr) {
        service->updateUidStates();
    }
    return binder::Status::ok();
}

// -----------  AudioPolicyService::AudioCommandThread implementation ----------

AudioPolicyService::AudioCommandThread::AudioCommandThread(String8 name,
                                                           const wp<AudioPolicyService>& service)
    : Thread(false), mName(name), mService(service)
{
}


AudioPolicyService::AudioCommandThread::~AudioCommandThread()
{
    if (!mAudioCommands.isEmpty()) {
        release_wake_lock(mName.c_str());
    }
    mAudioCommands.clear();
}

void AudioPolicyService::AudioCommandThread::onFirstRef()
{
    run(mName.c_str(), ANDROID_PRIORITY_AUDIO);
}

bool AudioPolicyService::AudioCommandThread::threadLoop()
{
    nsecs_t waitTime = -1;

    audio_utils::unique_lock ul(mMutex);
    while (!exitPending())
    {
        sp<AudioPolicyService> svc;
        int numTimesBecameEmpty = 0;
        while (!mAudioCommands.isEmpty() && !exitPending()) {
            nsecs_t curTime = systemTime();
            // commands are sorted by increasing time stamp: execute them from index 0 and up
            if (mAudioCommands[0]->mTime <= curTime) {
                sp<AudioCommand> command = mAudioCommands[0];
                mAudioCommands.removeAt(0);
                if (mAudioCommands.isEmpty()) {
                  ++numTimesBecameEmpty;
                }
                mLastCommand = command;

                switch (command->mCommand) {
                case SET_VOLUME: {
                    VolumeData *data = (VolumeData *)command->mParam.get();
                    ALOGV("AudioCommandThread() processing set volume stream %d, \
                            volume %f, output %d", data->mStream, data->mVolume, data->mIO);
                    ul.unlock();
                    command->mStatus = AudioSystem::setStreamVolume(data->mStream,
                                                                    data->mVolume,
                                                                    data->mIO);
                    ul.lock();
                    }break;
                case SET_PARAMETERS: {
                    ParametersData *data = (ParametersData *)command->mParam.get();
                    ALOGV("AudioCommandThread() processing set parameters string %s, io %d",
                            data->mKeyValuePairs.c_str(), data->mIO);
                    ul.unlock();
                    command->mStatus = AudioSystem::setParameters(data->mIO, data->mKeyValuePairs);
                    ul.lock();
                    }break;
                case SET_VOICE_VOLUME: {
                    VoiceVolumeData *data = (VoiceVolumeData *)command->mParam.get();
                    ALOGV("AudioCommandThread() processing set voice volume volume %f",
                            data->mVolume);
                    ul.unlock();
                    command->mStatus = AudioSystem::setVoiceVolume(data->mVolume);
                    ul.lock();
                    }break;
                case STOP_OUTPUT: {
                    StopOutputData *data = (StopOutputData *)command->mParam.get();
                    ALOGV("AudioCommandThread() processing stop output portId %d",
                            data->mPortId);
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->doStopOutput(data->mPortId);
                    ul.lock();
                    }break;
                case RELEASE_OUTPUT: {
                    ReleaseOutputData *data = (ReleaseOutputData *)command->mParam.get();
                    ALOGV("AudioCommandThread() processing release output portId %d",
                            data->mPortId);
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->doReleaseOutput(data->mPortId);
                    ul.lock();
                    }break;
                case CREATE_AUDIO_PATCH: {
                    CreateAudioPatchData *data = (CreateAudioPatchData *)command->mParam.get();
                    ALOGV("AudioCommandThread() processing create audio patch");
                    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
                    if (af == 0) {
                        command->mStatus = PERMISSION_DENIED;
                    } else {
                        ul.unlock();
                        command->mStatus = af->createAudioPatch(&data->mPatch, &data->mHandle);
                        ul.lock();
                    }
                    } break;
                case RELEASE_AUDIO_PATCH: {
                    ReleaseAudioPatchData *data = (ReleaseAudioPatchData *)command->mParam.get();
                    ALOGV("AudioCommandThread() processing release audio patch");
                    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
                    if (af == 0) {
                        command->mStatus = PERMISSION_DENIED;
                    } else {
                        ul.unlock();
                        command->mStatus = af->releaseAudioPatch(data->mHandle);
                        ul.lock();
                    }
                    } break;
                case UPDATE_AUDIOPORT_LIST: {
                    ALOGV("AudioCommandThread() processing update audio port list");
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->doOnAudioPortListUpdate();
                    ul.lock();
                    }break;
                case UPDATE_AUDIOPATCH_LIST: {
                    ALOGV("AudioCommandThread() processing update audio patch list");
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->doOnAudioPatchListUpdate();
                    ul.lock();
                    }break;
                case CHANGED_AUDIOVOLUMEGROUP: {
                    AudioVolumeGroupData *data =
                            static_cast<AudioVolumeGroupData *>(command->mParam.get());
                    ALOGV("AudioCommandThread() processing update audio volume group");
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->doOnAudioVolumeGroupChanged(data->mGroup, data->mFlags);
                    ul.lock();
                    }break;
                case SET_AUDIOPORT_CONFIG: {
                    SetAudioPortConfigData *data = (SetAudioPortConfigData *)command->mParam.get();
                    ALOGV("AudioCommandThread() processing set port config");
                    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
                    if (af == 0) {
                        command->mStatus = PERMISSION_DENIED;
                    } else {
                        ul.unlock();
                        command->mStatus = af->setAudioPortConfig(&data->mConfig);
                        ul.lock();
                    }
                    } break;
                case DYN_POLICY_MIX_STATE_UPDATE: {
                    DynPolicyMixStateUpdateData *data =
                            (DynPolicyMixStateUpdateData *)command->mParam.get();
                    ALOGV("AudioCommandThread() processing dyn policy mix state update %s %d",
                            data->mRegId.c_str(), data->mState);
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->doOnDynamicPolicyMixStateUpdate(data->mRegId, data->mState);
                    ul.lock();
                    } break;
                case RECORDING_CONFIGURATION_UPDATE: {
                    RecordingConfigurationUpdateData *data =
                            (RecordingConfigurationUpdateData *)command->mParam.get();
                    ALOGV("AudioCommandThread() processing recording configuration update");
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->doOnRecordingConfigurationUpdate(data->mEvent, &data->mClientInfo,
                            &data->mClientConfig, data->mClientEffects,
                            &data->mDeviceConfig, data->mEffects,
                            data->mPatchHandle, data->mSource);
                    ul.lock();
                    } break;
                case SET_EFFECT_SUSPENDED: {
                    SetEffectSuspendedData *data = (SetEffectSuspendedData *)command->mParam.get();
                    ALOGV("AudioCommandThread() processing set effect suspended");
                    sp<IAudioFlinger> af = AudioSystem::get_audio_flinger();
                    if (af != 0) {
                        ul.unlock();
                        af->setEffectSuspended(data->mEffectId, data->mSessionId, data->mSuspended);
                        ul.lock();
                    }
                    } break;
                case AUDIO_MODULES_UPDATE: {
                    ALOGV("AudioCommandThread() processing audio modules update");
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->doOnNewAudioModulesAvailable();
                    ul.lock();
                    } break;
                case ROUTING_UPDATED: {
                    ALOGV("AudioCommandThread() processing routing update");
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->doOnRoutingUpdated();
                    ul.lock();
                    } break;

                case UPDATE_UID_STATES: {
                    ALOGV("AudioCommandThread() processing updateUID states");
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->updateUidStates();
                    ul.lock();
                    } break;

                case CHECK_SPATIALIZER_OUTPUT: {
                    ALOGV("AudioCommandThread() processing check spatializer");
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->doOnCheckSpatializer();
                    ul.lock();
                    } break;

                case UPDATE_ACTIVE_SPATIALIZER_TRACKS: {
                    ALOGV("AudioCommandThread() processing update spatializer tracks");
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->doOnUpdateActiveSpatializerTracks();
                    ul.lock();
                    } break;

                case VOL_RANGE_INIT_REQUEST: {
                    ALOGV("AudioCommandThread() processing volume range init request");
                    svc = mService.promote();
                    if (svc == 0) {
                        break;
                    }
                    ul.unlock();
                    svc->doOnVolumeRangeInitRequest();
                    ul.lock();
                    } break;

                default:
                    ALOGW("AudioCommandThread() unknown command %d", command->mCommand);
                }
                {
                    audio_utils::lock_guard _l(command->mMutex);
                    if (command->mWaitStatus) {
                        command->mWaitStatus = false;
                        command->mCond.notify_one();
                    }
                }
                waitTime = -1;
                // release ul before releasing strong reference on the service as
                // AudioPolicyService destructor calls AudioCommandThread::exit() which
                // acquires ul.
                ul.unlock();
                svc.clear();
                ul.lock();
            } else {
                waitTime = mAudioCommands[0]->mTime - curTime;
                break;
            }
        }

        // release delayed commands wake lock as many times as we made the  queue is
        // empty during popping.
        while (numTimesBecameEmpty--) {
            release_wake_lock(mName.c_str());
        }

        // At this stage we have either an empty command queue or the first command in the queue
        // has a finite delay. So unless we are exiting it is safe to wait.
        if (!exitPending()) {
            ALOGV("AudioCommandThread() going to sleep");
            if (waitTime == -1) {
                mWaitWorkCV.wait(ul);
            } else {
                // discard return value.
                mWaitWorkCV.wait_for(ul, std::chrono::nanoseconds(waitTime));
            }
        }
    }
    // release delayed commands wake lock before quitting
    if (!mAudioCommands.isEmpty()) {
        release_wake_lock(mName.c_str());
    }
    return false;
}

status_t AudioPolicyService::AudioCommandThread::dump(int fd)
NO_THREAD_SAFETY_ANALYSIS  // trylock
{
    const size_t SIZE = 256;
    char buffer[SIZE];
    String8 result;

    const bool locked = mMutex.try_lock(kDumpLockTimeoutNs);
    if (!locked) {
        String8 result2(kCmdDeadlockedString);
        write(fd, result2.c_str(), result2.size());
    }

    snprintf(buffer, SIZE, "- Commands:\n");
    result = String8(buffer);
    result.append("   Command Time        Wait pParam\n");
    for (size_t i = 0; i < mAudioCommands.size(); i++) {
        mAudioCommands[i]->dump(buffer, SIZE);
        result.append(buffer);
    }
    result.append("  Last Command\n");
    if (mLastCommand != 0) {
        mLastCommand->dump(buffer, SIZE);
        result.append(buffer);
    } else {
        result.append("     none\n");
    }

    write(fd, result.c_str(), result.size());

    dumpReleaseLock(mMutex, locked);

    return NO_ERROR;
}

status_t AudioPolicyService::AudioCommandThread::volumeCommand(audio_stream_type_t stream,
                                                               float volume,
                                                               audio_io_handle_t output,
                                                               int delayMs)
{
    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = SET_VOLUME;
    sp<VolumeData> data = new VolumeData();
    data->mStream = stream;
    data->mVolume = volume;
    data->mIO = output;
    command->mParam = data;
    command->mWaitStatus = true;
    ALOGV("AudioCommandThread() adding set volume stream %d, volume %f, output %d",
            stream, volume, output);
    return sendCommand(command, delayMs);
}

status_t AudioPolicyService::AudioCommandThread::parametersCommand(audio_io_handle_t ioHandle,
                                                                   const char *keyValuePairs,
                                                                   int delayMs)
{
    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = SET_PARAMETERS;
    sp<ParametersData> data = new ParametersData();
    data->mIO = ioHandle;
    data->mKeyValuePairs = String8(keyValuePairs);
    command->mParam = data;
    command->mWaitStatus = true;
    ALOGV("AudioCommandThread() adding set parameter string %s, io %d ,delay %d",
            keyValuePairs, ioHandle, delayMs);
    return sendCommand(command, delayMs);
}

status_t AudioPolicyService::AudioCommandThread::voiceVolumeCommand(float volume, int delayMs)
{
    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = SET_VOICE_VOLUME;
    sp<VoiceVolumeData> data = new VoiceVolumeData();
    data->mVolume = volume;
    command->mParam = data;
    command->mWaitStatus = true;
    ALOGV("AudioCommandThread() adding set voice volume volume %f", volume);
    return sendCommand(command, delayMs);
}

void AudioPolicyService::AudioCommandThread::setEffectSuspendedCommand(int effectId,
                                                                       audio_session_t sessionId,
                                                                       bool suspended)
{
    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = SET_EFFECT_SUSPENDED;
    sp<SetEffectSuspendedData> data = new SetEffectSuspendedData();
    data->mEffectId = effectId;
    data->mSessionId = sessionId;
    data->mSuspended = suspended;
    command->mParam = data;
    ALOGV("AudioCommandThread() adding set suspended effectId %d sessionId %d suspended %d",
        effectId, sessionId, suspended);
    sendCommand(command);
}


void AudioPolicyService::AudioCommandThread::stopOutputCommand(audio_port_handle_t portId)
{
    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = STOP_OUTPUT;
    sp<StopOutputData> data = new StopOutputData();
    data->mPortId = portId;
    command->mParam = data;
    ALOGV("AudioCommandThread() adding stop output portId %d", portId);
    sendCommand(command);
}

void AudioPolicyService::AudioCommandThread::releaseOutputCommand(audio_port_handle_t portId)
{
    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = RELEASE_OUTPUT;
    sp<ReleaseOutputData> data = new ReleaseOutputData();
    data->mPortId = portId;
    command->mParam = data;
    ALOGV("AudioCommandThread() adding release output portId %d", portId);
    sendCommand(command);
}

status_t AudioPolicyService::AudioCommandThread::createAudioPatchCommand(
                                                const struct audio_patch *patch,
                                                audio_patch_handle_t *handle,
                                                int delayMs)
{
    status_t status = NO_ERROR;

    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = CREATE_AUDIO_PATCH;
    CreateAudioPatchData *data = new CreateAudioPatchData();
    data->mPatch = *patch;
    data->mHandle = *handle;
    command->mParam = data;
    command->mWaitStatus = true;
    ALOGV("AudioCommandThread() adding create patch delay %d", delayMs);
    status = sendCommand(command, delayMs);
    if (status == NO_ERROR) {
        *handle = data->mHandle;
    }
    return status;
}

status_t AudioPolicyService::AudioCommandThread::releaseAudioPatchCommand(audio_patch_handle_t handle,
                                                 int delayMs)
{
    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = RELEASE_AUDIO_PATCH;
    ReleaseAudioPatchData *data = new ReleaseAudioPatchData();
    data->mHandle = handle;
    command->mParam = data;
    command->mWaitStatus = true;
    ALOGV("AudioCommandThread() adding release patch delay %d", delayMs);
    return sendCommand(command, delayMs);
}

void AudioPolicyService::AudioCommandThread::updateAudioPortListCommand()
{
    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = UPDATE_AUDIOPORT_LIST;
    ALOGV("AudioCommandThread() adding update audio port list");
    sendCommand(command);
}

void AudioPolicyService::AudioCommandThread::updateUidStatesCommand()
{
    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = UPDATE_UID_STATES;
    ALOGV("AudioCommandThread() adding update UID states");
    sendCommand(command);
}

void AudioPolicyService::AudioCommandThread::updateAudioPatchListCommand()
{
    sp<AudioCommand>command = new AudioCommand();
    command->mCommand = UPDATE_AUDIOPATCH_LIST;
    ALOGV("AudioCommandThread() adding update audio patch list");
    sendCommand(command);
}

void AudioPolicyService::AudioCommandThread::changeAudioVolumeGroupCommand(volume_group_t group,
                                                                           int flags)
{
    sp<AudioCommand>command = new AudioCommand();
    command->mCommand = CHANGED_AUDIOVOLUMEGROUP;
    AudioVolumeGroupData *data= new AudioVolumeGroupData();
    data->mGroup = group;
    data->mFlags = flags;
    command->mParam = data;
    ALOGV("AudioCommandThread() adding audio volume group changed");
    sendCommand(command);
}

status_t AudioPolicyService::AudioCommandThread::setAudioPortConfigCommand(
                                            const struct audio_port_config *config, int delayMs)
{
    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = SET_AUDIOPORT_CONFIG;
    SetAudioPortConfigData *data = new SetAudioPortConfigData();
    data->mConfig = *config;
    command->mParam = data;
    command->mWaitStatus = true;
    ALOGV("AudioCommandThread() adding set port config delay %d", delayMs);
    return sendCommand(command, delayMs);
}

void AudioPolicyService::AudioCommandThread::dynamicPolicyMixStateUpdateCommand(
        const String8& regId, int32_t state)
{
    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = DYN_POLICY_MIX_STATE_UPDATE;
    DynPolicyMixStateUpdateData *data = new DynPolicyMixStateUpdateData();
    data->mRegId = regId;
    data->mState = state;
    command->mParam = data;
    ALOGV("AudioCommandThread() sending dynamic policy mix (id=%s) state update to %d",
            regId.c_str(), state);
    sendCommand(command);
}

void AudioPolicyService::AudioCommandThread::recordingConfigurationUpdateCommand(
                                                int event,
                                                const record_client_info_t *clientInfo,
                                                const audio_config_base_t *clientConfig,
                                                std::vector<effect_descriptor_t> clientEffects,
                                                const audio_config_base_t *deviceConfig,
                                                std::vector<effect_descriptor_t> effects,
                                                audio_patch_handle_t patchHandle,
                                                audio_source_t source)
{
    sp<AudioCommand>command = new AudioCommand();
    command->mCommand = RECORDING_CONFIGURATION_UPDATE;
    RecordingConfigurationUpdateData *data = new RecordingConfigurationUpdateData();
    data->mEvent = event;
    data->mClientInfo = *clientInfo;
    data->mClientConfig = *clientConfig;
    data->mClientEffects = clientEffects;
    data->mDeviceConfig = *deviceConfig;
    data->mEffects = effects;
    data->mPatchHandle = patchHandle;
    data->mSource = source;
    command->mParam = data;
    ALOGV("AudioCommandThread() adding recording configuration update event %d, source %d uid %u",
            event, clientInfo->source, clientInfo->uid);
    sendCommand(command);
}

void AudioPolicyService::AudioCommandThread::audioModulesUpdateCommand()
{
    sp<AudioCommand> command = new AudioCommand();
    command->mCommand = AUDIO_MODULES_UPDATE;
    sendCommand(command);
}

void AudioPolicyService::AudioCommandThread::routingChangedCommand()
{
    sp<AudioCommand>command = new AudioCommand();
    command->mCommand = ROUTING_UPDATED;
    ALOGV("AudioCommandThread() adding routing update");
    sendCommand(command);
}

void AudioPolicyService::AudioCommandThread::checkSpatializerCommand()
{
    sp<AudioCommand>command = new AudioCommand();
    command->mCommand = CHECK_SPATIALIZER_OUTPUT;
    ALOGV("AudioCommandThread() adding check spatializer");
    sendCommand(command);
}

void AudioPolicyService::AudioCommandThread::updateActiveSpatializerTracksCommand()
{
    sp<AudioCommand>command = new AudioCommand();
    command->mCommand = UPDATE_ACTIVE_SPATIALIZER_TRACKS;
    ALOGV("AudioCommandThread() adding update active spatializer tracks");
    sendCommand(command);
}

void AudioPolicyService::AudioCommandThread::volRangeInitReqCommand()
{
    sp<AudioCommand>command = new AudioCommand();
    command->mCommand = VOL_RANGE_INIT_REQUEST;
    ALOGV("AudioCommandThread() adding volume range init request");
    sendCommand(command);
}

status_t AudioPolicyService::AudioCommandThread::sendCommand(sp<AudioCommand>& command, int delayMs)
{
    {
        audio_utils::lock_guard _l(mMutex);
        insertCommand_l(command, delayMs);
        mWaitWorkCV.notify_one();
    }
    audio_utils::unique_lock ul(command->mMutex);
    while (command->mWaitStatus) {
        nsecs_t timeOutNs = kAudioCommandTimeoutNs + milliseconds(delayMs);
        if (command->mCond.wait_for(
                ul, std::chrono::nanoseconds(timeOutNs), getTid()) == std::cv_status::timeout) {
            command->mStatus = TIMED_OUT;
            command->mWaitStatus = false;
        }
    }
    return command->mStatus;
}

// insertCommand_l() must be called with mMutex held
void AudioPolicyService::AudioCommandThread::insertCommand_l(sp<AudioCommand>& command, int delayMs)
{
    ssize_t i;  // not size_t because i will count down to -1
    Vector < sp<AudioCommand> > removedCommands;
    command->mTime = systemTime() + milliseconds(delayMs);

    // acquire wake lock to make sure delayed commands are processed
    if (mAudioCommands.isEmpty()) {
        acquire_wake_lock(PARTIAL_WAKE_LOCK, mName.c_str());
    }

    // check same pending commands with later time stamps and eliminate them
    for (i = (ssize_t)mAudioCommands.size()-1; i >= 0; i--) {
        sp<AudioCommand> command2 = mAudioCommands[i];
        // commands are sorted by increasing time stamp: no need to scan the rest of mAudioCommands
        if (command2->mTime <= command->mTime) break;

        // create audio patch or release audio patch commands are equivalent
        // with regard to filtering
        if ((command->mCommand == CREATE_AUDIO_PATCH) ||
                (command->mCommand == RELEASE_AUDIO_PATCH)) {
            if ((command2->mCommand != CREATE_AUDIO_PATCH) &&
                    (command2->mCommand != RELEASE_AUDIO_PATCH)) {
                continue;
            }
        } else if (command2->mCommand != command->mCommand) continue;

        switch (command->mCommand) {
        case SET_PARAMETERS: {
            ParametersData *data = (ParametersData *)command->mParam.get();
            ParametersData *data2 = (ParametersData *)command2->mParam.get();
            if (data->mIO != data2->mIO) break;
            ALOGV("Comparing parameter command %s to new command %s",
                    data2->mKeyValuePairs.c_str(), data->mKeyValuePairs.c_str());
            AudioParameter param = AudioParameter(data->mKeyValuePairs);
            AudioParameter param2 = AudioParameter(data2->mKeyValuePairs);
            for (size_t j = 0; j < param.size(); j++) {
                String8 key;
                String8 value;
                param.getAt(j, key, value);
                for (size_t k = 0; k < param2.size(); k++) {
                    String8 key2;
                    String8 value2;
                    param2.getAt(k, key2, value2);
                    if (key2 == key) {
                        param2.remove(key2);
                        ALOGV("Filtering out parameter %s", key2.c_str());
                        break;
                    }
                }
            }
            // if all keys have been filtered out, remove the command.
            // otherwise, update the key value pairs
            if (param2.size() == 0) {
                removedCommands.add(command2);
            } else {
                data2->mKeyValuePairs = param2.toString();
            }
            command->mTime = command2->mTime;
            // force delayMs to non 0 so that code below does not request to wait for
            // command status as the command is now delayed
            delayMs = 1;
        } break;

        case SET_VOLUME: {
            VolumeData *data = (VolumeData *)command->mParam.get();
            VolumeData *data2 = (VolumeData *)command2->mParam.get();
            if (data->mIO != data2->mIO) break;
            if (data->mStream != data2->mStream) break;
            ALOGV("Filtering out volume command on output %d for stream %d",
                    data->mIO, data->mStream);
            removedCommands.add(command2);
            command->mTime = command2->mTime;
            // force delayMs to non 0 so that code below does not request to wait for
            // command status as the command is now delayed
            delayMs = 1;
        } break;

        case SET_VOICE_VOLUME: {
            VoiceVolumeData *data = (VoiceVolumeData *)command->mParam.get();
            VoiceVolumeData *data2 = (VoiceVolumeData *)command2->mParam.get();
            ALOGV("Filtering out voice volume command value %f replaced by %f",
                  data2->mVolume, data->mVolume);
            removedCommands.add(command2);
            command->mTime = command2->mTime;
            // force delayMs to non 0 so that code below does not request to wait for
            // command status as the command is now delayed
            delayMs = 1;
        } break;

        case CREATE_AUDIO_PATCH:
        case RELEASE_AUDIO_PATCH: {
            audio_patch_handle_t handle;
            struct audio_patch patch;
            if (command->mCommand == CREATE_AUDIO_PATCH) {
                handle = ((CreateAudioPatchData *)command->mParam.get())->mHandle;
                patch = ((CreateAudioPatchData *)command->mParam.get())->mPatch;
            } else {
                handle = ((ReleaseAudioPatchData *)command->mParam.get())->mHandle;
                memset(&patch, 0, sizeof(patch));
            }
            audio_patch_handle_t handle2;
            struct audio_patch patch2;
            if (command2->mCommand == CREATE_AUDIO_PATCH) {
                handle2 = ((CreateAudioPatchData *)command2->mParam.get())->mHandle;
                patch2 = ((CreateAudioPatchData *)command2->mParam.get())->mPatch;
            } else {
                handle2 = ((ReleaseAudioPatchData *)command2->mParam.get())->mHandle;
                memset(&patch2, 0, sizeof(patch2));
            }
            if (handle != handle2) break;
            /* Filter CREATE_AUDIO_PATCH commands only when they are issued for
               same output. */
            if( (command->mCommand == CREATE_AUDIO_PATCH) &&
                (command2->mCommand == CREATE_AUDIO_PATCH) ) {
                bool isOutputDiff = false;
                if (patch.num_sources == patch2.num_sources) {
                    for (unsigned count = 0; count < patch.num_sources; count++) {
                        if (patch.sources[count].id != patch2.sources[count].id) {
                            isOutputDiff = true;
                            break;
                        }
                    }
                    if (isOutputDiff)
                       break;
                }
            }
            ALOGV("Filtering out %s audio patch command for handle %d",
                  (command->mCommand == CREATE_AUDIO_PATCH) ? "create" : "release", handle);
            removedCommands.add(command2);
            command->mTime = command2->mTime;
            // force delayMs to non 0 so that code below does not request to wait for
            // command status as the command is now delayed
            delayMs = 1;
        } break;

        case DYN_POLICY_MIX_STATE_UPDATE: {

        } break;

        case RECORDING_CONFIGURATION_UPDATE: {

        } break;

        case ROUTING_UPDATED: {

        } break;

        case VOL_RANGE_INIT_REQUEST: {
            // command may come from different requests, do not filter
        } break;

        default:
            break;
        }
    }

    // remove filtered commands
    for (size_t j = 0; j < removedCommands.size(); j++) {
        // removed commands always have time stamps greater than current command
        for (size_t k = i + 1; k < mAudioCommands.size(); k++) {
            if (mAudioCommands[k].get() == removedCommands[j].get()) {
                ALOGV("suppressing command: %d", mAudioCommands[k]->mCommand);
                mAudioCommands.removeAt(k);
                break;
            }
        }
    }
    removedCommands.clear();

    // Disable wait for status if delay is not 0.
    // Except for create audio patch command because the returned patch handle
    // is needed by audio policy manager
    if (delayMs != 0 && command->mCommand != CREATE_AUDIO_PATCH) {
        command->mWaitStatus = false;
    }

    // insert command at the right place according to its time stamp
    ALOGV("inserting command: %d at index %zd, num commands %zu",
            command->mCommand, i+1, mAudioCommands.size());
    mAudioCommands.insertAt(command, i + 1);
}

void AudioPolicyService::AudioCommandThread::exit()
{
    ALOGV("AudioCommandThread::exit");
    {
        audio_utils::lock_guard _l(mMutex);
        requestExit();
        mWaitWorkCV.notify_one();
    }
    // Note that we can call it from the thread loop if all other references have been released
    // but it will safely return WOULD_BLOCK in this case
    requestExitAndWait();
}

void AudioPolicyService::AudioCommandThread::AudioCommand::dump(char* buffer, size_t size)
{
    snprintf(buffer, size, "   %02d      %06d.%03d  %01u    %p\n",
            mCommand,
            (int)ns2s(mTime),
            (int)ns2ms(mTime)%1000,
            mWaitStatus,
            mParam.get());
}

/******* helpers for the service_ops callbacks defined below *********/
void AudioPolicyService::setParameters(audio_io_handle_t ioHandle,
                                       const char *keyValuePairs,
                                       int delayMs)
{
    mAudioCommandThread->parametersCommand(ioHandle, keyValuePairs,
                                           delayMs);
}

int AudioPolicyService::setStreamVolume(audio_stream_type_t stream,
                                        float volume,
                                        audio_io_handle_t output,
                                        int delayMs)
{
    return (int)mAudioCommandThread->volumeCommand(stream, volume,
                                                   output, delayMs);
}

int AudioPolicyService::setVoiceVolume(float volume, int delayMs)
{
    return (int)mAudioCommandThread->voiceVolumeCommand(volume, delayMs);
}

void AudioPolicyService::setEffectSuspended(int effectId,
                                            audio_session_t sessionId,
                                            bool suspended)
{
    mAudioCommandThread->setEffectSuspendedCommand(effectId, sessionId, suspended);
}

Status AudioPolicyService::onNewAudioModulesAvailable()
{
    mOutputCommandThread->audioModulesUpdateCommand();
    return Status::ok();
}


extern "C" {
audio_module_handle_t aps_load_hw_module(void *service __unused,
                                             const char *name);
audio_io_handle_t aps_open_output(void *service __unused,
                                         audio_devices_t *pDevices,
                                         uint32_t *pSamplingRate,
                                         audio_format_t *pFormat,
                                         audio_channel_mask_t *pChannelMask,
                                         uint32_t *pLatencyMs,
                                         audio_output_flags_t flags);

audio_io_handle_t aps_open_output_on_module(void *service __unused,
                                                   audio_module_handle_t module,
                                                   audio_devices_t *pDevices,
                                                   uint32_t *pSamplingRate,
                                                   audio_format_t *pFormat,
                                                   audio_channel_mask_t *pChannelMask,
                                                   uint32_t *pLatencyMs,
                                                   audio_output_flags_t flags,
                                                   const audio_offload_info_t *offloadInfo);
audio_io_handle_t aps_open_dup_output(void *service __unused,
                                                 audio_io_handle_t output1,
                                                 audio_io_handle_t output2);
int aps_close_output(void *service __unused, audio_io_handle_t output);
int aps_suspend_output(void *service __unused, audio_io_handle_t output);
int aps_restore_output(void *service __unused, audio_io_handle_t output);
audio_io_handle_t aps_open_input(void *service __unused,
                                        audio_devices_t *pDevices,
                                        uint32_t *pSamplingRate,
                                        audio_format_t *pFormat,
                                        audio_channel_mask_t *pChannelMask,
                                        audio_in_acoustics_t acoustics __unused);
audio_io_handle_t aps_open_input_on_module(void *service __unused,
                                                  audio_module_handle_t module,
                                                  audio_devices_t *pDevices,
                                                  uint32_t *pSamplingRate,
                                                  audio_format_t *pFormat,
                                                  audio_channel_mask_t *pChannelMask);
int aps_close_input(void *service __unused, audio_io_handle_t input);
int aps_invalidate_stream(void *service __unused, audio_stream_type_t stream);
int aps_move_effects(void *service __unused, audio_session_t session,
                                audio_io_handle_t src_output,
                                audio_io_handle_t dst_output);
char * aps_get_parameters(void *service __unused, audio_io_handle_t io_handle,
                                     const char *keys);
void aps_set_parameters(void *service, audio_io_handle_t io_handle,
                                   const char *kv_pairs, int delay_ms);
int aps_set_stream_volume(void *service, audio_stream_type_t stream,
                                     float volume, audio_io_handle_t output,
                                     int delay_ms);
int aps_set_voice_volume(void *service, float volume, int delay_ms);
};

} // namespace android
