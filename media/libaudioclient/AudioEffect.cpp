/*
**
** Copyright 2010, The Android Open Source Project
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


//#define LOG_NDEBUG 0
#define LOG_TAG "AudioEffect"

#include <stdint.h>
#include <sys/types.h>
#include <limits.h>

#include <android/media/IAudioPolicyService.h>
#include <binder/IPCThreadState.h>
#include <media/AidlConversion.h>
#include <media/AudioEffect.h>
#include <media/PolicyAidlConversion.h>
#include <media/ShmemCompat.h>
#include <private/media/AudioEffectShared.h>
#include <utils/Log.h>

namespace android {
using aidl_utils::statusTFromBinderStatus;
using binder::Status;
using media::IAudioPolicyService;
using media::audio::common::AudioSource;
using media::audio::common::AudioUuid;

namespace {

// Copy from a raw pointer + size into a vector of bytes.
void appendToBuffer(const void* data,
                    size_t size,
                    std::vector<uint8_t>* buffer) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
    buffer->insert(buffer->end(), p, p + size);
}

}  // namespace

// ---------------------------------------------------------------------------

AudioEffect::AudioEffect(const android::content::AttributionSourceState& attributionSource)
    : mClientAttributionSource(attributionSource)
{
}

status_t AudioEffect::set(const effect_uuid_t *type,
                const effect_uuid_t *uuid,
                int32_t priority,
                const wp<IAudioEffectCallback>& callback,
                audio_session_t sessionId,
                audio_io_handle_t io,
                const AudioDeviceTypeAddr& device,
                bool probe,
                bool notifyFramesProcessed)
{
    sp<media::IEffect> iEffect;
    sp<IMemory> cblk;
    int enabled;

    ALOGV("set %p uuid: %p timeLow %08x", this, type, type ? type->timeLow : 0);

    if (mIEffect != 0) {
        ALOGW("Effect already in use");
        return INVALID_OPERATION;
    }

    if (sessionId == AUDIO_SESSION_DEVICE && io != AUDIO_IO_HANDLE_NONE) {
        ALOGW("IO handle should not be specified for device effect");
        return BAD_VALUE;
    }
    const sp<IAudioFlinger>& audioFlinger = AudioSystem::get_audio_flinger();
    if (audioFlinger == 0) {
        ALOGE("set(): Could not get audioflinger");
        return NO_INIT;
    }

    if (type == nullptr && uuid == nullptr) {
        ALOGW("Must specify at least type or uuid");
        return BAD_VALUE;
    }
    mProbe = probe;
    mPriority = priority;
    mSessionId = sessionId;
    mCallback = callback;

    memset(&mDescriptor, 0, sizeof(effect_descriptor_t));
    mDescriptor.type = *(type != nullptr ? type : EFFECT_UUID_NULL);
    mDescriptor.uuid = *(uuid != nullptr ? uuid : EFFECT_UUID_NULL);

    // TODO b/182392769: use attribution source util
    mIEffectClient = new EffectClient(this);
    pid_t pid = IPCThreadState::self()->getCallingPid();
    mClientAttributionSource.pid = VALUE_OR_RETURN_STATUS(legacy2aidl_pid_t_int32_t(pid));
    pid_t uid = IPCThreadState::self()->getCallingUid();
    mClientAttributionSource.uid = VALUE_OR_RETURN_STATUS(legacy2aidl_uid_t_int32_t(uid));

    media::CreateEffectRequest request;
    request.desc = VALUE_OR_RETURN_STATUS(
            legacy2aidl_effect_descriptor_t_EffectDescriptor(mDescriptor));
    request.client = mIEffectClient;
    request.priority = priority;
    request.output = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_io_handle_t_int32_t(io));
    request.sessionId = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_session_t_int32_t(mSessionId));
    request.device = VALUE_OR_RETURN_STATUS(legacy2aidl_AudioDeviceTypeAddress(device));
    request.attributionSource = mClientAttributionSource;
    request.probe = probe;
    request.notifyFramesProcessed = notifyFramesProcessed;

    media::CreateEffectResponse response;

    mStatus = audioFlinger->createEffect(request, &response);

    if (mStatus == OK) {
        if (response.alreadyExists) {
            mStatus = ALREADY_EXISTS;
        }
        mId = response.id;
        enabled = response.enabled;
        iEffect = response.effect;
        mDescriptor = VALUE_OR_RETURN_STATUS(
                aidl2legacy_EffectDescriptor_effect_descriptor_t(response.desc));
    }

    // In probe mode, we stop here and return the status: the IEffect interface to
    // audio flinger will not be retained. initCheck() will return the creation status
    // but all other APIs will return invalid operation.
    if (probe || iEffect == 0 || (mStatus != NO_ERROR && mStatus != ALREADY_EXISTS)) {
        char typeBuffer[64] = {}, uuidBuffer[64] = {};
        guidToString(type, typeBuffer, sizeof(typeBuffer));
        guidToString(uuid, uuidBuffer, sizeof(uuidBuffer));
        ALOGE_IF(!probe, "set(): AudioFlinger could not create effect %s / %s, status: %d",
                type != nullptr ? typeBuffer : "NULL",
                uuid != nullptr ? uuidBuffer : "NULL",
                mStatus);
        if (!probe && iEffect == 0) {
            mStatus = NO_INIT;
        }
        return mStatus;
    }

    mEnabled = (volatile int32_t)enabled;

    if (media::SharedFileRegion shmem;
            !iEffect->getCblk(&shmem).isOk()
            || !convertSharedFileRegionToIMemory(shmem, &cblk)
            || cblk == 0) {
        mStatus = NO_INIT;
        ALOGE("Could not get control block");
        return mStatus;
    }

    mIEffect = iEffect;
    mCblkMemory = cblk;
    // TODO: Using unsecurePointer() has some associated security pitfalls
    //       (see declaration for details).
    //       Either document why it is safe in this case or address the
    //       issue (e.g. by copying).
    mCblk = static_cast<effect_param_cblk_t*>(cblk->unsecurePointer());
    int bufOffset = ((sizeof(effect_param_cblk_t) - 1) / sizeof(int) + 1) * sizeof(int);
    mCblk->buffer = (uint8_t *)mCblk + bufOffset;

    IInterface::asBinder(iEffect)->linkToDeath(mIEffectClient);
    ALOGV("set() %p OK effect: %s id: %d status %d enabled %d pid %d", this, mDescriptor.name, mId,
            mStatus, mEnabled, mClientAttributionSource.pid);

    if (!audio_is_global_session(mSessionId)) {
        AudioSystem::acquireAudioSessionId(mSessionId, pid, uid);
    }

    return mStatus;
}

namespace {
class LegacyCallbackWrapper : public AudioEffect::IAudioEffectCallback {
 public:
    LegacyCallbackWrapper(AudioEffect::legacy_callback_t callback, void* user):
            mCallback(callback), mUser(user) {}
 private:
    void onControlStatusChanged(bool isGranted) override {
        mCallback(AudioEffect::EVENT_CONTROL_STATUS_CHANGED, mUser, &isGranted);
    }

    void onEnableStatusChanged(bool isEnabled) override {
        mCallback(AudioEffect::EVENT_ENABLE_STATUS_CHANGED, mUser, &isEnabled);
    }

    void onParameterChanged(std::vector<uint8_t> param) override {
        mCallback(AudioEffect::EVENT_PARAMETER_CHANGED, mUser, param.data());
    }

    void onError(status_t errorCode) override {
        mCallback(AudioEffect::EVENT_ERROR, mUser, &errorCode);
    }

    void onFramesProcessed(int32_t framesProcessed) override {
        mCallback(AudioEffect::EVENT_FRAMES_PROCESSED, mUser, &framesProcessed);
    }

    const AudioEffect::legacy_callback_t mCallback;
    void* const mUser;
};
} // namespace

status_t AudioEffect::set(const effect_uuid_t *type,
                const effect_uuid_t *uuid,
                int32_t priority,
                legacy_callback_t cbf,
                void* user,
                audio_session_t sessionId,
                audio_io_handle_t io,
                const AudioDeviceTypeAddr& device,
                bool probe,
                bool notifyFramesProcessed)
{
    if (cbf != nullptr) {
        mLegacyWrapper = sp<LegacyCallbackWrapper>::make(cbf, user);
    } else if (user != nullptr) {
        LOG_ALWAYS_FATAL("%s: User provided without callback", __func__);
    }
    return set(type, uuid, priority, mLegacyWrapper, sessionId, io, device, probe,
               notifyFramesProcessed);
}
status_t AudioEffect::set(const char *typeStr,
                const char *uuidStr,
                int32_t priority,
                const wp<IAudioEffectCallback>& callback,
                audio_session_t sessionId,
                audio_io_handle_t io,
                const AudioDeviceTypeAddr& device,
                bool probe,
                bool notifyFramesProcessed)
{
    effect_uuid_t type;
    effect_uuid_t *pType = nullptr;
    effect_uuid_t uuid;
    effect_uuid_t *pUuid = nullptr;

    ALOGV("AudioEffect::set string\n - type: %s\n - uuid: %s",
            typeStr ? typeStr : "nullptr", uuidStr ? uuidStr : "nullptr");

    if (stringToGuid(typeStr, &type) == NO_ERROR) {
        pType = &type;
    }
    if (stringToGuid(uuidStr, &uuid) == NO_ERROR) {
        pUuid = &uuid;
    }

    return set(pType, pUuid, priority, callback, sessionId, io,
               device, probe, notifyFramesProcessed);
}

status_t AudioEffect::set(const char *typeStr,
                const char *uuidStr,
                int32_t priority,
                legacy_callback_t cbf,
                void* user,
                audio_session_t sessionId,
                audio_io_handle_t io,
                const AudioDeviceTypeAddr& device,
                bool probe,
                bool notifyFramesProcessed)
{
    if (cbf != nullptr) {
        mLegacyWrapper = sp<LegacyCallbackWrapper>::make(cbf, user);
    } else if (user != nullptr) {
        LOG_ALWAYS_FATAL("%s: User provided without callback", __func__);
    }
    return set(typeStr, uuidStr, priority, mLegacyWrapper, sessionId, io, device, probe,
               notifyFramesProcessed);
}
AudioEffect::~AudioEffect()
{
    ALOGV("Destructor %p", this);

    if (!mProbe && (mStatus == NO_ERROR || mStatus == ALREADY_EXISTS)) {
        if (!audio_is_global_session(mSessionId)) {
            AudioSystem::releaseAudioSessionId(mSessionId,
                VALUE_OR_FATAL(aidl2legacy_int32_t_pid_t(mClientAttributionSource.pid)));
        }
        if (mIEffect != nullptr) {
            mIEffect->disconnect();
            IInterface::asBinder(mIEffect)->unlinkToDeath(mIEffectClient);
        }
        mIEffect.clear();
        mCblkMemory.clear();
    }
    mIEffectClient.clear();
    IPCThreadState::self()->flushCommands();
}


status_t AudioEffect::initCheck() const
{
    return mStatus;
}

// -------------------------------------------------------------------------

effect_descriptor_t AudioEffect::descriptor() const
{
    return mDescriptor;
}

bool AudioEffect::getEnabled() const
{
    return (mEnabled != 0);
}

status_t AudioEffect::setEnabled(bool enabled)
{
    if (mProbe) {
        return INVALID_OPERATION;
    }
    if (mStatus != NO_ERROR) {
        return (mStatus == ALREADY_EXISTS) ? (status_t) INVALID_OPERATION : mStatus;
    }

    status_t status = NO_ERROR;
    AutoMutex lock(mLock);
    if (enabled != mEnabled) {
        Status bs;

        if (enabled) {
            ALOGV("enable %p", this);
            bs = mIEffect->enable(&status);
        } else {
            ALOGV("disable %p", this);
            bs = mIEffect->disable(&status);
        }
        if (!bs.isOk()) {
            status = statusTFromBinderStatus(bs);
        }
        if (status == NO_ERROR) {
            mEnabled = enabled;
        }
    }
    return status;
}

status_t AudioEffect::command(uint32_t cmdCode,
                              uint32_t cmdSize,
                              void *cmdData,
                              uint32_t *replySize,
                              void *replyData)
{
    if (mProbe) {
        return INVALID_OPERATION;
    }
    if (mStatus != NO_ERROR && mStatus != ALREADY_EXISTS) {
        ALOGV("command() bad status %d", mStatus);
        return mStatus;
    }

    std::unique_lock ul(mLock, std::defer_lock);
    if (cmdCode == EFFECT_CMD_ENABLE || cmdCode == EFFECT_CMD_DISABLE) {
        ul.lock();
        if (mEnabled == (cmdCode == EFFECT_CMD_ENABLE)) {
            return NO_ERROR;
        }
        if (replySize == nullptr || *replySize != sizeof(status_t) || replyData == nullptr) {
            return BAD_VALUE;
        }
    }

    std::vector<uint8_t> data;
    appendToBuffer(cmdData, cmdSize, &data);

    status_t status;
    std::vector<uint8_t> response;

    Status bs = mIEffect->command(cmdCode, data, *replySize, &response, &status);
    if (!bs.isOk()) {
        status = statusTFromBinderStatus(bs);
    }
    if (status == NO_ERROR) {
        memcpy(replyData, response.data(), response.size());
        *replySize = response.size();
    }

    if (cmdCode == EFFECT_CMD_ENABLE || cmdCode == EFFECT_CMD_DISABLE) {
        if (status == NO_ERROR) {
            status = *(status_t *)replyData;
        }
        if (status == NO_ERROR) {
            mEnabled = (cmdCode == EFFECT_CMD_ENABLE);
        }
    }

    return status;
}

status_t AudioEffect::setParameter(effect_param_t *param)
{
    if (mProbe) {
        return INVALID_OPERATION;
    }
    if (mStatus != NO_ERROR) {
        return (mStatus == ALREADY_EXISTS) ? (status_t) INVALID_OPERATION : mStatus;
    }

    if (param == nullptr || param->psize == 0 || param->vsize == 0) {
        return BAD_VALUE;
    }

    uint32_t psize = ((param->psize - 1) / sizeof(int) + 1) * sizeof(int) + param->vsize;

    ALOGV("setParameter: param: %d, param2: %d", *(int *)param->data,
            (param->psize == 8) ? *((int *)param->data + 1): -1);

    std::vector<uint8_t> cmd;
    appendToBuffer(param, sizeof(effect_param_t) + psize, &cmd);
    std::vector<uint8_t> response;
    status_t status;
    Status bs = mIEffect->command(EFFECT_CMD_SET_PARAM,
                                  cmd,
                                  sizeof(int),
                                  &response,
                                  &status);
    if (!bs.isOk()) {
        status = statusTFromBinderStatus(bs);
        return status;
    }
    assert(response.size() == sizeof(int));
    memcpy(&param->status, response.data(), response.size());
    return status;
}

status_t AudioEffect::setParameterDeferred(effect_param_t *param)
{
    if (mProbe) {
        return INVALID_OPERATION;
    }
    if (mStatus != NO_ERROR) {
        return (mStatus == ALREADY_EXISTS) ? (status_t) INVALID_OPERATION : mStatus;
    }
    if (param == nullptr || param->psize == 0 || param->vsize == 0) {
        return BAD_VALUE;
    }

    Mutex::Autolock _l(mCblk->lock);

    int psize = ((param->psize - 1) / sizeof(int) + 1) * sizeof(int) + param->vsize;
    int size = ((sizeof(effect_param_t) + psize - 1) / sizeof(int) + 1) * sizeof(int);

    if (mCblk->clientIndex + size > EFFECT_PARAM_BUFFER_SIZE) {
        return NO_MEMORY;
    }
    int *p = (int *)(mCblk->buffer + mCblk->clientIndex);
    *p++ = size;
    memcpy(p, param, sizeof(effect_param_t) + psize);
    mCblk->clientIndex += size;

    return NO_ERROR;
}

status_t AudioEffect::setParameterCommit()
{
    if (mProbe) {
        return INVALID_OPERATION;
    }
    if (mStatus != NO_ERROR) {
        return (mStatus == ALREADY_EXISTS) ? (status_t) INVALID_OPERATION : mStatus;
    }

    Mutex::Autolock _l(mCblk->lock);
    if (mCblk->clientIndex == 0) {
        return INVALID_OPERATION;
    }
    std::vector<uint8_t> cmd;
    std::vector<uint8_t> response;
    status_t status;
    Status bs = mIEffect->command(EFFECT_CMD_SET_PARAM_COMMIT,
                                  cmd,
                                  0,
                                  &response,
                                  &status);
    if (!bs.isOk()) {
        status = statusTFromBinderStatus(bs);
    }
    return status;
}

status_t AudioEffect::getParameter(effect_param_t *param)
{
    if (mProbe) {
        return INVALID_OPERATION;
    }
    if (mStatus != NO_ERROR && mStatus != ALREADY_EXISTS) {
        return mStatus;
    }
    if (param == nullptr || param->psize == 0 || param->vsize == 0) {
        return BAD_VALUE;
    }

    ALOGV("getParameter: param: %d, param2: %d", *(int *)param->data,
            (param->psize == 8) ? *((int *)param->data + 1): -1);

    uint32_t psize = sizeof(effect_param_t) + ((param->psize - 1) / sizeof(int) + 1) * sizeof(int) +
            param->vsize;

    status_t status;
    std::vector<uint8_t> cmd;
    std::vector<uint8_t> response;
    appendToBuffer(param, sizeof(effect_param_t) + param->psize, &cmd);

    Status bs = mIEffect->command(EFFECT_CMD_GET_PARAM, cmd, psize, &response, &status);
    if (!bs.isOk()) {
        status = statusTFromBinderStatus(bs);
        return status;
    }
    memcpy(param, response.data(), response.size());
    return status;
}

status_t AudioEffect::getConfigs(
        audio_config_base_t *inputCfg, audio_config_base_t *outputCfg)
{
    if (mProbe) {
        return INVALID_OPERATION;
    }
    if (mStatus != NO_ERROR && mStatus != ALREADY_EXISTS) {
        return mStatus;
    }
    if (inputCfg == NULL || outputCfg == NULL) {
        return BAD_VALUE;
    }
    status_t status;
    media::EffectConfig cfg;
    Status bs = mIEffect->getConfig(&cfg, &status);
    if (!bs.isOk()) {
        status = statusTFromBinderStatus(bs);
        ALOGW("%s received status %d from binder transaction", __func__, status);
        return status;
    }
    if (status == NO_ERROR) {
        *inputCfg = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioConfigBase_audio_config_base_t(
                        cfg.inputCfg, cfg.isOnInputStream));
        *outputCfg = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioConfigBase_audio_config_base_t(
                        cfg.outputCfg, cfg.isOnInputStream));
    } else {
        ALOGW("%s received status %d from the effect", __func__, status);
    }
    return status;
}

// -------------------------------------------------------------------------

void AudioEffect::binderDied()
{
    ALOGW("IEffect died");
    mStatus = DEAD_OBJECT;
    auto cb = mCallback.promote();
    if (cb != nullptr) {
        cb->onError(mStatus);
    }
}

// -------------------------------------------------------------------------

void AudioEffect::controlStatusChanged(bool controlGranted)
{
    auto cb = mCallback.promote();
    ALOGV("controlStatusChanged %p control %d callback %p", this, controlGranted, cb.get());
    if (controlGranted) {
        if (mStatus == ALREADY_EXISTS) {
            mStatus = NO_ERROR;
        }
    } else {
        if (mStatus == NO_ERROR) {
            mStatus = ALREADY_EXISTS;
        }
    }
    if (cb != nullptr) {
        cb->onControlStatusChanged(controlGranted);
    }
}

void AudioEffect::enableStatusChanged(bool enabled)
{
    auto cb = mCallback.promote();
    ALOGV("enableStatusChanged %p enabled %d mCallback %p", this, enabled, cb.get());
    if (mStatus == ALREADY_EXISTS) {
        mEnabled = enabled;
        if (cb != nullptr) {
            cb->onEnableStatusChanged(enabled);
        }
    }
}

void AudioEffect::commandExecuted(int32_t cmdCode,
                                  const std::vector<uint8_t>& cmdData,
                                  const std::vector<uint8_t>& replyData)
{
    if (cmdData.empty() || replyData.empty()) {
        return;
    }
    auto cb = mCallback.promote();
    if (cb != nullptr && cmdCode == EFFECT_CMD_SET_PARAM) {
        std::vector<uint8_t> cmdDataCopy(cmdData);
        effect_param_t* cmd = reinterpret_cast<effect_param_t *>(cmdDataCopy.data());
        cmd->status = *reinterpret_cast<const int32_t *>(replyData.data());
        cb->onParameterChanged(std::move(cmdDataCopy));
    }
}

void AudioEffect::framesProcessed(int32_t frames)
{
    auto cb = mCallback.promote();
    if (cb != nullptr) {
        cb->onFramesProcessed(frames);
    }
}

// -------------------------------------------------------------------------

status_t AudioEffect::queryNumberEffects(uint32_t *numEffects)
{
    if (numEffects == nullptr) {
        return BAD_VALUE;
    }
    const sp<IAudioFlinger>& af = AudioSystem::get_audio_flinger();
    if (af == 0) return PERMISSION_DENIED;
    return af->queryNumberEffects(numEffects);
}

status_t AudioEffect::queryEffect(uint32_t index, effect_descriptor_t *descriptor)
{
    if (descriptor == nullptr) {
        return BAD_VALUE;
    }
    const sp<IAudioFlinger>& af = AudioSystem::get_audio_flinger();
    if (af == 0) return PERMISSION_DENIED;
    return af->queryEffect(index, descriptor);
}

status_t AudioEffect::getEffectDescriptor(const effect_uuid_t *uuid,
                                          const effect_uuid_t *type,
                                          uint32_t preferredTypeFlag,
                                          effect_descriptor_t *descriptor)
{
    if (uuid == nullptr || type == nullptr || descriptor == nullptr) {
        return BAD_VALUE;
    }
    const sp<IAudioFlinger>& af = AudioSystem::get_audio_flinger();
    if (af == 0) return PERMISSION_DENIED;
    return af->getEffectDescriptor(uuid, type, preferredTypeFlag, descriptor);
}

status_t AudioEffect::queryDefaultPreProcessing(audio_session_t audioSession,
                                          effect_descriptor_t *descriptors,
                                          uint32_t *count)
{
    if (descriptors == nullptr || count == nullptr) {
        return BAD_VALUE;
    }
    const sp<IAudioPolicyService>& aps = AudioSystem::get_audio_policy_service();
    if (aps == 0) return PERMISSION_DENIED;

    int32_t audioSessionAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_session_t_int32_t(audioSession));
    media::audio::common::Int countAidl;
    countAidl.value = VALUE_OR_RETURN_STATUS(convertIntegral<int32_t>(*count));
    std::vector<media::EffectDescriptor> retAidl;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            aps->queryDefaultPreProcessing(audioSessionAidl, &countAidl, &retAidl)));
    *count = VALUE_OR_RETURN_STATUS(convertIntegral<uint32_t>(countAidl.value));
    RETURN_STATUS_IF_ERROR(convertRange(retAidl.begin(), retAidl.end(), descriptors,
                                        aidl2legacy_EffectDescriptor_effect_descriptor_t));
    return OK;
}

status_t AudioEffect::newEffectUniqueId(audio_unique_id_t* id)
{
    if (id == nullptr) {
        return BAD_VALUE;
    }
    const sp<IAudioFlinger>& af = AudioSystem::get_audio_flinger();
    if (af == 0) return PERMISSION_DENIED;
    *id = af->newAudioUniqueId(AUDIO_UNIQUE_ID_USE_EFFECT);
    return NO_ERROR;
}

status_t AudioEffect::addSourceDefaultEffect(const char *typeStr,
                                             const String16& opPackageName,
                                             const char *uuidStr,
                                             int32_t priority,
                                             audio_source_t source,
                                             audio_unique_id_t *id)
{
    if ((typeStr == nullptr && uuidStr == nullptr) || id == nullptr) {
        return BAD_VALUE;
    }
    const sp<IAudioPolicyService>& aps = AudioSystem::get_audio_policy_service();
    if (aps == 0) return PERMISSION_DENIED;

    // Convert type & uuid from string to effect_uuid_t.
    effect_uuid_t type;
    if (typeStr != nullptr) {
        status_t res = stringToGuid(typeStr, &type);
        if (res != OK) return res;
    } else {
        type = *EFFECT_UUID_NULL;
    }

    effect_uuid_t uuid;
    if (uuidStr != nullptr) {
        status_t res = stringToGuid(uuidStr, &uuid);
        if (res != OK) return res;
    } else {
        uuid = *EFFECT_UUID_NULL;
    }

    AudioUuid typeAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_uuid_t_AudioUuid(type));
    AudioUuid uuidAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_uuid_t_AudioUuid(uuid));
    std::string opPackageNameAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_String16_string(opPackageName));
    AudioSource sourceAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_source_t_AudioSource(source));
    int32_t retAidl;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            aps->addSourceDefaultEffect(typeAidl, opPackageNameAidl, uuidAidl, priority, sourceAidl,
                                        &retAidl)));
    *id = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_unique_id_t(retAidl));
    return OK;
}

status_t AudioEffect::addStreamDefaultEffect(const char *typeStr,
                                             const String16& opPackageName,
                                             const char *uuidStr,
                                             int32_t priority,
                                             audio_usage_t usage,
                                             audio_unique_id_t *id)
{
    if ((typeStr == nullptr && uuidStr == nullptr) || id == nullptr) {
        return BAD_VALUE;
    }
    const sp<IAudioPolicyService>& aps = AudioSystem::get_audio_policy_service();
    if (aps == 0) return PERMISSION_DENIED;

    // Convert type & uuid from string to effect_uuid_t.
    effect_uuid_t type;
    if (typeStr != nullptr) {
        status_t res = stringToGuid(typeStr, &type);
        if (res != OK) return res;
    } else {
        type = *EFFECT_UUID_NULL;
    }

    effect_uuid_t uuid;
    if (uuidStr != nullptr) {
        status_t res = stringToGuid(uuidStr, &uuid);
        if (res != OK) return res;
    } else {
        uuid = *EFFECT_UUID_NULL;
    }

    AudioUuid typeAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_uuid_t_AudioUuid(type));
    AudioUuid uuidAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_uuid_t_AudioUuid(uuid));
    std::string opPackageNameAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_String16_string(opPackageName));
    media::audio::common::AudioUsage usageAidl = VALUE_OR_RETURN_STATUS(
            legacy2aidl_audio_usage_t_AudioUsage(usage));
    int32_t retAidl;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
            aps->addStreamDefaultEffect(typeAidl, opPackageNameAidl, uuidAidl, priority, usageAidl,
                                        &retAidl)));
    *id = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_unique_id_t(retAidl));
    return OK;
}

status_t AudioEffect::removeSourceDefaultEffect(audio_unique_id_t id)
{
    const sp<IAudioPolicyService>& aps = AudioSystem::get_audio_policy_service();
    if (aps == 0) return PERMISSION_DENIED;

    int32_t idAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_unique_id_t_int32_t(id));
    return statusTFromBinderStatus(aps->removeSourceDefaultEffect(idAidl));
}

status_t AudioEffect::removeStreamDefaultEffect(audio_unique_id_t id)
{
    const sp<IAudioPolicyService>& aps = AudioSystem::get_audio_policy_service();
    if (aps == 0) return PERMISSION_DENIED;

    int32_t idAidl = VALUE_OR_RETURN_STATUS(legacy2aidl_audio_unique_id_t_int32_t(id));
    return statusTFromBinderStatus(aps->removeStreamDefaultEffect(idAidl));
}

// -------------------------------------------------------------------------

status_t AudioEffect::stringToGuid(const char *str, effect_uuid_t *guid)
{
    if (str == nullptr || guid == nullptr) {
        return BAD_VALUE;
    }

    int tmp[10];

    if (sscanf(str, "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
            tmp, tmp+1, tmp+2, tmp+3, tmp+4, tmp+5, tmp+6, tmp+7, tmp+8, tmp+9) < 10) {
        return BAD_VALUE;
    }
    guid->timeLow = (uint32_t)tmp[0];
    guid->timeMid = (uint16_t)tmp[1];
    guid->timeHiAndVersion = (uint16_t)tmp[2];
    guid->clockSeq = (uint16_t)tmp[3];
    guid->node[0] = (uint8_t)tmp[4];
    guid->node[1] = (uint8_t)tmp[5];
    guid->node[2] = (uint8_t)tmp[6];
    guid->node[3] = (uint8_t)tmp[7];
    guid->node[4] = (uint8_t)tmp[8];
    guid->node[5] = (uint8_t)tmp[9];

    return NO_ERROR;
}

status_t AudioEffect::guidToString(const effect_uuid_t *guid, char *str, size_t maxLen)
{
    if (guid == nullptr || str == nullptr) {
        return BAD_VALUE;
    }

    snprintf(str, maxLen, "%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
            guid->timeLow,
            guid->timeMid,
            guid->timeHiAndVersion,
            guid->clockSeq,
            guid->node[0],
            guid->node[1],
            guid->node[2],
            guid->node[3],
            guid->node[4],
            guid->node[5]);

    return NO_ERROR;
}


} // namespace android
