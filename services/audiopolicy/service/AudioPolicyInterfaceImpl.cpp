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

#define LOG_TAG "AudioPolicyIntefaceImpl"
//#define LOG_NDEBUG 0

#include "AudioPolicyService.h"
#include "TypeConverter.h"
#include <media/AidlConversion.h>
#include <media/AudioPolicy.h>
#include <media/AudioValidator.h>
#include <media/MediaMetricsItem.h>
#include <media/PolicyAidlConversion.h>
#include <utils/Log.h>
#include <android/content/AttributionSourceState.h>

#define VALUE_OR_RETURN_BINDER_STATUS(x) \
    ({ auto _tmp = (x); \
       if (!_tmp.ok()) return aidl_utils::binderStatusFromStatusT(_tmp.error()); \
       std::move(_tmp.value()); })

#define RETURN_IF_BINDER_ERROR(x)      \
    {                                  \
        binder::Status _tmp = (x);     \
        if (!_tmp.isOk()) return _tmp; \
    }

#define MAX_ITEMS_PER_LIST 1024

namespace android {
using binder::Status;
using aidl_utils::binderStatusFromStatusT;
using content::AttributionSourceState;

const std::vector<audio_usage_t>& SYSTEM_USAGES = {
    AUDIO_USAGE_CALL_ASSISTANT,
    AUDIO_USAGE_EMERGENCY,
    AUDIO_USAGE_SAFETY,
    AUDIO_USAGE_VEHICLE_STATUS,
    AUDIO_USAGE_ANNOUNCEMENT
};

bool isSystemUsage(audio_usage_t usage) {
    return std::find(std::begin(SYSTEM_USAGES), std::end(SYSTEM_USAGES), usage)
        != std::end(SYSTEM_USAGES);
}

bool AudioPolicyService::isSupportedSystemUsage(audio_usage_t usage) {
    return std::find(std::begin(mSupportedSystemUsages), std::end(mSupportedSystemUsages), usage)
        != std::end(mSupportedSystemUsages);
}

status_t AudioPolicyService::validateUsage(audio_usage_t usage) {
     return validateUsage(usage, getCallingAttributionSource());
}

status_t AudioPolicyService::validateUsage(audio_usage_t usage,
        const AttributionSourceState& attributionSource) {
    if (isSystemUsage(usage)) {
        if (isSupportedSystemUsage(usage)) {
            if (!modifyAudioRoutingAllowed(attributionSource)) {
                ALOGE(("permission denied: modify audio routing not allowed "
                       "for attributionSource %s"), attributionSource.toString().c_str());
                return PERMISSION_DENIED;
            }
        } else {
            return BAD_VALUE;
        }
    }
    return NO_ERROR;
}



// ----------------------------------------------------------------------------

void AudioPolicyService::doOnNewAudioModulesAvailable()
{
    if (mAudioPolicyManager == NULL) return;
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    mAudioPolicyManager->onNewAudioModulesAvailable();
}

Status AudioPolicyService::setDeviceConnectionState(
        const media::AudioDevice& deviceAidl,
        media::AudioPolicyDeviceState stateAidl,
        const std::string& deviceNameAidl,
        media::audio::common::AudioFormat encodedFormatAidl) {
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_devices_t(deviceAidl.type));
    audio_policy_dev_state_t state = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPolicyDeviceState_audio_policy_dev_state_t(stateAidl));
    audio_format_t encodedFormat = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioFormat_audio_format_t(encodedFormatAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!settingsAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (state != AUDIO_POLICY_DEVICE_STATE_AVAILABLE &&
            state != AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE) {
        return binderStatusFromStatusT(BAD_VALUE);
    }

    ALOGV("setDeviceConnectionState()");
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    return binderStatusFromStatusT(
            mAudioPolicyManager->setDeviceConnectionState(device, state,
                                                          deviceAidl.address.c_str(),
                                                          deviceNameAidl.c_str(),
                                                          encodedFormat));
}

Status AudioPolicyService::getDeviceConnectionState(const media::AudioDevice& deviceAidl,
                                                    media::AudioPolicyDeviceState* _aidl_return) {
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_devices_t(deviceAidl.type));
    if (mAudioPolicyManager == NULL) {
        *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_policy_dev_state_t_AudioPolicyDeviceState(
                        AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE));
        return Status::ok();
    }
    AutoCallerClear acc;
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_policy_dev_state_t_AudioPolicyDeviceState(
                    mAudioPolicyManager->getDeviceConnectionState(device,
                                                                  deviceAidl.address.c_str())));
    return Status::ok();
}

Status AudioPolicyService::handleDeviceConfigChange(
        const media::AudioDevice& deviceAidl,
        const std::string& deviceNameAidl,
        media::audio::common::AudioFormat encodedFormatAidl) {
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_devices_t(deviceAidl.type));
    audio_format_t encodedFormat = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioFormat_audio_format_t(encodedFormatAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!settingsAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    ALOGV("handleDeviceConfigChange()");
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    return binderStatusFromStatusT(
            mAudioPolicyManager->handleDeviceConfigChange(device, deviceAidl.address.c_str(),
                                                          deviceNameAidl.c_str(), encodedFormat));
}

Status AudioPolicyService::setPhoneState(media::AudioMode stateAidl, int32_t uidAidl)
{
    audio_mode_t state = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioMode_audio_mode_t(stateAidl));
    uid_t uid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(uidAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!settingsAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (uint32_t(state) >= AUDIO_MODE_CNT) {
        return binderStatusFromStatusT(BAD_VALUE);
    }

    ALOGV("setPhoneState()");

    // acquire lock before calling setMode() so that setMode() + setPhoneState() are an atomic
    // operation from policy manager standpoint (no other operation (e.g track start or stop)
    // can be interleaved).
    Mutex::Autolock _l(mLock);
    // TODO: check if it is more appropriate to do it in platform specific policy manager
    AudioSystem::setMode(state);

    AutoCallerClear acc;
    mAudioPolicyManager->setPhoneState(state);
    mPhoneState = state;
    mPhoneStateOwnerUid = uid;
    updateUidStates_l();
    return Status::ok();
}

Status AudioPolicyService::getPhoneState(media::AudioMode* _aidl_return) {
    Mutex::Autolock _l(mLock);
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_audio_mode_t_AudioMode(mPhoneState));
    return Status::ok();
}

Status AudioPolicyService::setForceUse(media::AudioPolicyForceUse usageAidl,
                                       media::AudioPolicyForcedConfig configAidl)
{
    audio_policy_force_use_t usage = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPolicyForceUse_audio_policy_force_use_t(usageAidl));
    audio_policy_forced_cfg_t config = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPolicyForcedConfig_audio_policy_forced_cfg_t(configAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }

    if (!modifyAudioRoutingAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    if (usage < 0 || usage >= AUDIO_POLICY_FORCE_USE_CNT) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    if (config < 0 || config >= AUDIO_POLICY_FORCE_CFG_CNT) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    ALOGV("setForceUse()");
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    mAudioPolicyManager->setForceUse(usage, config);
    return Status::ok();
}

Status AudioPolicyService::getForceUse(media::AudioPolicyForceUse usageAidl,
                                       media::AudioPolicyForcedConfig* _aidl_return) {
    audio_policy_force_use_t usage = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPolicyForceUse_audio_policy_force_use_t(usageAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (usage < 0 || usage >= AUDIO_POLICY_FORCE_USE_CNT) {
        *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_policy_forced_cfg_t_AudioPolicyForcedConfig(AUDIO_POLICY_FORCE_NONE));
        return Status::ok();
    }
    AutoCallerClear acc;
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_policy_forced_cfg_t_AudioPolicyForcedConfig(
                    mAudioPolicyManager->getForceUse(usage)));
    return Status::ok();
}

Status AudioPolicyService::getOutput(media::AudioStreamType streamAidl, int32_t* _aidl_return)
{
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));

    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT) {
        *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_io_handle_t_int32_t(AUDIO_IO_HANDLE_NONE));
        return Status::ok();
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    ALOGV("getOutput()");
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_io_handle_t_int32_t(mAudioPolicyManager->getOutput(stream)));
    return Status::ok();
}

Status AudioPolicyService::getOutputForAttr(const media::AudioAttributesInternal& attrAidl,
                                            int32_t sessionAidl,
                                            const AttributionSourceState& attributionSource,
                                            const media::AudioConfig& configAidl,
                                            int32_t flagsAidl,
                                            int32_t selectedDeviceIdAidl,
                                            media::GetOutputForAttrResponse* _aidl_return)
{
    audio_attributes_t attr = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributesInternal_audio_attributes_t(attrAidl));
    audio_session_t session = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_session_t(sessionAidl));
    audio_stream_type_t stream = AUDIO_STREAM_DEFAULT;
    audio_config_t config = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioConfig_audio_config_t(configAidl));
    audio_output_flags_t flags = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_output_flags_t_mask(flagsAidl));
    audio_port_handle_t selectedDeviceId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(selectedDeviceIdAidl));

    audio_io_handle_t output;
    audio_port_handle_t portId;
    std::vector<audio_io_handle_t> secondaryOutputs;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }

    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(AudioValidator::validateAudioAttributes(attr, "68953950")));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(validateUsage(attr.usage, attributionSource)));

    ALOGV("%s()", __func__);
    Mutex::Autolock _l(mLock);

    // TODO b/182392553: refactor or remove
    AttributionSourceState adjAttributionSource = attributionSource;
    const uid_t callingUid = IPCThreadState::self()->getCallingUid();
    if (!isAudioServerOrMediaServerUid(callingUid) || attributionSource.uid == -1) {
        int32_t callingUidAidl = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_uid_t_int32_t(callingUid));
        ALOGW_IF(attributionSource.uid != -1 && attributionSource.uid != callingUidAidl,
                "%s uid %d tried to pass itself off as %d", __func__,
                callingUidAidl, attributionSource.uid);
        adjAttributionSource.uid = callingUidAidl;
    }
    if (!mPackageManager.allowPlaybackCapture(VALUE_OR_RETURN_BINDER_STATUS(
        aidl2legacy_int32_t_uid_t(adjAttributionSource.uid)))) {
        attr.flags = static_cast<audio_flags_mask_t>(attr.flags | AUDIO_FLAG_NO_MEDIA_PROJECTION);
    }
    if (((attr.flags & (AUDIO_FLAG_BYPASS_INTERRUPTION_POLICY|AUDIO_FLAG_BYPASS_MUTE)) != 0)
            && !bypassInterruptionPolicyAllowed(adjAttributionSource)) {
        attr.flags = static_cast<audio_flags_mask_t>(
                attr.flags & ~(AUDIO_FLAG_BYPASS_INTERRUPTION_POLICY|AUDIO_FLAG_BYPASS_MUTE));
    }
    AutoCallerClear acc;
    AudioPolicyInterface::output_type_t outputType;
    status_t result = mAudioPolicyManager->getOutputForAttr(&attr, &output, session,
                                                            &stream,
                                                            adjAttributionSource,
                                                            &config,
                                                            &flags, &selectedDeviceId, &portId,
                                                            &secondaryOutputs,
                                                            &outputType);

    // FIXME: Introduce a way to check for the the telephony device before opening the output
    if (result == NO_ERROR) {
        // enforce permission (if any) required for each type of input
        switch (outputType) {
        case AudioPolicyInterface::API_OUTPUT_LEGACY:
            break;
        case AudioPolicyInterface::API_OUTPUT_TELEPHONY_TX:
            if (!modifyPhoneStateAllowed(adjAttributionSource)) {
                ALOGE("%s() permission denied: modify phone state not allowed for uid %d",
                    __func__, adjAttributionSource.uid);
                result = PERMISSION_DENIED;
            }
            break;
        case AudioPolicyInterface::API_OUT_MIX_PLAYBACK:
            if (!modifyAudioRoutingAllowed(adjAttributionSource)) {
                ALOGE("%s() permission denied: modify audio routing not allowed for uid %d",
                    __func__, adjAttributionSource.uid);
                result = PERMISSION_DENIED;
            }
            break;
        case AudioPolicyInterface::API_OUTPUT_INVALID:
        default:
            LOG_ALWAYS_FATAL("%s() encountered an invalid output type %d",
                __func__, (int)outputType);
        }
    }

    if (result == NO_ERROR) {
        sp<AudioPlaybackClient> client =
                new AudioPlaybackClient(attr, output, adjAttributionSource, session,
                    portId, selectedDeviceId, stream);
        mAudioPlaybackClients.add(portId, client);

        _aidl_return->output = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_io_handle_t_int32_t(output));
        _aidl_return->stream = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_stream_type_t_AudioStreamType(stream));
        _aidl_return->selectedDeviceId = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_port_handle_t_int32_t(selectedDeviceId));
        _aidl_return->portId = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_port_handle_t_int32_t(portId));
        _aidl_return->secondaryOutputs = VALUE_OR_RETURN_BINDER_STATUS(
                convertContainer<std::vector<int32_t>>(secondaryOutputs,
                                                       legacy2aidl_audio_io_handle_t_int32_t));
    }
    return binderStatusFromStatusT(result);
}

void AudioPolicyService::getPlaybackClientAndEffects(audio_port_handle_t portId,
                                                     sp<AudioPlaybackClient>& client,
                                                     sp<AudioPolicyEffects>& effects,
                                                     const char *context)
{
    Mutex::Autolock _l(mLock);
    const ssize_t index = mAudioPlaybackClients.indexOfKey(portId);
    if (index < 0) {
        ALOGE("%s AudioTrack client not found for portId %d", context, portId);
        return;
    }
    client = mAudioPlaybackClients.valueAt(index);
    effects = mAudioPolicyEffects;
}

Status AudioPolicyService::startOutput(int32_t portIdAidl)
{
    audio_port_handle_t portId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portIdAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    ALOGV("startOutput()");
    sp<AudioPlaybackClient> client;
    sp<AudioPolicyEffects>audioPolicyEffects;

    getPlaybackClientAndEffects(portId, client, audioPolicyEffects, __func__);

    if (audioPolicyEffects != 0) {
        // create audio processors according to stream
        status_t status = audioPolicyEffects->addOutputSessionEffects(
            client->io, client->stream, client->session);
        if (status != NO_ERROR && status != ALREADY_EXISTS) {
            ALOGW("Failed to add effects on session %d", client->session);
        }
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    status_t status = mAudioPolicyManager->startOutput(portId);
    if (status == NO_ERROR) {
        client->active = true;
    }
    return binderStatusFromStatusT(status);
}

Status AudioPolicyService::stopOutput(int32_t portIdAidl)
{
    audio_port_handle_t portId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portIdAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    ALOGV("stopOutput()");
    mOutputCommandThread->stopOutputCommand(portId);
    return Status::ok();
}

status_t  AudioPolicyService::doStopOutput(audio_port_handle_t portId)
{
    ALOGV("doStopOutput");
    sp<AudioPlaybackClient> client;
    sp<AudioPolicyEffects>audioPolicyEffects;

    getPlaybackClientAndEffects(portId, client, audioPolicyEffects, __func__);

    if (audioPolicyEffects != 0) {
        // release audio processors from the stream
        status_t status = audioPolicyEffects->releaseOutputSessionEffects(
            client->io, client->stream, client->session);
        if (status != NO_ERROR && status != ALREADY_EXISTS) {
            ALOGW("Failed to release effects on session %d", client->session);
        }
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    status_t status = mAudioPolicyManager->stopOutput(portId);
    if (status == NO_ERROR) {
        client->active = false;
    }
    return status;
}

Status AudioPolicyService::releaseOutput(int32_t portIdAidl)
{
    audio_port_handle_t portId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portIdAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    ALOGV("releaseOutput()");
    mOutputCommandThread->releaseOutputCommand(portId);
    return Status::ok();
}

void AudioPolicyService::doReleaseOutput(audio_port_handle_t portId)
{
    ALOGV("doReleaseOutput from tid %d", gettid());
    sp<AudioPlaybackClient> client;
    sp<AudioPolicyEffects> audioPolicyEffects;

    getPlaybackClientAndEffects(portId, client, audioPolicyEffects, __func__);

    if (audioPolicyEffects != 0 && client->active) {
        // clean up effects if output was not stopped before being released
        audioPolicyEffects->releaseOutputSessionEffects(
            client->io, client->stream, client->session);
    }
    Mutex::Autolock _l(mLock);
    mAudioPlaybackClients.removeItem(portId);

    // called from internal thread: no need to clear caller identity
    mAudioPolicyManager->releaseOutput(portId);
}

Status AudioPolicyService::getInputForAttr(const media::AudioAttributesInternal& attrAidl,
                                           int32_t inputAidl,
                                           int32_t riidAidl,
                                           int32_t sessionAidl,
                                           const AttributionSourceState& attributionSource,
                                           const media::AudioConfigBase& configAidl,
                                           int32_t flagsAidl,
                                           int32_t selectedDeviceIdAidl,
                                           media::GetInputForAttrResponse* _aidl_return) {
    audio_attributes_t attr = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributesInternal_audio_attributes_t(attrAidl));
    audio_io_handle_t input = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_io_handle_t(inputAidl));
    audio_unique_id_t riid = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_unique_id_t(riidAidl));
    audio_session_t session = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_session_t(sessionAidl));
    audio_config_base_t config = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioConfigBase_audio_config_base_t(configAidl));
    audio_input_flags_t flags = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_input_flags_t_mask(flagsAidl));
    audio_port_handle_t selectedDeviceId = VALUE_OR_RETURN_BINDER_STATUS(
                aidl2legacy_int32_t_audio_port_handle_t(selectedDeviceIdAidl));

    audio_port_handle_t portId;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }

    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(AudioValidator::validateAudioAttributes(attr, "68953950")));

    audio_source_t inputSource = attr.source;
    if (inputSource == AUDIO_SOURCE_DEFAULT) {
        inputSource = AUDIO_SOURCE_MIC;
    }

    // already checked by client, but double-check in case the client wrapper is bypassed
    if ((inputSource < AUDIO_SOURCE_DEFAULT)
            || (inputSource >= AUDIO_SOURCE_CNT
                && inputSource != AUDIO_SOURCE_HOTWORD
                && inputSource != AUDIO_SOURCE_FM_TUNER
                && inputSource != AUDIO_SOURCE_ECHO_REFERENCE)) {
        return binderStatusFromStatusT(BAD_VALUE);
    }

    // Make sure attribution source represents the current caller
    AttributionSourceState adjAttributionSource = attributionSource;
    // TODO b/182392553: refactor or remove
    bool updatePid = (attributionSource.pid == -1);
    const uid_t callingUid =IPCThreadState::self()->getCallingUid();
    const uid_t currentUid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(
            attributionSource.uid));
    if (!isAudioServerOrMediaServerUid(callingUid)) {
        ALOGW_IF(currentUid != (uid_t)-1 && currentUid != callingUid,
                "%s uid %d tried to pass itself off as %d", __FUNCTION__, callingUid,
                currentUid);
        adjAttributionSource.uid = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_uid_t_int32_t(
                callingUid));
        updatePid = true;
    }

    if (updatePid) {
        const int32_t callingPid = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_pid_t_int32_t(
            IPCThreadState::self()->getCallingPid()));
        ALOGW_IF(attributionSource.pid != -1 && attributionSource.pid != callingPid,
                 "%s uid %d pid %d tried to pass itself off as pid %d",
                 __func__, adjAttributionSource.uid, callingPid, attributionSource.pid);
        adjAttributionSource.pid = callingPid;
    }

    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(validateUsage(attr.usage,
            adjAttributionSource)));

    // check calling permissions.
    // Capturing from FM_TUNER source is controlled by captureTunerAudioInputAllowed() and
    // captureAudioOutputAllowed() (deprecated) as this does not affect users privacy
    // as does capturing from an actual microphone.
    if (!isAudioServerOrMediaServerUid(callingUid) && !(recordingAllowed(adjAttributionSource, attr.source)
            || attr.source == AUDIO_SOURCE_FM_TUNER)) {
        ALOGE("%s permission denied: recording not allowed for %s",
                __func__, adjAttributionSource.toString().c_str());
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    bool canCaptureOutput = captureAudioOutputAllowed(adjAttributionSource);
    if ((inputSource == AUDIO_SOURCE_VOICE_UPLINK ||
        inputSource == AUDIO_SOURCE_VOICE_DOWNLINK ||
        inputSource == AUDIO_SOURCE_VOICE_CALL ||
        inputSource == AUDIO_SOURCE_ECHO_REFERENCE)
        && !canCaptureOutput) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    if (inputSource == AUDIO_SOURCE_FM_TUNER
        && !captureTunerAudioInputAllowed(adjAttributionSource)
        && !canCaptureOutput) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    bool canCaptureHotword = captureHotwordAllowed(adjAttributionSource);
    if ((inputSource == AUDIO_SOURCE_HOTWORD) && !canCaptureHotword) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    if (((flags & AUDIO_INPUT_FLAG_HW_HOTWORD) != 0)
            && !canCaptureHotword) {
        ALOGE("%s: permission denied: hotword mode not allowed"
              " for uid %d pid %d", __func__, adjAttributionSource.uid, adjAttributionSource.pid);
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    sp<AudioPolicyEffects>audioPolicyEffects;
    {
        status_t status;
        AudioPolicyInterface::input_type_t inputType;

        Mutex::Autolock _l(mLock);
        {
            AutoCallerClear acc;
            // the audio_in_acoustics_t parameter is ignored by get_input()
            status = mAudioPolicyManager->getInputForAttr(&attr, &input, riid, session,
                                                          adjAttributionSource, &config,
                                                          flags, &selectedDeviceId,
                                                          &inputType, &portId);

        }
        audioPolicyEffects = mAudioPolicyEffects;

        if (status == NO_ERROR) {
            // enforce permission (if any) required for each type of input
            switch (inputType) {
            case AudioPolicyInterface::API_INPUT_MIX_PUBLIC_CAPTURE_PLAYBACK:
                // this use case has been validated in audio service with a MediaProjection token,
                // and doesn't rely on regular permissions
            case AudioPolicyInterface::API_INPUT_LEGACY:
                break;
            case AudioPolicyInterface::API_INPUT_TELEPHONY_RX:
                // FIXME: use the same permission as for remote submix for now.
            case AudioPolicyInterface::API_INPUT_MIX_CAPTURE:
                if (!isAudioServerOrMediaServerUid(callingUid) && !canCaptureOutput) {
                    ALOGE("getInputForAttr() permission denied: capture not allowed");
                    status = PERMISSION_DENIED;
                }
                break;
            case AudioPolicyInterface::API_INPUT_MIX_EXT_POLICY_REROUTE:
                if (!modifyAudioRoutingAllowed(adjAttributionSource)) {
                    ALOGE("getInputForAttr() permission denied: modify audio routing not allowed");
                    status = PERMISSION_DENIED;
                }
                break;
            case AudioPolicyInterface::API_INPUT_INVALID:
            default:
                LOG_ALWAYS_FATAL("getInputForAttr() encountered an invalid input type %d",
                        (int)inputType);
            }
        }

        if (status != NO_ERROR) {
            if (status == PERMISSION_DENIED) {
                AutoCallerClear acc;
                mAudioPolicyManager->releaseInput(portId);
            }
            return binderStatusFromStatusT(status);
        }

        sp<AudioRecordClient> client = new AudioRecordClient(attr, input, session, portId,
                                                             selectedDeviceId, adjAttributionSource,
                                                             canCaptureOutput, canCaptureHotword,
                                                             mOutputCommandThread);
        mAudioRecordClients.add(portId, client);
    }

    if (audioPolicyEffects != 0) {
        // create audio pre processors according to input source
        status_t status = audioPolicyEffects->addInputEffects(input, inputSource, session);
        if (status != NO_ERROR && status != ALREADY_EXISTS) {
            ALOGW("Failed to add effects on input %d", input);
        }
    }

    _aidl_return->input = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_io_handle_t_int32_t(input));
    _aidl_return->selectedDeviceId = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_port_handle_t_int32_t(selectedDeviceId));
    _aidl_return->portId = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_port_handle_t_int32_t(portId));
    return Status::ok();
}

std::string AudioPolicyService::getDeviceTypeStrForPortId(audio_port_handle_t portId) {
    struct audio_port_v7 port = {};
    port.id = portId;
    status_t status = mAudioPolicyManager->getAudioPort(&port);
    if (status == NO_ERROR && port.type == AUDIO_PORT_TYPE_DEVICE) {
        return toString(port.ext.device.type);
    }
    return {};
}

Status AudioPolicyService::startInput(int32_t portIdAidl)
{
    audio_port_handle_t portId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portIdAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    sp<AudioRecordClient> client;
    {
        Mutex::Autolock _l(mLock);

        ssize_t index = mAudioRecordClients.indexOfKey(portId);
        if (index < 0) {
            return binderStatusFromStatusT(INVALID_OPERATION);
        }
        client = mAudioRecordClients.valueAt(index);
    }

    std::stringstream msg;
    msg << "Audio recording on session " << client->session;

    // check calling permissions
    if (!isAudioServerOrMediaServerUid(IPCThreadState::self()->getCallingUid()) && !(startRecording(client->attributionSource, String16(msg.str().c_str()),
        client->attributes.source)
            || client->attributes.source == AUDIO_SOURCE_FM_TUNER)) {
        ALOGE("%s permission denied: recording not allowed for attribution source %s",
                __func__, client->attributionSource.toString().c_str());
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    Mutex::Autolock _l(mLock);

    client->active = true;
    client->startTimeNs = systemTime();
    updateUidStates_l();

    status_t status;
    {
        AutoCallerClear acc;
        status = mAudioPolicyManager->startInput(portId);

    }

    // including successes gets very verbose
    // but once we cut over to statsd, log them all.
    if (status != NO_ERROR) {

        static constexpr char kAudioPolicy[] = "audiopolicy";

        static constexpr char kAudioPolicyStatus[] = "android.media.audiopolicy.status";
        static constexpr char kAudioPolicyRqstSrc[] = "android.media.audiopolicy.rqst.src";
        static constexpr char kAudioPolicyRqstPkg[] = "android.media.audiopolicy.rqst.pkg";
        static constexpr char kAudioPolicyRqstSession[] = "android.media.audiopolicy.rqst.session";
        static constexpr char kAudioPolicyRqstDevice[] =
                "android.media.audiopolicy.rqst.device";
        static constexpr char kAudioPolicyActiveSrc[] = "android.media.audiopolicy.active.src";
        static constexpr char kAudioPolicyActivePkg[] = "android.media.audiopolicy.active.pkg";
        static constexpr char kAudioPolicyActiveSession[] =
                "android.media.audiopolicy.active.session";
        static constexpr char kAudioPolicyActiveDevice[] =
                "android.media.audiopolicy.active.device";

        mediametrics::Item *item = mediametrics::Item::create(kAudioPolicy);
        if (item != NULL) {

            item->setInt32(kAudioPolicyStatus, status);

            item->setCString(kAudioPolicyRqstSrc,
                             toString(client->attributes.source).c_str());
            item->setInt32(kAudioPolicyRqstSession, client->session);
            if (client->attributionSource.packageName.has_value() &&
                client->attributionSource.packageName.value().size() != 0) {
                item->setCString(kAudioPolicyRqstPkg,
                    client->attributionSource.packageName.value().c_str());
            } else {
                item->setCString(kAudioPolicyRqstPkg,
                    std::to_string(client->attributionSource.uid).c_str());
            }
            item->setCString(
                    kAudioPolicyRqstDevice, getDeviceTypeStrForPortId(client->deviceId).c_str());

            int count = mAudioRecordClients.size();
            for (int i = 0; i < count ; i++) {
                if (portId == mAudioRecordClients.keyAt(i)) {
                    continue;
                }
                sp<AudioRecordClient> other = mAudioRecordClients.valueAt(i);
                if (other->active) {
                    // keeps the last of the clients marked active
                    item->setCString(kAudioPolicyActiveSrc,
                                     toString(other->attributes.source).c_str());
                    item->setInt32(kAudioPolicyActiveSession, other->session);
                    if (other->attributionSource.packageName.has_value() &&
                        other->attributionSource.packageName.value().size() != 0) {
                        item->setCString(kAudioPolicyActivePkg,
                            other->attributionSource.packageName.value().c_str());
                    } else {
                        item->setCString(kAudioPolicyRqstPkg, std::to_string(
                            other->attributionSource.uid).c_str());
                    }
                    item->setCString(kAudioPolicyActiveDevice,
                                     getDeviceTypeStrForPortId(other->deviceId).c_str());
                }
            }
            item->selfrecord();
            delete item;
            item = NULL;
        }
    }

    if (status != NO_ERROR) {
        client->active = false;
        client->startTimeNs = 0;
        updateUidStates_l();
        finishRecording(client->attributionSource, client->attributes.source);
    }

    return binderStatusFromStatusT(status);
}

Status AudioPolicyService::stopInput(int32_t portIdAidl)
{
    audio_port_handle_t portId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portIdAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }

    Mutex::Autolock _l(mLock);

    ssize_t index = mAudioRecordClients.indexOfKey(portId);
    if (index < 0) {
        return binderStatusFromStatusT(INVALID_OPERATION);
    }
    sp<AudioRecordClient> client = mAudioRecordClients.valueAt(index);

    client->active = false;
    client->startTimeNs = 0;

    updateUidStates_l();

    // finish the recording app op
    finishRecording(client->attributionSource, client->attributes.source);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->stopInput(portId));
}

Status AudioPolicyService::releaseInput(int32_t portIdAidl)
{
    audio_port_handle_t portId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portIdAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    sp<AudioPolicyEffects>audioPolicyEffects;
    sp<AudioRecordClient> client;
    {
        Mutex::Autolock _l(mLock);
        audioPolicyEffects = mAudioPolicyEffects;
        ssize_t index = mAudioRecordClients.indexOfKey(portId);
        if (index < 0) {
            return Status::ok();
        }
        client = mAudioRecordClients.valueAt(index);

        if (client->active) {
            ALOGW("%s releasing active client portId %d", __FUNCTION__, portId);
            client->active = false;
            client->startTimeNs = 0;
            updateUidStates_l();
        }

        mAudioRecordClients.removeItem(portId);
    }
    if (client == 0) {
        return Status::ok();
    }
    if (audioPolicyEffects != 0) {
        // release audio processors from the input
        status_t status = audioPolicyEffects->releaseInputEffects(client->io, client->session);
        if(status != NO_ERROR) {
            ALOGW("Failed to release effects on input %d", client->io);
        }
    }
    {
        Mutex::Autolock _l(mLock);
        AutoCallerClear acc;
        mAudioPolicyManager->releaseInput(portId);
    }
    return Status::ok();
}

Status AudioPolicyService::initStreamVolume(media::AudioStreamType streamAidl,
                                            int32_t indexMinAidl,
                                            int32_t indexMaxAidl) {
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));
    int indexMin = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexMinAidl));
    int indexMax = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexMaxAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!settingsAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    mAudioPolicyManager->initStreamVolume(stream, indexMin, indexMax);
    return binderStatusFromStatusT(NO_ERROR);
}

Status AudioPolicyService::setStreamVolumeIndex(media::AudioStreamType streamAidl,
                                                int32_t deviceAidl, int32_t indexAidl) {
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));
    int index = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexAidl));
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_devices_t(deviceAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!settingsAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->setStreamVolumeIndex(stream,
                                                                             index,
                                                                             device));
}

Status AudioPolicyService::getStreamVolumeIndex(media::AudioStreamType streamAidl,
                                                int32_t deviceAidl, int32_t* _aidl_return) {
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_devices_t(deviceAidl));
    int index;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getStreamVolumeIndex(stream, &index, device)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(index));
    return Status::ok();
}

Status AudioPolicyService::setVolumeIndexForAttributes(
        const media::AudioAttributesInternal& attrAidl, int32_t deviceAidl, int32_t indexAidl) {
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributesInternal_audio_attributes_t(attrAidl));
    int index = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexAidl));
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_devices_t(deviceAidl));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioAttributes(attributes, "169572641")));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!settingsAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    return binderStatusFromStatusT(
            mAudioPolicyManager->setVolumeIndexForAttributes(attributes, index, device));
}

Status AudioPolicyService::getVolumeIndexForAttributes(
        const media::AudioAttributesInternal& attrAidl, int32_t deviceAidl, int32_t* _aidl_return) {
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributesInternal_audio_attributes_t(attrAidl));
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_devices_t(deviceAidl));
    int index;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioAttributes(attributes, "169572641")));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getVolumeIndexForAttributes(attributes, index, device)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(index));
    return Status::ok();
}

Status AudioPolicyService::getMinVolumeIndexForAttributes(
        const media::AudioAttributesInternal& attrAidl, int32_t* _aidl_return) {
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributesInternal_audio_attributes_t(attrAidl));
    int index;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioAttributes(attributes, "169572641")));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getMinVolumeIndexForAttributes(attributes, index)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(index));
    return Status::ok();
}

Status AudioPolicyService::getMaxVolumeIndexForAttributes(
        const media::AudioAttributesInternal& attrAidl, int32_t* _aidl_return) {
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributesInternal_audio_attributes_t(attrAidl));
    int index;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioAttributes(attributes, "169572641")));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getMaxVolumeIndexForAttributes(attributes, index)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(index));
    return Status::ok();
}

Status AudioPolicyService::getStrategyForStream(media::AudioStreamType streamAidl,
                                                int32_t* _aidl_return) {
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));

    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT) {
        *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
                convertReinterpret<int32_t>(PRODUCT_STRATEGY_NONE));
        return Status::ok();
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }

    // DO NOT LOCK, may be called from AudioFlinger with lock held, reaching deadlock
    AutoCallerClear acc;
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_product_strategy_t_int32_t(
                    mAudioPolicyManager->getStrategyForStream(stream)));
    return Status::ok();
}

//audio policy: use audio_device_t appropriately

Status AudioPolicyService::getDevicesForStream(media::AudioStreamType streamAidl,
                                               int32_t* _aidl_return) {
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));

    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT) {
        *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_devices_t_int32_t(AUDIO_DEVICE_NONE));
        return Status::ok();
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_devices_t_int32_t(mAudioPolicyManager->getDevicesForStream(stream)));
    return Status::ok();
}

Status AudioPolicyService::getDevicesForAttributes(const media::AudioAttributesEx& attrAidl,
                                                   std::vector<media::AudioDevice>* _aidl_return)
{
    AudioAttributes aa = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributesEx_AudioAttributes(attrAidl));
    AudioDeviceTypeAddrVector devices;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getDevicesForAttributes(aa.getAttributes(), &devices)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<media::AudioDevice>>(devices,
                                                              legacy2aidl_AudioDeviceTypeAddress));
    return Status::ok();
}

Status AudioPolicyService::getOutputForEffect(const media::EffectDescriptor& descAidl,
                                              int32_t* _aidl_return) {
    effect_descriptor_t desc = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_EffectDescriptor_effect_descriptor_t(descAidl));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateEffectDescriptor(desc, "73126106")));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_io_handle_t_int32_t(mAudioPolicyManager->getOutputForEffect(&desc)));
    return Status::ok();
}

Status AudioPolicyService::registerEffect(const media::EffectDescriptor& descAidl, int32_t ioAidl,
                                          int32_t strategyAidl, int32_t sessionAidl,
                                          int32_t idAidl) {
    effect_descriptor_t desc = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_EffectDescriptor_effect_descriptor_t(descAidl));
    audio_io_handle_t io = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_io_handle_t(ioAidl));
    product_strategy_t strategy = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_product_strategy_t(strategyAidl));
    audio_session_t session = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_session_t(sessionAidl));
    int id = VALUE_OR_RETURN_BINDER_STATUS(convertReinterpret<int>(idAidl));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateEffectDescriptor(desc, "73126106")));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    return binderStatusFromStatusT(
            mAudioPolicyManager->registerEffect(&desc, io, strategy, session, id));
}

Status AudioPolicyService::unregisterEffect(int32_t idAidl)
{
    int id = VALUE_OR_RETURN_BINDER_STATUS(convertReinterpret<int>(idAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->unregisterEffect(id));
}

Status AudioPolicyService::setEffectEnabled(int32_t idAidl, bool enabled)
{
    int id = VALUE_OR_RETURN_BINDER_STATUS(convertReinterpret<int>(idAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->setEffectEnabled(id, enabled));
}

Status AudioPolicyService::moveEffectsToIo(const std::vector<int32_t>& idsAidl, int32_t ioAidl)

{
    const std::vector<int>& ids = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<int>>(idsAidl, convertReinterpret<int, int32_t>));
    audio_io_handle_t io = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_io_handle_t(ioAidl));
    if (ids.size() > MAX_ITEMS_PER_LIST) {
        return binderStatusFromStatusT(BAD_VALUE);
    }

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->moveEffectsToIo(ids, io));
}

Status AudioPolicyService::isStreamActive(media::AudioStreamType streamAidl, int32_t inPastMsAidl,
                                          bool* _aidl_return) {
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));
    uint32_t inPastMs = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<uint32_t>(inPastMsAidl));

    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT) {
        *_aidl_return = false;
        return Status::ok();
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->isStreamActive(stream, inPastMs);
    return Status::ok();
}

Status AudioPolicyService::isStreamActiveRemotely(media::AudioStreamType streamAidl,
                                                  int32_t inPastMsAidl,
                                                  bool* _aidl_return) {
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));
    uint32_t inPastMs = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<uint32_t>(inPastMsAidl));

    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT) {
        *_aidl_return = false;
        return Status::ok();
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->isStreamActiveRemotely(stream, inPastMs);
    return Status::ok();
}

Status AudioPolicyService::isSourceActive(media::AudioSourceType sourceAidl, bool* _aidl_return) {
    audio_source_t source = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSourceType_audio_source_t(sourceAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->isSourceActive(source);
    return Status::ok();
}

status_t AudioPolicyService::getAudioPolicyEffects(sp<AudioPolicyEffects>& audioPolicyEffects)
{
    if (mAudioPolicyManager == NULL) {
        return NO_INIT;
    }
    {
        Mutex::Autolock _l(mLock);
        audioPolicyEffects = mAudioPolicyEffects;
    }
    if (audioPolicyEffects == 0) {
        return NO_INIT;
    }

    return OK;
}

Status AudioPolicyService::queryDefaultPreProcessing(
        int32_t audioSessionAidl,
        media::Int* countAidl,
        std::vector<media::EffectDescriptor>* _aidl_return) {
    audio_session_t audioSession = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_session_t(audioSessionAidl));
    uint32_t count = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<uint32_t>(countAidl->value));
    if (count > AudioEffect::kMaxPreProcessing) {
        count = AudioEffect::kMaxPreProcessing;
    }
    uint32_t countReq = count;
    std::unique_ptr<effect_descriptor_t[]> descriptors(new effect_descriptor_t[count]);

    sp<AudioPolicyEffects> audioPolicyEffects;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(getAudioPolicyEffects(audioPolicyEffects)));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(audioPolicyEffects->queryDefaultInputEffects(
            (audio_session_t) audioSession, descriptors.get(), &count)));
    countReq = std::min(count, countReq);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(descriptors.get(), descriptors.get() + countReq,
                         std::back_inserter(*_aidl_return),
                         legacy2aidl_effect_descriptor_t_EffectDescriptor)));
    countAidl->value = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<uint32_t>(count));
    return Status::ok();
}

Status AudioPolicyService::addSourceDefaultEffect(const media::AudioUuid& typeAidl,
                                                  const std::string& opPackageNameAidl,
                                                  const media::AudioUuid& uuidAidl,
                                                  int32_t priority,
                                                  media::AudioSourceType sourceAidl,
                                                  int32_t* _aidl_return) {
    effect_uuid_t type = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioUuid_audio_uuid_t(typeAidl));
    String16 opPackageName = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_string_view_String16(opPackageNameAidl));
    effect_uuid_t uuid = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioUuid_audio_uuid_t(uuidAidl));
    audio_source_t source = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSourceType_audio_source_t(sourceAidl));
    audio_unique_id_t id;

    sp<AudioPolicyEffects>audioPolicyEffects;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(getAudioPolicyEffects(audioPolicyEffects)));
    if (!modifyDefaultAudioEffectsAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(audioPolicyEffects->addSourceDefaultEffect(
            &type, opPackageName, &uuid, priority, source, &id)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_audio_unique_id_t_int32_t(id));
    return Status::ok();
}

Status AudioPolicyService::addStreamDefaultEffect(const media::AudioUuid& typeAidl,
                                                  const std::string& opPackageNameAidl,
                                                  const media::AudioUuid& uuidAidl,
                                                  int32_t priority, media::AudioUsage usageAidl,
                                                  int32_t* _aidl_return) {
    effect_uuid_t type = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioUuid_audio_uuid_t(typeAidl));
    String16 opPackageName = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_string_view_String16(opPackageNameAidl));
    effect_uuid_t uuid = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioUuid_audio_uuid_t(uuidAidl));
    audio_usage_t usage = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioUsage_audio_usage_t(usageAidl));
    audio_unique_id_t id;

    sp<AudioPolicyEffects> audioPolicyEffects;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(getAudioPolicyEffects(audioPolicyEffects)));
    if (!modifyDefaultAudioEffectsAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(audioPolicyEffects->addStreamDefaultEffect(
            &type, opPackageName, &uuid, priority, usage, &id)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_audio_unique_id_t_int32_t(id));
    return Status::ok();
}

Status AudioPolicyService::removeSourceDefaultEffect(int32_t idAidl)
{
    audio_unique_id_t id = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_unique_id_t(idAidl));
    sp<AudioPolicyEffects>audioPolicyEffects;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(getAudioPolicyEffects(audioPolicyEffects)));
    if (!modifyDefaultAudioEffectsAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    return binderStatusFromStatusT(audioPolicyEffects->removeSourceDefaultEffect(id));
}

Status AudioPolicyService::removeStreamDefaultEffect(int32_t idAidl)
{
    audio_unique_id_t id = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_unique_id_t(idAidl));
    sp<AudioPolicyEffects>audioPolicyEffects;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(getAudioPolicyEffects(audioPolicyEffects)));
    if (!modifyDefaultAudioEffectsAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    return binderStatusFromStatusT(audioPolicyEffects->removeStreamDefaultEffect(id));
}

Status AudioPolicyService::setSupportedSystemUsages(
        const std::vector<media::AudioUsage>& systemUsagesAidl) {
    size_t size = systemUsagesAidl.size();
    if (size > MAX_ITEMS_PER_LIST) {
        size = MAX_ITEMS_PER_LIST;
    }
    std::vector<audio_usage_t> systemUsages;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(systemUsagesAidl.begin(), systemUsagesAidl.begin() + size,
                         std::back_inserter(systemUsages), aidl2legacy_AudioUsage_audio_usage_t)));

    Mutex::Autolock _l(mLock);
    if(!modifyAudioRoutingAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    bool areAllSystemUsages = std::all_of(begin(systemUsages), end(systemUsages),
        [](audio_usage_t usage) { return isSystemUsage(usage); });
    if (!areAllSystemUsages) {
        return binderStatusFromStatusT(BAD_VALUE);
    }

    mSupportedSystemUsages = systemUsages;
    return Status::ok();
}

Status AudioPolicyService::setAllowedCapturePolicy(int32_t uidAidl, int32_t capturePolicyAidl) {
    uid_t uid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(uidAidl));
    audio_flags_mask_t capturePolicy = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_flags_mask_t_mask(capturePolicyAidl));

    Mutex::Autolock _l(mLock);
    if (mAudioPolicyManager == NULL) {
        ALOGV("%s() mAudioPolicyManager == NULL", __func__);
        return binderStatusFromStatusT(NO_INIT);
    }
    return binderStatusFromStatusT(
            mAudioPolicyManager->setAllowedCapturePolicy(uid, capturePolicy));
}

Status AudioPolicyService::getOffloadSupport(const media::AudioOffloadInfo& infoAidl,
                                             media::AudioOffloadMode* _aidl_return) {
    audio_offload_info_t info = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioOffloadInfo_audio_offload_info_t(infoAidl));
    if (mAudioPolicyManager == NULL) {
        ALOGV("mAudioPolicyManager == NULL");
        return binderStatusFromStatusT(AUDIO_OFFLOAD_NOT_SUPPORTED);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_audio_offload_mode_t_AudioOffloadMode(
            mAudioPolicyManager->getOffloadSupport(info)));
    return Status::ok();
}

Status AudioPolicyService::isDirectOutputSupported(
        const media::AudioConfigBase& configAidl,
        const media::AudioAttributesInternal& attributesAidl,
        bool* _aidl_return) {
    audio_config_base_t config = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioConfigBase_audio_config_base_t(configAidl));
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributesInternal_audio_attributes_t(attributesAidl));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioAttributes(attributes, "169572641")));

    if (mAudioPolicyManager == NULL) {
        ALOGV("mAudioPolicyManager == NULL");
        return binderStatusFromStatusT(NO_INIT);
    }

    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(validateUsage(attributes.usage)));

    Mutex::Autolock _l(mLock);
    *_aidl_return = mAudioPolicyManager->isDirectOutputSupported(config, attributes);
    return Status::ok();
}


Status AudioPolicyService::listAudioPorts(media::AudioPortRole roleAidl,
                                          media::AudioPortType typeAidl, media::Int* count,
                                          std::vector<media::AudioPort>* portsAidl,
                                          int32_t* _aidl_return) {
    audio_port_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPortRole_audio_port_role_t(roleAidl));
    audio_port_type_t type = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPortType_audio_port_type_t(typeAidl));
    unsigned int num_ports = VALUE_OR_RETURN_BINDER_STATUS(
            convertIntegral<unsigned int>(count->value));
    if (num_ports > MAX_ITEMS_PER_LIST) {
        num_ports = MAX_ITEMS_PER_LIST;
    }
    unsigned int numPortsReq = num_ports;
    std::unique_ptr<audio_port_v7[]> ports(new audio_port_v7[num_ports]);
    unsigned int generation;

    Mutex::Autolock _l(mLock);
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->listAudioPorts(role, type, &num_ports, ports.get(), &generation)));
    numPortsReq = std::min(numPortsReq, num_ports);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(ports.get(), ports.get() + numPortsReq, std::back_inserter(*portsAidl),
                         legacy2aidl_audio_port_v7_AudioPort)));
    count->value = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(num_ports));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(generation));
    return Status::ok();
}

Status AudioPolicyService::getAudioPort(const media::AudioPort& portAidl,
                                        media::AudioPort* _aidl_return) {
    audio_port_v7 port = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPort_audio_port_v7(portAidl));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(AudioValidator::validateAudioPort(port)));

    Mutex::Autolock _l(mLock);
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(mAudioPolicyManager->getAudioPort(&port)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_audio_port_v7_AudioPort(port));
    return Status::ok();
}

Status AudioPolicyService::createAudioPatch(const media::AudioPatch& patchAidl, int32_t handleAidl,
                                            int32_t* _aidl_return) {
    audio_patch patch = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPatch_audio_patch(patchAidl));
    audio_patch_handle_t handle = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(handleAidl));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(AudioValidator::validateAudioPatch(patch)));

    Mutex::Autolock _l(mLock);
    if(!modifyAudioRoutingAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->createAudioPatch(&patch, &handle,
                                                  IPCThreadState::self()->getCallingUid())));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_audio_patch_handle_t_int32_t(handle));
    return Status::ok();
}

Status AudioPolicyService::releaseAudioPatch(int32_t handleAidl)
{
    audio_patch_handle_t handle = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_patch_handle_t(handleAidl));
    Mutex::Autolock _l(mLock);
    if(!modifyAudioRoutingAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    return binderStatusFromStatusT(
            mAudioPolicyManager->releaseAudioPatch(handle,
                                                   IPCThreadState::self()->getCallingUid()));
}

Status AudioPolicyService::listAudioPatches(media::Int* count,
                                            std::vector<media::AudioPatch>* patchesAidl,
                                            int32_t* _aidl_return) {
    unsigned int num_patches = VALUE_OR_RETURN_BINDER_STATUS(
            convertIntegral<unsigned int>(count->value));
    if (num_patches > MAX_ITEMS_PER_LIST) {
        num_patches = MAX_ITEMS_PER_LIST;
    }
    unsigned int numPatchesReq = num_patches;
    std::unique_ptr<audio_patch[]> patches(new audio_patch[num_patches]);
    unsigned int generation;

    Mutex::Autolock _l(mLock);
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->listAudioPatches(&num_patches, patches.get(), &generation)));
    numPatchesReq = std::min(numPatchesReq, num_patches);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(patches.get(), patches.get() + numPatchesReq,
                         std::back_inserter(*patchesAidl), legacy2aidl_audio_patch_AudioPatch)));
    count->value = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(num_patches));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(generation));
    return Status::ok();
}

Status AudioPolicyService::setAudioPortConfig(const media::AudioPortConfig& configAidl)
{
    audio_port_config config = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPortConfig_audio_port_config(configAidl));
    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(AudioValidator::validateAudioPortConfig(config)));

    Mutex::Autolock _l(mLock);
    if(!modifyAudioRoutingAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->setAudioPortConfig(&config));
}

Status AudioPolicyService::acquireSoundTriggerSession(media::SoundTriggerSession* _aidl_return)
{
    audio_session_t session;
    audio_io_handle_t ioHandle;
    audio_devices_t device;

    {
        Mutex::Autolock _l(mLock);
        if (mAudioPolicyManager == NULL) {
            return binderStatusFromStatusT(NO_INIT);
        }
        AutoCallerClear acc;
        RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
                mAudioPolicyManager->acquireSoundTriggerSession(&session, &ioHandle, &device)));
    }

    _aidl_return->session = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_session_t_int32_t(session));
    _aidl_return->ioHandle = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_io_handle_t_int32_t(ioHandle));
    _aidl_return->device = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_devices_t_int32_t(device));
    return Status::ok();
}

Status AudioPolicyService::releaseSoundTriggerSession(int32_t sessionAidl)
{
    audio_session_t session = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_session_t(sessionAidl));
    Mutex::Autolock _l(mLock);
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->releaseSoundTriggerSession(session));
}

Status AudioPolicyService::registerPolicyMixes(const std::vector<media::AudioMix>& mixesAidl,
                                               bool registration) {
    size_t size = mixesAidl.size();
    if (size > MAX_MIXES_PER_POLICY) {
        size = MAX_MIXES_PER_POLICY;
    }
    Vector<AudioMix> mixes;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(mixesAidl.begin(), mixesAidl.begin() + size, std::back_inserter(mixes),
                         aidl2legacy_AudioMix)));

    Mutex::Autolock _l(mLock);

    // loopback|render only need a MediaProjection (checked in caller AudioService.java)
    bool needModifyAudioRouting = std::any_of(mixes.begin(), mixes.end(), [](auto& mix) {
            return !is_mix_loopback_render(mix.mRouteFlags); });
    if (needModifyAudioRouting && !modifyAudioRoutingAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    // If one of the mixes has needCaptureVoiceCommunicationOutput set to true, then we
    // need to verify that the caller still has CAPTURE_VOICE_COMMUNICATION_OUTPUT
    bool needCaptureVoiceCommunicationOutput =
        std::any_of(mixes.begin(), mixes.end(), [](auto& mix) {
            return mix.mVoiceCommunicationCaptureAllowed; });

    bool needCaptureMediaOutput = std::any_of(mixes.begin(), mixes.end(), [](auto& mix) {
            return mix.mAllowPrivilegedMediaPlaybackCapture; });

    const AttributionSourceState attributionSource = getCallingAttributionSource();


    if (needCaptureMediaOutput && !captureMediaOutputAllowed(attributionSource)) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    if (needCaptureVoiceCommunicationOutput &&
        !captureVoiceCommunicationOutputAllowed(attributionSource)) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    if (registration) {
        return binderStatusFromStatusT(mAudioPolicyManager->registerPolicyMixes(mixes));
    } else {
        return binderStatusFromStatusT(mAudioPolicyManager->unregisterPolicyMixes(mixes));
    }
}

Status AudioPolicyService::setUidDeviceAffinities(
        int32_t uidAidl,
        const std::vector<media::AudioDevice>& devicesAidl) {
    uid_t uid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(uidAidl));
    AudioDeviceTypeAddrVector devices = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<AudioDeviceTypeAddrVector>(devicesAidl,
                                                        aidl2legacy_AudioDeviceTypeAddress));

    Mutex::Autolock _l(mLock);
    if(!modifyAudioRoutingAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->setUidDeviceAffinities(uid, devices));
}

Status AudioPolicyService::removeUidDeviceAffinities(int32_t uidAidl) {
    uid_t uid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(uidAidl));

    Mutex::Autolock _l(mLock);
    if(!modifyAudioRoutingAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->removeUidDeviceAffinities(uid));
}

Status AudioPolicyService::setUserIdDeviceAffinities(
        int32_t userIdAidl,
        const std::vector<media::AudioDevice>& devicesAidl) {
    int userId = VALUE_OR_RETURN_BINDER_STATUS(convertReinterpret<int>(userIdAidl));
    AudioDeviceTypeAddrVector devices = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<AudioDeviceTypeAddrVector>(devicesAidl,
                                                        aidl2legacy_AudioDeviceTypeAddress));

    Mutex::Autolock _l(mLock);
    if(!modifyAudioRoutingAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->setUserIdDeviceAffinities(userId, devices));
}

Status AudioPolicyService::removeUserIdDeviceAffinities(int32_t userIdAidl) {
    int userId = VALUE_OR_RETURN_BINDER_STATUS(convertReinterpret<int>(userIdAidl));

    Mutex::Autolock _l(mLock);
    if(!modifyAudioRoutingAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->removeUserIdDeviceAffinities(userId));
}

Status AudioPolicyService::startAudioSource(const media::AudioPortConfig& sourceAidl,
                                            const media::AudioAttributesInternal& attributesAidl,
                                            int32_t* _aidl_return) {
    audio_port_config source = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPortConfig_audio_port_config(sourceAidl));
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributesInternal_audio_attributes_t(attributesAidl));
    audio_port_handle_t portId;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioPortConfig(source)));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioAttributes(attributes, "68953950")));

    Mutex::Autolock _l(mLock);
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }

    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(validateUsage(attributes.usage)));

    // startAudioSource should be created as the calling uid
    const uid_t callingUid = IPCThreadState::self()->getCallingUid();
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->startAudioSource(&source, &attributes, &portId, callingUid)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_audio_port_handle_t_int32_t(portId));
    return Status::ok();
}

Status AudioPolicyService::stopAudioSource(int32_t portIdAidl)
{
    audio_port_handle_t portId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portIdAidl));

    Mutex::Autolock _l(mLock);
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->stopAudioSource(portId));
}

Status AudioPolicyService::setMasterMono(bool mono)
{
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!settingsAllowed()) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->setMasterMono(mono));
}

Status AudioPolicyService::getMasterMono(bool* _aidl_return)
{
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->getMasterMono(_aidl_return));
}


Status AudioPolicyService::getStreamVolumeDB(media::AudioStreamType streamAidl, int32_t indexAidl,
                                             int32_t deviceAidl, float* _aidl_return) {
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));
    int index = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexAidl));
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_devices_t(deviceAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->getStreamVolumeDB(stream, index, device);
    return Status::ok();
}

Status AudioPolicyService::getSurroundFormats(media::Int* count,
        std::vector<media::audio::common::AudioFormat>* formats,
        std::vector<bool>* formatsEnabled) {
    unsigned int numSurroundFormats = VALUE_OR_RETURN_BINDER_STATUS(
            convertIntegral<unsigned int>(count->value));
    if (numSurroundFormats > MAX_ITEMS_PER_LIST) {
        numSurroundFormats = MAX_ITEMS_PER_LIST;
    }
    unsigned int numSurroundFormatsReq = numSurroundFormats;
    std::unique_ptr<audio_format_t[]>surroundFormats(new audio_format_t[numSurroundFormats]);
    std::unique_ptr<bool[]>surroundFormatsEnabled(new bool[numSurroundFormats]);

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getSurroundFormats(&numSurroundFormats, surroundFormats.get(),
                                                    surroundFormatsEnabled.get())));
    numSurroundFormatsReq = std::min(numSurroundFormats, numSurroundFormatsReq);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(surroundFormats.get(), surroundFormats.get() + numSurroundFormatsReq,
                         std::back_inserter(*formats), legacy2aidl_audio_format_t_AudioFormat)));
    formatsEnabled->insert(
            formatsEnabled->begin(),
            surroundFormatsEnabled.get(),
            surroundFormatsEnabled.get() + numSurroundFormatsReq);
    count->value = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<uint32_t>(numSurroundFormats));
    return Status::ok();
}

Status AudioPolicyService::getReportedSurroundFormats(
        media::Int* count, std::vector<media::audio::common::AudioFormat>* formats) {
    unsigned int numSurroundFormats = VALUE_OR_RETURN_BINDER_STATUS(
            convertIntegral<unsigned int>(count->value));
    if (numSurroundFormats > MAX_ITEMS_PER_LIST) {
        numSurroundFormats = MAX_ITEMS_PER_LIST;
    }
    unsigned int numSurroundFormatsReq = numSurroundFormats;
    std::unique_ptr<audio_format_t[]>surroundFormats(new audio_format_t[numSurroundFormats]);

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getReportedSurroundFormats(
                    &numSurroundFormats, surroundFormats.get())));
    numSurroundFormatsReq = std::min(numSurroundFormats, numSurroundFormatsReq);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(surroundFormats.get(), surroundFormats.get() + numSurroundFormatsReq,
                         std::back_inserter(*formats), legacy2aidl_audio_format_t_AudioFormat)));
    count->value = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<uint32_t>(numSurroundFormats));
    return Status::ok();
}

Status AudioPolicyService::getHwOffloadEncodingFormatsSupportedForA2DP(
        std::vector<media::audio::common::AudioFormat>* _aidl_return) {
    std::vector<audio_format_t> formats;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getHwOffloadEncodingFormatsSupportedForA2DP(&formats)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<media::audio::common::AudioFormat>>(
                    formats,
                    legacy2aidl_audio_format_t_AudioFormat));
    return Status::ok();
}

Status AudioPolicyService::setSurroundFormatEnabled(
        media::audio::common::AudioFormat audioFormatAidl, bool enabled) {
    audio_format_t audioFormat = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioFormat_audio_format_t(audioFormatAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    return binderStatusFromStatusT(
            mAudioPolicyManager->setSurroundFormatEnabled(audioFormat, enabled));
}

Status AudioPolicyService::setAssistantUid(int32_t uidAidl)
{
    uid_t uid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(uidAidl));
    Mutex::Autolock _l(mLock);
    mUidPolicy->setAssistantUid(uid);
    return Status::ok();
}

Status AudioPolicyService::setHotwordDetectionServiceUid(int32_t uidAidl)
{
    uid_t uid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(uidAidl));
    Mutex::Autolock _l(mLock);
    mUidPolicy->setHotwordDetectionServiceUid(uid);
    return Status::ok();
}

Status AudioPolicyService::setA11yServicesUids(const std::vector<int32_t>& uidsAidl)
{
    size_t size = uidsAidl.size();
    if (size > MAX_ITEMS_PER_LIST) {
        size = MAX_ITEMS_PER_LIST;
    }
    std::vector<uid_t> uids;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(uidsAidl.begin(),
                         uidsAidl.begin() + size,
                         std::back_inserter(uids),
                         aidl2legacy_int32_t_uid_t)));
    Mutex::Autolock _l(mLock);
    mUidPolicy->setA11yUids(uids);
    return Status::ok();
}

Status AudioPolicyService::setCurrentImeUid(int32_t uidAidl)
{
    uid_t uid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(uidAidl));
    Mutex::Autolock _l(mLock);
    mUidPolicy->setCurrentImeUid(uid);
    return Status::ok();
}

Status AudioPolicyService::isHapticPlaybackSupported(bool* _aidl_return)
{
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->isHapticPlaybackSupported();
    return Status::ok();
}

Status AudioPolicyService::listAudioProductStrategies(
        std::vector<media::AudioProductStrategy>* _aidl_return) {
    AudioProductStrategyVector strategies;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(mAudioPolicyManager->listAudioProductStrategies(strategies)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<media::AudioProductStrategy>>(
                    strategies,
                    legacy2aidl_AudioProductStrategy));
    return Status::ok();
}

Status AudioPolicyService::getProductStrategyFromAudioAttributes(
        const media::AudioAttributesEx& aaAidl, bool fallbackOnDefault, int32_t* _aidl_return) {
    AudioAttributes aa = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributesEx_AudioAttributes(aaAidl));
    product_strategy_t productStrategy;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getProductStrategyFromAudioAttributes(
                    aa, productStrategy, fallbackOnDefault)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_product_strategy_t_int32_t(productStrategy));
    return Status::ok();
}

Status AudioPolicyService::listAudioVolumeGroups(std::vector<media::AudioVolumeGroup>* _aidl_return)
{
    AudioVolumeGroupVector groups;
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(mAudioPolicyManager->listAudioVolumeGroups(groups)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<media::AudioVolumeGroup>>(groups,
                                                                   legacy2aidl_AudioVolumeGroup));
    return Status::ok();
}

Status AudioPolicyService::getVolumeGroupFromAudioAttributes(
        const media::AudioAttributesEx& aaAidl, bool fallbackOnDefault, int32_t* _aidl_return) {
    AudioAttributes aa = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributesEx_AudioAttributes(aaAidl));
    volume_group_t volumeGroup;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(
                    mAudioPolicyManager->getVolumeGroupFromAudioAttributes(
                            aa, volumeGroup, fallbackOnDefault)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_volume_group_t_int32_t(volumeGroup));
    return Status::ok();
}

Status AudioPolicyService::setRttEnabled(bool enabled)
{
    Mutex::Autolock _l(mLock);
    mUidPolicy->setRttEnabled(enabled);
    return Status::ok();
}

Status AudioPolicyService::isCallScreenModeSupported(bool* _aidl_return)
{
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->isCallScreenModeSupported();
    return Status::ok();
}

Status AudioPolicyService::setDevicesRoleForStrategy(
        int32_t strategyAidl,
        media::DeviceRole roleAidl,
        const std::vector<media::AudioDevice>& devicesAidl) {
    product_strategy_t strategy = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_product_strategy_t(strategyAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
    AudioDeviceTypeAddrVector devices = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<AudioDeviceTypeAddrVector>(devicesAidl,
                                                        aidl2legacy_AudioDeviceTypeAddress));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    return binderStatusFromStatusT(
            mAudioPolicyManager->setDevicesRoleForStrategy(strategy, role, devices));
}

Status AudioPolicyService::removeDevicesRoleForStrategy(int32_t strategyAidl,
                                                        media::DeviceRole roleAidl) {
     product_strategy_t strategy = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_product_strategy_t(strategyAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
   if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    return binderStatusFromStatusT(
            mAudioPolicyManager->removeDevicesRoleForStrategy(strategy, role));
}

Status AudioPolicyService::getDevicesForRoleAndStrategy(
        int32_t strategyAidl,
        media::DeviceRole roleAidl,
        std::vector<media::AudioDevice>* _aidl_return) {
    product_strategy_t strategy = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_product_strategy_t(strategyAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
    AudioDeviceTypeAddrVector devices;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getDevicesForRoleAndStrategy(strategy, role, devices)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<media::AudioDevice>>(devices,
                                                              legacy2aidl_AudioDeviceTypeAddress));
    return Status::ok();
}

Status AudioPolicyService::registerSoundTriggerCaptureStateListener(
        const sp<media::ICaptureStateListener>& listener, bool* _aidl_return) {
    *_aidl_return = mCaptureStateNotifier.RegisterListener(listener);
    return Status::ok();
}

Status AudioPolicyService::setDevicesRoleForCapturePreset(
        media::AudioSourceType audioSourceAidl,
        media::DeviceRole roleAidl,
        const std::vector<media::AudioDevice>& devicesAidl) {
    audio_source_t audioSource = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSourceType_audio_source_t(audioSourceAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
    AudioDeviceTypeAddrVector devices = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<AudioDeviceTypeAddrVector>(devicesAidl,
                                                        aidl2legacy_AudioDeviceTypeAddress));

    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    return binderStatusFromStatusT(
            mAudioPolicyManager->setDevicesRoleForCapturePreset(audioSource, role, devices));
}

Status AudioPolicyService::addDevicesRoleForCapturePreset(
        media::AudioSourceType audioSourceAidl,
        media::DeviceRole roleAidl,
        const std::vector<media::AudioDevice>& devicesAidl) {
    audio_source_t audioSource = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSourceType_audio_source_t(audioSourceAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
    AudioDeviceTypeAddrVector devices = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<AudioDeviceTypeAddrVector>(devicesAidl,
                                                        aidl2legacy_AudioDeviceTypeAddress));

    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    return binderStatusFromStatusT(
            mAudioPolicyManager->addDevicesRoleForCapturePreset(audioSource, role, devices));
}

Status AudioPolicyService::removeDevicesRoleForCapturePreset(
        media::AudioSourceType audioSourceAidl,
        media::DeviceRole roleAidl,
        const std::vector<media::AudioDevice>& devicesAidl) {
    audio_source_t audioSource = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSourceType_audio_source_t(audioSourceAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
    AudioDeviceTypeAddrVector devices = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<AudioDeviceTypeAddrVector>(devicesAidl,
                                                        aidl2legacy_AudioDeviceTypeAddress));

   if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    return binderStatusFromStatusT(
            mAudioPolicyManager->removeDevicesRoleForCapturePreset(audioSource, role, devices));
}

Status AudioPolicyService::clearDevicesRoleForCapturePreset(media::AudioSourceType audioSourceAidl,
                                                            media::DeviceRole roleAidl) {
    audio_source_t audioSource = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSourceType_audio_source_t(audioSourceAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));

    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    return binderStatusFromStatusT(
            mAudioPolicyManager->clearDevicesRoleForCapturePreset(audioSource, role));
}

Status AudioPolicyService::getDevicesForRoleAndCapturePreset(
        media::AudioSourceType audioSourceAidl,
        media::DeviceRole roleAidl,
        std::vector<media::AudioDevice>* _aidl_return) {
    audio_source_t audioSource = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSourceType_audio_source_t(audioSourceAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
    AudioDeviceTypeAddrVector devices;

    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    Mutex::Autolock _l(mLock);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getDevicesForRoleAndCapturePreset(audioSource, role, devices)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<media::AudioDevice>>(devices,
                                                              legacy2aidl_AudioDeviceTypeAddress));
    return Status::ok();
}

} // namespace android
