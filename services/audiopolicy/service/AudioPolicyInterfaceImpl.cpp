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

#define LOG_TAG "AudioPolicyInterfaceImpl"
//#define LOG_NDEBUG 0

#include "AudioPolicyService.h"
#include "AudioRecordClient.h"

#include <android/content/AttributionSourceState.h>
#include <android_media_audiopolicy.h>
#include <android_media_audio.h>
#include <binder/Enums.h>
#include <com_android_media_audio.h>
#include <cutils/properties.h>
#include <error/expected_utils.h>
#include <media/AidlConversion.h>
#include <media/AudioPermissionPolicy.h>
#include <media/AudioPolicy.h>
#include <media/AudioValidator.h>
#include <media/MediaMetricsItem.h>
#include <media/PolicyAidlConversion.h>
#include <utils/Log.h>

namespace audio_flags = android::media::audiopolicy;

#define CHECK_PERM(expr1, expr2) \
    VALUE_OR_RETURN_STATUS(getPermissionProvider().checkPermission((expr1), (expr2)))

#define PROPAGATE_FALSEY(val) do { if (!val.has_value() || !val.value()) return val; } while (0)

#define MAX_ITEMS_PER_LIST 1024

namespace android {
using binder::Status;
using aidl_utils::binderStatusFromStatusT;
using android::media::audio::concurrent_audio_record_bypass_permission;
using com::android::media::permission::NativePermissionController;
using com::android::media::permission::PermissionEnum;
using com::android::media::permission::PermissionEnum::ACCESS_ULTRASOUND;
using com::android::media::permission::PermissionEnum::CALL_AUDIO_INTERCEPTION;
using com::android::media::permission::PermissionEnum::CAPTURE_AUDIO_HOTWORD;
using com::android::media::permission::PermissionEnum::CAPTURE_VOICE_COMMUNICATION_OUTPUT;
using com::android::media::permission::PermissionEnum::CAPTURE_AUDIO_OUTPUT;
using com::android::media::permission::PermissionEnum::CAPTURE_MEDIA_OUTPUT;
using com::android::media::permission::PermissionEnum::CAPTURE_TUNER_AUDIO_INPUT;
using com::android::media::permission::PermissionEnum::MODIFY_AUDIO_ROUTING;
using com::android::media::permission::PermissionEnum::MODIFY_AUDIO_SETTINGS;
using com::android::media::permission::PermissionEnum::MODIFY_AUDIO_SETTINGS_PRIVILEGED;
using com::android::media::permission::PermissionEnum::MODIFY_DEFAULT_AUDIO_EFFECTS;
using com::android::media::permission::PermissionEnum::MODIFY_PHONE_STATE;
using com::android::media::permission::PermissionEnum::RECORD_AUDIO;
using com::android::media::permission::PermissionEnum::WRITE_SECURE_SETTINGS;
using com::android::media::permission::PermissionEnum::BLUETOOTH_CONNECT;
using com::android::media::permission::PermissionEnum::BYPASS_CONCURRENT_RECORD_AUDIO_RESTRICTION;
using content::AttributionSourceState;
using media::audio::common::AudioConfig;
using media::audio::common::AudioConfigBase;
using media::audio::common::AudioDevice;
using media::audio::common::AudioDeviceAddress;
using media::audio::common::AudioDeviceDescription;
using media::audio::common::AudioFormatDescription;
using media::audio::common::AudioMode;
using media::audio::common::AudioOffloadInfo;
using media::audio::common::AudioSource;
using media::audio::common::AudioStreamType;
using media::audio::common::AudioUsage;
using media::audio::common::AudioUuid;
using media::audio::common::Int;
using media::permission::isSystemUsage;

constexpr int kDefaultVirtualDeviceId = 0;
namespace {
constexpr auto PERMISSION_HARD_DENIED = permission::PermissionChecker::PERMISSION_HARD_DENIED;
constexpr auto PERMISSION_GRANTED = permission::PermissionChecker::PERMISSION_GRANTED;

bool mustAnonymizeBluetoothAddress(const AttributionSourceState& attributionSource,
                                   const IPermissionProvider& provider) {
    switch(multiuser_get_app_id(attributionSource.uid)) {
        // out of caution, to prevent regression
        case AID_ROOT:
        case AID_SYSTEM:
        case AID_AUDIOSERVER:
        case AID_RADIO:
        case AID_BLUETOOTH:
        case AID_MEDIA:
            return false;
    }
    const auto res = provider.checkPermission(BLUETOOTH_CONNECT, attributionSource.uid);
    if (res.has_value()) {
        return !(*res);
    } else {
        ALOGE("%s: error: %s", __func__, res.error().toString8().c_str());
        return true;
    }
}

}

bool AudioPolicyService::isSupportedSystemUsage(audio_usage_t usage) {
    return std::find(std::begin(mSupportedSystemUsages), std::end(mSupportedSystemUsages), usage)
        != std::end(mSupportedSystemUsages);
}

Status AudioPolicyService::validateUsage(const audio_attributes_t& attr) {
     return validateUsage(attr, getCallingAttributionSource());
}

Status AudioPolicyService::validateUsage(const audio_attributes_t& attr,
        const AttributionSourceState& attributionSource) {
    if (isSystemUsage(attr.usage)) {
        if (isSupportedSystemUsage(attr.usage)) {
            if (attr.usage == AUDIO_USAGE_CALL_ASSISTANT
                    && ((attr.flags & AUDIO_FLAG_CALL_REDIRECTION) != 0)) {
                if (!CHECK_PERM(CALL_AUDIO_INTERCEPTION, attributionSource.uid)) {
                    ALOGE("%s: call audio interception not allowed for attribution source: %s",
                           __func__, attributionSource.toString().c_str());
                    return Status::fromExceptionCode(Status::EX_SECURITY,
                            "Call audio interception not allowed");
                }
            } else if (!CHECK_PERM(MODIFY_AUDIO_ROUTING, attributionSource.uid)) {
                ALOGE("%s: modify audio routing not allowed for attribution source: %s",
                        __func__, attributionSource.toString().c_str());
                    return Status::fromExceptionCode(Status::EX_SECURITY,
                            "Modify audio routing not allowed");
            }
        } else {
            return Status::fromExceptionCode(Status::EX_ILLEGAL_ARGUMENT);
        }
    }
    return Status::ok();
}



// ----------------------------------------------------------------------------

void AudioPolicyService::doOnNewAudioModulesAvailable()
{
    if (mAudioPolicyManager == NULL) return;
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    mAudioPolicyManager->onNewAudioModulesAvailable();
}

Status AudioPolicyService::setDeviceConnectionState(
        media::AudioPolicyDeviceState stateAidl,
        const android::media::audio::common::AudioPort& port,
        const AudioFormatDescription& encodedFormatAidl,
        bool deviceSwitch) {
    audio_policy_dev_state_t state = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPolicyDeviceState_audio_policy_dev_state_t(stateAidl));
    audio_format_t encodedFormat = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioFormatDescription_audio_format_t(encodedFormatAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!CHECK_PERM(MODIFY_AUDIO_SETTINGS, IPCThreadState::self()->getCallingUid())) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (state != AUDIO_POLICY_DEVICE_STATE_AVAILABLE &&
            state != AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE) {
        return binderStatusFromStatusT(BAD_VALUE);
    }

    ALOGV("setDeviceConnectionState()");
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    status_t status = mAudioPolicyManager->setDeviceConnectionState(
            state, port, encodedFormat, deviceSwitch);
    if (status == NO_ERROR) {
        maybeCheckSpatializer_l();
    }
    return binderStatusFromStatusT(status);
}

Status AudioPolicyService::getDeviceConnectionState(const AudioDevice& deviceAidl,
                                                    media::AudioPolicyDeviceState* _aidl_return) {
    audio_devices_t device;
    std::string address;
    RETURN_BINDER_STATUS_IF_ERROR(
            aidl2legacy_AudioDevice_audio_device(deviceAidl, &device, &address));
    if (mAudioPolicyManager == NULL) {
        *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_policy_dev_state_t_AudioPolicyDeviceState(
                        AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE));
        return Status::ok();
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_policy_dev_state_t_AudioPolicyDeviceState(
                    mAudioPolicyManager->getDeviceConnectionState(
                            device, address.c_str())));
    return Status::ok();
}

Status AudioPolicyService::handleDeviceConfigChange(
        const AudioDevice& deviceAidl,
        const std::string& deviceNameAidl,
        const AudioFormatDescription& encodedFormatAidl) {
    audio_devices_t device;
    std::string address;
    RETURN_BINDER_STATUS_IF_ERROR(
            aidl2legacy_AudioDevice_audio_device(deviceAidl, &device, &address));
    audio_format_t encodedFormat = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioFormatDescription_audio_format_t(encodedFormatAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!CHECK_PERM(MODIFY_AUDIO_SETTINGS, IPCThreadState::self()->getCallingUid())) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    ALOGV("handleDeviceConfigChange()");
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    status_t status =  mAudioPolicyManager->handleDeviceConfigChange(
            device, address.c_str(), deviceNameAidl.c_str(), encodedFormat);

    if (status == NO_ERROR) {
       maybeCheckSpatializer_l();
    }
    return binderStatusFromStatusT(status);
}

Status AudioPolicyService::setPhoneState(AudioMode stateAidl, int32_t uidAidl)
{
    audio_mode_t state = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioMode_audio_mode_t(stateAidl));
    uid_t uid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(uidAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!CHECK_PERM(MODIFY_AUDIO_SETTINGS, IPCThreadState::self()->getCallingUid())) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (uint32_t(state) >= AUDIO_MODE_CNT) {
        return binderStatusFromStatusT(BAD_VALUE);
    }

    ALOGV("setPhoneState()");

    // acquire lock before calling setMode() so that setMode() + setPhoneState() are an atomic
    // operation from policy manager standpoint (no other operation (e.g track start or stop)
    // can be interleaved).
    audio_utils::lock_guard _l(mMutex);
    // TODO: check if it is more appropriate to do it in platform specific policy manager

    // Audio HAL mode conversion for call redirect modes
    audio_mode_t halMode = state;
    if (state == AUDIO_MODE_CALL_REDIRECT) {
        halMode = AUDIO_MODE_CALL_SCREEN;
    } else if (state == AUDIO_MODE_COMMUNICATION_REDIRECT) {
        halMode = AUDIO_MODE_NORMAL;
    }
    AudioSystem::setMode(halMode);

    AutoCallerClear acc;
    mAudioPolicyManager->setPhoneState(state);
    mPhoneState = state;
    mPhoneStateOwnerUid = uid;
    updateUidStates_l();
    return Status::ok();
}

Status AudioPolicyService::getPhoneState(AudioMode* _aidl_return) {
    audio_utils::lock_guard _l(mMutex);
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

    if (!CHECK_PERM(MODIFY_AUDIO_ROUTING, IPCThreadState::self()->getCallingUid())) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    if (usage < 0 || usage >= AUDIO_POLICY_FORCE_USE_CNT) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    if (config < 0 || config >= AUDIO_POLICY_FORCE_CFG_CNT) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    ALOGV("setForceUse()");
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    mAudioPolicyManager->setForceUse(usage, config);
    maybeCheckSpatializer_l();
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

Status AudioPolicyService::getOutput(AudioStreamType streamAidl, int32_t* _aidl_return)
{
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));

    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT
          && stream != AUDIO_STREAM_ASSISTANT && stream != AUDIO_STREAM_CALL_ASSISTANT) {
        *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_io_handle_t_int32_t(AUDIO_IO_HANDLE_NONE));
        return Status::ok();
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    ALOGV("getOutput()");
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_io_handle_t_int32_t(mAudioPolicyManager->getOutput(stream)));
    return Status::ok();
}

Status AudioPolicyService::getOutputForAttr(const media::audio::common::AudioAttributes& attrAidl,
                                            int32_t sessionAidl,
                                            const AttributionSourceState& attributionSource,
                                            const AudioConfig& configAidl,
                                            int32_t flagsAidl,
                                            const std::vector<int32_t>& selectedDeviceIdsAidl,
                                            media::GetOutputForAttrResponse* _aidl_return)
{
    audio_attributes_t attr = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl));
    audio_session_t session = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_session_t(sessionAidl));
    audio_stream_type_t stream = AUDIO_STREAM_DEFAULT;
    audio_config_t config = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioConfig_audio_config_t(configAidl, false /*isInput*/));
    audio_output_flags_t flags = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_output_flags_t_mask(flagsAidl));
    DeviceIdVector selectedDeviceIds = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<DeviceIdVector>(selectedDeviceIdsAidl,
                                             aidl2legacy_int32_t_audio_port_handle_t));

    audio_io_handle_t output;
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
    std::vector<audio_io_handle_t> secondaryOutputs;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }

    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(AudioValidator::validateAudioAttributes(attr, "68953950")));
    RETURN_IF_BINDER_ERROR(validateUsage(attr, attributionSource));

    ALOGV("%s()", __func__);
    const auto captureRes =
            getPermissionProvider().doesUidPermitPlaybackCapture(attributionSource.uid);
    if (!captureRes.ok()) {
        ALOGE("%s Failed to get playback capture flag for %d due to %s", __func__,
              attributionSource.uid, captureRes.error().toString8().c_str());
    }
    audio_utils::lock_guard _l(mMutex);
    if (!captureRes.value_or(false)) {
        attr.flags = static_cast<audio_flags_mask_t>(attr.flags | AUDIO_FLAG_NO_MEDIA_PROJECTION);
    }
    const bool bypassInterruptionAllowed = (
            CHECK_PERM(MODIFY_AUDIO_ROUTING, attributionSource.uid) ||
            CHECK_PERM(MODIFY_PHONE_STATE, attributionSource.uid) ||
            CHECK_PERM(WRITE_SECURE_SETTINGS, attributionSource.uid));

    if (((attr.flags & (AUDIO_FLAG_BYPASS_INTERRUPTION_POLICY|AUDIO_FLAG_BYPASS_MUTE)) != 0)
            && !bypassInterruptionAllowed) {
        attr.flags = static_cast<audio_flags_mask_t>(
                attr.flags & ~(AUDIO_FLAG_BYPASS_INTERRUPTION_POLICY|AUDIO_FLAG_BYPASS_MUTE));
    }

    if (attr.content_type == AUDIO_CONTENT_TYPE_ULTRASOUND) {
        if (!CHECK_PERM(ACCESS_ULTRASOUND, attributionSource.uid)) {
            ALOGE("%s: permission denied: ultrasound not allowed for uid %d pid %d",
                    __func__, attributionSource.uid, attributionSource.pid);
            return binderStatusFromStatusT(PERMISSION_DENIED);
        }
    }

    if (audio_is_system_usage(attr.usage)) {
        if (!CHECK_PERM(MODIFY_AUDIO_ROUTING, attributionSource.uid)) {
            ALOGE("%s: permission denied: Attribute %d not allowed for uid %d pid %d",
                    __func__, attr.usage, attributionSource.uid, attributionSource.pid);
            return binderStatusFromStatusT(PERMISSION_DENIED);
        }
    }

    if (strlen(attr.tags) != 0) {
        const bool audioAttributesTagsAllowed = (
                CHECK_PERM(MODIFY_AUDIO_SETTINGS_PRIVILEGED, attributionSource.uid) ||
                CHECK_PERM(MODIFY_AUDIO_ROUTING, attributionSource.uid) ||
                CHECK_PERM(CALL_AUDIO_INTERCEPTION, attributionSource.uid) ||
                CHECK_PERM(CAPTURE_MEDIA_OUTPUT, attributionSource.uid) ||
                CHECK_PERM(CAPTURE_VOICE_COMMUNICATION_OUTPUT, attributionSource.uid));
        if (!audioAttributesTagsAllowed) {
            ALOGE("%s: permission denied: audio attributes tags not allowed for uid %d pid %d",
                  __func__, attributionSource.uid, attributionSource.pid);
            return binderStatusFromStatusT(PERMISSION_DENIED);
        }
    }

    AutoCallerClear acc;
    AudioPolicyInterface::output_type_t outputType;
    bool isSpatialized = false;
    bool isBitPerfect = false;
    status_t result = mAudioPolicyManager->getOutputForAttr(&attr, &output, session,
                                                            &stream,
                                                            attributionSource,
                                                            &config,
                                                            &flags, &selectedDeviceIds, &portId,
                                                            &secondaryOutputs,
                                                            &outputType,
                                                            &isSpatialized,
                                                            &isBitPerfect);

    // FIXME: Introduce a way to check for the the telephony device before opening the output
    if (result == NO_ERROR) {
        // enforce permission (if any) required for each type of input
        switch (outputType) {
        case AudioPolicyInterface::API_OUTPUT_LEGACY:
            break;
        case AudioPolicyInterface::API_OUTPUT_TELEPHONY_TX:
            if (((attr.flags & AUDIO_FLAG_CALL_REDIRECTION) != 0)
                && !CHECK_PERM(CALL_AUDIO_INTERCEPTION, attributionSource.uid)) {
                ALOGE("%s() permission denied: call redirection not allowed for uid %d",
                    __func__, attributionSource.uid);
                result = PERMISSION_DENIED;
            } else if (!CHECK_PERM(MODIFY_PHONE_STATE, attributionSource.uid)) {
                ALOGE("%s() permission denied: modify phone state not allowed for uid %d",
                    __func__, attributionSource.uid);
                result = PERMISSION_DENIED;
            }
            break;
        case AudioPolicyInterface::API_OUT_MIX_PLAYBACK:
            if (!CHECK_PERM(MODIFY_AUDIO_ROUTING, attributionSource.uid)) {
                ALOGE("%s() permission denied: modify audio routing not allowed for uid %d",
                    __func__, attributionSource.uid);
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
        // usecase validator is disabled by default
        if (property_get_bool("ro.audio.usecase_validator_enabled", false /* default */)) {
                attr = VALUE_OR_RETURN_BINDER_STATUS(
                        mUsecaseValidator->verifyAudioAttributes(output, attributionSource, attr));
        }

        sp<AudioPlaybackClient> client =
                new AudioPlaybackClient(attr, output, attributionSource, session,
                    portId, selectedDeviceIds, stream, isSpatialized, config.channel_mask);
        mAudioPlaybackClients.add(portId, client);

        _aidl_return->output = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_io_handle_t_int32_t(output));
        _aidl_return->stream = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_stream_type_t_AudioStreamType(stream));
        _aidl_return->selectedDeviceIds = VALUE_OR_RETURN_BINDER_STATUS(
                convertContainer<std::vector<int32_t>>(selectedDeviceIds,
                                                       legacy2aidl_audio_port_handle_t_int32_t));
        _aidl_return->portId = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_port_handle_t_int32_t(portId));
        _aidl_return->secondaryOutputs = VALUE_OR_RETURN_BINDER_STATUS(
                convertContainer<std::vector<int32_t>>(secondaryOutputs,
                                                       legacy2aidl_audio_io_handle_t_int32_t));
        _aidl_return->isSpatialized = isSpatialized;
        _aidl_return->isBitPerfect = isBitPerfect;
        _aidl_return->attr = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_attributes_t_AudioAttributes(attr));
    } else {
        _aidl_return->configBase.format = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_format_t_AudioFormatDescription(config.format));
        _aidl_return->configBase.channelMask = VALUE_OR_RETURN_BINDER_STATUS(
                legacy2aidl_audio_channel_mask_t_AudioChannelLayout(
                        config.channel_mask, false /*isInput*/));
        _aidl_return->configBase.sampleRate = config.sample_rate;
    }
    return binderStatusFromStatusT(result);
}

void AudioPolicyService::getPlaybackClientAndEffects(audio_port_handle_t portId,
                                                     sp<AudioPlaybackClient>& client,
                                                     sp<AudioPolicyEffects>& effects,
                                                     const char *context)
{
    audio_utils::lock_guard _l(mMutex);
    const ssize_t index = mAudioPlaybackClients.indexOfKey(portId);
    if (index < 0) {
        ALOGE("%s AudioTrack client not found for portId %d", context, portId);
        return;
    }
    client = mAudioPlaybackClients.valueAt(index);
    effects = mAudioPolicyEffects;
}

void AudioPolicyService::getPlaybackClientsAndEffects(
        audio_io_handle_t io,
        std::vector<sp<AudioPlaybackClient>>& clients,
        sp<AudioPolicyEffects>& effects,
        const char *context)
{
    audio_utils::lock_guard _l(mMutex);
    for (size_t i = 0; i < mAudioPlaybackClients.size(); i++) {
        auto client = mAudioPlaybackClients.valueAt(i);
        if (client->io == io) {
            clients.push_back(client);
        }
    }
    ALOGI_IF(clients.empty(), "%s no AudioTrack clients found for the IO handle %d", context, io);
    effects = mAudioPolicyEffects;
}

Status AudioPolicyService::startOutput(
        int32_t portIdAidl, media::StartOutputResponse* _aidl_return)
{
    audio_port_handle_t portId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portIdAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    ALOGV("startOutput()");
    sp<AudioPlaybackClient> client;
    sp<AudioPolicyEffects> audioPolicyEffects;

    getPlaybackClientAndEffects(portId, client, audioPolicyEffects, __func__);

    if (audioPolicyEffects != 0) {
        // create audio processors according to stream
        status_t status = audioPolicyEffects->addOutputSessionEffects(client->io, client->stream,
                                                                      client->session);
        if (status != NO_ERROR && status != ALREADY_EXISTS) {
            ALOGW("Failed to add effects on session %d", client->session);
        }
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    float volume;
    bool muted;
    status_t status = mAudioPolicyManager->startOutput(portId, &volume, &muted);
    if (status == NO_ERROR) {
        //TODO b/257922898: decide if/how we need to handle attributes update when playback starts
        // or during playback
        (void)mUsecaseValidator->startClient(client->io, client->portId, client->attributionSource,
                client->attributes, nullptr /* callback */);
        client->active = true;
        onUpdateActiveSpatializerTracks_l();
        _aidl_return->volume = volume;
        _aidl_return->muted = muted;
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

    if (client != nullptr && audioPolicyEffects != nullptr) {
        // release audio processors from the stream
        status_t status = audioPolicyEffects->releaseOutputSessionEffects(
            client->io, client->stream, client->session);
        if (status != NO_ERROR && status != ALREADY_EXISTS) {
            ALOGW("Failed to release effects on session %d", client->session);
        }
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    status_t status = mAudioPolicyManager->stopOutput(portId);
    if (status == NO_ERROR) {
        if (client != nullptr) client->active = false;
        onUpdateActiveSpatializerTracks_l();
        if (client != nullptr) mUsecaseValidator->stopClient(client->io, client->portId);
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

    if (audioPolicyEffects != nullptr && client != nullptr && client->active) {
        // clean up effects if output was not stopped before being released
        audioPolicyEffects->releaseOutputSessionEffects(
            client->io, client->stream, client->session);
    }
    audio_utils::lock_guard _l(mMutex);
    if (client != nullptr && client->active) {
        onUpdateActiveSpatializerTracks_l();
    }
    mAudioPlaybackClients.removeItem(portId);
    // called from internal thread: no need to clear caller identity
    mAudioPolicyManager->releaseOutput(portId);
}

Status AudioPolicyService::forceReleaseDirectOutput(int32_t outputIdAidl)
{
    audio_port_handle_t outputId =
            VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_audio_io_handle_t(outputIdAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    ALOGV("forceReleaseDirectOutput()");
    return binderStatusFromStatusT(mOutputCommandThread->forceReleaseDirectOutputCommand(outputId));
}

status_t AudioPolicyService::doForceReleaseDirectOutput(audio_io_handle_t outputId)
{
    ALOGV("doForceReleaseDirectOutput from tid %d", gettid());
    std::vector<sp<AudioPlaybackClient>> clients;
    sp<AudioPolicyEffects> audioPolicyEffects;

    getPlaybackClientsAndEffects(outputId, clients, audioPolicyEffects, __func__);

    bool hasOneActiveClient = false;
    std::vector<audio_port_handle_t> portIds;
    portIds.reserve(clients.size());
    for (const auto& client : clients) {
        if (client->active) hasOneActiveClient = true;
        portIds.push_back(client->portId);
        if (audioPolicyEffects != nullptr && client->active) {
            // clean up effects if output was not stopped before being released
            audioPolicyEffects->releaseOutputSessionEffects(
                    client->io, client->stream, client->session);
        }
    }
    audio_utils::lock_guard _l(mMutex);
    if (hasOneActiveClient) {
        onUpdateActiveSpatializerTracks_l();
    }
    for (const auto portId : portIds) {
        mAudioPlaybackClients.removeItem(portId);
    }

    // called from internal thread: no need to clear caller identity
    return mAudioPolicyManager->forceReleaseDirectOutput(outputId);
}

// These are sources for which CAPTURE_AUDIO_OUTPUT granted access
// for legacy reasons, before more specific permissions were deployed.
// TODO: remove this access
static bool isLegacyOutputSource(AudioSource source) {
    switch (source) {
        case AudioSource::VOICE_CALL:
        case AudioSource::VOICE_DOWNLINK:
        case AudioSource::VOICE_UPLINK:
        case AudioSource::FM_TUNER:
            return true;
        default:
            return false;
    }
}

error::BinderResult<bool> AudioPolicyService::AudioPolicyClient::checkPermissionForInput(
        const AttributionSourceState& attrSource, const PermissionReqs& req) {

    error::BinderResult<bool> permRes = true;
    const auto check_perm = [&](PermissionEnum perm, uid_t uid) {
        return mAudioPolicyService->getPermissionProvider().checkPermission(perm, uid);
    };
    switch (req.source) {
        case AudioSource::VOICE_UPLINK:
        case AudioSource::VOICE_DOWNLINK:
        case AudioSource::VOICE_CALL:
            permRes = check_perm(CALL_AUDIO_INTERCEPTION, attrSource.uid);
            break;
        case AudioSource::ECHO_REFERENCE:
            permRes = check_perm(CAPTURE_AUDIO_OUTPUT, attrSource.uid);
            break;
        case AudioSource::FM_TUNER:
            permRes = check_perm(CAPTURE_TUNER_AUDIO_INPUT, attrSource.uid);
            break;
        case AudioSource::HOTWORD:
            permRes = check_perm(CAPTURE_AUDIO_HOTWORD, attrSource.uid);
            break;
        case AudioSource::ULTRASOUND:
            permRes = check_perm(ACCESS_ULTRASOUND, attrSource.uid);
            break;
        case AudioSource::SYS_RESERVED_INVALID:
        case AudioSource::DEFAULT:
        case AudioSource::MIC:
        case AudioSource::CAMCORDER:
        case AudioSource::VOICE_RECOGNITION:
        case AudioSource::VOICE_COMMUNICATION:
        case AudioSource::UNPROCESSED:
        case AudioSource::VOICE_PERFORMANCE:
            // No additional check intended
        case AudioSource::REMOTE_SUBMIX:
            // special-case checked based on mix type below
            break;
    }

    if (!permRes.has_value()) return permRes;
    if (!permRes.value()) {
        if (isLegacyOutputSource(req.source)) {
            permRes = check_perm(CAPTURE_AUDIO_OUTPUT, attrSource.uid);
            PROPAGATE_FALSEY(permRes);
        } else {
            return false;
        }
    }

    if (req.isHotword) {
        permRes = check_perm(CAPTURE_AUDIO_HOTWORD, attrSource.uid);
        PROPAGATE_FALSEY(permRes);
    }

    // TODO evaluate whether we should be checking call redirection like this
    bool isAllowedDueToCallPerm = false;
    if (req.isCallRedir) {
        const auto checkCall = check_perm(CALL_AUDIO_INTERCEPTION, attrSource.uid);
        isAllowedDueToCallPerm = VALUE_OR_RETURN(checkCall);
    }

    switch (req.mixType) {
        case MixType::NONE:
            break;
        case MixType::PUBLIC_CAPTURE_PLAYBACK:
            // this use case has been validated in audio service with a MediaProjection token,
            // and doesn't rely on regular permissions
            // TODO (b/378778313)
            break;
        case MixType::TELEPHONY_RX_CAPTURE:
            if (isAllowedDueToCallPerm) break;
            // FIXME: use the same permission as for remote submix for now.
            FALLTHROUGH_INTENDED;
        case MixType::CAPTURE:
            permRes = check_perm(CAPTURE_AUDIO_OUTPUT, attrSource.uid);
            break;
        case MixType::EXT_POLICY_REROUTE:
            // TODO intended?
            if (isAllowedDueToCallPerm) break;
            permRes = check_perm(MODIFY_AUDIO_ROUTING, attrSource.uid);
            break;
    }

    PROPAGATE_FALSEY(permRes);

    // All sources which aren't output capture
    // AND capture from vdi policy mix (the injected audio is mic data from another device)
    // REQUIRE RECORD perms
    const auto legacySource = aidl2legacy_AudioSource_audio_source_t(req.source).value();
    if (req.virtualDeviceId != kDefaultVirtualDeviceId) {
        // TODO assert that this is always a recordOpSource
        // TODO upcall solution
        return recordingAllowed(attrSource, req.virtualDeviceId, legacySource);
    }

    if (isRecordOpRequired(legacySource)) {
        permRes = check_perm(RECORD_AUDIO, attrSource.uid);
        PROPAGATE_FALSEY(permRes);
    }
    return true;
}

Status AudioPolicyService::getInputForAttr(const media::audio::common::AudioAttributes& attrAidl,
                                           int32_t inputAidl,
                                           int32_t riidAidl,
                                           int32_t sessionAidl,
                                           const AttributionSourceState& attributionSource,
                                           const AudioConfigBase& configAidl,
                                           int32_t flagsAidl,
                                           int32_t selectedDeviceIdAidl,
                                           media::GetInputForAttrResponse* _aidl_return) {
    auto inputSource = attrAidl.source;
    const audio_attributes_t attr = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl));
    const audio_io_handle_t requestedInput = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_io_handle_t(inputAidl));
    const audio_unique_id_t riid = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_unique_id_t(riidAidl));
    const audio_session_t session = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_session_t(sessionAidl));
    const audio_config_base_t config = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioConfigBase_audio_config_base_t(configAidl, true /*isInput*/));
    const audio_input_flags_t flags = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_input_flags_t_mask(flagsAidl));
    const audio_port_handle_t requestedDeviceId = VALUE_OR_RETURN_BINDER_STATUS(
                aidl2legacy_int32_t_audio_port_handle_t(selectedDeviceIdAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }

    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(AudioValidator::validateAudioAttributes(attr, "68953950")));

    if (inputSource == AudioSource::SYS_RESERVED_INVALID ||
            std::find(enum_range<AudioSource>().begin(), enum_range<AudioSource>().end(),
                inputSource) == enum_range<AudioSource>().end()) {
        return binderStatusFromStatusT(BAD_VALUE);
    }

    if (inputSource == AudioSource::DEFAULT) {
        inputSource = AudioSource::MIC;
    }

    //TODO(b/374751406): remove forcing canBypassConcurrentPolicy to canCaptureOutput
    // once all system apps using CAPTURE_AUDIO_OUTPUT to capture during calls
    // are updated to use the new BYPASS_CONCURRENT_RECORD_AUDIO_RESTRICTION permission.
    bool canBypassConcurrentPolicy = CHECK_PERM(CAPTURE_AUDIO_OUTPUT, attributionSource.uid);
    if (concurrent_audio_record_bypass_permission()) {
        // TODO(b/374751406): allow either capture output or bypass permission until
        // all system apps have migrated to new permission.
        canBypassConcurrentPolicy |=
                CHECK_PERM(BYPASS_CONCURRENT_RECORD_AUDIO_RESTRICTION, attributionSource.uid);
    }

    sp<AudioPolicyEffects> audioPolicyEffects;
    base::expected<media::GetInputForAttrResponse, std::variant<binder::Status, AudioConfigBase>>
            res;
    {
        audio_utils::lock_guard _l(mMutex);
        AutoCallerClear acc;
        // the audio_in_acoustics_t parameter is ignored by get_input()
        res = mAudioPolicyManager->getInputForAttr(attr, requestedInput, requestedDeviceId,
                                                   config, flags, riid, session,
                                                   attributionSource);
        if (!res.has_value()) {
            if (res.error().index() == 1) {
                _aidl_return->config = std::get<1>(res.error());
                return Status::fromExceptionCode(EX_ILLEGAL_STATE);
            } else {
                return std::get<0>(res.error());
            }
        }

        audioPolicyEffects = mAudioPolicyEffects;

        // For app compat, apps which targetSdk below 34 can continue unsilenced recording when they
        // move to a bkgd UID state.
        const bool shouldExemptFgSilencing =
                getPermissionProvider()
                        .getHighestTargetSdkForUid(attributionSource.uid)
                        .value_or(1000) < __ANDROID_API_U__;
        sp<AudioRecordClient> client = new AudioRecordClient(
                attr, res->input, session, res->portId, {res->selectedDeviceId}, attributionSource,
                res->virtualDeviceId, canBypassConcurrentPolicy, shouldExemptFgSilencing,
                mOutputCommandThread);
        mAudioRecordClients.add(res->portId, client);
    }

    if (audioPolicyEffects != nullptr) {
        // create audio pre processors according to input source
        status_t status = audioPolicyEffects->addInputEffects(res->input,
                aidl2legacy_AudioSource_audio_source_t(inputSource).value(), session);
        if (status != NO_ERROR && status != ALREADY_EXISTS) {
            ALOGW("Failed to add effects on input %d", res->input);
        }
    }

    *_aidl_return = res.value();

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

std::string AudioPolicyService::getDeviceTypeStrForPortIds(DeviceIdVector portIds) {
    std::string output = {};
    for (auto it = portIds.begin(); it != portIds.end(); ++it) {
        if (it != portIds.begin()) {
            output += ", ";
        }
        output += getDeviceTypeStrForPortId(*it);
    }
    return output;
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
        audio_utils::lock_guard _l(mMutex);

        ssize_t index = mAudioRecordClients.indexOfKey(portId);
        if (index < 0) {
            return binderStatusFromStatusT(INVALID_OPERATION);
        }
        client = mAudioRecordClients.valueAt(index);
    }

    std::stringstream msg;
    msg << "Audio recording on session " << client->session;

    const auto permitted = startRecording(client->attributionSource, client->virtualDeviceId,
            String16(msg.str().c_str()), client->attributes.source);

    // check calling permissions
    if (permitted == PERMISSION_HARD_DENIED) {
        ALOGE("%s permission denied: recording not allowed for attribution source %s",
                __func__, client->attributionSource.toString().c_str());
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    audio_utils::lock_guard _l(mMutex);

    ALOGW_IF(client->silenced, "startInput on silenced input for port %d, uid %d. Unsilencing.",
            portIdAidl,
            client->attributionSource.uid);

    if (client->active) {
        ALOGE("Client should never be active before startInput. Uid %d port %d",
                client->attributionSource.uid, portId);
        finishRecording(client->attributionSource, client->virtualDeviceId,
                        client->attributes.source);
        return binderStatusFromStatusT(INVALID_OPERATION);
    }

    // Force the possibly silenced client to match the state on the appops side
    // following the call to startRecording (i.e. unsilenced iff call succeeded)
    // At this point in time, the client is inactive, so no calls to appops are
    // sent in setAppState_l. This ensures existing clients have the same
    // behavior as new clients.
    // TODO(b/282076713)
    if (permitted == PERMISSION_GRANTED) {
        setAppState_l(client, APP_STATE_TOP);
    } else {
        setAppState_l(client, APP_STATE_IDLE);
    }

    client->active = true;
    client->startTimeNs = systemTime();
    // This call updates the silenced state, and since we are active, appropriately notifies appops
    // if we silence the track.
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
        static constexpr char kAudioPolicyActiveDevices[] =
                "android.media.audiopolicy.active.devices";

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
            item->setCString(kAudioPolicyRqstDevice,
                    getDeviceTypeStrForPortId(getFirstDeviceId(client->deviceIds)).c_str());

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
                            getDeviceTypeStrForPortId(getFirstDeviceId(other->deviceIds)).c_str());
                    item->setCString(kAudioPolicyActiveDevices,
                            getDeviceTypeStrForPortIds(other->deviceIds).c_str());
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
        if (!client->silenced) {
            finishRecording(client->attributionSource, client->virtualDeviceId,
                    client->attributes.source);
        }
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

    audio_utils::lock_guard _l(mMutex);

    ssize_t index = mAudioRecordClients.indexOfKey(portId);
    if (index < 0) {
        return binderStatusFromStatusT(INVALID_OPERATION);
    }
    sp<AudioRecordClient> client = mAudioRecordClients.valueAt(index);

    client->active = false;
    client->startTimeNs = 0;

    updateUidStates_l();

    // finish the recording app op
    if (!client->silenced) {
        finishRecording(client->attributionSource, client->virtualDeviceId,
                client->attributes.source);
    }

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
        audio_utils::lock_guard _l(mMutex);
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
        audio_utils::lock_guard _l(mMutex);
        AutoCallerClear acc;
        mAudioPolicyManager->releaseInput(portId);
    }
    return Status::ok();
}

Status AudioPolicyService::setDeviceAbsoluteVolumeEnabled(const AudioDevice& deviceAidl,
                                                          bool enabled,
                                                          AudioStreamType streamToDriveAbsAidl) {
    ALOGI("%s: deviceAidl %s, enabled %d, streamToDriveAbsAidl %d", __func__,
          deviceAidl.toString().c_str(), enabled, streamToDriveAbsAidl);

    audio_stream_type_t streamToDriveAbs = AUDIO_STREAM_DEFAULT;
    if (enabled) {
        streamToDriveAbs = VALUE_OR_RETURN_BINDER_STATUS(
                aidl2legacy_AudioStreamType_audio_stream_type_t(streamToDriveAbsAidl));
    }

    audio_devices_t deviceType;
    std::string address;
    RETURN_BINDER_STATUS_IF_ERROR(
            aidl2legacy_AudioDevice_audio_device(deviceAidl, &deviceType, &address));

    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!CHECK_PERM(MODIFY_AUDIO_SETTINGS, IPCThreadState::self()->getCallingUid())) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    return binderStatusFromStatusT(
            mAudioPolicyManager->setDeviceAbsoluteVolumeEnabled(deviceType, address.c_str(),
                                                                enabled, streamToDriveAbs));
}

Status AudioPolicyService::initStreamVolume(AudioStreamType streamAidl,
                                            int32_t indexMinAidl,
                                            int32_t indexMaxAidl) {
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));
    int indexMin = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexMinAidl));
    int indexMax = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexMaxAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!CHECK_PERM(MODIFY_AUDIO_SETTINGS, IPCThreadState::self()->getCallingUid())) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    mAudioPolicyManager->initStreamVolume(stream, indexMin, indexMax);
    return binderStatusFromStatusT(NO_ERROR);
}

Status AudioPolicyService::setStreamVolumeIndex(AudioStreamType streamAidl,
                                                const AudioDeviceDescription& deviceAidl,
                                                int32_t indexAidl, bool muted) {
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));
    int index = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexAidl));
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioDeviceDescription_audio_devices_t(deviceAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!CHECK_PERM(MODIFY_AUDIO_SETTINGS, IPCThreadState::self()->getCallingUid())) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->setStreamVolumeIndex(stream,
                                                                             index,
                                                                             muted,
                                                                             device));
}

Status AudioPolicyService::getStreamVolumeIndex(AudioStreamType streamAidl,
                                                const AudioDeviceDescription& deviceAidl,
                                                int32_t* _aidl_return) {
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioDeviceDescription_audio_devices_t(deviceAidl));
    int index;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (uint32_t(stream) >= AUDIO_STREAM_PUBLIC_CNT) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getStreamVolumeIndex(stream, &index, device)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(index));
    return Status::ok();
}

Status AudioPolicyService::setVolumeIndexForAttributes(
        const media::audio::common::AudioAttributes& attrAidl,
        const AudioDeviceDescription& deviceAidl, int32_t indexAidl, bool muted) {
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl));
    int index = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexAidl));
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioDeviceDescription_audio_devices_t(deviceAidl));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioAttributes(attributes, "169572641")));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (!CHECK_PERM(MODIFY_AUDIO_SETTINGS, IPCThreadState::self()->getCallingUid())) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    return binderStatusFromStatusT(
            mAudioPolicyManager->setVolumeIndexForAttributes(attributes, index, muted, device));
}

Status AudioPolicyService::getVolumeIndexForAttributes(
        const media::audio::common::AudioAttributes& attrAidl,
        const AudioDeviceDescription& deviceAidl, int32_t* _aidl_return) {
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl));
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioDeviceDescription_audio_devices_t(deviceAidl));
    int index;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioAttributes(attributes, "169572641")));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getVolumeIndexForAttributes(attributes, index, device)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(index));
    return Status::ok();
}

Status AudioPolicyService::getMinVolumeIndexForAttributes(
        const media::audio::common::AudioAttributes& attrAidl, int32_t* _aidl_return) {
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl));
    int index;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioAttributes(attributes, "169572641")));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getMinVolumeIndexForAttributes(attributes, index)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(index));
    return Status::ok();
}

Status AudioPolicyService::getMaxVolumeIndexForAttributes(
        const media::audio::common::AudioAttributes& attrAidl, int32_t* _aidl_return) {
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl));
    int index;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioAttributes(attributes, "169572641")));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getMaxVolumeIndexForAttributes(attributes, index)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(index));
    return Status::ok();
}

Status AudioPolicyService::setVolumeIndexForGroup(int32_t groupIdAidl,
        const AudioDeviceDescription& deviceAidl, int32_t indexAidl, bool muted) {
    volume_group_t groupId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_volume_group_t(groupIdAidl));
    int index = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexAidl));
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioDeviceDescription_audio_devices_t(deviceAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    return binderStatusFromStatusT(
            mAudioPolicyManager->setVolumeIndexForGroup(groupId, index, muted, device));
}

Status AudioPolicyService::getVolumeIndexForGroup(
        int32_t groupIdAidl, const AudioDeviceDescription& deviceAidl, int32_t* _aidl_return) {
    volume_group_t groupId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_volume_group_t(groupIdAidl));
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioDeviceDescription_audio_devices_t(deviceAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    int index;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getVolumeIndexForGroup(groupId, index, device)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(index));
    return Status::ok();
}

Status AudioPolicyService::getMinVolumeIndexForGroup(int32_t groupIdAidl, int32_t* _aidl_return) {
    volume_group_t groupId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_volume_group_t(groupIdAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    int index;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getMinVolumeIndexForGroup(groupId, index)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(index));
    return Status::ok();
}


Status AudioPolicyService::setMinVolumeIndexForGroup(int32_t groupIdAidl, int32_t indexAidl) {
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    volume_group_t groupId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_volume_group_t(groupIdAidl));
    int index = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexAidl));
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->setMinVolumeIndexForGroup(groupId, index));
}

Status AudioPolicyService::getMaxVolumeIndexForGroup(int32_t groupIdAidl, int32_t* _aidl_return) {
    volume_group_t groupId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_volume_group_t(groupIdAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    int index;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getMaxVolumeIndexForGroup(groupId, index)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(index));
    return Status::ok();
}

Status AudioPolicyService::setMaxVolumeIndexForGroup(int32_t groupIdAidl, int32_t indexAidl) {
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    volume_group_t groupId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_volume_group_t(groupIdAidl));
    int index = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexAidl));
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->setMaxVolumeIndexForGroup(groupId, index));
}

Status AudioPolicyService::getStrategyForStream(AudioStreamType streamAidl,
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

Status AudioPolicyService::getDevicesForAttributes(
        const media::audio::common::AudioAttributes& attrAidl,
        bool forVolume,
        std::vector<AudioDevice>* _aidl_return)
{
    audio_attributes_t aa = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl));
    AudioDeviceTypeAddrVector devices;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getDevicesForAttributes(aa, &devices, forVolume)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<AudioDevice>>(devices,
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
    audio_utils::lock_guard _l(mMutex);
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
    audio_utils::lock_guard _l(mMutex);
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
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->unregisterEffect(id));
}

Status AudioPolicyService::setEffectEnabled(int32_t idAidl, bool enabled)
{
    int id = VALUE_OR_RETURN_BINDER_STATUS(convertReinterpret<int>(idAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
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
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->moveEffectsToIo(ids, io));
}

Status AudioPolicyService::isStreamActive(AudioStreamType streamAidl, int32_t inPastMsAidl,
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
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->isStreamActive(stream, inPastMs);
    return Status::ok();
}

Status AudioPolicyService::isStreamActiveRemotely(AudioStreamType streamAidl,
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
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->isStreamActiveRemotely(stream, inPastMs);
    return Status::ok();
}

Status AudioPolicyService::isSourceActive(AudioSource sourceAidl, bool* _aidl_return) {
    audio_source_t source = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSource_audio_source_t(sourceAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
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
        audio_utils::lock_guard _l(mMutex);
        audioPolicyEffects = mAudioPolicyEffects;
    }
    if (audioPolicyEffects == 0) {
        return NO_INIT;
    }

    return OK;
}

Status AudioPolicyService::queryDefaultPreProcessing(
        int32_t audioSessionAidl,
        Int* countAidl,
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

Status AudioPolicyService::addSourceDefaultEffect(const AudioUuid& typeAidl,
                                                  const std::string& opPackageNameAidl,
                                                  const AudioUuid& uuidAidl,
                                                  int32_t priority,
                                                  AudioSource sourceAidl,
                                                  int32_t* _aidl_return) {
    effect_uuid_t type = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioUuid_audio_uuid_t(typeAidl));
    String16 opPackageName = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_string_view_String16(opPackageNameAidl));
    effect_uuid_t uuid = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioUuid_audio_uuid_t(uuidAidl));
    audio_source_t source = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSource_audio_source_t(sourceAidl));
    audio_unique_id_t id;

    sp<AudioPolicyEffects>audioPolicyEffects;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(getAudioPolicyEffects(audioPolicyEffects)));
    if (!CHECK_PERM(MODIFY_DEFAULT_AUDIO_EFFECTS, IPCThreadState::self()->getCallingUid())) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(audioPolicyEffects->addSourceDefaultEffect(
            &type, opPackageName, &uuid, priority, source, &id)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_audio_unique_id_t_int32_t(id));
    return Status::ok();
}

Status AudioPolicyService::addStreamDefaultEffect(const AudioUuid& typeAidl,
                                                  const std::string& opPackageNameAidl,
                                                  const AudioUuid& uuidAidl,
                                                  int32_t priority, AudioUsage usageAidl,
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
    if (!CHECK_PERM(MODIFY_DEFAULT_AUDIO_EFFECTS, IPCThreadState::self()->getCallingUid())) {
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
    if (!CHECK_PERM(MODIFY_DEFAULT_AUDIO_EFFECTS, IPCThreadState::self()->getCallingUid())) {
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
    if (!CHECK_PERM(MODIFY_DEFAULT_AUDIO_EFFECTS, IPCThreadState::self()->getCallingUid())) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    return binderStatusFromStatusT(audioPolicyEffects->removeStreamDefaultEffect(id));
}

Status AudioPolicyService::setSupportedSystemUsages(
        const std::vector<AudioUsage>& systemUsagesAidl) {
    size_t size = systemUsagesAidl.size();
    if (size > MAX_ITEMS_PER_LIST) {
        size = MAX_ITEMS_PER_LIST;
    }
    std::vector<audio_usage_t> systemUsages;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(systemUsagesAidl.begin(), systemUsagesAidl.begin() + size,
                         std::back_inserter(systemUsages), aidl2legacy_AudioUsage_audio_usage_t)));

    audio_utils::lock_guard _l(mMutex);
    if (!CHECK_PERM(MODIFY_AUDIO_ROUTING, IPCThreadState::self()->getCallingUid())) {
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

    audio_utils::lock_guard _l(mMutex);
    if (mAudioPolicyManager == NULL) {
        ALOGV("%s() mAudioPolicyManager == NULL", __func__);
        return binderStatusFromStatusT(NO_INIT);
    }
    return binderStatusFromStatusT(
            mAudioPolicyManager->setAllowedCapturePolicy(uid, capturePolicy));
}

Status AudioPolicyService::getOffloadSupport(const AudioOffloadInfo& infoAidl,
                                             media::AudioOffloadMode* _aidl_return) {
    audio_offload_info_t info = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioOffloadInfo_audio_offload_info_t(infoAidl));
    if (mAudioPolicyManager == NULL) {
        ALOGV("mAudioPolicyManager == NULL");
        return binderStatusFromStatusT(AUDIO_OFFLOAD_NOT_SUPPORTED);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_audio_offload_mode_t_AudioOffloadMode(
            mAudioPolicyManager->getOffloadSupport(info)));
    return Status::ok();
}

Status AudioPolicyService::isDirectOutputSupported(
        const AudioConfigBase& configAidl,
        const media::audio::common::AudioAttributes& attributesAidl,
        bool* _aidl_return) {
    audio_config_base_t config = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioConfigBase_audio_config_base_t(configAidl, false /*isInput*/));
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attributesAidl));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioAttributes(attributes, "169572641")));

    if (mAudioPolicyManager == NULL) {
        ALOGV("mAudioPolicyManager == NULL");
        return binderStatusFromStatusT(NO_INIT);
    }

    RETURN_IF_BINDER_ERROR(validateUsage(attributes));

    audio_utils::lock_guard _l(mMutex);
    *_aidl_return = mAudioPolicyManager->isDirectOutputSupported(config, attributes);
    return Status::ok();
}

template <typename Port>
void anonymizePortBluetoothAddress(Port& port) {
    if (port.type != AUDIO_PORT_TYPE_DEVICE) {
        return;
    }
    if (!(audio_is_a2dp_device(port.ext.device.type)
            || audio_is_ble_device(port.ext.device.type)
            || audio_is_bluetooth_sco_device(port.ext.device.type)
            || audio_is_hearing_aid_out_device(port.ext.device.type))) {
        return;
    }
    anonymizeBluetoothAddress(port.ext.device.address);
}

Status AudioPolicyService::listAudioPorts(media::AudioPortRole roleAidl,
                                          media::AudioPortType typeAidl, Int* count,
                                          std::vector<media::AudioPortFw>* portsAidl,
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

    const AttributionSourceState attributionSource = getCallingAttributionSource();
    AutoCallerClear acc;
    {
        audio_utils::lock_guard _l(mMutex);
        if (mAudioPolicyManager == NULL) {
            return binderStatusFromStatusT(NO_INIT);
        }
        // AudioPolicyManager->listAudioPorts makes a deep copy of port structs into ports
        // so it is safe to access after releasing the mutex
        RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
                mAudioPolicyManager->listAudioPorts(
                        role, type, &num_ports, ports.get(), &generation)));
        numPortsReq = std::min(numPortsReq, num_ports);
    }

    if (mustAnonymizeBluetoothAddress(attributionSource, getPermissionProvider())) {
        for (size_t i = 0; i < numPortsReq; ++i) {
            anonymizePortBluetoothAddress(ports[i]);
        }
    }

    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(ports.get(), ports.get() + numPortsReq, std::back_inserter(*portsAidl),
                         legacy2aidl_audio_port_v7_AudioPortFw)));
    count->value = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(num_ports));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(generation));
    return Status::ok();
}

Status AudioPolicyService::listDeclaredDevicePorts(media::AudioPortRole role,
                                                    std::vector<media::AudioPortFw>* _aidl_return) {
    audio_utils::lock_guard _l(mMutex);
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->listDeclaredDevicePorts(
                    role, _aidl_return));
}

Status AudioPolicyService::getAudioPort(int portId,
                                        media::AudioPortFw* _aidl_return) {
    audio_port_v7 port{ .id = portId };

    const AttributionSourceState attributionSource = getCallingAttributionSource();
    AutoCallerClear acc;

    {
        audio_utils::lock_guard _l(mMutex);
        if (mAudioPolicyManager == NULL) {
            return binderStatusFromStatusT(NO_INIT);
        }
        // AudioPolicyManager->getAudioPort makes a deep copy of the port struct into port
        // so it is safe to access after releasing the mutex
        RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(mAudioPolicyManager->getAudioPort(&port)));
    }

    if (mustAnonymizeBluetoothAddress(attributionSource, getPermissionProvider())) {
        anonymizePortBluetoothAddress(port);
    }

    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_audio_port_v7_AudioPortFw(port));
    return Status::ok();
}

Status AudioPolicyService::createAudioPatch(const media::AudioPatchFw& patchAidl,
                                            int32_t handleAidl,
                                            int32_t* _aidl_return) {
    audio_patch patch = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPatchFw_audio_patch(patchAidl));
    audio_patch_handle_t handle = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(handleAidl));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(AudioValidator::validateAudioPatch(patch)));

    audio_utils::lock_guard _l(mMutex);
    if (!CHECK_PERM(MODIFY_AUDIO_ROUTING, IPCThreadState::self()->getCallingUid())) {
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
    audio_utils::lock_guard _l(mMutex);
    if (!CHECK_PERM(MODIFY_AUDIO_ROUTING, IPCThreadState::self()->getCallingUid())) {
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

Status AudioPolicyService::listAudioPatches(Int* count,
                                            std::vector<media::AudioPatchFw>* patchesAidl,
                                            int32_t* _aidl_return) {
    unsigned int num_patches = VALUE_OR_RETURN_BINDER_STATUS(
            convertIntegral<unsigned int>(count->value));
    if (num_patches > MAX_ITEMS_PER_LIST) {
        num_patches = MAX_ITEMS_PER_LIST;
    }
    unsigned int numPatchesReq = num_patches;
    std::unique_ptr<audio_patch[]> patches(new audio_patch[num_patches]);
    unsigned int generation;

    const AttributionSourceState attributionSource = getCallingAttributionSource();
    AutoCallerClear acc;

    {
        audio_utils::lock_guard _l(mMutex);
        if (mAudioPolicyManager == NULL) {
            return binderStatusFromStatusT(NO_INIT);
        }
        // AudioPolicyManager->listAudioPatches makes a deep copy of patches structs into patches
        // so it is safe to access after releasing the mutex
        RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
                mAudioPolicyManager->listAudioPatches(&num_patches, patches.get(), &generation)));
        numPatchesReq = std::min(numPatchesReq, num_patches);
    }

    if (mustAnonymizeBluetoothAddress(attributionSource, getPermissionProvider())) {
        for (size_t i = 0; i < numPatchesReq; ++i) {
            for (size_t j = 0; j < patches[i].num_sources; ++j) {
                anonymizePortBluetoothAddress(patches[i].sources[j]);
            }
            for (size_t j = 0; j < patches[i].num_sinks; ++j) {
                anonymizePortBluetoothAddress(patches[i].sinks[j]);
            }
        }
    }

    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(patches.get(), patches.get() + numPatchesReq,
                         std::back_inserter(*patchesAidl), legacy2aidl_audio_patch_AudioPatchFw)));
    count->value = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(num_patches));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int32_t>(generation));
    return Status::ok();
}

Status AudioPolicyService::setAudioPortConfig(const media::AudioPortConfigFw& configAidl)
{
    audio_port_config config = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPortConfigFw_audio_port_config(configAidl));
    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(AudioValidator::validateAudioPortConfig(config)));

    audio_utils::lock_guard _l(mMutex);
    if (!CHECK_PERM(MODIFY_AUDIO_ROUTING, IPCThreadState::self()->getCallingUid())) {
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
        audio_utils::lock_guard _l(mMutex);
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
            legacy2aidl_audio_devices_t_AudioDeviceDescription(device));
    return Status::ok();
}

Status AudioPolicyService::releaseSoundTriggerSession(int32_t sessionAidl)
{
    audio_session_t session = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_session_t(sessionAidl));
    audio_utils::lock_guard _l(mMutex);
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
    std::vector<AudioMix> mixes;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(mixesAidl.begin(), mixesAidl.begin() + size, std::back_inserter(mixes),
                         aidl2legacy_AudioMix)));

    audio_utils::lock_guard _l(mMutex);

    // loopback|render only need a MediaProjection (checked in caller AudioService.java)
    bool needModifyAudioRouting = std::any_of(mixes.begin(), mixes.end(), [](auto& mix) {
            return !is_mix_loopback_render(mix.mRouteFlags); });
    if (needModifyAudioRouting &&
            !CHECK_PERM(MODIFY_AUDIO_ROUTING, IPCThreadState::self()->getCallingUid())) {
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


    if (needCaptureMediaOutput && !CHECK_PERM(CAPTURE_MEDIA_OUTPUT, attributionSource.uid)) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }

    if (needCaptureVoiceCommunicationOutput
            && !CHECK_PERM(CAPTURE_VOICE_COMMUNICATION_OUTPUT, attributionSource.uid)) {
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

Status
AudioPolicyService::getRegisteredPolicyMixes(std::vector<::android::media::AudioMix>* mixesAidl) {
    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }

    std::vector<AudioMix> mixes;
    int status = mAudioPolicyManager->getRegisteredPolicyMixes(mixes);

    for (const auto& mix : mixes) {
        media::AudioMix aidlMix = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_AudioMix(mix));
        mixesAidl->push_back(aidlMix);
    }

    return binderStatusFromStatusT(status);
}

Status AudioPolicyService::updatePolicyMixes(
        const ::std::vector<::android::media::AudioMixUpdate>& updates) {
    audio_utils::lock_guard _l(mMutex);
    for (const auto& update : updates) {
        AudioMix mix = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_AudioMix(update.audioMix));
        std::vector<AudioMixMatchCriterion> newCriteria =
                VALUE_OR_RETURN_BINDER_STATUS(convertContainer<std::vector<AudioMixMatchCriterion>>(
                        update.newCriteria, aidl2legacy_AudioMixMatchCriterion));
        int status;
        if((status = mAudioPolicyManager->updatePolicyMix(mix, newCriteria)) != NO_ERROR) {
            return binderStatusFromStatusT(status);
        }
    }
    return binderStatusFromStatusT(NO_ERROR);
}

Status AudioPolicyService::setUidDeviceAffinities(
        int32_t uidAidl,
        const std::vector<AudioDevice>& devicesAidl) {
    uid_t uid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(uidAidl));
    AudioDeviceTypeAddrVector devices = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<AudioDeviceTypeAddrVector>(devicesAidl,
                                                        aidl2legacy_AudioDeviceTypeAddress));

    audio_utils::lock_guard _l(mMutex);
    if (!CHECK_PERM(MODIFY_AUDIO_ROUTING, IPCThreadState::self()->getCallingUid())) {
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

    audio_utils::lock_guard _l(mMutex);
    if (!CHECK_PERM(MODIFY_AUDIO_ROUTING, IPCThreadState::self()->getCallingUid())) {
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
        const std::vector<AudioDevice>& devicesAidl) {
    int userId = VALUE_OR_RETURN_BINDER_STATUS(convertReinterpret<int>(userIdAidl));
    AudioDeviceTypeAddrVector devices = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<AudioDeviceTypeAddrVector>(devicesAidl,
                                                        aidl2legacy_AudioDeviceTypeAddress));

    audio_utils::lock_guard _l(mMutex);
    if (!CHECK_PERM(MODIFY_AUDIO_ROUTING, IPCThreadState::self()->getCallingUid())) {
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

    audio_utils::lock_guard _l(mMutex);
    if (!CHECK_PERM(MODIFY_AUDIO_ROUTING, IPCThreadState::self()->getCallingUid())) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->removeUserIdDeviceAffinities(userId));
}

Status AudioPolicyService::startAudioSource(const media::AudioPortConfigFw& sourceAidl,
        const media::audio::common::AudioAttributes& attributesAidl,
        int32_t* _aidl_return) {
    audio_port_config source = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioPortConfigFw_audio_port_config(sourceAidl));
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attributesAidl));
    audio_port_handle_t portId;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioPortConfig(source)));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            AudioValidator::validateAudioAttributes(attributes, "68953950")));

    audio_utils::lock_guard _l(mMutex);
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }

    RETURN_IF_BINDER_ERROR(validateUsage(attributes));

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

    audio_utils::lock_guard _l(mMutex);
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
    if (!CHECK_PERM(MODIFY_AUDIO_SETTINGS, IPCThreadState::self()->getCallingUid())) {
        return binderStatusFromStatusT(PERMISSION_DENIED);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->setMasterMono(mono));
}

Status AudioPolicyService::getMasterMono(bool* _aidl_return)
{
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    return binderStatusFromStatusT(mAudioPolicyManager->getMasterMono(_aidl_return));
}


Status AudioPolicyService::getStreamVolumeDB(
        AudioStreamType streamAidl, int32_t indexAidl,
        const AudioDeviceDescription& deviceAidl, float* _aidl_return) {
    audio_stream_type_t stream = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(streamAidl));
    int index = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<int>(indexAidl));
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioDeviceDescription_audio_devices_t(deviceAidl));

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->getStreamVolumeDB(stream, index, device);
    return Status::ok();
}

Status AudioPolicyService::getSurroundFormats(Int* count,
        std::vector<AudioFormatDescription>* formats,
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
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getSurroundFormats(&numSurroundFormats, surroundFormats.get(),
                                                    surroundFormatsEnabled.get())));
    numSurroundFormatsReq = std::min(numSurroundFormats, numSurroundFormatsReq);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(surroundFormats.get(), surroundFormats.get() + numSurroundFormatsReq,
                         std::back_inserter(*formats),
                         legacy2aidl_audio_format_t_AudioFormatDescription)));
    formatsEnabled->insert(
            formatsEnabled->begin(),
            surroundFormatsEnabled.get(),
            surroundFormatsEnabled.get() + numSurroundFormatsReq);
    count->value = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<uint32_t>(numSurroundFormats));
    return Status::ok();
}

Status AudioPolicyService::getReportedSurroundFormats(
        Int* count, std::vector<AudioFormatDescription>* formats) {
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
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getReportedSurroundFormats(
                    &numSurroundFormats, surroundFormats.get())));
    numSurroundFormatsReq = std::min(numSurroundFormats, numSurroundFormatsReq);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            convertRange(surroundFormats.get(), surroundFormats.get() + numSurroundFormatsReq,
                         std::back_inserter(*formats),
                         legacy2aidl_audio_format_t_AudioFormatDescription)));
    count->value = VALUE_OR_RETURN_BINDER_STATUS(convertIntegral<uint32_t>(numSurroundFormats));
    return Status::ok();
}

Status AudioPolicyService::getHwOffloadFormatsSupportedForBluetoothMedia(
        const AudioDeviceDescription& deviceAidl,
        std::vector<AudioFormatDescription>* _aidl_return) {
    std::vector<audio_format_t> formats;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    audio_devices_t device = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioDeviceDescription_audio_devices_t(deviceAidl));
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getHwOffloadFormatsSupportedForBluetoothMedia(device, &formats)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<AudioFormatDescription>>(
                    formats,
                    legacy2aidl_audio_format_t_AudioFormatDescription));
    return Status::ok();
}

Status AudioPolicyService::setSurroundFormatEnabled(
        const AudioFormatDescription& audioFormatAidl, bool enabled) {
    audio_format_t audioFormat = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioFormatDescription_audio_format_t(audioFormatAidl));
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    return binderStatusFromStatusT(
            mAudioPolicyManager->setSurroundFormatEnabled(audioFormat, enabled));
}

Status convertInt32VectorToUidVectorWithLimit(
        const std::vector<int32_t>& uidsAidl, std::vector<uid_t>& uids) {
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
        convertRangeWithLimit(uidsAidl.begin(),
            uidsAidl.end(),
            std::back_inserter(uids),
            aidl2legacy_int32_t_uid_t,
            MAX_ITEMS_PER_LIST)));

    return Status::ok();
}

Status AudioPolicyService::setAssistantServicesUids(const std::vector<int32_t>& uidsAidl)
{
    std::vector<uid_t> uids;
    RETURN_IF_BINDER_ERROR(convertInt32VectorToUidVectorWithLimit(uidsAidl, uids));

    audio_utils::lock_guard _l(mMutex);
    mUidPolicy->setAssistantUids(uids);
    return Status::ok();
}

Status AudioPolicyService::setActiveAssistantServicesUids(
        const std::vector<int32_t>& activeUidsAidl) {
    std::vector<uid_t> activeUids;
    RETURN_IF_BINDER_ERROR(convertInt32VectorToUidVectorWithLimit(activeUidsAidl, activeUids));

    audio_utils::lock_guard _l(mMutex);
    mUidPolicy->setActiveAssistantUids(activeUids);
    return Status::ok();
}

Status AudioPolicyService::setA11yServicesUids(const std::vector<int32_t>& uidsAidl)
{
    std::vector<uid_t> uids;
    RETURN_IF_BINDER_ERROR(convertInt32VectorToUidVectorWithLimit(uidsAidl, uids));

    audio_utils::lock_guard _l(mMutex);
    mUidPolicy->setA11yUids(uids);
    return Status::ok();
}

Status AudioPolicyService::setCurrentImeUid(int32_t uidAidl)
{
    uid_t uid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(uidAidl));
    audio_utils::lock_guard _l(mMutex);
    mUidPolicy->setCurrentImeUid(uid);
    return Status::ok();
}

Status AudioPolicyService::isHapticPlaybackSupported(bool* _aidl_return)
{
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->isHapticPlaybackSupported();
    return Status::ok();
}

Status AudioPolicyService::isUltrasoundSupported(bool* _aidl_return)
{
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->isUltrasoundSupported();
    return Status::ok();
}

Status AudioPolicyService::isHotwordStreamSupported(bool lookbackAudio, bool* _aidl_return)
{
    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->isHotwordStreamSupported(lookbackAudio);
    return Status::ok();
}

binder::Status AudioPolicyService::getStreamTypeForAttributes(
        const media::audio::common::AudioAttributes& attributesAidl,
        AudioStreamType* _aidl_return) {
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_attributes_t attributes = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attributesAidl));

    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    audio_stream_type_t streamType = mAudioPolicyManager->getStreamTypeForAttributes(attributes);

    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_stream_type_t_AudioStreamType(streamType));

    return Status::ok();
}

binder::Status AudioPolicyService::getAttributesForStreamType(AudioStreamType stream,
                                          media::audio::common::AudioAttributes* _aidl_return) {
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }

    audio_stream_type_t streamType = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioStreamType_audio_stream_type_t(stream));

    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    audio_attributes_t attributes = mAudioPolicyManager->getAttributesForStreamType(streamType);

    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_attributes_t_AudioAttributes(attributes));

    return Status::ok();
}

Status AudioPolicyService::listAudioProductStrategies(
        std::vector<media::AudioProductStrategy>* _aidl_return) {

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }

    AudioProductStrategyVector strategies;
    audio_utils::lock_guard _l(mMutex);
    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(mAudioPolicyManager->listAudioProductStrategies(strategies)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<media::AudioProductStrategy>>(
                    strategies,
                    legacy2aidl_AudioProductStrategy));
    return Status::ok();
}

Status AudioPolicyService::getProductStrategyFromAudioAttributes(
        const media::audio::common::AudioAttributes& aaAidl,
        bool fallbackOnDefault, int32_t* _aidl_return) {
    audio_attributes_t aa = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(aaAidl));
    product_strategy_t productStrategy;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
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
    audio_utils::lock_guard _l(mMutex);
    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(mAudioPolicyManager->listAudioVolumeGroups(groups)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<media::AudioVolumeGroup>>(groups,
                                                                   legacy2aidl_AudioVolumeGroup));
    return Status::ok();
}

Status AudioPolicyService::getVolumeGroupFromAudioAttributes(
        const media::audio::common::AudioAttributes& aaAidl,
        bool fallbackOnDefault, int32_t* _aidl_return) {
    audio_attributes_t aa = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(aaAidl));
    volume_group_t volumeGroup;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(
                    mAudioPolicyManager->getVolumeGroupFromAudioAttributes(
                            aa, volumeGroup, fallbackOnDefault)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_volume_group_t_int32_t(volumeGroup));
    return Status::ok();
}

Status AudioPolicyService::setRttEnabled(bool enabled)
{
    audio_utils::lock_guard _l(mMutex);
    mUidPolicy->setRttEnabled(enabled);
    return Status::ok();
}

Status AudioPolicyService::isCallScreenModeSupported(bool* _aidl_return)
{
    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    AutoCallerClear acc;
    *_aidl_return = mAudioPolicyManager->isCallScreenModeSupported();
    return Status::ok();
}

Status AudioPolicyService::setDevicesRoleForStrategy(
        int32_t strategyAidl,
        media::DeviceRole roleAidl,
        const std::vector<AudioDevice>& devicesAidl) {
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
    audio_utils::lock_guard _l(mMutex);
    status_t status = mAudioPolicyManager->setDevicesRoleForStrategy(strategy, role, devices);
    if (status == NO_ERROR) {
       maybeCheckSpatializer_l();
    }
    return binderStatusFromStatusT(status);
}

Status AudioPolicyService::removeDevicesRoleForStrategy(
        int32_t strategyAidl,
        media::DeviceRole roleAidl,
        const std::vector<AudioDevice>& devicesAidl) {
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
    audio_utils::lock_guard _l(mMutex);
    status_t status = mAudioPolicyManager->removeDevicesRoleForStrategy(strategy, role, devices);
    if (status == NO_ERROR) {
       maybeCheckSpatializer_l();
    }
    return binderStatusFromStatusT(status);
}

Status AudioPolicyService::clearDevicesRoleForStrategy(int32_t strategyAidl,
                                                           media::DeviceRole roleAidl) {
     product_strategy_t strategy = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_product_strategy_t(strategyAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
   if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    status_t status = mAudioPolicyManager->clearDevicesRoleForStrategy(strategy, role);
    if (status == NO_ERROR) {
       maybeCheckSpatializer_l();
    }
    return binderStatusFromStatusT(status);
}

Status AudioPolicyService::getDevicesForRoleAndStrategy(
        int32_t strategyAidl,
        media::DeviceRole roleAidl,
        std::vector<AudioDevice>* _aidl_return) {
    product_strategy_t strategy = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_product_strategy_t(strategyAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
    AudioDeviceTypeAddrVector devices;

    if (mAudioPolicyManager == NULL) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getDevicesForRoleAndStrategy(strategy, role, devices)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<AudioDevice>>(devices,
                                                       legacy2aidl_AudioDeviceTypeAddress));
    return Status::ok();
}

Status AudioPolicyService::registerSoundTriggerCaptureStateListener(
        const sp<media::ICaptureStateListener>& listener, bool* _aidl_return) {
    *_aidl_return = mCaptureStateNotifier.RegisterListener(listener);
    return Status::ok();
}

Status AudioPolicyService::setDevicesRoleForCapturePreset(
        AudioSource audioSourceAidl,
        media::DeviceRole roleAidl,
        const std::vector<AudioDevice>& devicesAidl) {
    audio_source_t audioSource = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSource_audio_source_t(audioSourceAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
    AudioDeviceTypeAddrVector devices = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<AudioDeviceTypeAddrVector>(devicesAidl,
                                                        aidl2legacy_AudioDeviceTypeAddress));

    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    return binderStatusFromStatusT(
            mAudioPolicyManager->setDevicesRoleForCapturePreset(audioSource, role, devices));
}

Status AudioPolicyService::addDevicesRoleForCapturePreset(
        AudioSource audioSourceAidl,
        media::DeviceRole roleAidl,
        const std::vector<AudioDevice>& devicesAidl) {
    audio_source_t audioSource = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSource_audio_source_t(audioSourceAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
    AudioDeviceTypeAddrVector devices = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<AudioDeviceTypeAddrVector>(devicesAidl,
                                                        aidl2legacy_AudioDeviceTypeAddress));

    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    return binderStatusFromStatusT(
            mAudioPolicyManager->addDevicesRoleForCapturePreset(audioSource, role, devices));
}

Status AudioPolicyService::removeDevicesRoleForCapturePreset(
        AudioSource audioSourceAidl,
        media::DeviceRole roleAidl,
        const std::vector<AudioDevice>& devicesAidl) {
    audio_source_t audioSource = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSource_audio_source_t(audioSourceAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
    AudioDeviceTypeAddrVector devices = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<AudioDeviceTypeAddrVector>(devicesAidl,
                                                        aidl2legacy_AudioDeviceTypeAddress));

   if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    return binderStatusFromStatusT(
            mAudioPolicyManager->removeDevicesRoleForCapturePreset(audioSource, role, devices));
}

Status AudioPolicyService::clearDevicesRoleForCapturePreset(AudioSource audioSourceAidl,
                                                            media::DeviceRole roleAidl) {
    audio_source_t audioSource = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSource_audio_source_t(audioSourceAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));

    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    return binderStatusFromStatusT(
            mAudioPolicyManager->clearDevicesRoleForCapturePreset(audioSource, role));
}

Status AudioPolicyService::getDevicesForRoleAndCapturePreset(
        AudioSource audioSourceAidl,
        media::DeviceRole roleAidl,
        std::vector<AudioDevice>* _aidl_return) {
    audio_source_t audioSource = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioSource_audio_source_t(audioSourceAidl));
    device_role_t role = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_DeviceRole_device_role_t(roleAidl));
    AudioDeviceTypeAddrVector devices;

    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getDevicesForRoleAndCapturePreset(audioSource, role, devices)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<AudioDevice>>(devices,
                                                       legacy2aidl_AudioDeviceTypeAddress));
    return Status::ok();
}

Status AudioPolicyService::getSpatializer(
        const sp<media::INativeSpatializerCallback>& callback,
        media::GetSpatializerResponse* _aidl_return) {
    _aidl_return->spatializer = nullptr;
    if (callback == nullptr) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    if (mSpatializer != nullptr) {
        RETURN_IF_BINDER_ERROR(
                binderStatusFromStatusT(mSpatializer->registerCallback(callback)));
        _aidl_return->spatializer = mSpatializer;
    }
    return Status::ok();
}

Status AudioPolicyService::canBeSpatialized(
        const std::optional<media::audio::common::AudioAttributes>& attrAidl,
        const std::optional<AudioConfig>& configAidl,
        const std::vector<AudioDevice>& devicesAidl,
        bool* _aidl_return) {
    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_attributes_t attr = AUDIO_ATTRIBUTES_INITIALIZER;
    if (attrAidl.has_value()) {
        attr = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl.value()));
    }
    audio_config_t config = AUDIO_CONFIG_INITIALIZER;
    if (configAidl.has_value()) {
        config = VALUE_OR_RETURN_BINDER_STATUS(
                                    aidl2legacy_AudioConfig_audio_config_t(configAidl.value(),
                                    false /*isInput*/));
    }
    AudioDeviceTypeAddrVector devices = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<AudioDeviceTypeAddrVector>(devicesAidl,
                                                        aidl2legacy_AudioDeviceTypeAddress));

    audio_utils::lock_guard _l(mMutex);
    *_aidl_return = mAudioPolicyManager->canBeSpatialized(&attr, &config, devices);
    return Status::ok();
}

Status AudioPolicyService::getDirectPlaybackSupport(
        const media::audio::common::AudioAttributes &attrAidl,
        const AudioConfig &configAidl,
        media::AudioDirectMode *_aidl_return) {
    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    if (_aidl_return == nullptr) {
        return binderStatusFromStatusT(BAD_VALUE);
    }
    audio_attributes_t attr = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl));
    audio_config_t config = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioConfig_audio_config_t(configAidl, false /*isInput*/));
    audio_utils::lock_guard _l(mMutex);
    *_aidl_return = static_cast<media::AudioDirectMode>(
            VALUE_OR_RETURN_BINDER_STATUS(legacy2aidl_audio_direct_mode_t_int32_t_mask(
                    mAudioPolicyManager->getDirectPlaybackSupport(&attr, &config))));
    return Status::ok();
}

Status AudioPolicyService::getDirectProfilesForAttributes(
                                const media::audio::common::AudioAttributes& attrAidl,
                                std::vector<media::audio::common::AudioProfile>* _aidl_return) {
   if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_attributes_t attr = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl));
    AudioProfileVector audioProfiles;

    audio_utils::lock_guard _l(mMutex);
    RETURN_IF_BINDER_ERROR(binderStatusFromStatusT(
            mAudioPolicyManager->getDirectProfilesForAttributes(&attr, audioProfiles)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<media::audio::common::AudioProfile>>(
                audioProfiles, legacy2aidl_AudioProfile_common, false /*isInput*/));

    return Status::ok();
}

Status AudioPolicyService::getSupportedMixerAttributes(
        int32_t portIdAidl, std::vector<media::AudioMixerAttributesInternal>* _aidl_return) {
    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }

    audio_port_handle_t portId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portIdAidl));

    std::vector<audio_mixer_attributes_t> mixerAttrs;
    audio_utils::lock_guard _l(mMutex);
    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(mAudioPolicyManager->getSupportedMixerAttributes(
                    portId, mixerAttrs)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            convertContainer<std::vector<media::AudioMixerAttributesInternal>>(
                    mixerAttrs,
                    legacy2aidl_audio_mixer_attributes_t_AudioMixerAttributesInternal));
    return Status::ok();
}

Status AudioPolicyService::setPreferredMixerAttributes(
        const media::audio::common::AudioAttributes& attrAidl,
        int32_t portIdAidl,
        int32_t uidAidl,
        const media::AudioMixerAttributesInternal& mixerAttrAidl) {
    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }

    audio_attributes_t  attr = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl));
    audio_mixer_attributes_t mixerAttr = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioMixerAttributesInternal_audio_mixer_attributes_t(mixerAttrAidl));
    uid_t uid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(uidAidl));
    audio_port_handle_t portId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portIdAidl));

    audio_utils::lock_guard _l(mMutex);
    return binderStatusFromStatusT(
            mAudioPolicyManager->setPreferredMixerAttributes(&attr, portId, uid, &mixerAttr));
}

Status AudioPolicyService::getPreferredMixerAttributes(
        const media::audio::common::AudioAttributes& attrAidl,
        int32_t portIdAidl,
        std::optional<media::AudioMixerAttributesInternal>* _aidl_return) {
    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }

    audio_attributes_t  attr = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl));
    audio_port_handle_t portId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portIdAidl));

    audio_utils::lock_guard _l(mMutex);
    audio_mixer_attributes_t mixerAttr = AUDIO_MIXER_ATTRIBUTES_INITIALIZER;
    RETURN_IF_BINDER_ERROR(
            binderStatusFromStatusT(mAudioPolicyManager->getPreferredMixerAttributes(
                    &attr, portId, &mixerAttr)));
    *_aidl_return = VALUE_OR_RETURN_BINDER_STATUS(
            legacy2aidl_audio_mixer_attributes_t_AudioMixerAttributesInternal(mixerAttr));
    return Status::ok();
}

Status AudioPolicyService::clearPreferredMixerAttributes(
        const media::audio::common::AudioAttributes& attrAidl,
        int32_t portIdAidl,
        int32_t uidAidl) {
    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }

    audio_attributes_t  attr = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_AudioAttributes_audio_attributes_t(attrAidl));
    uid_t uid = VALUE_OR_RETURN_BINDER_STATUS(aidl2legacy_int32_t_uid_t(uidAidl));
    audio_port_handle_t portId = VALUE_OR_RETURN_BINDER_STATUS(
            aidl2legacy_int32_t_audio_port_handle_t(portIdAidl));

    audio_utils::lock_guard _l(mMutex);
    return binderStatusFromStatusT(
            mAudioPolicyManager->clearPreferredMixerAttributes(&attr, portId, uid));
}

Status AudioPolicyService::getPermissionController(sp<INativePermissionController>* out) {
    *out = mPermissionController;
    return Status::ok();
}

Status AudioPolicyService::getMmapPolicyInfos(
        AudioMMapPolicyType policyType, std::vector<AudioMMapPolicyInfo> *_aidl_return) {
    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    return binderStatusFromStatusT(
            mAudioPolicyManager->getMmapPolicyInfos(policyType, _aidl_return));
}

Status AudioPolicyService::getMmapPolicyForDevice(
        AudioMMapPolicyType policyType, AudioMMapPolicyInfo *policyInfo) {
    if (mAudioPolicyManager == nullptr) {
        return binderStatusFromStatusT(NO_INIT);
    }
    audio_utils::lock_guard _l(mMutex);
    return binderStatusFromStatusT(
            mAudioPolicyManager->getMmapPolicyForDevice(policyType, policyInfo));
}

Status AudioPolicyService::setEnableHardening(bool shouldEnable) {
    mShouldEnableHardening.store(shouldEnable);
    return Status::ok();
}

} // namespace android
