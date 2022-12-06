/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define LOG_TAG "APM::AudioPolicyEngine"
//#define LOG_NDEBUG 0

//#define VERY_VERBOSE_LOGGING
#ifdef VERY_VERBOSE_LOGGING
#define ALOGVV ALOGV
#else
#define ALOGVV(a...) do { } while(0)
#endif

#include "Engine.h"
#include <android-base/macros.h>
#include <AudioPolicyManagerObserver.h>
#include <PolicyAudioPort.h>
#include <IOProfile.h>
#include <AudioIODescriptorInterface.h>
#include <policy.h>
#include <media/AudioContainers.h>
#include <utils/String8.h>
#include <utils/Log.h>

namespace android
{
namespace audio_policy
{

struct legacy_strategy_map { const char *name; legacy_strategy id; };
static const std::vector<legacy_strategy_map>& getLegacyStrategy() {
    static const std::vector<legacy_strategy_map> legacyStrategy = {
        { "STRATEGY_NONE", STRATEGY_NONE },
        { "STRATEGY_MEDIA", STRATEGY_MEDIA },
        { "STRATEGY_PHONE", STRATEGY_PHONE },
        { "STRATEGY_SONIFICATION", STRATEGY_SONIFICATION },
        { "STRATEGY_SONIFICATION_RESPECTFUL", STRATEGY_SONIFICATION_RESPECTFUL },
        { "STRATEGY_DTMF", STRATEGY_DTMF },
        { "STRATEGY_ENFORCED_AUDIBLE", STRATEGY_ENFORCED_AUDIBLE },
        { "STRATEGY_TRANSMITTED_THROUGH_SPEAKER", STRATEGY_TRANSMITTED_THROUGH_SPEAKER },
        { "STRATEGY_ACCESSIBILITY", STRATEGY_ACCESSIBILITY },
        { "STRATEGY_REROUTING", STRATEGY_REROUTING },
        { "STRATEGY_PATCH", STRATEGY_REROUTING }, // boiler to manage stream patch volume
        { "STRATEGY_CALL_ASSISTANT", STRATEGY_CALL_ASSISTANT },
    };
    return legacyStrategy;
}

Engine::Engine()
{
    auto result = EngineBase::loadAudioPolicyEngineConfig();
    ALOGE_IF(result.nbSkippedElement != 0,
             "Policy Engine configuration is partially invalid, skipped %zu elements",
             result.nbSkippedElement);

    auto legacyStrategy = getLegacyStrategy();
    for (const auto &strategy : legacyStrategy) {
        mLegacyStrategyMap[getProductStrategyByName(strategy.name)] = strategy.id;
    }
}

status_t Engine::setForceUse(audio_policy_force_use_t usage, audio_policy_forced_cfg_t config)
{
    switch(usage) {
    case AUDIO_POLICY_FORCE_FOR_COMMUNICATION:
        if (config != AUDIO_POLICY_FORCE_SPEAKER && config != AUDIO_POLICY_FORCE_BT_SCO &&
            config != AUDIO_POLICY_FORCE_NONE) {
            ALOGW("setForceUse() invalid config %d for FOR_COMMUNICATION", config);
            return BAD_VALUE;
        }
        break;
    case AUDIO_POLICY_FORCE_FOR_MEDIA:
        if (config != AUDIO_POLICY_FORCE_HEADPHONES && config != AUDIO_POLICY_FORCE_BT_A2DP &&
            config != AUDIO_POLICY_FORCE_WIRED_ACCESSORY &&
            config != AUDIO_POLICY_FORCE_ANALOG_DOCK &&
            config != AUDIO_POLICY_FORCE_DIGITAL_DOCK && config != AUDIO_POLICY_FORCE_NONE &&
            config != AUDIO_POLICY_FORCE_NO_BT_A2DP && config != AUDIO_POLICY_FORCE_SPEAKER ) {
            ALOGW("setForceUse() invalid config %d for FOR_MEDIA", config);
            return BAD_VALUE;
        }
        break;
    case AUDIO_POLICY_FORCE_FOR_RECORD:
        if (config != AUDIO_POLICY_FORCE_BT_SCO && config != AUDIO_POLICY_FORCE_WIRED_ACCESSORY &&
            config != AUDIO_POLICY_FORCE_NONE) {
            ALOGW("setForceUse() invalid config %d for FOR_RECORD", config);
            return BAD_VALUE;
        }
        break;
    case AUDIO_POLICY_FORCE_FOR_DOCK:
        if (config != AUDIO_POLICY_FORCE_NONE && config != AUDIO_POLICY_FORCE_BT_CAR_DOCK &&
            config != AUDIO_POLICY_FORCE_BT_DESK_DOCK &&
            config != AUDIO_POLICY_FORCE_WIRED_ACCESSORY &&
            config != AUDIO_POLICY_FORCE_ANALOG_DOCK &&
            config != AUDIO_POLICY_FORCE_DIGITAL_DOCK) {
            ALOGW("setForceUse() invalid config %d for FOR_DOCK", config);
        }
        break;
    case AUDIO_POLICY_FORCE_FOR_SYSTEM:
        if (config != AUDIO_POLICY_FORCE_NONE &&
            config != AUDIO_POLICY_FORCE_SYSTEM_ENFORCED) {
            ALOGW("setForceUse() invalid config %d for FOR_SYSTEM", config);
        }
        break;
    case AUDIO_POLICY_FORCE_FOR_HDMI_SYSTEM_AUDIO:
        if (config != AUDIO_POLICY_FORCE_NONE &&
            config != AUDIO_POLICY_FORCE_HDMI_SYSTEM_AUDIO_ENFORCED) {
            ALOGW("setForceUse() invalid config %d for HDMI_SYSTEM_AUDIO", config);
        }
        break;
    case AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND:
        if (config != AUDIO_POLICY_FORCE_NONE &&
                config != AUDIO_POLICY_FORCE_ENCODED_SURROUND_NEVER &&
                config != AUDIO_POLICY_FORCE_ENCODED_SURROUND_ALWAYS &&
                config != AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL) {
            ALOGW("setForceUse() invalid config %d for ENCODED_SURROUND", config);
            return BAD_VALUE;
        }
        break;
    case AUDIO_POLICY_FORCE_FOR_VIBRATE_RINGING:
        if (config != AUDIO_POLICY_FORCE_BT_SCO && config != AUDIO_POLICY_FORCE_NONE) {
            ALOGW("setForceUse() invalid config %d for FOR_VIBRATE_RINGING", config);
            return BAD_VALUE;
        }
        break;
    default:
        ALOGW("setForceUse() invalid usage %d", usage);
        break; // TODO return BAD_VALUE?
    }
    return EngineBase::setForceUse(usage, config);
}

void Engine::filterOutputDevicesForStrategy(legacy_strategy strategy,
                                            DeviceVector& availableOutputDevices,
                                            const SwAudioOutputCollection &outputs) const
{
    DeviceVector availableInputDevices = getApmObserver()->getAvailableInputDevices();

    switch (strategy) {
    case STRATEGY_SONIFICATION_RESPECTFUL: {
        if (!(isInCall() || outputs.isActiveLocally(toVolumeSource(AUDIO_STREAM_VOICE_CALL)))) {
            // routing is same as media without the "remote" device
            availableOutputDevices.remove(availableOutputDevices.getDevicesFromType(
                    AUDIO_DEVICE_OUT_REMOTE_SUBMIX));
        }
        } break;
    case STRATEGY_DTMF:
    case STRATEGY_PHONE: {
        // Force use of only devices on primary output if:
        // - in call AND
        //   - cannot route from voice call RX OR
        //   - audio HAL version is < 3.0 and TX device is on the primary HW module
        if (getPhoneState() == AUDIO_MODE_IN_CALL) {
            audio_devices_t txDevice = getDeviceForInputSource(
                    AUDIO_SOURCE_VOICE_COMMUNICATION)->type();
            sp<AudioOutputDescriptor> primaryOutput = outputs.getPrimaryOutput();
            LOG_ALWAYS_FATAL_IF(primaryOutput == nullptr, "Primary output not found");
            DeviceVector availPrimaryInputDevices =
                    availableInputDevices.getDevicesFromHwModule(primaryOutput->getModuleHandle());

            // TODO: getPrimaryOutput return only devices from first module in
            // audio_policy_configuration.xml, hearing aid is not there, but it's
            // a primary device
            // FIXME: this is not the right way of solving this problem
            DeviceVector availPrimaryOutputDevices = availableOutputDevices.getDevicesFromTypes(
                    primaryOutput->supportedDevices().types());
            availPrimaryOutputDevices.add(
                    availableOutputDevices.getDevicesFromType(AUDIO_DEVICE_OUT_HEARING_AID));

            if ((availableInputDevices.getDevice(AUDIO_DEVICE_IN_TELEPHONY_RX,
                                                 String8(""), AUDIO_FORMAT_DEFAULT) == nullptr) ||
                ((availPrimaryInputDevices.getDevice(
                        txDevice, String8(""), AUDIO_FORMAT_DEFAULT) != nullptr) &&
                 (primaryOutput->getPolicyAudioPort()->getModuleVersionMajor() < 3))) {
                availableOutputDevices = availPrimaryOutputDevices;
            }

        }
        // Do not use A2DP devices when in call but use them when not in call
        // (e.g for voice mail playback)
        if (isInCall()) {
            availableOutputDevices.remove(availableOutputDevices.getDevicesFromTypes({
                    AUDIO_DEVICE_OUT_BLUETOOTH_A2DP, AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
                    AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER, }));
        }
        // If connected to a dock, never use the device speaker for calls
        if (!availableOutputDevices.getDevicesFromTypes({AUDIO_DEVICE_OUT_DGTL_DOCK_HEADSET})
                .isEmpty()) {
            availableOutputDevices.remove(
                    availableOutputDevices.getDevicesFromTypes({AUDIO_DEVICE_OUT_SPEAKER}));
        }
        } break;
    case STRATEGY_ACCESSIBILITY: {
        // do not route accessibility prompts to a digital output currently configured with a
        // compressed format as they would likely not be mixed and dropped.
        for (size_t i = 0; i < outputs.size(); i++) {
            sp<AudioOutputDescriptor> desc = outputs.valueAt(i);
            if (desc->isActive() && !audio_is_linear_pcm(desc->getFormat())) {
                availableOutputDevices.remove(desc->devices().getDevicesFromTypes({
                        AUDIO_DEVICE_OUT_HDMI, AUDIO_DEVICE_OUT_SPDIF,
                        AUDIO_DEVICE_OUT_HDMI_ARC, AUDIO_DEVICE_OUT_HDMI_EARC}));
            }
        }
        } break;
    default:
        break;
    }
}

product_strategy_t Engine::remapStrategyFromContext(product_strategy_t strategy,
                                                 const SwAudioOutputCollection &outputs) const {
    auto legacyStrategy = mLegacyStrategyMap.find(strategy) != end(mLegacyStrategyMap) ?
                          mLegacyStrategyMap.at(strategy) : STRATEGY_NONE;

    if (isInCall()) {
        switch (legacyStrategy) {
        case STRATEGY_ACCESSIBILITY:
        case STRATEGY_DTMF:
        case STRATEGY_MEDIA:
        case STRATEGY_SONIFICATION:
        case STRATEGY_SONIFICATION_RESPECTFUL:
            legacyStrategy = STRATEGY_PHONE;
            break;

        default:
            return strategy;
        }
    } else {
        switch (legacyStrategy) {
        case STRATEGY_SONIFICATION_RESPECTFUL:
        case STRATEGY_SONIFICATION:
            if (outputs.isActiveLocally(toVolumeSource(AUDIO_STREAM_VOICE_CALL))) {
                legacyStrategy = STRATEGY_PHONE;
            }
            break;

        case STRATEGY_ACCESSIBILITY:
            if (outputs.isActive(toVolumeSource(AUDIO_STREAM_RING)) ||
                    outputs.isActive(toVolumeSource(AUDIO_STREAM_ALARM))) {
                legacyStrategy = STRATEGY_SONIFICATION;
            }
            break;

        default:
            return strategy;
        }
    }
    return getProductStrategyFromLegacy(legacyStrategy);
}

DeviceVector Engine::getDevicesForStrategyInt(legacy_strategy strategy,
                                              DeviceVector availableOutputDevices,
                                              const SwAudioOutputCollection &outputs) const
{
    DeviceVector devices;

    switch (strategy) {

    case STRATEGY_TRANSMITTED_THROUGH_SPEAKER:
        devices = availableOutputDevices.getDevicesFromType(AUDIO_DEVICE_OUT_SPEAKER);
        break;

    case STRATEGY_PHONE: {
        devices = availableOutputDevices.getDevicesFromType(AUDIO_DEVICE_OUT_HEARING_AID);
        if (!devices.isEmpty()) break;
        devices = availableOutputDevices.getFirstDevicesFromTypes(
                        getLastRemovableMediaDevices(GROUP_NONE, {AUDIO_DEVICE_OUT_BLE_HEADSET}));
        if (!devices.isEmpty()) break;
        devices = availableOutputDevices.getFirstDevicesFromTypes({
                AUDIO_DEVICE_OUT_DGTL_DOCK_HEADSET, AUDIO_DEVICE_OUT_EARPIECE});
    } break;

    case STRATEGY_SONIFICATION:
    case STRATEGY_ENFORCED_AUDIBLE:
        // strategy STRATEGY_ENFORCED_AUDIBLE uses same routing policy as STRATEGY_SONIFICATION
        // except:
        //   - when in call where it doesn't default to STRATEGY_PHONE behavior
        //   - in countries where not enforced in which case it follows STRATEGY_MEDIA

        if ((strategy == STRATEGY_SONIFICATION) ||
                (getForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM) == AUDIO_POLICY_FORCE_SYSTEM_ENFORCED)) {
            devices = availableOutputDevices.getDevicesFromType(AUDIO_DEVICE_OUT_SPEAKER);
        }

        // if SCO headset is connected and we are told to use it, play ringtone over
        // speaker and BT SCO
        if (!availableOutputDevices.getDevicesFromTypes(getAudioDeviceOutAllScoSet()).isEmpty()) {
            DeviceVector devices2;
            devices2 = availableOutputDevices.getFirstDevicesFromTypes({
                    AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT, AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,
                    AUDIO_DEVICE_OUT_BLUETOOTH_SCO});
            // Use ONLY Bluetooth SCO output when ringing in vibration mode
            if (!((getForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM) == AUDIO_POLICY_FORCE_SYSTEM_ENFORCED)
                    && (strategy == STRATEGY_ENFORCED_AUDIBLE))) {
                if (getForceUse(AUDIO_POLICY_FORCE_FOR_VIBRATE_RINGING)
                        == AUDIO_POLICY_FORCE_BT_SCO) {
                    if (!devices2.isEmpty()) {
                        devices = devices2;
                        break;
                    }
                }
            }
            // Use both Bluetooth SCO and phone default output when ringing in normal mode
            if (audio_is_bluetooth_out_sco_device(getPreferredDeviceTypeForLegacyStrategy(
                    availableOutputDevices, STRATEGY_PHONE))) {
                if (strategy == STRATEGY_SONIFICATION) {
                    devices.replaceDevicesByType(
                            AUDIO_DEVICE_OUT_SPEAKER,
                            availableOutputDevices.getDevicesFromType(
                                    AUDIO_DEVICE_OUT_SPEAKER_SAFE));
                }
                if (!devices2.isEmpty()) {
                    devices.add(devices2);
                    break;
                }
            }
        }
        // The second device used for sonification is the same as the device used by media strategy
        FALLTHROUGH_INTENDED;

    case STRATEGY_DTMF:
    case STRATEGY_ACCESSIBILITY:
    case STRATEGY_SONIFICATION_RESPECTFUL:
    case STRATEGY_REROUTING:
    case STRATEGY_MEDIA: {
        DeviceVector devices2;
        if (strategy != STRATEGY_SONIFICATION) {
            // no sonification on remote submix (e.g. WFD)
            sp<DeviceDescriptor> remoteSubmix;
            if ((remoteSubmix = availableOutputDevices.getDevice(
                    AUDIO_DEVICE_OUT_REMOTE_SUBMIX, String8("0"),
                    AUDIO_FORMAT_DEFAULT)) != nullptr) {
                devices2.add(remoteSubmix);
            }
        }

        if ((devices2.isEmpty()) &&
            (getForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA) == AUDIO_POLICY_FORCE_SPEAKER)) {
            devices2 = availableOutputDevices.getDevicesFromType(AUDIO_DEVICE_OUT_SPEAKER);
        }

        // LE audio broadcast device is only used if:
        // - No call is active
        // - either MEDIA or SONIFICATION_RESPECTFUL is the highest priority active strategy
        //   OR the LE audio unicast device is not active
        if (devices2.isEmpty() && !isInCall()
                && (strategy == STRATEGY_MEDIA || strategy == STRATEGY_SONIFICATION_RESPECTFUL)) {
            legacy_strategy topActiveStrategy = STRATEGY_NONE;
            for (const auto &ps : getOrderedProductStrategies()) {
                if (outputs.isStrategyActive(ps)) {
                    topActiveStrategy =  mLegacyStrategyMap.find(ps) != end(mLegacyStrategyMap) ?
                            mLegacyStrategyMap.at(ps) : STRATEGY_NONE;
                    break;
                }
            }

            if (topActiveStrategy == STRATEGY_NONE || topActiveStrategy == STRATEGY_MEDIA
                    || topActiveStrategy == STRATEGY_SONIFICATION_RESPECTFUL
                    || !outputs.isAnyDeviceTypeActive(getAudioDeviceOutLeAudioUnicastSet())) {
                devices2 =
                        availableOutputDevices.getDevicesFromType(AUDIO_DEVICE_OUT_BLE_BROADCAST);
            }
        }

        if (devices2.isEmpty() && (getLastRemovableMediaDevices().size() > 0)) {
            if ((getForceUse(AUDIO_POLICY_FORCE_FOR_MEDIA) != AUDIO_POLICY_FORCE_NO_BT_A2DP)) {
                // Get the last connected device of wired and bluetooth a2dp
                devices2 = availableOutputDevices.getFirstDevicesFromTypes(
                        getLastRemovableMediaDevices());
            } else {
                // Get the last connected device of wired except bluetooth a2dp
                devices2 = availableOutputDevices.getFirstDevicesFromTypes(
                        getLastRemovableMediaDevices(GROUP_WIRED));
            }
        }
        if ((devices2.isEmpty()) && (strategy != STRATEGY_SONIFICATION)) {
            // no sonification on aux digital (e.g. HDMI)
            devices2 = availableOutputDevices.getDevicesFromType(AUDIO_DEVICE_OUT_AUX_DIGITAL);
        }
        if ((devices2.isEmpty()) &&
                (getForceUse(AUDIO_POLICY_FORCE_FOR_DOCK) == AUDIO_POLICY_FORCE_ANALOG_DOCK)) {
            devices2 = availableOutputDevices.getDevicesFromType(
                    AUDIO_DEVICE_OUT_ANLG_DOCK_HEADSET);
        }
        if ((devices2.isEmpty()) && (strategy != STRATEGY_SONIFICATION)) {
            // no sonification on WFD sink
            devices2 = availableOutputDevices.getDevicesFromType(AUDIO_DEVICE_OUT_PROXY);
        }
        if (devices2.isEmpty()) {
            devices2 = availableOutputDevices.getFirstDevicesFromTypes({
                        AUDIO_DEVICE_OUT_DGTL_DOCK_HEADSET, AUDIO_DEVICE_OUT_SPEAKER});
        }
        DeviceVector devices3;
        if (strategy == STRATEGY_MEDIA) {
            // ARC, SPDIF and AUX_LINE can co-exist with others.
            devices3 = availableOutputDevices.getDevicesFromTypes({
                    AUDIO_DEVICE_OUT_HDMI_ARC, AUDIO_DEVICE_OUT_HDMI_EARC,
                    AUDIO_DEVICE_OUT_SPDIF, AUDIO_DEVICE_OUT_AUX_LINE,
                    });
        }

        devices2.add(devices3);
        // device is DEVICE_OUT_SPEAKER if we come from case STRATEGY_SONIFICATION or
        // STRATEGY_ENFORCED_AUDIBLE, AUDIO_DEVICE_NONE otherwise
        devices.add(devices2);

        // If hdmi system audio mode is on, remove speaker out of output list.
        if ((strategy == STRATEGY_MEDIA) &&
            (getForceUse(AUDIO_POLICY_FORCE_FOR_HDMI_SYSTEM_AUDIO) ==
                AUDIO_POLICY_FORCE_HDMI_SYSTEM_AUDIO_ENFORCED)) {
            devices.remove(devices.getDevicesFromType(AUDIO_DEVICE_OUT_SPEAKER));
        }

        bool mediaActiveLocally =
                outputs.isActiveLocally(toVolumeSource(AUDIO_STREAM_MUSIC),
                                        SONIFICATION_RESPECTFUL_AFTER_MUSIC_DELAY)
                || outputs.isActiveLocally(
                    toVolumeSource(AUDIO_STREAM_ACCESSIBILITY),
                    SONIFICATION_RESPECTFUL_AFTER_MUSIC_DELAY);

        bool ringActiveLocally = outputs.isActiveLocally(toVolumeSource(AUDIO_STREAM_RING), 0);
        // - for STRATEGY_SONIFICATION and ringtone active:
        // if SPEAKER was selected, and SPEAKER_SAFE is available, use SPEAKER_SAFE instead
        // - for STRATEGY_SONIFICATION_RESPECTFUL:
        // if no media is playing on the device, check for mandatory use of "safe" speaker
        // when media would have played on speaker, and the safe speaker path is available
        if (strategy == STRATEGY_SONIFICATION || ringActiveLocally
            || (strategy == STRATEGY_SONIFICATION_RESPECTFUL && !mediaActiveLocally)) {
            devices.replaceDevicesByType(
                    AUDIO_DEVICE_OUT_SPEAKER,
                    availableOutputDevices.getDevicesFromType(
                            AUDIO_DEVICE_OUT_SPEAKER_SAFE));
        }
        } break;

    case STRATEGY_CALL_ASSISTANT:
        devices = availableOutputDevices.getDevicesFromType(AUDIO_DEVICE_OUT_TELEPHONY_TX);
        break;

    case STRATEGY_NONE:
        // Happens when internal strategies are processed ("rerouting", "patch"...)
        break;

    default:
        ALOGW("%s unknown strategy: %d", __func__, strategy);
        break;
    }

    if (devices.isEmpty()) {
        ALOGV("%s no device found for strategy %d", __func__, strategy);
        sp<DeviceDescriptor> defaultOutputDevice = getApmObserver()->getDefaultOutputDevice();
        if (defaultOutputDevice != nullptr) {
            devices.add(defaultOutputDevice);
        }
        ALOGE_IF(devices.isEmpty(),
                 "%s no default device defined", __func__);
    }

    ALOGVV("%s strategy %d, device %s", __func__,
           strategy, dumpDeviceTypes(devices.types()).c_str());
    return devices;
}


sp<DeviceDescriptor> Engine::getDeviceForInputSource(audio_source_t inputSource) const
{
    const DeviceVector availableOutputDevices = getApmObserver()->getAvailableOutputDevices();
    const DeviceVector availableInputDevices = getApmObserver()->getAvailableInputDevices();
    const SwAudioOutputCollection &outputs = getApmObserver()->getOutputs();
    DeviceVector availableDevices = availableInputDevices;
    sp<AudioOutputDescriptor> primaryOutput = outputs.getPrimaryOutput();
    DeviceVector availablePrimaryDevices = primaryOutput == nullptr ? DeviceVector()
            : availableInputDevices.getDevicesFromHwModule(primaryOutput->getModuleHandle());
    sp<DeviceDescriptor> device;

    // when a call is active, force device selection to match source VOICE_COMMUNICATION
    // for most other input sources to avoid rerouting call TX audio
    if (isInCall()) {
        switch (inputSource) {
        case AUDIO_SOURCE_DEFAULT:
        case AUDIO_SOURCE_MIC:
        case AUDIO_SOURCE_VOICE_RECOGNITION:
        case AUDIO_SOURCE_UNPROCESSED:
        case AUDIO_SOURCE_HOTWORD:
        case AUDIO_SOURCE_CAMCORDER:
        case AUDIO_SOURCE_VOICE_PERFORMANCE:
        case AUDIO_SOURCE_ULTRASOUND:
            inputSource = AUDIO_SOURCE_VOICE_COMMUNICATION;
            break;
        default:
            break;
        }
    }

    audio_devices_t commDeviceType =
        getPreferredDeviceTypeForLegacyStrategy(availableOutputDevices, STRATEGY_PHONE);

    switch (inputSource) {
    case AUDIO_SOURCE_DEFAULT:
    case AUDIO_SOURCE_MIC:
        device = availableDevices.getDevice(
                AUDIO_DEVICE_IN_BLUETOOTH_A2DP, String8(""), AUDIO_FORMAT_DEFAULT);
        if (device != nullptr) break;
        if (audio_is_bluetooth_out_sco_device(commDeviceType)) {
            device = availableDevices.getDevice(
                    AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, String8(""), AUDIO_FORMAT_DEFAULT);
            if (device != nullptr) break;
        }
        device = availableDevices.getFirstExistingDevice({
                AUDIO_DEVICE_IN_WIRED_HEADSET,
                AUDIO_DEVICE_IN_USB_HEADSET, AUDIO_DEVICE_IN_USB_DEVICE,
                AUDIO_DEVICE_IN_BLUETOOTH_BLE, AUDIO_DEVICE_IN_BUILTIN_MIC});
        break;

    case AUDIO_SOURCE_VOICE_COMMUNICATION:
        // Allow only use of devices on primary input if in call and HAL does not support routing
        // to voice call path.
        if ((getPhoneState() == AUDIO_MODE_IN_CALL) &&
                (availableOutputDevices.getDevice(AUDIO_DEVICE_OUT_TELEPHONY_TX,
                        String8(""), AUDIO_FORMAT_DEFAULT)) == nullptr) {
            LOG_ALWAYS_FATAL_IF(availablePrimaryDevices.isEmpty(), "Primary devices not found");
            availableDevices = availablePrimaryDevices;
        }

        if (audio_is_bluetooth_out_sco_device(commDeviceType)) {
            // if SCO device is requested but no SCO device is available, fall back to default case
            device = availableDevices.getDevice(
                    AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, String8(""), AUDIO_FORMAT_DEFAULT);
            if (device != nullptr) {
                break;
            }
        }
        switch (commDeviceType) {
        case AUDIO_DEVICE_OUT_BLE_HEADSET:
            device = availableDevices.getDevice(
                    AUDIO_DEVICE_IN_BLE_HEADSET, String8(""), AUDIO_FORMAT_DEFAULT);
            break;
        case AUDIO_DEVICE_OUT_SPEAKER:
            device = availableDevices.getFirstExistingDevice({
                    AUDIO_DEVICE_IN_BACK_MIC, AUDIO_DEVICE_IN_BUILTIN_MIC,
                    AUDIO_DEVICE_IN_USB_DEVICE, AUDIO_DEVICE_IN_USB_HEADSET});
            break;
        default:    // FORCE_NONE
            device = availableDevices.getFirstExistingDevice({
                    AUDIO_DEVICE_IN_WIRED_HEADSET, AUDIO_DEVICE_IN_USB_HEADSET,
                    AUDIO_DEVICE_IN_USB_DEVICE, AUDIO_DEVICE_IN_BLUETOOTH_BLE,
                    AUDIO_DEVICE_IN_BUILTIN_MIC});
            break;

        }
        break;

    case AUDIO_SOURCE_VOICE_RECOGNITION:
    case AUDIO_SOURCE_UNPROCESSED:
        if (audio_is_bluetooth_out_sco_device(commDeviceType)) {
            device = availableDevices.getDevice(
                    AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, String8(""), AUDIO_FORMAT_DEFAULT);
            if (device != nullptr) break;
        }
        // we need to make BLUETOOTH_BLE has higher priority than BUILTIN_MIC,
        // because sometimes user want to do voice search by bt remote
        // even if BUILDIN_MIC is available.
        device = availableDevices.getFirstExistingDevice({
                AUDIO_DEVICE_IN_WIRED_HEADSET,
                AUDIO_DEVICE_IN_USB_HEADSET, AUDIO_DEVICE_IN_USB_DEVICE,
                AUDIO_DEVICE_IN_BLUETOOTH_BLE, AUDIO_DEVICE_IN_BUILTIN_MIC});

        break;
    case AUDIO_SOURCE_HOTWORD:
        // We should not use primary output criteria for Hotword but rather limit
        // to devices attached to the same HW module as the build in mic
        LOG_ALWAYS_FATAL_IF(availablePrimaryDevices.isEmpty(), "Primary devices not found");
        availableDevices = availablePrimaryDevices;
        if (audio_is_bluetooth_out_sco_device(commDeviceType)) {
            device = availableDevices.getDevice(
                    AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET, String8(""), AUDIO_FORMAT_DEFAULT);
            if (device != nullptr) break;
        }
        device = availableDevices.getFirstExistingDevice({
                AUDIO_DEVICE_IN_WIRED_HEADSET,
                AUDIO_DEVICE_IN_USB_HEADSET, AUDIO_DEVICE_IN_USB_DEVICE,
                AUDIO_DEVICE_IN_BUILTIN_MIC});
        break;
    case AUDIO_SOURCE_CAMCORDER:
        // For a device without built-in mic, adding usb device
        device = availableDevices.getFirstExistingDevice({
                AUDIO_DEVICE_IN_BACK_MIC, AUDIO_DEVICE_IN_BUILTIN_MIC,
                AUDIO_DEVICE_IN_USB_DEVICE});
        break;
    case AUDIO_SOURCE_VOICE_DOWNLINK:
    case AUDIO_SOURCE_VOICE_CALL:
    case AUDIO_SOURCE_VOICE_UPLINK:
        device = availableDevices.getDevice(
                AUDIO_DEVICE_IN_VOICE_CALL, String8(""), AUDIO_FORMAT_DEFAULT);
        break;
    case AUDIO_SOURCE_VOICE_PERFORMANCE:
        device = availableDevices.getFirstExistingDevice({
                AUDIO_DEVICE_IN_WIRED_HEADSET, AUDIO_DEVICE_IN_USB_HEADSET,
                AUDIO_DEVICE_IN_USB_DEVICE, AUDIO_DEVICE_IN_BLUETOOTH_BLE,
                AUDIO_DEVICE_IN_BUILTIN_MIC});
        break;
    case AUDIO_SOURCE_REMOTE_SUBMIX:
        device = availableDevices.getDevice(
                AUDIO_DEVICE_IN_REMOTE_SUBMIX, String8(""), AUDIO_FORMAT_DEFAULT);
        break;
    case AUDIO_SOURCE_FM_TUNER:
        device = availableDevices.getDevice(
                AUDIO_DEVICE_IN_FM_TUNER, String8(""), AUDIO_FORMAT_DEFAULT);
        break;
    case AUDIO_SOURCE_ECHO_REFERENCE:
        device = availableDevices.getDevice(
                AUDIO_DEVICE_IN_ECHO_REFERENCE, String8(""), AUDIO_FORMAT_DEFAULT);
        break;
    case AUDIO_SOURCE_ULTRASOUND:
        device = availableDevices.getFirstExistingDevice({
                AUDIO_DEVICE_IN_BUILTIN_MIC, AUDIO_DEVICE_IN_BACK_MIC});
        break;
    default:
        ALOGW("getDeviceForInputSource() invalid input source %d", inputSource);
        break;
    }
    if (device == nullptr) {
        ALOGV("getDeviceForInputSource() no device found for source %d", inputSource);
        device = availableDevices.getDevice(
                AUDIO_DEVICE_IN_STUB, String8(""), AUDIO_FORMAT_DEFAULT);
        ALOGE_IF(device == nullptr,
                 "getDeviceForInputSource() no default device defined");
    }

    ALOGV_IF(device != nullptr,
             "getDeviceForInputSource()input source %d, device %08x",
             inputSource, device->type());
    return device;
}

void Engine::updateDeviceSelectionCache()
{
    for (const auto &iter : getProductStrategies()) {
        const auto& strategy = iter.second;
        auto devices = getDevicesForProductStrategy(strategy->getId());
        mDevicesForStrategies[strategy->getId()] = devices;
        strategy->setDeviceTypes(devices.types());
        strategy->setDeviceAddress(devices.getFirstValidAddress().c_str());
    }
}

product_strategy_t Engine::getProductStrategyFromLegacy(legacy_strategy legacyStrategy) const {
    for (const auto& strategyMap : mLegacyStrategyMap) {
        if (strategyMap.second == legacyStrategy) {
            return strategyMap.first;
        }
    }
    return PRODUCT_STRATEGY_NONE;
}

audio_devices_t Engine::getPreferredDeviceTypeForLegacyStrategy(
        const DeviceVector& availableOutputDevices, legacy_strategy legacyStrategy) const {
    product_strategy_t strategy = getProductStrategyFromLegacy(legacyStrategy);
    DeviceVector devices = getPreferredAvailableDevicesForProductStrategy(
            availableOutputDevices, strategy);
    if (devices.size() > 0) {
        return devices[0]->type();
    }
    return AUDIO_DEVICE_NONE;
}

DeviceVector Engine::getPreferredAvailableDevicesForProductStrategy(
        const DeviceVector& availableOutputDevices, product_strategy_t strategy) const {
    DeviceVector preferredAvailableDevVec = {};
    AudioDeviceTypeAddrVector preferredStrategyDevices;
    const status_t status = getDevicesForRoleAndStrategy(
            strategy, DEVICE_ROLE_PREFERRED, preferredStrategyDevices);
    if (status == NO_ERROR) {
        // there is a preferred device, is it available?
        preferredAvailableDevVec =
                availableOutputDevices.getDevicesFromDeviceTypeAddrVec(preferredStrategyDevices);
        if (preferredAvailableDevVec.size() == preferredStrategyDevices.size()) {
            ALOGVV("%s using pref device %s for strategy %u",
                   __func__, preferredAvailableDevVec.toString().c_str(), strategy);
            return preferredAvailableDevVec;
        }
    }
    return preferredAvailableDevVec;
}


DeviceVector Engine::getDevicesForProductStrategy(product_strategy_t strategy) const {
    const SwAudioOutputCollection& outputs = getApmObserver()->getOutputs();

    // Take context into account to remap product strategy before
    // checking preferred device for strategy and applying default routing rules
    strategy = remapStrategyFromContext(strategy, outputs);

    auto legacyStrategy = mLegacyStrategyMap.find(strategy) != end(mLegacyStrategyMap) ?
                          mLegacyStrategyMap.at(strategy) : STRATEGY_NONE;

    DeviceVector availableOutputDevices = getApmObserver()->getAvailableOutputDevices();

    filterOutputDevicesForStrategy(legacyStrategy, availableOutputDevices, outputs);

    // check if this strategy has a preferred device that is available,
    // if yes, give priority to it.
    DeviceVector preferredAvailableDevVec =
            getPreferredAvailableDevicesForProductStrategy(availableOutputDevices, strategy);
    if (!preferredAvailableDevVec.isEmpty()) {
        return preferredAvailableDevVec;
    }

    return getDevicesForStrategyInt(legacyStrategy,
                                    availableOutputDevices,
                                    outputs);
}

DeviceVector Engine::getOutputDevicesForAttributes(const audio_attributes_t &attributes,
                                                   const sp<DeviceDescriptor> &preferredDevice,
                                                   bool fromCache) const
{
    // First check for explict routing device
    if (preferredDevice != nullptr) {
        ALOGV("%s explicit Routing on device %s", __func__, preferredDevice->toString().c_str());
        return DeviceVector(preferredDevice);
    }
    product_strategy_t strategy = getProductStrategyForAttributes(attributes);
    const DeviceVector availableOutputDevices = getApmObserver()->getAvailableOutputDevices();
    const SwAudioOutputCollection &outputs = getApmObserver()->getOutputs();
    //
    // @TODO: what is the priority of explicit routing? Shall it be considered first as it used to
    // be by APM?
    //
    // Honor explicit routing requests only if all active clients have a preferred route in which
    // case the last active client route is used
    sp<DeviceDescriptor> device = findPreferredDevice(outputs, strategy, availableOutputDevices);
    if (device != nullptr) {
        return DeviceVector(device);
    }

    return fromCache? mDevicesForStrategies.at(strategy) : getDevicesForProductStrategy(strategy);
}

DeviceVector Engine::getOutputDevicesForStream(audio_stream_type_t stream, bool fromCache) const
{
    auto attributes = getAttributesForStreamType(stream);
    return getOutputDevicesForAttributes(attributes, nullptr, fromCache);
}

sp<DeviceDescriptor> Engine::getInputDeviceForAttributes(const audio_attributes_t &attr,
                                                         uid_t uid,
                                                         sp<AudioPolicyMix> *mix) const
{
    const auto &policyMixes = getApmObserver()->getAudioPolicyMixCollection();
    const auto availableInputDevices = getApmObserver()->getAvailableInputDevices();
    const auto &inputs = getApmObserver()->getInputs();
    std::string address;

    //
    // Explicit Routing ??? what is the priority of explicit routing? Shall it be considered
    // first as it used to be by APM?
    //
    // Honor explicit routing requests only if all active clients have a preferred route in which
    // case the last active client route is used
    sp<DeviceDescriptor> device =
            findPreferredDevice(inputs, attr.source, availableInputDevices);
    if (device != nullptr) {
        return device;
    }

    device = policyMixes.getDeviceAndMixForInputSource(attr.source,
                                                       availableInputDevices,
                                                       uid,
                                                       mix);
    if (device != nullptr) {
        return device;
    }

    device = getDeviceForInputSource(attr.source);
    if (device == nullptr || !audio_is_remote_submix_device(device->type())) {
        // Return immediately if the device is null or it is not a remote submix device.
        return device;
    }

    // For remote submix device, try to find the device by address.
    address = "0";
    std::size_t pos;
    std::string tags { attr.tags };
    if ((pos = tags.find("addr=")) != std::string::npos) {
        address = tags.substr(pos + std::strlen("addr="));
    }
    return availableInputDevices.getDevice(device->type(),
                                           String8(address.c_str()),
                                           AUDIO_FORMAT_DEFAULT);
}

} // namespace audio_policy
} // namespace android


