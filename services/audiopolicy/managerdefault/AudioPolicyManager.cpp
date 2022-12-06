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

#define LOG_TAG "APM_AudioPolicyManager"

// Need to keep the log statements even in production builds
// to enable VERBOSE logging dynamically.
// You can enable VERBOSE logging as follows:
// adb shell setprop log.tag.APM_AudioPolicyManager V
#define LOG_NDEBUG 0

//#define VERY_VERBOSE_LOGGING
#ifdef VERY_VERBOSE_LOGGING
#define ALOGVV ALOGV
#else
#define ALOGVV(a...) do { } while(0)
#endif

#include <algorithm>
#include <inttypes.h>
#include <map>
#include <math.h>
#include <set>
#include <unordered_set>
#include <vector>

#include <Serializer.h>
#include <android/media/audio/common/AudioPort.h>
#include <cutils/bitops.h>
#include <cutils/properties.h>
#include <media/AudioParameter.h>
#include <policy.h>
#include <private/android_filesystem_config.h>
#include <system/audio.h>
#include <system/audio_config.h>
#include <system/audio_effects/effect_hapticgenerator.h>
#include <utils/Log.h>

#include "AudioPolicyManager.h"
#include "TypeConverter.h"

namespace android {

using android::media::audio::common::AudioDevice;
using android::media::audio::common::AudioDeviceAddress;
using android::media::audio::common::AudioPortDeviceExt;
using android::media::audio::common::AudioPortExt;
using content::AttributionSourceState;

//FIXME: workaround for truncated touch sounds
// to be removed when the problem is handled by system UI
#define TOUCH_SOUND_FIXED_DELAY_MS 100

// Largest difference in dB on earpiece in call between the voice volume and another
// media / notification / system volume.
constexpr float IN_CALL_EARPIECE_HEADROOM_DB = 3.f;

// Compressed formats for MSD module, ordered from most preferred to least preferred.
static const std::vector<audio_format_t> msdCompressedFormatsOrder = {{
        AUDIO_FORMAT_IEC60958, AUDIO_FORMAT_MAT_2_1, AUDIO_FORMAT_MAT_2_0, AUDIO_FORMAT_E_AC3,
        AUDIO_FORMAT_AC3, AUDIO_FORMAT_PCM_16_BIT }};
// Channel masks for MSD module, 3D > 2D > 1D ordering (most preferred to least preferred).
static const std::vector<audio_channel_mask_t> msdSurroundChannelMasksOrder = {{
        AUDIO_CHANNEL_OUT_3POINT1POINT2, AUDIO_CHANNEL_OUT_3POINT0POINT2,
        AUDIO_CHANNEL_OUT_2POINT1POINT2, AUDIO_CHANNEL_OUT_2POINT0POINT2,
        AUDIO_CHANNEL_OUT_5POINT1, AUDIO_CHANNEL_OUT_STEREO }};

template <typename T>
bool operator== (const SortedVector<T> &left, const SortedVector<T> &right)
{
    if (left.size() != right.size()) {
        return false;
    }
    for (size_t index = 0; index < right.size(); index++) {
        if (left[index] != right[index]) {
            return false;
        }
    }
    return true;
}

template <typename T>
bool operator!= (const SortedVector<T> &left, const SortedVector<T> &right)
{
    return !(left == right);
}

// ----------------------------------------------------------------------------
// AudioPolicyInterface implementation
// ----------------------------------------------------------------------------

status_t AudioPolicyManager::setDeviceConnectionState(audio_policy_dev_state_t state,
        const android::media::audio::common::AudioPort& port, audio_format_t encodedFormat) {
    status_t status = setDeviceConnectionStateInt(state, port, encodedFormat);
    nextAudioPortGeneration();
    return status;
}

status_t AudioPolicyManager::setDeviceConnectionState(audio_devices_t device,
                                                      audio_policy_dev_state_t state,
                                                      const char* device_address,
                                                      const char* device_name,
                                                      audio_format_t encodedFormat) {
    media::AudioPort aidlPort;
    if (status_t status = deviceToAudioPort(device, device_address, device_name, &aidlPort);
        status == OK) {
        return setDeviceConnectionState(state, aidlPort.hal, encodedFormat);
    } else {
        ALOGE("Failed to convert to AudioPort Parcelable: %s", statusToString(status).c_str());
        return status;
    }
}

void AudioPolicyManager::broadcastDeviceConnectionState(const sp<DeviceDescriptor> &device,
                                                        audio_policy_dev_state_t state)
{
    audio_port_v7 devicePort;
    device->toAudioPort(&devicePort);
    if (status_t status = mpClientInterface->setDeviceConnectedState(
                    &devicePort, state == AUDIO_POLICY_DEVICE_STATE_AVAILABLE);
            status != OK) {
        ALOGE("Error %d while setting connected state for device %s", status,
                device->getDeviceTypeAddr().toString(false).c_str());
    }
}

status_t AudioPolicyManager::setDeviceConnectionStateInt(
        audio_policy_dev_state_t state, const android::media::audio::common::AudioPort& port,
        audio_format_t encodedFormat) {
    // TODO: b/211601178 Forward 'port' to Audio HAL via mHwModules. For now, only device_type,
    // device_address and device_name are forwarded.
    if (port.ext.getTag() != AudioPortExt::device) {
        return BAD_VALUE;
    }
    audio_devices_t device_type;
    std::string device_address;
    if (status_t status = aidl2legacy_AudioDevice_audio_device(
                port.ext.get<AudioPortExt::device>().device, &device_type, &device_address);
        status != OK) {
        return status;
    };
    const char* device_name = port.name.c_str();
    // connect/disconnect only 1 device at a time
    if (!audio_is_output_device(device_type) && !audio_is_input_device(device_type))
        return BAD_VALUE;

    sp<DeviceDescriptor> device = mHwModules.getDeviceDescriptor(
            device_type, device_address.c_str(), device_name, encodedFormat,
            state == AUDIO_POLICY_DEVICE_STATE_AVAILABLE);
    return device ? setDeviceConnectionStateInt(device, state) : INVALID_OPERATION;
}

status_t AudioPolicyManager::setDeviceConnectionStateInt(audio_devices_t deviceType,
                                                         audio_policy_dev_state_t state,
                                                         const char* device_address,
                                                         const char* device_name,
                                                         audio_format_t encodedFormat) {
    media::AudioPort aidlPort;
    if (status_t status = deviceToAudioPort(deviceType, device_address, device_name, &aidlPort);
        status == OK) {
        return setDeviceConnectionStateInt(state, aidlPort.hal, encodedFormat);
    } else {
        ALOGE("Failed to convert to AudioPort Parcelable: %s", statusToString(status).c_str());
        return status;
    }
}

status_t AudioPolicyManager::setDeviceConnectionStateInt(const sp<DeviceDescriptor> &device,
                                                         audio_policy_dev_state_t state)
{
    // handle output devices
    if (audio_is_output_device(device->type())) {
        SortedVector <audio_io_handle_t> outputs;

        ssize_t index = mAvailableOutputDevices.indexOf(device);

        // save a copy of the opened output descriptors before any output is opened or closed
        // by checkOutputsForDevice(). This will be needed by checkOutputForAllStrategies()
        mPreviousOutputs = mOutputs;

        bool wasLeUnicastActive = isLeUnicastActive();

        switch (state)
        {
        // handle output device connection
        case AUDIO_POLICY_DEVICE_STATE_AVAILABLE: {
            if (index >= 0) {
                ALOGW("%s() device already connected: %s", __func__, device->toString().c_str());
                return INVALID_OPERATION;
            }
            ALOGV("%s() connecting device %s format %x",
                    __func__, device->toString().c_str(), device->getEncodedFormat());

            // register new device as available
            if (mAvailableOutputDevices.add(device) < 0) {
                return NO_MEMORY;
            }

            // Before checking outputs, broadcast connect event to allow HAL to retrieve dynamic
            // parameters on newly connected devices (instead of opening the outputs...)
            broadcastDeviceConnectionState(device, state);

            if (checkOutputsForDevice(device, state, outputs) != NO_ERROR) {
                mAvailableOutputDevices.remove(device);

                mHwModules.cleanUpForDevice(device);

                broadcastDeviceConnectionState(device, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE);
                return INVALID_OPERATION;
            }

            // Populate encapsulation information when a output device is connected.
            device->setEncapsulationInfoFromHal(mpClientInterface);

            // outputs should never be empty here
            ALOG_ASSERT(outputs.size() != 0, "setDeviceConnectionState():"
                    "checkOutputsForDevice() returned no outputs but status OK");
            ALOGV("%s() checkOutputsForDevice() returned %zu outputs", __func__, outputs.size());

            } break;
        // handle output device disconnection
        case AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE: {
            if (index < 0) {
                ALOGW("%s() device not connected: %s", __func__, device->toString().c_str());
                return INVALID_OPERATION;
            }

            ALOGV("%s() disconnecting output device %s", __func__, device->toString().c_str());

            // Send Disconnect to HALs
            broadcastDeviceConnectionState(device, state);

            // remove device from available output devices
            mAvailableOutputDevices.remove(device);

            mOutputs.clearSessionRoutesForDevice(device);

            checkOutputsForDevice(device, state, outputs);

            // Reset active device codec
            device->setEncodedFormat(AUDIO_FORMAT_DEFAULT);

            // remove device from mReportedFormatsMap cache
            mReportedFormatsMap.erase(device);

            } break;

        default:
            ALOGE("%s() invalid state: %x", __func__, state);
            return BAD_VALUE;
        }

        // Propagate device availability to Engine
        setEngineDeviceConnectionState(device, state);

        // No need to evaluate playback routing when connecting a remote submix
        // output device used by a dynamic policy of type recorder as no
        // playback use case is affected.
        bool doCheckForDeviceAndOutputChanges = true;
        if (device->type() == AUDIO_DEVICE_OUT_REMOTE_SUBMIX && device->address() != "0") {
            for (audio_io_handle_t output : outputs) {
                sp<SwAudioOutputDescriptor> desc = mOutputs.valueFor(output);
                sp<AudioPolicyMix> policyMix = desc->mPolicyMix.promote();
                if (policyMix != nullptr
                        && policyMix->mMixType == MIX_TYPE_RECORDERS
                        && device->address() == policyMix->mDeviceAddress.string()) {
                    doCheckForDeviceAndOutputChanges = false;
                    break;
                }
            }
        }

        auto checkCloseOutputs = [&]() {
            // outputs must be closed after checkOutputForAllStrategies() is executed
            if (!outputs.isEmpty()) {
                for (audio_io_handle_t output : outputs) {
                    sp<SwAudioOutputDescriptor> desc = mOutputs.valueFor(output);
                    // close unused outputs after device disconnection or direct outputs that have
                    // been opened by checkOutputsForDevice() to query dynamic parameters
                    // "outputs" vector never contains duplicated outputs
                    if ((state == AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE)
                            || (((desc->mFlags & AUDIO_OUTPUT_FLAG_DIRECT) != 0) &&
                                (desc->mDirectOpenCount == 0))
                            || (((desc->mFlags & AUDIO_OUTPUT_FLAG_SPATIALIZER) != 0) &&
                                !isOutputOnlyAvailableRouteToSomeDevice(desc))) {
                        clearAudioSourcesForOutput(output);
                        closeOutput(output);
                    }
                }
                // check A2DP again after closing A2DP output to reset mA2dpSuspended if needed
                return true;
            }
            return false;
        };

        if (doCheckForDeviceAndOutputChanges) {
            checkForDeviceAndOutputChanges(checkCloseOutputs);
        } else {
            checkCloseOutputs();
        }
        (void)updateCallRouting(false /*fromCache*/);
        std::vector<audio_io_handle_t> outputsToReopen;
        const DeviceVector msdOutDevices = getMsdAudioOutDevices();
        const DeviceVector activeMediaDevices =
                mEngine->getActiveMediaDevices(mAvailableOutputDevices);
        for (size_t i = 0; i < mOutputs.size(); i++) {
            sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
            if (desc->isActive() && ((mEngine->getPhoneState() != AUDIO_MODE_IN_CALL) ||
                (desc != mPrimaryOutput))) {
                DeviceVector newDevices = getNewOutputDevices(desc, true /*fromCache*/);
                // do not force device change on duplicated output because if device is 0, it will
                // also force a device 0 for the two outputs it is duplicated to which may override
                // a valid device selection on those outputs.
                bool force = (msdOutDevices.isEmpty() || msdOutDevices != desc->devices())
                        && !desc->isDuplicated()
                        && (!device_distinguishes_on_address(device->type())
                                // always force when disconnecting (a non-duplicated device)
                                || (state == AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE));
                setOutputDevices(desc, newDevices, force, 0);
            }
            if (!desc->isDuplicated() && desc->mProfile->hasDynamicAudioProfile() &&
                    !activeMediaDevices.empty() && desc->devices() != activeMediaDevices &&
                    desc->supportsDevicesForPlayback(activeMediaDevices)) {
                // Reopen the output to query the dynamic profiles when there is not active
                // clients or all active clients will be rerouted. Otherwise, set the flag
                // `mPendingReopenToQueryProfiles` in the SwOutputDescriptor so that the output
                // can be reopened to query dynamic profiles when all clients are inactive.
                if (areAllActiveTracksRerouted(desc)) {
                    outputsToReopen.push_back(mOutputs.keyAt(i));
                } else {
                    desc->mPendingReopenToQueryProfiles = true;
                }
            }
            if (!desc->supportsDevicesForPlayback(activeMediaDevices)) {
                // Clear the flag that previously set for re-querying profiles.
                desc->mPendingReopenToQueryProfiles = false;
            }
        }
        for (const auto& output : outputsToReopen) {
            sp<SwAudioOutputDescriptor> desc = mOutputs.valueFor(output);
            closeOutput(output);
            openOutputWithProfileAndDevice(desc->mProfile, activeMediaDevices);
        }

        if (state == AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE) {
            cleanUpForDevice(device);
        }

        checkLeBroadcastRoutes(wasLeUnicastActive, nullptr, 0);

        mpClientInterface->onAudioPortListUpdate();
        return NO_ERROR;
    }  // end if is output device

    // handle input devices
    if (audio_is_input_device(device->type())) {
        ssize_t index = mAvailableInputDevices.indexOf(device);
        switch (state)
        {
        // handle input device connection
        case AUDIO_POLICY_DEVICE_STATE_AVAILABLE: {
            if (index >= 0) {
                ALOGW("%s() device already connected: %s", __func__, device->toString().c_str());
                return INVALID_OPERATION;
            }

            if (mAvailableInputDevices.add(device) < 0) {
                return NO_MEMORY;
            }

            // Before checking intputs, broadcast connect event to allow HAL to retrieve dynamic
            // parameters on newly connected devices (instead of opening the inputs...)
            broadcastDeviceConnectionState(device, state);

            if (checkInputsForDevice(device, state) != NO_ERROR) {
                mAvailableInputDevices.remove(device);

                broadcastDeviceConnectionState(device, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE);

                mHwModules.cleanUpForDevice(device);

                return INVALID_OPERATION;
            }

        } break;

        // handle input device disconnection
        case AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE: {
            if (index < 0) {
                ALOGW("%s() device not connected: %s", __func__, device->toString().c_str());
                return INVALID_OPERATION;
            }

            ALOGV("%s() disconnecting input device %s", __func__, device->toString().c_str());

            // Set Disconnect to HALs
            broadcastDeviceConnectionState(device, state);

            mAvailableInputDevices.remove(device);

            checkInputsForDevice(device, state);

            // remove device from mReportedFormatsMap cache
            mReportedFormatsMap.erase(device);
        } break;

        default:
            ALOGE("%s() invalid state: %x", __func__, state);
            return BAD_VALUE;
        }

        // Propagate device availability to Engine
        setEngineDeviceConnectionState(device, state);

        checkCloseInputs();
        // As the input device list can impact the output device selection, update
        // getDeviceForStrategy() cache
        updateDevicesAndOutputs();

        (void)updateCallRouting(false /*fromCache*/);
        // Reconnect Audio Source
        for (const auto &strategy : mEngine->getOrderedProductStrategies()) {
            auto attributes = mEngine->getAllAttributesForProductStrategy(strategy).front();
            checkAudioSourceForAttributes(attributes);
        }
        if (state == AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE) {
            cleanUpForDevice(device);
        }

        mpClientInterface->onAudioPortListUpdate();
        return NO_ERROR;
    } // end if is input device

    ALOGW("%s() invalid device: %s", __func__, device->toString().c_str());
    return BAD_VALUE;
}

status_t AudioPolicyManager::deviceToAudioPort(audio_devices_t device, const char* device_address,
                                               const char* device_name,
                                               media::AudioPort* aidlPort) {
    DeviceDescriptorBase devDescr(device, device_address);
    devDescr.setName(device_name);
    return devDescr.writeToParcelable(aidlPort);
}

void AudioPolicyManager::setEngineDeviceConnectionState(const sp<DeviceDescriptor> device,
                                      audio_policy_dev_state_t state) {

    // the Engine does not have to know about remote submix devices used by dynamic audio policies
    if (audio_is_remote_submix_device(device->type()) && device->address() != "0") {
        return;
    }
    mEngine->setDeviceConnectionState(device, state);
}


audio_policy_dev_state_t AudioPolicyManager::getDeviceConnectionState(audio_devices_t device,
                                                                      const char *device_address)
{
    sp<DeviceDescriptor> devDesc =
            mHwModules.getDeviceDescriptor(device, device_address, "", AUDIO_FORMAT_DEFAULT,
                                           false /* allowToCreate */,
                                           (strlen(device_address) != 0)/*matchAddress*/);

    if (devDesc == 0) {
        ALOGV("getDeviceConnectionState() undeclared device, type %08x, address: %s",
              device, device_address);
        return AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE;
    }

    DeviceVector *deviceVector;

    if (audio_is_output_device(device)) {
        deviceVector = &mAvailableOutputDevices;
    } else if (audio_is_input_device(device)) {
        deviceVector = &mAvailableInputDevices;
    } else {
        ALOGW("%s() invalid device type %08x", __func__, device);
        return AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE;
    }

    return (deviceVector->getDevice(
                device, String8(device_address), AUDIO_FORMAT_DEFAULT) != 0) ?
            AUDIO_POLICY_DEVICE_STATE_AVAILABLE : AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE;
}

status_t AudioPolicyManager::handleDeviceConfigChange(audio_devices_t device,
                                                      const char *device_address,
                                                      const char *device_name,
                                                      audio_format_t encodedFormat)
{
    status_t status;
    String8 reply;
    AudioParameter param;
    int isReconfigA2dpSupported = 0;

    ALOGV("handleDeviceConfigChange(() device: 0x%X, address %s name %s encodedFormat: 0x%X",
          device, device_address, device_name, encodedFormat);

    // connect/disconnect only 1 device at a time
    if (!audio_is_output_device(device) && !audio_is_input_device(device)) return BAD_VALUE;

    // Check if the device is currently connected
    DeviceVector deviceList = mAvailableOutputDevices.getDevicesFromType(device);
    if (deviceList.empty()) {
        // Nothing to do: device is not connected
        return NO_ERROR;
    }
    sp<DeviceDescriptor> devDesc = deviceList.itemAt(0);

    // For offloaded A2DP, Hw modules may have the capability to
    // configure codecs.
    // Handle two specific cases by sending a set parameter to
    // configure A2DP codecs. No need to toggle device state.
    // Case 1: A2DP active device switches from primary to primary
    // module
    // Case 2: A2DP device config changes on primary module.
    if (audio_is_a2dp_out_device(device) && hasPrimaryOutput()) {
        sp<HwModule> module = mHwModules.getModuleForDeviceType(device, encodedFormat);
        audio_module_handle_t primaryHandle = mPrimaryOutput->getModuleHandle();
        if (availablePrimaryOutputDevices().contains(devDesc) &&
           (module != 0 && module->getHandle() == primaryHandle)) {
            reply = mpClientInterface->getParameters(
                        AUDIO_IO_HANDLE_NONE,
                        String8(AudioParameter::keyReconfigA2dpSupported));
            AudioParameter repliedParameters(reply);
            repliedParameters.getInt(
                    String8(AudioParameter::keyReconfigA2dpSupported), isReconfigA2dpSupported);
            if (isReconfigA2dpSupported) {
                const String8 key(AudioParameter::keyReconfigA2dp);
                param.add(key, String8("true"));
                mpClientInterface->setParameters(AUDIO_IO_HANDLE_NONE, param.toString());
                devDesc->setEncodedFormat(encodedFormat);
                return NO_ERROR;
            }
        }
    }
    auto musicStrategy = streamToStrategy(AUDIO_STREAM_MUSIC);
    for (size_t i = 0; i < mOutputs.size(); i++) {
       sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
       // mute media strategies and delay device switch by the largest
       // This avoid sending the music tail into the earpiece or headset.
       setStrategyMute(musicStrategy, true, desc);
       setStrategyMute(musicStrategy, false, desc, MUTE_TIME_MS,
          mEngine->getOutputDevicesForAttributes(attributes_initializer(AUDIO_USAGE_MEDIA),
                                              nullptr, true /*fromCache*/).types());
    }
    // Toggle the device state: UNAVAILABLE -> AVAILABLE
    // This will force reading again the device configuration
    status = setDeviceConnectionState(device,
                                      AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                      device_address, device_name,
                                      devDesc->getEncodedFormat());
    if (status != NO_ERROR) {
        ALOGW("handleDeviceConfigChange() error disabling connection state: %d",
              status);
        return status;
    }

    status = setDeviceConnectionState(device,
                                      AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                      device_address, device_name, encodedFormat);
    if (status != NO_ERROR) {
        ALOGW("handleDeviceConfigChange() error enabling connection state: %d",
              status);
        return status;
    }

    return NO_ERROR;
}

status_t AudioPolicyManager::getHwOffloadFormatsSupportedForBluetoothMedia(
                                    audio_devices_t device, std::vector<audio_format_t> *formats)
{
    ALOGV("getHwOffloadFormatsSupportedForBluetoothMedia()");
    status_t status = NO_ERROR;
    std::unordered_set<audio_format_t> formatSet;
    sp<HwModule> primaryModule =
            mHwModules.getModuleFromName(AUDIO_HARDWARE_MODULE_ID_PRIMARY);
    if (primaryModule == nullptr) {
        ALOGE("%s() unable to get primary module", __func__);
        return NO_INIT;
    }

    DeviceTypeSet audioDeviceSet;

    switch(device) {
    case AUDIO_DEVICE_OUT_BLUETOOTH_A2DP:
        audioDeviceSet = getAudioDeviceOutAllA2dpSet();
        break;
    case AUDIO_DEVICE_OUT_BLE_HEADSET:
        audioDeviceSet = getAudioDeviceOutAllBleSet();
        break;
    default:
        ALOGE("%s() device type 0x%08x not supported", __func__, device);
        return BAD_VALUE;
    }

    DeviceVector declaredDevices = primaryModule->getDeclaredDevices().getDevicesFromTypes(
            audioDeviceSet);
    for (const auto& device : declaredDevices) {
        formatSet.insert(device->encodedFormats().begin(), device->encodedFormats().end());
    }
    formats->assign(formatSet.begin(), formatSet.end());
    return status;
}

DeviceVector AudioPolicyManager::selectBestRxSinkDevicesForCall(bool fromCache)
{
    DeviceVector rxSinkdevices{};
    rxSinkdevices = mEngine->getOutputDevicesForAttributes(
                attributes_initializer(AUDIO_USAGE_VOICE_COMMUNICATION), nullptr, fromCache);
    if (!rxSinkdevices.isEmpty() && mAvailableOutputDevices.contains(rxSinkdevices.itemAt(0))) {
        auto rxSinkDevice = rxSinkdevices.itemAt(0);
        auto telephonyRxModule = mHwModules.getModuleForDeviceType(
                    AUDIO_DEVICE_IN_TELEPHONY_RX, AUDIO_FORMAT_DEFAULT);
        // retrieve Rx Source device descriptor
        sp<DeviceDescriptor> rxSourceDevice = mAvailableInputDevices.getDevice(
                    AUDIO_DEVICE_IN_TELEPHONY_RX, String8(), AUDIO_FORMAT_DEFAULT);

        // RX Telephony and Rx sink devices are declared by Primary Audio HAL
        if (isPrimaryModule(telephonyRxModule) && (telephonyRxModule->getHalVersionMajor() >= 3) &&
                telephonyRxModule->supportsPatch(rxSourceDevice, rxSinkDevice)) {
            ALOGW("%s() device %s using HW Bridge", __func__, rxSinkDevice->toString().c_str());
            return DeviceVector(rxSinkDevice);
        }
    }
    // Note that despite the fact that getNewOutputDevices() is called on the primary output,
    // the device returned is not necessarily reachable via this output
    // (filter later by setOutputDevices())
    return getNewOutputDevices(mPrimaryOutput, fromCache);
}

status_t AudioPolicyManager::updateCallRouting(bool fromCache, uint32_t delayMs, uint32_t *waitMs)
{
    if (mEngine->getPhoneState() == AUDIO_MODE_IN_CALL && hasPrimaryOutput()) {
        DeviceVector rxDevices = selectBestRxSinkDevicesForCall(fromCache);
        return updateCallRoutingInternal(rxDevices, delayMs, waitMs);
    }
    return INVALID_OPERATION;
}

status_t AudioPolicyManager::updateCallRoutingInternal(
        const DeviceVector &rxDevices, uint32_t delayMs, uint32_t *waitMs)
{
    bool createTxPatch = false;
    bool createRxPatch = false;
    uint32_t muteWaitMs = 0;
    if(!hasPrimaryOutput() ||
            mPrimaryOutput->devices().onlyContainsDevicesWithType(AUDIO_DEVICE_OUT_STUB)) {
        return INVALID_OPERATION;
    }
    ALOG_ASSERT(!rxDevices.isEmpty(), "%s() no selected output device", __func__);

    audio_attributes_t attr = { .source = AUDIO_SOURCE_VOICE_COMMUNICATION };
    auto txSourceDevice = mEngine->getInputDeviceForAttributes(attr);
    ALOG_ASSERT(txSourceDevice != 0, "%s() input selected device not available", __func__);

    ALOGV("%s device rxDevice %s txDevice %s", __func__,
          rxDevices.itemAt(0)->toString().c_str(), txSourceDevice->toString().c_str());

    disconnectTelephonyAudioSource(mCallRxSourceClient);
    disconnectTelephonyAudioSource(mCallTxSourceClient);

    auto telephonyRxModule =
        mHwModules.getModuleForDeviceType(AUDIO_DEVICE_IN_TELEPHONY_RX, AUDIO_FORMAT_DEFAULT);
    auto telephonyTxModule =
        mHwModules.getModuleForDeviceType(AUDIO_DEVICE_OUT_TELEPHONY_TX, AUDIO_FORMAT_DEFAULT);
    // retrieve Rx Source and Tx Sink device descriptors
    sp<DeviceDescriptor> rxSourceDevice =
        mAvailableInputDevices.getDevice(AUDIO_DEVICE_IN_TELEPHONY_RX,
                                         String8(),
                                         AUDIO_FORMAT_DEFAULT);
    sp<DeviceDescriptor> txSinkDevice =
        mAvailableOutputDevices.getDevice(AUDIO_DEVICE_OUT_TELEPHONY_TX,
                                          String8(),
                                          AUDIO_FORMAT_DEFAULT);

    // RX and TX Telephony device are declared by Primary Audio HAL
    if (isPrimaryModule(telephonyRxModule) && isPrimaryModule(telephonyTxModule) &&
            (telephonyRxModule->getHalVersionMajor() >= 3)) {
        if (rxSourceDevice == 0 || txSinkDevice == 0) {
            // RX / TX Telephony device(s) is(are) not currently available
            ALOGE("%s() no telephony Tx and/or RX device", __func__);
            return INVALID_OPERATION;
        }
        // createAudioPatchInternal now supports both HW / SW bridging
        createRxPatch = true;
        createTxPatch = true;
    } else {
        // If the RX device is on the primary HW module, then use legacy routing method for
        // voice calls via setOutputDevice() on primary output.
        // Otherwise, create two audio patches for TX and RX path.
        createRxPatch = !(availablePrimaryOutputDevices().contains(rxDevices.itemAt(0))) &&
                (rxSourceDevice != 0);
        // If the TX device is also on the primary HW module, setOutputDevice() will take care
        // of it due to legacy implementation. If not, create a patch.
        createTxPatch = !(availablePrimaryModuleInputDevices().contains(txSourceDevice)) &&
                (txSinkDevice != 0);
    }
    // Use legacy routing method for voice calls via setOutputDevice() on primary output.
    // Otherwise, create two audio patches for TX and RX path.
    if (!createRxPatch) {
        muteWaitMs = setOutputDevices(mPrimaryOutput, rxDevices, true, delayMs);
    } else { // create RX path audio patch
        connectTelephonyRxAudioSource();
        // If the TX device is on the primary HW module but RX device is
        // on other HW module, SinkMetaData of telephony input should handle it
        // assuming the device uses audio HAL V5.0 and above
    }
    if (createTxPatch) { // create TX path audio patch
        // terminate active capture if on the same HW module as the call TX source device
        // FIXME: would be better to refine to only inputs whose profile connects to the
        // call TX device but this information is not in the audio patch and logic here must be
        // symmetric to the one in startInput()
        for (const auto& activeDesc : mInputs.getActiveInputs()) {
            if (activeDesc->hasSameHwModuleAs(txSourceDevice)) {
                closeActiveClients(activeDesc);
            }
        }
        connectTelephonyTxAudioSource(txSourceDevice, txSinkDevice, delayMs);
    }
    if (waitMs != nullptr) {
        *waitMs = muteWaitMs;
    }
    return NO_ERROR;
}

bool AudioPolicyManager::isDeviceOfModule(
        const sp<DeviceDescriptor>& devDesc, const char *moduleId) const {
    sp<HwModule> module = mHwModules.getModuleFromName(moduleId);
    if (module != 0) {
        return mAvailableOutputDevices.getDevicesFromHwModule(module->getHandle())
                .indexOf(devDesc) != NAME_NOT_FOUND
                || mAvailableInputDevices.getDevicesFromHwModule(module->getHandle())
                .indexOf(devDesc) != NAME_NOT_FOUND;
    }
    return false;
}

void AudioPolicyManager::connectTelephonyRxAudioSource()
{
    disconnectTelephonyAudioSource(mCallRxSourceClient);
    const struct audio_port_config source = {
        .role = AUDIO_PORT_ROLE_SOURCE, .type = AUDIO_PORT_TYPE_DEVICE,
        .ext.device.type = AUDIO_DEVICE_IN_TELEPHONY_RX, .ext.device.address = ""
    };
    const auto aa = mEngine->getAttributesForStreamType(AUDIO_STREAM_VOICE_CALL);
    mCallRxSourceClient = startAudioSourceInternal(&source, &aa, 0/*uid*/);
    ALOGE_IF(mCallRxSourceClient == nullptr,
             "%s failed to start Telephony Rx AudioSource", __func__);
}

void AudioPolicyManager::disconnectTelephonyAudioSource(sp<SourceClientDescriptor> &clientDesc)
{
    if (clientDesc == nullptr) {
        return;
    }
    ALOGW_IF(stopAudioSource(clientDesc->portId()) != NO_ERROR,
            "%s error stopping audio source", __func__);
    clientDesc.clear();
}

void AudioPolicyManager::connectTelephonyTxAudioSource(
        const sp<DeviceDescriptor> &srcDevice, const sp<DeviceDescriptor> &sinkDevice,
        uint32_t delayMs)
{
    disconnectTelephonyAudioSource(mCallTxSourceClient);
    if (srcDevice == nullptr || sinkDevice == nullptr) {
        ALOGW("%s could not create patch, invalid sink and/or source device(s)", __func__);
        return;
    }
    PatchBuilder patchBuilder;
    patchBuilder.addSource(srcDevice).addSink(sinkDevice);
    ALOGV("%s between source %s and sink %s", __func__,
            srcDevice->toString().c_str(), sinkDevice->toString().c_str());
    auto callTxSourceClientPortId = PolicyAudioPort::getNextUniqueId();
    const audio_attributes_t aa = { .source = AUDIO_SOURCE_VOICE_COMMUNICATION };
    struct audio_port_config source = {};
    srcDevice->toAudioPortConfig(&source);
    mCallTxSourceClient = new InternalSourceClientDescriptor(
                callTxSourceClientPortId, mUidCached, aa, source, srcDevice, sinkDevice,
                mCommunnicationStrategy, toVolumeSource(aa));
    audio_patch_handle_t patchHandle = AUDIO_PATCH_HANDLE_NONE;
    status_t status = connectAudioSourceToSink(
                mCallTxSourceClient, sinkDevice, patchBuilder.patch(), patchHandle, mUidCached,
                delayMs);
    ALOGE_IF(status != NO_ERROR, "%s() error %d creating TX audio patch", __func__, status);
    if (status == NO_ERROR) {
        mAudioSources.add(callTxSourceClientPortId, mCallTxSourceClient);
    }
}

void AudioPolicyManager::setPhoneState(audio_mode_t state)
{
    ALOGV("setPhoneState() state %d", state);
    // store previous phone state for management of sonification strategy below
    int oldState = mEngine->getPhoneState();
    bool wasLeUnicastActive = isLeUnicastActive();

    if (mEngine->setPhoneState(state) != NO_ERROR) {
        ALOGW("setPhoneState() invalid or same state %d", state);
        return;
    }
    /// Opens: can these line be executed after the switch of volume curves???
    if (isStateInCall(oldState)) {
        ALOGV("setPhoneState() in call state management: new state is %d", state);
        // force reevaluating accessibility routing when call stops
        mpClientInterface->invalidateStream(AUDIO_STREAM_ACCESSIBILITY);
    }

    /**
     * Switching to or from incall state or switching between telephony and VoIP lead to force
     * routing command.
     */
    bool force = ((isStateInCall(oldState) != isStateInCall(state))
                  || (isStateInCall(state) && (state != oldState)));

    // check for device and output changes triggered by new phone state
    checkForDeviceAndOutputChanges();

    int delayMs = 0;
    if (isStateInCall(state)) {
        nsecs_t sysTime = systemTime();
        auto musicStrategy = streamToStrategy(AUDIO_STREAM_MUSIC);
        auto sonificationStrategy = streamToStrategy(AUDIO_STREAM_ALARM);
        for (size_t i = 0; i < mOutputs.size(); i++) {
            sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
            // mute media and sonification strategies and delay device switch by the largest
            // latency of any output where either strategy is active.
            // This avoid sending the ring tone or music tail into the earpiece or headset.
            if ((desc->isStrategyActive(musicStrategy, SONIFICATION_HEADSET_MUSIC_DELAY, sysTime) ||
                 desc->isStrategyActive(sonificationStrategy, SONIFICATION_HEADSET_MUSIC_DELAY,
                                        sysTime)) &&
                    (delayMs < (int)desc->latency()*2)) {
                delayMs = desc->latency()*2;
            }
            setStrategyMute(musicStrategy, true, desc);
            setStrategyMute(musicStrategy, false, desc, MUTE_TIME_MS,
                mEngine->getOutputDevicesForAttributes(attributes_initializer(AUDIO_USAGE_MEDIA),
                                                       nullptr, true /*fromCache*/).types());
            setStrategyMute(sonificationStrategy, true, desc);
            setStrategyMute(sonificationStrategy, false, desc, MUTE_TIME_MS,
                mEngine->getOutputDevicesForAttributes(attributes_initializer(AUDIO_USAGE_ALARM),
                                                       nullptr, true /*fromCache*/).types());
        }
    }

    if (hasPrimaryOutput()) {
        if (state == AUDIO_MODE_IN_CALL) {
            (void)updateCallRouting(false /*fromCache*/, delayMs);
        } else {
            DeviceVector rxDevices = getNewOutputDevices(mPrimaryOutput, false /*fromCache*/);
            // force routing command to audio hardware when ending call
            // even if no device change is needed
            if (isStateInCall(oldState) && rxDevices.isEmpty()) {
                rxDevices = mPrimaryOutput->devices();
            }
            if (oldState == AUDIO_MODE_IN_CALL) {
                disconnectTelephonyAudioSource(mCallRxSourceClient);
                disconnectTelephonyAudioSource(mCallTxSourceClient);
            }
            setOutputDevices(mPrimaryOutput, rxDevices, force, 0);
        }
    }

    // reevaluate routing on all outputs in case tracks have been started during the call
    for (size_t i = 0; i < mOutputs.size(); i++) {
        sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
        DeviceVector newDevices = getNewOutputDevices(desc, true /*fromCache*/);
        if (state != AUDIO_MODE_IN_CALL || (desc != mPrimaryOutput && !isTelephonyRxOrTx(desc))) {
            bool forceRouting = !newDevices.isEmpty();
            setOutputDevices(desc, newDevices, forceRouting, 0 /*delayMs*/, nullptr,
                             true /*requiresMuteCheck*/, !forceRouting /*requiresVolumeCheck*/);
        }
    }

    checkLeBroadcastRoutes(wasLeUnicastActive, nullptr, delayMs);

    if (isStateInCall(state)) {
        ALOGV("setPhoneState() in call state management: new state is %d", state);
        // force reevaluating accessibility routing when call starts
        mpClientInterface->invalidateStream(AUDIO_STREAM_ACCESSIBILITY);
    }

    // Flag that ringtone volume must be limited to music volume until we exit MODE_RINGTONE
    mLimitRingtoneVolume = (state == AUDIO_MODE_RINGTONE &&
                            isStreamActive(AUDIO_STREAM_MUSIC, SONIFICATION_HEADSET_MUSIC_DELAY));
}

audio_mode_t AudioPolicyManager::getPhoneState() {
    return mEngine->getPhoneState();
}

void AudioPolicyManager::setForceUse(audio_policy_force_use_t usage,
                                     audio_policy_forced_cfg_t config)
{
    ALOGV("setForceUse() usage %d, config %d, mPhoneState %d", usage, config, mEngine->getPhoneState());
    if (config == mEngine->getForceUse(usage)) {
        return;
    }

    if (mEngine->setForceUse(usage, config) != NO_ERROR) {
        ALOGW("setForceUse() could not set force cfg %d for usage %d", config, usage);
        return;
    }
    bool forceVolumeReeval = (usage == AUDIO_POLICY_FORCE_FOR_COMMUNICATION) ||
            (usage == AUDIO_POLICY_FORCE_FOR_DOCK) ||
            (usage == AUDIO_POLICY_FORCE_FOR_SYSTEM);

    // check for device and output changes triggered by new force usage
    checkForDeviceAndOutputChanges();

    // force client reconnection to reevaluate flag AUDIO_FLAG_AUDIBILITY_ENFORCED
    if (usage == AUDIO_POLICY_FORCE_FOR_SYSTEM) {
        mpClientInterface->invalidateStream(AUDIO_STREAM_SYSTEM);
        mpClientInterface->invalidateStream(AUDIO_STREAM_ENFORCED_AUDIBLE);
    }

    //FIXME: workaround for truncated touch sounds
    // to be removed when the problem is handled by system UI
    uint32_t delayMs = 0;
    if (usage == AUDIO_POLICY_FORCE_FOR_COMMUNICATION) {
        delayMs = TOUCH_SOUND_FIXED_DELAY_MS;
    }

    updateCallAndOutputRouting(forceVolumeReeval, delayMs);
    updateInputRouting();
}

void AudioPolicyManager::setSystemProperty(const char* property, const char* value)
{
    ALOGV("setSystemProperty() property %s, value %s", property, value);
}

// Find an MSD output profile compatible with the parameters passed.
// When "directOnly" is set, restrict search to profiles for direct outputs.
sp<IOProfile> AudioPolicyManager::getMsdProfileForOutput(
                                                   const DeviceVector& devices,
                                                   uint32_t samplingRate,
                                                   audio_format_t format,
                                                   audio_channel_mask_t channelMask,
                                                   audio_output_flags_t flags,
                                                   bool directOnly)
{
    flags = getRelevantFlags(flags, directOnly);

    sp<HwModule> msdModule = mHwModules.getModuleFromName(AUDIO_HARDWARE_MODULE_ID_MSD);
    if (msdModule != nullptr) {
        // for the msd module check if there are patches to the output devices
        if (msdHasPatchesToAllDevices(devices.toTypeAddrVector())) {
            HwModuleCollection modules;
            modules.add(msdModule);
            return searchCompatibleProfileHwModules(
                    modules, getMsdAudioOutDevices(), samplingRate, format, channelMask,
                    flags, directOnly);
        }
    }
    return nullptr;
}

// Find an output profile compatible with the parameters passed. When "directOnly" is set, restrict
// search to profiles for direct outputs.
sp<IOProfile> AudioPolicyManager::getProfileForOutput(
                                                   const DeviceVector& devices,
                                                   uint32_t samplingRate,
                                                   audio_format_t format,
                                                   audio_channel_mask_t channelMask,
                                                   audio_output_flags_t flags,
                                                   bool directOnly)
{
    flags = getRelevantFlags(flags, directOnly);

    return searchCompatibleProfileHwModules(
            mHwModules, devices, samplingRate, format, channelMask, flags, directOnly);
}

audio_output_flags_t AudioPolicyManager::getRelevantFlags (
                                            audio_output_flags_t flags, bool directOnly) {
    if (directOnly) {
         // only retain flags that will drive the direct output profile selection
         // if explicitly requested
         static const uint32_t kRelevantFlags =
                (AUDIO_OUTPUT_FLAG_HW_AV_SYNC | AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD |
                AUDIO_OUTPUT_FLAG_VOIP_RX | AUDIO_OUTPUT_FLAG_MMAP_NOIRQ);
         flags = (audio_output_flags_t)((flags & kRelevantFlags) | AUDIO_OUTPUT_FLAG_DIRECT);
    }
    return flags;
}

sp<IOProfile> AudioPolicyManager::searchCompatibleProfileHwModules (
                                        const HwModuleCollection& hwModules,
                                        const DeviceVector& devices,
                                        uint32_t samplingRate,
                                        audio_format_t format,
                                        audio_channel_mask_t channelMask,
                                        audio_output_flags_t flags,
                                        bool directOnly) {
    sp<IOProfile> profile;
    for (const auto& hwModule : hwModules) {
        for (const auto& curProfile : hwModule->getOutputProfiles()) {
             if (!curProfile->isCompatibleProfile(devices,
                     samplingRate, NULL /*updatedSamplingRate*/,
                     format, NULL /*updatedFormat*/,
                     channelMask, NULL /*updatedChannelMask*/,
                     flags)) {
                 continue;
             }
             // reject profiles not corresponding to a device currently available
             if (!mAvailableOutputDevices.containsAtLeastOne(curProfile->getSupportedDevices())) {
                 continue;
             }
             // reject profiles if connected device does not support codec
             if (!curProfile->devicesSupportEncodedFormats(devices.types())) {
                 continue;
             }
             if (!directOnly) {
                return curProfile;
             }

             // when searching for direct outputs, if several profiles are compatible, give priority
             // to one with offload capability
             if (profile != 0 && 
                 ((curProfile->getFlags() & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) == 0)) {
                continue;
             }
             profile = curProfile;
             if ((profile->getFlags() & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) != 0) {
                 break;
             }
        }
    }
    return profile;
}

sp<IOProfile> AudioPolicyManager::getSpatializerOutputProfile(
        const audio_config_t *config __unused, const AudioDeviceTypeAddrVector &devices) const
{
    for (const auto& hwModule : mHwModules) {
        for (const auto& curProfile : hwModule->getOutputProfiles()) {
            if (curProfile->getFlags() != AUDIO_OUTPUT_FLAG_SPATIALIZER) {
                continue;
            }
            if (!devices.empty()) {
                // reject profiles not corresponding to a device currently available
                DeviceVector supportedDevices = curProfile->getSupportedDevices();
                if (!mAvailableOutputDevices.containsAtLeastOne(supportedDevices)) {
                    continue;
                }
                if (supportedDevices.getDevicesFromDeviceTypeAddrVec(devices).size()
                        != devices.size()) {
                    continue;
                }
            }
            ALOGV("%s found profile %s", __func__, curProfile->getName().c_str());
            return curProfile;
        }
    }
    return nullptr;
}

audio_io_handle_t AudioPolicyManager::getOutput(audio_stream_type_t stream)
{
    DeviceVector devices = mEngine->getOutputDevicesForStream(stream, false /*fromCache*/);

    // Note that related method getOutputForAttr() uses getOutputForDevice() not selectOutput().
    // We use selectOutput() here since we don't have the desired AudioTrack sample rate,
    // format, flags, etc. This may result in some discrepancy for functions that utilize
    // getOutput() solely on audio_stream_type such as AudioSystem::getOutputFrameCount()
    // and AudioSystem::getOutputSamplingRate().

    SortedVector<audio_io_handle_t> outputs = getOutputsForDevices(devices, mOutputs);
    const audio_io_handle_t output = selectOutput(outputs);

    ALOGV("getOutput() stream %d selected devices %s, output %d", stream,
          devices.toString().c_str(), output);
    return output;
}

status_t AudioPolicyManager::getAudioAttributes(audio_attributes_t *dstAttr,
                                                const audio_attributes_t *srcAttr,
                                                audio_stream_type_t srcStream)
{
    if (srcAttr != NULL) {
        if (!isValidAttributes(srcAttr)) {
            ALOGE("%s invalid attributes: usage=%d content=%d flags=0x%x tags=[%s]",
                    __func__,
                    srcAttr->usage, srcAttr->content_type, srcAttr->flags,
                    srcAttr->tags);
            return BAD_VALUE;
        }
        *dstAttr = *srcAttr;
    } else {
        if (srcStream < AUDIO_STREAM_MIN || srcStream >= AUDIO_STREAM_PUBLIC_CNT) {
            ALOGE("%s:  invalid stream type", __func__);
            return BAD_VALUE;
        }
        *dstAttr = mEngine->getAttributesForStreamType(srcStream);
    }

    // Only honor audibility enforced when required. The client will be
    // forced to reconnect if the forced usage changes.
    if (mEngine->getForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM) != AUDIO_POLICY_FORCE_SYSTEM_ENFORCED) {
        dstAttr->flags = static_cast<audio_flags_mask_t>(
                dstAttr->flags & ~AUDIO_FLAG_AUDIBILITY_ENFORCED);
    }

    return NO_ERROR;
}

status_t AudioPolicyManager::getOutputForAttrInt(
        audio_attributes_t *resultAttr,
        audio_io_handle_t *output,
        audio_session_t session,
        const audio_attributes_t *attr,
        audio_stream_type_t *stream,
        uid_t uid,
        const audio_config_t *config,
        audio_output_flags_t *flags,
        audio_port_handle_t *selectedDeviceId,
        bool *isRequestedDeviceForExclusiveUse,
        std::vector<sp<AudioPolicyMix>> *secondaryMixes,
        output_type_t *outputType,
        bool *isSpatialized)
{
    DeviceVector outputDevices;
    const audio_port_handle_t requestedPortId = *selectedDeviceId;
    DeviceVector msdDevices = getMsdAudioOutDevices();
    const sp<DeviceDescriptor> requestedDevice =
        mAvailableOutputDevices.getDeviceFromId(requestedPortId);

    *outputType = API_OUTPUT_INVALID;
    *isSpatialized = false;

    status_t status = getAudioAttributes(resultAttr, attr, *stream);
    if (status != NO_ERROR) {
        return status;
    }
    if (auto it = mAllowedCapturePolicies.find(uid); it != end(mAllowedCapturePolicies)) {
        resultAttr->flags = static_cast<audio_flags_mask_t>(resultAttr->flags | it->second);
    }
    *stream = mEngine->getStreamTypeForAttributes(*resultAttr);

    ALOGV("%s() attributes=%s stream=%s session %d selectedDeviceId %d", __func__,
          toString(*resultAttr).c_str(), toString(*stream).c_str(), session, requestedPortId);

    // The primary output is the explicit routing (eg. setPreferredDevice) if specified,
    //       otherwise, fallback to the dynamic policies, if none match, query the engine.
    // Secondary outputs are always found by dynamic policies as the engine do not support them
    sp<AudioPolicyMix> primaryMix;
    const audio_config_base_t clientConfig = {.sample_rate = config->sample_rate,
        .channel_mask = config->channel_mask,
        .format = config->format,
    };
    status = mPolicyMixes.getOutputForAttr(*resultAttr, clientConfig, uid, *flags, primaryMix,
                                           secondaryMixes);
    if (status != OK) {
        return status;
    }

    // Explicit routing is higher priority then any dynamic policy primary output
    bool usePrimaryOutputFromPolicyMixes = requestedDevice == nullptr && primaryMix != nullptr;

    // FIXME: in case of RENDER policy, the output capabilities should be checked
    if ((secondaryMixes != nullptr && !secondaryMixes->empty())
            && !audio_is_linear_pcm(config->format)) {
        ALOGD("%s: rejecting request as secondary mixes only support pcm", __func__);
        return BAD_VALUE;
    }
    if (usePrimaryOutputFromPolicyMixes) {
        sp<DeviceDescriptor> deviceDesc =
                mAvailableOutputDevices.getDevice(primaryMix->mDeviceType,
                                                  primaryMix->mDeviceAddress,
                                                  AUDIO_FORMAT_DEFAULT);
        sp<SwAudioOutputDescriptor> policyDesc = primaryMix->getOutput();
        bool tryDirectForFlags = policyDesc == nullptr ||
                (policyDesc->mFlags & AUDIO_OUTPUT_FLAG_DIRECT);
        // if a direct output can be opened to deliver the track's multi-channel content to the
        // output rather than being downmixed by the primary output, then use this direct
        // output by by-passing the primary mix if possible, otherwise fall-through to primary
        // mix.
        bool tryDirectForChannelMask = policyDesc != nullptr
                    && (audio_channel_count_from_out_mask(policyDesc->getConfig().channel_mask) <
                        audio_channel_count_from_out_mask(config->channel_mask));
        if (deviceDesc != nullptr && (tryDirectForFlags || tryDirectForChannelMask)) {
            audio_io_handle_t newOutput;
            status = openDirectOutput(
                    *stream, session, config,
                    (audio_output_flags_t)(*flags | AUDIO_OUTPUT_FLAG_DIRECT),
                    DeviceVector(deviceDesc), &newOutput);
            if (status == NO_ERROR) {
                policyDesc = mOutputs.valueFor(newOutput);
                primaryMix->setOutput(policyDesc);
            } else if (tryDirectForFlags) {
                policyDesc = nullptr;
            } // otherwise use primary if available.
        }
        if (policyDesc != nullptr) {
            policyDesc->mPolicyMix = primaryMix;
            *output = policyDesc->mIoHandle;
            *selectedDeviceId = deviceDesc != 0 ? deviceDesc->getId() : AUDIO_PORT_HANDLE_NONE;

            ALOGV("getOutputForAttr() returns output %d", *output);
            if (resultAttr->usage == AUDIO_USAGE_VIRTUAL_SOURCE) {
                *outputType = API_OUT_MIX_PLAYBACK;
            } else {
                *outputType = API_OUTPUT_LEGACY;
            }
            return NO_ERROR;
        }
    }
    // Virtual sources must always be dynamicaly or explicitly routed
    if (resultAttr->usage == AUDIO_USAGE_VIRTUAL_SOURCE) {
        ALOGW("getOutputForAttr() no policy mix found for usage AUDIO_USAGE_VIRTUAL_SOURCE");
        return BAD_VALUE;
    }
    // explicit routing managed by getDeviceForStrategy in APM is now handled by engine
    // in order to let the choice of the order to future vendor engine
    outputDevices = mEngine->getOutputDevicesForAttributes(*resultAttr, requestedDevice, false);

    if ((resultAttr->flags & AUDIO_FLAG_HW_AV_SYNC) != 0) {
        *flags = (audio_output_flags_t)(*flags | AUDIO_OUTPUT_FLAG_HW_AV_SYNC);
    }

    // Set incall music only if device was explicitly set, and fallback to the device which is
    // chosen by the engine if not.
    // FIXME: provide a more generic approach which is not device specific and move this back
    // to getOutputForDevice.
    // TODO: Remove check of AUDIO_STREAM_MUSIC once migration is completed on the app side.
    if (outputDevices.onlyContainsDevicesWithType(AUDIO_DEVICE_OUT_TELEPHONY_TX) &&
        (*stream == AUDIO_STREAM_MUSIC  || resultAttr->usage == AUDIO_USAGE_VOICE_COMMUNICATION) &&
        audio_is_linear_pcm(config->format) &&
        isCallAudioAccessible()) {
        if (requestedPortId != AUDIO_PORT_HANDLE_NONE) {
            *flags = (audio_output_flags_t)AUDIO_OUTPUT_FLAG_INCALL_MUSIC;
            *isRequestedDeviceForExclusiveUse = true;
        }
    }

    ALOGV("%s() device %s, sampling rate %d, format %#x, channel mask %#x, flags %#x stream %s",
          __func__, outputDevices.toString().c_str(), config->sample_rate, config->format,
          config->channel_mask, *flags, toString(*stream).c_str());

    *output = AUDIO_IO_HANDLE_NONE;
    if (!msdDevices.isEmpty()) {
        *output = getOutputForDevices(msdDevices, session, resultAttr, config, flags, isSpatialized);
        if (*output != AUDIO_IO_HANDLE_NONE && setMsdOutputPatches(&outputDevices) == NO_ERROR) {
            ALOGV("%s() Using MSD devices %s instead of devices %s",
                  __func__, msdDevices.toString().c_str(), outputDevices.toString().c_str());
        } else {
            *output = AUDIO_IO_HANDLE_NONE;
        }
    }
    if (*output == AUDIO_IO_HANDLE_NONE) {
        *output = getOutputForDevices(outputDevices, session, resultAttr, config,
                flags, isSpatialized, resultAttr->flags & AUDIO_FLAG_MUTE_HAPTIC);
    }
    if (*output == AUDIO_IO_HANDLE_NONE) {
        return INVALID_OPERATION;
    }

    *selectedDeviceId = getFirstDeviceId(outputDevices);
    for (auto &outputDevice : outputDevices) {
        if (outputDevice->getId() == getConfig().getDefaultOutputDevice()->getId()) {
            *selectedDeviceId = outputDevice->getId();
            break;
        }
    }

    if (outputDevices.onlyContainsDevicesWithType(AUDIO_DEVICE_OUT_TELEPHONY_TX)) {
        *outputType = API_OUTPUT_TELEPHONY_TX;
    } else {
        *outputType = API_OUTPUT_LEGACY;
    }

    ALOGV("%s returns output %d selectedDeviceId %d", __func__, *output, *selectedDeviceId);

    return NO_ERROR;
}

status_t AudioPolicyManager::getOutputForAttr(const audio_attributes_t *attr,
                                              audio_io_handle_t *output,
                                              audio_session_t session,
                                              audio_stream_type_t *stream,
                                              const AttributionSourceState& attributionSource,
                                              const audio_config_t *config,
                                              audio_output_flags_t *flags,
                                              audio_port_handle_t *selectedDeviceId,
                                              audio_port_handle_t *portId,
                                              std::vector<audio_io_handle_t> *secondaryOutputs,
                                              output_type_t *outputType,
                                              bool *isSpatialized)
{
    // The supplied portId must be AUDIO_PORT_HANDLE_NONE
    if (*portId != AUDIO_PORT_HANDLE_NONE) {
        return INVALID_OPERATION;
    }
    const uid_t uid = VALUE_OR_RETURN_STATUS(
        aidl2legacy_int32_t_uid_t(attributionSource.uid));
    const audio_port_handle_t requestedPortId = *selectedDeviceId;
    audio_attributes_t resultAttr;
    bool isRequestedDeviceForExclusiveUse = false;
    std::vector<sp<AudioPolicyMix>> secondaryMixes;
    const sp<DeviceDescriptor> requestedDevice =
      mAvailableOutputDevices.getDeviceFromId(requestedPortId);

    // Prevent from storing invalid requested device id in clients
    const audio_port_handle_t sanitizedRequestedPortId =
      requestedDevice != nullptr ? requestedPortId : AUDIO_PORT_HANDLE_NONE;
    *selectedDeviceId = sanitizedRequestedPortId;

    status_t status = getOutputForAttrInt(&resultAttr, output, session, attr, stream, uid,
            config, flags, selectedDeviceId, &isRequestedDeviceForExclusiveUse,
            secondaryOutputs != nullptr ? &secondaryMixes : nullptr, outputType, isSpatialized);
    if (status != NO_ERROR) {
        return status;
    }
    std::vector<wp<SwAudioOutputDescriptor>> weakSecondaryOutputDescs;
    if (secondaryOutputs != nullptr) {
        for (auto &secondaryMix : secondaryMixes) {
            sp<SwAudioOutputDescriptor> outputDesc = secondaryMix->getOutput();
            if (outputDesc != nullptr &&
                outputDesc->mIoHandle != AUDIO_IO_HANDLE_NONE) {
                secondaryOutputs->push_back(outputDesc->mIoHandle);
                weakSecondaryOutputDescs.push_back(outputDesc);
            }
        }
    }

    audio_config_base_t clientConfig = {.sample_rate = config->sample_rate,
        .channel_mask = config->channel_mask,
        .format = config->format,
    };
    *portId = PolicyAudioPort::getNextUniqueId();

    sp<SwAudioOutputDescriptor> outputDesc = mOutputs.valueFor(*output);
    sp<TrackClientDescriptor> clientDesc =
        new TrackClientDescriptor(*portId, uid, session, resultAttr, clientConfig,
                                  sanitizedRequestedPortId, *stream,
                                  mEngine->getProductStrategyForAttributes(resultAttr),
                                  toVolumeSource(resultAttr),
                                  *flags, isRequestedDeviceForExclusiveUse,
                                  std::move(weakSecondaryOutputDescs),
                                  outputDesc->mPolicyMix);
    outputDesc->addClient(clientDesc);

    ALOGV("%s() returns output %d requestedPortId %d selectedDeviceId %d for port ID %d", __func__,
          *output, requestedPortId, *selectedDeviceId, *portId);

    return NO_ERROR;
}

status_t AudioPolicyManager::openDirectOutput(audio_stream_type_t stream,
                                              audio_session_t session,
                                              const audio_config_t *config,
                                              audio_output_flags_t flags,
                                              const DeviceVector &devices,
                                              audio_io_handle_t *output) {

    *output = AUDIO_IO_HANDLE_NONE;

    // skip direct output selection if the request can obviously be attached to a mixed output
    // and not explicitly requested
    if (((flags & AUDIO_OUTPUT_FLAG_DIRECT) == 0) &&
            audio_is_linear_pcm(config->format) && config->sample_rate <= SAMPLE_RATE_HZ_MAX &&
            audio_channel_count_from_out_mask(config->channel_mask) <= 2) {
        return NAME_NOT_FOUND;
    }

    // Do not allow offloading if one non offloadable effect is enabled or MasterMono is enabled.
    // This prevents creating an offloaded track and tearing it down immediately after start
    // when audioflinger detects there is an active non offloadable effect.
    // FIXME: We should check the audio session here but we do not have it in this context.
    // This may prevent offloading in rare situations where effects are left active by apps
    // in the background.
    sp<IOProfile> profile;
    if (((flags & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) == 0) ||
            !(mEffects.isNonOffloadableEffectEnabled() || mMasterMono)) {
        profile = getProfileForOutput(
                devices, config->sample_rate, config->format, config->channel_mask,
                flags, true /* directOnly */);
    }

    if (profile == nullptr) {
        return NAME_NOT_FOUND;
    }

    // exclusive outputs for MMAP and Offload are enforced by different session ids.
    for (size_t i = 0; i < mOutputs.size(); i++) {
        sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
        if (!desc->isDuplicated() && (profile == desc->mProfile)) {
            // reuse direct output if currently open by the same client
            // and configured with same parameters
            if ((config->sample_rate == desc->getSamplingRate()) &&
                (config->format == desc->getFormat()) &&
                (config->channel_mask == desc->getChannelMask()) &&
                (session == desc->mDirectClientSession)) {
                desc->mDirectOpenCount++;
                ALOGV("%s reusing direct output %d for session %d", __func__,
                    mOutputs.keyAt(i), session);
                *output = mOutputs.keyAt(i);
                return NO_ERROR;
            }
        }
    }

    if (!profile->canOpenNewIo()) {
        return NAME_NOT_FOUND;
    }

    sp<SwAudioOutputDescriptor> outputDesc =
            new SwAudioOutputDescriptor(profile, mpClientInterface);

    // An MSD patch may be using the only output stream that can service this request. Release
    // all MSD patches to prioritize this request over any active output on MSD.
    releaseMsdOutputPatches(devices);

    status_t status =
            outputDesc->open(config, nullptr /* mixerConfig */, devices, stream, flags, output);

    // only accept an output with the requested parameters
    if (status != NO_ERROR ||
        (config->sample_rate != 0 && config->sample_rate != outputDesc->getSamplingRate()) ||
        (config->format != AUDIO_FORMAT_DEFAULT && config->format != outputDesc->getFormat()) ||
        (config->channel_mask != 0 && config->channel_mask != outputDesc->getChannelMask())) {
        ALOGV("%s failed opening direct output: output %d sample rate %d %d,"
                "format %d %d, channel mask %04x %04x", __func__, *output, config->sample_rate,
                outputDesc->getSamplingRate(), config->format, outputDesc->getFormat(),
                config->channel_mask, outputDesc->getChannelMask());
        if (*output != AUDIO_IO_HANDLE_NONE) {
            outputDesc->close();
        }
        // fall back to mixer output if possible when the direct output could not be open
        if (audio_is_linear_pcm(config->format) &&
                config->sample_rate  <= SAMPLE_RATE_HZ_MAX) {
            return NAME_NOT_FOUND;
        }
        *output = AUDIO_IO_HANDLE_NONE;
        return BAD_VALUE;
    }
    outputDesc->mDirectOpenCount = 1;
    outputDesc->mDirectClientSession = session;

    addOutput(*output, outputDesc);
    mPreviousOutputs = mOutputs;
    ALOGV("%s returns new direct output %d", __func__, *output);
    mpClientInterface->onAudioPortListUpdate();
    return NO_ERROR;
}

audio_io_handle_t AudioPolicyManager::getOutputForDevices(
        const DeviceVector &devices,
        audio_session_t session,
        const audio_attributes_t *attr,
        const audio_config_t *config,
        audio_output_flags_t *flags,
        bool *isSpatialized,
        bool forceMutingHaptic)
{
    audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;

    // Discard haptic channel mask when forcing muting haptic channels.
    audio_channel_mask_t channelMask = forceMutingHaptic
            ? static_cast<audio_channel_mask_t>(config->channel_mask & ~AUDIO_CHANNEL_HAPTIC_ALL)
            : config->channel_mask;

    // open a direct output if required by specified parameters
    //force direct flag if offload flag is set: offloading implies a direct output stream
    // and all common behaviors are driven by checking only the direct flag
    // this should normally be set appropriately in the policy configuration file
    if ((*flags & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) != 0) {
        *flags = (audio_output_flags_t)(*flags | AUDIO_OUTPUT_FLAG_DIRECT);
    }
    if ((*flags & AUDIO_OUTPUT_FLAG_HW_AV_SYNC) != 0) {
        *flags = (audio_output_flags_t)(*flags | AUDIO_OUTPUT_FLAG_DIRECT);
    }

    audio_stream_type_t stream = mEngine->getStreamTypeForAttributes(*attr);

    // only allow deep buffering for music stream type
    if (stream != AUDIO_STREAM_MUSIC) {
        *flags = (audio_output_flags_t)(*flags &~AUDIO_OUTPUT_FLAG_DEEP_BUFFER);
    } else if (/* stream == AUDIO_STREAM_MUSIC && */
            *flags == AUDIO_OUTPUT_FLAG_NONE &&
            property_get_bool("audio.deep_buffer.media", false /* default_value */)) {
        // use DEEP_BUFFER as default output for music stream type
        *flags = (audio_output_flags_t)AUDIO_OUTPUT_FLAG_DEEP_BUFFER;
    }
    if (stream == AUDIO_STREAM_TTS) {
        *flags = AUDIO_OUTPUT_FLAG_TTS;
    } else if (stream == AUDIO_STREAM_VOICE_CALL &&
               audio_is_linear_pcm(config->format) &&
               (*flags & AUDIO_OUTPUT_FLAG_INCALL_MUSIC) == 0) {
        *flags = (audio_output_flags_t)(AUDIO_OUTPUT_FLAG_VOIP_RX |
                                       AUDIO_OUTPUT_FLAG_DIRECT);
        ALOGV("Set VoIP and Direct output flags for PCM format");
    }

    // Attach the Ultrasound flag for the AUDIO_CONTENT_TYPE_ULTRASOUND
    if (attr->content_type == AUDIO_CONTENT_TYPE_ULTRASOUND) {
        *flags = (audio_output_flags_t)(*flags | AUDIO_OUTPUT_FLAG_ULTRASOUND);
    }

    *isSpatialized = false;
    if (mSpatializerOutput != nullptr
            && canBeSpatializedInt(attr, config, devices.toTypeAddrVector())) {
        *isSpatialized = true;
        return mSpatializerOutput->mIoHandle;
    }

    audio_config_t directConfig = *config;
    directConfig.channel_mask = channelMask;
    status_t status = openDirectOutput(stream, session, &directConfig, *flags, devices, &output);
    if (status != NAME_NOT_FOUND) {
        return output;
    }

    // A request for HW A/V sync cannot fallback to a mixed output because time
    // stamps are embedded in audio data
    if ((*flags & (AUDIO_OUTPUT_FLAG_HW_AV_SYNC | AUDIO_OUTPUT_FLAG_MMAP_NOIRQ)) != 0) {
        return AUDIO_IO_HANDLE_NONE;
    }

    // ignoring channel mask due to downmix capability in mixer

    // open a non direct output

    // for non direct outputs, only PCM is supported
    if (audio_is_linear_pcm(config->format)) {
        // get which output is suitable for the specified stream. The actual
        // routing change will happen when startOutput() will be called
        SortedVector<audio_io_handle_t> outputs = getOutputsForDevices(devices, mOutputs);

        // at this stage we should ignore the DIRECT flag as no direct output could be found earlier
        *flags = (audio_output_flags_t)(*flags & ~AUDIO_OUTPUT_FLAG_DIRECT);
        output = selectOutput(
                outputs, *flags, config->format, channelMask, config->sample_rate, session);
    }
    ALOGW_IF((output == 0), "getOutputForDevices() could not find output for stream %d, "
            "sampling rate %d, format %#x, channels %#x, flags %#x",
            stream, config->sample_rate, config->format, channelMask, *flags);

    return output;
}

sp<DeviceDescriptor> AudioPolicyManager::getMsdAudioInDevice() const {
    auto msdInDevices = mHwModules.getAvailableDevicesFromModuleName(AUDIO_HARDWARE_MODULE_ID_MSD,
                                                                     mAvailableInputDevices);
    return msdInDevices.isEmpty()? nullptr : msdInDevices.itemAt(0);
}

DeviceVector AudioPolicyManager::getMsdAudioOutDevices() const {
    return mHwModules.getAvailableDevicesFromModuleName(AUDIO_HARDWARE_MODULE_ID_MSD,
                                                        mAvailableOutputDevices);
}

const AudioPatchCollection AudioPolicyManager::getMsdOutputPatches() const {
    AudioPatchCollection msdPatches;
    sp<HwModule> msdModule = mHwModules.getModuleFromName(AUDIO_HARDWARE_MODULE_ID_MSD);
    if (msdModule != 0) {
        for (size_t i = 0; i < mAudioPatches.size(); ++i) {
            sp<AudioPatch> patch = mAudioPatches.valueAt(i);
            for (size_t j = 0; j < patch->mPatch.num_sources; ++j) {
                const struct audio_port_config *source = &patch->mPatch.sources[j];
                if (source->type == AUDIO_PORT_TYPE_DEVICE &&
                        source->ext.device.hw_module == msdModule->getHandle()) {
                    msdPatches.addAudioPatch(patch->getHandle(), patch);
                }
            }
        }
    }
    return msdPatches;
}

bool AudioPolicyManager::isMsdPatch(const audio_patch_handle_t &handle) const {
    ssize_t index = mAudioPatches.indexOfKey(handle);
    if (index < 0) {
        return false;
    }
    const sp<AudioPatch> patch = mAudioPatches.valueAt(index);
    sp<HwModule> msdModule = mHwModules.getModuleFromName(AUDIO_HARDWARE_MODULE_ID_MSD);
    if (msdModule == nullptr) {
        return false;
    }
    const struct audio_port_config *sink = &patch->mPatch.sinks[0];
    if (getMsdAudioOutDevices().contains(mAvailableOutputDevices.getDeviceFromId(sink->id))) {
        return true;
    }
    index = getMsdOutputPatches().indexOfKey(handle);
    if (index < 0) {
        return false;
    }
    return true;
}

status_t AudioPolicyManager::getMsdProfiles(bool hwAvSync,
                                            const InputProfileCollection &inputProfiles,
                                            const OutputProfileCollection &outputProfiles,
                                            const sp<DeviceDescriptor> &sourceDevice,
                                            const sp<DeviceDescriptor> &sinkDevice,
                                            AudioProfileVector& sourceProfiles,
                                            AudioProfileVector& sinkProfiles) const {
    if (inputProfiles.isEmpty()) {
        ALOGE("%s() no input profiles for source module", __func__);
        return NO_INIT;
    }
    if (outputProfiles.isEmpty()) {
        ALOGE("%s() no output profiles for sink module", __func__);
        return NO_INIT;
    }
    for (const auto &inProfile : inputProfiles) {
        if (hwAvSync == ((inProfile->getFlags() & AUDIO_INPUT_FLAG_HW_AV_SYNC) != 0) &&
                inProfile->supportsDevice(sourceDevice)) {
            appendAudioProfiles(sourceProfiles, inProfile->getAudioProfiles());
        }
    }
    for (const auto &outProfile : outputProfiles) {
        if (hwAvSync == ((outProfile->getFlags() & AUDIO_OUTPUT_FLAG_HW_AV_SYNC) != 0) &&
                outProfile->supportsDevice(sinkDevice)) {
            appendAudioProfiles(sinkProfiles, outProfile->getAudioProfiles());
        }
    }
    return NO_ERROR;
}

status_t AudioPolicyManager::getBestMsdConfig(bool hwAvSync,
        const AudioProfileVector &sourceProfiles, const AudioProfileVector &sinkProfiles,
        audio_port_config *sourceConfig, audio_port_config *sinkConfig) const
{
    struct audio_config_base bestSinkConfig;
    status_t result = findBestMatchingOutputConfig(sourceProfiles, sinkProfiles,
            msdCompressedFormatsOrder, msdSurroundChannelMasksOrder,
            true /*preferHigherSamplingRates*/, bestSinkConfig);
    if (result != NO_ERROR) {
        ALOGD("%s() no matching config found for sink, hwAvSync: %d",
                __func__, hwAvSync);
        return result;
    }
    sinkConfig->sample_rate = bestSinkConfig.sample_rate;
    sinkConfig->channel_mask = bestSinkConfig.channel_mask;
    sinkConfig->format = bestSinkConfig.format;
    // For encoded streams force direct flag to prevent downstream mixing.
    sinkConfig->flags.output = static_cast<audio_output_flags_t>(
            sinkConfig->flags.output | AUDIO_OUTPUT_FLAG_DIRECT);
    if (audio_is_iec61937_compatible(sinkConfig->format)) {
        // For formats compatible with IEC61937 encapsulation, assume that
        // the input is IEC61937 framed (for proportional buffer sizing).
        // Add the AUDIO_OUTPUT_FLAG_IEC958_NONAUDIO flag so downstream HAL can distinguish between
        // raw and IEC61937 framed streams.
        sinkConfig->flags.output = static_cast<audio_output_flags_t>(
                sinkConfig->flags.output | AUDIO_OUTPUT_FLAG_IEC958_NONAUDIO);
    }
    sourceConfig->sample_rate = bestSinkConfig.sample_rate;
    // Specify exact channel mask to prevent guessing by bit count in PatchPanel.
    sourceConfig->channel_mask = audio_channel_mask_out_to_in(bestSinkConfig.channel_mask);
    sourceConfig->format = bestSinkConfig.format;
    // Copy input stream directly without any processing (e.g. resampling).
    sourceConfig->flags.input = static_cast<audio_input_flags_t>(
            sourceConfig->flags.input | AUDIO_INPUT_FLAG_DIRECT);
    if (hwAvSync) {
        sinkConfig->flags.output = static_cast<audio_output_flags_t>(
                sinkConfig->flags.output | AUDIO_OUTPUT_FLAG_HW_AV_SYNC);
        sourceConfig->flags.input = static_cast<audio_input_flags_t>(
                sourceConfig->flags.input | AUDIO_INPUT_FLAG_HW_AV_SYNC);
    }
    const unsigned int config_mask = AUDIO_PORT_CONFIG_SAMPLE_RATE |
            AUDIO_PORT_CONFIG_CHANNEL_MASK | AUDIO_PORT_CONFIG_FORMAT | AUDIO_PORT_CONFIG_FLAGS;
    sinkConfig->config_mask |= config_mask;
    sourceConfig->config_mask |= config_mask;
    return NO_ERROR;
}

PatchBuilder AudioPolicyManager::buildMsdPatch(bool msdIsSource,
                                               const sp<DeviceDescriptor> &device) const
{
    PatchBuilder patchBuilder;
    sp<HwModule> msdModule = mHwModules.getModuleFromName(AUDIO_HARDWARE_MODULE_ID_MSD);
    ALOG_ASSERT(msdModule != nullptr, "MSD module not available");
    sp<HwModule> deviceModule = mHwModules.getModuleForDevice(device, AUDIO_FORMAT_DEFAULT);
    if (deviceModule == nullptr) {
        ALOGE("%s() unable to get module for %s", __func__, device->toString().c_str());
        return patchBuilder;
    }
    const InputProfileCollection inputProfiles = msdIsSource ?
            msdModule->getInputProfiles() : deviceModule->getInputProfiles();
    const OutputProfileCollection outputProfiles = msdIsSource ?
            deviceModule->getOutputProfiles() : msdModule->getOutputProfiles();

    const sp<DeviceDescriptor> sourceDevice = msdIsSource ? getMsdAudioInDevice() : device;
    const sp<DeviceDescriptor> sinkDevice = msdIsSource ?
            device : getMsdAudioOutDevices().itemAt(0);
    patchBuilder.addSource(sourceDevice).addSink(sinkDevice);

    audio_port_config sourceConfig = patchBuilder.patch()->sources[0];
    audio_port_config sinkConfig = patchBuilder.patch()->sinks[0];
    AudioProfileVector sourceProfiles;
    AudioProfileVector sinkProfiles;
    // TODO: Figure out whether MSD module has HW_AV_SYNC flag set in the AP config file.
    // For now, we just forcefully try with HwAvSync first.
    for (auto hwAvSync : { true, false }) {
        if (getMsdProfiles(hwAvSync, inputProfiles, outputProfiles, sourceDevice, sinkDevice,
                sourceProfiles, sinkProfiles) != NO_ERROR) {
            continue;
        }
        if (getBestMsdConfig(hwAvSync, sourceProfiles, sinkProfiles, &sourceConfig,
                &sinkConfig) == NO_ERROR) {
            // Found a matching config. Re-create PatchBuilder with this config.
            return (PatchBuilder()).addSource(sourceConfig).addSink(sinkConfig);
        }
    }
    ALOGV("%s() no matching config found. Fall through to default PCM patch"
            " supporting PCM format conversion.", __func__);
    return patchBuilder;
}

status_t AudioPolicyManager::setMsdOutputPatches(const DeviceVector *outputDevices) {
    DeviceVector devices;
    if (outputDevices != nullptr && outputDevices->size() > 0) {
        devices.add(*outputDevices);
    } else {
        // Use media strategy for unspecified output device. This should only
        // occur on checkForDeviceAndOutputChanges(). Device connection events may
        // therefore invalidate explicit routing requests.
        devices = mEngine->getOutputDevicesForAttributes(
                    attributes_initializer(AUDIO_USAGE_MEDIA), nullptr, false /*fromCache*/);
        LOG_ALWAYS_FATAL_IF(devices.isEmpty(), "no output device to set MSD patch");
    }
    std::vector<PatchBuilder> patchesToCreate;
    for (auto i = 0u; i < devices.size(); ++i) {
        ALOGV("%s() for device %s", __func__, devices[i]->toString().c_str());
        patchesToCreate.push_back(buildMsdPatch(true /*msdIsSource*/, devices[i]));
    }
    // Retain only the MSD patches associated with outputDevices request.
    // Tear down the others, and create new ones as needed.
    AudioPatchCollection patchesToRemove = getMsdOutputPatches();
    for (auto it = patchesToCreate.begin(); it != patchesToCreate.end(); ) {
        auto retainedPatch = false;
        for (auto i = 0u; i < patchesToRemove.size(); ++i) {
            if (audio_patches_are_equal(it->patch(), &patchesToRemove[i]->mPatch)) {
                patchesToRemove.removeItemsAt(i);
                retainedPatch = true;
                break;
            }
        }
        if (retainedPatch) {
            it = patchesToCreate.erase(it);
            continue;
        }
        ++it;
    }
    if (patchesToCreate.size() == 0 && patchesToRemove.size() == 0) {
        return NO_ERROR;
    }
    for (auto i = 0u; i < patchesToRemove.size(); ++i) {
        auto &currentPatch = patchesToRemove.valueAt(i);
        releaseAudioPatch(currentPatch->getHandle(), mUidCached);
    }
    status_t status = NO_ERROR;
    for (const auto &p : patchesToCreate) {
        auto currStatus = installPatch(__func__, -1 /*index*/, nullptr /*patchHandle*/,
                p.patch(), 0 /*delayMs*/, mUidCached, nullptr /*patchDescPtr*/);
        char message[256];
        snprintf(message, sizeof(message), "%s() %s: creating MSD patch from device:IN_BUS to "
            "device:%#x (format:%#x channels:%#x samplerate:%d)", __func__,
                currStatus == NO_ERROR ? "Success" : "Error",
                p.patch()->sinks[0].ext.device.type, p.patch()->sources[0].format,
                p.patch()->sources[0].channel_mask, p.patch()->sources[0].sample_rate);
        if (currStatus == NO_ERROR) {
            ALOGD("%s", message);
        } else {
            ALOGE("%s", message);
            if (status == NO_ERROR) {
                status = currStatus;
            }
        }
    }
    return status;
}

void AudioPolicyManager::releaseMsdOutputPatches(const DeviceVector& devices) {
    AudioPatchCollection msdPatches = getMsdOutputPatches();
    for (size_t i = 0; i < msdPatches.size(); i++) {
        const auto& patch = msdPatches[i];
        for (size_t j = 0; j < patch->mPatch.num_sinks; ++j) {
            const struct audio_port_config *sink = &patch->mPatch.sinks[j];
            if (sink->type == AUDIO_PORT_TYPE_DEVICE && devices.getDevice(sink->ext.device.type,
                    String8(sink->ext.device.address), AUDIO_FORMAT_DEFAULT) != nullptr) {
                releaseAudioPatch(patch->getHandle(), mUidCached);
                break;
            }
        }
    }
}

bool AudioPolicyManager::msdHasPatchesToAllDevices(const AudioDeviceTypeAddrVector& devices) {
    DeviceVector devicesToCheck = mOutputDevicesAll.getDevicesFromDeviceTypeAddrVec(devices);
    AudioPatchCollection msdPatches = getMsdOutputPatches();
    for (size_t i = 0; i < msdPatches.size(); i++) {
        const auto& patch = msdPatches[i];
        for (size_t j = 0; j < patch->mPatch.num_sinks; ++j) {
            const struct audio_port_config *sink = &patch->mPatch.sinks[j];
            if (sink->type == AUDIO_PORT_TYPE_DEVICE) {
                const auto& foundDevice = devicesToCheck.getDevice(
                    sink->ext.device.type, String8(sink->ext.device.address), AUDIO_FORMAT_DEFAULT);
                if (foundDevice != nullptr) {
                    devicesToCheck.remove(foundDevice);
                    if (devicesToCheck.isEmpty()) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

audio_io_handle_t AudioPolicyManager::selectOutput(const SortedVector<audio_io_handle_t>& outputs,
                                                   audio_output_flags_t flags,
                                                   audio_format_t format,
                                                   audio_channel_mask_t channelMask,
                                                   uint32_t samplingRate,
                                                   audio_session_t sessionId)
{
    LOG_ALWAYS_FATAL_IF(!(format == AUDIO_FORMAT_INVALID || audio_is_linear_pcm(format)),
        "%s called with format %#x", __func__, format);

    // Return the output that haptic-generating attached to when 1) session id is specified,
    // 2) haptic-generating effect exists for given session id and 3) the output that
    // haptic-generating effect attached to is in given outputs.
    if (sessionId != AUDIO_SESSION_NONE) {
        audio_io_handle_t hapticGeneratingOutput = mEffects.getIoForSession(
                sessionId, FX_IID_HAPTICGENERATOR);
        if (outputs.indexOf(hapticGeneratingOutput) >= 0) {
            return hapticGeneratingOutput;
        }
    }

    // Flags disqualifying an output: the match must happen before calling selectOutput()
    static const audio_output_flags_t kExcludedFlags = (audio_output_flags_t)
        (AUDIO_OUTPUT_FLAG_HW_AV_SYNC | AUDIO_OUTPUT_FLAG_MMAP_NOIRQ | AUDIO_OUTPUT_FLAG_DIRECT);

    // Flags expressing a functional request: must be honored in priority over
    // other criteria
    static const audio_output_flags_t kFunctionalFlags = (audio_output_flags_t)
        (AUDIO_OUTPUT_FLAG_VOIP_RX | AUDIO_OUTPUT_FLAG_INCALL_MUSIC |
            AUDIO_OUTPUT_FLAG_TTS | AUDIO_OUTPUT_FLAG_DIRECT_PCM | AUDIO_OUTPUT_FLAG_ULTRASOUND |
            AUDIO_OUTPUT_FLAG_SPATIALIZER);
    // Flags expressing a performance request: have lower priority than serving
    // requested sampling rate or channel mask
    static const audio_output_flags_t kPerformanceFlags = (audio_output_flags_t)
        (AUDIO_OUTPUT_FLAG_FAST | AUDIO_OUTPUT_FLAG_DEEP_BUFFER |
            AUDIO_OUTPUT_FLAG_RAW | AUDIO_OUTPUT_FLAG_SYNC);

    const audio_output_flags_t functionalFlags =
        (audio_output_flags_t)(flags & kFunctionalFlags);
    const audio_output_flags_t performanceFlags =
        (audio_output_flags_t)(flags & kPerformanceFlags);

    audio_io_handle_t bestOutput = (outputs.size() == 0) ? AUDIO_IO_HANDLE_NONE : outputs[0];

    // select one output among several that provide a path to a particular device or set of
    // devices (the list was previously build by getOutputsForDevices()).
    // The priority is as follows:
    // 1: the output supporting haptic playback when requesting haptic playback
    // 2: the output with the highest number of requested functional flags
    //    with tiebreak preferring the minimum number of extra functional flags
    //    (see b/200293124, the incorrect selection of AUDIO_OUTPUT_FLAG_VOIP_RX).
    // 3: the output supporting the exact channel mask
    // 4: the output with a higher channel count than requested
    // 5: the output with the highest sampling rate if the requested sample rate is
    //    greater than default sampling rate
    // 6: the output with the highest number of requested performance flags
    // 7: the output with the bit depth the closest to the requested one
    // 8: the primary output
    // 9: the first output in the list

    // matching criteria values in priority order for best matching output so far
    std::vector<uint32_t> bestMatchCriteria(8, 0);

    const uint32_t channelCount = audio_channel_count_from_out_mask(channelMask);
    const uint32_t hapticChannelCount = audio_channel_count_from_out_mask(
        channelMask & AUDIO_CHANNEL_HAPTIC_ALL);

    for (audio_io_handle_t output : outputs) {
        sp<SwAudioOutputDescriptor> outputDesc = mOutputs.valueFor(output);
        // matching criteria values in priority order for current output
        std::vector<uint32_t> currentMatchCriteria(8, 0);

        if (outputDesc->isDuplicated()) {
            continue;
        }
        if ((kExcludedFlags & outputDesc->mFlags) != 0) {
            continue;
        }

        // If haptic channel is specified, use the haptic output if present.
        // When using haptic output, same audio format and sample rate are required.
        const uint32_t outputHapticChannelCount = audio_channel_count_from_out_mask(
            outputDesc->getChannelMask() & AUDIO_CHANNEL_HAPTIC_ALL);
        if ((hapticChannelCount == 0) != (outputHapticChannelCount == 0)) {
            continue;
        }
        if (outputHapticChannelCount >= hapticChannelCount
            && format == outputDesc->getFormat()
            && samplingRate == outputDesc->getSamplingRate()) {
                currentMatchCriteria[0] = outputHapticChannelCount;
        }

        // functional flags match
        const int matchingFunctionalFlags =
                __builtin_popcount(outputDesc->mFlags & functionalFlags);
        const int totalFunctionalFlags =
                __builtin_popcount(outputDesc->mFlags & kFunctionalFlags);
        // Prefer matching functional flags, but subtract unnecessary functional flags.
        currentMatchCriteria[1] = 100 * (matchingFunctionalFlags + 1) - totalFunctionalFlags;

        // channel mask and channel count match
        uint32_t outputChannelCount = audio_channel_count_from_out_mask(
                outputDesc->getChannelMask());
        if (channelMask != AUDIO_CHANNEL_NONE && channelCount > 2 &&
            channelCount <= outputChannelCount) {
            if ((audio_channel_mask_get_representation(channelMask) ==
                    audio_channel_mask_get_representation(outputDesc->getChannelMask())) &&
                    ((channelMask & outputDesc->getChannelMask()) == channelMask)) {
                currentMatchCriteria[2] = outputChannelCount;
            }
            currentMatchCriteria[3] = outputChannelCount;
        }

        // sampling rate match
        if (samplingRate > SAMPLE_RATE_HZ_DEFAULT) {
            currentMatchCriteria[4] = outputDesc->getSamplingRate();
        }

        // performance flags match
        currentMatchCriteria[5] = popcount(outputDesc->mFlags & performanceFlags);

        // format match
        if (format != AUDIO_FORMAT_INVALID) {
            currentMatchCriteria[6] =
                PolicyAudioPort::kFormatDistanceMax -
                PolicyAudioPort::formatDistance(format, outputDesc->getFormat());
        }

        // primary output match
        currentMatchCriteria[7] = outputDesc->mFlags & AUDIO_OUTPUT_FLAG_PRIMARY;

        // compare match criteria by priority then value
        if (std::lexicographical_compare(bestMatchCriteria.begin(), bestMatchCriteria.end(),
                currentMatchCriteria.begin(), currentMatchCriteria.end())) {
            bestMatchCriteria = currentMatchCriteria;
            bestOutput = output;

            std::stringstream result;
            std::copy(bestMatchCriteria.begin(), bestMatchCriteria.end(),
                std::ostream_iterator<int>(result, " "));
            ALOGV("%s new bestOutput %d criteria %s",
                __func__, bestOutput, result.str().c_str());
        }
    }

    return bestOutput;
}

status_t AudioPolicyManager::startOutput(audio_port_handle_t portId)
{
    ALOGV("%s portId %d", __FUNCTION__, portId);

    sp<SwAudioOutputDescriptor> outputDesc = mOutputs.getOutputForClient(portId);
    if (outputDesc == 0) {
        ALOGW("startOutput() no output for client %d", portId);
        return BAD_VALUE;
    }
    sp<TrackClientDescriptor> client = outputDesc->getClient(portId);

    ALOGV("startOutput() output %d, stream %d, session %d",
          outputDesc->mIoHandle, client->stream(), client->session());

    status_t status = outputDesc->start();
    if (status != NO_ERROR) {
        return status;
    }

    uint32_t delayMs;
    status = startSource(outputDesc, client, &delayMs);

    if (status != NO_ERROR) {
        outputDesc->stop();
        return status;
    }
    if (delayMs != 0) {
        usleep(delayMs * 1000);
    }

    return status;
}

bool AudioPolicyManager::isLeUnicastActive() const {
    if (isInCall()) {
        return true;
    }
    return isAnyDeviceTypeActive(getAudioDeviceOutLeAudioUnicastSet());
}

bool AudioPolicyManager::isAnyDeviceTypeActive(const DeviceTypeSet& deviceTypes) const {
    if (mAvailableOutputDevices.getDevicesFromTypes(deviceTypes).isEmpty()) {
        return false;
    }
    bool active = mOutputs.isAnyDeviceTypeActive(deviceTypes);
    ALOGV("%s active %d", __func__, active);
    return active;
}

status_t AudioPolicyManager::startSource(const sp<SwAudioOutputDescriptor>& outputDesc,
                                         const sp<TrackClientDescriptor>& client,
                                         uint32_t *delayMs)
{
    // cannot start playback of STREAM_TTS if any other output is being used
    uint32_t beaconMuteLatency = 0;

    *delayMs = 0;
    audio_stream_type_t stream = client->stream();
    auto clientVolSrc = client->volumeSource();
    auto clientStrategy = client->strategy();
    auto clientAttr = client->attributes();
    if (stream == AUDIO_STREAM_TTS) {
        ALOGV("\t found BEACON stream");
        if (!mTtsOutputAvailable && mOutputs.isAnyOutputActive(
                                    toVolumeSource(AUDIO_STREAM_TTS, false) /*sourceToIgnore*/)) {
            return INVALID_OPERATION;
        } else {
            beaconMuteLatency = handleEventForBeacon(STARTING_BEACON);
        }
    } else {
        // some playback other than beacon starts
        beaconMuteLatency = handleEventForBeacon(STARTING_OUTPUT);
    }

    // force device change if the output is inactive and no audio patch is already present.
    // check active before incrementing usage count
    bool force = !outputDesc->isActive() && !outputDesc->isRouted();

    DeviceVector devices;
    sp<AudioPolicyMix> policyMix = outputDesc->mPolicyMix.promote();
    const char *address = NULL;
    if (policyMix != nullptr) {
        audio_devices_t newDeviceType;
        address = policyMix->mDeviceAddress.string();
        if ((policyMix->mRouteFlags & MIX_ROUTE_FLAG_LOOP_BACK) == MIX_ROUTE_FLAG_LOOP_BACK) {
            newDeviceType = AUDIO_DEVICE_OUT_REMOTE_SUBMIX;
        } else {
            newDeviceType = policyMix->mDeviceType;
        }
        sp device = mAvailableOutputDevices.getDevice(newDeviceType, String8(address),
                                                        AUDIO_FORMAT_DEFAULT);
        ALOG_ASSERT(device, "%s: no device found t=%u, a=%s", __func__, newDeviceType, address);
        devices.add(device);
    }

    // requiresMuteCheck is false when we can bypass mute strategy.
    // It covers a common case when there is no materially active audio
    // and muting would result in unnecessary delay and dropped audio.
    const uint32_t outputLatencyMs = outputDesc->latency();
    bool requiresMuteCheck = outputDesc->isActive(outputLatencyMs * 2);  // account for drain
    bool wasLeUnicastActive = isLeUnicastActive();

    // increment usage count for this stream on the requested output:
    // NOTE that the usage count is the same for duplicated output and hardware output which is
    // necessary for a correct control of hardware output routing by startOutput() and stopOutput()
    outputDesc->setClientActive(client, true);

    if (client->hasPreferredDevice(true)) {
        if (outputDesc->clientsList(true /*activeOnly*/).size() == 1 &&
                client->isPreferredDeviceForExclusiveUse()) {
            // Preferred device may be exclusive, use only if no other active clients on this output
            devices = DeviceVector(
                        mAvailableOutputDevices.getDeviceFromId(client->preferredDeviceId()));
        } else {
            devices = getNewOutputDevices(outputDesc, false /*fromCache*/);
        }
        if (devices != outputDesc->devices()) {
            checkStrategyRoute(clientStrategy, outputDesc->mIoHandle);
        }
    }

    if (followsSameRouting(clientAttr, attributes_initializer(AUDIO_USAGE_MEDIA))) {
        selectOutputForMusicEffects();
    }

    if (outputDesc->getActivityCount(clientVolSrc) == 1 || !devices.isEmpty()) {
        // starting an output being rerouted?
        if (devices.isEmpty()) {
            devices = getNewOutputDevices(outputDesc, false /*fromCache*/);
        }
        bool shouldWait =
            (followsSameRouting(clientAttr, attributes_initializer(AUDIO_USAGE_ALARM)) ||
             followsSameRouting(clientAttr, attributes_initializer(AUDIO_USAGE_NOTIFICATION)) ||
             (beaconMuteLatency > 0));
        uint32_t waitMs = beaconMuteLatency;
        for (size_t i = 0; i < mOutputs.size(); i++) {
            sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
            if (desc != outputDesc) {
                // An output has a shared device if
                // - managed by the same hw module
                // - supports the currently selected device
                const bool sharedDevice = outputDesc->sharesHwModuleWith(desc)
                        && (!desc->filterSupportedDevices(devices).isEmpty());

                // force a device change if any other output is:
                // - managed by the same hw module
                // - supports currently selected device
                // - has a current device selection that differs from selected device.
                // - has an active audio patch
                // In this case, the audio HAL must receive the new device selection so that it can
                // change the device currently selected by the other output.
                if (sharedDevice &&
                        desc->devices() != devices &&
                        desc->getPatchHandle() != AUDIO_PATCH_HANDLE_NONE) {
                    force = true;
                }
                // wait for audio on other active outputs to be presented when starting
                // a notification so that audio focus effect can propagate, or that a mute/unmute
                // event occurred for beacon
                const uint32_t latencyMs = desc->latency();
                const bool isActive = desc->isActive(latencyMs * 2);  // account for drain

                if (shouldWait && isActive && (waitMs < latencyMs)) {
                    waitMs = latencyMs;
                }

                // Require mute check if another output is on a shared device
                // and currently active to have proper drain and avoid pops.
                // Note restoring AudioTracks onto this output needs to invoke
                // a volume ramp if there is no mute.
                requiresMuteCheck |= sharedDevice && isActive;
            }
        }

        const uint32_t muteWaitMs =
                setOutputDevices(outputDesc, devices, force, 0, NULL, requiresMuteCheck);

        // apply volume rules for current stream and device if necessary
        auto &curves = getVolumeCurves(client->attributes());
        if (NO_ERROR != checkAndSetVolume(curves, client->volumeSource(),
                          curves.getVolumeIndex(outputDesc->devices().types()),
                          outputDesc,
                          outputDesc->devices().types(), 0 /*delay*/,
                          outputDesc->useHwGain() /*force*/)) {
            // request AudioService to reinitialize the volume curves asynchronously
            ALOGE("checkAndSetVolume failed, requesting volume range init");
            mpClientInterface->onVolumeRangeInitRequest();
        };

        // update the outputs if starting an output with a stream that can affect notification
        // routing
        handleNotificationRoutingForStream(stream);

        // force reevaluating accessibility routing when ringtone or alarm starts
        if (followsSameRouting(clientAttr, attributes_initializer(AUDIO_USAGE_ALARM))) {
            mpClientInterface->invalidateStream(AUDIO_STREAM_ACCESSIBILITY);
        }

        if (waitMs > muteWaitMs) {
            *delayMs = waitMs - muteWaitMs;
        }

        // FIXME: A device change (muteWaitMs > 0) likely introduces a volume change.
        // A volume change enacted by APM with 0 delay is not synchronous, as it goes
        // via AudioCommandThread to AudioFlinger.  Hence it is possible that the volume
        // change occurs after the MixerThread starts and causes a stream volume
        // glitch.
        //
        // We do not introduce additional delay here.
    }

    if (stream == AUDIO_STREAM_ENFORCED_AUDIBLE &&
            mEngine->getForceUse(
                    AUDIO_POLICY_FORCE_FOR_SYSTEM) == AUDIO_POLICY_FORCE_SYSTEM_ENFORCED) {
        setStrategyMute(streamToStrategy(AUDIO_STREAM_ALARM), true, outputDesc);
    }

    // Automatically enable the remote submix input when output is started on a re routing mix
    // of type MIX_TYPE_RECORDERS
    if (isSingleDeviceType(devices.types(), &audio_is_remote_submix_device) &&
        policyMix != NULL && policyMix->mMixType == MIX_TYPE_RECORDERS) {
        setDeviceConnectionStateInt(AUDIO_DEVICE_IN_REMOTE_SUBMIX,
                                    AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                    address,
                                    "remote-submix",
                                    AUDIO_FORMAT_DEFAULT);
    }

    checkLeBroadcastRoutes(wasLeUnicastActive, outputDesc, *delayMs);

    return NO_ERROR;
}

void AudioPolicyManager::checkLeBroadcastRoutes(bool wasUnicastActive,
        sp<SwAudioOutputDescriptor> ignoredOutput, uint32_t delayMs) {
    bool isUnicastActive = isLeUnicastActive();

    if (wasUnicastActive != isUnicastActive) {
        //reroute all outputs routed to LE broadcast if LE unicast activy changed on any output
        for (size_t i = 0; i < mOutputs.size(); i++) {
            sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
            if (desc != ignoredOutput && desc->isActive()
                    && ((isUnicastActive &&
                            !desc->devices().
                                    getDevicesFromType(AUDIO_DEVICE_OUT_BLE_BROADCAST).isEmpty())
                        || (wasUnicastActive &&
                            !desc->devices().getDevicesFromTypes(
                                    getAudioDeviceOutLeAudioUnicastSet()).isEmpty()))) {
                DeviceVector newDevices = getNewOutputDevices(desc, false /*fromCache*/);
                bool force = desc->devices() != newDevices;
                setOutputDevices(desc, newDevices, force, delayMs);
                // re-apply device specific volume if not done by setOutputDevice()
                if (!force) {
                    applyStreamVolumes(desc, newDevices.types(), delayMs);
                }
            }
        }
    }
}

status_t AudioPolicyManager::stopOutput(audio_port_handle_t portId)
{
    ALOGV("%s portId %d", __FUNCTION__, portId);

    sp<SwAudioOutputDescriptor> outputDesc = mOutputs.getOutputForClient(portId);
    if (outputDesc == 0) {
        ALOGW("stopOutput() no output for client %d", portId);
        return BAD_VALUE;
    }
    sp<TrackClientDescriptor> client = outputDesc->getClient(portId);

    ALOGV("stopOutput() output %d, stream %d, session %d",
          outputDesc->mIoHandle, client->stream(), client->session());

    status_t status = stopSource(outputDesc, client);

    if (status == NO_ERROR ) {
        outputDesc->stop();
    }
    return status;
}

status_t AudioPolicyManager::stopSource(const sp<SwAudioOutputDescriptor>& outputDesc,
                                        const sp<TrackClientDescriptor>& client)
{
    // always handle stream stop, check which stream type is stopping
    audio_stream_type_t stream = client->stream();
    auto clientVolSrc = client->volumeSource();
    bool wasLeUnicastActive = isLeUnicastActive();

    handleEventForBeacon(stream == AUDIO_STREAM_TTS ? STOPPING_BEACON : STOPPING_OUTPUT);

    if (outputDesc->getActivityCount(clientVolSrc) > 0) {
        if (outputDesc->getActivityCount(clientVolSrc) == 1) {
            // Automatically disable the remote submix input when output is stopped on a
            // re routing mix of type MIX_TYPE_RECORDERS
            sp<AudioPolicyMix> policyMix = outputDesc->mPolicyMix.promote();
            if (isSingleDeviceType(
                    outputDesc->devices().types(), &audio_is_remote_submix_device) &&
                policyMix != nullptr &&
                policyMix->mMixType == MIX_TYPE_RECORDERS) {
                setDeviceConnectionStateInt(AUDIO_DEVICE_IN_REMOTE_SUBMIX,
                                            AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                            policyMix->mDeviceAddress,
                                            "remote-submix", AUDIO_FORMAT_DEFAULT);
            }
        }
        bool forceDeviceUpdate = false;
        if (client->hasPreferredDevice(true)) {
            checkStrategyRoute(client->strategy(), AUDIO_IO_HANDLE_NONE);
            forceDeviceUpdate = true;
        }

        // decrement usage count of this stream on the output
        outputDesc->setClientActive(client, false);

        // store time at which the stream was stopped - see isStreamActive()
        if (outputDesc->getActivityCount(clientVolSrc) == 0 || forceDeviceUpdate) {
            outputDesc->setStopTime(client, systemTime());
            DeviceVector newDevices = getNewOutputDevices(outputDesc, false /*fromCache*/);

            // If the routing does not change, if an output is routed on a device using HwGain
            // (aka setAudioPortConfig) and there are still active clients following different
            // volume group(s), force reapply volume
            bool requiresVolumeCheck = outputDesc->getActivityCount(clientVolSrc) == 0 &&
                    outputDesc->useHwGain() && outputDesc->isAnyActive(VOLUME_SOURCE_NONE);

            // delay the device switch by twice the latency because stopOutput() is executed when
            // the track stop() command is received and at that time the audio track buffer can
            // still contain data that needs to be drained. The latency only covers the audio HAL
            // and kernel buffers. Also the latency does not always include additional delay in the
            // audio path (audio DSP, CODEC ...)
            setOutputDevices(outputDesc, newDevices, false, outputDesc->latency()*2,
                             nullptr, true /*requiresMuteCheck*/, requiresVolumeCheck);

            // force restoring the device selection on other active outputs if it differs from the
            // one being selected for this output
            uint32_t delayMs = outputDesc->latency()*2;
            for (size_t i = 0; i < mOutputs.size(); i++) {
                sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
                if (desc != outputDesc &&
                        desc->isActive() &&
                        outputDesc->sharesHwModuleWith(desc) &&
                        (newDevices != desc->devices())) {
                    DeviceVector newDevices2 = getNewOutputDevices(desc, false /*fromCache*/);
                    bool force = desc->devices() != newDevices2;

                    setOutputDevices(desc, newDevices2, force, delayMs);

                    // re-apply device specific volume if not done by setOutputDevice()
                    if (!force) {
                        applyStreamVolumes(desc, newDevices2.types(), delayMs);
                    }
                }
            }
            // update the outputs if stopping one with a stream that can affect notification routing
            handleNotificationRoutingForStream(stream);
        }

        if (stream == AUDIO_STREAM_ENFORCED_AUDIBLE &&
                mEngine->getForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM) == AUDIO_POLICY_FORCE_SYSTEM_ENFORCED) {
            setStrategyMute(streamToStrategy(AUDIO_STREAM_ALARM), false, outputDesc);
        }

        if (followsSameRouting(client->attributes(), attributes_initializer(AUDIO_USAGE_MEDIA))) {
            selectOutputForMusicEffects();
        }

        checkLeBroadcastRoutes(wasLeUnicastActive, outputDesc, outputDesc->latency()*2);

        return NO_ERROR;
    } else {
        ALOGW("stopOutput() refcount is already 0");
        return INVALID_OPERATION;
    }
}

bool AudioPolicyManager::releaseOutput(audio_port_handle_t portId)
{
    ALOGV("%s portId %d", __FUNCTION__, portId);

    sp<SwAudioOutputDescriptor> outputDesc = mOutputs.getOutputForClient(portId);
    if (outputDesc == 0) {
        // If an output descriptor is closed due to a device routing change,
        // then there are race conditions with releaseOutput from tracks
        // that may be destroyed (with no PlaybackThread) or a PlaybackThread
        // destroyed shortly thereafter.
        //
        // Here we just log a warning, instead of a fatal error.
        ALOGW("releaseOutput() no output for client %d", portId);
        return false;
    }

    ALOGV("releaseOutput() %d", outputDesc->mIoHandle);

    sp<TrackClientDescriptor> client = outputDesc->getClient(portId);
    if (outputDesc->isClientActive(client)) {
        ALOGW("releaseOutput() inactivates portId %d in good faith", portId);
        stopOutput(portId);
    }

    if (outputDesc->mFlags & AUDIO_OUTPUT_FLAG_DIRECT) {
        if (outputDesc->mDirectOpenCount <= 0) {
            ALOGW("releaseOutput() invalid open count %d for output %d",
                  outputDesc->mDirectOpenCount, outputDesc->mIoHandle);
            return false;
        }
        if (--outputDesc->mDirectOpenCount == 0) {
            closeOutput(outputDesc->mIoHandle);
            mpClientInterface->onAudioPortListUpdate();
        }
    }

    outputDesc->removeClient(portId);
    if (outputDesc->mPendingReopenToQueryProfiles && outputDesc->getClientCount() == 0) {
        // The output is pending reopened to query dynamic profiles and
        // there is no active clients
        closeOutput(outputDesc->mIoHandle);
        sp<SwAudioOutputDescriptor> newOutputDesc = openOutputWithProfileAndDevice(
                outputDesc->mProfile, mEngine->getActiveMediaDevices(mAvailableOutputDevices));
        if (newOutputDesc == nullptr) {
            ALOGE("%s failed to open output", __func__);
        }
        return true;
    }
    return false;
}

status_t AudioPolicyManager::getInputForAttr(const audio_attributes_t *attr,
                                             audio_io_handle_t *input,
                                             audio_unique_id_t riid,
                                             audio_session_t session,
                                             const AttributionSourceState& attributionSource,
                                             const audio_config_base_t *config,
                                             audio_input_flags_t flags,
                                             audio_port_handle_t *selectedDeviceId,
                                             input_type_t *inputType,
                                             audio_port_handle_t *portId)
{
    ALOGV("%s() source %d, sampling rate %d, format %#x, channel mask %#x, session %d, "
          "flags %#x attributes=%s requested device ID %d",
          __func__, attr->source, config->sample_rate, config->format, config->channel_mask,
          session, flags, toString(*attr).c_str(), *selectedDeviceId);

    status_t status = NO_ERROR;
    audio_attributes_t attributes = *attr;
    sp<AudioPolicyMix> policyMix;
    sp<DeviceDescriptor> device;
    sp<AudioInputDescriptor> inputDesc;
    sp<RecordClientDescriptor> clientDesc;
    audio_port_handle_t requestedDeviceId = *selectedDeviceId;
    uid_t uid = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_uid_t(attributionSource.uid));
    bool isSoundTrigger;

    // The supplied portId must be AUDIO_PORT_HANDLE_NONE
    if (*portId != AUDIO_PORT_HANDLE_NONE) {
        return INVALID_OPERATION;
    }

    if (attr->source == AUDIO_SOURCE_DEFAULT) {
        attributes.source = AUDIO_SOURCE_MIC;
    }

    // Explicit routing?
    sp<DeviceDescriptor> explicitRoutingDevice =
            mAvailableInputDevices.getDeviceFromId(*selectedDeviceId);

    // special case for mmap capture: if an input IO handle is specified, we reuse this input if
    // possible
    if ((flags & AUDIO_INPUT_FLAG_MMAP_NOIRQ) == AUDIO_INPUT_FLAG_MMAP_NOIRQ &&
            *input != AUDIO_IO_HANDLE_NONE) {
        ssize_t index = mInputs.indexOfKey(*input);
        if (index < 0) {
            ALOGW("getInputForAttr() unknown MMAP input %d", *input);
            status = BAD_VALUE;
            goto error;
        }
        sp<AudioInputDescriptor> inputDesc = mInputs.valueAt(index);
        RecordClientVector clients = inputDesc->getClientsForSession(session);
        if (clients.size() == 0) {
            ALOGW("getInputForAttr() unknown session %d on input %d", session, *input);
            status = BAD_VALUE;
            goto error;
        }
        // For MMAP mode, the first call to getInputForAttr() is made on behalf of audioflinger.
        // The second call is for the first active client and sets the UID. Any further call
        // corresponds to a new client and is only permitted from the same UID.
        // If the first UID is silenced, allow a new UID connection and replace with new UID
        if (clients.size() > 1) {
            for (const auto& client : clients) {
                // The client map is ordered by key values (portId) and portIds are allocated
                // incrementaly. So the first client in this list is the one opened by audio flinger
                // when the mmap stream is created and should be ignored as it does not correspond
                // to an actual client
                if (client == *clients.cbegin()) {
                    continue;
                }
                if (uid != client->uid() && !client->isSilenced()) {
                    ALOGW("getInputForAttr() bad uid %d for client %d uid %d",
                          uid, client->portId(), client->uid());
                    status = INVALID_OPERATION;
                    goto error;
                }
            }
        }
        *inputType = API_INPUT_LEGACY;
        device = inputDesc->getDevice();

        ALOGV("%s reusing MMAP input %d for session %d", __FUNCTION__, *input, session);
        goto exit;
    }

    *input = AUDIO_IO_HANDLE_NONE;
    *inputType = API_INPUT_INVALID;

    if (attributes.source == AUDIO_SOURCE_REMOTE_SUBMIX &&
            strncmp(attributes.tags, "addr=", strlen("addr=")) == 0) {
        status = mPolicyMixes.getInputMixForAttr(attributes, &policyMix);
        if (status != NO_ERROR) {
            ALOGW("%s could not find input mix for attr %s",
                    __func__, toString(attributes).c_str());
            goto error;
        }
        device = mAvailableInputDevices.getDevice(AUDIO_DEVICE_IN_REMOTE_SUBMIX,
                                                  String8(attr->tags + strlen("addr=")),
                                                  AUDIO_FORMAT_DEFAULT);
        if (device == nullptr) {
            ALOGW("%s could not find in Remote Submix device for source %d, tags %s",
                    __func__, attributes.source, attributes.tags);
            status = BAD_VALUE;
            goto error;
        }

        if (is_mix_loopback_render(policyMix->mRouteFlags)) {
            *inputType = API_INPUT_MIX_PUBLIC_CAPTURE_PLAYBACK;
        } else {
            *inputType = API_INPUT_MIX_EXT_POLICY_REROUTE;
        }
    } else {
        if (explicitRoutingDevice != nullptr) {
            device = explicitRoutingDevice;
        } else {
            // Prevent from storing invalid requested device id in clients
            requestedDeviceId = AUDIO_PORT_HANDLE_NONE;
            device = mEngine->getInputDeviceForAttributes(attributes, uid, &policyMix);
            ALOGV_IF(device != nullptr, "%s found device type is 0x%X",
                __FUNCTION__, device->type());
        }
        if (device == nullptr) {
            ALOGW("getInputForAttr() could not find device for source %d", attributes.source);
            status = BAD_VALUE;
            goto error;
        }
        if (device->type() == AUDIO_DEVICE_IN_ECHO_REFERENCE) {
            *inputType = API_INPUT_MIX_CAPTURE;
        } else if (policyMix) {
            ALOG_ASSERT(policyMix->mMixType == MIX_TYPE_RECORDERS, "Invalid Mix Type");
            // there is an external policy, but this input is attached to a mix of recorders,
            // meaning it receives audio injected into the framework, so the recorder doesn't
            // know about it and is therefore considered "legacy"
            *inputType = API_INPUT_LEGACY;
        } else if (audio_is_remote_submix_device(device->type())) {
            *inputType = API_INPUT_MIX_CAPTURE;
        } else if (device->type() == AUDIO_DEVICE_IN_TELEPHONY_RX) {
            *inputType = API_INPUT_TELEPHONY_RX;
        } else {
            *inputType = API_INPUT_LEGACY;
        }

    }

    *input = getInputForDevice(device, session, attributes, config, flags, policyMix);
    if (*input == AUDIO_IO_HANDLE_NONE) {
        status = INVALID_OPERATION;
        goto error;
    }

exit:

    *selectedDeviceId = mAvailableInputDevices.contains(device) ?
                device->getId() : AUDIO_PORT_HANDLE_NONE;

    isSoundTrigger = attributes.source == AUDIO_SOURCE_HOTWORD &&
        mSoundTriggerSessions.indexOfKey(session) >= 0;
    *portId = PolicyAudioPort::getNextUniqueId();

    clientDesc = new RecordClientDescriptor(*portId, riid, uid, session, attributes, *config,
                                            requestedDeviceId, attributes.source, flags,
                                            isSoundTrigger);
    inputDesc = mInputs.valueFor(*input);
    inputDesc->addClient(clientDesc);

    ALOGV("getInputForAttr() returns input %d type %d selectedDeviceId %d for port ID %d",
            *input, *inputType, *selectedDeviceId, *portId);

    return NO_ERROR;

error:
    return status;
}


audio_io_handle_t AudioPolicyManager::getInputForDevice(const sp<DeviceDescriptor> &device,
                                                        audio_session_t session,
                                                        const audio_attributes_t &attributes,
                                                        const audio_config_base_t *config,
                                                        audio_input_flags_t flags,
                                                        const sp<AudioPolicyMix> &policyMix)
{
    audio_io_handle_t input = AUDIO_IO_HANDLE_NONE;
    audio_source_t halInputSource = attributes.source;
    bool isSoundTrigger = false;

    if (attributes.source == AUDIO_SOURCE_HOTWORD) {
        ssize_t index = mSoundTriggerSessions.indexOfKey(session);
        if (index >= 0) {
            input = mSoundTriggerSessions.valueFor(session);
            isSoundTrigger = true;
            flags = (audio_input_flags_t)(flags | AUDIO_INPUT_FLAG_HW_HOTWORD);
            ALOGV("SoundTrigger capture on session %d input %d", session, input);
        } else {
            halInputSource = AUDIO_SOURCE_VOICE_RECOGNITION;
        }
    } else if (attributes.source == AUDIO_SOURCE_VOICE_COMMUNICATION &&
               audio_is_linear_pcm(config->format)) {
        flags = (audio_input_flags_t)(flags | AUDIO_INPUT_FLAG_VOIP_TX);
    }

    if (attributes.source == AUDIO_SOURCE_ULTRASOUND) {
        flags = (audio_input_flags_t)(flags | AUDIO_INPUT_FLAG_ULTRASOUND);
    }

    // find a compatible input profile (not necessarily identical in parameters)
    sp<IOProfile> profile;
    // sampling rate and flags may be updated by getInputProfile
    uint32_t profileSamplingRate = (config->sample_rate == 0) ?
            SAMPLE_RATE_HZ_DEFAULT : config->sample_rate;
    audio_format_t profileFormat;
    audio_channel_mask_t profileChannelMask = config->channel_mask;
    audio_input_flags_t profileFlags = flags;
    for (;;) {
        profileFormat = config->format; // reset each time through loop, in case it is updated
        profile = getInputProfile(device, profileSamplingRate, profileFormat, profileChannelMask,
                                  profileFlags);
        if (profile != 0) {
            break; // success
        } else if (profileFlags & AUDIO_INPUT_FLAG_RAW) {
            profileFlags = (audio_input_flags_t) (profileFlags & ~AUDIO_INPUT_FLAG_RAW); // retry
        } else if (profileFlags != AUDIO_INPUT_FLAG_NONE && audio_is_linear_pcm(config->format)) {
            profileFlags = AUDIO_INPUT_FLAG_NONE; // retry
        } else { // fail
            ALOGW("%s could not find profile for device %s, sampling rate %u, format %#x, "
                  "channel mask 0x%X, flags %#x", __func__, device->toString().c_str(),
                  config->sample_rate, config->format, config->channel_mask, flags);
            return input;
        }
    }
    // Pick input sampling rate if not specified by client
    uint32_t samplingRate = config->sample_rate;
    if (samplingRate == 0) {
        samplingRate = profileSamplingRate;
    }

    if (profile->getModuleHandle() == 0) {
        ALOGE("getInputForAttr(): HW module %s not opened", profile->getModuleName());
        return input;
    }

    // Reuse an already opened input if a client with the same session ID already exists
    // on that input
    for (size_t i = 0; i < mInputs.size(); i++) {
        sp <AudioInputDescriptor> desc = mInputs.valueAt(i);
        if (desc->mProfile != profile) {
            continue;
        }
        RecordClientVector clients = desc->clientsList();
        for (const auto &client : clients) {
            if (session == client->session()) {
                return desc->mIoHandle;
            }
        }
    }

    if (!profile->canOpenNewIo()) {
        for (size_t i = 0; i < mInputs.size(); ) {
            sp<AudioInputDescriptor> desc = mInputs.valueAt(i);
            if (desc->mProfile != profile) {
                i++;
                continue;
            }
            // if sound trigger, reuse input if used by other sound trigger on same session
            // else
            //    reuse input if active client app is not in IDLE state
            //
            RecordClientVector clients = desc->clientsList();
            bool doClose = false;
            for (const auto& client : clients) {
                if (isSoundTrigger != client->isSoundTrigger()) {
                    continue;
                }
                if (client->isSoundTrigger()) {
                    if (session == client->session()) {
                        return desc->mIoHandle;
                    }
                    continue;
                }
                if (client->active() && client->appState() != APP_STATE_IDLE) {
                    return desc->mIoHandle;
                }
                doClose = true;
            }
            if (doClose) {
                closeInput(desc->mIoHandle);
            } else {
                i++;
            }
        }
    }

    sp<AudioInputDescriptor> inputDesc = new AudioInputDescriptor(profile, mpClientInterface);

    audio_config_t lConfig = AUDIO_CONFIG_INITIALIZER;
    lConfig.sample_rate = profileSamplingRate;
    lConfig.channel_mask = profileChannelMask;
    lConfig.format = profileFormat;

    status_t status = inputDesc->open(&lConfig, device, halInputSource, profileFlags, &input);

    // only accept input with the exact requested set of parameters
    if (status != NO_ERROR || input == AUDIO_IO_HANDLE_NONE ||
        (profileSamplingRate != lConfig.sample_rate) ||
        !audio_formats_match(profileFormat, lConfig.format) ||
        (profileChannelMask != lConfig.channel_mask)) {
        ALOGW("getInputForAttr() failed opening input: sampling rate %d"
              ", format %#x, channel mask %#x",
              profileSamplingRate, profileFormat, profileChannelMask);
        if (input != AUDIO_IO_HANDLE_NONE) {
            inputDesc->close();
        }
        return AUDIO_IO_HANDLE_NONE;
    }

    inputDesc->mPolicyMix = policyMix;

    addInput(input, inputDesc);
    mpClientInterface->onAudioPortListUpdate();

    return input;
}

status_t AudioPolicyManager::startInput(audio_port_handle_t portId)
{
    ALOGV("%s portId %d", __FUNCTION__, portId);

    sp<AudioInputDescriptor> inputDesc = mInputs.getInputForClient(portId);
    if (inputDesc == 0) {
        ALOGW("%s no input for client %d", __FUNCTION__, portId);
        return DEAD_OBJECT;
    }
    audio_io_handle_t input = inputDesc->mIoHandle;
    sp<RecordClientDescriptor> client = inputDesc->getClient(portId);
    if (client->active()) {
        ALOGW("%s input %d client %d already started", __FUNCTION__, input, client->portId());
        return INVALID_OPERATION;
    }

    audio_session_t session = client->session();

    ALOGV("%s input:%d, session:%d)", __FUNCTION__, input, session);

    Vector<sp<AudioInputDescriptor>> activeInputs = mInputs.getActiveInputs();

    status_t status = inputDesc->start();
    if (status != NO_ERROR) {
        return status;
    }

    // increment activity count before calling getNewInputDevice() below as only active sessions
    // are considered for device selection
    inputDesc->setClientActive(client, true);

    // indicate active capture to sound trigger service if starting capture from a mic on
    // primary HW module
    sp<DeviceDescriptor> device = getNewInputDevice(inputDesc);
    if (device != nullptr) {
        status = setInputDevice(input, device, true /* force */);
    } else {
        ALOGW("%s no new input device can be found for descriptor %d",
                __FUNCTION__, inputDesc->getId());
        status = BAD_VALUE;
    }

    if (status == NO_ERROR && inputDesc->activeCount() == 1) {
        sp<AudioPolicyMix> policyMix = inputDesc->mPolicyMix.promote();
        // if input maps to a dynamic policy with an activity listener, notify of state change
        if ((policyMix != nullptr)
                && ((policyMix->mCbFlags & AudioMix::kCbFlagNotifyActivity) != 0)) {
            mpClientInterface->onDynamicPolicyMixStateUpdate(policyMix->mDeviceAddress,
                    MIX_STATE_MIXING);
        }

        DeviceVector primaryInputDevices = availablePrimaryModuleInputDevices();
        if (primaryInputDevices.contains(device) &&
                mInputs.activeInputsCountOnDevices(primaryInputDevices) == 1) {
            mpClientInterface->setSoundTriggerCaptureState(true);
        }

        // automatically enable the remote submix output when input is started if not
        // used by a policy mix of type MIX_TYPE_RECORDERS
        // For remote submix (a virtual device), we open only one input per capture request.
        if (audio_is_remote_submix_device(inputDesc->getDeviceType())) {
            String8 address = String8("");
            if (policyMix == nullptr) {
                address = String8("0");
            } else if (policyMix->mMixType == MIX_TYPE_PLAYERS) {
                address = policyMix->mDeviceAddress;
            }
            if (address != "") {
                setDeviceConnectionStateInt(AUDIO_DEVICE_OUT_REMOTE_SUBMIX,
                        AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                        address, "remote-submix", AUDIO_FORMAT_DEFAULT);
            }
        }
    } else if (status != NO_ERROR) {
        // Restore client activity state.
        inputDesc->setClientActive(client, false);
        inputDesc->stop();
    }

    ALOGV("%s input %d source = %d status = %d exit",
            __FUNCTION__, input, client->source(), status);

    return status;
}

status_t AudioPolicyManager::stopInput(audio_port_handle_t portId)
{
    ALOGV("%s portId %d", __FUNCTION__, portId);

    sp<AudioInputDescriptor> inputDesc = mInputs.getInputForClient(portId);
    if (inputDesc == 0) {
        ALOGW("%s no input for client %d", __FUNCTION__, portId);
        return BAD_VALUE;
    }
    audio_io_handle_t input = inputDesc->mIoHandle;
    sp<RecordClientDescriptor> client = inputDesc->getClient(portId);
    if (!client->active()) {
        ALOGW("%s input %d client %d already stopped", __FUNCTION__, input, client->portId());
        return INVALID_OPERATION;
    }
    auto old_source = inputDesc->source();
    inputDesc->setClientActive(client, false);

    inputDesc->stop();
    if (inputDesc->isActive()) {
        auto current_source = inputDesc->source();
        setInputDevice(input, getNewInputDevice(inputDesc),
                old_source != current_source /* force */);
    } else {
        sp<AudioPolicyMix> policyMix = inputDesc->mPolicyMix.promote();
        // if input maps to a dynamic policy with an activity listener, notify of state change
        if ((policyMix != nullptr)
                && ((policyMix->mCbFlags & AudioMix::kCbFlagNotifyActivity) != 0)) {
            mpClientInterface->onDynamicPolicyMixStateUpdate(policyMix->mDeviceAddress,
                    MIX_STATE_IDLE);
        }

        // automatically disable the remote submix output when input is stopped if not
        // used by a policy mix of type MIX_TYPE_RECORDERS
        if (audio_is_remote_submix_device(inputDesc->getDeviceType())) {
            String8 address = String8("");
            if (policyMix == nullptr) {
                address = String8("0");
            } else if (policyMix->mMixType == MIX_TYPE_PLAYERS) {
                address = policyMix->mDeviceAddress;
            }
            if (address != "") {
                setDeviceConnectionStateInt(AUDIO_DEVICE_OUT_REMOTE_SUBMIX,
                                         AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                         address, "remote-submix", AUDIO_FORMAT_DEFAULT);
            }
        }
        resetInputDevice(input);

        // indicate inactive capture to sound trigger service if stopping capture from a mic on
        // primary HW module
        DeviceVector primaryInputDevices = availablePrimaryModuleInputDevices();
        if (primaryInputDevices.contains(inputDesc->getDevice()) &&
                mInputs.activeInputsCountOnDevices(primaryInputDevices) == 0) {
            mpClientInterface->setSoundTriggerCaptureState(false);
        }
        inputDesc->clearPreemptedSessions();
    }
    return NO_ERROR;
}

void AudioPolicyManager::releaseInput(audio_port_handle_t portId)
{
    ALOGV("%s portId %d", __FUNCTION__, portId);

    sp<AudioInputDescriptor> inputDesc = mInputs.getInputForClient(portId);
    if (inputDesc == 0) {
        ALOGW("%s no input for client %d", __FUNCTION__, portId);
        return;
    }
    sp<RecordClientDescriptor> client = inputDesc->getClient(portId);
    audio_io_handle_t input = inputDesc->mIoHandle;

    ALOGV("%s %d", __FUNCTION__, input);

    inputDesc->removeClient(portId);

    if (inputDesc->getClientCount() > 0) {
        ALOGV("%s(%d) %zu clients remaining", __func__, portId, inputDesc->getClientCount());
        return;
    }

    closeInput(input);
    mpClientInterface->onAudioPortListUpdate();
    ALOGV("%s exit", __FUNCTION__);
}

void AudioPolicyManager::closeActiveClients(const sp<AudioInputDescriptor>& input)
{
    RecordClientVector clients = input->clientsList(true);

    for (const auto& client : clients) {
        closeClient(client->portId());
    }
}

void AudioPolicyManager::closeClient(audio_port_handle_t portId)
{
    stopInput(portId);
    releaseInput(portId);
}

void AudioPolicyManager::checkCloseInputs() {
    // After connecting or disconnecting an input device, close input if:
    // - it has no client (was just opened to check profile)  OR
    // - none of its supported devices are connected anymore OR
    // - one of its clients cannot be routed to one of its supported
    // devices anymore. Otherwise update device selection
    std::vector<audio_io_handle_t> inputsToClose;
    for (size_t i = 0; i < mInputs.size(); i++) {
        const sp<AudioInputDescriptor> input = mInputs.valueAt(i);
        if (input->clientsList().size() == 0
                || !mAvailableInputDevices.containsAtLeastOne(input->supportedDevices())) {
            inputsToClose.push_back(mInputs.keyAt(i));
        } else {
            bool close = false;
            for (const auto& client : input->clientsList()) {
                sp<DeviceDescriptor> device =
                    mEngine->getInputDeviceForAttributes(client->attributes(), client->uid());
                if (!input->supportedDevices().contains(device)) {
                    close = true;
                    break;
                }
            }
            if (close) {
                inputsToClose.push_back(mInputs.keyAt(i));
            } else {
                setInputDevice(input->mIoHandle, getNewInputDevice(input));
            }
        }
    }

    for (const audio_io_handle_t handle : inputsToClose) {
        ALOGV("%s closing input %d", __func__, handle);
        closeInput(handle);
    }
}

void AudioPolicyManager::initStreamVolume(audio_stream_type_t stream, int indexMin, int indexMax)
{
    ALOGV("initStreamVolume() stream %d, min %d, max %d", stream , indexMin, indexMax);
    if (indexMin < 0 || indexMax < 0) {
        ALOGE("%s for stream %d: invalid min %d or max %d", __func__, stream , indexMin, indexMax);
        return;
    }
    getVolumeCurves(stream).initVolume(indexMin, indexMax);

    // initialize other private stream volumes which follow this one
    for (int curStream = 0; curStream < AUDIO_STREAM_FOR_POLICY_CNT; curStream++) {
        if (!streamsMatchForvolume(stream, (audio_stream_type_t)curStream)) {
            continue;
        }
        getVolumeCurves((audio_stream_type_t)curStream).initVolume(indexMin, indexMax);
    }
}

status_t AudioPolicyManager::setStreamVolumeIndex(audio_stream_type_t stream,
                                                  int index,
                                                  audio_devices_t device)
{
    auto attributes = mEngine->getAttributesForStreamType(stream);
    if (attributes == AUDIO_ATTRIBUTES_INITIALIZER) {
        ALOGW("%s: no group for stream %s, bailing out", __func__, toString(stream).c_str());
        return NO_ERROR;
    }
    ALOGV("%s: stream %s attributes=%s", __func__,
          toString(stream).c_str(), toString(attributes).c_str());
    return setVolumeIndexForAttributes(attributes, index, device);
}

status_t AudioPolicyManager::getStreamVolumeIndex(audio_stream_type_t stream,
                                                  int *index,
                                                  audio_devices_t device)
{
    // if device is AUDIO_DEVICE_OUT_DEFAULT_FOR_VOLUME, return volume for device selected for this
    // stream by the engine.
    DeviceTypeSet deviceTypes = {device};
    if (device == AUDIO_DEVICE_OUT_DEFAULT_FOR_VOLUME) {
        deviceTypes = mEngine->getOutputDevicesForStream(
                stream, true /*fromCache*/).types();
    }
    return getVolumeIndex(getVolumeCurves(stream), *index, deviceTypes);
}

status_t AudioPolicyManager::setVolumeIndexForAttributes(const audio_attributes_t &attributes,
                                                         int index,
                                                         audio_devices_t device)
{
    // Get Volume group matching the Audio Attributes
    auto group = mEngine->getVolumeGroupForAttributes(attributes);
    if (group == VOLUME_GROUP_NONE) {
        ALOGD("%s: no group matching with %s", __FUNCTION__, toString(attributes).c_str());
        return BAD_VALUE;
    }
    ALOGV("%s: group %d matching with %s", __FUNCTION__, group, toString(attributes).c_str());
    status_t status = NO_ERROR;
    IVolumeCurves &curves = getVolumeCurves(attributes);
    VolumeSource vs = toVolumeSource(group);
    product_strategy_t strategy = mEngine->getProductStrategyForAttributes(attributes);

    status = setVolumeCurveIndex(index, device, curves);
    if (status != NO_ERROR) {
        ALOGE("%s failed to set curve index for group %d device 0x%X", __func__, group, device);
        return status;
    }

    DeviceTypeSet curSrcDevices;
    auto curCurvAttrs = curves.getAttributes();
    if (!curCurvAttrs.empty() && curCurvAttrs.front() != defaultAttr) {
        auto attr = curCurvAttrs.front();
        curSrcDevices = mEngine->getOutputDevicesForAttributes(attr, nullptr, false).types();
    } else if (!curves.getStreamTypes().empty()) {
        auto stream = curves.getStreamTypes().front();
        curSrcDevices = mEngine->getOutputDevicesForStream(stream, false).types();
    } else {
        ALOGE("%s: Invalid src %d: no valid attributes nor stream",__func__, vs);
        return BAD_VALUE;
    }
    audio_devices_t curSrcDevice = Volume::getDeviceForVolume(curSrcDevices);
    resetDeviceTypes(curSrcDevices, curSrcDevice);

    // update volume on all outputs and streams matching the following:
    // - The requested stream (or a stream matching for volume control) is active on the output
    // - The device (or devices) selected by the engine for this stream includes
    // the requested device
    // - For non default requested device, currently selected device on the output is either the
    // requested device or one of the devices selected by the engine for this stream
    // - For default requested device (AUDIO_DEVICE_OUT_DEFAULT_FOR_VOLUME), apply volume only if
    // no specific device volume value exists for currently selected device.
    for (size_t i = 0; i < mOutputs.size(); i++) {
        sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
        DeviceTypeSet curDevices = desc->devices().types();

        if (curDevices.erase(AUDIO_DEVICE_OUT_SPEAKER_SAFE)) {
            curDevices.insert(AUDIO_DEVICE_OUT_SPEAKER);
        }
        if (!(desc->isActive(vs) || isInCall())) {
            continue;
        }
        if (device != AUDIO_DEVICE_OUT_DEFAULT_FOR_VOLUME &&
                curDevices.find(device) == curDevices.end()) {
            continue;
        }
        bool applyVolume = false;
        if (device != AUDIO_DEVICE_OUT_DEFAULT_FOR_VOLUME) {
            curSrcDevices.insert(device);
            applyVolume = (curSrcDevices.find(
                    Volume::getDeviceForVolume(curDevices)) != curSrcDevices.end());
        } else {
            applyVolume = !curves.hasVolumeIndexForDevice(curSrcDevice);
        }
        if (!applyVolume) {
            continue; // next output
        }
        // Inter / intra volume group priority management: Loop on strategies arranged by priority
        // If a higher priority strategy is active, and the output is routed to a device with a
        // HW Gain management, do not change the volume
        if (desc->useHwGain()) {
            applyVolume = false;
            // If the volume source is active with higher priority source, ensure at least Sw Muted
            desc->setSwMute((index == 0), vs, curves.getStreamTypes(), curDevices, 0 /*delayMs*/);
            for (const auto &productStrategy : mEngine->getOrderedProductStrategies()) {
                auto activeClients = desc->clientsList(true /*activeOnly*/, productStrategy,
                                                       false /*preferredDevice*/);
                if (activeClients.empty()) {
                    continue;
                }
                bool isPreempted = false;
                bool isHigherPriority = productStrategy < strategy;
                for (const auto &client : activeClients) {
                    if (isHigherPriority && (client->volumeSource() != vs)) {
                        ALOGV("%s: Strategy=%d (\nrequester:\n"
                              " group %d, volumeGroup=%d attributes=%s)\n"
                              " higher priority source active:\n"
                              " volumeGroup=%d attributes=%s) \n"
                              " on output %zu, bailing out", __func__, productStrategy,
                              group, group, toString(attributes).c_str(),
                              client->volumeSource(), toString(client->attributes()).c_str(), i);
                        applyVolume = false;
                        isPreempted = true;
                        break;
                    }
                    // However, continue for loop to ensure no higher prio clients running on output
                    if (client->volumeSource() == vs) {
                        applyVolume = true;
                    }
                }
                if (isPreempted || applyVolume) {
                    break;
                }
            }
            if (!applyVolume) {
                continue; // next output
            }
        }
        //FIXME: workaround for truncated touch sounds
        // delayed volume change for system stream to be removed when the problem is
        // handled by system UI
        status_t volStatus = checkAndSetVolume(
                    curves, vs, index, desc, curDevices,
                    ((vs == toVolumeSource(AUDIO_STREAM_SYSTEM, false))?
                         TOUCH_SOUND_FIXED_DELAY_MS : 0));
        if (volStatus != NO_ERROR) {
            status = volStatus;
        }
    }
    mpClientInterface->onAudioVolumeGroupChanged(group, 0 /*flags*/);
    return status;
}

status_t AudioPolicyManager::setVolumeCurveIndex(int index,
                                                 audio_devices_t device,
                                                 IVolumeCurves &volumeCurves)
{
    // VOICE_CALL stream has minVolumeIndex > 0  but can be muted directly by an
    // app that has MODIFY_PHONE_STATE permission.
    bool hasVoice = hasVoiceStream(volumeCurves.getStreamTypes());
    if (((index < volumeCurves.getVolumeIndexMin()) && !(hasVoice && index == 0)) ||
            (index > volumeCurves.getVolumeIndexMax())) {
        ALOGD("%s: wrong index %d min=%d max=%d", __FUNCTION__, index,
              volumeCurves.getVolumeIndexMin(), volumeCurves.getVolumeIndexMax());
        return BAD_VALUE;
    }
    if (!audio_is_output_device(device)) {
        return BAD_VALUE;
    }

    // Force max volume if stream cannot be muted
    if (!volumeCurves.canBeMuted()) index = volumeCurves.getVolumeIndexMax();

    ALOGV("%s device %08x, index %d", __FUNCTION__ , device, index);
    volumeCurves.addCurrentVolumeIndex(device, index);
    return NO_ERROR;
}

status_t AudioPolicyManager::getVolumeIndexForAttributes(const audio_attributes_t &attr,
                                                         int &index,
                                                         audio_devices_t device)
{
    // if device is AUDIO_DEVICE_OUT_DEFAULT_FOR_VOLUME, return volume for device selected for this
    // stream by the engine.
    DeviceTypeSet deviceTypes = {device};
    if (device == AUDIO_DEVICE_OUT_DEFAULT_FOR_VOLUME) {
        DeviceTypeSet deviceTypes = mEngine->getOutputDevicesForAttributes(
                attr, nullptr, true /*fromCache*/).types();
    }
    return getVolumeIndex(getVolumeCurves(attr), index, deviceTypes);
}

status_t AudioPolicyManager::getVolumeIndex(const IVolumeCurves &curves,
                                            int &index,
                                            const DeviceTypeSet& deviceTypes) const
{
    if (isSingleDeviceType(deviceTypes, audio_is_output_device)) {
        return BAD_VALUE;
    }
    index = curves.getVolumeIndex(deviceTypes);
    ALOGV("%s: device %s index %d", __FUNCTION__, dumpDeviceTypes(deviceTypes).c_str(), index);
    return NO_ERROR;
}

status_t AudioPolicyManager::getMinVolumeIndexForAttributes(const audio_attributes_t &attr,
                                                            int &index)
{
    index = getVolumeCurves(attr).getVolumeIndexMin();
    return NO_ERROR;
}

status_t AudioPolicyManager::getMaxVolumeIndexForAttributes(const audio_attributes_t &attr,
                                                            int &index)
{
    index = getVolumeCurves(attr).getVolumeIndexMax();
    return NO_ERROR;
}

audio_io_handle_t AudioPolicyManager::selectOutputForMusicEffects()
{
    // select one output among several suitable for global effects.
    // The priority is as follows:
    // 1: An offloaded output. If the effect ends up not being offloadable,
    //    AudioFlinger will invalidate the track and the offloaded output
    //    will be closed causing the effect to be moved to a PCM output.
    // 2: A deep buffer output
    // 3: The primary output
    // 4: the first output in the list

    DeviceVector devices = mEngine->getOutputDevicesForAttributes(
                attributes_initializer(AUDIO_USAGE_MEDIA), nullptr, false /*fromCache*/);
    SortedVector<audio_io_handle_t> outputs = getOutputsForDevices(devices, mOutputs);

    if (outputs.size() == 0) {
        return AUDIO_IO_HANDLE_NONE;
    }

    audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;
    bool activeOnly = true;

    while (output == AUDIO_IO_HANDLE_NONE) {
        audio_io_handle_t outputOffloaded = AUDIO_IO_HANDLE_NONE;
        audio_io_handle_t outputDeepBuffer = AUDIO_IO_HANDLE_NONE;
        audio_io_handle_t outputPrimary = AUDIO_IO_HANDLE_NONE;

        for (audio_io_handle_t output : outputs) {
            sp<SwAudioOutputDescriptor> desc = mOutputs.valueFor(output);
            if (activeOnly && !desc->isActive(toVolumeSource(AUDIO_STREAM_MUSIC))) {
                continue;
            }
            ALOGV("selectOutputForMusicEffects activeOnly %d output %d flags 0x%08x",
                  activeOnly, output, desc->mFlags);
            if ((desc->mFlags & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) != 0) {
                outputOffloaded = output;
            }
            if ((desc->mFlags & AUDIO_OUTPUT_FLAG_DEEP_BUFFER) != 0) {
                outputDeepBuffer = output;
            }
            if ((desc->mFlags & AUDIO_OUTPUT_FLAG_PRIMARY) != 0) {
                outputPrimary = output;
            }
        }
        if (outputOffloaded != AUDIO_IO_HANDLE_NONE) {
            output = outputOffloaded;
        } else if (outputDeepBuffer != AUDIO_IO_HANDLE_NONE) {
            output = outputDeepBuffer;
        } else if (outputPrimary != AUDIO_IO_HANDLE_NONE) {
            output = outputPrimary;
        } else {
            output = outputs[0];
        }
        activeOnly = false;
    }

    if (output != mMusicEffectOutput) {
        mEffects.moveEffects(AUDIO_SESSION_OUTPUT_MIX, mMusicEffectOutput, output);
        mpClientInterface->moveEffects(AUDIO_SESSION_OUTPUT_MIX, mMusicEffectOutput, output);
        mMusicEffectOutput = output;
    }

    ALOGV("selectOutputForMusicEffects selected output %d", output);
    return output;
}

audio_io_handle_t AudioPolicyManager::getOutputForEffect(const effect_descriptor_t *desc __unused)
{
    return selectOutputForMusicEffects();
}

status_t AudioPolicyManager::registerEffect(const effect_descriptor_t *desc,
                                audio_io_handle_t io,
                                product_strategy_t strategy,
                                int session,
                                int id)
{
    if (session != AUDIO_SESSION_DEVICE) {
        ssize_t index = mOutputs.indexOfKey(io);
        if (index < 0) {
            index = mInputs.indexOfKey(io);
            if (index < 0) {
                ALOGW("registerEffect() unknown io %d", io);
                return INVALID_OPERATION;
            }
        }
    }
    bool isMusicEffect = (session != AUDIO_SESSION_OUTPUT_STAGE)
                            && ((strategy == streamToStrategy(AUDIO_STREAM_MUSIC)
                                    || strategy == PRODUCT_STRATEGY_NONE));
    return mEffects.registerEffect(desc, io, session, id, isMusicEffect);
}

status_t AudioPolicyManager::unregisterEffect(int id)
{
    if (mEffects.getEffect(id) == nullptr) {
        return INVALID_OPERATION;
    }
    if (mEffects.isEffectEnabled(id)) {
        ALOGW("%s effect %d enabled", __FUNCTION__, id);
        setEffectEnabled(id, false);
    }
    return mEffects.unregisterEffect(id);
}

status_t AudioPolicyManager::setEffectEnabled(int id, bool enabled)
{
    sp<EffectDescriptor> effect = mEffects.getEffect(id);
    if (effect == nullptr) {
        return INVALID_OPERATION;
    }

    status_t status = mEffects.setEffectEnabled(id, enabled);
    if (status == NO_ERROR) {
        mInputs.trackEffectEnabled(effect, enabled);
    }
    return status;
}


status_t AudioPolicyManager::moveEffectsToIo(const std::vector<int>& ids, audio_io_handle_t io)
{
   mEffects.moveEffects(ids, io);
   return NO_ERROR;
}

bool AudioPolicyManager::isStreamActive(audio_stream_type_t stream, uint32_t inPastMs) const
{
    auto vs = toVolumeSource(stream, false);
    return vs != VOLUME_SOURCE_NONE ? mOutputs.isActive(vs, inPastMs) : false;
}

bool AudioPolicyManager::isStreamActiveRemotely(audio_stream_type_t stream, uint32_t inPastMs) const
{
    auto vs = toVolumeSource(stream, false);
    return vs != VOLUME_SOURCE_NONE ? mOutputs.isActiveRemotely(vs, inPastMs) : false;
}

bool AudioPolicyManager::isSourceActive(audio_source_t source) const
{
    for (size_t i = 0; i < mInputs.size(); i++) {
        const sp<AudioInputDescriptor>  inputDescriptor = mInputs.valueAt(i);
        if (inputDescriptor->isSourceActive(source)) {
            return true;
        }
    }
    return false;
}

// Register a list of custom mixes with their attributes and format.
// When a mix is registered, corresponding input and output profiles are
// added to the remote submix hw module. The profile contains only the
// parameters (sampling rate, format...) specified by the mix.
// The corresponding input remote submix device is also connected.
//
// When a remote submix device is connected, the address is checked to select the
// appropriate profile and the corresponding input or output stream is opened.
//
// When capture starts, getInputForAttr() will:
//  - 1 look for a mix matching the address passed in attribtutes tags if any
//  - 2 if none found, getDeviceForInputSource() will:
//     - 2.1 look for a mix matching the attributes source
//     - 2.2 if none found, default to device selection by policy rules
// At this time, the corresponding output remote submix device is also connected
// and active playback use cases can be transferred to this mix if needed when reconnecting
// after AudioTracks are invalidated
//
// When playback starts, getOutputForAttr() will:
//  - 1 look for a mix matching the address passed in attribtutes tags if any
//  - 2 if none found, look for a mix matching the attributes usage
//  - 3 if none found, default to device and output selection by policy rules.

status_t AudioPolicyManager::registerPolicyMixes(const Vector<AudioMix>& mixes)
{
    ALOGV("registerPolicyMixes() %zu mix(es)", mixes.size());
    status_t res = NO_ERROR;
    bool checkOutputs = false;
    sp<HwModule> rSubmixModule;
    // examine each mix's route type
    for (size_t i = 0; i < mixes.size(); i++) {
        AudioMix mix = mixes[i];
        // Only capture of playback is allowed in LOOP_BACK & RENDER mode
        if (is_mix_loopback_render(mix.mRouteFlags) && mix.mMixType != MIX_TYPE_PLAYERS) {
            ALOGE("Unsupported Policy Mix %zu of %zu: "
                  "Only capture of playback is allowed in LOOP_BACK & RENDER mode",
                   i, mixes.size());
            res = INVALID_OPERATION;
            break;
        }
        // LOOP_BACK and LOOP_BACK | RENDER have the same remote submix backend and are handled
        // in the same way.
        if ((mix.mRouteFlags & MIX_ROUTE_FLAG_LOOP_BACK) == MIX_ROUTE_FLAG_LOOP_BACK) {
            ALOGV("registerPolicyMixes() mix %zu of %zu is LOOP_BACK %d", i, mixes.size(),
                  mix.mRouteFlags);
            if (rSubmixModule == 0) {
                rSubmixModule = mHwModules.getModuleFromName(
                        AUDIO_HARDWARE_MODULE_ID_REMOTE_SUBMIX);
                if (rSubmixModule == 0) {
                    ALOGE("Unable to find audio module for submix, aborting mix %zu registration",
                            i);
                    res = INVALID_OPERATION;
                    break;
                }
            }

            String8 address = mix.mDeviceAddress;
            audio_devices_t deviceTypeToMakeAvailable;
            if (mix.mMixType == MIX_TYPE_PLAYERS) {
                mix.mDeviceType = AUDIO_DEVICE_OUT_REMOTE_SUBMIX;
                deviceTypeToMakeAvailable = AUDIO_DEVICE_IN_REMOTE_SUBMIX;
            } else {
                mix.mDeviceType = AUDIO_DEVICE_IN_REMOTE_SUBMIX;
                deviceTypeToMakeAvailable = AUDIO_DEVICE_OUT_REMOTE_SUBMIX;
            }

            if (mPolicyMixes.registerMix(mix, 0 /*output desc*/) != NO_ERROR) {
                ALOGE("Error registering mix %zu for address %s", i, address.string());
                res = INVALID_OPERATION;
                break;
            }
            audio_config_t outputConfig = mix.mFormat;
            audio_config_t inputConfig = mix.mFormat;
            // NOTE: audio flinger mixer does not support mono output: configure remote submix HAL
            // in stereo and let audio flinger do the channel conversion if needed.
            outputConfig.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
            inputConfig.channel_mask = AUDIO_CHANNEL_IN_STEREO;
            rSubmixModule->addOutputProfile(address.c_str(), &outputConfig,
                    AUDIO_DEVICE_OUT_REMOTE_SUBMIX, address);
            rSubmixModule->addInputProfile(address.c_str(), &inputConfig,
                    AUDIO_DEVICE_IN_REMOTE_SUBMIX, address);

            if ((res = setDeviceConnectionStateInt(deviceTypeToMakeAvailable,
                    AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                    address.string(), "remote-submix", AUDIO_FORMAT_DEFAULT)) != NO_ERROR) {
                ALOGE("Failed to set remote submix device available, type %u, address %s",
                        mix.mDeviceType, address.string());
                break;
            }
        } else if ((mix.mRouteFlags & MIX_ROUTE_FLAG_RENDER) == MIX_ROUTE_FLAG_RENDER) {
            String8 address = mix.mDeviceAddress;
            audio_devices_t type = mix.mDeviceType;
            ALOGV(" registerPolicyMixes() mix %zu of %zu is RENDER, dev=0x%X addr=%s",
                    i, mixes.size(), type, address.string());

            sp<DeviceDescriptor> device = mHwModules.getDeviceDescriptor(
                    mix.mDeviceType, mix.mDeviceAddress,
                    String8(), AUDIO_FORMAT_DEFAULT);
            if (device == nullptr) {
                res = INVALID_OPERATION;
                break;
            }

            bool foundOutput = false;
            // First try to find an already opened output supporting the device
            for (size_t j = 0 ; j < mOutputs.size() && !foundOutput && res == NO_ERROR; j++) {
                sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(j);

                if (!desc->isDuplicated() && desc->supportedDevices().contains(device)) {
                    if (mPolicyMixes.registerMix(mix, desc) != NO_ERROR) {
                        ALOGE("Could not register mix RENDER,  dev=0x%X addr=%s", type,
                              address.string());
                        res = INVALID_OPERATION;
                    } else {
                        foundOutput = true;
                    }
                }
            }
            // If no output found, try to find a direct output profile supporting the device
            for (size_t i = 0; i < mHwModules.size() && !foundOutput && res == NO_ERROR; i++) {
                sp<HwModule> module = mHwModules[i];
                for (size_t j = 0;
                        j < module->getOutputProfiles().size() && !foundOutput && res == NO_ERROR;
                        j++) {
                    sp<IOProfile> profile = module->getOutputProfiles()[j];
                    if (profile->isDirectOutput() && profile->supportsDevice(device)) {
                        if (mPolicyMixes.registerMix(mix, nullptr) != NO_ERROR) {
                            ALOGE("Could not register mix RENDER,  dev=0x%X addr=%s", type,
                                  address.string());
                            res = INVALID_OPERATION;
                        } else {
                            foundOutput = true;
                        }
                    }
                }
            }
            if (res != NO_ERROR) {
                ALOGE(" Error registering mix %zu for device 0x%X addr %s",
                        i, type, address.string());
                res = INVALID_OPERATION;
                break;
            } else if (!foundOutput) {
                ALOGE(" Output not found for mix %zu for device 0x%X addr %s",
                        i, type, address.string());
                res = INVALID_OPERATION;
                break;
            } else {
                checkOutputs = true;
            }
        }
    }
    if (res != NO_ERROR) {
        unregisterPolicyMixes(mixes);
    } else if (checkOutputs) {
        checkForDeviceAndOutputChanges();
        updateCallAndOutputRouting();
    }
    return res;
}

status_t AudioPolicyManager::unregisterPolicyMixes(Vector<AudioMix> mixes)
{
    ALOGV("unregisterPolicyMixes() num mixes %zu", mixes.size());
    status_t res = NO_ERROR;
    bool checkOutputs = false;
    sp<HwModule> rSubmixModule;
    // examine each mix's route type
    for (const auto& mix : mixes) {
        if ((mix.mRouteFlags & MIX_ROUTE_FLAG_LOOP_BACK) == MIX_ROUTE_FLAG_LOOP_BACK) {

            if (rSubmixModule == 0) {
                rSubmixModule = mHwModules.getModuleFromName(
                        AUDIO_HARDWARE_MODULE_ID_REMOTE_SUBMIX);
                if (rSubmixModule == 0) {
                    res = INVALID_OPERATION;
                    continue;
                }
            }

            String8 address = mix.mDeviceAddress;

            if (mPolicyMixes.unregisterMix(mix) != NO_ERROR) {
                res = INVALID_OPERATION;
                continue;
            }

            for (auto device : {AUDIO_DEVICE_IN_REMOTE_SUBMIX, AUDIO_DEVICE_OUT_REMOTE_SUBMIX}) {
                if (getDeviceConnectionState(device, address.string()) ==
                        AUDIO_POLICY_DEVICE_STATE_AVAILABLE)  {
                    res = setDeviceConnectionStateInt(device, AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                      address.string(), "remote-submix",
                                                      AUDIO_FORMAT_DEFAULT);
                    if (res != OK) {
                        ALOGE("Error making RemoteSubmix device unavailable for mix "
                              "with type %d, address %s", device, address.string());
                    }
                }
            }
            rSubmixModule->removeOutputProfile(address.c_str());
            rSubmixModule->removeInputProfile(address.c_str());

        } else if ((mix.mRouteFlags & MIX_ROUTE_FLAG_RENDER) == MIX_ROUTE_FLAG_RENDER) {
            if (mPolicyMixes.unregisterMix(mix) != NO_ERROR) {
                res = INVALID_OPERATION;
                continue;
            } else {
                checkOutputs = true;
            }
        }
    }
    if (res == NO_ERROR && checkOutputs) {
        checkForDeviceAndOutputChanges();
        updateCallAndOutputRouting();
    }
    return res;
}

void AudioPolicyManager::dumpManualSurroundFormats(String8 *dst) const
{
    size_t i = 0;
    constexpr size_t audioFormatPrefixLen = sizeof("AUDIO_FORMAT_");
    for (const auto& fmt : mManualSurroundFormats) {
        if (i++ != 0) dst->append(", ");
        std::string sfmt;
        FormatConverter::toString(fmt, sfmt);
        dst->append(sfmt.size() >= audioFormatPrefixLen ?
                sfmt.c_str() + audioFormatPrefixLen - 1 : sfmt.c_str());
    }
}

// Returns true if all devices types match the predicate and are supported by one HW module
bool  AudioPolicyManager::areAllDevicesSupported(
        const AudioDeviceTypeAddrVector& devices,
        std::function<bool(audio_devices_t)> predicate,
        const char *context) {
    for (size_t i = 0; i < devices.size(); i++) {
        sp<DeviceDescriptor> devDesc = mHwModules.getDeviceDescriptor(
                devices[i].mType, devices[i].getAddress(), String8(),
                AUDIO_FORMAT_DEFAULT, false /*allowToCreate*/, true /*matchAddress*/);
        if (devDesc == nullptr || (predicate != nullptr && !predicate(devices[i].mType))) {
            ALOGE("%s: device type %#x address %s not supported or not match predicate",
                    context, devices[i].mType, devices[i].getAddress());
            return false;
        }
    }
    return true;
}

status_t AudioPolicyManager::setUidDeviceAffinities(uid_t uid,
        const AudioDeviceTypeAddrVector& devices) {
    ALOGV("%s() uid=%d num devices %zu", __FUNCTION__, uid, devices.size());
    if (!areAllDevicesSupported(devices, audio_is_output_device, __func__)) {
        return BAD_VALUE;
    }
    status_t res =  mPolicyMixes.setUidDeviceAffinities(uid, devices);
    if (res != NO_ERROR) {
        ALOGE("%s() Could not set all device affinities for uid = %d", __FUNCTION__, uid);
        return res;
    }

    checkForDeviceAndOutputChanges();
    updateCallAndOutputRouting();

    return NO_ERROR;
}

status_t AudioPolicyManager::removeUidDeviceAffinities(uid_t uid) {
    ALOGV("%s() uid=%d", __FUNCTION__, uid);
    status_t res = mPolicyMixes.removeUidDeviceAffinities(uid);
    if (res != NO_ERROR) {
        ALOGE("%s() Could not remove all device affinities for uid = %d",
            __FUNCTION__, uid);
        return INVALID_OPERATION;
    }

    checkForDeviceAndOutputChanges();
    updateCallAndOutputRouting();

    return res;
}


status_t AudioPolicyManager::setDevicesRoleForStrategy(product_strategy_t strategy,
                                                       device_role_t role,
                                                       const AudioDeviceTypeAddrVector &devices) {
    ALOGV("%s() strategy=%d role=%d %s", __func__, strategy, role,
            dumpAudioDeviceTypeAddrVector(devices).c_str());

    if (!areAllDevicesSupported(devices, audio_is_output_device, __func__)) {
        return BAD_VALUE;
    }
    status_t status = mEngine->setDevicesRoleForStrategy(strategy, role, devices);
    if (status != NO_ERROR) {
        ALOGW("Engine could not set preferred devices %s for strategy %d role %d",
                dumpAudioDeviceTypeAddrVector(devices).c_str(), strategy, role);
        return status;
    }

    checkForDeviceAndOutputChanges();

    bool forceVolumeReeval = false;
    // FIXME: workaround for truncated touch sounds
    // to be removed when the problem is handled by system UI
    uint32_t delayMs = 0;
    if (strategy == mCommunnicationStrategy) {
        forceVolumeReeval = true;
        delayMs = TOUCH_SOUND_FIXED_DELAY_MS;
        updateInputRouting();
    }
    updateCallAndOutputRouting(forceVolumeReeval, delayMs);

    return NO_ERROR;
}

void AudioPolicyManager::updateCallAndOutputRouting(bool forceVolumeReeval, uint32_t delayMs)
{
    uint32_t waitMs = 0;
    bool wasLeUnicastActive = isLeUnicastActive();
    if (updateCallRouting(true /*fromCache*/, delayMs, &waitMs) == NO_ERROR) {
        // Only apply special touch sound delay once
        delayMs = 0;
    }
    for (size_t i = 0; i < mOutputs.size(); i++) {
        sp<SwAudioOutputDescriptor> outputDesc = mOutputs.valueAt(i);
        DeviceVector newDevices = getNewOutputDevices(outputDesc, true /*fromCache*/);
        if ((mEngine->getPhoneState() != AUDIO_MODE_IN_CALL) ||
                (outputDesc != mPrimaryOutput && !isTelephonyRxOrTx(outputDesc))) {
            // As done in setDeviceConnectionState, we could also fix default device issue by
            // preventing the force re-routing in case of default dev that distinguishes on address.
            // Let's give back to engine full device choice decision however.
            bool forceRouting = !newDevices.isEmpty();
            waitMs = setOutputDevices(outputDesc, newDevices, forceRouting, delayMs, nullptr,
                                      true /*requiresMuteCheck*/,
                                      !forceRouting /*requiresVolumeCheck*/);
            // Only apply special touch sound delay once
            delayMs = 0;
        }
        if (forceVolumeReeval && !newDevices.isEmpty()) {
            applyStreamVolumes(outputDesc, newDevices.types(), waitMs, true);
        }
    }
    checkLeBroadcastRoutes(wasLeUnicastActive, nullptr, delayMs);
}

void AudioPolicyManager::updateInputRouting() {
    for (const auto& activeDesc : mInputs.getActiveInputs()) {
        // Skip for hotword recording as the input device switch
        // is handled within sound trigger HAL
        if (activeDesc->isSoundTrigger() && activeDesc->source() == AUDIO_SOURCE_HOTWORD) {
            continue;
        }
        auto newDevice = getNewInputDevice(activeDesc);
        // Force new input selection if the new device can not be reached via current input
        if (activeDesc->mProfile->getSupportedDevices().contains(newDevice)) {
            setInputDevice(activeDesc->mIoHandle, newDevice);
        } else {
            closeInput(activeDesc->mIoHandle);
        }
    }
}

status_t AudioPolicyManager::removeDevicesRoleForStrategy(product_strategy_t strategy,
                                                          device_role_t role)
{
    ALOGV("%s() strategy=%d role=%d", __func__, strategy, role);

    status_t status = mEngine->removeDevicesRoleForStrategy(strategy, role);
    if (status != NO_ERROR) {
        ALOGV("Engine could not remove preferred device for strategy %d status %d",
                strategy, status);
        return status;
    }

    checkForDeviceAndOutputChanges();

    bool forceVolumeReeval = false;
    // FIXME: workaround for truncated touch sounds
    // to be removed when the problem is handled by system UI
    uint32_t delayMs = 0;
    if (strategy == mCommunnicationStrategy) {
        forceVolumeReeval = true;
        delayMs = TOUCH_SOUND_FIXED_DELAY_MS;
        updateInputRouting();
    }
    updateCallAndOutputRouting(forceVolumeReeval, delayMs);

    return NO_ERROR;
}

status_t AudioPolicyManager::getDevicesForRoleAndStrategy(product_strategy_t strategy,
                                                          device_role_t role,
                                                          AudioDeviceTypeAddrVector &devices) {
    return mEngine->getDevicesForRoleAndStrategy(strategy, role, devices);
}

status_t AudioPolicyManager::setDevicesRoleForCapturePreset(
        audio_source_t audioSource, device_role_t role, const AudioDeviceTypeAddrVector &devices) {
    ALOGV("%s() audioSource=%d role=%d %s", __func__, audioSource, role,
            dumpAudioDeviceTypeAddrVector(devices).c_str());

    if (!areAllDevicesSupported(devices, audio_call_is_input_device, __func__)) {
        return BAD_VALUE;
    }
    status_t status = mEngine->setDevicesRoleForCapturePreset(audioSource, role, devices);
    ALOGW_IF(status != NO_ERROR,
            "Engine could not set preferred devices %s for audio source %d role %d",
            dumpAudioDeviceTypeAddrVector(devices).c_str(), audioSource, role);

    return status;
}

status_t AudioPolicyManager::addDevicesRoleForCapturePreset(
        audio_source_t audioSource, device_role_t role, const AudioDeviceTypeAddrVector &devices) {
    ALOGV("%s() audioSource=%d role=%d %s", __func__, audioSource, role,
            dumpAudioDeviceTypeAddrVector(devices).c_str());

    if (!areAllDevicesSupported(devices, audio_call_is_input_device, __func__)) {
        return BAD_VALUE;
    }
    status_t status = mEngine->addDevicesRoleForCapturePreset(audioSource, role, devices);
    ALOGW_IF(status != NO_ERROR,
            "Engine could not add preferred devices %s for audio source %d role %d",
            dumpAudioDeviceTypeAddrVector(devices).c_str(), audioSource, role);

    updateInputRouting();
    return status;
}

status_t AudioPolicyManager::removeDevicesRoleForCapturePreset(
        audio_source_t audioSource, device_role_t role, const AudioDeviceTypeAddrVector& devices)
{
    ALOGV("%s() audioSource=%d role=%d devices=%s", __func__, audioSource, role,
            dumpAudioDeviceTypeAddrVector(devices).c_str());

    if (!areAllDevicesSupported(devices, audio_call_is_input_device, __func__)) {
        return BAD_VALUE;
    }

    status_t status = mEngine->removeDevicesRoleForCapturePreset(
            audioSource, role, devices);
    ALOGW_IF(status != NO_ERROR,
            "Engine could not remove devices role (%d) for capture preset %d", role, audioSource);

    updateInputRouting();
    return status;
}

status_t AudioPolicyManager::clearDevicesRoleForCapturePreset(audio_source_t audioSource,
                                                              device_role_t role) {
    ALOGV("%s() audioSource=%d role=%d", __func__, audioSource, role);

    status_t status = mEngine->clearDevicesRoleForCapturePreset(audioSource, role);
    ALOGW_IF(status != NO_ERROR,
            "Engine could not clear devices role (%d) for capture preset %d", role, audioSource);

    updateInputRouting();
    return status;
}

status_t AudioPolicyManager::getDevicesForRoleAndCapturePreset(
        audio_source_t audioSource, device_role_t role, AudioDeviceTypeAddrVector &devices) {
    return mEngine->getDevicesForRoleAndCapturePreset(audioSource, role, devices);
}

status_t AudioPolicyManager::setUserIdDeviceAffinities(int userId,
        const AudioDeviceTypeAddrVector& devices) {
    ALOGV("%s() userId=%d num devices %zu", __func__, userId, devices.size());
    if (!areAllDevicesSupported(devices, audio_is_output_device, __func__)) {
        return BAD_VALUE;
    }
    status_t status =  mPolicyMixes.setUserIdDeviceAffinities(userId, devices);
    if (status != NO_ERROR) {
        ALOGE("%s() could not set device affinity for userId %d",
            __FUNCTION__, userId);
        return status;
    }

    // reevaluate outputs for all devices
    checkForDeviceAndOutputChanges();
    updateCallAndOutputRouting();

    return NO_ERROR;
}

status_t AudioPolicyManager::removeUserIdDeviceAffinities(int userId) {
    ALOGV("%s() userId=%d", __FUNCTION__, userId);
    status_t status = mPolicyMixes.removeUserIdDeviceAffinities(userId);
    if (status != NO_ERROR) {
        ALOGE("%s() Could not remove all device affinities fo userId = %d",
            __FUNCTION__, userId);
        return status;
    }

    // reevaluate outputs for all devices
    checkForDeviceAndOutputChanges();
    updateCallAndOutputRouting();

    return NO_ERROR;
}

void AudioPolicyManager::dump(String8 *dst) const
{
    dst->appendFormat("\nAudioPolicyManager Dump: %p\n", this);
    dst->appendFormat(" Primary Output I/O handle: %d\n",
             hasPrimaryOutput() ? mPrimaryOutput->mIoHandle : AUDIO_IO_HANDLE_NONE);
    std::string stateLiteral;
    AudioModeConverter::toString(mEngine->getPhoneState(), stateLiteral);
    dst->appendFormat(" Phone state: %s\n", stateLiteral.c_str());
    const char* forceUses[AUDIO_POLICY_FORCE_USE_CNT] = {
        "communications", "media", "record", "dock", "system",
        "HDMI system audio", "encoded surround output", "vibrate ringing" };
    for (audio_policy_force_use_t i = AUDIO_POLICY_FORCE_FOR_COMMUNICATION;
         i < AUDIO_POLICY_FORCE_USE_CNT; i = (audio_policy_force_use_t)((int)i + 1)) {
        audio_policy_forced_cfg_t forceUseValue = mEngine->getForceUse(i);
        dst->appendFormat(" Force use for %s: %d", forceUses[i], forceUseValue);
        if (i == AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND &&
                forceUseValue == AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL) {
            dst->append(" (MANUAL: ");
            dumpManualSurroundFormats(dst);
            dst->append(")");
        }
        dst->append("\n");
    }
    dst->appendFormat(" TTS output %savailable\n", mTtsOutputAvailable ? "" : "not ");
    dst->appendFormat(" Master mono: %s\n", mMasterMono ? "on" : "off");
    dst->appendFormat(" Communication Strategy id: %d\n", mCommunnicationStrategy);
    dst->appendFormat(" Config source: %s\n", mConfig.getSource().c_str()); // getConfig not const

    dst->append("\n");
    mAvailableOutputDevices.dump(dst, String8("Available output"), 1);
    dst->append("\n");
    mAvailableInputDevices.dump(dst, String8("Available input"), 1);
    mHwModulesAll.dump(dst);
    mOutputs.dump(dst);
    mInputs.dump(dst);
    mEffects.dump(dst, 1);
    mAudioPatches.dump(dst);
    mPolicyMixes.dump(dst);
    mAudioSources.dump(dst);

    dst->appendFormat(" AllowedCapturePolicies:\n");
    for (auto& policy : mAllowedCapturePolicies) {
        dst->appendFormat("   - uid=%d flag_mask=%#x\n", policy.first, policy.second);
    }

    dst->appendFormat("\nPolicy Engine dump:\n");
    mEngine->dump(dst);
}

status_t AudioPolicyManager::dump(int fd)
{
    String8 result;
    dump(&result);
    write(fd, result.string(), result.size());
    return NO_ERROR;
}

status_t AudioPolicyManager::setAllowedCapturePolicy(uid_t uid, audio_flags_mask_t capturePolicy)
{
    mAllowedCapturePolicies[uid] = capturePolicy;
    return NO_ERROR;
}

// This function checks for the parameters which can be offloaded.
// This can be enhanced depending on the capability of the DSP and policy
// of the system.
audio_offload_mode_t AudioPolicyManager::getOffloadSupport(const audio_offload_info_t& offloadInfo)
{
    ALOGV("%s: SR=%u, CM=0x%x, Format=0x%x, StreamType=%d,"
     " BitRate=%u, duration=%" PRId64 " us, has_video=%d",
     __func__, offloadInfo.sample_rate, offloadInfo.channel_mask,
     offloadInfo.format,
     offloadInfo.stream_type, offloadInfo.bit_rate, offloadInfo.duration_us,
     offloadInfo.has_video);

    if (!isOffloadPossible(offloadInfo)) {
        return AUDIO_OFFLOAD_NOT_SUPPORTED;
    }

    // See if there is a profile to support this.
    // AUDIO_DEVICE_NONE
    sp<IOProfile> profile = getProfileForOutput(DeviceVector() /*ignore device */,
                                            offloadInfo.sample_rate,
                                            offloadInfo.format,
                                            offloadInfo.channel_mask,
                                            AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD,
                                            true /* directOnly */);
    ALOGV("%s: profile %sfound%s", __func__, profile != nullptr ? "" : "NOT ",
            (profile != nullptr && (profile->getFlags() & AUDIO_OUTPUT_FLAG_GAPLESS_OFFLOAD) != 0)
            ? ", supports gapless" : "");
    if (profile == nullptr) {
        return AUDIO_OFFLOAD_NOT_SUPPORTED;
    }
    if ((profile->getFlags() & AUDIO_OUTPUT_FLAG_GAPLESS_OFFLOAD) != 0) {
        return AUDIO_OFFLOAD_GAPLESS_SUPPORTED;
    }
    return AUDIO_OFFLOAD_SUPPORTED;
}

bool AudioPolicyManager::isDirectOutputSupported(const audio_config_base_t& config,
                                                 const audio_attributes_t& attributes) {
    audio_output_flags_t output_flags = AUDIO_OUTPUT_FLAG_NONE;
    audio_flags_to_audio_output_flags(attributes.flags, &output_flags);
    DeviceVector outputDevices = mEngine->getOutputDevicesForAttributes(attributes);
    sp<IOProfile> profile = getProfileForOutput(outputDevices,
                                            config.sample_rate,
                                            config.format,
                                            config.channel_mask,
                                            output_flags,
                                            true /* directOnly */);
    ALOGV("%s() profile %sfound with name: %s, "
        "sample rate: %u, format: 0x%x, channel_mask: 0x%x, output flags: 0x%x",
        __FUNCTION__, profile != 0 ? "" : "NOT ",
        (profile != 0 ? profile->getTagName().c_str() : "null"),
        config.sample_rate, config.format, config.channel_mask, output_flags);

    // also try the MSD module if compatible profile not found
    if (profile == nullptr) {
        profile = getMsdProfileForOutput(outputDevices,
                                              config.sample_rate,
                                              config.format,
                                              config.channel_mask,
                                              output_flags,
                                              true /* directOnly */);
        ALOGV("%s() MSD profile %sfound with name: %s, "
            "sample rate: %u, format: 0x%x, channel_mask: 0x%x, output flags: 0x%x",
            __FUNCTION__, profile != 0 ? "" : "NOT ",
            (profile != 0 ? profile->getTagName().c_str() : "null"),
            config.sample_rate, config.format, config.channel_mask, output_flags);
    }
    return (profile != nullptr);
}

bool AudioPolicyManager::isOffloadPossible(const audio_offload_info_t &offloadInfo,
                                           bool durationIgnored) {
    if (mMasterMono) {
        return false; // no offloading if mono is set.
    }

    // Check if offload has been disabled
    if (property_get_bool("audio.offload.disable", false /* default_value */)) {
        ALOGV("%s: offload disabled by audio.offload.disable", __func__);
        return false;
    }

    // Check if stream type is music, then only allow offload as of now.
    if (offloadInfo.stream_type != AUDIO_STREAM_MUSIC)
    {
        ALOGV("%s: stream_type != MUSIC, returning false", __func__);
        return false;
    }

    //TODO: enable audio offloading with video when ready
    const bool allowOffloadWithVideo =
            property_get_bool("audio.offload.video", false /* default_value */);
    if (offloadInfo.has_video && !allowOffloadWithVideo) {
        ALOGV("%s: has_video == true, returning false", __func__);
        return false;
    }

    //If duration is less than minimum value defined in property, return false
    const int min_duration_secs = property_get_int32(
            "audio.offload.min.duration.secs", -1 /* default_value */);
    if (!durationIgnored) {
        if (min_duration_secs >= 0) {
            if (offloadInfo.duration_us < min_duration_secs * 1000000LL) {
                ALOGV("%s: Offload denied by duration < audio.offload.min.duration.secs(=%d)",
                      __func__, min_duration_secs);
                return false;
            }
        } else if (offloadInfo.duration_us < OFFLOAD_DEFAULT_MIN_DURATION_SECS * 1000000) {
            ALOGV("%s: Offload denied by duration < default min(=%u)",
                  __func__, OFFLOAD_DEFAULT_MIN_DURATION_SECS);
            return false;
        }
    }

    // Do not allow offloading if one non offloadable effect is enabled. This prevents from
    // creating an offloaded track and tearing it down immediately after start when audioflinger
    // detects there is an active non offloadable effect.
    // FIXME: We should check the audio session here but we do not have it in this context.
    // This may prevent offloading in rare situations where effects are left active by apps
    // in the background.
    if (mEffects.isNonOffloadableEffectEnabled()) {
        return false;
    }

    return true;
}

audio_direct_mode_t AudioPolicyManager::getDirectPlaybackSupport(const audio_attributes_t *attr,
                                                                 const audio_config_t *config) {
    audio_offload_info_t offloadInfo = AUDIO_INFO_INITIALIZER;
    offloadInfo.format = config->format;
    offloadInfo.sample_rate = config->sample_rate;
    offloadInfo.channel_mask = config->channel_mask;
    offloadInfo.stream_type = mEngine->getStreamTypeForAttributes(*attr);
    offloadInfo.has_video = false;
    offloadInfo.is_streaming = false;
    const bool offloadPossible = isOffloadPossible(offloadInfo, true /*durationIgnored*/);

    audio_direct_mode_t directMode = AUDIO_DIRECT_NOT_SUPPORTED;
    audio_output_flags_t flags = AUDIO_OUTPUT_FLAG_NONE;
    audio_flags_to_audio_output_flags(attr->flags, &flags);
    // only retain flags that will drive compressed offload or passthrough
    uint32_t relevantFlags = AUDIO_OUTPUT_FLAG_HW_AV_SYNC;
    if (offloadPossible) {
        relevantFlags |= AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD;
    }
    flags = (audio_output_flags_t)((flags & relevantFlags) | AUDIO_OUTPUT_FLAG_DIRECT);

    DeviceVector engineOutputDevices = mEngine->getOutputDevicesForAttributes(*attr);
    for (const auto& hwModule : mHwModules) {
        DeviceVector outputDevices = engineOutputDevices;
        // the MSD module checks for different conditions and output devices
        if (strcmp(hwModule->getName(), AUDIO_HARDWARE_MODULE_ID_MSD) == 0) {
            if (!msdHasPatchesToAllDevices(engineOutputDevices.toTypeAddrVector())) {
                continue;
            }
            outputDevices = getMsdAudioOutDevices();
        }
        for (const auto& curProfile : hwModule->getOutputProfiles()) {
            if (!curProfile->isCompatibleProfile(outputDevices,
                    config->sample_rate, nullptr /*updatedSamplingRate*/,
                    config->format, nullptr /*updatedFormat*/,
                    config->channel_mask, nullptr /*updatedChannelMask*/,
                    flags)) {
                continue;
            }
            // reject profiles not corresponding to a device currently available
            if (!mAvailableOutputDevices.containsAtLeastOne(curProfile->getSupportedDevices())) {
                continue;
            }
            if ((curProfile->getFlags() & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD)
                        != AUDIO_OUTPUT_FLAG_NONE) {
                if ((directMode & AUDIO_DIRECT_OFFLOAD_GAPLESS_SUPPORTED)
                        != AUDIO_DIRECT_NOT_SUPPORTED) {
                    // Already reports offload gapless supported. No need to report offload support.
                    continue;
                }
                if ((curProfile->getFlags() & AUDIO_OUTPUT_FLAG_GAPLESS_OFFLOAD)
                        != AUDIO_OUTPUT_FLAG_NONE) {
                    // If offload gapless is reported, no need to report offload support.
                    directMode = (audio_direct_mode_t) ((directMode &
                            ~AUDIO_DIRECT_OFFLOAD_SUPPORTED) |
                            AUDIO_DIRECT_OFFLOAD_GAPLESS_SUPPORTED);
                } else {
                    directMode = (audio_direct_mode_t)(directMode | AUDIO_DIRECT_OFFLOAD_SUPPORTED);
                }
            } else {
                directMode = (audio_direct_mode_t) (directMode | AUDIO_DIRECT_BITSTREAM_SUPPORTED);
            }
        }
    }
    return directMode;
}

status_t AudioPolicyManager::getDirectProfilesForAttributes(const audio_attributes_t* attr,
                                                AudioProfileVector& audioProfilesVector) {
    if (mEffects.isNonOffloadableEffectEnabled()) {
        return OK;
    }
    AudioDeviceTypeAddrVector devices;
    status_t status = getDevicesForAttributes(*attr, &devices, false /* forVolume */);
    if (status != OK) {
        return status;
    }
    ALOGV("%s: found %zu output devices for attributes.", __func__, devices.size());
    if (devices.empty()) {
        return OK; // no output devices for the attributes
    }

    for (const auto& hwModule : mHwModules) {
        // the MSD module checks for different conditions
        if (strcmp(hwModule->getName(), AUDIO_HARDWARE_MODULE_ID_MSD) == 0) {
            continue;
        }
        for (const auto& outputProfile : hwModule->getOutputProfiles()) {
            if (!outputProfile->asAudioPort()->isDirectOutput()) {
                continue;
            }
            // allow only profiles that support all the available and routed devices
            if (outputProfile->getSupportedDevices().getDevicesFromDeviceTypeAddrVec(devices).size()
                    != devices.size()) {
                continue;
            }
            audioProfilesVector.addAllValidProfiles(
                    outputProfile->asAudioPort()->getAudioProfiles());
        }
    }

    // add the direct profiles from MSD if present and has audio patches to all the output(s)
    const auto& msdModule = mHwModules.getModuleFromName(AUDIO_HARDWARE_MODULE_ID_MSD);
    if (msdModule != nullptr) {
        if (msdHasPatchesToAllDevices(devices)) {
            ALOGV("%s: MSD audio patches set to all output devices.", __func__);
            for (const auto& outputProfile : msdModule->getOutputProfiles()) {
                if (!outputProfile->asAudioPort()->isDirectOutput()) {
                    continue;
                }
                audioProfilesVector.addAllValidProfiles(
                        outputProfile->asAudioPort()->getAudioProfiles());
            }
        } else {
            ALOGV("%s: MSD audio patches NOT set to all output devices.", __func__);
        }
    }

    return NO_ERROR;
}

status_t AudioPolicyManager::listAudioPorts(audio_port_role_t role,
                                            audio_port_type_t type,
                                            unsigned int *num_ports,
                                            struct audio_port_v7 *ports,
                                            unsigned int *generation)
{
    if (num_ports == nullptr || (*num_ports != 0 && ports == nullptr) ||
            generation == nullptr) {
        return BAD_VALUE;
    }
    ALOGV("listAudioPorts() role %d type %d num_ports %d ports %p", role, type, *num_ports, ports);
    if (ports == nullptr) {
        *num_ports = 0;
    }

    size_t portsWritten = 0;
    size_t portsMax = *num_ports;
    *num_ports = 0;
    if (type == AUDIO_PORT_TYPE_NONE || type == AUDIO_PORT_TYPE_DEVICE) {
        // do not report devices with type AUDIO_DEVICE_IN_STUB or AUDIO_DEVICE_OUT_STUB
        // as they are used by stub HALs by convention
        if (role == AUDIO_PORT_ROLE_SINK || role == AUDIO_PORT_ROLE_NONE) {
            for (const auto& dev : mAvailableOutputDevices) {
                if (dev->type() == AUDIO_DEVICE_OUT_STUB) {
                    continue;
                }
                if (portsWritten < portsMax) {
                    dev->toAudioPort(&ports[portsWritten++]);
                }
                (*num_ports)++;
            }
        }
        if (role == AUDIO_PORT_ROLE_SOURCE || role == AUDIO_PORT_ROLE_NONE) {
            for (const auto& dev : mAvailableInputDevices) {
                if (dev->type() == AUDIO_DEVICE_IN_STUB) {
                    continue;
                }
                if (portsWritten < portsMax) {
                    dev->toAudioPort(&ports[portsWritten++]);
                }
                (*num_ports)++;
            }
        }
    }
    if (type == AUDIO_PORT_TYPE_NONE || type == AUDIO_PORT_TYPE_MIX) {
        if (role == AUDIO_PORT_ROLE_SINK || role == AUDIO_PORT_ROLE_NONE) {
            for (size_t i = 0; i < mInputs.size() && portsWritten < portsMax; i++) {
                mInputs[i]->toAudioPort(&ports[portsWritten++]);
            }
            *num_ports += mInputs.size();
        }
        if (role == AUDIO_PORT_ROLE_SOURCE || role == AUDIO_PORT_ROLE_NONE) {
            size_t numOutputs = 0;
            for (size_t i = 0; i < mOutputs.size(); i++) {
                if (!mOutputs[i]->isDuplicated()) {
                    numOutputs++;
                    if (portsWritten < portsMax) {
                        mOutputs[i]->toAudioPort(&ports[portsWritten++]);
                    }
                }
            }
            *num_ports += numOutputs;
        }
    }
    *generation = curAudioPortGeneration();
    ALOGV("listAudioPorts() got %zu ports needed %d", portsWritten, *num_ports);
    return NO_ERROR;
}

status_t AudioPolicyManager::getAudioPort(struct audio_port_v7 *port)
{
    if (port == nullptr || port->id == AUDIO_PORT_HANDLE_NONE) {
        return BAD_VALUE;
    }
    sp<DeviceDescriptor> dev = mAvailableOutputDevices.getDeviceFromId(port->id);
    if (dev != 0) {
        dev->toAudioPort(port);
        return NO_ERROR;
    }
    dev = mAvailableInputDevices.getDeviceFromId(port->id);
    if (dev != 0) {
        dev->toAudioPort(port);
        return NO_ERROR;
    }
    sp<SwAudioOutputDescriptor> out = mOutputs.getOutputFromId(port->id);
    if (out != 0) {
        out->toAudioPort(port);
        return NO_ERROR;
    }
    sp<AudioInputDescriptor> in = mInputs.getInputFromId(port->id);
    if (in != 0) {
        in->toAudioPort(port);
        return NO_ERROR;
    }
    return BAD_VALUE;
}

status_t AudioPolicyManager::createAudioPatch(const struct audio_patch *patch,
                                              audio_patch_handle_t *handle,
                                              uid_t uid)
{
    ALOGV("%s", __func__);
    if (handle == NULL || patch == NULL) {
        return BAD_VALUE;
    }
    ALOGV("%s num sources %d num sinks %d", __func__, patch->num_sources, patch->num_sinks);
    if (!audio_patch_is_valid(patch)) {
        return BAD_VALUE;
    }
    // only one source per audio patch supported for now
    if (patch->num_sources > 1) {
        return INVALID_OPERATION;
    }
    if (patch->sources[0].role != AUDIO_PORT_ROLE_SOURCE) {
        return INVALID_OPERATION;
    }
    for (size_t i = 0; i < patch->num_sinks; i++) {
        if (patch->sinks[i].role != AUDIO_PORT_ROLE_SINK) {
            return INVALID_OPERATION;
        }
    }

    sp<DeviceDescriptor> srcDevice = mAvailableInputDevices.getDeviceFromId(patch->sources[0].id);
    sp<DeviceDescriptor> sinkDevice = mAvailableOutputDevices.getDeviceFromId(patch->sinks[0].id);
    if (srcDevice == nullptr || sinkDevice == nullptr) {
        ALOGW("%s could not create patch, invalid sink and/or source device(s)", __func__);
        return BAD_VALUE;
    }
    ALOGV("%s between source %s and sink %s", __func__,
            srcDevice->toString().c_str(), sinkDevice->toString().c_str());
    audio_port_handle_t portId = PolicyAudioPort::getNextUniqueId();
    // Default attributes, default volume priority, not to infer with non raw audio patches.
    audio_attributes_t attributes = attributes_initializer(AUDIO_USAGE_MEDIA);
    const struct audio_port_config *source = &patch->sources[0];
    sp<SourceClientDescriptor> sourceDesc =
            new InternalSourceClientDescriptor(
                portId, uid, attributes, *source, srcDevice, sinkDevice,
                mEngine->getProductStrategyForAttributes(attributes), toVolumeSource(attributes));

    status_t status =
            connectAudioSourceToSink(sourceDesc, sinkDevice, patch, *handle, uid, 0 /* delayMs */);

    if (status != NO_ERROR) {
        return INVALID_OPERATION;
    }
    mAudioSources.add(portId, sourceDesc);
    return NO_ERROR;
}

status_t AudioPolicyManager::connectAudioSourceToSink(
        const sp<SourceClientDescriptor>& sourceDesc, const sp<DeviceDescriptor> &sinkDevice,
        const struct audio_patch *patch,
        audio_patch_handle_t &handle,
        uid_t uid, uint32_t delayMs)
{
    status_t status = createAudioPatchInternal(patch, &handle, uid, delayMs, sourceDesc);
    if (status != NO_ERROR || mAudioPatches.indexOfKey(handle) < 0) {
        ALOGW("%s patch panel could not connect device patch, error %d", __func__, status);
        return INVALID_OPERATION;
    }
    sourceDesc->connect(handle, sinkDevice);
    if (isMsdPatch(handle)) {
        return NO_ERROR;
    }
    // SW Bridge? (@todo: HW bridge, keep track of HwOutput for device selection "reconsideration")
    sp<SwAudioOutputDescriptor> swOutput = sourceDesc->swOutput().promote();
    ALOG_ASSERT(swOutput != nullptr, "%s: a swOutput shall always be associated", __func__);
    if (swOutput->getClient(sourceDesc->portId()) != nullptr) {
        ALOGW("%s source portId has already been attached to outputDesc", __func__);
        goto FailurePatchAdded;
    }
    status = swOutput->start();
    if (status != NO_ERROR) {
        goto FailureSourceAdded;
    }
    swOutput->addClient(sourceDesc);
    status = startSource(swOutput, sourceDesc, &delayMs);
    if (status != NO_ERROR) {
        ALOGW("%s failed to start source, error %d", __FUNCTION__, status);
        goto FailureSourceActive;
    }
    if (delayMs != 0) {
        usleep(delayMs * 1000);
    }
    return NO_ERROR;

FailureSourceActive:
    swOutput->stop();
    releaseOutput(sourceDesc->portId());
FailureSourceAdded:
    sourceDesc->setSwOutput(nullptr);
FailurePatchAdded:
    releaseAudioPatchInternal(handle);
    return INVALID_OPERATION;
}

status_t AudioPolicyManager::createAudioPatchInternal(const struct audio_patch *patch,
                                                      audio_patch_handle_t *handle,
                                                      uid_t uid, uint32_t delayMs,
                                                      const sp<SourceClientDescriptor>& sourceDesc)
{
    ALOGV("%s num sources %d num sinks %d", __func__, patch->num_sources, patch->num_sinks);
    sp<AudioPatch> patchDesc;
    ssize_t index = mAudioPatches.indexOfKey(*handle);

    ALOGV("%s source id %d role %d type %d", __func__, patch->sources[0].id,
                                                       patch->sources[0].role,
                                                       patch->sources[0].type);
#if LOG_NDEBUG == 0
    for (size_t i = 0; i < patch->num_sinks; i++) {
        ALOGV("%s sink %zu: id %d role %d type %d", __func__ ,i, patch->sinks[i].id,
                                                                 patch->sinks[i].role,
                                                                 patch->sinks[i].type);
    }
#endif

    if (index >= 0) {
        patchDesc = mAudioPatches.valueAt(index);
        ALOGV("%s mUidCached %d patchDesc->mUid %d uid %d",
              __func__, mUidCached, patchDesc->getUid(), uid);
        if (patchDesc->getUid() != mUidCached && uid != patchDesc->getUid()) {
            return INVALID_OPERATION;
        }
    } else {
        *handle = AUDIO_PATCH_HANDLE_NONE;
    }

    if (patch->sources[0].type == AUDIO_PORT_TYPE_MIX) {
        sp<SwAudioOutputDescriptor> outputDesc = mOutputs.getOutputFromId(patch->sources[0].id);
        if (outputDesc == NULL) {
            ALOGV("%s output not found for id %d", __func__, patch->sources[0].id);
            return BAD_VALUE;
        }
        ALOG_ASSERT(!outputDesc->isDuplicated(),"duplicated output %d in source in ports",
                                                outputDesc->mIoHandle);
        if (patchDesc != 0) {
            if (patchDesc->mPatch.sources[0].id != patch->sources[0].id) {
                ALOGV("%s source id differs for patch current id %d new id %d",
                      __func__, patchDesc->mPatch.sources[0].id, patch->sources[0].id);
                return BAD_VALUE;
            }
        }
        DeviceVector devices;
        for (size_t i = 0; i < patch->num_sinks; i++) {
            // Only support mix to devices connection
            // TODO add support for mix to mix connection
            if (patch->sinks[i].type != AUDIO_PORT_TYPE_DEVICE) {
                ALOGV("%s source mix but sink is not a device", __func__);
                return INVALID_OPERATION;
            }
            sp<DeviceDescriptor> devDesc =
                    mAvailableOutputDevices.getDeviceFromId(patch->sinks[i].id);
            if (devDesc == 0) {
                ALOGV("%s out device not found for id %d", __func__, patch->sinks[i].id);
                return BAD_VALUE;
            }

            if (!outputDesc->mProfile->isCompatibleProfile(DeviceVector(devDesc),
                                                           patch->sources[0].sample_rate,
                                                           NULL,  // updatedSamplingRate
                                                           patch->sources[0].format,
                                                           NULL,  // updatedFormat
                                                           patch->sources[0].channel_mask,
                                                           NULL,  // updatedChannelMask
                                                           AUDIO_OUTPUT_FLAG_NONE /*FIXME*/)) {
                ALOGV("%s profile not supported for device %08x", __func__, devDesc->type());
                return INVALID_OPERATION;
            }
            devices.add(devDesc);
        }
        if (devices.size() == 0) {
            return INVALID_OPERATION;
        }

        // TODO: reconfigure output format and channels here
        ALOGV("%s setting device %s on output %d",
              __func__, dumpDeviceTypes(devices.types()).c_str(), outputDesc->mIoHandle);
        setOutputDevices(outputDesc, devices, true, 0, handle);
        index = mAudioPatches.indexOfKey(*handle);
        if (index >= 0) {
            if (patchDesc != 0 && patchDesc != mAudioPatches.valueAt(index)) {
                ALOGW("%s setOutputDevice() did not reuse the patch provided", __func__);
            }
            patchDesc = mAudioPatches.valueAt(index);
            patchDesc->setUid(uid);
            ALOGV("%s success", __func__);
        } else {
            ALOGW("%s setOutputDevice() failed to create a patch", __func__);
            return INVALID_OPERATION;
        }
    } else if (patch->sources[0].type == AUDIO_PORT_TYPE_DEVICE) {
        if (patch->sinks[0].type == AUDIO_PORT_TYPE_MIX) {
            // input device to input mix connection
            // only one sink supported when connecting an input device to a mix
            if (patch->num_sinks > 1) {
                return INVALID_OPERATION;
            }
            sp<AudioInputDescriptor> inputDesc = mInputs.getInputFromId(patch->sinks[0].id);
            if (inputDesc == NULL) {
                return BAD_VALUE;
            }
            if (patchDesc != 0) {
                if (patchDesc->mPatch.sinks[0].id != patch->sinks[0].id) {
                    return BAD_VALUE;
                }
            }
            sp<DeviceDescriptor> device =
                    mAvailableInputDevices.getDeviceFromId(patch->sources[0].id);
            if (device == 0) {
                return BAD_VALUE;
            }

            if (!inputDesc->mProfile->isCompatibleProfile(DeviceVector(device),
                                                          patch->sinks[0].sample_rate,
                                                          NULL, /*updatedSampleRate*/
                                                          patch->sinks[0].format,
                                                          NULL, /*updatedFormat*/
                                                          patch->sinks[0].channel_mask,
                                                          NULL, /*updatedChannelMask*/
                                                          // FIXME for the parameter type,
                                                          // and the NONE
                                                          (audio_output_flags_t)
                                                            AUDIO_INPUT_FLAG_NONE)) {
                return INVALID_OPERATION;
            }
            // TODO: reconfigure output format and channels here
            ALOGV("%s setting device %s on output %d", __func__,
                  device->toString().c_str(), inputDesc->mIoHandle);
            setInputDevice(inputDesc->mIoHandle, device, true, handle);
            index = mAudioPatches.indexOfKey(*handle);
            if (index >= 0) {
                if (patchDesc != 0 && patchDesc != mAudioPatches.valueAt(index)) {
                    ALOGW("%s setInputDevice() did not reuse the patch provided", __func__);
                }
                patchDesc = mAudioPatches.valueAt(index);
                patchDesc->setUid(uid);
                ALOGV("%s success", __func__);
            } else {
                ALOGW("%s setInputDevice() failed to create a patch", __func__);
                return INVALID_OPERATION;
            }
        } else if (patch->sinks[0].type == AUDIO_PORT_TYPE_DEVICE) {
            // device to device connection
            if (patchDesc != 0) {
                if (patchDesc->mPatch.sources[0].id != patch->sources[0].id) {
                    return BAD_VALUE;
                }
            }
            sp<DeviceDescriptor> srcDevice =
                    mAvailableInputDevices.getDeviceFromId(patch->sources[0].id);
            if (srcDevice == 0) {
                return BAD_VALUE;
            }

            //update source and sink with our own data as the data passed in the patch may
            // be incomplete.
            PatchBuilder patchBuilder;
            audio_port_config sourcePortConfig = {};

            // if first sink is to MSD, establish single MSD patch
            if (getMsdAudioOutDevices().contains(
                        mAvailableOutputDevices.getDeviceFromId(patch->sinks[0].id))) {
                ALOGV("%s patching to MSD", __FUNCTION__);
                patchBuilder = buildMsdPatch(false /*msdIsSource*/, srcDevice);
                goto installPatch;
            }

            srcDevice->toAudioPortConfig(&sourcePortConfig, &patch->sources[0]);
            patchBuilder.addSource(sourcePortConfig);

            for (size_t i = 0; i < patch->num_sinks; i++) {
                if (patch->sinks[i].type != AUDIO_PORT_TYPE_DEVICE) {
                    ALOGV("%s source device but one sink is not a device", __func__);
                    return INVALID_OPERATION;
                }
                sp<DeviceDescriptor> sinkDevice =
                        mAvailableOutputDevices.getDeviceFromId(patch->sinks[i].id);
                if (sinkDevice == 0) {
                    return BAD_VALUE;
                }
                audio_port_config sinkPortConfig = {};
                sinkDevice->toAudioPortConfig(&sinkPortConfig, &patch->sinks[i]);
                patchBuilder.addSink(sinkPortConfig);

                // Whatever Sw or Hw bridge, we do attach an SwOutput to an Audio Source for
                // volume management purpose (tracking activity)
                // In case of Hw bridge, it is a Work Around. The mixPort used is the one declared
                // in config XML to reach the sink so that is can be declared as available.
                audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;
                sp<SwAudioOutputDescriptor> outputDesc = nullptr;
                if (!sourceDesc->isInternal()) {
                    // take care of dynamic routing for SwOutput selection,
                    audio_attributes_t attributes = sourceDesc->attributes();
                    audio_stream_type_t stream = sourceDesc->stream();
                    audio_attributes_t resultAttr;
                    audio_config_t config = AUDIO_CONFIG_INITIALIZER;
                    config.sample_rate = sourceDesc->config().sample_rate;
                    config.channel_mask = sourceDesc->config().channel_mask;
                    config.format = sourceDesc->config().format;
                    audio_output_flags_t flags = AUDIO_OUTPUT_FLAG_NONE;
                    audio_port_handle_t selectedDeviceId = AUDIO_PORT_HANDLE_NONE;
                    bool isRequestedDeviceForExclusiveUse = false;
                    output_type_t outputType;
                    bool isSpatialized;
                    getOutputForAttrInt(&resultAttr, &output, AUDIO_SESSION_NONE, &attributes,
                                        &stream, sourceDesc->uid(), &config, &flags,
                                        &selectedDeviceId, &isRequestedDeviceForExclusiveUse,
                                        nullptr, &outputType, &isSpatialized);
                    if (output == AUDIO_IO_HANDLE_NONE) {
                        ALOGV("%s no output for device %s",
                              __FUNCTION__, sinkDevice->toString().c_str());
                        return INVALID_OPERATION;
                    }
                    outputDesc = mOutputs.valueFor(output);
                    if (outputDesc->isDuplicated()) {
                        ALOGE("%s output is duplicated", __func__);
                        return INVALID_OPERATION;
                    }
                    sourceDesc->setSwOutput(outputDesc);
                } else {
                    // Same for "raw patches" aka created from createAudioPatch API
                    SortedVector<audio_io_handle_t> outputs =
                            getOutputsForDevices(DeviceVector(sinkDevice), mOutputs);
                    // if the sink device is reachable via an opened output stream, request to
                    // go via this output stream by adding a second source to the patch
                    // description
                    output = selectOutput(outputs);
                    if (output == AUDIO_IO_HANDLE_NONE) {
                        ALOGE("%s no output available for internal patch sink", __func__);
                        return INVALID_OPERATION;
                    }
                    outputDesc = mOutputs.valueFor(output);
                    if (outputDesc->isDuplicated()) {
                        ALOGV("%s output for device %s is duplicated",
                              __func__, sinkDevice->toString().c_str());
                        return INVALID_OPERATION;
                    }
                    sourceDesc->setSwOutput(outputDesc);
                }
                // create a software bridge in PatchPanel if:
                // - source and sink devices are on different HW modules OR
                // - audio HAL version is < 3.0
                // - audio HAL version is >= 3.0 but no route has been declared between devices
                // - called from startAudioSource (aka sourceDesc is not internal) and source device
                //   does not have a gain controller
                if (!srcDevice->hasSameHwModuleAs(sinkDevice) ||
                        (srcDevice->getModuleVersionMajor() < 3) ||
                        !srcDevice->getModule()->supportsPatch(srcDevice, sinkDevice) ||
                        (!sourceDesc->isInternal() &&
                         srcDevice->getAudioPort()->getGains().size() == 0)) {
                    // support only one sink device for now to simplify output selection logic
                    if (patch->num_sinks > 1) {
                        return INVALID_OPERATION;
                    }
                    sourceDesc->setUseSwBridge();
                    if (outputDesc != nullptr) {
                        audio_port_config srcMixPortConfig = {};
                        outputDesc->toAudioPortConfig(&srcMixPortConfig, nullptr);
                        // for volume control, we may need a valid stream
                        srcMixPortConfig.ext.mix.usecase.stream = !sourceDesc->isInternal() ?
                                    mEngine->getStreamTypeForAttributes(sourceDesc->attributes()) :
                                    AUDIO_STREAM_PATCH;
                        patchBuilder.addSource(srcMixPortConfig);
                    }
                }
            }
            // TODO: check from routing capabilities in config file and other conflicting patches

installPatch:
            status_t status = installPatch(
                        __func__, index, handle, patchBuilder.patch(), delayMs, uid, &patchDesc);
            if (status != NO_ERROR) {
                ALOGW("%s patch panel could not connect device patch, error %d", __func__, status);
                return INVALID_OPERATION;
            }
        } else {
            return BAD_VALUE;
        }
    } else {
        return BAD_VALUE;
    }
    return NO_ERROR;
}

status_t AudioPolicyManager::releaseAudioPatch(audio_patch_handle_t handle, uid_t uid)
{
    ALOGV("%s patch %d", __func__, handle);
    ssize_t index = mAudioPatches.indexOfKey(handle);

    if (index < 0) {
        return BAD_VALUE;
    }
    sp<AudioPatch> patchDesc = mAudioPatches.valueAt(index);
    ALOGV("%s() mUidCached %d patchDesc->mUid %d uid %d",
          __func__, mUidCached, patchDesc->getUid(), uid);
    if (patchDesc->getUid() != mUidCached && uid != patchDesc->getUid()) {
        return INVALID_OPERATION;
    }
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;
    for (size_t i = 0; i < mAudioSources.size(); i++)  {
        sp<SourceClientDescriptor> sourceDesc = mAudioSources.valueAt(i);
        if (sourceDesc != nullptr && sourceDesc->getPatchHandle() == handle) {
            portId = sourceDesc->portId();
            break;
        }
    }
    return portId != AUDIO_PORT_HANDLE_NONE ?
                stopAudioSource(portId) : releaseAudioPatchInternal(handle);
}

status_t AudioPolicyManager::releaseAudioPatchInternal(audio_patch_handle_t handle,
                                                       uint32_t delayMs,
                                                       const sp<SourceClientDescriptor>& sourceDesc)
{
    ALOGV("%s patch %d", __func__, handle);
    if (mAudioPatches.indexOfKey(handle) < 0) {
        ALOGE("%s: no patch found with handle=%d", __func__, handle);
        return BAD_VALUE;
    }
    sp<AudioPatch> patchDesc = mAudioPatches.valueFor(handle);
    struct audio_patch *patch = &patchDesc->mPatch;
    patchDesc->setUid(mUidCached);
    if (patch->sources[0].type == AUDIO_PORT_TYPE_MIX) {
        sp<SwAudioOutputDescriptor> outputDesc = mOutputs.getOutputFromId(patch->sources[0].id);
        if (outputDesc == NULL) {
            ALOGV("%s output not found for id %d", __func__, patch->sources[0].id);
            return BAD_VALUE;
        }

        setOutputDevices(outputDesc,
                         getNewOutputDevices(outputDesc, true /*fromCache*/),
                         true,
                         0,
                         NULL);
    } else if (patch->sources[0].type == AUDIO_PORT_TYPE_DEVICE) {
        if (patch->sinks[0].type == AUDIO_PORT_TYPE_MIX) {
            sp<AudioInputDescriptor> inputDesc = mInputs.getInputFromId(patch->sinks[0].id);
            if (inputDesc == NULL) {
                ALOGV("%s input not found for id %d", __func__, patch->sinks[0].id);
                return BAD_VALUE;
            }
            setInputDevice(inputDesc->mIoHandle,
                           getNewInputDevice(inputDesc),
                           true,
                           NULL);
        } else if (patch->sinks[0].type == AUDIO_PORT_TYPE_DEVICE) {
            status_t status =
                    mpClientInterface->releaseAudioPatch(patchDesc->getAfHandle(), delayMs);
            ALOGV("%s patch panel returned %d patchHandle %d",
                  __func__, status, patchDesc->getAfHandle());
            removeAudioPatch(patchDesc->getHandle());
            nextAudioPortGeneration();
            mpClientInterface->onAudioPatchListUpdate();
            // SW or HW Bridge
            sp<SwAudioOutputDescriptor> outputDesc = nullptr;
            audio_patch_handle_t patchHandle = AUDIO_PATCH_HANDLE_NONE;
            if (patch->num_sources > 1 && patch->sources[1].type == AUDIO_PORT_TYPE_MIX) {
                outputDesc = mOutputs.getOutputFromId(patch->sources[1].id);
            } else if (patch->num_sources == 1 && sourceDesc != nullptr) {
                outputDesc = sourceDesc->swOutput().promote();
            }
            if (outputDesc == nullptr) {
                ALOGW("%s no output for id %d", __func__, patch->sources[0].id);
                // releaseOutput has already called closeOutput in case of direct output
                return NO_ERROR;
            }
            if (!outputDesc->isActive() && !sourceDesc->useSwBridge()) {
                resetOutputDevice(outputDesc);
            } else {
                // Reuse patch handle if still valid / do not force rerouting if still routed
                patchHandle = outputDesc->getPatchHandle();
                setOutputDevices(outputDesc,
                                 getNewOutputDevices(outputDesc, true /*fromCache*/),
                                 patchHandle == AUDIO_PATCH_HANDLE_NONE, /*force*/
                                 0,
                                 patchHandle == AUDIO_PATCH_HANDLE_NONE ? nullptr : &patchHandle);
            }
        } else {
            return BAD_VALUE;
        }
    } else {
        return BAD_VALUE;
    }
    return NO_ERROR;
}

status_t AudioPolicyManager::listAudioPatches(unsigned int *num_patches,
                                              struct audio_patch *patches,
                                              unsigned int *generation)
{
    if (generation == NULL) {
        return BAD_VALUE;
    }
    *generation = curAudioPortGeneration();
    return mAudioPatches.listAudioPatches(num_patches, patches);
}

status_t AudioPolicyManager::setAudioPortConfig(const struct audio_port_config *config)
{
    ALOGV("setAudioPortConfig()");

    if (config == NULL) {
        return BAD_VALUE;
    }
    ALOGV("setAudioPortConfig() on port handle %d", config->id);
    // Only support gain configuration for now
    if (config->config_mask != AUDIO_PORT_CONFIG_GAIN) {
        return INVALID_OPERATION;
    }

    sp<AudioPortConfig> audioPortConfig;
    if (config->type == AUDIO_PORT_TYPE_MIX) {
        if (config->role == AUDIO_PORT_ROLE_SOURCE) {
            sp<SwAudioOutputDescriptor> outputDesc = mOutputs.getOutputFromId(config->id);
            if (outputDesc == NULL) {
                return BAD_VALUE;
            }
            ALOG_ASSERT(!outputDesc->isDuplicated(),
                        "setAudioPortConfig() called on duplicated output %d",
                        outputDesc->mIoHandle);
            audioPortConfig = outputDesc;
        } else if (config->role == AUDIO_PORT_ROLE_SINK) {
            sp<AudioInputDescriptor> inputDesc = mInputs.getInputFromId(config->id);
            if (inputDesc == NULL) {
                return BAD_VALUE;
            }
            audioPortConfig = inputDesc;
        } else {
            return BAD_VALUE;
        }
    } else if (config->type == AUDIO_PORT_TYPE_DEVICE) {
        sp<DeviceDescriptor> deviceDesc;
        if (config->role == AUDIO_PORT_ROLE_SOURCE) {
            deviceDesc = mAvailableInputDevices.getDeviceFromId(config->id);
        } else if (config->role == AUDIO_PORT_ROLE_SINK) {
            deviceDesc = mAvailableOutputDevices.getDeviceFromId(config->id);
        } else {
            return BAD_VALUE;
        }
        if (deviceDesc == NULL) {
            return BAD_VALUE;
        }
        audioPortConfig = deviceDesc;
    } else {
        return BAD_VALUE;
    }

    struct audio_port_config backupConfig = {};
    status_t status = audioPortConfig->applyAudioPortConfig(config, &backupConfig);
    if (status == NO_ERROR) {
        struct audio_port_config newConfig = {};
        audioPortConfig->toAudioPortConfig(&newConfig, config);
        status = mpClientInterface->setAudioPortConfig(&newConfig, 0);
    }
    if (status != NO_ERROR) {
        audioPortConfig->applyAudioPortConfig(&backupConfig);
    }

    return status;
}

void AudioPolicyManager::releaseResourcesForUid(uid_t uid)
{
    clearAudioSources(uid);
    clearAudioPatches(uid);
    clearSessionRoutes(uid);
}

void AudioPolicyManager::clearAudioPatches(uid_t uid)
{
    for (ssize_t i = (ssize_t)mAudioPatches.size() - 1; i >= 0; i--)  {
        sp<AudioPatch> patchDesc = mAudioPatches.valueAt(i);
        if (patchDesc->getUid() == uid) {
            releaseAudioPatch(mAudioPatches.keyAt(i), uid);
        }
    }
}

void AudioPolicyManager::checkStrategyRoute(product_strategy_t ps, audio_io_handle_t ouptutToSkip)
{
    // Take the first attributes following the product strategy as it is used to retrieve the routed
    // device. All attributes wihin a strategy follows the same "routing strategy"
    auto attributes = mEngine->getAllAttributesForProductStrategy(ps).front();
    DeviceVector devices = mEngine->getOutputDevicesForAttributes(attributes, nullptr, false);
    SortedVector<audio_io_handle_t> outputs = getOutputsForDevices(devices, mOutputs);
    for (size_t j = 0; j < mOutputs.size(); j++) {
        if (mOutputs.keyAt(j) == ouptutToSkip) {
            continue;
        }
        sp<SwAudioOutputDescriptor> outputDesc = mOutputs.valueAt(j);
        if (!outputDesc->isStrategyActive(ps)) {
            continue;
        }
        // If the default device for this strategy is on another output mix,
        // invalidate all tracks in this strategy to force re connection.
        // Otherwise select new device on the output mix.
        if (outputs.indexOf(mOutputs.keyAt(j)) < 0) {
            for (auto stream : mEngine->getStreamTypesForProductStrategy(ps)) {
                mpClientInterface->invalidateStream(stream);
            }
        } else {
            setOutputDevices(
                        outputDesc, getNewOutputDevices(outputDesc, false /*fromCache*/), false);
        }
    }
}

void AudioPolicyManager::clearSessionRoutes(uid_t uid)
{
    // remove output routes associated with this uid
    std::vector<product_strategy_t> affectedStrategies;
    for (size_t i = 0; i < mOutputs.size(); i++) {
        sp<AudioOutputDescriptor> outputDesc = mOutputs.valueAt(i);
        for (const auto& client : outputDesc->getClientIterable()) {
            if (client->hasPreferredDevice() && client->uid() == uid) {
                client->setPreferredDeviceId(AUDIO_PORT_HANDLE_NONE);
                auto clientStrategy = client->strategy();
                if (std::find(begin(affectedStrategies), end(affectedStrategies), clientStrategy) !=
                        end(affectedStrategies)) {
                    continue;
                }
                affectedStrategies.push_back(client->strategy());
            }
        }
    }
    // reroute outputs if necessary
    for (const auto& strategy : affectedStrategies) {
        checkStrategyRoute(strategy, AUDIO_IO_HANDLE_NONE);
    }

    // remove input routes associated with this uid
    SortedVector<audio_source_t> affectedSources;
    for (size_t i = 0; i < mInputs.size(); i++) {
        sp<AudioInputDescriptor> inputDesc = mInputs.valueAt(i);
        for (const auto& client : inputDesc->getClientIterable()) {
            if (client->hasPreferredDevice() && client->uid() == uid) {
                client->setPreferredDeviceId(AUDIO_PORT_HANDLE_NONE);
                affectedSources.add(client->source());
            }
        }
    }
    // reroute inputs if necessary
    SortedVector<audio_io_handle_t> inputsToClose;
    for (size_t i = 0; i < mInputs.size(); i++) {
        sp<AudioInputDescriptor> inputDesc = mInputs.valueAt(i);
        if (affectedSources.indexOf(inputDesc->source()) >= 0) {
            inputsToClose.add(inputDesc->mIoHandle);
        }
    }
    for (const auto& input : inputsToClose) {
        closeInput(input);
    }
}

void AudioPolicyManager::clearAudioSources(uid_t uid)
{
    for (ssize_t i = (ssize_t)mAudioSources.size() - 1; i >= 0; i--)  {
        sp<SourceClientDescriptor> sourceDesc = mAudioSources.valueAt(i);
        if (sourceDesc->uid() == uid) {
            stopAudioSource(mAudioSources.keyAt(i));
        }
    }
}

status_t AudioPolicyManager::acquireSoundTriggerSession(audio_session_t *session,
                                       audio_io_handle_t *ioHandle,
                                       audio_devices_t *device)
{
    *session = (audio_session_t)mpClientInterface->newAudioUniqueId(AUDIO_UNIQUE_ID_USE_SESSION);
    *ioHandle = (audio_io_handle_t)mpClientInterface->newAudioUniqueId(AUDIO_UNIQUE_ID_USE_INPUT);
    audio_attributes_t attr = { .source = AUDIO_SOURCE_HOTWORD };
    *device = mEngine->getInputDeviceForAttributes(attr)->type();

    return mSoundTriggerSessions.acquireSession(*session, *ioHandle);
}

status_t AudioPolicyManager::startAudioSource(const struct audio_port_config *source,
                                              const audio_attributes_t *attributes,
                                              audio_port_handle_t *portId,
                                              uid_t uid)
{
    ALOGV("%s", __FUNCTION__);
    *portId = AUDIO_PORT_HANDLE_NONE;

    if (source == NULL || attributes == NULL || portId == NULL) {
        ALOGW("%s invalid argument: source %p attributes %p handle %p",
              __FUNCTION__, source, attributes, portId);
        return BAD_VALUE;
    }

    if (source->role != AUDIO_PORT_ROLE_SOURCE ||
            source->type != AUDIO_PORT_TYPE_DEVICE) {
        ALOGW("%s INVALID_OPERATION source->role %d source->type %d",
              __FUNCTION__, source->role, source->type);
        return INVALID_OPERATION;
    }

    sp<DeviceDescriptor> srcDevice =
            mAvailableInputDevices.getDevice(source->ext.device.type,
                                             String8(source->ext.device.address),
                                             AUDIO_FORMAT_DEFAULT);
    if (srcDevice == 0) {
        ALOGW("%s source->ext.device.type %08x not found", __FUNCTION__, source->ext.device.type);
        return BAD_VALUE;
    }

    *portId = PolicyAudioPort::getNextUniqueId();

    sp<SourceClientDescriptor> sourceDesc =
        new SourceClientDescriptor(*portId, uid, *attributes, *source, srcDevice,
                                   mEngine->getStreamTypeForAttributes(*attributes),
                                   mEngine->getProductStrategyForAttributes(*attributes),
                                   toVolumeSource(*attributes));

    status_t status = connectAudioSource(sourceDesc);
    if (status == NO_ERROR) {
        mAudioSources.add(*portId, sourceDesc);
    }
    return status;
}

sp<SourceClientDescriptor> AudioPolicyManager::startAudioSourceInternal(
        const struct audio_port_config *source, const audio_attributes_t *attributes, uid_t uid)
{
    ALOGV("%s", __FUNCTION__);
    audio_port_handle_t portId = AUDIO_PORT_HANDLE_NONE;

    status_t status = startAudioSource(source, attributes, &portId, uid);
    ALOGE_IF(status != OK, "%s: failed to start audio source (%d)", __func__, status);
    return mAudioSources.valueFor(portId);
}


status_t AudioPolicyManager::connectAudioSource(const sp<SourceClientDescriptor>& sourceDesc)
{
    ALOGV("%s handle %d", __FUNCTION__, sourceDesc->portId());

    // make sure we only have one patch per source.
    disconnectAudioSource(sourceDesc);

    audio_attributes_t attributes = sourceDesc->attributes();
    // May the device (dynamic) have been disconnected/reconnected, id has changed.
    sp<DeviceDescriptor> srcDevice = mAvailableInputDevices.getDevice(
                sourceDesc->srcDevice()->type(),
                String8(sourceDesc->srcDevice()->address().c_str()),
                AUDIO_FORMAT_DEFAULT);
    DeviceVector sinkDevices =
            mEngine->getOutputDevicesForAttributes(attributes, nullptr, false /*fromCache*/);
    ALOG_ASSERT(!sinkDevices.isEmpty(), "connectAudioSource(): no device found for attributes");
    sp<DeviceDescriptor> sinkDevice = sinkDevices.itemAt(0);
    if (!mAvailableOutputDevices.contains(sinkDevice)) {
        ALOGE("%s Device %s not available", __func__, sinkDevice->toString().c_str());
        return INVALID_OPERATION;
    }
    PatchBuilder patchBuilder;
    patchBuilder.addSink(sinkDevice).addSource(srcDevice);
    audio_patch_handle_t handle = AUDIO_PATCH_HANDLE_NONE;

    return connectAudioSourceToSink(
                sourceDesc, sinkDevice, patchBuilder.patch(), handle, mUidCached, 0 /*delayMs*/);
}

status_t AudioPolicyManager::stopAudioSource(audio_port_handle_t portId)
{
    sp<SourceClientDescriptor> sourceDesc = mAudioSources.valueFor(portId);
    ALOGV("%s port ID %d", __FUNCTION__, portId);
    if (sourceDesc == 0) {
        ALOGW("%s unknown source for port ID %d", __FUNCTION__, portId);
        return BAD_VALUE;
    }
    status_t status = disconnectAudioSource(sourceDesc);

    mAudioSources.removeItem(portId);
    return status;
}

status_t AudioPolicyManager::setMasterMono(bool mono)
{
    if (mMasterMono == mono) {
        return NO_ERROR;
    }
    mMasterMono = mono;
    // if enabling mono we close all offloaded devices, which will invalidate the
    // corresponding AudioTrack. The AudioTrack client/MediaPlayer is responsible
    // for recreating the new AudioTrack as non-offloaded PCM.
    //
    // If disabling mono, we leave all tracks as is: we don't know which clients
    // and tracks are able to be recreated as offloaded. The next "song" should
    // play back offloaded.
    if (mMasterMono) {
        Vector<audio_io_handle_t> offloaded;
        for (size_t i = 0; i < mOutputs.size(); ++i) {
            sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
            if (desc->mFlags & AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD) {
                offloaded.push(desc->mIoHandle);
            }
        }
        for (const auto& handle : offloaded) {
            closeOutput(handle);
        }
    }
    // update master mono for all remaining outputs
    for (size_t i = 0; i < mOutputs.size(); ++i) {
        updateMono(mOutputs.keyAt(i));
    }
    return NO_ERROR;
}

status_t AudioPolicyManager::getMasterMono(bool *mono)
{
    *mono = mMasterMono;
    return NO_ERROR;
}

float AudioPolicyManager::getStreamVolumeDB(
        audio_stream_type_t stream, int index, audio_devices_t device)
{
    return computeVolume(getVolumeCurves(stream), toVolumeSource(stream), index, {device});
}

status_t AudioPolicyManager::getSurroundFormats(unsigned int *numSurroundFormats,
                                                audio_format_t *surroundFormats,
                                                bool *surroundFormatsEnabled)
{
    if (numSurroundFormats == nullptr || (*numSurroundFormats != 0 &&
            (surroundFormats == nullptr || surroundFormatsEnabled == nullptr))) {
        return BAD_VALUE;
    }
    ALOGV("%s() numSurroundFormats %d surroundFormats %p surroundFormatsEnabled %p",
            __func__, *numSurroundFormats, surroundFormats, surroundFormatsEnabled);

    size_t formatsWritten = 0;
    size_t formatsMax = *numSurroundFormats;

    *numSurroundFormats = mConfig.getSurroundFormats().size();
    audio_policy_forced_cfg_t forceUse = mEngine->getForceUse(
            AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND);
    for (const auto& format: mConfig.getSurroundFormats()) {
        if (formatsWritten < formatsMax) {
            surroundFormats[formatsWritten] = format.first;
            bool formatEnabled = true;
            switch (forceUse) {
                case AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL:
                    formatEnabled = mManualSurroundFormats.count(format.first) != 0;
                    break;
                case AUDIO_POLICY_FORCE_ENCODED_SURROUND_NEVER:
                    formatEnabled = false;
                    break;
                default: // AUTO or ALWAYS => true
                    break;
            }
            surroundFormatsEnabled[formatsWritten++] = formatEnabled;
        }
    }
    return NO_ERROR;
}

status_t AudioPolicyManager::getReportedSurroundFormats(unsigned int *numSurroundFormats,
                                                        audio_format_t *surroundFormats) {
    if (numSurroundFormats == nullptr || (*numSurroundFormats != 0 && surroundFormats == nullptr)) {
        return BAD_VALUE;
    }
    ALOGV("%s() numSurroundFormats %d surroundFormats %p",
            __func__, *numSurroundFormats, surroundFormats);

    size_t formatsWritten = 0;
    size_t formatsMax = *numSurroundFormats;
    std::unordered_set<audio_format_t> formats; // Uses primary surround formats only

    // Return formats from all device profiles that have already been resolved by
    // checkOutputsForDevice().
    for (size_t i = 0; i < mAvailableOutputDevices.size(); i++) {
        sp<DeviceDescriptor> device = mAvailableOutputDevices[i];
        audio_devices_t deviceType = device->type();
        // Enabling/disabling formats are applied to only HDMI devices. So, this function
        // returns formats reported by HDMI devices.
        if (deviceType != AUDIO_DEVICE_OUT_HDMI) {
            continue;
        }
        // Formats reported by sink devices
        std::unordered_set<audio_format_t> formatset;
        if (auto it = mReportedFormatsMap.find(device); it != mReportedFormatsMap.end()) {
            formatset.insert(it->second.begin(), it->second.end());
        }

        // Formats hard-coded in the in policy configuration file (if any).
        FormatVector encodedFormats = device->encodedFormats();
        formatset.insert(encodedFormats.begin(), encodedFormats.end());
        // Filter the formats which are supported by the vendor hardware.
        for (auto it = formatset.begin(); it != formatset.end(); ++it) {
            if (mConfig.getSurroundFormats().count(*it) != 0) {
                formats.insert(*it);
            } else {
                for (const auto& pair : mConfig.getSurroundFormats()) {
                    if (pair.second.count(*it) != 0) {
                        formats.insert(pair.first);
                        break;
                    }
                }
            }
        }
    }
    *numSurroundFormats = formats.size();
    for (const auto& format: formats) {
        if (formatsWritten < formatsMax) {
            surroundFormats[formatsWritten++] = format;
        }
    }
    return NO_ERROR;
}

status_t AudioPolicyManager::setSurroundFormatEnabled(audio_format_t audioFormat, bool enabled)
{
    ALOGV("%s() format 0x%X enabled %d", __func__, audioFormat, enabled);
    const auto& formatIter = mConfig.getSurroundFormats().find(audioFormat);
    if (formatIter == mConfig.getSurroundFormats().end()) {
        ALOGW("%s() format 0x%X is not a known surround format", __func__, audioFormat);
        return BAD_VALUE;
    }

    if (mEngine->getForceUse(AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND) !=
            AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL) {
        ALOGW("%s() not in manual mode for surround sound format selection", __func__);
        return INVALID_OPERATION;
    }

    if ((mManualSurroundFormats.count(audioFormat) != 0) == enabled) {
        return NO_ERROR;
    }

    std::unordered_set<audio_format_t> surroundFormatsBackup(mManualSurroundFormats);
    if (enabled) {
        mManualSurroundFormats.insert(audioFormat);
        for (const auto& subFormat : formatIter->second) {
            mManualSurroundFormats.insert(subFormat);
        }
    } else {
        mManualSurroundFormats.erase(audioFormat);
        for (const auto& subFormat : formatIter->second) {
            mManualSurroundFormats.erase(subFormat);
        }
    }

    sp<SwAudioOutputDescriptor> outputDesc;
    bool profileUpdated = false;
    DeviceVector hdmiOutputDevices = mAvailableOutputDevices.getDevicesFromType(
        AUDIO_DEVICE_OUT_HDMI);
    for (size_t i = 0; i < hdmiOutputDevices.size(); i++) {
        // Simulate reconnection to update enabled surround sound formats.
        String8 address = String8(hdmiOutputDevices[i]->address().c_str());
        std::string name = hdmiOutputDevices[i]->getName();
        status_t status = setDeviceConnectionStateInt(AUDIO_DEVICE_OUT_HDMI,
                                                      AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                      address.c_str(),
                                                      name.c_str(),
                                                      AUDIO_FORMAT_DEFAULT);
        if (status != NO_ERROR) {
            continue;
        }
        status = setDeviceConnectionStateInt(AUDIO_DEVICE_OUT_HDMI,
                                             AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                             address.c_str(),
                                             name.c_str(),
                                             AUDIO_FORMAT_DEFAULT);
        profileUpdated |= (status == NO_ERROR);
    }
    // FIXME: Why doing this for input HDMI devices if we don't augment their reported formats?
    DeviceVector hdmiInputDevices = mAvailableInputDevices.getDevicesFromType(
                AUDIO_DEVICE_IN_HDMI);
    for (size_t i = 0; i < hdmiInputDevices.size(); i++) {
        // Simulate reconnection to update enabled surround sound formats.
        String8 address = String8(hdmiInputDevices[i]->address().c_str());
        std::string name = hdmiInputDevices[i]->getName();
        status_t status = setDeviceConnectionStateInt(AUDIO_DEVICE_IN_HDMI,
                                                      AUDIO_POLICY_DEVICE_STATE_UNAVAILABLE,
                                                      address.c_str(),
                                                      name.c_str(),
                                                      AUDIO_FORMAT_DEFAULT);
        if (status != NO_ERROR) {
            continue;
        }
        status = setDeviceConnectionStateInt(AUDIO_DEVICE_IN_HDMI,
                                             AUDIO_POLICY_DEVICE_STATE_AVAILABLE,
                                             address.c_str(),
                                             name.c_str(),
                                             AUDIO_FORMAT_DEFAULT);
        profileUpdated |= (status == NO_ERROR);
    }

    if (!profileUpdated) {
        ALOGW("%s() no audio profiles updated, undoing surround formats change", __func__);
        mManualSurroundFormats = std::move(surroundFormatsBackup);
    }

    return profileUpdated ? NO_ERROR : INVALID_OPERATION;
}

void AudioPolicyManager::setAppState(audio_port_handle_t portId, app_state_t state)
{
    ALOGV("%s(portId:%d, state:%d)", __func__, portId, state);
    for (size_t i = 0; i < mInputs.size(); i++) {
        mInputs.valueAt(i)->setAppState(portId, state);
    }
}

bool AudioPolicyManager::isHapticPlaybackSupported()
{
    for (const auto& hwModule : mHwModules) {
        const OutputProfileCollection &outputProfiles = hwModule->getOutputProfiles();
        for (const auto &outProfile : outputProfiles) {
            struct audio_port audioPort;
            outProfile->toAudioPort(&audioPort);
            for (size_t i = 0; i < audioPort.num_channel_masks; i++) {
                if (audioPort.channel_masks[i] & AUDIO_CHANNEL_HAPTIC_ALL) {
                    return true;
                }
            }
        }
    }
    return false;
}

bool AudioPolicyManager::isUltrasoundSupported()
{
    bool hasUltrasoundOutput = false;
    bool hasUltrasoundInput = false;
    for (const auto& hwModule : mHwModules) {
        const OutputProfileCollection &outputProfiles = hwModule->getOutputProfiles();
        if (!hasUltrasoundOutput) {
            for (const auto &outProfile : outputProfiles) {
                if (outProfile->getFlags() & AUDIO_OUTPUT_FLAG_ULTRASOUND) {
                    hasUltrasoundOutput = true;
                    break;
                }
            }
        }

        const InputProfileCollection &inputProfiles = hwModule->getInputProfiles();
        if (!hasUltrasoundInput) {
            for (const auto &inputProfile : inputProfiles) {
                if (inputProfile->getFlags() & AUDIO_INPUT_FLAG_ULTRASOUND) {
                    hasUltrasoundInput = true;
                    break;
                }
            }
        }

        if (hasUltrasoundOutput && hasUltrasoundInput)
            return true;
    }
    return false;
}

bool AudioPolicyManager::isCallScreenModeSupported()
{
    return getConfig().isCallScreenModeSupported();
}


status_t AudioPolicyManager::disconnectAudioSource(const sp<SourceClientDescriptor>& sourceDesc)
{
    ALOGV("%s port Id %d", __FUNCTION__, sourceDesc->portId());
    if (!sourceDesc->isConnected()) {
        ALOGV("%s port Id %d already disconnected", __FUNCTION__, sourceDesc->portId());
        return NO_ERROR;
    }
    sp<SwAudioOutputDescriptor> swOutput = sourceDesc->swOutput().promote();
    if (swOutput != 0) {
        status_t status = stopSource(swOutput, sourceDesc);
        if (status == NO_ERROR) {
            swOutput->stop();
        }
        if (releaseOutput(sourceDesc->portId())) {
            // The output descriptor is reopened to query dynamic profiles. In that case, there is
            // no need to release audio patch here but just return NO_ERROR.
            return NO_ERROR;
        }
    } else {
        sp<HwAudioOutputDescriptor> hwOutputDesc = sourceDesc->hwOutput().promote();
        if (hwOutputDesc != 0) {
          //   close Hwoutput and remove from mHwOutputs
        } else {
            ALOGW("%s source has neither SW nor HW output", __FUNCTION__);
        }
    }
    status_t status = releaseAudioPatchInternal(sourceDesc->getPatchHandle(), 0, sourceDesc);
    sourceDesc->disconnect();
    return status;
}

sp<SourceClientDescriptor> AudioPolicyManager::getSourceForAttributesOnOutput(
        audio_io_handle_t output, const audio_attributes_t &attr)
{
    sp<SourceClientDescriptor> source;
    for (size_t i = 0; i < mAudioSources.size(); i++)  {
        sp<SourceClientDescriptor> sourceDesc = mAudioSources.valueAt(i);
        sp<SwAudioOutputDescriptor> outputDesc = sourceDesc->swOutput().promote();
        if (followsSameRouting(attr, sourceDesc->attributes()) &&
                               outputDesc != 0 && outputDesc->mIoHandle == output) {
            source = sourceDesc;
            break;
        }
    }
    return source;
}

bool AudioPolicyManager::canBeSpatializedInt(const audio_attributes_t *attr,
                                      const audio_config_t *config,
                                      const AudioDeviceTypeAddrVector &devices)  const
{
    // The caller can have the audio attributes criteria ignored by either passing a null ptr or
    // the AUDIO_ATTRIBUTES_INITIALIZER value.
    // If attributes are specified, current policy is to only allow spatialization for media
    // and game usages.
    if (attr != nullptr && *attr != AUDIO_ATTRIBUTES_INITIALIZER) {
        if (attr->usage != AUDIO_USAGE_MEDIA && attr->usage != AUDIO_USAGE_GAME) {
            return false;
        }
        if ((attr->flags & (AUDIO_FLAG_CONTENT_SPATIALIZED | AUDIO_FLAG_NEVER_SPATIALIZE)) != 0) {
            return false;
        }
    }

    sp<IOProfile> profile =
            getSpatializerOutputProfile(config, devices);
    if (profile == nullptr) {
        return false;
    }

    // The caller can have the audio config criteria ignored by either passing a null ptr or
    // the AUDIO_CONFIG_INITIALIZER value.
    // If an audio config is specified, current policy is to only allow spatialization for
    // some positional channel masks.

    if (config != nullptr && *config != AUDIO_CONFIG_INITIALIZER) {
        if (!audio_is_channel_mask_spatialized(config->channel_mask)) {
            return false;
        }
    }
    return true;
}

void AudioPolicyManager::checkVirtualizerClientRoutes() {
    std::set<audio_stream_type_t> streamsToInvalidate;
    for (size_t i = 0; i < mOutputs.size(); i++) {
        const sp<SwAudioOutputDescriptor>& desc = mOutputs[i];
        for (const sp<TrackClientDescriptor>& client : desc->getClientIterable()) {
            audio_attributes_t attr = client->attributes();
            DeviceVector devices = mEngine->getOutputDevicesForAttributes(attr, nullptr, false);
            AudioDeviceTypeAddrVector devicesTypeAddress = devices.toTypeAddrVector();
            audio_config_base_t clientConfig = client->config();
            audio_config_t config = audio_config_initializer(&clientConfig);
            if (desc != mSpatializerOutput
                    && canBeSpatializedInt(&attr, &config, devicesTypeAddress)) {
                streamsToInvalidate.insert(client->stream());
            }
        }
    }

    for (audio_stream_type_t stream : streamsToInvalidate) {
        mpClientInterface->invalidateStream(stream);
    }
}


bool AudioPolicyManager::isOutputOnlyAvailableRouteToSomeDevice(
        const sp<SwAudioOutputDescriptor>& outputDesc) {
    if (outputDesc->isDuplicated()) {
        return false;
    }
    DeviceVector devices = outputDesc->supportedDevices();
    for (size_t i = 0; i < mOutputs.size(); i++) {
        sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
        if (desc == outputDesc || desc->isDuplicated()) {
            continue;
        }
        DeviceVector sharedDevices = desc->filterSupportedDevices(devices);
        if (!sharedDevices.isEmpty()
                && (desc->devicesSupportEncodedFormats(sharedDevices.types())
                    == outputDesc->devicesSupportEncodedFormats(sharedDevices.types()))) {
            return false;
        }
    }
    return true;
}


status_t AudioPolicyManager::getSpatializerOutput(const audio_config_base_t *mixerConfig,
                                                        const audio_attributes_t *attr,
                                                        audio_io_handle_t *output) {
    *output = AUDIO_IO_HANDLE_NONE;

    DeviceVector devices = mEngine->getOutputDevicesForAttributes(*attr, nullptr, false);
    AudioDeviceTypeAddrVector devicesTypeAddress = devices.toTypeAddrVector();
    audio_config_t *configPtr = nullptr;
    audio_config_t config;
    if (mixerConfig != nullptr) {
        config = audio_config_initializer(mixerConfig);
        configPtr = &config;
    }
    if (!canBeSpatializedInt(attr, configPtr, devicesTypeAddress)) {
        ALOGV("%s provided attributes or mixer config cannot be spatialized", __func__);
        return BAD_VALUE;
    }

    sp<IOProfile> profile =
            getSpatializerOutputProfile(configPtr, devicesTypeAddress);
    if (profile == nullptr) {
        ALOGV("%s no suitable output profile for provided attributes or mixer config", __func__);
        return BAD_VALUE;
    }

    std::vector<sp<SwAudioOutputDescriptor>> spatializerOutputs;
    for (size_t i = 0; i < mOutputs.size(); i++) {
        sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
        if (!desc->isDuplicated()
                && (desc->mFlags & AUDIO_OUTPUT_FLAG_SPATIALIZER) != 0) {
            spatializerOutputs.push_back(desc);
            ALOGV("%s adding opened spatializer Output %d", __func__, desc->mIoHandle);
        }
    }
    mSpatializerOutput.clear();
    bool outputsChanged = false;
    for (const auto& desc : spatializerOutputs) {
        if (desc->mProfile == profile
                && (configPtr == nullptr
                   || configPtr->channel_mask == desc->mMixerChannelMask)) {
            mSpatializerOutput = desc;
            ALOGV("%s reusing current spatializer output %d", __func__, desc->mIoHandle);
        } else {
            ALOGV("%s closing spatializerOutput output %d to match channel mask %#x"
                    " and devices %s", __func__, desc->mIoHandle,
                    configPtr != nullptr ? configPtr->channel_mask : 0,
                    devices.toString().c_str());
            closeOutput(desc->mIoHandle);
            outputsChanged = true;
        }
    }

    if (mSpatializerOutput == nullptr) {
        sp<SwAudioOutputDescriptor> desc =
                openOutputWithProfileAndDevice(profile, devices, mixerConfig);
        if (desc != nullptr) {
            mSpatializerOutput = desc;
            outputsChanged = true;
        }
    }

    checkVirtualizerClientRoutes();

    if (outputsChanged) {
        mPreviousOutputs = mOutputs;
        mpClientInterface->onAudioPortListUpdate();
    }

    if (mSpatializerOutput == nullptr) {
        ALOGV("%s could not open spatializer output with requested config", __func__);
        return BAD_VALUE;
    }
    *output = mSpatializerOutput->mIoHandle;
    ALOGV("%s returning new spatializer output %d", __func__, *output);
    return OK;
}

status_t AudioPolicyManager::releaseSpatializerOutput(audio_io_handle_t output) {
    if (mSpatializerOutput == nullptr) {
        return INVALID_OPERATION;
    }
    if (mSpatializerOutput->mIoHandle != output) {
        return BAD_VALUE;
    }

    if (!isOutputOnlyAvailableRouteToSomeDevice(mSpatializerOutput)) {
        ALOGV("%s closing spatializer output %d", __func__, mSpatializerOutput->mIoHandle);
        closeOutput(mSpatializerOutput->mIoHandle);
        //from now on mSpatializerOutput is null
        checkVirtualizerClientRoutes();
    }

    return NO_ERROR;
}

// ----------------------------------------------------------------------------
// AudioPolicyManager
// ----------------------------------------------------------------------------
uint32_t AudioPolicyManager::nextAudioPortGeneration()
{
    return mAudioPortGeneration++;
}

static status_t deserializeAudioPolicyXmlConfig(AudioPolicyConfig &config) {
    if (std::string audioPolicyXmlConfigFile = audio_get_audio_policy_config_file();
            !audioPolicyXmlConfigFile.empty()) {
        status_t ret = deserializeAudioPolicyFile(audioPolicyXmlConfigFile.c_str(), &config);
        if (ret == NO_ERROR) {
            config.setSource(audioPolicyXmlConfigFile);
        }
        return ret;
    }
    return BAD_VALUE;
}

AudioPolicyManager::AudioPolicyManager(AudioPolicyClientInterface *clientInterface,
                                       bool /*forTesting*/)
    :
    mUidCached(AID_AUDIOSERVER), // no need to call getuid(), there's only one of us running.
    mpClientInterface(clientInterface),
    mLimitRingtoneVolume(false), mLastVoiceVolume(-1.0f),
    mA2dpSuspended(false),
    mConfig(mHwModulesAll, mOutputDevicesAll, mInputDevicesAll, mDefaultOutputDevice),
    mAudioPortGeneration(1),
    mBeaconMuteRefCount(0),
    mBeaconPlayingRefCount(0),
    mBeaconMuted(false),
    mTtsOutputAvailable(false),
    mMasterMono(false),
    mMusicEffectOutput(AUDIO_IO_HANDLE_NONE)
{
}

AudioPolicyManager::AudioPolicyManager(AudioPolicyClientInterface *clientInterface)
        : AudioPolicyManager(clientInterface, false /*forTesting*/)
{
    loadConfig();
}

void AudioPolicyManager::loadConfig() {
    if (deserializeAudioPolicyXmlConfig(getConfig()) != NO_ERROR) {
        ALOGE("could not load audio policy configuration file, setting defaults");
        getConfig().setDefault();
    }
}

status_t AudioPolicyManager::initialize() {
    {
        auto engLib = EngineLibrary::load(
                        "libaudiopolicyengine" + getConfig().getEngineLibraryNameSuffix() + ".so");
        if (!engLib) {
            ALOGE("%s: Failed to load the engine library", __FUNCTION__);
            return NO_INIT;
        }
        mEngine = engLib->createEngine();
        if (mEngine == nullptr) {
            ALOGE("%s: Failed to instantiate the APM engine", __FUNCTION__);
            return NO_INIT;
        }
    }
    mEngine->setObserver(this);
    status_t status = mEngine->initCheck();
    if (status != NO_ERROR) {
        LOG_FATAL("Policy engine not initialized(err=%d)", status);
        return status;
    }

    mEngine->updateDeviceSelectionCache();
    mCommunnicationStrategy = mEngine->getProductStrategyForAttributes(
        mEngine->getAttributesForStreamType(AUDIO_STREAM_VOICE_CALL));

    // after parsing the config, mOutputDevicesAll and mInputDevicesAll contain all known devices;
    // open all output streams needed to access attached devices
    onNewAudioModulesAvailableInt(nullptr /*newDevices*/);

    // make sure default device is reachable
    if (mDefaultOutputDevice == 0 || !mAvailableOutputDevices.contains(mDefaultOutputDevice)) {
        ALOGE_IF(mDefaultOutputDevice != 0, "Default device %s is unreachable",
                 mDefaultOutputDevice->toString().c_str());
        status = NO_INIT;
    }
    // If microphones address is empty, set it according to device type
    for (size_t i = 0; i < mAvailableInputDevices.size(); i++) {
        if (mAvailableInputDevices[i]->address().empty()) {
            if (mAvailableInputDevices[i]->type() == AUDIO_DEVICE_IN_BUILTIN_MIC) {
                mAvailableInputDevices[i]->setAddress(AUDIO_BOTTOM_MICROPHONE_ADDRESS);
            } else if (mAvailableInputDevices[i]->type() == AUDIO_DEVICE_IN_BACK_MIC) {
                mAvailableInputDevices[i]->setAddress(AUDIO_BACK_MICROPHONE_ADDRESS);
            }
        }
    }

    ALOGW_IF(mPrimaryOutput == nullptr, "The policy configuration does not declare a primary output");

    // Silence ALOGV statements
    property_set("log.tag." LOG_TAG, "D");

    updateDevicesAndOutputs();
    return status;
}

AudioPolicyManager::~AudioPolicyManager()
{
   for (size_t i = 0; i < mOutputs.size(); i++) {
        mOutputs.valueAt(i)->close();
   }
   for (size_t i = 0; i < mInputs.size(); i++) {
        mInputs.valueAt(i)->close();
   }
   mAvailableOutputDevices.clear();
   mAvailableInputDevices.clear();
   mOutputs.clear();
   mInputs.clear();
   mHwModules.clear();
   mHwModulesAll.clear();
   mManualSurroundFormats.clear();
}

status_t AudioPolicyManager::initCheck()
{
    return hasPrimaryOutput() ? NO_ERROR : NO_INIT;
}

// ---

void AudioPolicyManager::onNewAudioModulesAvailable()
{
    DeviceVector newDevices;
    onNewAudioModulesAvailableInt(&newDevices);
    if (!newDevices.empty()) {
        nextAudioPortGeneration();
        mpClientInterface->onAudioPortListUpdate();
    }
}

void AudioPolicyManager::onNewAudioModulesAvailableInt(DeviceVector *newDevices)
{
    for (const auto& hwModule : mHwModulesAll) {
        if (std::find(mHwModules.begin(), mHwModules.end(), hwModule) != mHwModules.end()) {
            continue;
        }
        hwModule->setHandle(mpClientInterface->loadHwModule(hwModule->getName()));
        if (hwModule->getHandle() == AUDIO_MODULE_HANDLE_NONE) {
            ALOGW("could not open HW module %s", hwModule->getName());
            continue;
        }
        mHwModules.push_back(hwModule);
        // open all output streams needed to access attached devices.
        // direct outputs are closed immediately after checking the availability of attached devices
        // This also validates mAvailableOutputDevices list
        for (const auto& outProfile : hwModule->getOutputProfiles()) {
            if (!outProfile->canOpenNewIo()) {
                ALOGE("Invalid Output profile max open count %u for profile %s",
                      outProfile->maxOpenCount, outProfile->getTagName().c_str());
                continue;
            }
            if (!outProfile->hasSupportedDevices()) {
                ALOGW("Output profile contains no device on module %s", hwModule->getName());
                continue;
            }
            if ((outProfile->getFlags() & AUDIO_OUTPUT_FLAG_TTS) != 0 ||
                (outProfile->getFlags() & AUDIO_OUTPUT_FLAG_ULTRASOUND) != 0) {
                mTtsOutputAvailable = true;
            }

            const DeviceVector &supportedDevices = outProfile->getSupportedDevices();
            DeviceVector availProfileDevices = supportedDevices.filter(mOutputDevicesAll);
            sp<DeviceDescriptor> supportedDevice = 0;
            if (supportedDevices.contains(mDefaultOutputDevice)) {
                supportedDevice = mDefaultOutputDevice;
            } else {
                // choose first device present in profile's SupportedDevices also part of
                // mAvailableOutputDevices.
                if (availProfileDevices.isEmpty()) {
                    continue;
                }
                supportedDevice = availProfileDevices.itemAt(0);
            }
            if (!mOutputDevicesAll.contains(supportedDevice)) {
                continue;
            }
            sp<SwAudioOutputDescriptor> outputDesc = new SwAudioOutputDescriptor(outProfile,
                                                                                 mpClientInterface);
            audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;
            status_t status = outputDesc->open(nullptr /* halConfig */, nullptr /* mixerConfig */,
                                               DeviceVector(supportedDevice),
                                               AUDIO_STREAM_DEFAULT,
                                               AUDIO_OUTPUT_FLAG_NONE, &output);
            if (status != NO_ERROR) {
                ALOGW("Cannot open output stream for devices %s on hw module %s",
                      supportedDevice->toString().c_str(), hwModule->getName());
                continue;
            }
            for (const auto &device : availProfileDevices) {
                // give a valid ID to an attached device once confirmed it is reachable
                if (!device->isAttached()) {
                    device->attach(hwModule);
                    mAvailableOutputDevices.add(device);
                    device->setEncapsulationInfoFromHal(mpClientInterface);
                    if (newDevices) newDevices->add(device);
                    setEngineDeviceConnectionState(device, AUDIO_POLICY_DEVICE_STATE_AVAILABLE);
                }
            }
            if (mPrimaryOutput == nullptr &&
                    outProfile->getFlags() & AUDIO_OUTPUT_FLAG_PRIMARY) {
                mPrimaryOutput = outputDesc;
            }
            if ((outProfile->getFlags() & AUDIO_OUTPUT_FLAG_DIRECT) != 0) {
                outputDesc->close();
            } else {
                addOutput(output, outputDesc);
                setOutputDevices(outputDesc,
                                 DeviceVector(supportedDevice),
                                 true,
                                 0,
                                 NULL);
            }
        }
        // open input streams needed to access attached devices to validate
        // mAvailableInputDevices list
        for (const auto& inProfile : hwModule->getInputProfiles()) {
            if (!inProfile->canOpenNewIo()) {
                ALOGE("Invalid Input profile max open count %u for profile %s",
                      inProfile->maxOpenCount, inProfile->getTagName().c_str());
                continue;
            }
            if (!inProfile->hasSupportedDevices()) {
                ALOGW("Input profile contains no device on module %s", hwModule->getName());
                continue;
            }
            // chose first device present in profile's SupportedDevices also part of
            // available input devices
            const DeviceVector &supportedDevices = inProfile->getSupportedDevices();
            DeviceVector availProfileDevices = supportedDevices.filter(mInputDevicesAll);
            if (availProfileDevices.isEmpty()) {
                ALOGV("%s: Input device list is empty! for profile %s",
                    __func__, inProfile->getTagName().c_str());
                continue;
            }
            sp<AudioInputDescriptor> inputDesc =
                    new AudioInputDescriptor(inProfile, mpClientInterface);

            audio_io_handle_t input = AUDIO_IO_HANDLE_NONE;
            status_t status = inputDesc->open(nullptr,
                                              availProfileDevices.itemAt(0),
                                              AUDIO_SOURCE_MIC,
                                              AUDIO_INPUT_FLAG_NONE,
                                              &input);
            if (status != NO_ERROR) {
                ALOGW("Cannot open input stream for device %s on hw module %s",
                      availProfileDevices.toString().c_str(),
                      hwModule->getName());
                continue;
            }
            for (const auto &device : availProfileDevices) {
                // give a valid ID to an attached device once confirmed it is reachable
                if (!device->isAttached()) {
                    device->attach(hwModule);
                    device->importAudioPortAndPickAudioProfile(inProfile, true);
                    mAvailableInputDevices.add(device);
                    if (newDevices) newDevices->add(device);
                    setEngineDeviceConnectionState(device, AUDIO_POLICY_DEVICE_STATE_AVAILABLE);
                }
            }
            inputDesc->close();
        }
    }

    // Check if spatializer outputs can be closed until used.
    // mOutputs vector never contains duplicated outputs at this point.
    std::vector<audio_io_handle_t> outputsClosed;
    for (size_t i = 0; i < mOutputs.size(); i++) {
        sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
        if ((desc->mFlags & AUDIO_OUTPUT_FLAG_SPATIALIZER) != 0
                && !isOutputOnlyAvailableRouteToSomeDevice(desc)) {
            outputsClosed.push_back(desc->mIoHandle);
            desc->close();
        }
    }
    for (auto output : outputsClosed) {
        removeOutput(output);
    }
}

void AudioPolicyManager::addOutput(audio_io_handle_t output,
                                   const sp<SwAudioOutputDescriptor>& outputDesc)
{
    mOutputs.add(output, outputDesc);
    applyStreamVolumes(outputDesc, DeviceTypeSet(), 0 /* delayMs */, true /* force */);
    updateMono(output); // update mono status when adding to output list
    selectOutputForMusicEffects();
    nextAudioPortGeneration();
}

void AudioPolicyManager::removeOutput(audio_io_handle_t output)
{
    if (mPrimaryOutput != 0 && mPrimaryOutput == mOutputs.valueFor(output)) {
        ALOGV("%s: removing primary output", __func__);
        mPrimaryOutput = nullptr;
    }
    mOutputs.removeItem(output);
    selectOutputForMusicEffects();
}

void AudioPolicyManager::addInput(audio_io_handle_t input,
                                  const sp<AudioInputDescriptor>& inputDesc)
{
    mInputs.add(input, inputDesc);
    nextAudioPortGeneration();
}

status_t AudioPolicyManager::checkOutputsForDevice(const sp<DeviceDescriptor>& device,
                                                   audio_policy_dev_state_t state,
                                                   SortedVector<audio_io_handle_t>& outputs)
{
    audio_devices_t deviceType = device->type();
    const String8 &address = String8(device->address().c_str());
    sp<SwAudioOutputDescriptor> desc;

    if (audio_device_is_digital(deviceType)) {
        // erase all current sample rates, formats and channel masks
        device->clearAudioProfiles();
    }

    if (state == AUDIO_POLICY_DEVICE_STATE_AVAILABLE) {
        // first call getAudioPort to get the supported attributes from the HAL
        struct audio_port_v7 port = {};
        device->toAudioPort(&port);
        status_t status = mpClientInterface->getAudioPort(&port);
        if (status == NO_ERROR) {
            device->importAudioPort(port);
        }

        // then list already open outputs that can be routed to this device
        for (size_t i = 0; i < mOutputs.size(); i++) {
            desc = mOutputs.valueAt(i);
            if (!desc->isDuplicated() && desc->supportsDevice(device)
                    && desc->devicesSupportEncodedFormats({deviceType})) {
                ALOGV("checkOutputsForDevice(): adding opened output %d on device %s",
                      mOutputs.keyAt(i), device->toString().c_str());
                outputs.add(mOutputs.keyAt(i));
            }
        }
        // then look for output profiles that can be routed to this device
        SortedVector< sp<IOProfile> > profiles;
        for (const auto& hwModule : mHwModules) {
            for (size_t j = 0; j < hwModule->getOutputProfiles().size(); j++) {
                sp<IOProfile> profile = hwModule->getOutputProfiles()[j];
                if (profile->supportsDevice(device)) {
                    profiles.add(profile);
                    ALOGV("checkOutputsForDevice(): adding profile %zu from module %s",
                          j, hwModule->getName());
                }
            }
        }

        ALOGV("  found %zu profiles, %zu outputs", profiles.size(), outputs.size());

        if (profiles.isEmpty() && outputs.isEmpty()) {
            ALOGW("checkOutputsForDevice(): No output available for device %04x", deviceType);
            return BAD_VALUE;
        }

        // open outputs for matching profiles if needed. Direct outputs are also opened to
        // query for dynamic parameters and will be closed later by setDeviceConnectionState()
        for (ssize_t profile_index = 0; profile_index < (ssize_t)profiles.size(); profile_index++) {
            sp<IOProfile> profile = profiles[profile_index];

            // nothing to do if one output is already opened for this profile
            size_t j;
            for (j = 0; j < outputs.size(); j++) {
                desc = mOutputs.valueFor(outputs.itemAt(j));
                if (!desc->isDuplicated() && desc->mProfile == profile) {
                    // matching profile: save the sample rates, format and channel masks supported
                    // by the profile in our device descriptor
                    if (audio_device_is_digital(deviceType)) {
                        device->importAudioPortAndPickAudioProfile(profile);
                    }
                    break;
                }
            }
            if (j != outputs.size()) {
                continue;
            }

            if (!profile->canOpenNewIo()) {
                ALOGW("Max Output number %u already opened for this profile %s",
                      profile->maxOpenCount, profile->getTagName().c_str());
                continue;
            }

            ALOGV("opening output for device %08x with params %s profile %p name %s",
                  deviceType, address.string(), profile.get(), profile->getName().c_str());
            desc = openOutputWithProfileAndDevice(profile, DeviceVector(device));
            audio_io_handle_t output = desc == nullptr ? AUDIO_IO_HANDLE_NONE : desc->mIoHandle;
            if (output == AUDIO_IO_HANDLE_NONE) {
                ALOGW("checkOutputsForDevice() could not open output for device %x", deviceType);
                profiles.removeAt(profile_index);
                profile_index--;
            } else {
                outputs.add(output);
                // Load digital format info only for digital devices
                if (audio_device_is_digital(deviceType)) {
                    // TODO: when getAudioPort is ready, it may not be needed to import the audio
                    // port but just pick audio profile
                    device->importAudioPortAndPickAudioProfile(profile);
                }

                if (device_distinguishes_on_address(deviceType)) {
                    ALOGV("checkOutputsForDevice(): setOutputDevices %s",
                            device->toString().c_str());
                    setOutputDevices(desc, DeviceVector(device), true/*force*/, 0/*delay*/,
                                     NULL/*patch handle*/);
                }
                ALOGV("checkOutputsForDevice(): adding output %d", output);
            }
        }

        if (profiles.isEmpty()) {
            ALOGW("checkOutputsForDevice(): No output available for device %04x", deviceType);
            return BAD_VALUE;
        }
    } else { // Disconnect
        // check if one opened output is not needed any more after disconnecting one device
        for (size_t i = 0; i < mOutputs.size(); i++) {
            desc = mOutputs.valueAt(i);
            if (!desc->isDuplicated()) {
                // exact match on device
                if (device_distinguishes_on_address(deviceType) && desc->supportsDevice(device)
                        && desc->containsSingleDeviceSupportingEncodedFormats(device)) {
                    outputs.add(mOutputs.keyAt(i));
                } else if (!mAvailableOutputDevices.containsAtLeastOne(desc->supportedDevices())) {
                    ALOGV("checkOutputsForDevice(): disconnecting adding output %d",
                            mOutputs.keyAt(i));
                    outputs.add(mOutputs.keyAt(i));
                }
            }
        }
        // Clear any profiles associated with the disconnected device.
        for (const auto& hwModule : mHwModules) {
            for (size_t j = 0; j < hwModule->getOutputProfiles().size(); j++) {
                sp<IOProfile> profile = hwModule->getOutputProfiles()[j];
                if (!profile->supportsDevice(device)) {
                    continue;
                }
                ALOGV("checkOutputsForDevice(): "
                        "clearing direct output profile %zu on module %s",
                        j, hwModule->getName());
                profile->clearAudioProfiles();
                if (!profile->hasDynamicAudioProfile()) {
                    continue;
                }
                // When a device is disconnected, if there is an IOProfile that contains dynamic
                // profiles and supports the disconnected device, call getAudioPort to repopulate
                // the capabilities of the devices that is supported by the IOProfile.
                for (const auto& supportedDevice : profile->getSupportedDevices()) {
                    if (supportedDevice == device ||
                            !mAvailableOutputDevices.contains(supportedDevice)) {
                        continue;
                    }
                    struct audio_port_v7 port;
                    supportedDevice->toAudioPort(&port);
                    status_t status = mpClientInterface->getAudioPort(&port);
                    if (status == NO_ERROR) {
                        supportedDevice->importAudioPort(port);
                    }
                }
            }
        }
    }
    return NO_ERROR;
}

status_t AudioPolicyManager::checkInputsForDevice(const sp<DeviceDescriptor>& device,
                                                  audio_policy_dev_state_t state)
{
    sp<AudioInputDescriptor> desc;

    if (audio_device_is_digital(device->type())) {
        // erase all current sample rates, formats and channel masks
        device->clearAudioProfiles();
    }

    if (state == AUDIO_POLICY_DEVICE_STATE_AVAILABLE) {
        // look for input profiles that can be routed to this device
        SortedVector< sp<IOProfile> > profiles;
        for (const auto& hwModule : mHwModules) {
            for (size_t profile_index = 0;
                 profile_index < hwModule->getInputProfiles().size();
                 profile_index++) {
                sp<IOProfile> profile = hwModule->getInputProfiles()[profile_index];

                if (profile->supportsDevice(device)) {
                    profiles.add(profile);
                    ALOGV("checkInputsForDevice(): adding profile %zu from module %s",
                          profile_index, hwModule->getName());
                }
            }
        }

        if (profiles.isEmpty()) {
            ALOGW("%s: No input profile available for device %s",
                __func__, device->toString().c_str());
            return BAD_VALUE;
        }

        // open inputs for matching profiles if needed. Direct inputs are also opened to
        // query for dynamic parameters and will be closed later by setDeviceConnectionState()
        for (ssize_t profile_index = 0; profile_index < (ssize_t)profiles.size(); profile_index++) {

            sp<IOProfile> profile = profiles[profile_index];

            // nothing to do if one input is already opened for this profile
            size_t input_index;
            for (input_index = 0; input_index < mInputs.size(); input_index++) {
                desc = mInputs.valueAt(input_index);
                if (desc->mProfile == profile) {
                    if (audio_device_is_digital(device->type())) {
                        device->importAudioPortAndPickAudioProfile(profile);
                    }
                    break;
                }
            }
            if (input_index != mInputs.size()) {
                continue;
            }

            if (!profile->canOpenNewIo()) {
                ALOGW("Max Input number %u already opened for this profile %s",
                      profile->maxOpenCount, profile->getTagName().c_str());
                continue;
            }

            desc = new AudioInputDescriptor(profile, mpClientInterface);
            audio_io_handle_t input = AUDIO_IO_HANDLE_NONE;
            status_t status = desc->open(nullptr,
                                         device,
                                         AUDIO_SOURCE_MIC,
                                         AUDIO_INPUT_FLAG_NONE,
                                         &input);

            if (status == NO_ERROR) {
                const String8& address = String8(device->address().c_str());
                if (!address.isEmpty()) {
                    char *param = audio_device_address_to_parameter(device->type(), address);
                    mpClientInterface->setParameters(input, String8(param));
                    free(param);
                }
                updateAudioProfiles(device, input, profile->getAudioProfiles());
                if (!profile->hasValidAudioProfile()) {
                    ALOGW("checkInputsForDevice() direct input missing param");
                    desc->close();
                    input = AUDIO_IO_HANDLE_NONE;
                }

                if (input != AUDIO_IO_HANDLE_NONE) {
                    addInput(input, desc);
                }
            } // endif input != 0

            if (input == AUDIO_IO_HANDLE_NONE) {
                ALOGW("%s could not open input for device %s", __func__,
                       device->toString().c_str());
                profiles.removeAt(profile_index);
                profile_index--;
            } else {
                if (audio_device_is_digital(device->type())) {
                    device->importAudioPortAndPickAudioProfile(profile);
                }
                ALOGV("checkInputsForDevice(): adding input %d", input);
            }
        } // end scan profiles

        if (profiles.isEmpty()) {
            ALOGW("%s: No input available for device %s", __func__,  device->toString().c_str());
            return BAD_VALUE;
        }
    } else {
        // Disconnect
        // Clear any profiles associated with the disconnected device.
        for (const auto& hwModule : mHwModules) {
            for (size_t profile_index = 0;
                 profile_index < hwModule->getInputProfiles().size();
                 profile_index++) {
                sp<IOProfile> profile = hwModule->getInputProfiles()[profile_index];
                if (profile->supportsDevice(device)) {
                    ALOGV("checkInputsForDevice(): clearing direct input profile %zu on module %s",
                            profile_index, hwModule->getName());
                    profile->clearAudioProfiles();
                }
            }
        }
    } // end disconnect

    return NO_ERROR;
}


void AudioPolicyManager::closeOutput(audio_io_handle_t output)
{
    ALOGV("closeOutput(%d)", output);

    sp<SwAudioOutputDescriptor> closingOutput = mOutputs.valueFor(output);
    if (closingOutput == NULL) {
        ALOGW("closeOutput() unknown output %d", output);
        return;
    }
    const bool closingOutputWasActive = closingOutput->isActive();
    mPolicyMixes.closeOutput(closingOutput);

    // look for duplicated outputs connected to the output being removed.
    for (size_t i = 0; i < mOutputs.size(); i++) {
        sp<SwAudioOutputDescriptor> dupOutput = mOutputs.valueAt(i);
        if (dupOutput->isDuplicated() &&
                (dupOutput->mOutput1 == closingOutput || dupOutput->mOutput2 == closingOutput)) {
            sp<SwAudioOutputDescriptor> remainingOutput =
                dupOutput->mOutput1 == closingOutput ? dupOutput->mOutput2 : dupOutput->mOutput1;
            // As all active tracks on duplicated output will be deleted,
            // and as they were also referenced on the other output, the reference
            // count for their stream type must be adjusted accordingly on
            // the other output.
            const bool wasActive = remainingOutput->isActive();
            // Note: no-op on the closing output where all clients has already been set inactive
            dupOutput->setAllClientsInactive();
            // stop() will be a no op if the output is still active but is needed in case all
            // active streams refcounts where cleared above
            if (wasActive) {
                remainingOutput->stop();
            }
            audio_io_handle_t duplicatedOutput = mOutputs.keyAt(i);
            ALOGV("closeOutput() closing also duplicated output %d", duplicatedOutput);

            mpClientInterface->closeOutput(duplicatedOutput);
            removeOutput(duplicatedOutput);
        }
    }

    nextAudioPortGeneration();

    ssize_t index = mAudioPatches.indexOfKey(closingOutput->getPatchHandle());
    if (index >= 0) {
        sp<AudioPatch> patchDesc = mAudioPatches.valueAt(index);
        (void) /*status_t status*/ mpClientInterface->releaseAudioPatch(
                    patchDesc->getAfHandle(), 0);
        mAudioPatches.removeItemsAt(index);
        mpClientInterface->onAudioPatchListUpdate();
    }

    if (closingOutputWasActive) {
        closingOutput->stop();
    }
    closingOutput->close();

    removeOutput(output);
    mPreviousOutputs = mOutputs;
    if (closingOutput == mSpatializerOutput) {
        mSpatializerOutput.clear();
    }

    // MSD patches may have been released to support a non-MSD direct output. Reset MSD patch if
    // no direct outputs are open.
    if (!getMsdAudioOutDevices().isEmpty()) {
        bool directOutputOpen = false;
        for (size_t i = 0; i < mOutputs.size(); i++) {
            if (mOutputs[i]->mFlags & AUDIO_OUTPUT_FLAG_DIRECT) {
                directOutputOpen = true;
                break;
            }
        }
        if (!directOutputOpen) {
            ALOGV("no direct outputs open, reset MSD patches");
            // TODO: The MSD patches to be established here may differ to current MSD patches due to
            // how output devices for patching are resolved. Avoid by caching and reusing the
            // arguments to mEngine->getOutputDevicesForAttributes() when resolving which output
            // devices to patch to. This may be complicated by the fact that devices may become
            // unavailable.
            setMsdOutputPatches();
        }
    }
}

void AudioPolicyManager::closeInput(audio_io_handle_t input)
{
    ALOGV("closeInput(%d)", input);

    sp<AudioInputDescriptor> inputDesc = mInputs.valueFor(input);
    if (inputDesc == NULL) {
        ALOGW("closeInput() unknown input %d", input);
        return;
    }

    nextAudioPortGeneration();

    sp<DeviceDescriptor> device = inputDesc->getDevice();
    ssize_t index = mAudioPatches.indexOfKey(inputDesc->getPatchHandle());
    if (index >= 0) {
        sp<AudioPatch> patchDesc = mAudioPatches.valueAt(index);
        (void) /*status_t status*/ mpClientInterface->releaseAudioPatch(
                    patchDesc->getAfHandle(), 0);
        mAudioPatches.removeItemsAt(index);
        mpClientInterface->onAudioPatchListUpdate();
    }

    inputDesc->close();
    mInputs.removeItem(input);

    DeviceVector primaryInputDevices = availablePrimaryModuleInputDevices();
    if (primaryInputDevices.contains(device) &&
            mInputs.activeInputsCountOnDevices(primaryInputDevices) == 0) {
        mpClientInterface->setSoundTriggerCaptureState(false);
    }
}

SortedVector<audio_io_handle_t> AudioPolicyManager::getOutputsForDevices(
            const DeviceVector &devices,
            const SwAudioOutputCollection& openOutputs)
{
    SortedVector<audio_io_handle_t> outputs;

    ALOGVV("%s() devices %s", __func__, devices.toString().c_str());
    for (size_t i = 0; i < openOutputs.size(); i++) {
        ALOGVV("output %zu isDuplicated=%d device=%s",
                i, openOutputs.valueAt(i)->isDuplicated(),
                openOutputs.valueAt(i)->supportedDevices().toString().c_str());
        if (openOutputs.valueAt(i)->supportsAllDevices(devices)
                && openOutputs.valueAt(i)->devicesSupportEncodedFormats(devices.types())) {
            ALOGVV("%s() found output %d", __func__, openOutputs.keyAt(i));
            outputs.add(openOutputs.keyAt(i));
        }
    }
    return outputs;
}

void AudioPolicyManager::checkForDeviceAndOutputChanges(std::function<bool()> onOutputsChecked)
{
    // checkA2dpSuspend must run before checkOutputForAllStrategies so that A2DP
    // output is suspended before any tracks are moved to it
    checkA2dpSuspend();
    checkOutputForAllStrategies();
    checkSecondaryOutputs();
    if (onOutputsChecked != nullptr && onOutputsChecked()) checkA2dpSuspend();
    updateDevicesAndOutputs();
    if (mHwModules.getModuleFromName(AUDIO_HARDWARE_MODULE_ID_MSD) != 0) {
        // TODO: The MSD patches to be established here may differ to current MSD patches due to how
        // output devices for patching are resolved. Nevertheless, AudioTracks affected by device
        // configuration changes will ultimately be rerouted correctly. We can still avoid
        // unnecessary rerouting by caching and reusing the arguments to
        // mEngine->getOutputDevicesForAttributes() when resolving which output devices to patch to.
        // This may be complicated by the fact that devices may become unavailable.
        setMsdOutputPatches();
    }
    // an event that changed routing likely occurred, inform upper layers
    mpClientInterface->onRoutingUpdated();
}

bool AudioPolicyManager::followsSameRouting(const audio_attributes_t &lAttr,
                                            const audio_attributes_t &rAttr) const
{
    return mEngine->getProductStrategyForAttributes(lAttr) ==
            mEngine->getProductStrategyForAttributes(rAttr);
}

void AudioPolicyManager::checkAudioSourceForAttributes(const audio_attributes_t &attr)
{
    for (size_t i = 0; i < mAudioSources.size(); i++)  {
        sp<SourceClientDescriptor> sourceDesc = mAudioSources.valueAt(i);
        if (sourceDesc != nullptr && followsSameRouting(attr, sourceDesc->attributes())
                && sourceDesc->getPatchHandle() == AUDIO_PATCH_HANDLE_NONE
                && !isCallRxAudioSource(sourceDesc) && !sourceDesc->isInternal()) {
            connectAudioSource(sourceDesc);
        }
    }
}

void AudioPolicyManager::clearAudioSourcesForOutput(audio_io_handle_t output)
{
    for (size_t i = 0; i < mAudioSources.size(); i++)  {
        sp<SourceClientDescriptor> sourceDesc = mAudioSources.valueAt(i);
        if (sourceDesc != nullptr && sourceDesc->swOutput().promote() != nullptr
                && sourceDesc->swOutput().promote()->mIoHandle == output) {
            disconnectAudioSource(sourceDesc);
        }
    }
}

void AudioPolicyManager::checkOutputForAttributes(const audio_attributes_t &attr)
{
    auto psId = mEngine->getProductStrategyForAttributes(attr);

    DeviceVector oldDevices = mEngine->getOutputDevicesForAttributes(attr, 0, true /*fromCache*/);
    DeviceVector newDevices = mEngine->getOutputDevicesForAttributes(attr, 0, false /*fromCache*/);

    SortedVector<audio_io_handle_t> srcOutputs = getOutputsForDevices(oldDevices, mPreviousOutputs);
    SortedVector<audio_io_handle_t> dstOutputs = getOutputsForDevices(newDevices, mOutputs);

    uint32_t maxLatency = 0;
    bool invalidate = false;
    // take into account dynamic audio policies related changes: if a client is now associated
    // to a different policy mix than at creation time, invalidate corresponding stream
    for (size_t i = 0; i < mPreviousOutputs.size() && !invalidate; i++) {
        const sp<SwAudioOutputDescriptor>& desc = mPreviousOutputs.valueAt(i);
        if (desc->isDuplicated()) {
            continue;
        }
        for (const sp<TrackClientDescriptor>& client : desc->getClientIterable()) {
            if (mEngine->getProductStrategyForAttributes(client->attributes()) != psId) {
                continue;
            }
            sp<AudioPolicyMix> primaryMix;
            status_t status = mPolicyMixes.getOutputForAttr(client->attributes(), client->config(),
                    client->uid(), client->flags(), primaryMix, nullptr);
            if (status != OK) {
                continue;
            }
            if (client->getPrimaryMix() != primaryMix || client->hasLostPrimaryMix()) {
                invalidate = true;
                if (desc->isStrategyActive(psId)) {
                    maxLatency = desc->latency();
                }
                break;
            }
        }
    }

    if (srcOutputs != dstOutputs || invalidate) {
        // get maximum latency of all source outputs to determine the minimum mute time guaranteeing
        // audio from invalidated tracks will be rendered when unmuting
        for (audio_io_handle_t srcOut : srcOutputs) {
            sp<SwAudioOutputDescriptor> desc = mPreviousOutputs.valueFor(srcOut);
            if (desc == nullptr) continue;

            if (desc->isStrategyActive(psId) && maxLatency < desc->latency()) {
                maxLatency = desc->latency();
            }

            if (invalidate) continue;

            for (auto client : desc->clientsList(false /*activeOnly*/)) {
                if (desc->isDuplicated() || !desc->mProfile->isDirectOutput()) {
                    // a client on a non direct outputs has necessarily a linear PCM format
                    // so we can call selectOutput() safely
                    const audio_io_handle_t newOutput = selectOutput(dstOutputs,
                                                                     client->flags(),
                                                                     client->config().format,
                                                                     client->config().channel_mask,
                                                                     client->config().sample_rate,
                                                                     client->session());
                    if (newOutput != srcOut) {
                        invalidate = true;
                        break;
                    }
                } else {
                    sp<IOProfile> profile = getProfileForOutput(newDevices,
                                   client->config().sample_rate,
                                   client->config().format,
                                   client->config().channel_mask,
                                   client->flags(),
                                   true /* directOnly */);
                    if (profile != desc->mProfile) {
                        invalidate = true;
                        break;
                    }
                }
            }
        }

        ALOGV_IF(!(srcOutputs.isEmpty() || dstOutputs.isEmpty()),
              "%s: strategy %d, moving from output %s to output %s", __func__, psId,
              std::to_string(srcOutputs[0]).c_str(),
              std::to_string(dstOutputs[0]).c_str());
        // mute strategy while moving tracks from one output to another
        for (audio_io_handle_t srcOut : srcOutputs) {
            sp<SwAudioOutputDescriptor> desc = mPreviousOutputs.valueFor(srcOut);
            if (desc == nullptr) continue;

            if (desc->isStrategyActive(psId)) {
                setStrategyMute(psId, true, desc);
                setStrategyMute(psId, false, desc, maxLatency * LATENCY_MUTE_FACTOR,
                                newDevices.types());
            }
            sp<SourceClientDescriptor> source = getSourceForAttributesOnOutput(srcOut, attr);
            if (source != nullptr && !isCallRxAudioSource(source) && !source->isInternal()) {
                connectAudioSource(source);
            }
        }

        // Move effects associated to this stream from previous output to new output
        if (followsSameRouting(attr, attributes_initializer(AUDIO_USAGE_MEDIA))) {
            selectOutputForMusicEffects();
        }
        // Move tracks associated to this stream (and linked) from previous output to new output
        if (invalidate) {
            for (auto stream :  mEngine->getStreamTypesForProductStrategy(psId)) {
                mpClientInterface->invalidateStream(stream);
            }
            for (audio_io_handle_t srcOut : srcOutputs) {
                sp<SwAudioOutputDescriptor> desc = mPreviousOutputs.valueFor(srcOut);
                if (desc == nullptr) continue;

                desc->setTracksInvalidatedStatusByStrategy(psId);
            }
        }
    }
}

void AudioPolicyManager::checkOutputForAllStrategies()
{
    for (const auto &strategy : mEngine->getOrderedProductStrategies()) {
        auto attributes = mEngine->getAllAttributesForProductStrategy(strategy).front();
        checkOutputForAttributes(attributes);
        checkAudioSourceForAttributes(attributes);
    }
}

void AudioPolicyManager::checkSecondaryOutputs() {
    std::set<audio_stream_type_t> streamsToInvalidate;
    TrackSecondaryOutputsMap trackSecondaryOutputs;
    for (size_t i = 0; i < mOutputs.size(); i++) {
        const sp<SwAudioOutputDescriptor>& outputDescriptor = mOutputs[i];
        for (const sp<TrackClientDescriptor>& client : outputDescriptor->getClientIterable()) {
            sp<AudioPolicyMix> primaryMix;
            std::vector<sp<AudioPolicyMix>> secondaryMixes;
            status_t status = mPolicyMixes.getOutputForAttr(client->attributes(), client->config(),
                    client->uid(), client->flags(), primaryMix, &secondaryMixes);
            std::vector<sp<SwAudioOutputDescriptor>> secondaryDescs;
            for (auto &secondaryMix : secondaryMixes) {
                sp<SwAudioOutputDescriptor> outputDesc = secondaryMix->getOutput();
                if (outputDesc != nullptr &&
                    outputDesc->mIoHandle != AUDIO_IO_HANDLE_NONE) {
                    secondaryDescs.push_back(outputDesc);
                }
            }

            if (status != OK) {
                streamsToInvalidate.insert(client->stream());
            } else if (!std::equal(
                    client->getSecondaryOutputs().begin(),
                    client->getSecondaryOutputs().end(),
                    secondaryDescs.begin(), secondaryDescs.end())) {
                if (!audio_is_linear_pcm(client->config().format)) {
                    // If the format is not PCM, the tracks should be invalidated to get correct
                    // behavior when the secondary output is changed.
                    streamsToInvalidate.insert(client->stream());
                } else {
                    std::vector<wp<SwAudioOutputDescriptor>> weakSecondaryDescs;
                    std::vector<audio_io_handle_t> secondaryOutputIds;
                    for (const auto &secondaryDesc: secondaryDescs) {
                        secondaryOutputIds.push_back(secondaryDesc->mIoHandle);
                        weakSecondaryDescs.push_back(secondaryDesc);
                    }
                    trackSecondaryOutputs.emplace(client->portId(), secondaryOutputIds);
                    client->setSecondaryOutputs(std::move(weakSecondaryDescs));
                }
            }
        }
    }
    if (!trackSecondaryOutputs.empty()) {
        mpClientInterface->updateSecondaryOutputs(trackSecondaryOutputs);
    }
    for (audio_stream_type_t stream : streamsToInvalidate) {
        ALOGD("%s Invalidate stream %d due to fail getting output for attr", __func__, stream);
        mpClientInterface->invalidateStream(stream);
    }
}

bool AudioPolicyManager::isScoRequestedForComm() const {
    AudioDeviceTypeAddrVector devices;
    mEngine->getDevicesForRoleAndStrategy(mCommunnicationStrategy, DEVICE_ROLE_PREFERRED, devices);
    for (const auto &device : devices) {
        if (audio_is_bluetooth_out_sco_device(device.mType)) {
            return true;
        }
    }
    return false;
}

bool AudioPolicyManager::isHearingAidUsedForComm() const {
    DeviceVector devices = mEngine->getOutputDevicesForStream(AUDIO_STREAM_VOICE_CALL,
                                                       true /*fromCache*/);
    for (const auto &device : devices) {
        if (device->type() == AUDIO_DEVICE_OUT_HEARING_AID) {
            return true;
        }
    }
    return false;
}


void AudioPolicyManager::checkA2dpSuspend()
{
    audio_io_handle_t a2dpOutput = mOutputs.getA2dpOutput();
    if (a2dpOutput == 0 || mOutputs.isA2dpOffloadedOnPrimary()) {
        mA2dpSuspended = false;
        return;
    }

    bool isScoConnected =
            (mAvailableInputDevices.types().count(AUDIO_DEVICE_IN_BLUETOOTH_SCO_HEADSET) != 0 ||
             !Intersection(mAvailableOutputDevices.types(), getAudioDeviceOutAllScoSet()).empty());
    bool isScoRequested = isScoRequestedForComm();

    // if suspended, restore A2DP output if:
    //      ((SCO device is NOT connected) ||
    //       ((SCO is not requested) &&
    //        (phone state is NOT in call) && (phone state is NOT ringing)))
    //
    // if not suspended, suspend A2DP output if:
    //      (SCO device is connected) &&
    //       ((SCO is requested) ||
    //       ((phone state is in call) || (phone state is ringing)))
    //
    if (mA2dpSuspended) {
        if (!isScoConnected ||
             (!isScoRequested &&
              (mEngine->getPhoneState() != AUDIO_MODE_IN_CALL) &&
              (mEngine->getPhoneState() != AUDIO_MODE_RINGTONE))) {

            mpClientInterface->restoreOutput(a2dpOutput);
            mA2dpSuspended = false;
        }
    } else {
        if (isScoConnected &&
             (isScoRequested ||
              (mEngine->getPhoneState() == AUDIO_MODE_IN_CALL) ||
              (mEngine->getPhoneState() == AUDIO_MODE_RINGTONE))) {

            mpClientInterface->suspendOutput(a2dpOutput);
            mA2dpSuspended = true;
        }
    }
}

DeviceVector AudioPolicyManager::getNewOutputDevices(const sp<SwAudioOutputDescriptor>& outputDesc,
                                                     bool fromCache)
{
    DeviceVector devices;

    ssize_t index = mAudioPatches.indexOfKey(outputDesc->getPatchHandle());
    if (index >= 0) {
        sp<AudioPatch> patchDesc = mAudioPatches.valueAt(index);
        if (patchDesc->getUid() != mUidCached) {
            ALOGV("%s device %s forced by patch %d", __func__,
                  outputDesc->devices().toString().c_str(), outputDesc->getPatchHandle());
            return  outputDesc->devices();
        }
    }

    // Do not retrieve engine device for outputs through MSD
    // TODO: support explicit routing requests by resetting MSD patch to engine device.
    if (outputDesc->devices() == getMsdAudioOutDevices()) {
        return outputDesc->devices();
    }

    // Honor explicit routing requests only if no client using default routing is active on this
    // input: a specific app can not force routing for other apps by setting a preferred device.
    bool active; // unused
    sp<DeviceDescriptor> device =
        findPreferredDevice(outputDesc, PRODUCT_STRATEGY_NONE, active, mAvailableOutputDevices);
    if (device != nullptr) {
        return DeviceVector(device);
    }

    // Legacy Engine cannot take care of bus devices and mix, so we need to handle the conflict
    // of setForceUse / Default Bus device here
    device = mPolicyMixes.getDeviceAndMixForOutput(outputDesc, mAvailableOutputDevices);
    if (device != nullptr) {
        return DeviceVector(device);
    }

    for (const auto &productStrategy : mEngine->getOrderedProductStrategies()) {
        StreamTypeVector streams = mEngine->getStreamTypesForProductStrategy(productStrategy);
        auto attr = mEngine->getAllAttributesForProductStrategy(productStrategy).front();
        auto hasStreamActive = [&](auto stream) {
            return hasStream(streams, stream) && isStreamActive(stream, 0);
        };

        auto doGetOutputDevicesForVoice = [&]() {
            return hasVoiceStream(streams) && (outputDesc == mPrimaryOutput ||
                outputDesc->isActive(toVolumeSource(AUDIO_STREAM_VOICE_CALL, false))) &&
                (isInCall() ||
                 mOutputs.isStrategyActiveOnSameModule(productStrategy, outputDesc)) &&
                !isStreamActive(AUDIO_STREAM_ENFORCED_AUDIBLE, 0);
        };

        // With low-latency playing on speaker, music on WFD, when the first low-latency
        // output is stopped, getNewOutputDevices checks for a product strategy
        // from the list, as STRATEGY_SONIFICATION comes prior to STRATEGY_MEDIA.
        // If an ALARM or ENFORCED_AUDIBLE stream is supported by the product strategy,
        // devices are returned for STRATEGY_SONIFICATION without checking whether the
        // stream is associated to the output descriptor.
        if (doGetOutputDevicesForVoice() || outputDesc->isStrategyActive(productStrategy) ||
               ((hasStreamActive(AUDIO_STREAM_ALARM) ||
                hasStreamActive(AUDIO_STREAM_ENFORCED_AUDIBLE)) &&
                mOutputs.isStrategyActiveOnSameModule(productStrategy, outputDesc))) {
            // Retrieval of devices for voice DL is done on primary output profile, cannot
            // check the route (would force modifying configuration file for this profile)
            devices = mEngine->getOutputDevicesForAttributes(attr, nullptr, fromCache);
            break;
        }
    }
    ALOGV("%s selected devices %s", __func__, devices.toString().c_str());
    return devices;
}

sp<DeviceDescriptor> AudioPolicyManager::getNewInputDevice(
        const sp<AudioInputDescriptor>& inputDesc)
{
    sp<DeviceDescriptor> device;

    ssize_t index = mAudioPatches.indexOfKey(inputDesc->getPatchHandle());
    if (index >= 0) {
        sp<AudioPatch> patchDesc = mAudioPatches.valueAt(index);
        if (patchDesc->getUid() != mUidCached) {
            ALOGV("getNewInputDevice() device %s forced by patch %d",
                  inputDesc->getDevice()->toString().c_str(), inputDesc->getPatchHandle());
            return inputDesc->getDevice();
        }
    }

    // Honor explicit routing requests only if no client using default routing is active on this
    // input: a specific app can not force routing for other apps by setting a preferred device.
    bool active;
    device = findPreferredDevice(inputDesc, AUDIO_SOURCE_DEFAULT, active, mAvailableInputDevices);
    if (device != nullptr) {
        return device;
    }

    // If we are not in call and no client is active on this input, this methods returns
    // a null sp<>, causing the patch on the input stream to be released.
    audio_attributes_t attributes;
    uid_t uid;
    sp<RecordClientDescriptor> topClient = inputDesc->getHighestPriorityClient();
    if (topClient != nullptr) {
        attributes = topClient->attributes();
        uid = topClient->uid();
    } else {
        attributes = { .source = AUDIO_SOURCE_DEFAULT };
        uid = 0;
    }

    if (attributes.source == AUDIO_SOURCE_DEFAULT && isInCall()) {
        attributes.source = AUDIO_SOURCE_VOICE_COMMUNICATION;
    }
    if (attributes.source != AUDIO_SOURCE_DEFAULT) {
        device = mEngine->getInputDeviceForAttributes(attributes, uid);
    }

    return device;
}

bool AudioPolicyManager::streamsMatchForvolume(audio_stream_type_t stream1,
                                               audio_stream_type_t stream2) {
    return (stream1 == stream2);
}

// TODO - consider MSD routes b/214971780
status_t AudioPolicyManager::getDevicesForAttributes(
        const audio_attributes_t &attr, AudioDeviceTypeAddrVector *devices, bool forVolume) {
    if (devices == nullptr) {
        return BAD_VALUE;
    }

    // Devices are determined in the following precedence:
    //
    // 1) Devices associated with a dynamic policy matching the attributes.  This is often
    //    a remote submix from MIX_ROUTE_FLAG_LOOP_BACK.
    //
    // If no such dynamic policy then
    // 2) Devices containing an active client using setPreferredDevice
    //    with same strategy as the attributes.
    //    (from the default Engine::getOutputDevicesForAttributes() implementation).
    //
    // If no corresponding active client with setPreferredDevice then
    // 3) Devices associated with the strategy determined by the attributes
    //    (from the default Engine::getOutputDevicesForAttributes() implementation).
    //
    // See related getOutputForAttrInt().

    // check dynamic policies but only for primary descriptors (secondary not used for audible
    // audio routing, only used for duplication for playback capture)
    sp<AudioPolicyMix> policyMix;
    status_t status = mPolicyMixes.getOutputForAttr(attr, AUDIO_CONFIG_BASE_INITIALIZER,
            0 /*uid unknown here*/, AUDIO_OUTPUT_FLAG_NONE, policyMix, nullptr);
    if (status != OK) {
        return status;
    }

    DeviceVector curDevices;
    if (policyMix != nullptr && policyMix->getOutput() != nullptr &&
            // For volume control, skip LOOPBACK mixes which use AUDIO_DEVICE_OUT_REMOTE_SUBMIX
            // as they are unaffected by device/stream volume
            // (per SwAudioOutputDescriptor::isFixedVolume()).
            (!forVolume || policyMix->mDeviceType != AUDIO_DEVICE_OUT_REMOTE_SUBMIX)
            ) {
        sp<DeviceDescriptor> deviceDesc = mAvailableOutputDevices.getDevice(
                policyMix->mDeviceType, policyMix->mDeviceAddress, AUDIO_FORMAT_DEFAULT);
        curDevices.add(deviceDesc);
    } else {
        // The default Engine::getOutputDevicesForAttributes() uses findPreferredDevice()
        // which selects setPreferredDevice if active.  This means forVolume call
        // will take an active setPreferredDevice, if such exists.

        curDevices = mEngine->getOutputDevicesForAttributes(
                attr, nullptr /* preferredDevice */, false /* fromCache */);
    }

    if (forVolume) {
        // We alias the device AUDIO_DEVICE_OUT_SPEAKER_SAFE to AUDIO_DEVICE_OUT_SPEAKER
        // for single volume control in AudioService (such relationship should exist if
        // SPEAKER_SAFE is present).
        //
        // (This is unrelated to a different device grouping as Volume::getDeviceCategory)
        DeviceVector speakerSafeDevices =
                curDevices.getDevicesFromType(AUDIO_DEVICE_OUT_SPEAKER_SAFE);
        if (!speakerSafeDevices.isEmpty()) {
            curDevices.merge(
                    mAvailableOutputDevices.getDevicesFromType(AUDIO_DEVICE_OUT_SPEAKER));
            curDevices.remove(speakerSafeDevices);
        }
    }
    for (const auto& device : curDevices) {
        devices->push_back(device->getDeviceTypeAddr());
    }
    return NO_ERROR;
}

void AudioPolicyManager::handleNotificationRoutingForStream(audio_stream_type_t stream) {
    switch(stream) {
    case AUDIO_STREAM_MUSIC:
        checkOutputForAttributes(attributes_initializer(AUDIO_USAGE_NOTIFICATION));
        updateDevicesAndOutputs();
        break;
    default:
        break;
    }
}

uint32_t AudioPolicyManager::handleEventForBeacon(int event) {

    // skip beacon mute management if a dedicated TTS output is available
    if (mTtsOutputAvailable) {
        return 0;
    }

    switch(event) {
    case STARTING_OUTPUT:
        mBeaconMuteRefCount++;
        break;
    case STOPPING_OUTPUT:
        if (mBeaconMuteRefCount > 0) {
            mBeaconMuteRefCount--;
        }
        break;
    case STARTING_BEACON:
        mBeaconPlayingRefCount++;
        break;
    case STOPPING_BEACON:
        if (mBeaconPlayingRefCount > 0) {
            mBeaconPlayingRefCount--;
        }
        break;
    }

    if (mBeaconMuteRefCount > 0) {
        // any playback causes beacon to be muted
        return setBeaconMute(true);
    } else {
        // no other playback: unmute when beacon starts playing, mute when it stops
        return setBeaconMute(mBeaconPlayingRefCount == 0);
    }
}

uint32_t AudioPolicyManager::setBeaconMute(bool mute) {
    ALOGV("setBeaconMute(%d) mBeaconMuteRefCount=%d mBeaconPlayingRefCount=%d",
            mute, mBeaconMuteRefCount, mBeaconPlayingRefCount);
    // keep track of muted state to avoid repeating mute/unmute operations
    if (mBeaconMuted != mute) {
        // mute/unmute AUDIO_STREAM_TTS on all outputs
        ALOGV("\t muting %d", mute);
        uint32_t maxLatency = 0;
        auto ttsVolumeSource = toVolumeSource(AUDIO_STREAM_TTS, false);
        if (ttsVolumeSource == VOLUME_SOURCE_NONE) {
            ALOGV("\t no tts volume source available");
            return 0;
        }
        for (size_t i = 0; i < mOutputs.size(); i++) {
            sp<SwAudioOutputDescriptor> desc = mOutputs.valueAt(i);
            setVolumeSourceMute(ttsVolumeSource, mute/*on*/, desc, 0 /*delay*/, DeviceTypeSet());
            const uint32_t latency = desc->latency() * 2;
            if (desc->isActive(latency * 2) && latency > maxLatency) {
                maxLatency = latency;
            }
        }
        mBeaconMuted = mute;
        return maxLatency;
    }
    return 0;
}

void AudioPolicyManager::updateDevicesAndOutputs()
{
    mEngine->updateDeviceSelectionCache();
    mPreviousOutputs = mOutputs;
}

uint32_t AudioPolicyManager::checkDeviceMuteStrategies(const sp<AudioOutputDescriptor>& outputDesc,
                                                       const DeviceVector &prevDevices,
                                                       uint32_t delayMs)
{
    // mute/unmute strategies using an incompatible device combination
    // if muting, wait for the audio in pcm buffer to be drained before proceeding
    // if unmuting, unmute only after the specified delay
    if (outputDesc->isDuplicated()) {
        return 0;
    }

    uint32_t muteWaitMs = 0;
    DeviceVector devices = outputDesc->devices();
    bool shouldMute = outputDesc->isActive() && (devices.size() >= 2);

    auto productStrategies = mEngine->getOrderedProductStrategies();
    for (const auto &productStrategy : productStrategies) {
        auto attributes = mEngine->getAllAttributesForProductStrategy(productStrategy).front();
        DeviceVector curDevices =
                mEngine->getOutputDevicesForAttributes(attributes, nullptr, false/*fromCache*/);
        curDevices = curDevices.filter(outputDesc->supportedDevices());
        bool mute = shouldMute && curDevices.containsAtLeastOne(devices) && curDevices != devices;
        bool doMute = false;

        if (mute && !outputDesc->isStrategyMutedByDevice(productStrategy)) {
            doMute = true;
            outputDesc->setStrategyMutedByDevice(productStrategy, true);
        } else if (!mute && outputDesc->isStrategyMutedByDevice(productStrategy)) {
            doMute = true;
            outputDesc->setStrategyMutedByDevice(productStrategy, false);
        }
        if (doMute) {
            for (size_t j = 0; j < mOutputs.size(); j++) {
                sp<AudioOutputDescriptor> desc = mOutputs.valueAt(j);
                // skip output if it does not share any device with current output
                if (!desc->supportedDevices().containsAtLeastOne(outputDesc->supportedDevices())) {
                    continue;
                }
                ALOGVV("%s() %s (curDevice %s)", __func__,
                      mute ? "muting" : "unmuting", curDevices.toString().c_str());
                setStrategyMute(productStrategy, mute, desc, mute ? 0 : delayMs);
                if (desc->isStrategyActive(productStrategy)) {
                    if (mute) {
                        // FIXME: should not need to double latency if volume could be applied
                        // immediately by the audioflinger mixer. We must account for the delay
                        // between now and the next time the audioflinger thread for this output
                        // will process a buffer (which corresponds to one buffer size,
                        // usually 1/2 or 1/4 of the latency).
                        if (muteWaitMs < desc->latency() * 2) {
                            muteWaitMs = desc->latency() * 2;
                        }
                    }
                }
            }
        }
    }

    // temporary mute output if device selection changes to avoid volume bursts due to
    // different per device volumes
    if (outputDesc->isActive() && (devices != prevDevices)) {
        uint32_t tempMuteWaitMs = outputDesc->latency() * 2;

        if (muteWaitMs < tempMuteWaitMs) {
            muteWaitMs = tempMuteWaitMs;
        }

        // If recommended duration is defined, replace temporary mute duration to avoid
        // truncated notifications at beginning, which depends on duration of changing path in HAL.
        // Otherwise, temporary mute duration is conservatively set to 4 times the reported latency.
        uint32_t tempRecommendedMuteDuration = outputDesc->getRecommendedMuteDurationMs();
        uint32_t tempMuteDurationMs = tempRecommendedMuteDuration > 0 ?
                tempRecommendedMuteDuration : outputDesc->latency() * 4;

        for (const auto &activeVs : outputDesc->getActiveVolumeSources()) {
            // make sure that we do not start the temporary mute period too early in case of
            // delayed device change
            setVolumeSourceMute(activeVs, true, outputDesc, delayMs);
            setVolumeSourceMute(activeVs, false, outputDesc, delayMs + tempMuteDurationMs,
                                devices.types());
        }
    }

    // wait for the PCM output buffers to empty before proceeding with the rest of the command
    if (muteWaitMs > delayMs) {
        muteWaitMs -= delayMs;
        usleep(muteWaitMs * 1000);
        return muteWaitMs;
    }
    return 0;
}

uint32_t AudioPolicyManager::setOutputDevices(const sp<SwAudioOutputDescriptor>& outputDesc,
                                              const DeviceVector &devices,
                                              bool force,
                                              int delayMs,
                                              audio_patch_handle_t *patchHandle,
                                              bool requiresMuteCheck, bool requiresVolumeCheck)
{
    ALOGV("%s device %s delayMs %d", __func__, devices.toString().c_str(), delayMs);
    uint32_t muteWaitMs;

    if (outputDesc->isDuplicated()) {
        muteWaitMs = setOutputDevices(outputDesc->subOutput1(), devices, force, delayMs,
                nullptr /* patchHandle */, requiresMuteCheck);
        muteWaitMs += setOutputDevices(outputDesc->subOutput2(), devices, force, delayMs,
                nullptr /* patchHandle */, requiresMuteCheck);
        return muteWaitMs;
    }

    // filter devices according to output selected
    DeviceVector filteredDevices = outputDesc->filterSupportedDevices(devices);
    DeviceVector prevDevices = outputDesc->devices();
    DeviceVector availPrevDevices = mAvailableOutputDevices.filter(prevDevices);

    ALOGV("setOutputDevices() prevDevice %s", prevDevices.toString().c_str());

    if (!filteredDevices.isEmpty()) {
        outputDesc->setDevices(filteredDevices);
    }

    // if the outputs are not materially active, there is no need to mute.
    if (requiresMuteCheck) {
        muteWaitMs = checkDeviceMuteStrategies(outputDesc, prevDevices, delayMs);
    } else {
        ALOGV("%s: suppressing checkDeviceMuteStrategies", __func__);
        muteWaitMs = 0;
    }

    bool outputRouted = outputDesc->isRouted();

    // no need to proceed if new device is not AUDIO_DEVICE_NONE and not supported by current
    // output profile or if new device is not supported AND previous device(s) is(are) still
    // available (otherwise reset device must be done on the output)
    if (!devices.isEmpty() && filteredDevices.isEmpty() && !availPrevDevices.empty()) {
        ALOGV("%s: unsupported device %s for output", __func__, devices.toString().c_str());
        // restore previous device after evaluating strategy mute state
        outputDesc->setDevices(prevDevices);
        return muteWaitMs;
    }

    // Do not change the routing if:
    //      the requested device is AUDIO_DEVICE_NONE
    //      OR the requested device is the same as current device
    //  AND force is not specified
    //  AND the output is connected by a valid audio patch.
    // Doing this check here allows the caller to call setOutputDevices() without conditions
    if ((filteredDevices.isEmpty() || filteredDevices == prevDevices) && !force && outputRouted) {
        ALOGV("%s setting same device %s or null device, force=%d, patch handle=%d", __func__,
              filteredDevices.toString().c_str(), force, outputDesc->getPatchHandle());
        if (requiresVolumeCheck && !filteredDevices.isEmpty()) {
            ALOGV("%s setting same device on routed output, force apply volumes", __func__);
            applyStreamVolumes(outputDesc, filteredDevices.types(), delayMs, true /*force*/);
        }
        return muteWaitMs;
    }

    ALOGV("%s changing device to %s", __func__, filteredDevices.toString().c_str());

    // do the routing
    if (filteredDevices.isEmpty() || mAvailableOutputDevices.filter(filteredDevices).empty()) {
        resetOutputDevice(outputDesc, delayMs, NULL);
    } else {
        PatchBuilder patchBuilder;
        patchBuilder.addSource(outputDesc);
        ALOG_ASSERT(filteredDevices.size() <= AUDIO_PATCH_PORTS_MAX, "Too many sink ports");
        for (const auto &filteredDevice : filteredDevices) {
            patchBuilder.addSink(filteredDevice);
        }

        // Add half reported latency to delayMs when muteWaitMs is null in order
        // to avoid disordered sequence of muting volume and changing devices.
        installPatch(__func__, patchHandle, outputDesc.get(), patchBuilder.patch(),
                muteWaitMs == 0 ? (delayMs + (outputDesc->latency() / 2)) : delayMs);
    }

    // update stream volumes according to new device
    applyStreamVolumes(outputDesc, filteredDevices.types(), delayMs);

    return muteWaitMs;
}

status_t AudioPolicyManager::resetOutputDevice(const sp<AudioOutputDescriptor>& outputDesc,
                                               int delayMs,
                                               audio_patch_handle_t *patchHandle)
{
    ssize_t index;
    if (patchHandle == nullptr && !outputDesc->isRouted()) {
        return INVALID_OPERATION;
    }
    if (patchHandle) {
        index = mAudioPatches.indexOfKey(*patchHandle);
    } else {
        index = mAudioPatches.indexOfKey(outputDesc->getPatchHandle());
    }
    if (index < 0) {
        return INVALID_OPERATION;
    }
    sp< AudioPatch> patchDesc = mAudioPatches.valueAt(index);
    status_t status = mpClientInterface->releaseAudioPatch(patchDesc->getAfHandle(), delayMs);
    ALOGV("resetOutputDevice() releaseAudioPatch returned %d", status);
    outputDesc->setPatchHandle(AUDIO_PATCH_HANDLE_NONE);
    removeAudioPatch(patchDesc->getHandle());
    nextAudioPortGeneration();
    mpClientInterface->onAudioPatchListUpdate();
    return status;
}

status_t AudioPolicyManager::setInputDevice(audio_io_handle_t input,
                                            const sp<DeviceDescriptor> &device,
                                            bool force,
                                            audio_patch_handle_t *patchHandle)
{
    status_t status = NO_ERROR;

    sp<AudioInputDescriptor> inputDesc = mInputs.valueFor(input);
    if ((device != nullptr) && ((device != inputDesc->getDevice()) || force)) {
        inputDesc->setDevice(device);

        if (mAvailableInputDevices.contains(device)) {
            PatchBuilder patchBuilder;
            patchBuilder.addSink(inputDesc,
            // AUDIO_SOURCE_HOTWORD is for internal use only:
            // handled as AUDIO_SOURCE_VOICE_RECOGNITION by the audio HAL
                    [inputDesc](const PatchBuilder::mix_usecase_t& usecase) {
                        auto result = usecase;
                        if (result.source == AUDIO_SOURCE_HOTWORD && !inputDesc->isSoundTrigger()) {
                            result.source = AUDIO_SOURCE_VOICE_RECOGNITION;
                        }
                        return result; }).
            //only one input device for now
                    addSource(device);
            status = installPatch(__func__, patchHandle, inputDesc.get(), patchBuilder.patch(), 0);
        }
    }
    return status;
}

status_t AudioPolicyManager::resetInputDevice(audio_io_handle_t input,
                                              audio_patch_handle_t *patchHandle)
{
    sp<AudioInputDescriptor> inputDesc = mInputs.valueFor(input);
    ssize_t index;
    if (patchHandle) {
        index = mAudioPatches.indexOfKey(*patchHandle);
    } else {
        index = mAudioPatches.indexOfKey(inputDesc->getPatchHandle());
    }
    if (index < 0) {
        return INVALID_OPERATION;
    }
    sp< AudioPatch> patchDesc = mAudioPatches.valueAt(index);
    status_t status = mpClientInterface->releaseAudioPatch(patchDesc->getAfHandle(), 0);
    ALOGV("resetInputDevice() releaseAudioPatch returned %d", status);
    inputDesc->setPatchHandle(AUDIO_PATCH_HANDLE_NONE);
    removeAudioPatch(patchDesc->getHandle());
    nextAudioPortGeneration();
    mpClientInterface->onAudioPatchListUpdate();
    return status;
}

sp<IOProfile> AudioPolicyManager::getInputProfile(const sp<DeviceDescriptor> &device,
                                                  uint32_t& samplingRate,
                                                  audio_format_t& format,
                                                  audio_channel_mask_t& channelMask,
                                                  audio_input_flags_t flags)
{
    // Choose an input profile based on the requested capture parameters: select the first available
    // profile supporting all requested parameters.
    //
    // TODO: perhaps isCompatibleProfile should return a "matching" score so we can return
    // the best matching profile, not the first one.

    sp<IOProfile> firstInexact;
    uint32_t updatedSamplingRate = 0;
    audio_format_t updatedFormat = AUDIO_FORMAT_INVALID;
    audio_channel_mask_t updatedChannelMask = AUDIO_CHANNEL_INVALID;
    for (const auto& hwModule : mHwModules) {
        for (const auto& profile : hwModule->getInputProfiles()) {
            // profile->log();
            //updatedFormat = format;
            if (profile->isCompatibleProfile(DeviceVector(device), samplingRate,
                                             &samplingRate  /*updatedSamplingRate*/,
                                             format,
                                             &format,       /*updatedFormat*/
                                             channelMask,
                                             &channelMask   /*updatedChannelMask*/,
                                             // FIXME ugly cast
                                             (audio_output_flags_t) flags,
                                             true /*exactMatchRequiredForInputFlags*/)) {
                return profile;
            }
            if (firstInexact == nullptr && profile->isCompatibleProfile(DeviceVector(device),
                                             samplingRate,
                                             &updatedSamplingRate,
                                             format,
                                             &updatedFormat,
                                             channelMask,
                                             &updatedChannelMask,
                                             // FIXME ugly cast
                                             (audio_output_flags_t) flags,
                                             false /*exactMatchRequiredForInputFlags*/)) {
                firstInexact = profile;
            }

        }
    }
    if (firstInexact != nullptr) {
        samplingRate = updatedSamplingRate;
        format = updatedFormat;
        channelMask = updatedChannelMask;
        return firstInexact;
    }
    return NULL;
}

float AudioPolicyManager::computeVolume(IVolumeCurves &curves,
                                        VolumeSource volumeSource,
                                        int index,
                                        const DeviceTypeSet& deviceTypes)
{
    float volumeDb = curves.volIndexToDb(Volume::getDeviceCategory(deviceTypes), index);

    // handle the case of accessibility active while a ringtone is playing: if the ringtone is much
    // louder than the accessibility prompt, the prompt cannot be heard, thus masking the touch
    // exploration of the dialer UI. In this situation, bring the accessibility volume closer to
    // the ringtone volume
    const auto callVolumeSrc = toVolumeSource(AUDIO_STREAM_VOICE_CALL, false);
    const auto ringVolumeSrc = toVolumeSource(AUDIO_STREAM_RING, false);
    const auto musicVolumeSrc = toVolumeSource(AUDIO_STREAM_MUSIC, false);
    const auto alarmVolumeSrc = toVolumeSource(AUDIO_STREAM_ALARM, false);
    const auto a11yVolumeSrc = toVolumeSource(AUDIO_STREAM_ACCESSIBILITY, false);

    if (volumeSource == a11yVolumeSrc
            && (AUDIO_MODE_RINGTONE == mEngine->getPhoneState()) &&
            mOutputs.isActive(ringVolumeSrc, 0)) {
        auto &ringCurves = getVolumeCurves(AUDIO_STREAM_RING);
        const float ringVolumeDb = computeVolume(ringCurves, ringVolumeSrc, index, deviceTypes);
        return ringVolumeDb - 4 > volumeDb ? ringVolumeDb - 4 : volumeDb;
    }

    // in-call: always cap volume by voice volume + some low headroom
    if ((volumeSource != callVolumeSrc && (isInCall() ||
                                           mOutputs.isActiveLocally(callVolumeSrc))) &&
            (volumeSource == toVolumeSource(AUDIO_STREAM_SYSTEM, false) ||
             volumeSource == ringVolumeSrc || volumeSource == musicVolumeSrc ||
             volumeSource == alarmVolumeSrc ||
             volumeSource == toVolumeSource(AUDIO_STREAM_NOTIFICATION, false) ||
             volumeSource == toVolumeSource(AUDIO_STREAM_ENFORCED_AUDIBLE, false) ||
             volumeSource == toVolumeSource(AUDIO_STREAM_DTMF, false) ||
             volumeSource == a11yVolumeSrc)) {
        auto &voiceCurves = getVolumeCurves(callVolumeSrc);
        int voiceVolumeIndex = voiceCurves.getVolumeIndex(deviceTypes);
        const float maxVoiceVolDb =
                computeVolume(voiceCurves, callVolumeSrc, voiceVolumeIndex, deviceTypes)
                + IN_CALL_EARPIECE_HEADROOM_DB;
        // FIXME: Workaround for call screening applications until a proper audio mode is defined
        // to support this scenario : Exempt the RING stream from the audio cap if the audio was
        // programmatically muted.
        // VOICE_CALL stream has minVolumeIndex > 0 : Users cannot set the volume of voice calls to
        // 0. We don't want to cap volume when the system has programmatically muted the voice call
        // stream. See setVolumeCurveIndex() for more information.
        bool exemptFromCapping =
                ((volumeSource == ringVolumeSrc) || (volumeSource == a11yVolumeSrc))
                && (voiceVolumeIndex == 0);
        ALOGV_IF(exemptFromCapping, "%s volume source %d at vol=%f not capped", __func__,
                 volumeSource, volumeDb);
        if ((volumeDb > maxVoiceVolDb) && !exemptFromCapping) {
            ALOGV("%s volume source %d at vol=%f overriden by volume group %d at vol=%f", __func__,
                  volumeSource, volumeDb, callVolumeSrc, maxVoiceVolDb);
            volumeDb = maxVoiceVolDb;
        }
    }
    // if a headset is connected, apply the following rules to ring tones and notifications
    // to avoid sound level bursts in user's ears:
    // - always attenuate notifications volume by 6dB
    // - attenuate ring tones volume by 6dB unless music is not playing and
    // speaker is part of the select devices
    // - if music is playing, always limit the volume to current music volume,
    // with a minimum threshold at -36dB so that notification is always perceived.
    if (!Intersection(deviceTypes,
            {AUDIO_DEVICE_OUT_BLUETOOTH_A2DP, AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES,
             AUDIO_DEVICE_OUT_WIRED_HEADSET, AUDIO_DEVICE_OUT_WIRED_HEADPHONE,
             AUDIO_DEVICE_OUT_USB_HEADSET, AUDIO_DEVICE_OUT_HEARING_AID,
             AUDIO_DEVICE_OUT_BLE_HEADSET}).empty() &&
            ((volumeSource == alarmVolumeSrc ||
              volumeSource == ringVolumeSrc) ||
             (volumeSource == toVolumeSource(AUDIO_STREAM_NOTIFICATION, false)) ||
             (volumeSource == toVolumeSource(AUDIO_STREAM_SYSTEM, false)) ||
             ((volumeSource == toVolumeSource(AUDIO_STREAM_ENFORCED_AUDIBLE, false)) &&
              (mEngine->getForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM) == AUDIO_POLICY_FORCE_NONE))) &&
            curves.canBeMuted()) {

        // when the phone is ringing we must consider that music could have been paused just before
        // by the music application and behave as if music was active if the last music track was
        // just stopped
        if (isStreamActive(AUDIO_STREAM_MUSIC, SONIFICATION_HEADSET_MUSIC_DELAY) ||
                mLimitRingtoneVolume) {
            volumeDb += SONIFICATION_HEADSET_VOLUME_FACTOR_DB;
            DeviceTypeSet musicDevice =
                    mEngine->getOutputDevicesForAttributes(attributes_initializer(AUDIO_USAGE_MEDIA),
                                                           nullptr, true /*fromCache*/).types();
            auto &musicCurves = getVolumeCurves(AUDIO_STREAM_MUSIC);
            float musicVolDb = computeVolume(musicCurves,
                                             musicVolumeSrc,
                                             musicCurves.getVolumeIndex(musicDevice),
                                             musicDevice);
            float minVolDb = (musicVolDb > SONIFICATION_HEADSET_VOLUME_MIN_DB) ?
                        musicVolDb : SONIFICATION_HEADSET_VOLUME_MIN_DB;
            if (volumeDb > minVolDb) {
                volumeDb = minVolDb;
                ALOGV("computeVolume limiting volume to %f musicVol %f", minVolDb, musicVolDb);
            }
            if (Volume::getDeviceForVolume(deviceTypes) != AUDIO_DEVICE_OUT_SPEAKER
                    &&  !Intersection(deviceTypes, {AUDIO_DEVICE_OUT_BLUETOOTH_A2DP,
                        AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES}).empty()) {
                // on A2DP, also ensure notification volume is not too low compared to media when
                // intended to be played
                if ((volumeDb > -96.0f) &&
                        (musicVolDb - SONIFICATION_A2DP_MAX_MEDIA_DIFF_DB > volumeDb)) {
                    ALOGV("%s increasing volume for volume source=%d device=%s from %f to %f",
                          __func__, volumeSource, dumpDeviceTypes(deviceTypes).c_str(), volumeDb,
                          musicVolDb - SONIFICATION_A2DP_MAX_MEDIA_DIFF_DB);
                    volumeDb = musicVolDb - SONIFICATION_A2DP_MAX_MEDIA_DIFF_DB;
                }
            }
        } else if ((Volume::getDeviceForVolume(deviceTypes) != AUDIO_DEVICE_OUT_SPEAKER) ||
                   (!(volumeSource == alarmVolumeSrc || volumeSource == ringVolumeSrc))) {
            volumeDb += SONIFICATION_HEADSET_VOLUME_FACTOR_DB;
        }
    }

    return volumeDb;
}

int AudioPolicyManager::rescaleVolumeIndex(int srcIndex,
                                           VolumeSource fromVolumeSource,
                                           VolumeSource toVolumeSource)
{
    if (fromVolumeSource == toVolumeSource) {
        return srcIndex;
    }
    auto &srcCurves = getVolumeCurves(fromVolumeSource);
    auto &dstCurves = getVolumeCurves(toVolumeSource);
    float minSrc = (float)srcCurves.getVolumeIndexMin();
    float maxSrc = (float)srcCurves.getVolumeIndexMax();
    float minDst = (float)dstCurves.getVolumeIndexMin();
    float maxDst = (float)dstCurves.getVolumeIndexMax();

    // preserve mute request or correct range
    if (srcIndex < minSrc) {
        if (srcIndex == 0) {
            return 0;
        }
        srcIndex = minSrc;
    } else if (srcIndex > maxSrc) {
        srcIndex = maxSrc;
    }
    return (int)(minDst + ((srcIndex - minSrc) * (maxDst - minDst)) / (maxSrc - minSrc));
}

status_t AudioPolicyManager::checkAndSetVolume(IVolumeCurves &curves,
                                               VolumeSource volumeSource,
                                               int index,
                                               const sp<AudioOutputDescriptor>& outputDesc,
                                               DeviceTypeSet deviceTypes,
                                               int delayMs,
                                               bool force)
{
    // do not change actual attributes volume if the attributes is muted
    if (outputDesc->isMuted(volumeSource)) {
        ALOGVV("%s: volume source %d muted count %d active=%d", __func__, volumeSource,
               outputDesc->getMuteCount(volumeSource), outputDesc->isActive(volumeSource));
        return NO_ERROR;
    }
    VolumeSource callVolSrc = toVolumeSource(AUDIO_STREAM_VOICE_CALL, false);
    VolumeSource btScoVolSrc = toVolumeSource(AUDIO_STREAM_BLUETOOTH_SCO, false);
    bool isVoiceVolSrc = (volumeSource != VOLUME_SOURCE_NONE) && (callVolSrc == volumeSource);
    bool isBtScoVolSrc = (volumeSource != VOLUME_SOURCE_NONE) && (btScoVolSrc == volumeSource);

    bool isScoRequested = isScoRequestedForComm();
    bool isHAUsed = isHearingAidUsedForComm();

    // do not change in call volume if bluetooth is connected and vice versa
    // if sco and call follow same curves, bypass forceUseForComm
    if ((callVolSrc != btScoVolSrc) &&
            ((isVoiceVolSrc && isScoRequested) ||
             (isBtScoVolSrc && !(isScoRequested || isHAUsed)))) {
        ALOGV("%s cannot set volume group %d volume when is%srequested for comm", __func__,
             volumeSource, isScoRequested ? " " : " not ");
        // Do not return an error here as AudioService will always set both voice call
        // and bluetooth SCO volumes due to stream aliasing.
        return NO_ERROR;
    }
    if (deviceTypes.empty()) {
        deviceTypes = outputDesc->devices().types();
    }

    if (curves.getVolumeIndexMin() < 0 || curves.getVolumeIndexMax() < 0) {
        ALOGE("invalid volume index range");
        return BAD_VALUE;
    }

    float volumeDb = computeVolume(curves, volumeSource, index, deviceTypes);
    if (outputDesc->isFixedVolume(deviceTypes) ||
            // Force VoIP volume to max for bluetooth SCO device except if muted
            (index != 0 && (isVoiceVolSrc || isBtScoVolSrc) &&
                    isSingleDeviceType(deviceTypes, audio_is_bluetooth_out_sco_device))) {
        volumeDb = 0.0f;
    }
    const bool muted = (index == 0) && (volumeDb != 0.0f);
    outputDesc->setVolume(
            volumeDb, muted, volumeSource, curves.getStreamTypes(), deviceTypes, delayMs, force);

    if (outputDesc == mPrimaryOutput && (isVoiceVolSrc || isBtScoVolSrc)) {
        float voiceVolume;
        // Force voice volume to max or mute for Bluetooth SCO as other attenuations are managed by the headset
        if (isVoiceVolSrc) {
            voiceVolume = (float)index/(float)curves.getVolumeIndexMax();
        } else {
            voiceVolume = index == 0 ? 0.0 : 1.0;
        }
        if (voiceVolume != mLastVoiceVolume) {
            mpClientInterface->setVoiceVolume(voiceVolume, delayMs);
            mLastVoiceVolume = voiceVolume;
        }
    }
    return NO_ERROR;
}

void AudioPolicyManager::applyStreamVolumes(const sp<AudioOutputDescriptor>& outputDesc,
                                            const DeviceTypeSet& deviceTypes,
                                            int delayMs,
                                            bool force)
{
    ALOGVV("applyStreamVolumes() for device %s", dumpDeviceTypes(deviceTypes).c_str());
    for (const auto &volumeGroup : mEngine->getVolumeGroups()) {
        auto &curves = getVolumeCurves(toVolumeSource(volumeGroup));
        checkAndSetVolume(curves, toVolumeSource(volumeGroup),
                          curves.getVolumeIndex(deviceTypes),
                          outputDesc, deviceTypes, delayMs, force);
    }
}

void AudioPolicyManager::setStrategyMute(product_strategy_t strategy,
                                         bool on,
                                         const sp<AudioOutputDescriptor>& outputDesc,
                                         int delayMs,
                                         DeviceTypeSet deviceTypes)
{
    std::vector<VolumeSource> sourcesToMute;
    for (auto attributes: mEngine->getAllAttributesForProductStrategy(strategy)) {
        ALOGVV("%s() attributes %s, mute %d, output ID %d", __func__,
               toString(attributes).c_str(), on, outputDesc->getId());
        VolumeSource source = toVolumeSource(attributes, false);
        if ((source != VOLUME_SOURCE_NONE) &&
                (std::find(begin(sourcesToMute), end(sourcesToMute), source)
                        == end(sourcesToMute))) {
            sourcesToMute.push_back(source);
        }
    }
    for (auto source : sourcesToMute) {
        setVolumeSourceMute(source, on, outputDesc, delayMs, deviceTypes);
    }

}

void AudioPolicyManager::setVolumeSourceMute(VolumeSource volumeSource,
                                             bool on,
                                             const sp<AudioOutputDescriptor>& outputDesc,
                                             int delayMs,
                                             DeviceTypeSet deviceTypes)
{
    if (deviceTypes.empty()) {
        deviceTypes = outputDesc->devices().types();
    }
    auto &curves = getVolumeCurves(volumeSource);
    if (on) {
        if (!outputDesc->isMuted(volumeSource)) {
            if (curves.canBeMuted() &&
                    (volumeSource != toVolumeSource(AUDIO_STREAM_ENFORCED_AUDIBLE, false) ||
                     (mEngine->getForceUse(AUDIO_POLICY_FORCE_FOR_SYSTEM) ==
                      AUDIO_POLICY_FORCE_NONE))) {
                checkAndSetVolume(curves, volumeSource, 0, outputDesc, deviceTypes, delayMs);
            }
        }
        // increment mMuteCount after calling checkAndSetVolume() so that volume change is not
        // ignored
        outputDesc->incMuteCount(volumeSource);
    } else {
        if (!outputDesc->isMuted(volumeSource)) {
            ALOGV("%s unmuting non muted attributes!", __func__);
            return;
        }
        if (outputDesc->decMuteCount(volumeSource) == 0) {
            checkAndSetVolume(curves, volumeSource,
                              curves.getVolumeIndex(deviceTypes),
                              outputDesc,
                              deviceTypes,
                              delayMs);
        }
    }
}

bool AudioPolicyManager::isValidAttributes(const audio_attributes_t *paa)
{
    // has flags that map to a stream type?
    if ((paa->flags & (AUDIO_FLAG_AUDIBILITY_ENFORCED | AUDIO_FLAG_SCO | AUDIO_FLAG_BEACON)) != 0) {
        return true;
    }

    // has known usage?
    switch (paa->usage) {
    case AUDIO_USAGE_UNKNOWN:
    case AUDIO_USAGE_MEDIA:
    case AUDIO_USAGE_VOICE_COMMUNICATION:
    case AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING:
    case AUDIO_USAGE_ALARM:
    case AUDIO_USAGE_NOTIFICATION:
    case AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE:
    case AUDIO_USAGE_NOTIFICATION_COMMUNICATION_REQUEST:
    case AUDIO_USAGE_NOTIFICATION_COMMUNICATION_INSTANT:
    case AUDIO_USAGE_NOTIFICATION_COMMUNICATION_DELAYED:
    case AUDIO_USAGE_NOTIFICATION_EVENT:
    case AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY:
    case AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE:
    case AUDIO_USAGE_ASSISTANCE_SONIFICATION:
    case AUDIO_USAGE_GAME:
    case AUDIO_USAGE_VIRTUAL_SOURCE:
    case AUDIO_USAGE_ASSISTANT:
    case AUDIO_USAGE_CALL_ASSISTANT:
    case AUDIO_USAGE_EMERGENCY:
    case AUDIO_USAGE_SAFETY:
    case AUDIO_USAGE_VEHICLE_STATUS:
    case AUDIO_USAGE_ANNOUNCEMENT:
        break;
    default:
        return false;
    }
    return true;
}

audio_policy_forced_cfg_t AudioPolicyManager::getForceUse(audio_policy_force_use_t usage)
{
    return mEngine->getForceUse(usage);
}

bool AudioPolicyManager::isInCall() const {
    return isStateInCall(mEngine->getPhoneState());
}

bool AudioPolicyManager::isStateInCall(int state) const {
    return is_state_in_call(state);
}

bool AudioPolicyManager::isCallAudioAccessible()
{
    audio_mode_t mode = mEngine->getPhoneState();
    return (mode == AUDIO_MODE_IN_CALL)
            || (mode == AUDIO_MODE_CALL_SCREEN)
            || (mode == AUDIO_MODE_CALL_REDIRECT);
}

void AudioPolicyManager::cleanUpForDevice(const sp<DeviceDescriptor>& deviceDesc)
{
    for (ssize_t i = (ssize_t)mAudioSources.size() - 1; i >= 0; i--)  {
        sp<SourceClientDescriptor> sourceDesc = mAudioSources.valueAt(i);
        if (sourceDesc->isConnected() && (sourceDesc->srcDevice()->equals(deviceDesc) ||
                                          sourceDesc->sinkDevice()->equals(deviceDesc))
                && !isCallRxAudioSource(sourceDesc)) {
            disconnectAudioSource(sourceDesc);
        }
    }

    for (ssize_t i = (ssize_t)mAudioPatches.size() - 1; i >= 0; i--)  {
        sp<AudioPatch> patchDesc = mAudioPatches.valueAt(i);
        bool release = false;
        for (size_t j = 0; j < patchDesc->mPatch.num_sources && !release; j++)  {
            const struct audio_port_config *source = &patchDesc->mPatch.sources[j];
            if (source->type == AUDIO_PORT_TYPE_DEVICE &&
                    source->ext.device.type == deviceDesc->type()) {
                release = true;
            }
        }
        const char *address = deviceDesc->address().c_str();
        for (size_t j = 0; j < patchDesc->mPatch.num_sinks && !release; j++)  {
            const struct audio_port_config *sink = &patchDesc->mPatch.sinks[j];
            if (sink->type == AUDIO_PORT_TYPE_DEVICE &&
                    sink->ext.device.type == deviceDesc->type() &&
                    (strnlen(address, AUDIO_DEVICE_MAX_ADDRESS_LEN) == 0
                     || strncmp(sink->ext.device.address, address,
                                 AUDIO_DEVICE_MAX_ADDRESS_LEN) == 0)) {
                release = true;
            }
        }
        if (release) {
            ALOGV("%s releasing patch %u", __FUNCTION__, patchDesc->getHandle());
            releaseAudioPatch(patchDesc->getHandle(), patchDesc->getUid());
        }
    }

    mInputs.clearSessionRoutesForDevice(deviceDesc);

    mHwModules.cleanUpForDevice(deviceDesc);
}

void AudioPolicyManager::modifySurroundFormats(
        const sp<DeviceDescriptor>& devDesc, FormatVector *formatsPtr) {
    std::unordered_set<audio_format_t> enforcedSurround(
            devDesc->encodedFormats().begin(), devDesc->encodedFormats().end());
    std::unordered_set<audio_format_t> allSurround;  // A flat set of all known surround formats
    for (const auto& pair : mConfig.getSurroundFormats()) {
        allSurround.insert(pair.first);
        for (const auto& subformat : pair.second) allSurround.insert(subformat);
    }

    audio_policy_forced_cfg_t forceUse = mEngine->getForceUse(
            AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND);
    ALOGD("%s: forced use = %d", __FUNCTION__, forceUse);
    // This is the resulting set of formats depending on the surround mode:
    //   'all surround' = allSurround
    //   'enforced surround' = enforcedSurround [may include IEC69137 which isn't raw surround fmt]
    //   'non-surround' = not in 'all surround' and not in 'enforced surround'
    //   'manual surround' = mManualSurroundFormats
    // AUTO:   formats v 'enforced surround'
    // ALWAYS: formats v 'all surround' v 'enforced surround'
    // NEVER:  formats ^ 'non-surround'
    // MANUAL: formats ^ ('non-surround' v 'manual surround' v (IEC69137 ^ 'enforced surround'))

    std::unordered_set<audio_format_t> formatSet;
    if (forceUse == AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL
            || forceUse == AUDIO_POLICY_FORCE_ENCODED_SURROUND_NEVER) {
        // formatSet is (formats ^ 'non-surround')
        for (auto formatIter = formatsPtr->begin(); formatIter != formatsPtr->end(); ++formatIter) {
            if (allSurround.count(*formatIter) == 0 && enforcedSurround.count(*formatIter) == 0) {
                formatSet.insert(*formatIter);
            }
        }
    } else {
        formatSet.insert(formatsPtr->begin(), formatsPtr->end());
    }
    formatsPtr->clear();  // Re-filled from the formatSet at the end.

    if (forceUse == AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL) {
        formatSet.insert(mManualSurroundFormats.begin(), mManualSurroundFormats.end());
        // Enable IEC61937 when in MANUAL mode if it's enforced for this device.
        if (enforcedSurround.count(AUDIO_FORMAT_IEC61937) != 0) {
            formatSet.insert(AUDIO_FORMAT_IEC61937);
        }
    } else if (forceUse != AUDIO_POLICY_FORCE_ENCODED_SURROUND_NEVER) { // AUTO or ALWAYS
        if (forceUse == AUDIO_POLICY_FORCE_ENCODED_SURROUND_ALWAYS) {
            formatSet.insert(allSurround.begin(), allSurround.end());
        }
        formatSet.insert(enforcedSurround.begin(), enforcedSurround.end());
    }
    for (const auto& format : formatSet) {
        formatsPtr->push_back(format);
    }
}

void AudioPolicyManager::modifySurroundChannelMasks(ChannelMaskSet *channelMasksPtr) {
    ChannelMaskSet &channelMasks = *channelMasksPtr;
    audio_policy_forced_cfg_t forceUse = mEngine->getForceUse(
            AUDIO_POLICY_FORCE_FOR_ENCODED_SURROUND);

    // If NEVER, then remove support for channelMasks > stereo.
    if (forceUse == AUDIO_POLICY_FORCE_ENCODED_SURROUND_NEVER) {
        for (auto it = channelMasks.begin(); it != channelMasks.end();) {
            audio_channel_mask_t channelMask = *it;
            if (channelMask & ~AUDIO_CHANNEL_OUT_STEREO) {
                ALOGV("%s: force NEVER, so remove channelMask 0x%08x", __FUNCTION__, channelMask);
                it = channelMasks.erase(it);
            } else {
                ++it;
            }
        }
    // If ALWAYS or MANUAL, then make sure we at least support 5.1
    } else if (forceUse == AUDIO_POLICY_FORCE_ENCODED_SURROUND_ALWAYS
            || forceUse == AUDIO_POLICY_FORCE_ENCODED_SURROUND_MANUAL) {
        bool supports5dot1 = false;
        // Are there any channel masks that can be considered "surround"?
        for (audio_channel_mask_t channelMask : channelMasks) {
            if ((channelMask & AUDIO_CHANNEL_OUT_5POINT1) == AUDIO_CHANNEL_OUT_5POINT1) {
                supports5dot1 = true;
                break;
            }
        }
        // If not then add 5.1 support.
        if (!supports5dot1) {
            channelMasks.insert(AUDIO_CHANNEL_OUT_5POINT1);
            ALOGV("%s: force MANUAL or ALWAYS, so adding channelMask for 5.1 surround", __func__);
        }
    }
}

void AudioPolicyManager::updateAudioProfiles(const sp<DeviceDescriptor>& devDesc,
                                             audio_io_handle_t ioHandle,
                                             AudioProfileVector &profiles)
{
    String8 reply;
    audio_devices_t device = devDesc->type();

    // Format MUST be checked first to update the list of AudioProfile
    if (profiles.hasDynamicFormat()) {
        reply = mpClientInterface->getParameters(
                ioHandle, String8(AudioParameter::keyStreamSupportedFormats));
        ALOGV("%s: supported formats %d, %s", __FUNCTION__, ioHandle, reply.string());
        AudioParameter repliedParameters(reply);
        if (repliedParameters.get(
                String8(AudioParameter::keyStreamSupportedFormats), reply) != NO_ERROR) {
            ALOGE("%s: failed to retrieve format, bailing out", __FUNCTION__);
            return;
        }
        FormatVector formats = formatsFromString(reply.string());
        mReportedFormatsMap[devDesc] = formats;
        if (device == AUDIO_DEVICE_OUT_HDMI
                || isDeviceOfModule(devDesc, AUDIO_HARDWARE_MODULE_ID_MSD)) {
            modifySurroundFormats(devDesc, &formats);
        }
        addProfilesForFormats(profiles, formats);
    }

    for (audio_format_t format : profiles.getSupportedFormats()) {
        ChannelMaskSet channelMasks;
        SampleRateSet samplingRates;
        AudioParameter requestedParameters;
        requestedParameters.addInt(String8(AudioParameter::keyFormat), format);

        if (profiles.hasDynamicRateFor(format)) {
            reply = mpClientInterface->getParameters(
                    ioHandle,
                    requestedParameters.toString() + ";" +
                    AudioParameter::keyStreamSupportedSamplingRates);
            ALOGV("%s: supported sampling rates %s", __FUNCTION__, reply.string());
            AudioParameter repliedParameters(reply);
            if (repliedParameters.get(
                    String8(AudioParameter::keyStreamSupportedSamplingRates), reply) == NO_ERROR) {
                samplingRates = samplingRatesFromString(reply.string());
            }
        }
        if (profiles.hasDynamicChannelsFor(format)) {
            reply = mpClientInterface->getParameters(ioHandle,
                                                     requestedParameters.toString() + ";" +
                                                     AudioParameter::keyStreamSupportedChannels);
            ALOGV("%s: supported channel masks %s", __FUNCTION__, reply.string());
            AudioParameter repliedParameters(reply);
            if (repliedParameters.get(
                    String8(AudioParameter::keyStreamSupportedChannels), reply) == NO_ERROR) {
                channelMasks = channelMasksFromString(reply.string());
                if (device == AUDIO_DEVICE_OUT_HDMI
                        || isDeviceOfModule(devDesc, AUDIO_HARDWARE_MODULE_ID_MSD)) {
                    modifySurroundChannelMasks(&channelMasks);
                }
            }
        }
        addDynamicAudioProfileAndSort(
                profiles, new AudioProfile(format, channelMasks, samplingRates));
    }
}

status_t AudioPolicyManager::installPatch(const char *caller,
                                          audio_patch_handle_t *patchHandle,
                                          AudioIODescriptorInterface *ioDescriptor,
                                          const struct audio_patch *patch,
                                          int delayMs)
{
    ssize_t index = mAudioPatches.indexOfKey(
            patchHandle && *patchHandle != AUDIO_PATCH_HANDLE_NONE ?
            *patchHandle : ioDescriptor->getPatchHandle());
    sp<AudioPatch> patchDesc;
    status_t status = installPatch(
            caller, index, patchHandle, patch, delayMs, mUidCached, &patchDesc);
    if (status == NO_ERROR) {
        ioDescriptor->setPatchHandle(patchDesc->getHandle());
    }
    return status;
}

status_t AudioPolicyManager::installPatch(const char *caller,
                                          ssize_t index,
                                          audio_patch_handle_t *patchHandle,
                                          const struct audio_patch *patch,
                                          int delayMs,
                                          uid_t uid,
                                          sp<AudioPatch> *patchDescPtr)
{
    sp<AudioPatch> patchDesc;
    audio_patch_handle_t afPatchHandle = AUDIO_PATCH_HANDLE_NONE;
    if (index >= 0) {
        patchDesc = mAudioPatches.valueAt(index);
        afPatchHandle = patchDesc->getAfHandle();
    }

    status_t status = mpClientInterface->createAudioPatch(patch, &afPatchHandle, delayMs);
    ALOGV("%s() AF::createAudioPatch returned %d patchHandle %d num_sources %d num_sinks %d",
            caller, status, afPatchHandle, patch->num_sources, patch->num_sinks);
    if (status == NO_ERROR) {
        if (index < 0) {
            patchDesc = new AudioPatch(patch, uid);
            addAudioPatch(patchDesc->getHandle(), patchDesc);
        } else {
            patchDesc->mPatch = *patch;
        }
        patchDesc->setAfHandle(afPatchHandle);
        if (patchHandle) {
            *patchHandle = patchDesc->getHandle();
        }
        nextAudioPortGeneration();
        mpClientInterface->onAudioPatchListUpdate();
    }
    if (patchDescPtr) *patchDescPtr = patchDesc;
    return status;
}

bool AudioPolicyManager::areAllActiveTracksRerouted(const sp<SwAudioOutputDescriptor>& output)
{
    const TrackClientVector activeClients = output->getActiveClients();
    if (activeClients.empty()) {
        return true;
    }
    ssize_t index = mAudioPatches.indexOfKey(output->getPatchHandle());
    if (index < 0) {
        ALOGE("%s, no audio patch found while there are active clients on output %d",
                __func__, output->getId());
        return false;
    }
    sp<AudioPatch> patchDesc = mAudioPatches.valueAt(index);
    DeviceVector routedDevices;
    for (int i = 0; i < patchDesc->mPatch.num_sinks; ++i) {
        sp<DeviceDescriptor> device = mAvailableOutputDevices.getDeviceFromId(
                patchDesc->mPatch.sinks[i].id);
        if (device == nullptr) {
            ALOGE("%s, no audio device found with id(%d)",
                    __func__, patchDesc->mPatch.sinks[i].id);
            return false;
        }
        routedDevices.add(device);
    }
    for (const auto& client : activeClients) {
        if (client->isInvalid()) {
            // No need to take care about invalidated clients.
            continue;
        }
        sp<DeviceDescriptor> preferredDevice =
                mAvailableOutputDevices.getDeviceFromId(client->preferredDeviceId());
        if (mEngine->getOutputDevicesForAttributes(
                client->attributes(), preferredDevice, false) == routedDevices) {
            return false;
        }
    }
    return true;
}

sp<SwAudioOutputDescriptor> AudioPolicyManager::openOutputWithProfileAndDevice(
        const sp<IOProfile>& profile, const DeviceVector& devices,
        const audio_config_base_t *mixerConfig)
{
    for (const auto& device : devices) {
        // TODO: This should be checking if the profile supports the device combo.
        if (!profile->supportsDevice(device)) {
            return nullptr;
        }
    }
    sp<SwAudioOutputDescriptor> desc = new SwAudioOutputDescriptor(profile, mpClientInterface);
    audio_io_handle_t output = AUDIO_IO_HANDLE_NONE;
    status_t status = desc->open(nullptr /* halConfig */, mixerConfig, devices,
            AUDIO_STREAM_DEFAULT, AUDIO_OUTPUT_FLAG_NONE, &output);
    if (status != NO_ERROR) {
        return nullptr;
    }

    // Here is where the out_set_parameters() for card & device gets called
    sp<DeviceDescriptor> device = devices.getDeviceForOpening();
    const audio_devices_t deviceType = device->type();
    const String8 &address = String8(device->address().c_str());
    if (!address.isEmpty()) {
        char *param = audio_device_address_to_parameter(deviceType, address.c_str());
        mpClientInterface->setParameters(output, String8(param));
        free(param);
    }
    updateAudioProfiles(device, output, profile->getAudioProfiles());
    if (!profile->hasValidAudioProfile()) {
        ALOGW("%s() missing param", __func__);
        desc->close();
        return nullptr;
    } else if (profile->hasDynamicAudioProfile()) {
        desc->close();
        output = AUDIO_IO_HANDLE_NONE;
        audio_config_t config = AUDIO_CONFIG_INITIALIZER;
        profile->pickAudioProfile(
                config.sample_rate, config.channel_mask, config.format);
        config.offload_info.sample_rate = config.sample_rate;
        config.offload_info.channel_mask = config.channel_mask;
        config.offload_info.format = config.format;

        status = desc->open(&config, mixerConfig, devices,
                            AUDIO_STREAM_DEFAULT, AUDIO_OUTPUT_FLAG_NONE, &output);
        if (status != NO_ERROR) {
            return nullptr;
        }
    }

    addOutput(output, desc);

    if (audio_is_remote_submix_device(deviceType) && address != "0") {
        sp<AudioPolicyMix> policyMix;
        if (mPolicyMixes.getAudioPolicyMix(deviceType, address, policyMix) == NO_ERROR) {
            policyMix->setOutput(desc);
            desc->mPolicyMix = policyMix;
        } else {
            ALOGW("checkOutputsForDevice() cannot find policy for address %s",
                    address.string());
        }

    } else if (hasPrimaryOutput() && profile->getModule()
                != mHwModules.getModuleFromName(AUDIO_HARDWARE_MODULE_ID_PRIMARY)
            && ((desc->mFlags & AUDIO_OUTPUT_FLAG_DIRECT) == 0)) {
        // no duplicated output for:
        // - direct outputs
        // - outputs used by dynamic policy mixes
        // - outputs opened on the primary HW module
        audio_io_handle_t duplicatedOutput = AUDIO_IO_HANDLE_NONE;

        //TODO: configure audio effect output stage here

        // open a duplicating output thread for the new output and the primary output
        sp<SwAudioOutputDescriptor> dupOutputDesc =
                new SwAudioOutputDescriptor(nullptr, mpClientInterface);
        status = dupOutputDesc->openDuplicating(mPrimaryOutput, desc, &duplicatedOutput);
        if (status == NO_ERROR) {
            // add duplicated output descriptor
            addOutput(duplicatedOutput, dupOutputDesc);
        } else {
            ALOGW("checkOutputsForDevice() could not open dup output for %d and %d",
                  mPrimaryOutput->mIoHandle, output);
            desc->close();
            removeOutput(output);
            nextAudioPortGeneration();
            return nullptr;
        }
    }
    if (mPrimaryOutput == nullptr && profile->getFlags() & AUDIO_OUTPUT_FLAG_PRIMARY) {
        ALOGV("%s(): re-assigning mPrimaryOutput", __func__);
        mPrimaryOutput = desc;
    }
    return desc;
}

} // namespace android
