/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <stdio.h>

#define LOG_TAG "DeviceHalHidl"
// #define LOG_NDEBUG 0

#include <cutils/native_handle.h>
#include <cutils/properties.h>
#include <hwbinder/IPCThreadState.h>
#include <media/AudioContainers.h>
#include <mediautils/TimeCheck.h>
#include <utils/Log.h>

#include PATH(android/hardware/audio/FILE_VERSION/IPrimaryDevice.h)
#include <HidlUtils.h>
#include <common/all-versions/VersionUtils.h>
#include <util/CoreUtils.h>

#include "DeviceHalHidl.h"
#include "EffectHalHidl.h"
#include "ParameterUtils.h"
#include "StreamHalHidl.h"

#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
#include <aidl/android/hardware/audio/core/sounddose/BpSoundDose.h>
#include <aidl/android/hardware/audio/sounddose/BpSoundDoseFactory.h>
#include <android/binder_manager.h>

constexpr std::string_view kSoundDoseInterfaceModule = "/default";

using aidl::android::hardware::audio::core::sounddose::ISoundDose;
using aidl::android::hardware::audio::sounddose::ISoundDoseFactory;
#endif

using ::android::hardware::audio::common::COMMON_TYPES_CPP_VERSION::implementation::HidlUtils;
using ::android::hardware::audio::common::utils::EnumBitfield;
using ::android::hardware::audio::CORE_TYPES_CPP_VERSION::implementation::CoreUtils;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;

namespace android {

using namespace ::android::hardware::audio::common::COMMON_TYPES_CPP_VERSION;
using namespace ::android::hardware::audio::CORE_TYPES_CPP_VERSION;

class DeviceHalHidl::SoundDoseWrapper {
public:
    SoundDoseWrapper() = default;
    ~SoundDoseWrapper() = default;

#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
    std::shared_ptr<ISoundDoseFactory> mSoundDoseFactory;
    std::shared_ptr<ISoundDose> mSoundDose;
#endif
};

DeviceHalHidl::DeviceHalHidl(const sp<::android::hardware::audio::CPP_VERSION::IDevice>& device)
        : CoreConversionHelperHidl("DeviceHalHidl"),
          mDevice(device),
          mSoundDoseWrapper(std::make_unique<DeviceHalHidl::SoundDoseWrapper>()) {
}

DeviceHalHidl::DeviceHalHidl(
        const sp<::android::hardware::audio::CPP_VERSION::IPrimaryDevice>& device)
        : CoreConversionHelperHidl("DeviceHalHidl"),
#if MAJOR_VERSION <= 6 || (MAJOR_VERSION == 7 && MINOR_VERSION == 0)
          mDevice(device),
#endif
          mPrimaryDevice(device),
          mSoundDoseWrapper(std::make_unique<DeviceHalHidl::SoundDoseWrapper>()) {
#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
    auto getDeviceRet = mPrimaryDevice->getDevice();
    if (getDeviceRet.isOk()) {
        mDevice = getDeviceRet;
    } else {
        ALOGE("Call to IPrimaryDevice.getDevice has failed: %s",
                getDeviceRet.description().c_str());
    }
#endif
}

DeviceHalHidl::~DeviceHalHidl() {
    if (mDevice != 0) {
#if MAJOR_VERSION <= 5
        mDevice.clear();
        hardware::IPCThreadState::self()->flushCommands();
#elif MAJOR_VERSION >= 6
        mDevice->close();
#endif
    }
}

status_t DeviceHalHidl::getAudioPorts(
        std::vector<media::audio::common::AudioPort> *ports __unused) {
    return INVALID_OPERATION;
}

status_t DeviceHalHidl::getAudioRoutes(std::vector<media::AudioRoute> *routes __unused) {
    return INVALID_OPERATION;
}

status_t DeviceHalHidl::getSupportedModes(
        std::vector<media::audio::common::AudioMode> *modes __unused) {
    return INVALID_OPERATION;
}

status_t DeviceHalHidl::getSupportedDevices(uint32_t*) {
    // Obsolete.
    return INVALID_OPERATION;
}

status_t DeviceHalHidl::initCheck() {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    return processReturn("initCheck", mDevice->initCheck());
}

status_t DeviceHalHidl::setVoiceVolume(float volume) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    if (mPrimaryDevice == 0) return INVALID_OPERATION;
    return processReturn("setVoiceVolume", mPrimaryDevice->setVoiceVolume(volume));
}

status_t DeviceHalHidl::setMasterVolume(float volume) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    return processReturn("setMasterVolume", mDevice->setMasterVolume(volume));
}

status_t DeviceHalHidl::getMasterVolume(float *volume) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    Result retval;
    Return<void> ret = mDevice->getMasterVolume(
            [&](Result r, float v) {
                retval = r;
                if (retval == Result::OK) {
                    *volume = v;
                }
            });
    return processReturn("getMasterVolume", ret, retval);
}

status_t DeviceHalHidl::setMode(audio_mode_t mode) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    if (mPrimaryDevice == 0) return INVALID_OPERATION;
    return processReturn("setMode", mPrimaryDevice->setMode(AudioMode(mode)));
}

status_t DeviceHalHidl::setMicMute(bool state) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    return processReturn("setMicMute", mDevice->setMicMute(state));
}

status_t DeviceHalHidl::getMicMute(bool *state) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    Result retval;
    Return<void> ret = mDevice->getMicMute(
            [&](Result r, bool mute) {
                retval = r;
                if (retval == Result::OK) {
                    *state = mute;
                }
            });
    return processReturn("getMicMute", ret, retval);
}

status_t DeviceHalHidl::setMasterMute(bool state) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    return processReturn("setMasterMute", mDevice->setMasterMute(state));
}

status_t DeviceHalHidl::getMasterMute(bool *state) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    Result retval;
    Return<void> ret = mDevice->getMasterMute(
            [&](Result r, bool mute) {
                retval = r;
                if (retval == Result::OK) {
                    *state = mute;
                }
            });
    return processReturn("getMasterMute", ret, retval);
}

status_t DeviceHalHidl::setParameters(const String8& kvPairs) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    hidl_vec<ParameterValue> hidlParams;
    status_t status = parametersFromHal(kvPairs, &hidlParams);
    if (status != OK) return status;
    // TODO: change the API so that context and kvPairs are separated
    return processReturn("setParameters",
                         utils::setParameters(mDevice, {} /* context */, hidlParams));
}

status_t DeviceHalHidl::getParameters(const String8& keys, String8 *values) {
    TIME_CHECK();
    values->clear();
    if (mDevice == 0) return NO_INIT;
    hidl_vec<hidl_string> hidlKeys;
    status_t status = keysFromHal(keys, &hidlKeys);
    if (status != OK) return status;
    Result retval;
    Return<void> ret = utils::getParameters(mDevice,
            {} /* context */,
            hidlKeys,
            [&](Result r, const hidl_vec<ParameterValue>& parameters) {
                retval = r;
                if (retval == Result::OK) {
                    parametersToHal(parameters, values);
                }
            });
    return processReturn("getParameters", ret, retval);
}

status_t DeviceHalHidl::getInputBufferSize(
        const struct audio_config *config, size_t *size) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    AudioConfig hidlConfig;
    HidlUtils::audioConfigFromHal(*config, true /*isInput*/, &hidlConfig);
    Result retval;
    Return<void> ret = mDevice->getInputBufferSize(
            hidlConfig,
            [&](Result r, uint64_t bufferSize) {
                retval = r;
                if (retval == Result::OK) {
                    *size = static_cast<size_t>(bufferSize);
                }
            });
    return processReturn("getInputBufferSize", ret, retval);
}

status_t DeviceHalHidl::openOutputStream(
        audio_io_handle_t handle,
        audio_devices_t deviceType,
        audio_output_flags_t flags,
        struct audio_config *config,
        const char *address,
        sp<StreamOutHalInterface> *outStream) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    DeviceAddress hidlDevice;
    if (status_t status = CoreUtils::deviceAddressFromHal(deviceType, address, &hidlDevice);
            status != OK) {
        return status;
    }
    AudioConfig hidlConfig;
    if (status_t status = HidlUtils::audioConfigFromHal(*config, false /*isInput*/, &hidlConfig);
            status != OK) {
        return status;
    }

#if !(MAJOR_VERSION == 7 && MINOR_VERSION == 1)
    //TODO: b/193496180 use spatializer flag at audio HAL when available
    if ((flags & AUDIO_OUTPUT_FLAG_SPATIALIZER) != 0) {
        flags = (audio_output_flags_t)(flags & ~AUDIO_OUTPUT_FLAG_SPATIALIZER);
        flags = (audio_output_flags_t)
                (flags | AUDIO_OUTPUT_FLAG_FAST | AUDIO_OUTPUT_FLAG_DEEP_BUFFER);
    }
#endif

    CoreUtils::AudioOutputFlags hidlFlags;
    if (status_t status = CoreUtils::audioOutputFlagsFromHal(flags, &hidlFlags); status != OK) {
        return status;
    }
    Result retval = Result::NOT_INITIALIZED;
#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
    Return<void> ret = mDevice->openOutputStream_7_1(
#else
    Return<void> ret = mDevice->openOutputStream(
#endif
            handle, hidlDevice, hidlConfig, hidlFlags,
#if MAJOR_VERSION >= 4
            {} /* metadata */,
#endif
            [&](Result r, const sp<::android::hardware::audio::CPP_VERSION::IStreamOut>& result,
                    const AudioConfig& suggestedConfig) {
                retval = r;
                if (retval == Result::OK) {
                    *outStream = new StreamOutHalHidl(result);
                }
                HidlUtils::audioConfigToHal(suggestedConfig, config);
            });
    const status_t status = processReturn("openOutputStream", ret, retval);
    cleanupStreams();
    if (status == NO_ERROR) {
        mStreams.insert({handle, *outStream});
    }
    return status;
}

status_t DeviceHalHidl::openInputStream(
        audio_io_handle_t handle,
        audio_devices_t devices,
        struct audio_config *config,
        audio_input_flags_t flags,
        const char *address,
        audio_source_t source,
        audio_devices_t outputDevice,
        const char *outputDeviceAddress,
        sp<StreamInHalInterface> *inStream) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    DeviceAddress hidlDevice;
    if (status_t status = CoreUtils::deviceAddressFromHal(devices, address, &hidlDevice);
            status != OK) {
        return status;
    }
    AudioConfig hidlConfig;
    if (status_t status = HidlUtils::audioConfigFromHal(*config, true /*isInput*/, &hidlConfig);
            status != OK) {
        return status;
    }
    CoreUtils::AudioInputFlags hidlFlags;
#if MAJOR_VERSION <= 5
    // Some flags were specific to framework and must not leak to the HAL.
    flags = static_cast<audio_input_flags_t>(flags & ~AUDIO_INPUT_FLAG_DIRECT);
#endif
    if (status_t status = CoreUtils::audioInputFlagsFromHal(flags, &hidlFlags); status != OK) {
        return status;
    }
    Result retval = Result::NOT_INITIALIZED;
#if MAJOR_VERSION == 2
    auto sinkMetadata = AudioSource(source);
#elif MAJOR_VERSION >= 4
    // TODO: correctly propagate the tracks sources and volume
    //       for now, only send the main source at 1dbfs
    AudioSource hidlSource;
    if (status_t status = HidlUtils::audioSourceFromHal(source, &hidlSource); status != OK) {
        return status;
    }
    SinkMetadata sinkMetadata = {{{ .source = std::move(hidlSource), .gain = 1 }}};
#endif
#if MAJOR_VERSION < 5
    (void)outputDevice;
    (void)outputDeviceAddress;
#else
#if MAJOR_VERSION >= 7
    (void)HidlUtils::audioChannelMaskFromHal(
            AUDIO_CHANNEL_NONE, true /*isInput*/, &sinkMetadata.tracks[0].channelMask);
#endif
    if (outputDevice != AUDIO_DEVICE_NONE) {
        DeviceAddress hidlOutputDevice;
        if (status_t status = CoreUtils::deviceAddressFromHal(
                        outputDevice, outputDeviceAddress, &hidlOutputDevice); status != OK) {
            return status;
        }
        sinkMetadata.tracks[0].destination.device(std::move(hidlOutputDevice));
    }
#endif
    Return<void> ret = mDevice->openInputStream(
            handle, hidlDevice, hidlConfig, hidlFlags, sinkMetadata,
            [&](Result r,
                const sp<::android::hardware::audio::CORE_TYPES_CPP_VERSION::IStreamIn>& result,
                    const AudioConfig& suggestedConfig) {
                retval = r;
                if (retval == Result::OK) {
                    *inStream = new StreamInHalHidl(result);
                }
                HidlUtils::audioConfigToHal(suggestedConfig, config);
            });
    const status_t status = processReturn("openInputStream", ret, retval);
    cleanupStreams();
    if (status == NO_ERROR) {
        mStreams.insert({handle, *inStream});
    }
    return status;
}

status_t DeviceHalHidl::supportsAudioPatches(bool *supportsPatches) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    return processReturn("supportsAudioPatches", mDevice->supportsAudioPatches(), supportsPatches);
}

status_t DeviceHalHidl::createAudioPatch(
        unsigned int num_sources,
        const struct audio_port_config *sources,
        unsigned int num_sinks,
        const struct audio_port_config *sinks,
        audio_patch_handle_t *patch) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    if (patch == nullptr) return BAD_VALUE;

#if MAJOR_VERSION < 6
    if (*patch != AUDIO_PATCH_HANDLE_NONE) {
        status_t status = releaseAudioPatch(*patch);
        ALOGW_IF(status != NO_ERROR, "%s error %d releasing patch handle %d",
            __func__, status, *patch);
        *patch = AUDIO_PATCH_HANDLE_NONE;
    }
#endif

    hidl_vec<AudioPortConfig> hidlSources, hidlSinks;
    HidlUtils::audioPortConfigsFromHal(num_sources, sources, &hidlSources);
    HidlUtils::audioPortConfigsFromHal(num_sinks, sinks, &hidlSinks);
    Result retval = Result::OK;
    Return<void> ret;
    std::string methodName = "createAudioPatch";
    if (*patch == AUDIO_PATCH_HANDLE_NONE) {  // always true for MAJOR_VERSION < 6
        ret = mDevice->createAudioPatch(
                hidlSources, hidlSinks,
                [&](Result r, AudioPatchHandle hidlPatch) {
                    retval = r;
                    if (retval == Result::OK) {
                        *patch = static_cast<audio_patch_handle_t>(hidlPatch);
                    }
                });
    } else {
#if MAJOR_VERSION >= 6
        ret = mDevice->updateAudioPatch(
                *patch,
                hidlSources, hidlSinks,
                [&](Result r, AudioPatchHandle hidlPatch) {
                    retval = r;
                    if (retval == Result::OK) {
                        *patch = static_cast<audio_patch_handle_t>(hidlPatch);
                    }
                });
        methodName = "updateAudioPatch";
#endif
    }
    return processReturn(methodName.c_str(), ret, retval);
}

status_t DeviceHalHidl::releaseAudioPatch(audio_patch_handle_t patch) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    return processReturn("releaseAudioPatch", mDevice->releaseAudioPatch(patch));
}

template <typename HalPort>
status_t DeviceHalHidl::getAudioPortImpl(HalPort *port) {
    using ::android::hardware::audio::common::COMMON_TYPES_CPP_VERSION::AudioPort;
    if (mDevice == 0) return NO_INIT;
    AudioPort hidlPort;
    HidlUtils::audioPortFromHal(*port, &hidlPort);
    Result retval;
    Return<void> ret = mDevice->getAudioPort(
            hidlPort,
            [&](Result r, const AudioPort& p) {
                retval = r;
                if (retval == Result::OK) {
                    HidlUtils::audioPortToHal(p, port);
                }
            });
    return processReturn("getAudioPort", ret, retval);
}

status_t DeviceHalHidl::getAudioPort(struct audio_port *port) {
    TIME_CHECK();
    return getAudioPortImpl(port);
}

status_t DeviceHalHidl::getAudioPort(struct audio_port_v7 *port) {
    TIME_CHECK();
#if MAJOR_VERSION >= 7
    return getAudioPortImpl(port);
#else
    struct audio_port audioPort = {};
    status_t result = NO_ERROR;
    if (!audio_populate_audio_port(port, &audioPort)) {
        ALOGE("Failed to populate legacy audio port from audio_port_v7");
        result = BAD_VALUE;
    }
    status_t status = getAudioPort(&audioPort);
    if (status == NO_ERROR) {
        audio_populate_audio_port_v7(&audioPort, port);
    } else {
        result = status;
    }
    return result;
#endif
}

status_t DeviceHalHidl::setAudioPortConfig(const struct audio_port_config *config) {
    using ::android::hardware::audio::common::COMMON_TYPES_CPP_VERSION::AudioPortConfig;
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    AudioPortConfig hidlConfig;
    HidlUtils::audioPortConfigFromHal(*config, &hidlConfig);
    return processReturn("setAudioPortConfig", mDevice->setAudioPortConfig(hidlConfig));
}

#if MAJOR_VERSION == 2
status_t DeviceHalHidl::getMicrophones(
        std::vector<audio_microphone_characteristic_t> *microphonesInfo __unused) {
    if (mDevice == 0) return NO_INIT;
    return INVALID_OPERATION;
}
#elif MAJOR_VERSION >= 4
status_t DeviceHalHidl::getMicrophones(
        std::vector<audio_microphone_characteristic_t> *microphonesInfo) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    Result retval;
    Return<void> ret = mDevice->getMicrophones(
            [&](Result r, hidl_vec<MicrophoneInfo> micArrayHal) {
        retval = r;
        for (size_t k = 0; k < micArrayHal.size(); k++) {
            audio_microphone_characteristic_t dst;
            //convert
            (void)CoreUtils::microphoneInfoToHal(micArrayHal[k], &dst);
            microphonesInfo->push_back(dst);
        }
    });
    return processReturn("getMicrophones", ret, retval);
}
#endif

#if MAJOR_VERSION >= 6
status_t DeviceHalHidl::addDeviceEffect(
        const struct audio_port_config *device, sp<EffectHalInterface> effect) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    auto hidlEffect = sp<effect::EffectHalHidl>::cast(effect);
    return processReturn("addDeviceEffect", mDevice->addDeviceEffect(
            static_cast<AudioPortHandle>(device->id), hidlEffect->effectId()));
}
#else
status_t DeviceHalHidl::addDeviceEffect(
        const struct audio_port_config *device __unused, sp<EffectHalInterface> effect __unused) {
    return INVALID_OPERATION;
}
#endif

#if MAJOR_VERSION >= 6
status_t DeviceHalHidl::removeDeviceEffect(
        const struct audio_port_config *device, sp<EffectHalInterface> effect) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    auto hidlEffect = sp<effect::EffectHalHidl>::cast(effect);
    return processReturn("removeDeviceEffect", mDevice->removeDeviceEffect(
            static_cast<AudioPortHandle>(device->id), hidlEffect->effectId()));
}
#else
status_t DeviceHalHidl::removeDeviceEffect(
        const struct audio_port_config *device __unused, sp<EffectHalInterface> effect __unused) {
    return INVALID_OPERATION;
}
#endif

status_t DeviceHalHidl::prepareToDisconnectExternalDevice(const struct audio_port_v7* port) {
    // For HIDL HAL, there is not API to call notify the HAL to prepare for device connected
    // state changed. Call `setConnectedState` directly.
    const status_t status = setConnectedState(port, false /*connected*/);
    if (status == NO_ERROR) {
        // Cache the port id so that it won't disconnect twice.
        mDeviceDisconnectionNotified.insert(port->id);
    }
    return status;
}

status_t DeviceHalHidl::setConnectedState(const struct audio_port_v7 *port, bool connected) {
    using ::android::hardware::audio::common::COMMON_TYPES_CPP_VERSION::AudioPort;
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    if (!connected && mDeviceDisconnectionNotified.erase(port->id) > 0) {
        // For device disconnection, APM will first call `prepareToDisconnectExternalDevice` and
        // then call `setConnectedState`. However, in HIDL HAL, there is no API for
        // `prepareToDisconnectExternalDevice`. In that case, HIDL HAL will call `setConnectedState`
        // when calling `prepareToDisconnectExternalDevice`. Do not call to the HAL if previous
        // call is successful. Also remove the cache here to avoid a large cache after a long run.
        return NO_ERROR;
    }
#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
    if (supportsSetConnectedState7_1) {
        AudioPort hidlPort;
        if (status_t result = HidlUtils::audioPortFromHal(*port, &hidlPort); result != NO_ERROR) {
            return result;
        }
        Return<Result> ret = mDevice->setConnectedState_7_1(hidlPort, connected);
        if (!ret.isOk() || ret != Result::NOT_SUPPORTED) {
            return processReturn("setConnectedState_7_1", ret);
        } else if (ret == Result::OK) {
            return NO_ERROR;
        }
        supportsSetConnectedState7_1 = false;
    }
#endif
    DeviceAddress hidlAddress;
    if (status_t result = CoreUtils::deviceAddressFromHal(
                    port->ext.device.type, port->ext.device.address, &hidlAddress);
            result != NO_ERROR) {
        return result;
    }
    return processReturn("setConnectedState", mDevice->setConnectedState(hidlAddress, connected));
}

error::Result<audio_hw_sync_t> DeviceHalHidl::getHwAvSync() {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    audio_hw_sync_t value;
    Result result;
    Return<void> ret = mDevice->getHwAvSync([&value, &result](Result r, audio_hw_sync_t v) {
        value = v;
        result = r;
    });
    RETURN_IF_ERROR(processReturn("getHwAvSync", ret, result));
    return value;
}

status_t DeviceHalHidl::dump(int fd, const Vector<String16>& args) {
    TIME_CHECK();
    if (mDevice == 0) return NO_INIT;
    native_handle_t* hidlHandle = native_handle_create(1, 0);
    hidlHandle->data[0] = fd;
    hidl_vec<hidl_string> hidlArgs;
    argsFromHal(args, &hidlArgs);
    Return<void> ret = mDevice->debug(hidlHandle, hidlArgs);
    native_handle_delete(hidlHandle);

    // TODO(b/111997867, b/177271958)  Workaround - remove when fixed.
    // A Binder transmitted fd may not close immediately due to a race condition b/111997867
    // when the remote binder thread removes the last refcount to the fd blocks in the
    // kernel for binder activity. We send a Binder ping() command to unblock the thread
    // and complete the fd close / release.
    //
    // See DeviceHalHidl::dump(), EffectHalHidl::dump(), StreamHalHidl::dump(),
    //     EffectsFactoryHalHidl::dumpEffects().

    (void)mDevice->ping(); // synchronous Binder call

    return processReturn("dump", ret);
}

#if MAJOR_VERSION == 7 && MINOR_VERSION == 1
status_t DeviceHalHidl::getSoundDoseInterface(const std::string& module,
                                              ::ndk::SpAIBinder* soundDoseBinder) {
    if (mSoundDoseWrapper->mSoundDose != nullptr) {
        *soundDoseBinder = mSoundDoseWrapper->mSoundDose->asBinder();
        return OK;
    }

    if (mSoundDoseWrapper->mSoundDoseFactory == nullptr) {
        std::string interface =
            std::string(ISoundDoseFactory::descriptor) + kSoundDoseInterfaceModule.data();
        AIBinder* binder = AServiceManager_checkService(interface.c_str());
        if (binder == nullptr) {
            ALOGW("%s service %s doesn't exist", __func__, interface.c_str());
            return NO_INIT;
        }
        mSoundDoseWrapper->mSoundDoseFactory =
                ISoundDoseFactory::fromBinder(ndk::SpAIBinder(binder));
    }

    auto result = mSoundDoseWrapper->mSoundDoseFactory->getSoundDose(
                        module, &mSoundDoseWrapper->mSoundDose);
    if (!result.isOk()) {
        ALOGW("%s could not get sound dose interface: %s", __func__, result.getMessage());
        return BAD_VALUE;
    }

    if (mSoundDoseWrapper->mSoundDose == nullptr) {
        ALOGW("%s standalone sound dose interface is not implemented", __func__);
        *soundDoseBinder = nullptr;
        return OK;
    }

    *soundDoseBinder = mSoundDoseWrapper->mSoundDose->asBinder();
    ALOGI("%s using standalone sound dose interface", __func__);
    return OK;
}
#else
status_t DeviceHalHidl::getSoundDoseInterface(const std::string& module,
                                              ::ndk::SpAIBinder* soundDoseBinder) {
    (void)module;  // avoid unused param
    (void)soundDoseBinder;  // avoid unused param
    return INVALID_OPERATION;
}
#endif

status_t DeviceHalHidl::supportsBluetoothVariableLatency(bool* supports) {
    if (supports == nullptr) {
        return BAD_VALUE;
    }
    *supports = false;

    String8 reply;
    status_t status = getParameters(
            String8(AUDIO_PARAMETER_BT_VARIABLE_LATENCY_SUPPORTED), &reply);
    if (status != NO_ERROR) {
        return status;
    }
    AudioParameter replyParams(reply);
    String8 trueOrFalse;
    status = replyParams.get(
            String8(AUDIO_PARAMETER_BT_VARIABLE_LATENCY_SUPPORTED), trueOrFalse);
    if (status != NO_ERROR) {
        return status;
    }
    *supports = trueOrFalse == AudioParameter::valueTrue;
    return NO_ERROR;
}

namespace {

status_t getParametersFromStream(
        sp<StreamHalInterface> stream,
        const char* parameters,
        const char* extraParameters,
        String8* reply) {
    String8 request(parameters);
    if (extraParameters != nullptr) {
        request.append(";");
        request.append(extraParameters);
    }
    status_t status = stream->getParameters(request, reply);
    if (status != NO_ERROR) {
        ALOGW("%s, failed to query %s, status=%d", __func__, parameters, status);
        return status;
    }
    AudioParameter repliedParameters(*reply);
    status = repliedParameters.get(String8(parameters), *reply);
    if (status != NO_ERROR) {
        ALOGW("%s: failed to retrieve %s, bailing out", __func__, parameters);
    }
    return status;
}

} // namespace

status_t DeviceHalHidl::getAudioMixPort(const struct audio_port_v7 *devicePort,
                                        struct audio_port_v7 *mixPort) {
    // For HIDL HAL, querying mix port information is not supported. If the HAL supports
    // `getAudioPort` API to query the device port attributes, use the structured audio profiles
    // that have the same attributes reported by the `getParameters` API. Otherwise, only use
    // the attributes reported by `getParameters` API.
    struct audio_port_v7 temp = *devicePort;
    AudioProfileAttributesMultimap attrsFromDevice;
    bool supportsPatches;
    if (supportsAudioPatches(&supportsPatches) == OK && supportsPatches) {
        // The audio patches are supported since HAL 3.0, which is the same HAL version
        // requirement for 'getAudioPort' API.
        if (getAudioPort(&temp) == NO_ERROR) {
            attrsFromDevice = createAudioProfilesAttrMap(temp.audio_profiles, 0 /*first*/,
                                                         temp.num_audio_profiles);
        }
    }
    auto streamIt = mStreams.find(mixPort->ext.mix.handle);
    if (streamIt == mStreams.end()) {
        return BAD_VALUE;
    }
    auto stream = streamIt->second.promote();
    if (stream == nullptr) {
        return BAD_VALUE;
    }

    String8 formatsStr;
    status_t status = getParametersFromStream(
            stream, AudioParameter::keyStreamSupportedFormats, nullptr /*extraParameters*/,
            &formatsStr);
    if (status != NO_ERROR) {
        return status;
    }
    FormatVector formats = formatsFromString(formatsStr.c_str());

    mixPort->num_audio_profiles = 0;
    for (audio_format_t format : formats) {
        if (mixPort->num_audio_profiles >= AUDIO_PORT_MAX_AUDIO_PROFILES) {
            ALOGW("%s, too many audio profiles", __func__);
            break;
        }
        AudioParameter formatParameter;
        formatParameter.addInt(String8(AudioParameter::keyFormat), format);

        String8 samplingRatesStr;
        status = getParametersFromStream(
                stream, AudioParameter::keyStreamSupportedSamplingRates,
                formatParameter.toString(), &samplingRatesStr);
        if (status != NO_ERROR) {
            // Failed to query supported sample rate for current format, may succeed with
            // other formats.
            ALOGW("Skip adding format=%#x, status=%d", format, status);
            continue;
        }
        SampleRateSet sampleRatesFromStream = samplingRatesFromString(samplingRatesStr.c_str());
        if (sampleRatesFromStream.empty()) {
            ALOGW("Skip adding format=%#x as the returned sampling rates are empty", format);
            continue;
        }
        String8 channelMasksStr;
        status = getParametersFromStream(
                stream, AudioParameter::keyStreamSupportedChannels,
                formatParameter.toString(), &channelMasksStr);
        if (status != NO_ERROR) {
            // Failed to query supported channel masks for current format, may succeed with
            // other formats.
            ALOGW("Skip adding format=%#x, status=%d", format, status);
            continue;
        }
        ChannelMaskSet channelMasksFromStream = channelMasksFromString(channelMasksStr.c_str());
        if (channelMasksFromStream.empty()) {
            ALOGW("Skip adding format=%#x as the returned channel masks are empty", format);
            continue;
        }

        // For an audio format, all audio profiles from the device port with the same format will
        // be added to mix port after filtering sample rates, channel masks according to the reply
        // of getParameters API. If there is any sample rate or channel mask reported by
        // getParameters API but not reported by the device, additional audio profiles will be
        // added.
        populateAudioProfiles(attrsFromDevice, format, channelMasksFromStream,
                              sampleRatesFromStream, mixPort->audio_profiles,
                              &mixPort->num_audio_profiles);
    }

    return NO_ERROR;
}

void DeviceHalHidl::cleanupStreams() {
    for (auto it = mStreams.begin(); it != mStreams.end();) {
        if (it->second.promote() == nullptr) {
            it = mStreams.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace android
