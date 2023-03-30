/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "DeviceHalAidl"
// #define LOG_NDEBUG 0

#include <algorithm>
#include <forward_list>

#include <aidl/android/hardware/audio/core/BnStreamCallback.h>
#include <aidl/android/hardware/audio/core/BnStreamOutEventCallback.h>
#include <aidl/android/hardware/audio/core/StreamDescriptor.h>
#include <android/binder_enums.h>
#include <binder/Enums.h>
#include <error/expected_utils.h>
#include <media/AidlConversionCppNdk.h>
#include <media/AidlConversionUtil.h>
#include <mediautils/TimeCheck.h>
#include <Utils.h>
#include <utils/Log.h>

#include "DeviceHalAidl.h"
#include "StreamHalAidl.h"

using aidl::android::aidl_utils::statusTFromBinderStatus;
using aidl::android::media::audio::common::AudioConfig;
using aidl::android::media::audio::common::AudioDevice;
using aidl::android::media::audio::common::AudioDeviceAddress;
using aidl::android::media::audio::common::AudioDeviceType;
using aidl::android::media::audio::common::AudioInputFlags;
using aidl::android::media::audio::common::AudioIoFlags;
using aidl::android::media::audio::common::AudioLatencyMode;
using aidl::android::media::audio::common::AudioMMapPolicy;
using aidl::android::media::audio::common::AudioMMapPolicyInfo;
using aidl::android::media::audio::common::AudioMMapPolicyType;
using aidl::android::media::audio::common::AudioMode;
using aidl::android::media::audio::common::AudioOutputFlags;
using aidl::android::media::audio::common::AudioPort;
using aidl::android::media::audio::common::AudioPortConfig;
using aidl::android::media::audio::common::AudioPortDeviceExt;
using aidl::android::media::audio::common::AudioPortExt;
using aidl::android::media::audio::common::AudioPortMixExt;
using aidl::android::media::audio::common::AudioPortMixExtUseCase;
using aidl::android::media::audio::common::AudioSource;
using aidl::android::media::audio::common::Float;
using aidl::android::media::audio::common::Int;
using aidl::android::media::audio::common::MicrophoneDynamicInfo;
using aidl::android::media::audio::common::MicrophoneInfo;
using aidl::android::hardware::audio::common::getFrameSizeInBytes;
using aidl::android::hardware::audio::common::isBitPositionFlagSet;
using aidl::android::hardware::audio::common::makeBitPositionFlagMask;
using aidl::android::hardware::audio::common::RecordTrackMetadata;
using aidl::android::hardware::audio::core::AudioPatch;
using aidl::android::hardware::audio::core::IModule;
using aidl::android::hardware::audio::core::ITelephony;
using aidl::android::hardware::audio::core::StreamDescriptor;

namespace android {

namespace {

bool isConfigEqualToPortConfig(const AudioConfig& config, const AudioPortConfig& portConfig) {
    return portConfig.sampleRate.value().value == config.base.sampleRate &&
            portConfig.channelMask.value() == config.base.channelMask &&
            portConfig.format.value() == config.base.format;
}

void setConfigFromPortConfig(AudioConfig* config, const AudioPortConfig& portConfig) {
    config->base.sampleRate = portConfig.sampleRate.value().value;
    config->base.channelMask = portConfig.channelMask.value();
    config->base.format = portConfig.format.value();
}

void setPortConfigFromConfig(AudioPortConfig* portConfig, const AudioConfig& config) {
    portConfig->sampleRate = Int{ .value = config.base.sampleRate };
    portConfig->channelMask = config.base.channelMask;
    portConfig->format = config.base.format;
}

template<typename OutEnum, typename OutEnumRange, typename InEnum>
ConversionResult<OutEnum> convertEnum(const OutEnumRange& range, InEnum e) {
    using InIntType = std::underlying_type_t<InEnum>;
    static_assert(std::is_same_v<InIntType, std::underlying_type_t<OutEnum>>);

    InIntType inEnumIndex = static_cast<InIntType>(e);
    OutEnum outEnum = static_cast<OutEnum>(inEnumIndex);
    if (std::find(range.begin(), range.end(), outEnum) == range.end()) {
        return ::android::base::unexpected(BAD_VALUE);
    }
    return outEnum;
}

template<typename NdkEnum, typename CppEnum>
ConversionResult<NdkEnum> cpp2ndk_Enum(CppEnum e) {
    return convertEnum<NdkEnum>(::ndk::enum_range<NdkEnum>(), e);
}

template<typename CppEnum, typename NdkEnum>
ConversionResult<CppEnum> ndk2cpp_Enum(NdkEnum e) {
    return convertEnum<CppEnum>(::android::enum_range<CppEnum>(), e);
}

ConversionResult<android::media::audio::common::AudioDeviceAddress>
ndk2cpp_AudioDeviceAddress(const AudioDeviceAddress& ndk) {
    using CppTag = android::media::audio::common::AudioDeviceAddress::Tag;
    using NdkTag = AudioDeviceAddress::Tag;

    CppTag cppTag = VALUE_OR_RETURN(ndk2cpp_Enum<CppTag>(ndk.getTag()));

    switch (cppTag) {
        case CppTag::id:
            return android::media::audio::common::AudioDeviceAddress::make<CppTag::id>(
                    ndk.get<NdkTag::id>());
        case CppTag::mac:
            return android::media::audio::common::AudioDeviceAddress::make<CppTag::mac>(
                    ndk.get<NdkTag::mac>());
        case CppTag::ipv4:
            return android::media::audio::common::AudioDeviceAddress::make<CppTag::ipv4>(
                    ndk.get<NdkTag::ipv4>());
        case CppTag::ipv6:
            return android::media::audio::common::AudioDeviceAddress::make<CppTag::ipv6>(
                    ndk.get<NdkTag::ipv6>());
        case CppTag::alsa:
            return android::media::audio::common::AudioDeviceAddress::make<CppTag::alsa>(
                    ndk.get<NdkTag::alsa>());
    }

    return ::android::base::unexpected(BAD_VALUE);
}

ConversionResult<media::audio::common::AudioDevice> ndk2cpp_AudioDevice(const AudioDevice& ndk) {
    media::audio::common::AudioDevice cpp;
    cpp.type.type = VALUE_OR_RETURN(
            ndk2cpp_Enum<media::audio::common::AudioDeviceType>(ndk.type.type));
    cpp.type.connection = ndk.type.connection;
    cpp.address = VALUE_OR_RETURN(ndk2cpp_AudioDeviceAddress(ndk.address));
    return cpp;
}

ConversionResult<media::audio::common::AudioMMapPolicyInfo>
ndk2cpp_AudioMMapPolicyInfo(const AudioMMapPolicyInfo& ndk) {
    media::audio::common::AudioMMapPolicyInfo cpp;
    cpp.device = VALUE_OR_RETURN(ndk2cpp_AudioDevice(ndk.device));
    cpp.mmapPolicy = VALUE_OR_RETURN(
            ndk2cpp_Enum<media::audio::common::AudioMMapPolicy>(ndk.mmapPolicy));
    return cpp;
}

}  // namespace

status_t DeviceHalAidl::getSupportedDevices(uint32_t*) {
    // Obsolete.
    return INVALID_OPERATION;
}

status_t DeviceHalAidl::initCheck() {
    TIME_CHECK();
    if (mModule == nullptr) return NO_INIT;
    std::vector<AudioPort> ports;
    RETURN_STATUS_IF_ERROR(
            statusTFromBinderStatus(mModule->getAudioPorts(&ports)));
    ALOGW_IF(ports.empty(), "%s: module %s returned an empty list of audio ports",
            __func__, mInstance.c_str());
    std::transform(ports.begin(), ports.end(), std::inserter(mPorts, mPorts.end()),
            [](const auto& p) { return std::make_pair(p.id, p); });
    mDefaultInputPortId = mDefaultOutputPortId = -1;
    const int defaultDeviceFlag = 1 << AudioPortDeviceExt::FLAG_INDEX_DEFAULT_DEVICE;
    for (const auto& pair : mPorts) {
        const auto& p = pair.second;
        if (p.ext.getTag() == AudioPortExt::Tag::device &&
                (p.ext.get<AudioPortExt::Tag::device>().flags & defaultDeviceFlag) != 0) {
            if (p.flags.getTag() == AudioIoFlags::Tag::input) {
                mDefaultInputPortId = p.id;
            } else if (p.flags.getTag() == AudioIoFlags::Tag::output) {
                mDefaultOutputPortId = p.id;
            }
        }
    }
    ALOGI("%s: module %s default port ids: input %d, output %d",
            __func__, mInstance.c_str(), mDefaultInputPortId, mDefaultOutputPortId);
    std::vector<AudioPortConfig> portConfigs;
    RETURN_STATUS_IF_ERROR(
            statusTFromBinderStatus(mModule->getAudioPortConfigs(&portConfigs)));  // OK if empty
    std::transform(portConfigs.begin(), portConfigs.end(),
            std::inserter(mPortConfigs, mPortConfigs.end()),
            [](const auto& p) { return std::make_pair(p.id, p); });
    std::vector<AudioPatch> patches;
    RETURN_STATUS_IF_ERROR(
            statusTFromBinderStatus(mModule->getAudioPatches(&patches)));  // OK if empty
    std::transform(patches.begin(), patches.end(),
            std::inserter(mPatches, mPatches.end()),
            [](const auto& p) { return std::make_pair(p.id, p); });
    return OK;
}

status_t DeviceHalAidl::setVoiceVolume(float volume) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    std::shared_ptr<ITelephony> telephony;
    if (ndk::ScopedAStatus status = mModule->getTelephony(&telephony);
            status.isOk() && telephony != nullptr) {
        ITelephony::TelecomConfig inConfig{ .voiceVolume = Float{volume} }, outConfig;
        RETURN_STATUS_IF_ERROR(
                statusTFromBinderStatus(telephony->setTelecomConfig(inConfig, &outConfig)));
        ALOGW_IF(outConfig.voiceVolume.has_value() && volume != outConfig.voiceVolume.value().value,
                "%s: the resulting voice volume %f is not the same as requested %f",
                __func__, outConfig.voiceVolume.value().value, volume);
    }
    return INVALID_OPERATION;
}

status_t DeviceHalAidl::setMasterVolume(float volume) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return statusTFromBinderStatus(mModule->setMasterVolume(volume));
}

status_t DeviceHalAidl::getMasterVolume(float *volume) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return statusTFromBinderStatus(mModule->getMasterVolume(volume));
}

status_t DeviceHalAidl::setMode(audio_mode_t mode) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    AudioMode audioMode = VALUE_OR_FATAL(::aidl::android::legacy2aidl_audio_mode_t_AudioMode(mode));
    std::shared_ptr<ITelephony> telephony;
    if (ndk::ScopedAStatus status = mModule->getTelephony(&telephony);
            status.isOk() && telephony != nullptr) {
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(telephony->switchAudioMode(audioMode)));
    }
    return statusTFromBinderStatus(mModule->updateAudioMode(audioMode));
}

status_t DeviceHalAidl::setMicMute(bool state) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return statusTFromBinderStatus(mModule->setMicMute(state));
}

status_t DeviceHalAidl::getMicMute(bool *state) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return statusTFromBinderStatus(mModule->getMicMute(state));
}

status_t DeviceHalAidl::setMasterMute(bool state) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return statusTFromBinderStatus(mModule->setMasterMute(state));
}

status_t DeviceHalAidl::getMasterMute(bool *state) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return statusTFromBinderStatus(mModule->getMasterMute(state));
}

status_t DeviceHalAidl::setParameters(const String8& kvPairs __unused) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t DeviceHalAidl::getParameters(const String8& keys __unused, String8 *values) {
    TIME_CHECK();
    values->clear();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

namespace {

class Cleanup {
  public:
    typedef void (DeviceHalAidl::*Cleaner)(int32_t);

    Cleanup(DeviceHalAidl* device, Cleaner cleaner, int32_t id) :
            mDevice(device), mCleaner(cleaner), mId(id) {}
    ~Cleanup() { clean(); }
    void clean() {
        if (mDevice != nullptr) (mDevice->*mCleaner)(mId);
        disarm();
    }
    void disarm() { mDevice = nullptr; }

  private:
    DeviceHalAidl* mDevice;
    const Cleaner mCleaner;
    const int32_t mId;
};

}  // namespace

// Since the order of container elements destruction is unspecified,
// ensure that cleanups are performed from the most recent one and upwards.
// This is the same as if there were individual Cleanup instances on the stack,
// however the bonus is that we can disarm all of them with just one statement.
class DeviceHalAidl::Cleanups : public std::forward_list<Cleanup> {
  public:
    ~Cleanups() { for (auto& c : *this) c.clean(); }
    void disarmAll() { for (auto& c : *this) c.disarm(); }
};

status_t DeviceHalAidl::getInputBufferSize(const struct audio_config* config, size_t* size) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    if (size == nullptr) return BAD_VALUE;
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    AudioConfig aidlConfig = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_config_t_AudioConfig(*config, true /*isInput*/));
    AudioDevice aidlDevice;
    aidlDevice.type.type = AudioDeviceType::IN_DEFAULT;
    AudioSource aidlSource = AudioSource::DEFAULT;
    AudioIoFlags aidlFlags = AudioIoFlags::make<AudioIoFlags::Tag::input>(0);
    AudioPortConfig mixPortConfig;
    Cleanups cleanups;
    audio_config writableConfig = *config;
    int32_t nominalLatency;
    RETURN_STATUS_IF_ERROR(prepareToOpenStream(0 /*handle*/, aidlDevice, aidlFlags, aidlSource,
                    &writableConfig, &cleanups, &aidlConfig, &mixPortConfig, &nominalLatency));
    *size = aidlConfig.frameCount *
            getFrameSizeInBytes(aidlConfig.base.format, aidlConfig.base.channelMask);
    // Do not disarm cleanups to release temporary port configs.
    return OK;
}

status_t DeviceHalAidl::prepareToOpenStream(
        int32_t aidlHandle, const AudioDevice& aidlDevice, const AudioIoFlags& aidlFlags,
        AudioSource aidlSource, struct audio_config* config,
        Cleanups* cleanups, AudioConfig* aidlConfig, AudioPortConfig* mixPortConfig,
        int32_t* nominalLatency) {
    const bool isInput = aidlFlags.getTag() == AudioIoFlags::Tag::input;
    // Find / create AudioPortConfigs for the device port and the mix port,
    // then find / create a patch between them, and open a stream on the mix port.
    AudioPortConfig devicePortConfig;
    bool created = false;
    RETURN_STATUS_IF_ERROR(findOrCreatePortConfig(aidlDevice, &devicePortConfig, &created));
    if (created) {
        cleanups->emplace_front(this, &DeviceHalAidl::resetPortConfig, devicePortConfig.id);
    }
    RETURN_STATUS_IF_ERROR(findOrCreatePortConfig(*aidlConfig, aidlFlags, aidlHandle, aidlSource,
                    mixPortConfig, &created));
    if (created) {
        cleanups->emplace_front(this, &DeviceHalAidl::resetPortConfig, mixPortConfig->id);
    }
    setConfigFromPortConfig(aidlConfig, *mixPortConfig);
    AudioPatch patch;
    if (isInput) {
        RETURN_STATUS_IF_ERROR(findOrCreatePatch(
                        {devicePortConfig.id}, {mixPortConfig->id}, &patch, &created));
    } else {
        RETURN_STATUS_IF_ERROR(findOrCreatePatch(
                        {mixPortConfig->id}, {devicePortConfig.id}, &patch, &created));
    }
    if (created) {
        cleanups->emplace_front(this, &DeviceHalAidl::resetPatch, patch.id);
    }
    *nominalLatency = patch.latenciesMs[0];
    if (aidlConfig->frameCount <= 0) {
        aidlConfig->frameCount = patch.minimumStreamBufferSizeFrames;
    }
    *config = VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_AudioConfig_audio_config_t(*aidlConfig, isInput));
    return OK;
}

namespace {

class StreamCallbackBase {
  protected:
    explicit StreamCallbackBase(const sp<CallbackBroker>& broker) : mBroker(broker) {}
  public:
    void* getCookie() const { return mCookie; }
    void setCookie(void* cookie) { mCookie = cookie; }
    sp<CallbackBroker> getBroker() const {
        if (void* cookie = mCookie; cookie != nullptr) return mBroker.promote();
        return nullptr;
    }
  private:
    const wp<CallbackBroker> mBroker;
    std::atomic<void*> mCookie;
};

template<class C>
class StreamCallbackBaseHelper {
  protected:
    explicit StreamCallbackBaseHelper(const StreamCallbackBase& base) : mBase(base) {}
    sp<C> getCb(const sp<CallbackBroker>& broker, void* cookie);
    using CbRef = const sp<C>&;
    ndk::ScopedAStatus runCb(const std::function<void(CbRef cb)>& f) {
        if (auto cb = getCb(mBase.getBroker(), mBase.getCookie()); cb != nullptr) f(cb);
        return ndk::ScopedAStatus::ok();
    }
  private:
    const StreamCallbackBase& mBase;
};

template<>
sp<StreamOutHalInterfaceCallback> StreamCallbackBaseHelper<StreamOutHalInterfaceCallback>::getCb(
        const sp<CallbackBroker>& broker, void* cookie) {
    if (broker != nullptr) return broker->getStreamOutCallback(cookie);
    return nullptr;
}

template<>
sp<StreamOutHalInterfaceEventCallback>
StreamCallbackBaseHelper<StreamOutHalInterfaceEventCallback>::getCb(
        const sp<CallbackBroker>& broker, void* cookie) {
    if (broker != nullptr) return broker->getStreamOutEventCallback(cookie);
    return nullptr;
}

template<>
sp<StreamOutHalInterfaceLatencyModeCallback>
StreamCallbackBaseHelper<StreamOutHalInterfaceLatencyModeCallback>::getCb(
        const sp<CallbackBroker>& broker, void* cookie) {
    if (broker != nullptr) return broker->getStreamOutLatencyModeCallback(cookie);
    return nullptr;
}

/*
Note on the callback ownership.

In the Binder ownership model, the server implementation is kept alive
as long as there is any client (proxy object) alive. This is done by
incrementing the refcount of the server-side object by the Binder framework.
When it detects that the last client is gone, it decrements the refcount back.

Thus, it is not needed to keep any references to StreamCallback on our
side (after we have sent an instance to the client), because we are
the server-side. The callback object will be kept alive as long as the HAL server
holds a strong ref to IStreamCallback proxy.
*/

class OutputStreamCallbackAidl : public StreamCallbackBase,
                             public StreamCallbackBaseHelper<StreamOutHalInterfaceCallback>,
                             public ::aidl::android::hardware::audio::core::BnStreamCallback {
  public:
    explicit OutputStreamCallbackAidl(const sp<CallbackBroker>& broker)
            : StreamCallbackBase(broker),
              StreamCallbackBaseHelper<StreamOutHalInterfaceCallback>(
                      *static_cast<StreamCallbackBase*>(this)) {}
    ndk::ScopedAStatus onTransferReady() override {
        return runCb([](CbRef cb) { cb->onWriteReady(); });
    }
    ndk::ScopedAStatus onError() override {
        return runCb([](CbRef cb) { cb->onError(); });
    }
    ndk::ScopedAStatus onDrainReady() override {
        return runCb([](CbRef cb) { cb->onDrainReady(); });
    }
};

class OutputStreamEventCallbackAidl :
            public StreamCallbackBase,
            public StreamCallbackBaseHelper<StreamOutHalInterfaceEventCallback>,
            public StreamCallbackBaseHelper<StreamOutHalInterfaceLatencyModeCallback>,
            public ::aidl::android::hardware::audio::core::BnStreamOutEventCallback {
  public:
    explicit OutputStreamEventCallbackAidl(const sp<CallbackBroker>& broker)
            : StreamCallbackBase(broker),
              StreamCallbackBaseHelper<StreamOutHalInterfaceEventCallback>(
                      *static_cast<StreamCallbackBase*>(this)),
              StreamCallbackBaseHelper<StreamOutHalInterfaceLatencyModeCallback>(
                      *static_cast<StreamCallbackBase*>(this)) {}
    ndk::ScopedAStatus onCodecFormatChanged(const std::vector<uint8_t>& in_audioMetadata) override {
        std::basic_string<uint8_t> halMetadata(in_audioMetadata.begin(), in_audioMetadata.end());
        return StreamCallbackBaseHelper<StreamOutHalInterfaceEventCallback>::runCb(
                [&halMetadata](auto cb) { cb->onCodecFormatChanged(halMetadata); });
    }
    ndk::ScopedAStatus onRecommendedLatencyModeChanged(
            const std::vector<AudioLatencyMode>& in_modes) override {
        auto halModes = VALUE_OR_FATAL(
                ::aidl::android::convertContainer<std::vector<audio_latency_mode_t>>(
                        in_modes,
                        ::aidl::android::aidl2legacy_AudioLatencyMode_audio_latency_mode_t));
        return StreamCallbackBaseHelper<StreamOutHalInterfaceLatencyModeCallback>::runCb(
                [&halModes](auto cb) { cb->onRecommendedLatencyModeChanged(halModes); });
    }
};

}  // namespace

status_t DeviceHalAidl::openOutputStream(
        audio_io_handle_t handle, audio_devices_t devices,
        audio_output_flags_t flags, struct audio_config* config,
        const char* address,
        sp<StreamOutHalInterface>* outStream) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    if (!outStream || !config) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    int32_t aidlHandle = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_io_handle_t_int32_t(handle));
    AudioConfig aidlConfig = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_config_t_AudioConfig(*config, false /*isInput*/));
    AudioDevice aidlDevice = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_device_AudioDevice(devices, address));
    int32_t aidlOutputFlags = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_output_flags_t_int32_t_mask(flags));
    AudioIoFlags aidlFlags = AudioIoFlags::make<AudioIoFlags::Tag::output>(aidlOutputFlags);
    AudioPortConfig mixPortConfig;
    Cleanups cleanups;
    int32_t nominalLatency;
    RETURN_STATUS_IF_ERROR(prepareToOpenStream(aidlHandle, aidlDevice, aidlFlags,
                    AudioSource::SYS_RESERVED_INVALID /*only needed for input*/,
                    config, &cleanups, &aidlConfig, &mixPortConfig, &nominalLatency));
    ::aidl::android::hardware::audio::core::IModule::OpenOutputStreamArguments args;
    args.portConfigId = mixPortConfig.id;
    const bool isOffload = isBitPositionFlagSet(
            aidlOutputFlags, AudioOutputFlags::COMPRESS_OFFLOAD);
    std::shared_ptr<OutputStreamCallbackAidl> streamCb;
    if (isOffload) {
        streamCb = ndk::SharedRefBase::make<OutputStreamCallbackAidl>(this);
    }
    auto eventCb = ndk::SharedRefBase::make<OutputStreamEventCallbackAidl>(this);
    if (isOffload) {
        args.offloadInfo = aidlConfig.offloadInfo;
        args.callback = streamCb;
    }
    args.bufferSizeFrames = aidlConfig.frameCount;
    args.eventCallback = eventCb;
    ::aidl::android::hardware::audio::core::IModule::OpenOutputStreamReturn ret;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->openOutputStream(args, &ret)));
    StreamContextAidl context(ret.desc, isOffload);
    if (!context.isValid()) {
        ALOGE("%s: Failed to created a valid stream context from the descriptor: %s",
                __func__, ret.desc.toString().c_str());
        return NO_INIT;
    }
    *outStream = sp<StreamOutHalAidl>::make(*config, std::move(context), nominalLatency,
            std::move(ret.stream), this /*callbackBroker*/);
    void* cbCookie = (*outStream).get();
    {
        std::lock_guard l(mLock);
        mCallbacks.emplace(cbCookie, Callbacks{});
    }
    if (streamCb) streamCb->setCookie(cbCookie);
    eventCb->setCookie(cbCookie);
    cleanups.disarmAll();
    return OK;
}

status_t DeviceHalAidl::openInputStream(
        audio_io_handle_t handle, audio_devices_t devices,
        struct audio_config* config, audio_input_flags_t flags,
        const char* address, audio_source_t source,
        audio_devices_t outputDevice, const char* outputDeviceAddress,
        sp<StreamInHalInterface>* inStream) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    if (!inStream || !config) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    int32_t aidlHandle = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_io_handle_t_int32_t(handle));
    AudioConfig aidlConfig = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_config_t_AudioConfig(*config, true /*isInput*/));
    AudioDevice aidlDevice = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_device_AudioDevice(devices, address));
    int32_t aidlInputFlags = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_input_flags_t_int32_t_mask(flags));
    AudioIoFlags aidlFlags = AudioIoFlags::make<AudioIoFlags::Tag::input>(aidlInputFlags);
    AudioSource aidlSource = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_source_t_AudioSource(source));
    AudioPortConfig mixPortConfig;
    Cleanups cleanups;
    int32_t nominalLatency;
    RETURN_STATUS_IF_ERROR(prepareToOpenStream(aidlHandle, aidlDevice, aidlFlags, aidlSource,
                    config, &cleanups, &aidlConfig, &mixPortConfig, &nominalLatency));
    ::aidl::android::hardware::audio::core::IModule::OpenInputStreamArguments args;
    args.portConfigId = mixPortConfig.id;
    RecordTrackMetadata aidlTrackMetadata{
        .source = aidlSource, .gain = 1, .channelMask = aidlConfig.base.channelMask };
    if (outputDevice != AUDIO_DEVICE_NONE) {
        aidlTrackMetadata.destinationDevice = VALUE_OR_RETURN_STATUS(
            ::aidl::android::legacy2aidl_audio_device_AudioDevice(
                    outputDevice, outputDeviceAddress));
    }
    args.sinkMetadata.tracks.push_back(std::move(aidlTrackMetadata));
    args.bufferSizeFrames = aidlConfig.frameCount;
    ::aidl::android::hardware::audio::core::IModule::OpenInputStreamReturn ret;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->openInputStream(args, &ret)));
    StreamContextAidl context(ret.desc, false /*isAsynchronous*/);
    if (!context.isValid()) {
        ALOGE("%s: Failed to created a valid stream context from the descriptor: %s",
                __func__, ret.desc.toString().c_str());
        return NO_INIT;
    }
    *inStream = sp<StreamInHalAidl>::make(*config, std::move(context), nominalLatency,
            std::move(ret.stream), this /*micInfoProvider*/);
    cleanups.disarmAll();
    return OK;
}

status_t DeviceHalAidl::supportsAudioPatches(bool* supportsPatches) {
    *supportsPatches = true;
    return OK;
}

status_t DeviceHalAidl::createAudioPatch(unsigned int num_sources,
                                         const struct audio_port_config* sources,
                                         unsigned int num_sinks,
                                         const struct audio_port_config* sinks,
                                         audio_patch_handle_t* patch) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    if (num_sinks > AUDIO_PATCH_PORTS_MAX || num_sources > AUDIO_PATCH_PORTS_MAX ||
        sources == nullptr || sinks == nullptr || patch == nullptr) {
        return BAD_VALUE;
    }
    // When the patch handle (*patch) is AUDIO_PATCH_HANDLE_NONE, it means
    // the framework wants to create a new patch. The handle has to be generated
    // by the HAL. Since handles generated this way can only be unique within
    // a HAL module, the framework generates a globally unique handle, and maps
    // it on the <HAL module, patch handle> pair.
    // When the patch handle is set, it meant the framework intends to update
    // an existing patch.
    //
    // This behavior corresponds to HAL module behavior, with the only difference
    // that the HAL module uses `int32_t` for patch IDs. The following assert ensures
    // that both the framework and the HAL use the same value for "no ID":
    static_assert(AUDIO_PATCH_HANDLE_NONE == 0);
    int32_t halPatchId = static_cast<int32_t>(*patch);

    // Upon conversion, mix port configs contain audio configuration, while
    // device port configs contain device address. This data is used to find
    // or create HAL configs.
    std::vector<AudioPortConfig> aidlSources, aidlSinks;
    for (unsigned int i = 0; i < num_sources; ++i) {
        bool isInput = VALUE_OR_RETURN_STATUS(::aidl::android::portDirection(
                        sources[i].role, sources[i].type)) ==
                ::aidl::android::AudioPortDirection::INPUT;
        aidlSources.push_back(VALUE_OR_RETURN_STATUS(
                        ::aidl::android::legacy2aidl_audio_port_config_AudioPortConfig(
                                sources[i], isInput, 0)));
    }
    for (unsigned int i = 0; i < num_sinks; ++i) {
        bool isInput = VALUE_OR_RETURN_STATUS(::aidl::android::portDirection(
                        sinks[i].role, sinks[i].type)) ==
                ::aidl::android::AudioPortDirection::INPUT;
        aidlSinks.push_back(VALUE_OR_RETURN_STATUS(
                        ::aidl::android::legacy2aidl_audio_port_config_AudioPortConfig(
                                sinks[i], isInput, 0)));
    }
    Cleanups cleanups;
    auto existingPatchIt = halPatchId != 0 ? mPatches.find(halPatchId): mPatches.end();
    AudioPatch aidlPatch;
    if (existingPatchIt != mPatches.end()) {
        aidlPatch = existingPatchIt->second;
        aidlPatch.sourcePortConfigIds.clear();
        aidlPatch.sinkPortConfigIds.clear();
    }
    ALOGD("%s: sources: %s, sinks: %s",
            __func__, ::android::internal::ToString(aidlSources).c_str(),
            ::android::internal::ToString(aidlSinks).c_str());
    auto fillPortConfigs = [&](
            const std::vector<AudioPortConfig>& configs, std::vector<int32_t>* ids) -> status_t {
        for (const auto& s : configs) {
            AudioPortConfig portConfig;
            bool created = false;
            RETURN_STATUS_IF_ERROR(findOrCreatePortConfig(s, &portConfig, &created));
            if (created) {
                cleanups.emplace_front(this, &DeviceHalAidl::resetPortConfig, portConfig.id);
            }
            ids->push_back(portConfig.id);
        }
        return OK;
    };
    RETURN_STATUS_IF_ERROR(fillPortConfigs(aidlSources, &aidlPatch.sourcePortConfigIds));
    RETURN_STATUS_IF_ERROR(fillPortConfigs(aidlSinks, &aidlPatch.sinkPortConfigIds));
    if (existingPatchIt != mPatches.end()) {
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(
                        mModule->setAudioPatch(aidlPatch, &aidlPatch)));
        existingPatchIt->second = aidlPatch;
    } else {
        bool created = false;
        RETURN_STATUS_IF_ERROR(findOrCreatePatch(aidlPatch, &aidlPatch, &created));
        // Since no cleanup of the patch is needed, 'created' is ignored.
        halPatchId = aidlPatch.id;
        *patch = static_cast<audio_patch_handle_t>(halPatchId);
    }
    cleanups.disarmAll();
    return OK;
}

status_t DeviceHalAidl::releaseAudioPatch(audio_patch_handle_t patch) {
    ALOGD("%p %s::%s", this, getClassName().c_str(), __func__);
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    static_assert(AUDIO_PATCH_HANDLE_NONE == 0);
    if (patch == AUDIO_PATCH_HANDLE_NONE) {
        return BAD_VALUE;
    }
    int32_t halPatchId = static_cast<int32_t>(patch);
    auto patchIt = mPatches.find(halPatchId);
    if (patchIt == mPatches.end()) {
        ALOGE("%s: patch with id %d not found", __func__, halPatchId);
        return BAD_VALUE;
    }
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->resetAudioPatch(halPatchId)));
    mPatches.erase(patchIt);
    return OK;
}

status_t DeviceHalAidl::getAudioPort(struct audio_port* port __unused) {
    TIME_CHECK();
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t DeviceHalAidl::getAudioPort(struct audio_port_v7 *port __unused) {
    TIME_CHECK();
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

status_t DeviceHalAidl::setAudioPortConfig(const struct audio_port_config* config __unused) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

MicrophoneInfoProvider::Info const* DeviceHalAidl::getMicrophoneInfo() {
    if (mMicrophones.status == Microphones::Status::UNKNOWN) {
        TIME_CHECK();
        std::vector<MicrophoneInfo> aidlInfo;
        status_t status = statusTFromBinderStatus(mModule->getMicrophones(&aidlInfo));
        if (status == OK) {
            mMicrophones.status = Microphones::Status::QUERIED;
            mMicrophones.info = std::move(aidlInfo);
        } else if (status == INVALID_OPERATION) {
            mMicrophones.status = Microphones::Status::NOT_SUPPORTED;
        } else {
            ALOGE("%s: Unexpected status from 'IModule.getMicrophones': %d", __func__, status);
            return {};
        }
    }
    if (mMicrophones.status == Microphones::Status::QUERIED) {
        return &mMicrophones.info;
    }
    return {};  // NOT_SUPPORTED
}

status_t DeviceHalAidl::getMicrophones(
        std::vector<audio_microphone_characteristic_t>* microphones) {
    if (!microphones) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    auto staticInfo = getMicrophoneInfo();
    if (!staticInfo) return INVALID_OPERATION;
    std::vector<MicrophoneDynamicInfo> emptyDynamicInfo;
    emptyDynamicInfo.reserve(staticInfo->size());
    std::transform(staticInfo->begin(), staticInfo->end(), std::back_inserter(emptyDynamicInfo),
            [](const auto& info) { return MicrophoneDynamicInfo{ .id = info.id }; });
    *microphones = VALUE_OR_RETURN_STATUS(
            ::aidl::android::convertContainers<std::vector<audio_microphone_characteristic_t>>(
                    *staticInfo, emptyDynamicInfo,
                    ::aidl::android::aidl2legacy_MicrophoneInfos_audio_microphone_characteristic_t)
    );
    return OK;
}

status_t DeviceHalAidl::addDeviceEffect(audio_port_handle_t device __unused,
        sp<EffectHalInterface> effect) {
    if (!effect) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}
status_t DeviceHalAidl::removeDeviceEffect(audio_port_handle_t device __unused,
                            sp<EffectHalInterface> effect) {
    if (!effect) {
        return BAD_VALUE;
    }
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    ALOGE("%s not implemented yet", __func__);
    return OK;
}

status_t DeviceHalAidl::getMmapPolicyInfos(
        media::audio::common::AudioMMapPolicyType policyType,
        std::vector<media::audio::common::AudioMMapPolicyInfo>* policyInfos) {
    TIME_CHECK();
    AudioMMapPolicyType mmapPolicyType =
            VALUE_OR_RETURN_STATUS(cpp2ndk_Enum<AudioMMapPolicyType>(policyType));

    std::vector<AudioMMapPolicyInfo> mmapPolicyInfos;

    if (status_t status = statusTFromBinderStatus(
            mModule->getMmapPolicyInfos(mmapPolicyType, &mmapPolicyInfos)); status != OK) {
        return status;
    }

    *policyInfos = VALUE_OR_RETURN_STATUS(
            convertContainer<std::vector<media::audio::common::AudioMMapPolicyInfo>>(
                mmapPolicyInfos, ndk2cpp_AudioMMapPolicyInfo));
    return OK;
}

int32_t DeviceHalAidl::getAAudioMixerBurstCount() {
    TIME_CHECK();
    int32_t mixerBurstCount = 0;
    if (mModule->getAAudioMixerBurstCount(&mixerBurstCount).isOk()) {
        return mixerBurstCount;
    }
    return 0;
}

int32_t DeviceHalAidl::getAAudioHardwareBurstMinUsec() {
    TIME_CHECK();
    int32_t hardwareBurstMinUsec = 0;
    if (mModule->getAAudioHardwareBurstMinUsec(&hardwareBurstMinUsec).isOk()) {
        return hardwareBurstMinUsec;
    }
    return 0;
}

error::Result<audio_hw_sync_t> DeviceHalAidl::getHwAvSync() {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    int32_t aidlHwAvSync;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->generateHwAvSyncId(&aidlHwAvSync)));
    return VALUE_OR_RETURN_STATUS(
            ::aidl::android::aidl2legacy_int32_t_audio_hw_sync_t(aidlHwAvSync));
}

status_t DeviceHalAidl::dump(int fd, const Vector<String16>& args) {
    TIME_CHECK();
    if (!mModule) return NO_INIT;
    return mModule->dump(fd, Args(args).args(), args.size());
}

int32_t DeviceHalAidl::supportsBluetoothVariableLatency(bool* supports __unused) {
    TIME_CHECK();
    ALOGE("%s not implemented yet", __func__);
    return INVALID_OPERATION;
}

bool DeviceHalAidl::audioDeviceMatches(const AudioDevice& device, const AudioPort& p) {
    if (p.ext.getTag() != AudioPortExt::Tag::device) return false;
    return p.ext.get<AudioPortExt::Tag::device>().device == device;
}

bool DeviceHalAidl::audioDeviceMatches(const AudioDevice& device, const AudioPortConfig& p) {
    if (p.ext.getTag() != AudioPortExt::Tag::device) return false;
    if (device.type.type == AudioDeviceType::IN_DEFAULT) {
        return p.portId == mDefaultInputPortId;
    } else if (device.type.type == AudioDeviceType::OUT_DEFAULT) {
        return p.portId == mDefaultOutputPortId;
    }
    return p.ext.get<AudioPortExt::Tag::device>().device == device;
}

status_t DeviceHalAidl::createPortConfig(
        const AudioPortConfig& requestedPortConfig, PortConfigs::iterator* result) {
    TIME_CHECK();
    AudioPortConfig appliedPortConfig;
    bool applied = false;
    RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->setAudioPortConfig(
                            requestedPortConfig, &appliedPortConfig, &applied)));
    if (!applied) {
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->setAudioPortConfig(
                                appliedPortConfig, &appliedPortConfig, &applied)));
        if (!applied) {
            ALOGE("%s: module %s did not apply suggested config %s",
                    __func__, mInstance.c_str(), appliedPortConfig.toString().c_str());
            return NO_INIT;
        }
    }
    auto id = appliedPortConfig.id;
    auto [it, inserted] = mPortConfigs.emplace(std::move(id), std::move(appliedPortConfig));
    LOG_ALWAYS_FATAL_IF(!inserted, "%s: port config with id %d already exists",
            __func__, it->first);
    *result = it;
    return OK;
}

status_t DeviceHalAidl::findOrCreatePatch(
        const AudioPatch& requestedPatch, AudioPatch* patch, bool* created) {
    std::set<int32_t> sourcePortConfigIds(requestedPatch.sourcePortConfigIds.begin(),
            requestedPatch.sourcePortConfigIds.end());
    std::set<int32_t> sinkPortConfigIds(requestedPatch.sinkPortConfigIds.begin(),
            requestedPatch.sinkPortConfigIds.end());
    return findOrCreatePatch(sourcePortConfigIds, sinkPortConfigIds, patch, created);
}

status_t DeviceHalAidl::findOrCreatePatch(
        const std::set<int32_t>& sourcePortConfigIds, const std::set<int32_t>& sinkPortConfigIds,
        AudioPatch* patch, bool* created) {
    auto patchIt = findPatch(sourcePortConfigIds, sinkPortConfigIds);
    if (patchIt == mPatches.end()) {
        TIME_CHECK();
        AudioPatch requestedPatch, appliedPatch;
        requestedPatch.sourcePortConfigIds.insert(requestedPatch.sourcePortConfigIds.end(),
                sourcePortConfigIds.begin(), sourcePortConfigIds.end());
        requestedPatch.sinkPortConfigIds.insert(requestedPatch.sinkPortConfigIds.end(),
                sinkPortConfigIds.begin(), sinkPortConfigIds.end());
        RETURN_STATUS_IF_ERROR(statusTFromBinderStatus(mModule->setAudioPatch(
                                requestedPatch, &appliedPatch)));
        patchIt = mPatches.insert(mPatches.end(), std::make_pair(appliedPatch.id, appliedPatch));
        *created = true;
    } else {
        *created = false;
    }
    *patch = patchIt->second;
    return OK;
}

status_t DeviceHalAidl::findOrCreatePortConfig(const AudioDevice& device,
        AudioPortConfig* portConfig, bool* created) {
    auto portConfigIt = findPortConfig(device);
    if (portConfigIt == mPortConfigs.end()) {
        auto portsIt = findPort(device);
        if (portsIt == mPorts.end()) {
            ALOGE("%s: device port for device %s is not found in the module %s",
                    __func__, device.toString().c_str(), mInstance.c_str());
            return BAD_VALUE;
        }
        AudioPortConfig requestedPortConfig;
        requestedPortConfig.portId = portsIt->first;
        RETURN_STATUS_IF_ERROR(createPortConfig(requestedPortConfig, &portConfigIt));
        *created = true;
    } else {
        *created = false;
    }
    *portConfig = portConfigIt->second;
    return OK;
}

status_t DeviceHalAidl::findOrCreatePortConfig(
        const AudioConfig& config, const std::optional<AudioIoFlags>& flags, int32_t ioHandle,
        AudioSource source, AudioPortConfig* portConfig, bool* created) {
    // These flags get removed one by one in this order when retrying port finding.
    static const std::vector<AudioInputFlags> kOptionalInputFlags{
        AudioInputFlags::FAST, AudioInputFlags::RAW };
    auto portConfigIt = findPortConfig(config, flags, ioHandle);
    if (portConfigIt == mPortConfigs.end() && flags.has_value()) {
        auto optionalInputFlagsIt = kOptionalInputFlags.begin();
        AudioIoFlags matchFlags = flags.value();
        auto portsIt = findPort(config, matchFlags);
        while (portsIt == mPorts.end() && matchFlags.getTag() == AudioIoFlags::Tag::input
                && optionalInputFlagsIt != kOptionalInputFlags.end()) {
            if (!isBitPositionFlagSet(
                            matchFlags.get<AudioIoFlags::Tag::input>(), *optionalInputFlagsIt)) {
                ++optionalInputFlagsIt;
                continue;
            }
            matchFlags.set<AudioIoFlags::Tag::input>(matchFlags.get<AudioIoFlags::Tag::input>() &
                    ~makeBitPositionFlagMask(*optionalInputFlagsIt++));
            portsIt = findPort(config, matchFlags);
            ALOGI("%s: mix port for config %s, flags %s was not found in the module %s, "
                    "retried with flags %s", __func__, config.toString().c_str(),
                    flags.value().toString().c_str(), mInstance.c_str(),
                    matchFlags.toString().c_str());
        }
        if (portsIt == mPorts.end()) {
            ALOGE("%s: mix port for config %s, flags %s is not found in the module %s",
                    __func__, config.toString().c_str(), matchFlags.toString().c_str(),
                    mInstance.c_str());
            return BAD_VALUE;
        }
        AudioPortConfig requestedPortConfig;
        requestedPortConfig.portId = portsIt->first;
        setPortConfigFromConfig(&requestedPortConfig, config);
        requestedPortConfig.ext = AudioPortMixExt{ .handle = ioHandle };
        if (matchFlags.getTag() == AudioIoFlags::Tag::input
                && source != AudioSource::SYS_RESERVED_INVALID) {
            requestedPortConfig.ext.get<AudioPortExt::Tag::mix>().usecase =
                    AudioPortMixExtUseCase::make<AudioPortMixExtUseCase::Tag::source>(source);
        }
        RETURN_STATUS_IF_ERROR(createPortConfig(requestedPortConfig, &portConfigIt));
        *created = true;
    } else if (!flags.has_value()) {
        ALOGW("%s: mix port config for %s, handle %d not found in the module %s, "
                "and was not created as flags are not specified",
                __func__, config.toString().c_str(), ioHandle, mInstance.c_str());
        return BAD_VALUE;
    } else {
        *created = false;
    }
    *portConfig = portConfigIt->second;
    return OK;
}

status_t DeviceHalAidl::findOrCreatePortConfig(
        const AudioPortConfig& requestedPortConfig, AudioPortConfig* portConfig, bool* created) {
    using Tag = AudioPortExt::Tag;
    if (requestedPortConfig.ext.getTag() == Tag::mix) {
        if (const auto& p = requestedPortConfig;
                !p.sampleRate.has_value() || !p.channelMask.has_value() ||
                !p.format.has_value()) {
            ALOGW("%s: provided mix port config is not fully specified: %s",
                    __func__, p.toString().c_str());
            return BAD_VALUE;
        }
        AudioConfig config;
        setConfigFromPortConfig(&config, requestedPortConfig);
        AudioSource source = requestedPortConfig.ext.get<Tag::mix>().usecase.getTag() ==
                AudioPortMixExtUseCase::Tag::source ?
                requestedPortConfig.ext.get<Tag::mix>().usecase.
                get<AudioPortMixExtUseCase::Tag::source>() : AudioSource::SYS_RESERVED_INVALID;
        return findOrCreatePortConfig(config, requestedPortConfig.flags,
                requestedPortConfig.ext.get<Tag::mix>().handle, source, portConfig, created);
    } else if (requestedPortConfig.ext.getTag() == Tag::device) {
        return findOrCreatePortConfig(
                requestedPortConfig.ext.get<Tag::device>().device, portConfig, created);
    }
    ALOGW("%s: unsupported audio port config: %s",
            __func__, requestedPortConfig.toString().c_str());
    return BAD_VALUE;
}

DeviceHalAidl::Patches::iterator DeviceHalAidl::findPatch(
        const std::set<int32_t>& sourcePortConfigIds, const std::set<int32_t>& sinkPortConfigIds) {
    return std::find_if(mPatches.begin(), mPatches.end(),
            [&](const auto& pair) {
                const auto& p = pair.second;
                std::set<int32_t> patchSrcs(
                        p.sourcePortConfigIds.begin(), p.sourcePortConfigIds.end());
                std::set<int32_t> patchSinks(
                        p.sinkPortConfigIds.begin(), p.sinkPortConfigIds.end());
                return sourcePortConfigIds == patchSrcs && sinkPortConfigIds == patchSinks; });
}

DeviceHalAidl::Ports::iterator DeviceHalAidl::findPort(const AudioDevice& device) {
    if (device.type.type == AudioDeviceType::IN_DEFAULT) {
        return mPorts.find(mDefaultInputPortId);
    } else if (device.type.type == AudioDeviceType::OUT_DEFAULT) {
        return mPorts.find(mDefaultOutputPortId);
    }
    return std::find_if(mPorts.begin(), mPorts.end(),
            [&](const auto& pair) { return audioDeviceMatches(device, pair.second); });
}

DeviceHalAidl::Ports::iterator DeviceHalAidl::findPort(
            const AudioConfig& config, const AudioIoFlags& flags) {
    auto matcher = [&](const auto& pair) {
        const auto& p = pair.second;
        return p.ext.getTag() == AudioPortExt::Tag::mix &&
                p.flags == flags &&
                std::find_if(p.profiles.begin(), p.profiles.end(),
                        [&](const auto& prof) {
                            return prof.format == config.base.format &&
                                    std::find(prof.channelMasks.begin(), prof.channelMasks.end(),
                                            config.base.channelMask) != prof.channelMasks.end() &&
                                    std::find(prof.sampleRates.begin(), prof.sampleRates.end(),
                                            config.base.sampleRate) != prof.sampleRates.end();
                        }) != p.profiles.end(); };
    return std::find_if(mPorts.begin(), mPorts.end(), matcher);
}

DeviceHalAidl::PortConfigs::iterator DeviceHalAidl::findPortConfig(const AudioDevice& device) {
    return std::find_if(mPortConfigs.begin(), mPortConfigs.end(),
            [&](const auto& pair) { return audioDeviceMatches(device, pair.second); });
}

DeviceHalAidl::PortConfigs::iterator DeviceHalAidl::findPortConfig(
            const AudioConfig& config, const std::optional<AudioIoFlags>& flags, int32_t ioHandle) {
    using Tag = AudioPortExt::Tag;
    return std::find_if(mPortConfigs.begin(), mPortConfigs.end(),
            [&](const auto& pair) {
                const auto& p = pair.second;
                LOG_ALWAYS_FATAL_IF(p.ext.getTag() == Tag::mix &&
                        !p.sampleRate.has_value() || !p.channelMask.has_value() ||
                        !p.format.has_value() || !p.flags.has_value(),
                        "%s: stored mix port config is not fully specified: %s",
                        __func__, p.toString().c_str());
                return p.ext.getTag() == Tag::mix &&
                        isConfigEqualToPortConfig(config, p) &&
                        (!flags.has_value() || p.flags.value() == flags.value()) &&
                        p.ext.template get<Tag::mix>().handle == ioHandle; });
}
/*
DeviceHalAidl::PortConfigs::iterator DeviceHalAidl::findPortConfig(
        const AudioPortConfig& portConfig) {
    using Tag = AudioPortExt::Tag;
    if (portConfig.ext.getTag() == Tag::mix) {
        return std::find_if(mPortConfigs.begin(), mPortConfigs.end(),
                [&](const auto& pair) {
                    const auto& p = pair.second;
                    LOG_ALWAYS_FATAL_IF(p.ext.getTag() == Tag::mix &&
                            !p.sampleRate.has_value() || !p.channelMask.has_value() ||
                            !p.format.has_value() || !p.flags.has_value(),
                            "%s: stored mix port config is not fully specified: %s",
                            __func__, p.toString().c_str());
                    return p.ext.getTag() == Tag::mix &&
                            (!portConfig.sampleRate.has_value() ||
                                    p.sampleRate == portConfig.sampleRate) &&
                            (!portConfig.channelMask.has_value() ||
                                    p.channelMask == portConfig.channelMask) &&
                            (!portConfig.format.has_value() || p.format == portConfig.format) &&
                            (!portConfig.flags.has_value() || p.flags == portConfig.flags) &&
                            p.ext.template get<Tag::mix>().handle ==
                            portConfig.ext.template get<Tag::mix>().handle; });
    } else if (portConfig.ext.getTag() == Tag::device) {
        return findPortConfig(portConfig.ext.get<Tag::device>().device);
    }
    return mPortConfigs.end();
}
*/
void DeviceHalAidl::resetPatch(int32_t patchId) {
    if (auto it = mPatches.find(patchId); it != mPatches.end()) {
        mPatches.erase(it);
        TIME_CHECK();
        if (ndk::ScopedAStatus status = mModule->resetAudioPatch(patchId); !status.isOk()) {
            ALOGE("%s: error while resetting patch %d: %s",
                    __func__, patchId, status.getDescription().c_str());
        }
        return;
    }
    ALOGE("%s: patch id %d not found", __func__, patchId);
}

void DeviceHalAidl::resetPortConfig(int32_t portConfigId) {
    if (auto it = mPortConfigs.find(portConfigId); it != mPortConfigs.end()) {
        mPortConfigs.erase(it);
        TIME_CHECK();
        if (ndk::ScopedAStatus status = mModule->resetAudioPortConfig(portConfigId);
                !status.isOk()) {
            ALOGE("%s: error while resetting port config %d: %s",
                    __func__, portConfigId, status.getDescription().c_str());
        }
        return;
    }
    ALOGE("%s: port config id %d not found", __func__, portConfigId);
}

void DeviceHalAidl::clearCallbacks(void* cookie) {
    std::lock_guard l(mLock);
    mCallbacks.erase(cookie);
}

sp<StreamOutHalInterfaceCallback> DeviceHalAidl::getStreamOutCallback(void* cookie) {
    return getCallbackImpl(cookie, &Callbacks::out);
}

void DeviceHalAidl::setStreamOutCallback(
        void* cookie, const sp<StreamOutHalInterfaceCallback>& cb) {
    setCallbackImpl(cookie, &Callbacks::out, cb);
}

sp<StreamOutHalInterfaceEventCallback> DeviceHalAidl::getStreamOutEventCallback(
        void* cookie) {
    return getCallbackImpl(cookie, &Callbacks::event);
}

void DeviceHalAidl::setStreamOutEventCallback(
        void* cookie, const sp<StreamOutHalInterfaceEventCallback>& cb) {
    setCallbackImpl(cookie, &Callbacks::event, cb);
}

sp<StreamOutHalInterfaceLatencyModeCallback> DeviceHalAidl::getStreamOutLatencyModeCallback(
        void* cookie) {
    return getCallbackImpl(cookie, &Callbacks::latency);
}

void DeviceHalAidl::setStreamOutLatencyModeCallback(
        void* cookie, const sp<StreamOutHalInterfaceLatencyModeCallback>& cb) {
    setCallbackImpl(cookie, &Callbacks::latency, cb);
}

template<class C>
sp<C> DeviceHalAidl::getCallbackImpl(void* cookie, wp<C> DeviceHalAidl::Callbacks::* field) {
    std::lock_guard l(mLock);
    if (auto it = mCallbacks.find(cookie); it != mCallbacks.end()) {
        return ((it->second).*field).promote();
    }
    return nullptr;
}
template<class C>
void DeviceHalAidl::setCallbackImpl(
        void* cookie, wp<C> DeviceHalAidl::Callbacks::* field, const sp<C>& cb) {
    std::lock_guard l(mLock);
    if (auto it = mCallbacks.find(cookie); it != mCallbacks.end()) {
        (it->second).*field = cb;
    }
}

} // namespace android
