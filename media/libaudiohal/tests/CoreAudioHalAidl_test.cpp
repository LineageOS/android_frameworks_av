/*
 * Copyright 2023 The Android Open Source Project
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

#include <algorithm>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#define LOG_TAG "CoreAudioHalAidlTest"
#include <gtest/gtest.h>

#include <DeviceHalAidl.h>
#include <Hal2AidlMapper.h>
#include <StreamHalAidl.h>
#include <aidl/android/hardware/audio/core/BnModule.h>
#include <aidl/android/hardware/audio/core/BnStreamCommon.h>
#include <aidl/android/hardware/audio/core/BnStreamIn.h>
#include <aidl/android/hardware/audio/core/BnStreamOut.h>
#include <aidl/android/media/audio/BnHalAdapterVendorExtension.h>
#include <aidl/android/media/audio/common/AudioGainMode.h>
#include <aidl/android/media/audio/common/Int.h>
#include <com_android_media_audio.h>
#include <flag_macros.h>
#include <media/AidlConversionCppNdk.h>
#include <utils/Log.h>

namespace {

using ::aidl::android::hardware::audio::core::AudioPatch;
using ::aidl::android::hardware::audio::core::AudioRoute;
using ::aidl::android::hardware::audio::core::VendorParameter;
using ::aidl::android::media::audio::common::AudioChannelLayout;
using ::aidl::android::media::audio::common::AudioConfig;
using ::aidl::android::media::audio::common::AudioDevice;
using ::aidl::android::media::audio::common::AudioDeviceDescription;
using ::aidl::android::media::audio::common::AudioDeviceType;
using ::aidl::android::media::audio::common::AudioFormatDescription;
using ::aidl::android::media::audio::common::AudioFormatType;
using ::aidl::android::media::audio::common::AudioGainConfig;
using ::aidl::android::media::audio::common::AudioGainMode;
using ::aidl::android::media::audio::common::AudioIoFlags;
using ::aidl::android::media::audio::common::AudioPort;
using ::aidl::android::media::audio::common::AudioPortConfig;
using ::aidl::android::media::audio::common::AudioPortDeviceExt;
using ::aidl::android::media::audio::common::AudioPortExt;
using ::aidl::android::media::audio::common::AudioPortMixExt;
using ::aidl::android::media::audio::common::AudioProfile;
using ::aidl::android::media::audio::common::AudioSource;
using ::aidl::android::media::audio::common::PcmType;

class VendorParameterMock {
  public:
    void clearParameters() {
        mAsyncParameters.clear();
        mSyncParameters.clear();
    }
    const std::vector<std::string>& getRetrievedParameterIds() const { return mGetParameterIds; }
    const std::vector<VendorParameter>& getAsyncParameters() const { return mAsyncParameters; }
    const std::vector<VendorParameter>& getSyncParameters() const { return mSyncParameters; }

  protected:
    ndk::ScopedAStatus getVendorParameters(const std::vector<std::string>& in_parameterIds) {
        mGetParameterIds.insert(mGetParameterIds.end(), in_parameterIds.begin(),
                                in_parameterIds.end());
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setVendorParameters(const std::vector<VendorParameter>& in_parameters,
                                           bool async) {
        if (async) {
            mAsyncParameters.insert(mAsyncParameters.end(), in_parameters.begin(),
                                    in_parameters.end());
        } else {
            mSyncParameters.insert(mSyncParameters.end(), in_parameters.begin(),
                                   in_parameters.end());
        }
        return ndk::ScopedAStatus::ok();
    }

  private:
    std::vector<std::string> mGetParameterIds;
    std::vector<VendorParameter> mAsyncParameters;
    std::vector<VendorParameter> mSyncParameters;
};

struct Configuration {
    std::vector<AudioPort> ports;
    std::vector<AudioPortConfig> portConfigs;
    std::vector<AudioRoute> routes;
    std::vector<AudioPatch> patches;
    std::map<int32_t, std::vector<AudioProfile>> connectedProfiles;
    // In this test, by default, all routes will be enabled (i.e., fully-connected)
    // w.r.t. the template, but the actual routing can be different and updated per
    // `dis/connectExternalDevice`, in which case this allows to configure
    // the exclusive endpoints of such ports in specific test cases.
    std::map<int32_t, std::vector<int32_t>> exclusiveRoutingForDeviceTemplate;
    int32_t nextPortId = 1;
    int32_t nextPatchId = 1;
};

void fillProfile(AudioProfile* profile, const std::vector<int32_t>& channelLayouts,
                 const std::vector<int32_t>& sampleRates) {
    for (auto layout : channelLayouts) {
        profile->channelMasks.push_back(
                AudioChannelLayout::make<AudioChannelLayout::layoutMask>(layout));
    }
    profile->sampleRates.insert(profile->sampleRates.end(), sampleRates.begin(), sampleRates.end());
}

AudioProfile createProfile(PcmType pcmType, const std::vector<int32_t>& channelLayouts,
                           const std::vector<int32_t>& sampleRates) {
    AudioProfile profile;
    profile.format.type = AudioFormatType::PCM;
    profile.format.pcm = pcmType;
    fillProfile(&profile, channelLayouts, sampleRates);
    return profile;
}

AudioPortExt createPortDeviceExt(AudioDeviceType devType, int32_t flags,
                                 std::string connection = "") {
    AudioPortDeviceExt deviceExt;
    deviceExt.device.type.type = devType;
    if (devType == AudioDeviceType::IN_MICROPHONE && connection.empty()) {
        deviceExt.device.address = "bottom";
    } else if (devType == AudioDeviceType::IN_MICROPHONE_BACK && connection.empty()) {
        deviceExt.device.address = "back";
    }
    deviceExt.device.type.connection = std::move(connection);
    deviceExt.flags = flags;
    return AudioPortExt::make<AudioPortExt::device>(deviceExt);
}

AudioPortExt createPortMixExt(int32_t maxOpenStreamCount, int32_t maxActiveStreamCount) {
    AudioPortMixExt mixExt;
    mixExt.maxOpenStreamCount = maxOpenStreamCount;
    mixExt.maxActiveStreamCount = maxActiveStreamCount;
    return AudioPortExt::make<AudioPortExt::mix>(mixExt);
}

AudioPort createPort(int32_t id, const std::string& name, int32_t flags, bool isInput,
                     const AudioPortExt& ext) {
    AudioPort port;
    port.id = id;
    port.name = name;
    port.flags = isInput ? AudioIoFlags::make<AudioIoFlags::input>(flags)
                         : AudioIoFlags::make<AudioIoFlags::output>(flags);
    port.ext = ext;
    return port;
}

AudioRoute createRoute(const std::vector<AudioPort>& sources, const AudioPort& sink) {
    AudioRoute route;
    route.sinkPortId = sink.id;
    std::transform(sources.begin(), sources.end(), std::back_inserter(route.sourcePortIds),
                   [](const auto& port) { return port.id; });
    return route;
}

template <typename T>
auto findById(std::vector<T>& v, int32_t id) {
    return std::find_if(v.begin(), v.end(), [&](const auto& e) { return e.id == id; });
}

Configuration getTestConfiguration() {
    const std::vector<AudioProfile> standardPcmAudioProfiles = {
            createProfile(PcmType::INT_16_BIT, {AudioChannelLayout::LAYOUT_STEREO}, {48000})};
    Configuration c;

    AudioPort micInDevice =
            createPort(c.nextPortId++, "Built-In Mic", 0, true,
                       createPortDeviceExt(AudioDeviceType::IN_MICROPHONE,
                                           1 << AudioPortDeviceExt::FLAG_INDEX_DEFAULT_DEVICE));
    micInDevice.profiles = standardPcmAudioProfiles;
    c.ports.push_back(micInDevice);

    AudioPort micInBackDevice =
            createPort(c.nextPortId++, "Built-In Back Mic", 0, true,
                       createPortDeviceExt(AudioDeviceType::IN_MICROPHONE_BACK, 0));
    micInDevice.profiles = standardPcmAudioProfiles;
    c.ports.push_back(micInBackDevice);

    AudioPort primaryInMix =
            createPort(c.nextPortId++, "primary input", 0, true, createPortMixExt(0, 1));
    primaryInMix.profiles = standardPcmAudioProfiles;
    c.ports.push_back(primaryInMix);

    AudioPort speakerOutDevice = createPort(c.nextPortId++, "Speaker", 0, false,
                                            createPortDeviceExt(AudioDeviceType::OUT_SPEAKER, 0));
    speakerOutDevice.profiles = standardPcmAudioProfiles;
    c.ports.push_back(speakerOutDevice);

    AudioPort primaryOutMix =
            createPort(c.nextPortId++, "primary output", 0, false, createPortMixExt(0, 1));
    primaryOutMix.profiles = standardPcmAudioProfiles;
    c.ports.push_back(primaryOutMix);

    AudioPort btOutDevice =
            createPort(c.nextPortId++, "BT A2DP Out", 0, false,
                       createPortDeviceExt(AudioDeviceType::OUT_DEVICE, 0,
                                           AudioDeviceDescription::CONNECTION_BT_A2DP));
    btOutDevice.profiles = standardPcmAudioProfiles;
    c.ports.push_back(btOutDevice);

    AudioPort btOutMix =
            createPort(c.nextPortId++, "a2dp output", 0, false, createPortMixExt(1, 1));
    btOutMix.profiles = standardPcmAudioProfiles;
    c.ports.push_back(btOutMix);

    AudioPort usbOutDevice =
            createPort(c.nextPortId++, "USB Out", 0, false,
                       createPortDeviceExt(AudioDeviceType::OUT_DEVICE, 0,
                                           AudioDeviceDescription::CONNECTION_USB));
    c.ports.push_back(usbOutDevice);
    c.connectedProfiles[usbOutDevice.id] = standardPcmAudioProfiles;

    // Simulates the edge case where a detachable device with non-standard audio profiles
    // whose template port routes to multiple mix ports ultimately routes to exactly
    // one endpoint on `connectExternalDevice`, determined by the HAL.
    //
    // Note that this is using `OUT_HEADSET` instead of `OUT_DEVICE` because the latter
    // is being used to test non-dynamic port behaviors. This makes a difference in
    // the mapper determining the template port, which makes them independent to each other.
    AudioPort usbDynamicHeadset =
            createPort(c.nextPortId++, "USB Dynamic Out", 0, false,
                       createPortDeviceExt(AudioDeviceType::OUT_HEADSET, 0,
                                           AudioDeviceDescription::CONNECTION_USB));
    c.ports.push_back(usbDynamicHeadset);
    // The profiles are unknown until the HAL queries the device in practice.
    // For testing, this will be set right before `connectExternalDevice` to
    // simulate generating the unknown (until connection in the HAL) profile.
    c.connectedProfiles[usbDynamicHeadset.id] = {};

    AudioPort hifiOutMix1 =
            createPort(c.nextPortId++, "hifi_out_1", 0, false, createPortMixExt(1, 1));
    c.ports.push_back(hifiOutMix1);
    c.connectedProfiles[hifiOutMix1.id] = standardPcmAudioProfiles;

    AudioPort hifiOutMix2 =
            createPort(c.nextPortId++, "hifi_out_2", 0, false, createPortMixExt(1, 1));
    c.ports.push_back(hifiOutMix2);
    c.connectedProfiles[hifiOutMix2.id] = standardPcmAudioProfiles;

    AudioPort dynamicOutMix1 =
            createPort(c.nextPortId++, "dynamic_out_1", 0, false, createPortMixExt(1, 1));
    c.ports.push_back(dynamicOutMix1);
    // The profiles are only populated by the HAL after `connectExternalDevice`
    c.connectedProfiles[dynamicOutMix1.id] = {};

    AudioPort dynamicOutMix2 =
            createPort(c.nextPortId++, "dynamic_out_2", 0, false, createPortMixExt(1, 1));
    c.ports.push_back(dynamicOutMix2);
    c.connectedProfiles[dynamicOutMix2.id] = {};

    AudioPort usbInDevice = createPort(c.nextPortId++, "USB In", 0, true,
                                       createPortDeviceExt(AudioDeviceType::IN_DEVICE, 0,
                                                           AudioDeviceDescription::CONNECTION_USB));
    c.ports.push_back(usbInDevice);
    c.connectedProfiles[usbInDevice.id] = standardPcmAudioProfiles;

    AudioPort hifiInMix1 = createPort(c.nextPortId++, "hifi_in_1", 0, true, createPortMixExt(1, 1));
    c.ports.push_back(hifiInMix1);
    c.connectedProfiles[hifiInMix1.id] = standardPcmAudioProfiles;

    AudioPort hifiInMix2 = createPort(c.nextPortId++, "hifi_in_2", 0, true, createPortMixExt(1, 1));
    c.ports.push_back(hifiInMix2);
    c.connectedProfiles[hifiInMix2.id] = standardPcmAudioProfiles;

    c.routes.push_back(createRoute({micInDevice, micInBackDevice}, primaryInMix));
    c.routes.push_back(createRoute({primaryOutMix}, speakerOutDevice));
    c.routes.push_back(createRoute({btOutMix}, btOutDevice));
    c.routes.push_back(createRoute({hifiOutMix1, hifiOutMix2}, usbOutDevice));
    c.routes.push_back(createRoute({dynamicOutMix1, dynamicOutMix2}, usbDynamicHeadset));
    c.routes.push_back(createRoute({usbInDevice}, hifiInMix1));
    c.routes.push_back(createRoute({usbInDevice}, hifiInMix2));

    return c;
}

class StreamCommonMock : public ::aidl::android::hardware::audio::core::BnStreamCommon,
                         public VendorParameterMock {
    ndk::ScopedAStatus close() override {
        mIsClosed = true;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus prepareToClose() override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus updateHwAvSyncId(int32_t) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getVendorParameters(const std::vector<std::string>& in_parameterIds,
                                           std::vector<VendorParameter>*) override {
        return VendorParameterMock::getVendorParameters(in_parameterIds);
    }
    ndk::ScopedAStatus setVendorParameters(const std::vector<VendorParameter>& in_parameters,
                                           bool async) override {
        return VendorParameterMock::setVendorParameters(in_parameters, async);
    }
    ndk::ScopedAStatus addEffect(
            const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus removeEffect(
            const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus createMmapBuffer(
            ::aidl::android::hardware::audio::core::MmapBufferDescriptor*) override {
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }

    bool mIsClosed = false;

  public:
    bool isStreamClosed() const { return mIsClosed; }
};

class StreamContext {
  public:
    using Descriptor = ::aidl::android::hardware::audio::core::StreamDescriptor;
    typedef ::android::AidlMessageQueue<
            Descriptor::Command, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite>
            CommandMQ;
    typedef ::android::AidlMessageQueue<
            Descriptor::Reply, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite>
            ReplyMQ;
    typedef ::android::AidlMessageQueue<
            int8_t, ::aidl::android::hardware::common::fmq::SynchronizedReadWrite>
            DataMQ;

    StreamContext() = default;
    StreamContext(std::unique_ptr<CommandMQ> commandMQ, std::unique_ptr<ReplyMQ> replyMQ,
                  std::unique_ptr<DataMQ> dataMQ)
        : mCommandMQ(std::move(commandMQ)),
          mReplyMQ(std::move(replyMQ)),
          mDataMQ(std::move(dataMQ)) {}
    void fillDescriptor(Descriptor* desc) {
        if (mCommandMQ) {
            desc->command = mCommandMQ->dupeDesc();
        }
        if (mReplyMQ) {
            desc->reply = mReplyMQ->dupeDesc();
        }
        if (mDataMQ) {
            desc->frameSizeBytes = 2;
            desc->bufferSizeFrames = 48;
            desc->audio.set<Descriptor::AudioBuffer::Tag::fmq>(mDataMQ->dupeDesc());
        }
    }

  private:
    std::unique_ptr<CommandMQ> mCommandMQ =
            std::make_unique<CommandMQ>(1, true /*configureEventFlagWord*/);
    std::unique_ptr<ReplyMQ> mReplyMQ =
            std::make_unique<ReplyMQ>(1, true /*configureEventFlagWord*/);
    std::unique_ptr<DataMQ> mDataMQ = std::make_unique<DataMQ>(96);
};

class StreamWrapper {
  public:
    virtual ~StreamWrapper() = default;
    virtual bool isStreamClosed() const = 0;
};

class StreamInMock : public ::aidl::android::hardware::audio::core::BnStreamIn,
                     public StreamWrapper {
  public:
    explicit StreamInMock(StreamContext&& ctx) : mContext(std::move(ctx)) {}

    bool isStreamClosed() const final { return mCommon->isStreamClosed(); }

  private:
    ndk::ScopedAStatus getStreamCommon(
            std::shared_ptr<::aidl::android::hardware::audio::core::IStreamCommon>* _aidl_return)
            override {
        if (!mCommon) {
            mCommon = ndk::SharedRefBase::make<StreamCommonMock>();
        }
        *_aidl_return = mCommon;
        return ndk::ScopedAStatus::ok();
    }

    ndk::ScopedAStatus getActiveMicrophones(
            std::vector<::aidl::android::media::audio::common::MicrophoneDynamicInfo>*) override {
        return ndk::ScopedAStatus::ok();
    }

    ndk::ScopedAStatus getMicrophoneDirection(
            ::aidl::android::hardware::audio::core::IStreamIn::MicrophoneDirection*) override {
        return ndk::ScopedAStatus::ok();
    }

    ndk::ScopedAStatus setMicrophoneDirection(
            ::aidl::android::hardware::audio::core::IStreamIn::MicrophoneDirection) override {
        return ndk::ScopedAStatus::ok();
    }

    ndk::ScopedAStatus getMicrophoneFieldDimension(float*) override {
        return ndk::ScopedAStatus::ok();
    }

    ndk::ScopedAStatus setMicrophoneFieldDimension(float) override {
        return ndk::ScopedAStatus::ok();
    }

    ndk::ScopedAStatus updateMetadata(
            const ::aidl::android::hardware::audio::common::SinkMetadata&) override {
        return ndk::ScopedAStatus::ok();
    }

    ndk::ScopedAStatus getHwGain(std::vector<float>*) override { return ndk::ScopedAStatus::ok(); }

    ndk::ScopedAStatus setHwGain(const std::vector<float>&) override {
        return ndk::ScopedAStatus::ok();
    }

    StreamContext mContext;
    std::shared_ptr<StreamCommonMock> mCommon;
};

class StreamOutMock : public ::aidl::android::hardware::audio::core::BnStreamOut,
                      public StreamWrapper {
  public:
    explicit StreamOutMock(StreamContext&& ctx) : mContext(std::move(ctx)) {}

    bool isStreamClosed() const final { return !mCommon || mCommon->isStreamClosed(); }

  private:
    ndk::ScopedAStatus getStreamCommon(
            std::shared_ptr<::aidl::android::hardware::audio::core::IStreamCommon>* _aidl_return)
            override {
        if (!mCommon) {
            mCommon = ndk::SharedRefBase::make<StreamCommonMock>();
        }
        *_aidl_return = mCommon;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateMetadata(
            const ::aidl::android::hardware::audio::common::SourceMetadata&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateOffloadMetadata(
            const ::aidl::android::hardware::audio::common::AudioOffloadMetadata&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getHwVolume(std::vector<float>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setHwVolume(const std::vector<float>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioDescriptionMixLevel(float*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setAudioDescriptionMixLevel(float) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getDualMonoMode(
            ::aidl::android::media::audio::common::AudioDualMonoMode*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setDualMonoMode(
            ::aidl::android::media::audio::common::AudioDualMonoMode) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getRecommendedLatencyModes(
            std::vector<::aidl::android::media::audio::common::AudioLatencyMode>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setLatencyMode(
            ::aidl::android::media::audio::common::AudioLatencyMode) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getPlaybackRateParameters(
            ::aidl::android::media::audio::common::AudioPlaybackRate*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setPlaybackRateParameters(
            const ::aidl::android::media::audio::common::AudioPlaybackRate&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus selectPresentation(int32_t, int32_t) override {
        return ndk::ScopedAStatus::ok();
    }
    StreamContext mContext;
    std::shared_ptr<StreamCommonMock> mCommon;
};

class ModuleMock : public ::aidl::android::hardware::audio::core::BnModule,
                   public VendorParameterMock {
  public:
    ModuleMock() = default;
    explicit ModuleMock(const Configuration& config) : mConfig(config) {}
    bool isScreenTurnedOn() const { return mIsScreenTurnedOn; }
    ScreenRotation getScreenRotation() const { return mScreenRotation; }
    std::vector<AudioPatch> getPatches() {
        std::vector<AudioPatch> result;
        getAudioPatches(&result);
        return result;
    }
    std::optional<AudioPortConfig> getPortConfig(int32_t id) {
        auto iter = findById<AudioPortConfig>(mConfig.portConfigs, id);
        if (iter != mConfig.portConfigs.end()) {
            return *iter;
        }
        return std::nullopt;
    }

    std::vector<int32_t> getRoutableMixPortIdsFor(const AudioDeviceDescription& deviceDesc) {
        std::vector<int32_t> result;
        if (deviceDesc.type > AudioDeviceType::OUT_DEFAULT) {
            for (const auto& route : mConfig.routes) {
                auto sinkPort = findById<AudioPort>(mConfig.ports, route.sinkPortId);
                if (sinkPort->ext.getTag() != AudioPortExt::Tag::device) {
                    continue;
                }
                if (sinkPort->ext.get<AudioPortExt::Tag::device>().device.type == deviceDesc) {
                    result = route.sourcePortIds;
                    break;
                }
            }
        } else {
            for (const auto& route : mConfig.routes) {
                for (int32_t sourcePortId : route.sourcePortIds) {
                    auto sourcePort = findById<AudioPort>(mConfig.ports, sourcePortId);
                    if (sourcePort->ext.getTag() != AudioPortExt::Tag::device) {
                        continue;
                    }
                    if (sourcePort->ext.get<AudioPortExt::Tag::device>().device.type ==
                        deviceDesc) {
                        result.push_back(route.sinkPortId);
                        break;
                    }
                }
            }
        }
        return result;
    }

    int32_t getPortIdFor(int32_t ioHandle) {
        for (auto& config : mConfig.portConfigs) {
            if (config.ext.getTag() == AudioPortExt::Tag::mix &&
                config.ext.get<AudioPortExt::Tag::mix>().handle == ioHandle) {
                return config.portId;
            }
        }
        return 0;
    }

    // Finds IDs of all device ports matching `deviceDesc`.
    std::vector<int32_t> getDevicePortIds(const AudioDeviceDescription& deviceDesc) {
        std::vector<int32_t> ids;
        for (auto& port : mConfig.ports) {
            if (port.ext.getTag() != AudioPortExt::Tag::device) continue;
            if (port.ext.get<AudioPortExt::Tag::device>().device.type != deviceDesc) continue;
            ids.push_back(port.id);
        }
        return ids;
    }

    // Finds device port ID by address for the specified direction.
    // Returns -1 if not found.
    int32_t getDevicePortIdWithAddress(const std::string& address, bool isInput) {
        const auto directionFlag = isInput ? AudioIoFlags::Tag::input : AudioIoFlags::Tag::output;
        for (auto& port : mConfig.ports) {
            if (port.flags.getTag() != directionFlag) continue;
            if (port.ext.getTag() != AudioPortExt::Tag::device) continue;
            if (port.ext.get<AudioPortExt::Tag::device>().device.address != address) continue;
            return port.id;
        }
        return -1;
    }

    // This updates the dynamic port referred to by the `id` so as if it, or the next
    // device that refers to it as a template, will claim to support `profile`.
    void setConnectedProfileForPort(int32_t id, const AudioProfile& profile) {
        mConfig.connectedProfiles[id].clear();
        mConfig.connectedProfiles[id].push_back(profile);
    }

    // If set, this determines the endpoints of the routes for upcoming connected
    // devices referring to the template port identified by `id`.
    void setExclusiveRoutingForPort(int32_t id, const std::vector<int32_t>& endpoints) {
        mConfig.exclusiveRoutingForDeviceTemplate[id] = endpoints;
    }

  private:
    ndk::ScopedAStatus setModuleDebug(
            const ::aidl::android::hardware::audio::core::ModuleDebug&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getTelephony(
            std::shared_ptr<::aidl::android::hardware::audio::core::ITelephony>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getBluetooth(
            std::shared_ptr<::aidl::android::hardware::audio::core::IBluetooth>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getBluetoothA2dp(
            std::shared_ptr<::aidl::android::hardware::audio::core::IBluetoothA2dp>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getBluetoothLe(
            std::shared_ptr<::aidl::android::hardware::audio::core::IBluetoothLe>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus connectExternalDevice(
            const ::aidl::android::media::audio::common::AudioPort& portIdAndData,
            ::aidl::android::media::audio::common::AudioPort* port) override {
        auto src = portIdAndData;  // Make a copy to mimic RPC behavior.
        auto iter = findById<AudioPort>(mConfig.ports, src.id);
        if (iter == mConfig.ports.end()) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        *port = *iter;
        port->ext = src.ext;
        if (auto it = mConfig.connectedProfiles.find(src.id);
            it != mConfig.connectedProfiles.end()) {
            // Update audio profiles for the device port when connecting
            port->profiles = it->second;
            // Update audio profile of mix ports that can be connected to the new connected device
            for (auto& r : mConfig.routes) {
                if (r.sinkPortId == src.id) {
                    for (auto sourceId : r.sourcePortIds) {
                        if (auto cpIt = mConfig.connectedProfiles.find(sourceId);
                            cpIt != mConfig.connectedProfiles.end()) {
                            findById<AudioPort>(mConfig.ports, cpIt->first)->profiles =
                                    cpIt->second;
                        }
                    }
                } else if (std::find(r.sourcePortIds.begin(), r.sourcePortIds.end(), src.id) !=
                           r.sourcePortIds.end()) {
                    if (auto cpIt = mConfig.connectedProfiles.find(r.sinkPortId);
                        cpIt != mConfig.connectedProfiles.end()) {
                        findById<AudioPort>(mConfig.ports, cpIt->first)->profiles = cpIt->second;
                    }
                }
            }
        }
        port->id = mConfig.nextPortId++;
        ALOGD("%s: returning %s", __func__, port->toString().c_str());
        mConfig.ports.push_back(*port);
        std::vector<AudioRoute> newRoutes;
        for (auto& r : mConfig.routes) {
            if (r.sinkPortId == src.id) {
                const auto& routableSourcePortIds =
                        mConfig.exclusiveRoutingForDeviceTemplate.count(src.id)
                                ? mConfig.exclusiveRoutingForDeviceTemplate[src.id]
                                : r.sourcePortIds;

                if (routableSourcePortIds.empty()) continue;

                newRoutes.push_back(AudioRoute{.sourcePortIds = routableSourcePortIds,
                                               .sinkPortId = port->id,
                                               .isExclusive = r.isExclusive});
            } else if (std::find(r.sourcePortIds.begin(), r.sourcePortIds.end(), src.id) !=
                       r.sourcePortIds.end()) {
                auto it = mConfig.exclusiveRoutingForDeviceTemplate.find(src.id);
                if (it != mConfig.exclusiveRoutingForDeviceTemplate.end()) {
                    const auto& routableSinkPortIds = it->second;
                    if (std::find(routableSinkPortIds.begin(), routableSinkPortIds.end(),
                                  r.sinkPortId) == routableSinkPortIds.end()) {
                        continue;
                    }
                }

                r.sourcePortIds.push_back(port->id);
            }
        }
        mConfig.routes.insert(mConfig.routes.end(), newRoutes.begin(), newRoutes.end());
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus disconnectExternalDevice(int32_t portId) override {
        auto iter = findById<AudioPort>(mConfig.ports, portId);
        if (iter == mConfig.ports.end()) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        mConfig.ports.erase(iter);
        for (auto it = mConfig.routes.begin(); it != mConfig.routes.end();) {
            if (it->sinkPortId == portId) {
                it = mConfig.routes.erase(it);
                for (auto sourceId : it->sourcePortIds) {
                    findById<AudioPort>(mConfig.ports, sourceId)->profiles.clear();
                }
            } else {
                if (auto srcIt =
                            std::find(it->sourcePortIds.begin(), it->sourcePortIds.end(), portId);
                    srcIt != it->sourcePortIds.end()) {
                    it->sourcePortIds.erase(srcIt);
                    findById<AudioPort>(mConfig.ports, it->sinkPortId)->profiles.clear();
                }
                ++it;
            }
        }
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPatches(
            std::vector<::aidl::android::hardware::audio::core::AudioPatch>* patches) override {
        *patches = mConfig.patches;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPort(
            int32_t portId, ::aidl::android::media::audio::common::AudioPort* port) override {
        auto iter = findById<AudioPort>(mConfig.ports, portId);
        if (iter == mConfig.ports.end()) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        *port = *iter;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPortConfigs(
            std::vector<::aidl::android::media::audio::common::AudioPortConfig>* configs) override {
        *configs = mConfig.portConfigs;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioPorts(
            std::vector<::aidl::android::media::audio::common::AudioPort>* ports) override {
        *ports = mConfig.ports;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioRoutes(
            std::vector<::aidl::android::hardware::audio::core::AudioRoute>* routes) override {
        *routes = mConfig.routes;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAudioRoutesForAudioPort(
            int32_t portId,
            std::vector<::aidl::android::hardware::audio::core::AudioRoute>* routes) override {
        for (auto& r : mConfig.routes) {
            const auto& srcs = r.sourcePortIds;
            if (r.sinkPortId == portId ||
                std::find(srcs.begin(), srcs.end(), portId) != srcs.end()) {
                routes->push_back(r);
            }
        }
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus openInputStream(const OpenInputStreamArguments& in_args,
                                       OpenInputStreamReturn* _aidl_return) override {
        AudioPort* port = nullptr;
        if (auto result = findPortForNewStream(in_args.portConfigId, &port); !result.isOk()) {
            return result;
        }
        if (port->flags.getTag() != AudioIoFlags::Tag::input) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        StreamContext context;
        context.fillDescriptor(&_aidl_return->desc);
        auto stream = ndk::SharedRefBase::make<StreamInMock>(std::move(context));
        _aidl_return->stream = stream;
        mStreams.emplace(port->id, stream);
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus openOutputStream(const OpenOutputStreamArguments& in_args,
                                        OpenOutputStreamReturn* _aidl_return) override {
        AudioPort* port = nullptr;
        if (auto result = findPortForNewStream(in_args.portConfigId, &port); !result.isOk()) {
            return result;
        }
        if (port->flags.getTag() != AudioIoFlags::Tag::output) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        StreamContext context;
        context.fillDescriptor(&_aidl_return->desc);
        auto stream = ndk::SharedRefBase::make<StreamOutMock>(std::move(context));
        _aidl_return->stream = stream;
        mStreams.emplace(port->id, stream);
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getSupportedPlaybackRateFactors(SupportedPlaybackRateFactors*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setAudioPatch(
            const ::aidl::android::hardware::audio::core::AudioPatch& requested,
            ::aidl::android::hardware::audio::core::AudioPatch* patch) override {
        if (requested.id == 0) {
            *patch = requested;
            patch->id = mConfig.nextPatchId++;
            patch->latenciesMs.push_back(100);
            mConfig.patches.push_back(*patch);
            ALOGD("%s: returning %s", __func__, patch->toString().c_str());
        } else {
            auto iter = findById<AudioPatch>(mConfig.patches, requested.id);
            if (iter == mConfig.patches.end()) {
                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
            }
            *iter = *patch = requested;
            ALOGD("%s: updated %s", __func__, patch->toString().c_str());
        }
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus setAudioPortConfig(
            const ::aidl::android::media::audio::common::AudioPortConfig& requested,
            ::aidl::android::media::audio::common::AudioPortConfig* config,
            bool* applied) override {
        *applied = false;
        auto src = requested;  // Make a copy to mimic RPC behavior.
        if (src.id == 0) {
            *config = src;
            if (config->ext.getTag() == AudioPortExt::unspecified) {
                auto iter = findById<AudioPort>(mConfig.ports, src.portId);
                if (iter == mConfig.ports.end()) {
                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
                }
                config->ext = iter->ext;
            }
            config->id = mConfig.nextPortId++;
            mConfig.portConfigs.push_back(*config);
            ALOGD("%s: returning %s", __func__, config->toString().c_str());
        } else {
            auto iter = findById<AudioPortConfig>(mConfig.portConfigs, src.id);
            if (iter == mConfig.portConfigs.end()) {
                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
            }
            *iter = *config = src;
            ALOGD("%s: updated %s", __func__, config->toString().c_str());
        }
        *applied = true;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus resetAudioPatch(int32_t patchId) override {
        auto iter = findById<AudioPatch>(mConfig.patches, patchId);
        if (iter == mConfig.patches.end()) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        mConfig.patches.erase(iter);
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus resetAudioPortConfig(int32_t portConfigId) override {
        auto iter = findById<AudioPortConfig>(mConfig.portConfigs, portConfigId);
        if (iter == mConfig.portConfigs.end()) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        mConfig.portConfigs.erase(iter);
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getMasterMute(bool*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus setMasterMute(bool) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getMasterVolume(float*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus setMasterVolume(float) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getMicMute(bool*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus setMicMute(bool) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getMicrophones(
            std::vector<::aidl::android::media::audio::common::MicrophoneInfo>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateAudioMode(::aidl::android::media::audio::common::AudioMode) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateScreenRotation(ScreenRotation in_rotation) override {
        mScreenRotation = in_rotation;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus updateScreenState(bool in_isTurnedOn) override {
        mIsScreenTurnedOn = in_isTurnedOn;
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getSoundDose(
            std::shared_ptr<::aidl::android::hardware::audio::core::sounddose::ISoundDose>*)
            override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus generateHwAvSyncId(int32_t*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getVendorParameters(const std::vector<std::string>& in_parameterIds,
                                           std::vector<VendorParameter>*) override {
        return VendorParameterMock::getVendorParameters(in_parameterIds);
    }
    ndk::ScopedAStatus setVendorParameters(const std::vector<VendorParameter>& in_parameters,
                                           bool async) override {
        return VendorParameterMock::setVendorParameters(in_parameters, async);
    }
    ndk::ScopedAStatus addDeviceEffect(
            int32_t,
            const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus removeDeviceEffect(
            int32_t,
            const std::shared_ptr<::aidl::android::hardware::audio::effect::IEffect>&) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getMmapPolicyInfos(
            ::aidl::android::media::audio::common::AudioMMapPolicyType,
            std::vector<::aidl::android::media::audio::common::AudioMMapPolicyInfo>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus supportsVariableLatency(bool*) override { return ndk::ScopedAStatus::ok(); }
    ndk::ScopedAStatus getAAudioMixerBurstCount(int32_t*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus getAAudioHardwareBurstMinUsec(int32_t*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus prepareToDisconnectExternalDevice(int32_t) override {
        return ndk::ScopedAStatus::ok();
    }

    size_t count(int32_t id) {
        // Streams do not remove themselves from the collection on close.
        erase_if(mStreams, [](const auto& pair) {
            auto streamWrapper = pair.second.lock();
            return !streamWrapper || streamWrapper->isStreamClosed();
        });
        return mStreams.count(id);
    }

    ndk::ScopedAStatus findPortForNewStream(int32_t in_portConfigId, AudioPort** port) {
        auto portConfig = getPortConfig(in_portConfigId);
        if (portConfig == std::nullopt) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        const int32_t portId = portConfig->portId;
        auto portIt = findById<AudioPort>(mConfig.ports, portId);
        if (portIt == mConfig.ports.end()) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        if (portIt->ext.getTag() != AudioPortExt::Tag::mix) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
        const size_t maxOpenStreamCount =
                portIt->ext.get<AudioPortExt::Tag::mix>().maxOpenStreamCount;
        if (maxOpenStreamCount != 0 && mStreams.count(portId) >= maxOpenStreamCount) {
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_STATE);
        }
        *port = &(*portIt);
        return ndk::ScopedAStatus::ok();
    }

    Configuration mConfig;
    bool mIsScreenTurnedOn = false;
    ScreenRotation mScreenRotation = ScreenRotation::DEG_0;
    std::multimap<int32_t, std::weak_ptr<StreamWrapper>> mStreams;
};

VendorParameter makeVendorParameter(const std::string& id, int value) {
    VendorParameter result{.id = id};
    // Note: in real life, a parcelable type defined by vendor must be used,
    // here we use Int just for test purposes.
    ::aidl::android::media::audio::common::Int vendorValue{.value = value};
    result.ext.setParcelable(std::move(vendorValue));
    return result;
}

android::status_t parseVendorParameter(const VendorParameter& param, int* value) {
    std::optional<::aidl::android::media::audio::common::Int> vendorValue;
    RETURN_STATUS_IF_ERROR(param.ext.getParcelable(&vendorValue));
    if (!vendorValue.has_value()) return android::BAD_VALUE;
    *value = vendorValue.value().value;
    return android::OK;
}

class TestHalAdapterVendorExtension
    : public ::aidl::android::media::audio::BnHalAdapterVendorExtension {
  public:
    static const std::string kLegacyParameterKey;
    static const std::string kLegacyAsyncParameterKey;
    static const std::string kModuleVendorParameterId;
    static const std::string kStreamVendorParameterId;

  private:
    ndk::ScopedAStatus parseVendorParameterIds(ParameterScope in_scope,
                                               const std::string& in_rawKeys,
                                               std::vector<std::string>* _aidl_return) override {
        android::AudioParameter keys(android::String8(in_rawKeys.c_str()));
        for (size_t i = 0; i < keys.size(); ++i) {
            android::String8 key;
            if (android::status_t status = keys.getAt(i, key); status != android::OK) {
                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
            }
            switch (in_scope) {
                case ParameterScope::MODULE:
                    if (key == android::String8(kLegacyParameterKey.c_str()) ||
                        key == android::String8(kLegacyAsyncParameterKey.c_str())) {
                        _aidl_return->push_back(kModuleVendorParameterId);
                    } else {
                        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
                    }
                    break;
                case ParameterScope::STREAM:
                    if (key == android::String8(kLegacyParameterKey.c_str()) ||
                        key == android::String8(kLegacyAsyncParameterKey.c_str())) {
                        _aidl_return->push_back(kStreamVendorParameterId);
                    } else {
                        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
                    }
                    break;
            }
        }
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus parseVendorParameters(
            ParameterScope in_scope, const std::string& in_rawKeysAndValues,
            std::vector<VendorParameter>* out_syncParameters,
            std::vector<VendorParameter>* out_asyncParameters) override {
        android::AudioParameter legacy(android::String8(in_rawKeysAndValues.c_str()));
        for (size_t i = 0; i < legacy.size(); ++i) {
            android::String8 key;
            if (android::status_t status = legacy.getAt(i, key); status != android::OK) {
                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
            }
            int value;
            if (android::status_t status = legacy.getInt(key, value); status != android::OK) {
                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
            }
            std::string parameterId;
            switch (in_scope) {
                case ParameterScope::MODULE:
                    parameterId = kModuleVendorParameterId;
                    break;
                case ParameterScope::STREAM:
                    parameterId = kStreamVendorParameterId;
                    break;
            }
            if (key == android::String8(kLegacyParameterKey.c_str())) {
                out_syncParameters->push_back(makeVendorParameter(parameterId, value));
            } else if (key == android::String8(kLegacyAsyncParameterKey.c_str())) {
                out_asyncParameters->push_back(makeVendorParameter(parameterId, value));
            } else {
                return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
            }
        }
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus parseBluetoothA2dpReconfigureOffload(
            const std::string&, std::vector<VendorParameter>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus parseBluetoothLeReconfigureOffload(const std::string&,
                                                          std::vector<VendorParameter>*) override {
        return ndk::ScopedAStatus::ok();
    }
    ndk::ScopedAStatus processVendorParameters(ParameterScope in_scope,
                                               const std::vector<VendorParameter>& in_parameters,
                                               std::string* _aidl_return) override {
        android::AudioParameter legacy;
        for (const auto& vendorParam : in_parameters) {
            if ((in_scope == ParameterScope::MODULE &&
                 vendorParam.id == kModuleVendorParameterId) ||
                (in_scope == ParameterScope::STREAM &&
                 vendorParam.id == kStreamVendorParameterId)) {
                int value;
                if (android::status_t status = parseVendorParameter(vendorParam, &value);
                    status != android::OK) {
                    return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
                }
                legacy.addInt(android::String8(kLegacyParameterKey.c_str()), value);
            }
        }
        *_aidl_return = legacy.toString().c_str();
        return ndk::ScopedAStatus::ok();
    }
};

class StreamHalAidlTest : public android::StreamHalAidl {
  public:
    StreamHalAidlTest(
            std::string_view className, bool isInput, const audio_config& config,
            int32_t nominalLatency, android::StreamContextAidl&& context,
            const std::shared_ptr<::aidl::android::hardware::audio::core::IStreamCommon>& stream,
            const std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension>& vext)
        : StreamHalAidl(className, isInput, config, nominalLatency, std::move(context), stream,
                        vext, nullptr /*closeHandler*/) {}
    android::status_t dump(int /*fd*/,
                           const android::Vector<android::String16>& /*args*/) override {
        return android::OK;
    }
};

const std::string TestHalAdapterVendorExtension::kLegacyParameterKey = "aosp_test_param";
const std::string TestHalAdapterVendorExtension::kLegacyAsyncParameterKey = "aosp_test_param_async";
// Note: in real life, there is no need to explicitly separate "module" and "stream"
// parameters, here it's done just for test purposes.
const std::string TestHalAdapterVendorExtension::kModuleVendorParameterId =
        "aosp.test.module.parameter";
const std::string TestHalAdapterVendorExtension::kStreamVendorParameterId =
        "aosp.test.stream.parameter";

android::String8 createParameterString(const std::string& key, const std::string& value) {
    android::AudioParameter params;
    params.add(android::String8(key.c_str()), android::String8(value.c_str()));
    return params.toString();
}

android::String8 createParameterString(const std::string& key, int value) {
    android::AudioParameter params;
    params.addInt(android::String8(key.c_str()), value);
    return params.toString();
}

template <typename>
struct mf_traits {};
template <class T, class U>
struct mf_traits<U T::*> {
    using member_type = U;
};

}  // namespace

// Provide value printers for types generated from AIDL
// They need to be in the same namespace as the types we intend to print
namespace aidl::android::hardware::audio::core {
template <typename P>
std::enable_if_t<std::is_function_v<typename mf_traits<decltype(&P::toString)>::member_type>,
                 std::ostream&>
operator<<(std::ostream& os, const P& p) {
    return os << p.toString();
}
template <typename E>
std::enable_if_t<std::is_enum_v<E>, std::ostream&> operator<<(std::ostream& os, const E& e) {
    return os << toString(e);
}
}  // namespace aidl::android::hardware::audio::core

namespace aidl::android::media::audio::common {
template <typename P>
std::enable_if_t<std::is_function_v<typename mf_traits<decltype(&P::toString)>::member_type>,
                 std::ostream&>
operator<<(std::ostream& os, const P& p) {
    return os << p.toString();
}
template <typename E>
std::enable_if_t<std::is_enum_v<E>, std::ostream&> operator<<(std::ostream& os, const E& e) {
    return os << toString(e);
}
}  // namespace aidl::android::media::audio::common

using namespace android;

namespace {

class StreamHalMock : public virtual StreamHalInterface {
  public:
    StreamHalMock() = default;
    ~StreamHalMock() override = default;
    status_t close() override { return OK; }
    status_t getBufferSize(size_t*) override { return OK; }
    status_t getAudioProperties(audio_config_base_t*) override { return OK; }
    status_t setParameters(const String8&) override { return OK; }
    status_t getParameters(const String8&, String8*) override { return OK; }
    status_t getFrameSize(size_t*) override { return OK; }
    status_t addEffect(sp<EffectHalInterface>) override { return OK; }
    status_t removeEffect(sp<EffectHalInterface>) override { return OK; }
    status_t standby() override { return OK; }
    status_t dump(int, const Vector<String16>&) override { return OK; }
    status_t start() override { return OK; }
    status_t stop() override { return OK; }
    status_t createMmapBuffer(int32_t, struct audio_mmap_buffer_info*) override { return OK; }
    status_t getMmapPosition(struct audio_mmap_position*) override { return OK; }
    status_t setHalThreadPriority(int) override { return OK; }
    status_t legacyCreateAudioPatch(const struct audio_port_config&, std::optional<audio_source_t>,
                                    audio_devices_t) override {
        return OK;
    }
    status_t legacyReleaseAudioPatch() override { return OK; }
};

}  // namespace

class DeviceHalAidlTest : public testing::Test {
  public:
    void SetUp() override {
        mModule = ndk::SharedRefBase::make<ModuleMock>(getTestConfiguration());
        mVendorExt = ndk::SharedRefBase::make<TestHalAdapterVendorExtension>();
        mDevice = sp<DeviceHalAidl>::make("test", mModule, mVendorExt);
    }
    void TearDown() override {
        mDevice.clear();
        mVendorExt.reset();
        mModule.reset();
    }

  protected:
    std::shared_ptr<ModuleMock> mModule;
    std::shared_ptr<TestHalAdapterVendorExtension> mVendorExt;
    sp<DeviceHalAidl> mDevice;
};

TEST_F(DeviceHalAidlTest, ScreenState) {
    EXPECT_FALSE(mModule->isScreenTurnedOn());
    EXPECT_EQ(OK, mDevice->setParameters(createParameterString(AudioParameter::keyScreenState,
                                                               AudioParameter::valueOn)));
    EXPECT_TRUE(mModule->isScreenTurnedOn());
    EXPECT_EQ(OK, mDevice->setParameters(createParameterString(AudioParameter::keyScreenState,
                                                               AudioParameter::valueOff)));
    EXPECT_FALSE(mModule->isScreenTurnedOn());
    // The adaptation layer only logs a warning.
    EXPECT_EQ(OK, mDevice->setParameters(
                          createParameterString(AudioParameter::keyScreenState, "blah")));
    EXPECT_FALSE(mModule->isScreenTurnedOn());
}

TEST_F(DeviceHalAidlTest, ScreenRotation) {
    using ScreenRotation = ::aidl::android::hardware::audio::core::IModule::ScreenRotation;
    EXPECT_EQ(ScreenRotation::DEG_0, mModule->getScreenRotation());
    EXPECT_EQ(OK,
              mDevice->setParameters(createParameterString(AudioParameter::keyScreenRotation, 90)));
    EXPECT_EQ(ScreenRotation::DEG_90, mModule->getScreenRotation());
    EXPECT_EQ(OK,
              mDevice->setParameters(createParameterString(AudioParameter::keyScreenRotation, 0)));
    EXPECT_EQ(ScreenRotation::DEG_0, mModule->getScreenRotation());
    // The adaptation layer only logs a warning.
    EXPECT_EQ(OK,
              mDevice->setParameters(createParameterString(AudioParameter::keyScreenRotation, 42)));
    EXPECT_EQ(ScreenRotation::DEG_0, mModule->getScreenRotation());
}

// See http://b/357487484#comment6
TEST_F(DeviceHalAidlTest, StreamReleaseOnMapperCleanup) {
    ASSERT_EQ(OK, mDevice->initCheck());
    // Since the test is in effect probabilistic, try multiple times.
    for (int i = 0; i < 100; ++i) {
        sp<StreamOutHalInterface> stream1;
        struct audio_config config = AUDIO_CONFIG_INITIALIZER;
        config.sample_rate = 48000;
        config.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
        config.format = AUDIO_FORMAT_PCM_16_BIT;
        ASSERT_EQ(OK, mDevice->openOutputStream(42 /*handle*/, AUDIO_DEVICE_OUT_SPEAKER,
                                                AUDIO_OUTPUT_FLAG_NONE, &config, "" /*address*/,
                                                &stream1));
        ASSERT_EQ(1, stream1->getStrongCount());
        std::atomic<bool> stopReleaser = false;
        // Try to catch the moment when Hal2AidlMapper promotes its wp<StreamHalInterface> to sp<>
        // in Hal2AidlMapper::resetUnusedPatchesAndPortConfigs and release on our side in order to
        // make Hal2AidlMapper the sole owner via a temporary sp and enforce destruction of the
        // stream while the DeviceHalAidl::mLock is held.
        std::thread releaser([&stream1, &stopReleaser]() {
            while (!stopReleaser) {
                if (stream1->getStrongCount() > 1) {
                    stream1.clear();
                    break;
                }
                std::this_thread::yield();
            }
        });
        sp<StreamOutHalInterface> stream2;
        // Opening another stream triggers a call to
        // Hal2AidlMapper::resetUnusedPatchesAndPortConfigs.  It must not cause a deadlock of the
        // test (main) thread.
        ASSERT_EQ(OK, mDevice->openOutputStream(43 /*handle*/, AUDIO_DEVICE_OUT_SPEAKER,
                                                AUDIO_OUTPUT_FLAG_NONE, &config, "" /*address*/,
                                                &stream2));
        stopReleaser = true;
        releaser.join();
    }
}

// Opening a stream creates an "implicit" patch which is not handled
// by the APM. If it were handled, the APM would release it at the
// moment when the stream is closed. Need to ensure that this behavior
// is replicated for "implicit" patches as well.
TEST_F(DeviceHalAidlTest, ImplicitPatchReleaseOnOutputStreamClose) {
    ASSERT_EQ(OK, mDevice->initCheck());
    sp<StreamOutHalInterface> stream;
    struct audio_config config = AUDIO_CONFIG_INITIALIZER;
    config.sample_rate = 48000;
    config.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
    config.format = AUDIO_FORMAT_PCM_16_BIT;
    const auto patchesBeforeStreamOpen = mModule->getPatches();
    ASSERT_EQ(OK,
              mDevice->openOutputStream(42 /*handle*/, AUDIO_DEVICE_OUT_SPEAKER,
                                        AUDIO_OUTPUT_FLAG_NONE, &config, "" /*address*/, &stream));
    const auto patchesAfterStreamOpen = mModule->getPatches();
    EXPECT_EQ(patchesBeforeStreamOpen.size() + 1, patchesAfterStreamOpen.size());
    ASSERT_EQ(OK, stream->close());
    const auto patchesAfterStreamClose = mModule->getPatches();
    EXPECT_EQ(patchesBeforeStreamOpen.size(), patchesAfterStreamClose.size());
}

TEST_F(DeviceHalAidlTest, ImplicitPatchReleaseOnInputStreamClose) {
    ASSERT_EQ(OK, mDevice->initCheck());
    sp<StreamInHalInterface> stream;
    struct audio_config config = AUDIO_CONFIG_INITIALIZER;
    config.sample_rate = 48000;
    config.channel_mask = AUDIO_CHANNEL_IN_STEREO;
    config.format = AUDIO_FORMAT_PCM_16_BIT;
    const auto patchesBeforeStreamOpen = mModule->getPatches();
    ASSERT_EQ(OK, mDevice->openInputStream(42 /*handle*/, AUDIO_DEVICE_IN_BUILTIN_MIC, &config,
                                           AUDIO_INPUT_FLAG_NONE, "bottom", AUDIO_SOURCE_MIC,
                                           AUDIO_DEVICE_NONE, "" /*outputDeviceAddress*/, &stream));
    const auto patchesAfterStreamOpen = mModule->getPatches();
    EXPECT_EQ(patchesBeforeStreamOpen.size() + 1, patchesAfterStreamOpen.size());
    ASSERT_EQ(OK, stream->close());
    const auto patchesAfterStreamClose = mModule->getPatches();
    EXPECT_EQ(patchesBeforeStreamOpen.size(), patchesAfterStreamClose.size());
}

TEST_F(DeviceHalAidlTest, MultipleOutputMixePortWithSameCapabilities) {
    ASSERT_EQ(OK, mDevice->initCheck());
    std::string deviceAddress = "card=1;device=0";
    struct audio_port_device_ext usbDeviceExt{};
    usbDeviceExt.type = AUDIO_DEVICE_OUT_USB_DEVICE;
    strcpy(usbDeviceExt.address, deviceAddress.c_str());
    struct audio_port_v7 usbDevice{};
    usbDevice.id = AUDIO_PORT_HANDLE_NONE, usbDevice.role = AUDIO_PORT_ROLE_SINK,
    usbDevice.type = AUDIO_PORT_TYPE_DEVICE, usbDevice.ext.device = usbDeviceExt;
    ASSERT_EQ(OK, mDevice->setConnectedState(&usbDevice, true /*connected*/));

    std::vector<media::AudioRoute> routes;
    ASSERT_EQ(OK, mDevice->getAudioRoutes(&routes));
    AudioDeviceDescription usbDeviceDesc;
    usbDeviceDesc.type = AudioDeviceType::OUT_DEVICE;
    usbDeviceDesc.connection = AudioDeviceDescription::CONNECTION_USB;
    auto routablePortIds = mModule->getRoutableMixPortIdsFor(usbDeviceDesc);
    std::vector<sp<StreamOutHalInterface>> streams;
    int32_t ioHandle = 42;
    for (auto portId : routablePortIds) {
        struct audio_config config = AUDIO_CONFIG_INITIALIZER;
        config.sample_rate = 48000;
        config.channel_mask = AUDIO_CHANNEL_OUT_STEREO;
        config.format = AUDIO_FORMAT_PCM_16_BIT;
        sp<StreamOutHalInterface> stream;
        ASSERT_EQ(OK, mDevice->openOutputStream(static_cast<audio_io_handle_t>(ioHandle),
                                                AUDIO_DEVICE_OUT_USB_DEVICE, AUDIO_OUTPUT_FLAG_NONE,
                                                &config, deviceAddress.c_str(), &stream,
                                                {} /*sourceMetadata*/, portId));
        ASSERT_EQ(portId, mModule->getPortIdFor(ioHandle));
        // Cache the stream so that it is not closed.
        streams.push_back(stream);
        ioHandle++;
    }

    ASSERT_EQ(OK, mDevice->setConnectedState(&usbDevice, false /*connected*/));
}

TEST_F(DeviceHalAidlTest, MultipleInputMixePortWithSameCapabilities) {
    ASSERT_EQ(OK, mDevice->initCheck());
    std::string deviceAddress = "card=1;device=0";
    struct audio_port_device_ext usbDeviceExt{};
    usbDeviceExt.type = AUDIO_DEVICE_IN_USB_DEVICE;
    strcpy(usbDeviceExt.address, deviceAddress.c_str());
    struct audio_port_v7 usbDevice{};
    usbDevice.id = AUDIO_PORT_HANDLE_NONE, usbDevice.role = AUDIO_PORT_ROLE_SOURCE,
    usbDevice.type = AUDIO_PORT_TYPE_DEVICE, usbDevice.ext.device = usbDeviceExt;
    ASSERT_EQ(OK, mDevice->setConnectedState(&usbDevice, true /*connected*/));

    std::vector<media::AudioRoute> routes;
    ASSERT_EQ(OK, mDevice->getAudioRoutes(&routes));
    AudioDeviceDescription usbDeviceDesc;
    usbDeviceDesc.type = AudioDeviceType::IN_DEVICE;
    usbDeviceDesc.connection = AudioDeviceDescription::CONNECTION_USB;
    auto routablePortIds = mModule->getRoutableMixPortIdsFor(usbDeviceDesc);
    std::vector<sp<StreamInHalInterface>> streams;
    int32_t ioHandle = 42;
    for (auto portId : routablePortIds) {
        struct audio_config config = AUDIO_CONFIG_INITIALIZER;
        config.sample_rate = 48000;
        config.channel_mask = AUDIO_CHANNEL_IN_STEREO;
        config.format = AUDIO_FORMAT_PCM_16_BIT;
        sp<StreamInHalInterface> stream;
        ASSERT_EQ(OK, mDevice->openInputStream(static_cast<audio_io_handle_t>(ioHandle),
                                               AUDIO_DEVICE_IN_USB_DEVICE, &config,
                                               AUDIO_INPUT_FLAG_NONE, deviceAddress.c_str(),
                                               AUDIO_SOURCE_MIC, AUDIO_DEVICE_NONE,
                                               "" /*outputDeviceAddress*/, &stream, portId));
        ASSERT_EQ(portId, mModule->getPortIdFor(ioHandle));
        // Cache the stream so that it is not closed.
        streams.push_back(stream);
        ioHandle++;
    }

    ASSERT_EQ(OK, mDevice->setConnectedState(&usbDevice, false /*connected*/));
}

// Note `OUT_USB_HEADSET` is configured to be dynamic, see `getTestConfiguration`.
TEST_F_WITH_FLAGS(DeviceHalAidlTest, MultipleDynamicConnectionsWithExclusiveRouting,
                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::media::audio,
                                                      check_route_in_get_audio_mix_port))) {
    ASSERT_EQ(OK, mDevice->initCheck());

    const size_t NUM_DEVICES = 2;

    const std::vector<AudioProfile> pcmAudioProfiles = {
            createProfile(PcmType::INT_24_BIT, {AudioChannelLayout::LAYOUT_STEREO}, {96000}),
            createProfile(PcmType::INT_16_BIT, {AudioChannelLayout::LAYOUT_STEREO}, {16000}),
    };

    AudioDeviceDescription usbDeviceDesc = {
            .type = AudioDeviceType::OUT_HEADSET,
            .connection = AudioDeviceDescription::CONNECTION_USB,
    };

    std::vector<media::AudioRoute> routes;
    ASSERT_EQ(OK, mDevice->getAudioRoutes(&routes));

    // Find routable mix ports specified by the template.
    const auto routablePortIds = mModule->getRoutableMixPortIdsFor(usbDeviceDesc);

    // We will map the mix ports to device ports 1:1 to test routing.
    ASSERT_EQ(NUM_DEVICES, routablePortIds.size());

    const auto templatePortIds = mModule->getDevicePortIds(usbDeviceDesc);
    ASSERT_EQ(1u, templatePortIds.size());
    const int32_t templatePortId = templatePortIds[0];

    std::vector<struct audio_port_v7> devices;
    for (size_t i = 0; i < NUM_DEVICES; ++i) {
        const std::string deviceAddress =
                std::string("card=") + std::to_string(i + 1) + std::string(";device=0");

        struct audio_port_device_ext usbDeviceExt{};
        usbDeviceExt.type = AUDIO_DEVICE_OUT_USB_HEADSET;
        strcpy(usbDeviceExt.address, deviceAddress.c_str());

        struct audio_port_v7 usbDevice{};
        usbDevice.id = AUDIO_PORT_HANDLE_NONE, usbDevice.role = AUDIO_PORT_ROLE_SINK,
        usbDevice.type = AUDIO_PORT_TYPE_DEVICE, usbDevice.ext.device = usbDeviceExt;

        // Override config so that the HAL would act as if this device
        // is discovered to support the given profile and route.
        mModule->setExclusiveRoutingForPort(templatePortId,
                                            std::vector<int32_t>(1, routablePortIds[i]));
        mModule->setConnectedProfileForPort(templatePortId, pcmAudioProfiles[i]);
        mModule->setConnectedProfileForPort(routablePortIds[i], pcmAudioProfiles[i]);

        ASSERT_EQ(OK, mDevice->setConnectedState(&usbDevice, /* connected= */ true));

        devices.push_back(usbDevice);
    }

    for (size_t i_device = 0; i_device < NUM_DEVICES; ++i_device) {
        for (size_t i_mix = 0; i_mix < NUM_DEVICES; ++i_mix) {
            struct audio_port_v7 devicePort = devices[i_device];
            struct audio_port_v7 mixPort = {.type = AUDIO_PORT_TYPE_MIX};
            int32_t mixPortHalId = routablePortIds[i_mix];

            status_t expected_status = i_device == i_mix ? OK : INVALID_OPERATION;
            ASSERT_EQ(expected_status,
                      mDevice->getAudioMixPort(&devicePort, &mixPort, mixPortHalId));
        }
    }

    for (const auto& device : devices) {
        ASSERT_EQ(OK, mDevice->setConnectedState(&device, /* connected= */ false));
    }
}

class DeviceHalAidlVendorParametersTest : public testing::Test {
  public:
    void SetUp() override {
        mModule = ndk::SharedRefBase::make<ModuleMock>();
        mVendorExt = ndk::SharedRefBase::make<TestHalAdapterVendorExtension>();
        mDevice = sp<DeviceHalAidl>::make("test", mModule, mVendorExt);
    }
    void TearDown() override {
        mDevice.clear();
        mVendorExt.reset();
        mModule.reset();
    }

  protected:
    std::shared_ptr<ModuleMock> mModule;
    std::shared_ptr<TestHalAdapterVendorExtension> mVendorExt;
    sp<DeviceHalAidl> mDevice;
};

TEST_F(DeviceHalAidlVendorParametersTest, GetVendorParameter) {
    EXPECT_EQ(0UL, mModule->getRetrievedParameterIds().size());
    String8 values;
    EXPECT_EQ(OK, mDevice->getParameters(
                          String8(TestHalAdapterVendorExtension::kLegacyParameterKey.c_str()),
                          &values));
    EXPECT_EQ(1UL, mModule->getRetrievedParameterIds().size());
    if (mModule->getRetrievedParameterIds().size() >= 1) {
        EXPECT_EQ(TestHalAdapterVendorExtension::kModuleVendorParameterId,
                  mModule->getRetrievedParameterIds()[0]);
    }
}

TEST_F(DeviceHalAidlVendorParametersTest, SetVendorParameter) {
    EXPECT_EQ(0UL, mModule->getAsyncParameters().size());
    EXPECT_EQ(0UL, mModule->getSyncParameters().size());
    EXPECT_EQ(OK, mDevice->setParameters(createParameterString(
                          TestHalAdapterVendorExtension::kLegacyParameterKey, 42)));
    EXPECT_EQ(0UL, mModule->getAsyncParameters().size());
    EXPECT_EQ(1UL, mModule->getSyncParameters().size());
    EXPECT_EQ(OK, mDevice->setParameters(createParameterString(
                          TestHalAdapterVendorExtension::kLegacyAsyncParameterKey, 43)));
    EXPECT_EQ(1UL, mModule->getAsyncParameters().size());
    EXPECT_EQ(1UL, mModule->getSyncParameters().size());
    if (mModule->getSyncParameters().size() >= 1) {
        EXPECT_EQ(TestHalAdapterVendorExtension::kModuleVendorParameterId,
                  mModule->getSyncParameters()[0].id);
        int value{};
        EXPECT_EQ(android::OK, parseVendorParameter(mModule->getSyncParameters()[0], &value));
        EXPECT_EQ(42, value);
    }
    if (mModule->getAsyncParameters().size() >= 1) {
        EXPECT_EQ(TestHalAdapterVendorExtension::kModuleVendorParameterId,
                  mModule->getAsyncParameters()[0].id);
        int value{};
        EXPECT_EQ(android::OK, parseVendorParameter(mModule->getAsyncParameters()[0], &value));
        EXPECT_EQ(43, value);
    }
}

TEST_F(DeviceHalAidlVendorParametersTest, SetInvalidVendorParameters) {
    android::AudioParameter legacy;
    legacy.addInt(android::String8(TestHalAdapterVendorExtension::kLegacyParameterKey.c_str()), 42);
    legacy.addInt(android::String8(TestHalAdapterVendorExtension::kLegacyAsyncParameterKey.c_str()),
                  43);
    legacy.addInt(android::String8("random_name"), 44);
    EXPECT_EQ(0UL, mModule->getAsyncParameters().size());
    EXPECT_EQ(0UL, mModule->getSyncParameters().size());
    // TestHalAdapterVendorExtension throws an error for unknown parameters.
    EXPECT_EQ(android::BAD_VALUE, mDevice->setParameters(legacy.toString()));
    EXPECT_EQ(0UL, mModule->getAsyncParameters().size());
    EXPECT_EQ(0UL, mModule->getSyncParameters().size());
}

class StreamHalAidlVendorParametersTest : public testing::Test {
  public:
    void SetUp() override {
        mStreamCommon = ndk::SharedRefBase::make<StreamCommonMock>();
        mVendorExt = ndk::SharedRefBase::make<TestHalAdapterVendorExtension>();
        struct audio_config config = AUDIO_CONFIG_INITIALIZER;
        ::aidl::android::hardware::audio::core::StreamDescriptor descriptor;
        StreamContextAidl context(descriptor, false /*isAsynchronous*/, 0,
                                  false /*hasClipTransitionSupport*/);
        mStream =
                sp<StreamHalAidlTest>::make("test", false /*isInput*/, config, 0 /*nominalLatency*/,
                                            std::move(context), mStreamCommon, mVendorExt);
        // The stream may check for some properties after creating.
        mStreamCommon->clearParameters();
    }
    void TearDown() override {
        mStream.clear();
        mVendorExt.reset();
        mStreamCommon.reset();
    }

  protected:
    std::shared_ptr<StreamCommonMock> mStreamCommon;
    std::shared_ptr<TestHalAdapterVendorExtension> mVendorExt;
    sp<StreamHalAidlTest> mStream;
};

TEST_F(StreamHalAidlVendorParametersTest, GetVendorParameter) {
    EXPECT_EQ(0UL, mStreamCommon->getRetrievedParameterIds().size());
    String8 values;
    EXPECT_EQ(OK, mStream->getParameters(
                          String8(TestHalAdapterVendorExtension::kLegacyParameterKey.c_str()),
                          &values));
    EXPECT_EQ(1UL, mStreamCommon->getRetrievedParameterIds().size());
    if (mStreamCommon->getRetrievedParameterIds().size() >= 1) {
        EXPECT_EQ(TestHalAdapterVendorExtension::kStreamVendorParameterId,
                  mStreamCommon->getRetrievedParameterIds()[0]);
    }
}

TEST_F(StreamHalAidlVendorParametersTest, SetVendorParameter) {
    EXPECT_EQ(0UL, mStreamCommon->getAsyncParameters().size());
    EXPECT_EQ(0UL, mStreamCommon->getSyncParameters().size());
    EXPECT_EQ(OK, mStream->setParameters(createParameterString(
                          TestHalAdapterVendorExtension::kLegacyParameterKey, 42)));
    EXPECT_EQ(0UL, mStreamCommon->getAsyncParameters().size());
    EXPECT_EQ(1UL, mStreamCommon->getSyncParameters().size());
    EXPECT_EQ(OK, mStream->setParameters(createParameterString(
                          TestHalAdapterVendorExtension::kLegacyAsyncParameterKey, 43)));
    EXPECT_EQ(1UL, mStreamCommon->getAsyncParameters().size());
    EXPECT_EQ(1UL, mStreamCommon->getSyncParameters().size());
    if (mStreamCommon->getSyncParameters().size() >= 1) {
        EXPECT_EQ(TestHalAdapterVendorExtension::kStreamVendorParameterId,
                  mStreamCommon->getSyncParameters()[0].id);
        int value{};
        EXPECT_EQ(android::OK, parseVendorParameter(mStreamCommon->getSyncParameters()[0], &value));
        EXPECT_EQ(42, value);
    }
    if (mStreamCommon->getAsyncParameters().size() >= 1) {
        EXPECT_EQ(TestHalAdapterVendorExtension::kStreamVendorParameterId,
                  mStreamCommon->getAsyncParameters()[0].id);
        int value{};
        EXPECT_EQ(android::OK,
                  parseVendorParameter(mStreamCommon->getAsyncParameters()[0], &value));
        EXPECT_EQ(43, value);
    }
}

TEST_F(StreamHalAidlVendorParametersTest, SetInvalidVendorParameters) {
    android::AudioParameter legacy;
    legacy.addInt(android::String8(TestHalAdapterVendorExtension::kLegacyParameterKey.c_str()), 42);
    legacy.addInt(android::String8(TestHalAdapterVendorExtension::kLegacyAsyncParameterKey.c_str()),
                  43);
    legacy.addInt(android::String8("random_name"), 44);
    EXPECT_EQ(0UL, mStreamCommon->getAsyncParameters().size());
    EXPECT_EQ(0UL, mStreamCommon->getSyncParameters().size());
    // TestHalAdapterVendorExtension throws an error for unknown parameters.
    EXPECT_EQ(android::BAD_VALUE, mStream->setParameters(legacy.toString()));
    EXPECT_EQ(0UL, mStreamCommon->getAsyncParameters().size());
    EXPECT_EQ(0UL, mStreamCommon->getSyncParameters().size());
}

class Hal2AidlMapperTest : public testing::Test {
  public:
    void SetUp() override {
        mModule = ndk::SharedRefBase::make<ModuleMock>(getTestConfiguration());
        mMapper = std::make_unique<Hal2AidlMapper>("test", mModule);
        ASSERT_EQ(OK, mMapper->initialize());

        mConnectedPort.ext = createPortDeviceExt(AudioDeviceType::OUT_DEVICE, 0,
                                                 AudioDeviceDescription::CONNECTION_BT_A2DP);
        mConnectedPort.ext.get<AudioPortExt::device>().device.address = "00:11:22:33:44:55";
        ASSERT_EQ(OK, mMapper->setDevicePortConnectedState(mConnectedPort, true /*connected*/));

        std::mutex mutex;  // Only needed for cleanups.
        auto mapperAccessor = std::make_unique<LockedAccessor<Hal2AidlMapper>>(*mMapper, mutex);
        Hal2AidlMapper::Cleanups cleanups(*mapperAccessor);
        AudioConfig config;
        config.base.channelMask = AudioChannelLayout::make<AudioChannelLayout::layoutMask>(
                AudioChannelLayout::LAYOUT_STEREO);
        config.base.format =
                AudioFormatDescription{.type = AudioFormatType::PCM, .pcm = PcmType::INT_16_BIT};
        config.base.sampleRate = 48000;
        ASSERT_EQ(OK, mMapper->prepareToOpenStream(
                              42 /*ioHandle*/, 0 /*mixPortHalId*/,
                              mConnectedPort.ext.get<AudioPortExt::device>().device,
                              AudioIoFlags::make<AudioIoFlags::output>(0), AudioSource::DEFAULT,
                              &cleanups, &config, &mMixPortConfig, &mPatch));
        cleanups.disarmAll();
        ASSERT_NE(0, mPatch.id);
        ASSERT_NE(0, mMixPortConfig.id);
        mStream = sp<StreamHalMock>::make();
        mMapper->addStream(mStream, mMixPortConfig.id, mPatch.id);

        ASSERT_EQ(OK, mMapper->findPortConfig(mConnectedPort.ext.get<AudioPortExt::device>().device,
                                              &mDevicePortConfig));
        ASSERT_EQ(1UL, mPatch.sourcePortConfigIds.size());
        ASSERT_EQ(mMixPortConfig.id, mPatch.sourcePortConfigIds[0]);
        ASSERT_EQ(1UL, mPatch.sinkPortConfigIds.size());
        ASSERT_EQ(mDevicePortConfig.id, mPatch.sinkPortConfigIds[0]);
    }

    void TearDown() override {
        mStream.clear();
        mMapper.reset();
        mModule.reset();
    }

  protected:
    void CloseDisconnectImpl() {
        mStream.clear();
        ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    }

    void ConnectAnotherDevice() {
        mConnectedPort.ext.get<AudioPortExt::device>().device.address = "00:11:22:33:44:66";
        ASSERT_EQ(OK, mMapper->setDevicePortConnectedState(mConnectedPort, true /*connected*/));
    }

    void CreateFwkPatch(int32_t* patchId) {
        std::mutex mutex;  // Only needed for cleanups.
        auto mapperAccessor = std::make_unique<LockedAccessor<Hal2AidlMapper>>(*mMapper, mutex);
        Hal2AidlMapper::Cleanups cleanups(*mapperAccessor);
        ASSERT_EQ(OK, mMapper->createOrUpdatePatch({mMixPortConfig}, {mDevicePortConfig}, patchId,
                                                   &cleanups));
        cleanups.disarmAll();
    }

    void DisconnectDevice() {
        ASSERT_EQ(OK, mMapper->prepareToDisconnectExternalDevice(mConnectedPort));
        ASSERT_EQ(OK, mMapper->setDevicePortConnectedState(mConnectedPort, false /*connected*/));
    }

    void ReleaseFwkOnlyPatch(int32_t patchId) {
        // The patch only exists for the framework.
        EXPECT_EQ(patchId, mMapper->findFwkPatch(patchId));
        ASSERT_EQ(BAD_VALUE, mMapper->releaseAudioPatch(patchId));
        mMapper->eraseFwkPatch(patchId);
        // The patch is now erased.
        EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
    }

    std::shared_ptr<ModuleMock> mModule;
    std::unique_ptr<Hal2AidlMapper> mMapper;
    AudioPort mConnectedPort;
    AudioPortConfig mMixPortConfig;
    AudioPortConfig mDevicePortConfig;
    AudioPatch mPatch;
    sp<StreamHalInterface> mStream;
};

/**
 * External device connections and patches tests diagram.
 *
 * [Connect device] -> [Create Stream]
 *                            |-> [ (1) Close Stream] -> [Disconnect Device]
 *                            |-> [ (2) Disconnect Device]
 *                            |          |-> [ (3) Close Stream]
 *                            |          \-> [ (4) Connect Another Device]
 *                            |                    |-> (1)
 *                            |                    |-> (2) -> (3)
 *                            |                    \-> (5) -> (7)
 *                            \-> [ (5) Create/Update Fwk Patch]
 *                                       |-> [(6) Release Fwk Patch]
 *                                       |        |-> (1)
 *                                       |        \-> (2) (including reconnection)
 *                                       \-> [(7) Disconnect Device]
 *                                                |-> [Release Fwk Patch] -> [Close Stream]
 *                                                \-> (4) -> (5) -> (6) -> (1)
 *
 * Note that the test (acting on behalf of DeviceHalAidl) is responsible
 * for calling `eraseFwkPatch` and `updateFwkPatch` when needed.
 */

// (1)
TEST_F(Hal2AidlMapperTest, CloseDisconnect) {
    ASSERT_NO_FATAL_FAILURE(CloseDisconnectImpl());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
}

// (2) -> (3)
TEST_F(Hal2AidlMapperTest, DisconnectClose) {
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    mStream.clear();
}

// (2) -> (4) -> (1)
TEST_F(Hal2AidlMapperTest, DisconnectConnectCloseDisconnect) {
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    ASSERT_NO_FATAL_FAILURE(ConnectAnotherDevice());
    ASSERT_NO_FATAL_FAILURE(CloseDisconnectImpl());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
}

// (2) -> (4) -> (2) -> (3)
TEST_F(Hal2AidlMapperTest, DisconnectConnectDisconnectClose) {
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    ASSERT_NO_FATAL_FAILURE(ConnectAnotherDevice());
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    mStream.clear();
}

// (5) -> (6) -> (1)
TEST_F(Hal2AidlMapperTest, CreateFwkPatchReleaseCloseDisconnect) {
    int32_t patchId;
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&patchId));
    // Must be the patch created during stream opening.
    ASSERT_EQ(mPatch.id, patchId);
    // The patch was not reset by HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_EQ(OK, mMapper->releaseAudioPatch(patchId));
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
    ASSERT_NO_FATAL_FAILURE(CloseDisconnectImpl());
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
}

// (5) -> (6) -> (2) -> (3)
TEST_F(Hal2AidlMapperTest, CreateFwkPatchReleaseDisconnectClose) {
    int32_t patchId;
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&patchId));
    // Must be the patch created during stream opening.
    ASSERT_EQ(mPatch.id, patchId);
    // The patch was not reset by HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_EQ(OK, mMapper->releaseAudioPatch(patchId));
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    mStream.clear();
}

// (5) -> (6) -> (2) -> (4) -> (2) -> (3)
TEST_F(Hal2AidlMapperTest, CreateFwkPatchReleaseDisconnectConnectDisconnectClose) {
    int32_t patchId;
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&patchId));
    // Must be the patch created during stream opening.
    ASSERT_EQ(mPatch.id, patchId);
    // The patch was not reset by HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_EQ(OK, mMapper->releaseAudioPatch(patchId));
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_NO_FATAL_FAILURE(ConnectAnotherDevice());
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    mStream.clear();
}

// (5) -> (7) -> Release -> Close
TEST_F(Hal2AidlMapperTest, CreateFwkPatchDisconnectReleaseClose) {
    int32_t patchId;
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&patchId));
    // Must be the patch created during stream opening.
    ASSERT_EQ(mPatch.id, patchId);
    // The patch was not reset by HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    ASSERT_NO_FATAL_FAILURE(ReleaseFwkOnlyPatch(patchId));

    mStream.clear();
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
}

// (5) -> (7) -> (4) -> (5) -> (6) -> (1)
TEST_F(Hal2AidlMapperTest, CreateFwkPatchDisconnectConnectUpdateReleaseCloseDisconnect) {
    int32_t patchId;
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&patchId));
    // Must be the patch created during stream opening.
    ASSERT_EQ(mPatch.id, patchId);
    // The patch was not reset by HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch now only exists for the framework.
    EXPECT_EQ(mPatch.id, mMapper->findFwkPatch(mPatch.id));

    ASSERT_NO_FATAL_FAILURE(ConnectAnotherDevice());
    // Change the device address locally, for patch update.
    mDevicePortConfig.ext.get<AudioPortExt::device>().device.address =
            mConnectedPort.ext.get<AudioPortExt::device>().device.address;
    int32_t newPatchId = patchId;
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&newPatchId));
    EXPECT_NE(patchId, newPatchId);
    mMapper->updateFwkPatch(patchId, newPatchId);
    EXPECT_EQ(newPatchId, mMapper->findFwkPatch(patchId));
    // Just in case, check that HAL patch ID is not listed as a fwk patch.
    EXPECT_EQ(0, mMapper->findFwkPatch(newPatchId));
    // Verify that device port config was updated.
    ASSERT_EQ(OK, mMapper->findPortConfig(mConnectedPort.ext.get<AudioPortExt::device>().device,
                                          &mDevicePortConfig));

    ASSERT_EQ(OK, mMapper->releaseAudioPatch(newPatchId));
    // The patch does not exist both for the fwk and the HAL, must not be listed under fwkPatches.
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
    // Just in case, check that HAL patch ID is not listed.
    EXPECT_EQ(0, mMapper->findFwkPatch(newPatchId));

    ASSERT_NO_FATAL_FAILURE(CloseDisconnectImpl());
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    EXPECT_EQ(0, mMapper->findFwkPatch(patchId));
    EXPECT_EQ(0, mMapper->findFwkPatch(newPatchId));
}

// (2) -> (4) -> (5) -> (7) -> Release -> Close
TEST_F(Hal2AidlMapperTest, DisconnectConnectCreateFwkPatchDisconnectReleaseClose) {
    const int32_t patchId = mPatch.id;
    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    // The patch is owned by HAL, must not be listed under fwkPatches after disconnection.
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));

    ASSERT_NO_FATAL_FAILURE(ConnectAnotherDevice());
    // Change the device address locally, for patch update.
    mDevicePortConfig.ext.get<AudioPortExt::device>().device.address =
            mConnectedPort.ext.get<AudioPortExt::device>().device.address;
    int32_t newPatchId = 0;  // Use 0 since the fwk does not know about the HAL patch.
    EXPECT_EQ(0, mMapper->findFwkPatch(newPatchId));
    ASSERT_NO_FATAL_FAILURE(CreateFwkPatch(&newPatchId));
    EXPECT_NE(0, newPatchId);
    EXPECT_NE(patchId, newPatchId);
    // Just in case, check that HAL patch ID is not listed as a fwk patch.
    EXPECT_EQ(0, mMapper->findFwkPatch(newPatchId));
    // Verify that device port config was updated.
    ASSERT_EQ(OK, mMapper->findPortConfig(mConnectedPort.ext.get<AudioPortExt::device>().device,
                                          &mDevicePortConfig));

    ASSERT_NO_FATAL_FAILURE(DisconnectDevice());
    ASSERT_NO_FATAL_FAILURE(ReleaseFwkOnlyPatch(newPatchId));

    mStream.clear();
    EXPECT_EQ(0, mMapper->findFwkPatch(mPatch.id));
    EXPECT_EQ(0, mMapper->findFwkPatch(newPatchId));
}

TEST_F(Hal2AidlMapperTest, ChangeTransientPatchDevice) {
    std::mutex mutex;  // Only needed for cleanups.
    auto mapperAccessor = std::make_unique<LockedAccessor<Hal2AidlMapper>>(*mMapper, mutex);
    Hal2AidlMapper::Cleanups cleanups(*mapperAccessor);
    AudioConfig config;
    config.base.channelMask = AudioChannelLayout::make<AudioChannelLayout::layoutMask>(
            AudioChannelLayout::LAYOUT_STEREO);
    config.base.format =
            AudioFormatDescription{.type = AudioFormatType::PCM, .pcm = PcmType::INT_16_BIT};
    config.base.sampleRate = 48000;
    AudioDevice defaultDevice;
    defaultDevice.type.type = AudioDeviceType::IN_DEFAULT;
    AudioPortConfig mixPortConfig;
    AudioPatch transientPatch;
    ASSERT_EQ(OK, mMapper->prepareToOpenStream(43 /*ioHandle*/, 0 /*mixPortHalId*/, defaultDevice,
                                               AudioIoFlags::make<AudioIoFlags::input>(0),
                                               AudioSource::DEFAULT, &cleanups, &config,
                                               &mixPortConfig, &transientPatch));
    cleanups.disarmAll();
    ASSERT_NE(0, transientPatch.id);
    ASSERT_NE(0, mixPortConfig.id);
    sp<StreamHalInterface> stream = sp<StreamHalMock>::make();
    mMapper->addStream(stream, mixPortConfig.id, transientPatch.id);

    AudioPatch patch{};
    int32_t patchId;
    AudioPortConfig backMicPortConfig;
    backMicPortConfig.channelMask = config.base.channelMask;
    backMicPortConfig.format = config.base.format;
    backMicPortConfig.sampleRate = aidl::android::media::audio::common::Int{config.base.sampleRate};
    backMicPortConfig.flags = AudioIoFlags::make<AudioIoFlags::input>(0);
    backMicPortConfig.ext = createPortDeviceExt(AudioDeviceType::IN_MICROPHONE_BACK, 0);
    ASSERT_EQ(OK, mMapper->createOrUpdatePatch({backMicPortConfig}, {mixPortConfig}, &patchId,
                                               &cleanups));
    cleanups.disarmAll();
    ASSERT_EQ(android::OK,
              mMapper->findPortConfig(backMicPortConfig.ext.get<AudioPortExt::device>().device,
                                      &backMicPortConfig));
    EXPECT_NE(0, backMicPortConfig.id);

    EXPECT_EQ(transientPatch.id, patchId);
    auto patches = mModule->getPatches();
    auto patchIt = findById(patches, patchId);
    ASSERT_NE(patchIt, patches.end());
    EXPECT_EQ(std::vector<int32_t>{backMicPortConfig.id}, patchIt->sourcePortConfigIds);
    EXPECT_EQ(std::vector<int32_t>{mixPortConfig.id}, patchIt->sinkPortConfigIds);
}

TEST_F(Hal2AidlMapperTest, SetAudioPortConfigGainChangeExistingPortConfig) {
    // First set config, then update gain.
    AudioPortConfig speakerPortConfig;
    speakerPortConfig.ext = createPortDeviceExt(AudioDeviceType::OUT_SPEAKER, 0);
    speakerPortConfig.channelMask = AudioChannelLayout::make<AudioChannelLayout::layoutMask>(
            AudioChannelLayout::LAYOUT_STEREO);
    speakerPortConfig.format =
            AudioFormatDescription{.type = AudioFormatType::PCM, .pcm = PcmType::INT_16_BIT};
    speakerPortConfig.sampleRate = ::aidl::android::media::audio::common::Int(48000);
    AudioPortConfig resultingPortConfig;
    ASSERT_EQ(OK,
              mMapper->setPortConfig(speakerPortConfig, std::set<int32_t>(), &resultingPortConfig));
    EXPECT_NE(0, resultingPortConfig.id);
    EXPECT_NE(0, resultingPortConfig.portId);

    AudioPortConfig gainUpdate;
    gainUpdate.ext = createPortDeviceExt(AudioDeviceType::OUT_SPEAKER, 0);
    AudioGainConfig gainConfig{.index = -1,
                               .mode = 1 << static_cast<int>(AudioGainMode::JOINT),
                               .channelMask = AudioChannelLayout{},
                               .values = std::vector<int32_t>{-3200},
                               .rampDurationMs = 0};
    gainUpdate.gain = gainConfig;
    AudioPortConfig resultingGainUpdate;
    ASSERT_EQ(OK, mMapper->setPortConfig(gainUpdate, std::set<int32_t>(), &resultingGainUpdate));
    EXPECT_EQ(resultingPortConfig.id, resultingGainUpdate.id);
    auto updatedPortConfig = mModule->getPortConfig(resultingGainUpdate.id);
    ASSERT_TRUE(updatedPortConfig.has_value());
    ASSERT_TRUE(updatedPortConfig->gain.has_value());
    EXPECT_EQ(gainConfig, updatedPortConfig->gain);
}

TEST_F(Hal2AidlMapperTest, SetAudioPortConfigGainChangeFromScratch) {
    // Set gain as the first operation, the HAL should suggest the rest of the configuration.
    AudioPortConfig gainSet;
    gainSet.ext = createPortDeviceExt(AudioDeviceType::OUT_SPEAKER, 0);
    AudioGainConfig gainConfig{.index = -1,
                               .mode = 1 << static_cast<int>(AudioGainMode::JOINT),
                               .channelMask = AudioChannelLayout{},
                               .values = std::vector<int32_t>{-3200},
                               .rampDurationMs = 0};
    gainSet.gain = gainConfig;
    AudioPortConfig resultingPortConfig;
    ASSERT_EQ(OK, mMapper->setPortConfig(gainSet, std::set<int32_t>(), &resultingPortConfig));
    EXPECT_NE(0, resultingPortConfig.id);
    EXPECT_NE(0, resultingPortConfig.portId);
    auto portConfig = mModule->getPortConfig(resultingPortConfig.id);
    ASSERT_TRUE(portConfig.has_value());
    ASSERT_TRUE(portConfig->gain.has_value());
    EXPECT_EQ(gainConfig, portConfig->gain);
}

// Note `OUT_USB_HEADSET` is configured to be dynamic, see `getTestConfiguration`.
TEST_F_WITH_FLAGS(Hal2AidlMapperTest, MultipleDynamicConnectionsWithExclusiveRouting,
                  REQUIRES_FLAGS_ENABLED(ACONFIG_FLAG(com::android::media::audio,
                                                      check_route_in_get_audio_mix_port))) {
    const size_t NUM_DEVICES = 2;
    const std::vector<AudioProfile> pcmAudioProfiles = {
            createProfile(PcmType::INT_24_BIT, {AudioChannelLayout::LAYOUT_STEREO}, {96000}),
            createProfile(PcmType::INT_16_BIT, {AudioChannelLayout::LAYOUT_STEREO}, {16000}),
    };

    AudioDeviceDescription usbDeviceDesc = {
            .type = AudioDeviceType::OUT_HEADSET,
            .connection = AudioDeviceDescription::CONNECTION_USB,
    };

    const auto routablePortIds = mModule->getRoutableMixPortIdsFor(usbDeviceDesc);

    // We will map the mix ports to device ports 1:1 to test routing.
    ASSERT_EQ(NUM_DEVICES, routablePortIds.size());

    const auto templatePortIds = mModule->getDevicePortIds(usbDeviceDesc);
    ASSERT_EQ(1u, templatePortIds.size());
    const int32_t templatePortId = templatePortIds[0];

    std::vector<int32_t> devicePortIds;
    for (size_t i = 0; i < NUM_DEVICES; ++i) {
        const std::string deviceAddress =
                std::string("card=") + std::to_string(i + 1) + std::string(";device=0");

        AudioPort usbDevicePort;
        usbDevicePort.ext = createPortDeviceExt(AudioDeviceType::OUT_HEADSET, 0,
                                                AudioDeviceDescription::CONNECTION_USB);
        usbDevicePort.ext.get<AudioPortExt::device>().device.address = deviceAddress;

        // Override config so that the HAL would act as if this device
        // is discovered to support the given profile and route.
        mModule->setExclusiveRoutingForPort(templatePortId,
                                            std::vector<int32_t>(1, routablePortIds[i]));
        mModule->setConnectedProfileForPort(routablePortIds[i], pcmAudioProfiles[i]);
        mModule->setConnectedProfileForPort(templatePortId, pcmAudioProfiles[i]);

        ASSERT_EQ(OK, mMapper->setDevicePortConnectedState(usbDevicePort, /* connected= */ true));

        int32_t portId = mModule->getDevicePortIdWithAddress(deviceAddress, /* isInput= */ false);
        ASSERT_NE(-1, portId);
        devicePortIds.push_back(portId);
    }

    for (size_t i_device = 0; i_device < NUM_DEVICES; ++i_device) {
        for (size_t i_mix = 0; i_mix < NUM_DEVICES; ++i_mix) {
            int32_t devicePortId = devicePortIds[i_device];
            int32_t mixPortId = routablePortIds[i_mix];
            bool is_routable = i_device == i_mix;
            ASSERT_EQ(is_routable, mMapper->isRoutable(devicePortId, mixPortId));
        }
    }
}
