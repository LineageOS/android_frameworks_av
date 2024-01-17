/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include <memory>
#include <map>
#include <set>
#include <utility>
#include <vector>

#include <aidl/android/hardware/audio/core/IModule.h>
#include <media/AidlConversionUtil.h>

#include "Cleanups.h"

namespace android {

class Hal2AidlMapper;
class StreamHalInterface;

// The mapper class is needed because the framework was not yet updated to operate on AIDL-based
// structures directly. Mapper does the job of translating the "legacy" way of identifying ports
// and port configs (by device addresses and I/O handles) into AIDL IDs. Once the framework will
// be updated to provide these IDs directly to libaudiohal, the need for the mapper will cease.
//
// Note that unlike DeviceHalInterface, which sometimes allows a method to return an error,
// but still consider some of the outputs to be valid (for example, in 'open{Input|Output}Stream'),
// 'Hal2AidlMapper' follows the Binder convention. It means that if a method returns an error,
// the outputs may not be initialized at all and should not be considered by the caller.
class Hal2AidlMapper {
  public:
    using Cleanups = Cleanups<Hal2AidlMapper>;

    Hal2AidlMapper(
            const std::string& instance,
            const std::shared_ptr<::aidl::android::hardware::audio::core::IModule>& module);

    void addStream(const sp<StreamHalInterface>& stream, int32_t portConfigId, int32_t patchId);
    status_t createOrUpdatePatch(
            const std::vector<::aidl::android::media::audio::common::AudioPortConfig>& sources,
            const std::vector<::aidl::android::media::audio::common::AudioPortConfig>& sinks,
            int32_t* patchId, Cleanups* cleanups);
    status_t findPortConfig(
            const ::aidl::android::media::audio::common::AudioDevice& device,
            ::aidl::android::media::audio::common::AudioPortConfig* portConfig);
    status_t getAudioMixPort(
            int32_t ioHandle, ::aidl::android::media::audio::common::AudioPort* port);
    status_t getAudioPortCached(
            const ::aidl::android::media::audio::common::AudioDevice& device,
            ::aidl::android::media::audio::common::AudioPort* port);
    template<typename OutputContainer, typename Func>
    status_t getAudioPorts(OutputContainer* ports, Func converter) {
        return ::aidl::android::convertContainer(mPorts, ports,
                [&converter](const auto& pair) { return converter(pair.second); });
    }
    template<typename OutputContainer, typename Func>
    status_t getAudioRoutes(OutputContainer* routes, Func converter) {
        return ::aidl::android::convertContainer(mRoutes, routes, converter);
    }
    status_t initialize();
    status_t prepareToDisconnectExternalDevice(
            const ::aidl::android::media::audio::common::AudioPort& devicePort);
    // If the resulting 'mixPortConfig->id' is 0, that means the stream was not created,
    // and 'config' is a suggested config.
    status_t prepareToOpenStream(
        int32_t ioHandle,
        const ::aidl::android::media::audio::common::AudioDevice& device,
        const ::aidl::android::media::audio::common::AudioIoFlags& flags,
        ::aidl::android::media::audio::common::AudioSource source,
        Cleanups* cleanups,
        ::aidl::android::media::audio::common::AudioConfig* config,
        ::aidl::android::media::audio::common::AudioPortConfig* mixPortConfig,
        ::aidl::android::hardware::audio::core::AudioPatch* patch);
    status_t setPortConfig(
        const ::aidl::android::media::audio::common::AudioPortConfig& requestedPortConfig,
        const std::set<int32_t>& destinationPortIds,
        ::aidl::android::media::audio::common::AudioPortConfig* portConfig,
        Cleanups* cleanups = nullptr);
    status_t releaseAudioPatch(int32_t patchId);
    void resetUnusedPatchesPortConfigsAndPorts();
    status_t setDevicePortConnectedState(
            const ::aidl::android::media::audio::common::AudioPort& devicePort, bool connected);

  private:
    // IDs of ports for connected external devices, and whether they are held by streams.
    using ConnectedPorts = std::map<int32_t /*port ID*/, bool>;
    using Patches = std::map<int32_t /*patch ID*/,
            ::aidl::android::hardware::audio::core::AudioPatch>;
    using PortConfigs = std::map<int32_t /*port config ID*/,
            ::aidl::android::media::audio::common::AudioPortConfig>;
    using Ports = std::map<int32_t /*port ID*/, ::aidl::android::media::audio::common::AudioPort>;
    using Routes = std::vector<::aidl::android::hardware::audio::core::AudioRoute>;
    // Answers the question "whether portID 'first' is reachable from portID 'second'?"
    // It's not a map because both portIDs are known. The matrix is symmetric.
    using RoutingMatrix = std::set<std::pair<int32_t, int32_t>>;
    // There is always a port config ID set. The patch ID is set after stream
    // creation, and can be set to '-1' later if the framework happens to create
    // a patch between the same endpoints. In that case, the ownership of the patch
    // is on the framework.
    using Streams = std::map<wp<StreamHalInterface>,
            std::pair<int32_t /*port config ID*/, int32_t /*patch ID*/>>;

    const std::string mInstance;
    const std::shared_ptr<::aidl::android::hardware::audio::core::IModule> mModule;

    bool audioDeviceMatches(const ::aidl::android::media::audio::common::AudioDevice& device,
            const ::aidl::android::media::audio::common::AudioPort& p);
    bool audioDeviceMatches(const ::aidl::android::media::audio::common::AudioDevice& device,
            const ::aidl::android::media::audio::common::AudioPortConfig& p);
    // If the 'result->id' is 0, that means, the config was not created/updated,
    // and the 'result' is a suggestion from the HAL.
    status_t createOrUpdatePortConfig(
            const ::aidl::android::media::audio::common::AudioPortConfig& requestedPortConfig,
            ::aidl::android::media::audio::common::AudioPortConfig* result, bool *created);
    status_t createOrUpdatePortConfigRetry(
            const ::aidl::android::media::audio::common::AudioPortConfig& requestedPortConfig,
            ::aidl::android::media::audio::common::AudioPortConfig* result, bool *created);
    void eraseConnectedPort(int32_t portId);
    status_t findOrCreatePatch(
        const std::set<int32_t>& sourcePortConfigIds,
        const std::set<int32_t>& sinkPortConfigIds,
        ::aidl::android::hardware::audio::core::AudioPatch* patch, bool* created);
    status_t findOrCreatePatch(
        const ::aidl::android::hardware::audio::core::AudioPatch& requestedPatch,
        ::aidl::android::hardware::audio::core::AudioPatch* patch, bool* created);
    status_t findOrCreateDevicePortConfig(
            const ::aidl::android::media::audio::common::AudioDevice& device,
            const ::aidl::android::media::audio::common::AudioConfig* config,
            ::aidl::android::media::audio::common::AudioPortConfig* portConfig,
            bool* created);
    // If the resulting 'portConfig->id' is 0, that means the config was not created,
    // and 'portConfig' is a suggested config.
    status_t findOrCreateMixPortConfig(
            const ::aidl::android::media::audio::common::AudioConfig& config,
            const std::optional<::aidl::android::media::audio::common::AudioIoFlags>& flags,
            int32_t ioHandle,
            ::aidl::android::media::audio::common::AudioSource source,
            const std::set<int32_t>& destinationPortIds,
            ::aidl::android::media::audio::common::AudioPortConfig* portConfig, bool* created);
    status_t findOrCreatePortConfig(
        const ::aidl::android::media::audio::common::AudioPortConfig& requestedPortConfig,
        const std::set<int32_t>& destinationPortIds,
        ::aidl::android::media::audio::common::AudioPortConfig* portConfig, bool* created);
    Patches::iterator findPatch(const std::set<int32_t>& sourcePortConfigIds,
            const std::set<int32_t>& sinkPortConfigIds);
    Ports::iterator findPort(const ::aidl::android::media::audio::common::AudioDevice& device);
    Ports::iterator findPort(
            const ::aidl::android::media::audio::common::AudioConfig& config,
            const ::aidl::android::media::audio::common::AudioIoFlags& flags,
            const std::set<int32_t>& destinationPortIds);
    PortConfigs::iterator findPortConfig(
            const ::aidl::android::media::audio::common::AudioDevice& device);
    PortConfigs::iterator findPortConfig(
            const std::optional<::aidl::android::media::audio::common::AudioConfig>& config,
            const std::optional<::aidl::android::media::audio::common::AudioIoFlags>& flags,
            int32_t ioHandle);
    bool isPortBeingHeld(int32_t portId);
    status_t prepareToOpenStreamHelper(
        int32_t ioHandle, int32_t devicePortId, int32_t devicePortConfigId,
        const ::aidl::android::media::audio::common::AudioIoFlags& flags,
        ::aidl::android::media::audio::common::AudioSource source,
        const ::aidl::android::media::audio::common::AudioConfig& initialConfig,
        Cleanups* cleanups, ::aidl::android::media::audio::common::AudioConfig* config,
        ::aidl::android::media::audio::common::AudioPortConfig* mixPortConfig,
        ::aidl::android::hardware::audio::core::AudioPatch* patch);
    bool portConfigBelongsToPort(int32_t portConfigId, int32_t portId) {
        auto it = mPortConfigs.find(portConfigId);
        return it != mPortConfigs.end() && it->second.portId == portId;
    }
    status_t releaseAudioPatches(const std::set<int32_t>& patchIds);
    void resetPatch(int32_t patchId) { (void)releaseAudioPatch(patchId); }
    void resetPortConfig(int32_t portConfigId);
    void resetUnusedPortConfigsAndPorts();
    status_t updateAudioPort(
            int32_t portId, ::aidl::android::media::audio::common::AudioPort* port);
    status_t updateRoutes();
    void updateDynamicMixPorts();

    Ports mPorts;
    // Remote submix "template" ports (no address specified, no profiles).
    // They are excluded from `mPorts` as their presence confuses the framework code.
    std::optional<::aidl::android::media::audio::common::AudioPort> mRemoteSubmixIn;
    std::optional<::aidl::android::media::audio::common::AudioPort> mRemoteSubmixOut;
    int32_t mDefaultInputPortId = -1;
    int32_t mDefaultOutputPortId = -1;
    PortConfigs mPortConfigs;
    std::set<int32_t> mInitialPortConfigIds;
    Patches mPatches;
    Routes mRoutes;
    RoutingMatrix mRoutingMatrix;
    Streams mStreams;
    ConnectedPorts mConnectedPorts;
    std::pair<int32_t, ::aidl::android::media::audio::common::AudioPort>
            mDisconnectedPortReplacement;
    std::set<int32_t> mDynamicMixPortIds;
};

}  // namespace android
