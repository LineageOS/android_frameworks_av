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

#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <aidl/android/media/audio/IHalAdapterVendorExtension.h>
#include <aidl/android/hardware/audio/core/BpModule.h>
#include <aidl/android/hardware/audio/core/sounddose/BpSoundDose.h>
#include <android-base/thread_annotations.h>
#include <media/audiohal/DeviceHalInterface.h>
#include <media/audiohal/EffectHalInterface.h>

#include "Cleanups.h"
#include "ConversionHelperAidl.h"
#include "Hal2AidlMapper.h"

namespace android {

class StreamOutHalInterfaceCallback;
class StreamOutHalInterfaceEventCallback;
class StreamOutHalInterfaceLatencyModeCallback;

// The role of the broker is to connect AIDL callback interface implementations
// with StreamOut callback implementations. Since AIDL requires all callbacks
// to be provided upfront, while libaudiohal interfaces allow late registration,
// there is a need to coordinate the matching process.
class CallbackBroker : public virtual RefBase {
  public:
    virtual ~CallbackBroker() = default;
    // The cookie is always the stream instance pointer. We don't use weak pointers to avoid extra
    // costs on reference counting. The stream cleans up related entries on destruction. Since
    // access to the callbacks map is synchronized, the possibility for pointer aliasing due to
    // allocation of a new stream at the address of previously deleted stream is avoided.
    virtual void clearCallbacks(void* cookie) = 0;
    virtual sp<StreamOutHalInterfaceCallback> getStreamOutCallback(void* cookie) = 0;
    virtual void setStreamOutCallback(void* cookie, const sp<StreamOutHalInterfaceCallback>&) = 0;
    virtual sp<StreamOutHalInterfaceEventCallback> getStreamOutEventCallback(void* cookie) = 0;
    virtual void setStreamOutEventCallback(void* cookie,
            const sp<StreamOutHalInterfaceEventCallback>&) = 0;
    virtual sp<StreamOutHalInterfaceLatencyModeCallback> getStreamOutLatencyModeCallback(
            void* cookie) = 0;
    virtual void setStreamOutLatencyModeCallback(
            void* cookie, const sp<StreamOutHalInterfaceLatencyModeCallback>&) = 0;
};

class MicrophoneInfoProvider : public virtual RefBase {
  public:
    using Info = std::vector<::aidl::android::media::audio::common::MicrophoneInfo>;
    virtual ~MicrophoneInfoProvider() = default;
    // Returns a nullptr if the HAL does not support microphone info retrieval.
    virtual Info const* getMicrophoneInfo() = 0;
};

class DeviceHalAidl : public DeviceHalInterface, public ConversionHelperAidl,
                      public CallbackBroker, public MicrophoneInfoProvider {
  public:
    status_t getAudioPorts(std::vector<media::audio::common::AudioPort> *ports) override;

    status_t getAudioRoutes(std::vector<media::AudioRoute> *routes) override;

    status_t getSupportedModes(std::vector<media::audio::common::AudioMode> *modes) override;

    // Sets the value of 'devices' to a bitmask of 1 or more values of audio_devices_t.
    status_t getSupportedDevices(uint32_t *devices) override;

    // Check to see if the audio hardware interface has been initialized.
    status_t initCheck() override;

    // Set the audio volume of a voice call. Range is between 0.0 and 1.0.
    status_t setVoiceVolume(float volume) override;

    // Set the audio volume for all audio activities other than voice call.
    status_t setMasterVolume(float volume) override;

    // Get the current master volume value for the HAL.
    status_t getMasterVolume(float *volume) override;

    // Called when the audio mode changes.
    status_t setMode(audio_mode_t mode) override;

    // Muting control.
    status_t setMicMute(bool state) override;

    status_t getMicMute(bool* state) override;

    status_t setMasterMute(bool state) override;

    status_t getMasterMute(bool *state) override;

    // Set global audio parameters.
    status_t setParameters(const String8& kvPairs) override;

    // Get global audio parameters.
    status_t getParameters(const String8& keys, String8 *values) override;

    // Returns audio input buffer size according to parameters passed.
    status_t getInputBufferSize(struct audio_config* config, size_t* size) override;

    // Creates and opens the audio hardware output stream. The stream is closed
    // by releasing all references to the returned object.
    status_t openOutputStream(audio_io_handle_t handle, audio_devices_t devices,
                              audio_output_flags_t flags, struct audio_config* config,
                              const char* address, sp<StreamOutHalInterface>* outStream) override;

    // Creates and opens the audio hardware input stream. The stream is closed
    // by releasing all references to the returned object.
    status_t openInputStream(audio_io_handle_t handle, audio_devices_t devices,
                             struct audio_config* config, audio_input_flags_t flags,
                             const char* address, audio_source_t source,
                             audio_devices_t outputDevice, const char* outputDeviceAddress,
                             sp<StreamInHalInterface>* inStream) override;

    // Returns whether createAudioPatch and releaseAudioPatch operations are supported.
    status_t supportsAudioPatches(bool* supportsPatches) override;

    // Creates an audio patch between several source and sink ports.
    status_t createAudioPatch(unsigned int num_sources, const struct audio_port_config* sources,
                              unsigned int num_sinks, const struct audio_port_config* sinks,
                              audio_patch_handle_t* patch) override;

    // Releases an audio patch.
    status_t releaseAudioPatch(audio_patch_handle_t patch) override;

    // Fills the list of supported attributes for a given audio port.
    status_t getAudioPort(struct audio_port* port) override;

    // Fills the list of supported attributes for a given audio port.
    status_t getAudioPort(struct audio_port_v7 *port) override;

    // Set audio port configuration.
    status_t setAudioPortConfig(const struct audio_port_config* config) override;

    // List microphones
    status_t getMicrophones(std::vector<audio_microphone_characteristic_t>* microphones) override;

    status_t addDeviceEffect(
            const struct audio_port_config *device, sp<EffectHalInterface> effect) override;

    status_t removeDeviceEffect(
            const struct audio_port_config *device, sp<EffectHalInterface> effect) override;

    status_t getMmapPolicyInfos(media::audio::common::AudioMMapPolicyType policyType __unused,
                                std::vector<media::audio::common::AudioMMapPolicyInfo>* policyInfos
                                        __unused) override;

    int32_t getAAudioMixerBurstCount() override;

    int32_t getAAudioHardwareBurstMinUsec() override;

    error::Result<audio_hw_sync_t> getHwAvSync() override;

    status_t supportsBluetoothVariableLatency(bool* supports __unused) override;

    status_t getSoundDoseInterface(const std::string& module,
                                   ::ndk::SpAIBinder* soundDoseBinder) override;

    status_t prepareToDisconnectExternalDevice(const struct audio_port_v7 *port) override;

    status_t setConnectedState(const struct audio_port_v7 *port, bool connected) override;

    status_t setSimulateDeviceConnections(bool enabled) override;

    status_t getAudioMixPort(const struct audio_port_v7* devicePort,
                             struct audio_port_v7* mixPort) override;

    status_t dump(int __unused, const Vector<String16>& __unused) override;

  private:
    friend class sp<DeviceHalAidl>;

    struct Callbacks {  // No need to use `atomic_wp` because access is serialized.
        wp<StreamOutHalInterfaceCallback> out;
        wp<StreamOutHalInterfaceEventCallback> event;
        wp<StreamOutHalInterfaceLatencyModeCallback> latency;
    };
    struct Microphones {
        enum Status { UNKNOWN, NOT_SUPPORTED, QUERIED };
        Status status = Status::UNKNOWN;
        MicrophoneInfoProvider::Info info;
    };

    // Must not be constructed directly by clients.
    DeviceHalAidl(
            const std::string& instance,
            const std::shared_ptr<::aidl::android::hardware::audio::core::IModule>& module,
            const std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension>& vext);

    ~DeviceHalAidl() override = default;

    status_t filterAndRetrieveBtA2dpParameters(AudioParameter &keys, AudioParameter *result);
    status_t filterAndRetrieveBtLeParameters(AudioParameter &keys, AudioParameter *result);
    status_t filterAndUpdateBtA2dpParameters(AudioParameter &parameters);
    status_t filterAndUpdateBtHfpParameters(AudioParameter &parameters);
    status_t filterAndUpdateBtLeParameters(AudioParameter &parameters);
    status_t filterAndUpdateBtScoParameters(AudioParameter &parameters);
    status_t filterAndUpdateScreenParameters(AudioParameter &parameters);
    status_t filterAndUpdateTelephonyParameters(AudioParameter &parameters);

    // CallbackBroker implementation
    void clearCallbacks(void* cookie) override;
    sp<StreamOutHalInterfaceCallback> getStreamOutCallback(void* cookie) override;
    void setStreamOutCallback(void* cookie, const sp<StreamOutHalInterfaceCallback>& cb) override;
    sp<StreamOutHalInterfaceEventCallback> getStreamOutEventCallback(void* cookie) override;
    void setStreamOutEventCallback(void* cookie,
            const sp<StreamOutHalInterfaceEventCallback>& cb) override;
    sp<StreamOutHalInterfaceLatencyModeCallback> getStreamOutLatencyModeCallback(
            void* cookie) override;
    void setStreamOutLatencyModeCallback(
            void* cookie, const sp<StreamOutHalInterfaceLatencyModeCallback>& cb) override;
    // Implementation helpers.
    template<class C> sp<C> getCallbackImpl(void* cookie, wp<C> Callbacks::* field);
    template<class C> void setCallbackImpl(void* cookie, wp<C> Callbacks::* field, const sp<C>& cb);

    // MicrophoneInfoProvider implementation
    MicrophoneInfoProvider::Info const* getMicrophoneInfo() override;

    const std::string mInstance;
    const std::shared_ptr<::aidl::android::hardware::audio::core::IModule> mModule;
    const std::shared_ptr<::aidl::android::media::audio::IHalAdapterVendorExtension> mVendorExt;
    const std::shared_ptr<::aidl::android::hardware::audio::core::ITelephony> mTelephony;
    const std::shared_ptr<::aidl::android::hardware::audio::core::IBluetooth> mBluetooth;
    const std::shared_ptr<::aidl::android::hardware::audio::core::IBluetoothA2dp> mBluetoothA2dp;
    const std::shared_ptr<::aidl::android::hardware::audio::core::IBluetoothLe> mBluetoothLe;
    const std::shared_ptr<::aidl::android::hardware::audio::core::sounddose::ISoundDose> mSoundDose;

    std::mutex mLock;
    std::map<void*, Callbacks> mCallbacks GUARDED_BY(mLock);
    std::set<audio_port_handle_t> mDeviceDisconnectionNotified GUARDED_BY(mLock);
    Hal2AidlMapper mMapper GUARDED_BY(mLock);
    LockedAccessor<Hal2AidlMapper> mMapperAccessor;
    Microphones mMicrophones GUARDED_BY(mLock);
};

} // namespace android
