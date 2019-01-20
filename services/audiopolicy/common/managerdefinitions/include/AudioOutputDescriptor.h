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

#pragma once

#include <sys/types.h>

#include <utils/Errors.h>
#include <utils/Timers.h>
#include <utils/KeyedVector.h>
#include <system/audio.h>
#include <RoutingStrategy.h>
#include "AudioIODescriptorInterface.h"
#include "AudioPort.h"
#include "ClientDescriptor.h"
#include "DeviceDescriptor.h"
#include <map>

namespace android {

class IOProfile;
class AudioMix;
class AudioPolicyClientInterface;

// descriptor for audio outputs. Used to maintain current configuration of each opened audio output
// and keep track of the usage of this output by each audio stream type.
class AudioOutputDescriptor: public AudioPortConfig, public AudioIODescriptorInterface
    , public ClientMapHandler<TrackClientDescriptor>
{
public:
    AudioOutputDescriptor(const sp<AudioPort>& port,
                          AudioPolicyClientInterface *clientInterface);
    virtual ~AudioOutputDescriptor() {}

    void dump(String8 *dst) const override;
    void        log(const char* indent);

    audio_port_handle_t getId() const;
    virtual DeviceVector devices() const { return mDevices; }
    bool sharesHwModuleWith(const sp<AudioOutputDescriptor>& outputDesc);
    virtual DeviceVector supportedDevices() const  { return mDevices; }
    virtual bool isDuplicated() const { return false; }
    virtual uint32_t latency() { return 0; }
    virtual bool isFixedVolume(audio_devices_t device);
    virtual bool setVolume(float volume,
                           audio_stream_type_t stream,
                           audio_devices_t device,
                           uint32_t delayMs,
                           bool force);

    /**
     * Changes the stream active count and mActiveClients only.
     * This does not change the client->active() state or the output descriptor's
     * global active count.
     */
    virtual void changeStreamActiveCount(const sp<TrackClientDescriptor>& client, int delta);
            uint32_t streamActiveCount(audio_stream_type_t stream) const
                            { return mActiveCount[stream]; }

    /**
     * Changes the client->active() state and the output descriptor's global active count,
     * along with the stream active count and mActiveClients.
     * The client must be previously added by the base class addClient().
     */
            void setClientActive(const sp<TrackClientDescriptor>& client, bool active);

    bool isActive(uint32_t inPastMs = 0) const;
    bool isStreamActive(audio_stream_type_t stream,
                        uint32_t inPastMs = 0,
                        nsecs_t sysTime = 0) const;

    virtual void toAudioPortConfig(struct audio_port_config *dstConfig,
                           const struct audio_port_config *srcConfig = NULL) const;
    virtual sp<AudioPort> getAudioPort() const { return mPort; }
    virtual void toAudioPort(struct audio_port *port) const;

    audio_module_handle_t getModuleHandle() const;

    // implementation of AudioIODescriptorInterface
    audio_config_base_t getConfig() const override;
    audio_patch_handle_t getPatchHandle() const override;
    void setPatchHandle(audio_patch_handle_t handle) override;

    TrackClientVector clientsList(bool activeOnly = false,
        routing_strategy strategy = STRATEGY_NONE, bool preferredDeviceOnly = false) const;

    // override ClientMapHandler to abort when removing a client when active.
    void removeClient(audio_port_handle_t portId) override {
        auto client = getClient(portId);
        LOG_ALWAYS_FATAL_IF(client.get() == nullptr,
                "%s(%d): nonexistent client portId %d", __func__, mId, portId);
        // it is possible that when a client is removed, we could remove its
        // associated active count by calling changeStreamActiveCount(),
        // but that would be hiding a problem, so we log fatal instead.
        auto it2 = mActiveClients.find(client);
        LOG_ALWAYS_FATAL_IF(it2 != mActiveClients.end(),
                "%s(%d) removing client portId %d which is active (count %zu)",
                __func__, mId, portId, it2->second);
        ClientMapHandler<TrackClientDescriptor>::removeClient(portId);
    }

    using ActiveClientMap = std::map<sp<TrackClientDescriptor>, size_t /* count */>;
    // required for duplicating thread
    const ActiveClientMap& getActiveClients() const {
        return mActiveClients;
    }

    DeviceVector mDevices; /**< current devices this output is routed to */
    nsecs_t mStopTime[AUDIO_STREAM_CNT];
    int mMuteCount[AUDIO_STREAM_CNT];            // mute request counter
    bool mStrategyMutedByDevice[NUM_STRATEGIES]; // strategies muted because of incompatible
                                        // device selection. See checkDeviceMuteStrategies()
    AudioMix *mPolicyMix = nullptr;              // non NULL when used by a dynamic policy

protected:
    const sp<AudioPort> mPort;
    AudioPolicyClientInterface * const mClientInterface;
    float mCurVolume[AUDIO_STREAM_CNT];   // current stream volume in dB
    uint32_t mActiveCount[AUDIO_STREAM_CNT]; // number of streams of each type active on this output
    uint32_t mGlobalActiveCount = 0;  // non-client-specific active count
    audio_patch_handle_t mPatchHandle = AUDIO_PATCH_HANDLE_NONE;
    audio_port_handle_t mId = AUDIO_PORT_HANDLE_NONE;

    // The ActiveClientMap shows the clients that contribute to the streams counts
    // and may include upstream clients from a duplicating thread.
    // Compare with the ClientMap (mClients) which are external AudioTrack clients of the
    // output descriptor (and do not count internal PatchTracks).
    ActiveClientMap mActiveClients;
};

// Audio output driven by a software mixer in audio flinger.
class SwAudioOutputDescriptor: public AudioOutputDescriptor
{
public:
    SwAudioOutputDescriptor(const sp<IOProfile>& profile,
                            AudioPolicyClientInterface *clientInterface);
    virtual ~SwAudioOutputDescriptor() {}

            void dump(String8 *dst) const override;
    virtual DeviceVector devices() const;
    void setDevices(const DeviceVector &devices) { mDevices = devices; }
    bool sharesHwModuleWith(const sp<SwAudioOutputDescriptor>& outputDesc);
    virtual DeviceVector supportedDevices() const;
    virtual uint32_t latency();
    virtual bool isDuplicated() const { return (mOutput1 != NULL && mOutput2 != NULL); }
    virtual bool isFixedVolume(audio_devices_t device);
    sp<SwAudioOutputDescriptor> subOutput1() { return mOutput1; }
    sp<SwAudioOutputDescriptor> subOutput2() { return mOutput2; }
            void changeStreamActiveCount(
                    const sp<TrackClientDescriptor>& client, int delta) override;
    virtual bool setVolume(float volume,
                           audio_stream_type_t stream,
                           audio_devices_t device,
                           uint32_t delayMs,
                           bool force);

    virtual void toAudioPortConfig(struct audio_port_config *dstConfig,
                           const struct audio_port_config *srcConfig = NULL) const;
    virtual void toAudioPort(struct audio_port *port) const;

        status_t open(const audio_config_t *config,
                      const DeviceVector &devices,
                      audio_stream_type_t stream,
                      audio_output_flags_t flags,
                      audio_io_handle_t *output);

        // Called when a stream is about to be started
        // Note: called before setClientActive(true);
        status_t start();
        // Called after a stream is stopped.
        // Note: called after setClientActive(false);
        void stop();
        void close();
        status_t openDuplicating(const sp<SwAudioOutputDescriptor>& output1,
                                 const sp<SwAudioOutputDescriptor>& output2,
                                 audio_io_handle_t *ioHandle);

    /**
     * @brief supportsDevice
     * @param device to be checked against
     * @return true if the device is supported by type (for non bus / remote submix devices),
     *         true if the device is supported (both type and address) for bus / remote submix
     *         false otherwise
     */
    bool supportsDevice(const sp<DeviceDescriptor> &device) const;

    /**
     * @brief supportsAllDevices
     * @param devices to be checked against
     * @return true if the device is weakly supported by type (e.g. for non bus / rsubmix devices),
     *         true if the device is supported (both type and address) for bus / remote submix
     *         false otherwise
     */
    bool supportsAllDevices(const DeviceVector &devices) const;

    /**
     * @brief filterSupportedDevices takes a vector of devices and filters them according to the
     * device supported by this output (the profile from which this output derives from)
     * @param devices reference device vector to be filtered
     * @return vector of devices filtered from the supported devices of this output (weakly or not
     * depending on the device type)
     */
    DeviceVector filterSupportedDevices(const DeviceVector &devices) const;

    const sp<IOProfile> mProfile;          // I/O profile this output derives from
    audio_io_handle_t mIoHandle;           // output handle
    uint32_t mLatency;                  //
    audio_output_flags_t mFlags;   //
    sp<SwAudioOutputDescriptor> mOutput1;    // used by duplicated outputs: first output
    sp<SwAudioOutputDescriptor> mOutput2;    // used by duplicated outputs: second output
    uint32_t mDirectOpenCount; // number of clients using this output (direct outputs only)
    audio_session_t mDirectClientSession; // session id of the direct output client
};

// Audio output driven by an input device directly.
class HwAudioOutputDescriptor: public AudioOutputDescriptor
{
public:
    HwAudioOutputDescriptor(const sp<SourceClientDescriptor>& source,
                            AudioPolicyClientInterface *clientInterface);
    virtual ~HwAudioOutputDescriptor() {}

            void dump(String8 *dst) const override;

    virtual bool setVolume(float volume,
                           audio_stream_type_t stream,
                           audio_devices_t device,
                           uint32_t delayMs,
                           bool force);

    virtual void toAudioPortConfig(struct audio_port_config *dstConfig,
                           const struct audio_port_config *srcConfig = NULL) const;
    virtual void toAudioPort(struct audio_port *port) const;

    const sp<SourceClientDescriptor> mSource;

};

class SwAudioOutputCollection :
        public DefaultKeyedVector< audio_io_handle_t, sp<SwAudioOutputDescriptor> >
{
public:
    bool isStreamActive(audio_stream_type_t stream, uint32_t inPastMs = 0) const;

    /**
     * return whether a stream is playing remotely, override to change the definition of
     * local/remote playback, used for instance by notification manager to not make
     * media players lose audio focus when not playing locally
     * For the base implementation, "remotely" means playing during screen mirroring which
     * uses an output for playback with a non-empty, non "0" address.
     */
    bool isStreamActiveRemotely(audio_stream_type_t stream, uint32_t inPastMs = 0) const;

    /**
     * return whether a stream is playing, but not on a "remote" device.
     * Override to change the definition of a local/remote playback.
     * Used for instance by policy manager to alter the speaker playback ("speaker safe" behavior)
     * when media plays or not locally.
     * For the base implementation, "remotely" means playing during screen mirroring.
     */
    bool isStreamActiveLocally(audio_stream_type_t stream, uint32_t inPastMs = 0) const;

    /**
     * returns the A2DP output handle if it is open or 0 otherwise
     */
    audio_io_handle_t getA2dpOutput() const;

    /**
     * returns true if primary HAL supports A2DP Offload
     */
    bool isA2dpOffloadedOnPrimary() const;

    /**
     * returns true if A2DP is supported (either via hardware offload or software encoding)
     */
    bool isA2dpSupported() const;

    sp<SwAudioOutputDescriptor> getOutputFromId(audio_port_handle_t id) const;

    sp<SwAudioOutputDescriptor> getPrimaryOutput() const;

    /**
     * return true if any output is playing anything besides the stream to ignore
     */
    bool isAnyOutputActive(audio_stream_type_t streamToIgnore) const;

    audio_devices_t getSupportedDevices(audio_io_handle_t handle) const;

    sp<SwAudioOutputDescriptor> getOutputForClient(audio_port_handle_t portId);

    void dump(String8 *dst) const;
};

class HwAudioOutputCollection :
        public DefaultKeyedVector< audio_io_handle_t, sp<HwAudioOutputDescriptor> >
{
public:
    bool isStreamActive(audio_stream_type_t stream, uint32_t inPastMs = 0) const;

    /**
     * return true if any output is playing anything besides the stream to ignore
     */
    bool isAnyOutputActive(audio_stream_type_t streamToIgnore) const;

    void dump(String8 *dst) const;
};


} // namespace android
