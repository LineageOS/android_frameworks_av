/*
 * Copyright (C) 2018 The Android Open Source Project
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
#include <unistd.h>

#include <map>
#include <vector>

#include <android-base/stringprintf.h>
#include <audiomanager/AudioManager.h>
#include <media/AudioProductStrategy.h>
#include <policy.h>
#include <system/audio.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/RefBase.h>
#include <utils/String8.h>
#include <Volume.h>
#include "AudioPatch.h"
#include "EffectDescriptor.h"

namespace android {

class AudioPolicyMix;
class DeviceDescriptor;
class HwAudioOutputDescriptor;
class SwAudioOutputDescriptor;

class ClientDescriptor: public RefBase
{
public:
    ClientDescriptor(audio_port_handle_t portId, uid_t uid, audio_session_t sessionId,
                     audio_attributes_t attributes, audio_config_base_t config,
                     audio_port_handle_t preferredDeviceId,
                     bool isPreferredDeviceForExclusiveUse = false) :
        mPortId(portId), mUid(uid), mSessionId(sessionId), mAttributes(attributes),
        mConfig(config), mPreferredDeviceId(preferredDeviceId), mActive(false),
        mPreferredDeviceForExclusiveUse(isPreferredDeviceForExclusiveUse){}
    ~ClientDescriptor() override = default;

    virtual void dump(String8 *dst, int spaces) const;
    virtual std::string toShortString() const;
    /**
     * @brief isInternal
     * @return true if the client corresponds to an audio patch created from createAudioPatch API or
     * for call audio routing, or false if the client corresponds to an AudioTrack, AudioRecord or
     * HW Audio Source.
     */
    virtual bool isInternal() const { return false; }
    audio_port_handle_t portId() const { return mPortId; }
    uid_t uid() const { return mUid; }
    audio_session_t session() const { return mSessionId; };
    audio_attributes_t attributes() const { return mAttributes; }
    audio_config_base_t config() const { return mConfig; }
    audio_port_handle_t preferredDeviceId() const { return mPreferredDeviceId; };
    void setPreferredDeviceId(audio_port_handle_t preferredDeviceId) {
        mPreferredDeviceId = preferredDeviceId;
    }
    bool isPreferredDeviceForExclusiveUse() const { return mPreferredDeviceForExclusiveUse; }
    virtual void setActive(bool active) { mActive = active; }
    bool active() const { return mActive; }
    /**
     * @brief hasPreferredDevice Note that as internal clients use preferred device for convenience,
     * we do hide this internal behavior to prevent from regression (like invalidating track for
     * clients following same strategies...)
     * @param activeOnly
     * @return
     */
    bool hasPreferredDevice(bool activeOnly = false) const {
        return !isInternal() &&
                mPreferredDeviceId != AUDIO_PORT_HANDLE_NONE && (!activeOnly || mActive);
    }

private:
    const audio_port_handle_t mPortId;  // unique Id for this client
    const uid_t mUid;                     // client UID
    const audio_session_t mSessionId;       // audio session ID
    const audio_attributes_t mAttributes; // usage...
    const audio_config_base_t mConfig;
          audio_port_handle_t mPreferredDeviceId;  // selected input device port ID
          bool mActive;
          bool mPreferredDeviceForExclusiveUse = false;
};

class TrackClientDescriptor: public ClientDescriptor
{
public:
    TrackClientDescriptor(audio_port_handle_t portId, uid_t uid, audio_session_t sessionId,
                          audio_attributes_t attributes, audio_config_base_t config,
                          audio_port_handle_t preferredDeviceId, audio_stream_type_t stream,
                          product_strategy_t strategy, VolumeSource volumeSource,
                          audio_output_flags_t flags,
                          bool isPreferredDeviceForExclusiveUse,
                          std::vector<wp<SwAudioOutputDescriptor>> secondaryOutputs,
                          wp<AudioPolicyMix> primaryMix) :
        ClientDescriptor(portId, uid, sessionId, attributes, config, preferredDeviceId,
                         isPreferredDeviceForExclusiveUse),
        mStream(stream), mStrategy(strategy), mVolumeSource(volumeSource), mFlags(flags),
        mSecondaryOutputs(std::move(secondaryOutputs)), mPrimaryMix(primaryMix) {}
    ~TrackClientDescriptor() override = default;

    using ClientDescriptor::dump;
    void dump(String8 *dst, int spaces) const override;
    std::string toShortString() const override;

    audio_output_flags_t flags() const { return mFlags; }
    audio_stream_type_t stream() const { return mStream; }
    product_strategy_t strategy() const { return mStrategy; }
    const std::vector<wp<SwAudioOutputDescriptor>>& getSecondaryOutputs() const {
        return mSecondaryOutputs;
    };
    void setSecondaryOutputs(std::vector<wp<SwAudioOutputDescriptor>>&& secondaryOutputs) {
        mSecondaryOutputs = std::move(secondaryOutputs);
    }
    VolumeSource volumeSource() const { return mVolumeSource; }
    const sp<AudioPolicyMix> getPrimaryMix() const {
        return mPrimaryMix.promote();
    };
    bool hasLostPrimaryMix() const {
        return mPrimaryMix.unsafe_get() && !mPrimaryMix.promote();
    }

    void setActive(bool active) override
    {
        int delta = active ? 1 : -1;
        changeActivityCount(delta);
    }
    void changeActivityCount(int delta)
    {
        if (delta > 0) {
            mActivityCount += delta;
        } else {
            LOG_ALWAYS_FATAL_IF(!mActivityCount, "%s(%s) invalid delta %d, inactive client",
                                 __func__, toShortString().c_str(), delta);
            LOG_ALWAYS_FATAL_IF(static_cast<int>(mActivityCount) < -delta,
                                "%s(%s) invalid delta %d, active client count %d",
                                 __func__, toShortString().c_str(), delta, mActivityCount);
            mActivityCount += delta;
        }
        ClientDescriptor::setActive(mActivityCount > 0);
    }
    uint32_t getActivityCount() const { return mActivityCount; }

    bool isInvalid() const {
        return mIsInvalid;
    }

    void setIsInvalid() {
        mIsInvalid = true;
    }

private:
    const audio_stream_type_t mStream;
    const product_strategy_t mStrategy;
    const VolumeSource mVolumeSource;
    const audio_output_flags_t mFlags;
    std::vector<wp<SwAudioOutputDescriptor>> mSecondaryOutputs;
    const wp<AudioPolicyMix> mPrimaryMix;
    /**
     * required for duplicating thread, prevent from removing active client from an output
     * involved in a duplication.
     */
    uint32_t mActivityCount = 0;
    bool mIsInvalid = false;
};

class RecordClientDescriptor: public ClientDescriptor
{
public:
    RecordClientDescriptor(audio_port_handle_t portId, audio_unique_id_t riid, uid_t uid,
                        audio_session_t sessionId, audio_attributes_t attributes,
                        audio_config_base_t config, audio_port_handle_t preferredDeviceId,
                        audio_source_t source, audio_input_flags_t flags, bool isSoundTrigger) :
        ClientDescriptor(portId, uid, sessionId, attributes, config, preferredDeviceId),
        mRIId(riid), mSource(source), mFlags(flags), mIsSoundTrigger(isSoundTrigger),
        mAppState(APP_STATE_IDLE) {}
    ~RecordClientDescriptor() override = default;

    using ClientDescriptor::dump;
    void dump(String8 *dst, int spaces) const override;

    audio_unique_id_t riid() const { return mRIId; }
    audio_source_t source() const { return mSource; }
    audio_input_flags_t flags() const { return mFlags; }
    bool isSoundTrigger() const { return mIsSoundTrigger; }
    bool isLowLevel() const { return mRIId == RECORD_RIID_INVALID; }
    void setAppState(app_state_t appState) { mAppState = appState; }
    app_state_t appState() { return mAppState; }
    bool isSilenced() const { return mAppState == APP_STATE_IDLE; }
    void trackEffectEnabled(const sp<EffectDescriptor> &effect, bool enabled);
    EffectDescriptorCollection getEnabledEffects() const { return mEnabledEffects; }

private:
    const audio_unique_id_t mRIId;
    const audio_source_t mSource;
    const audio_input_flags_t mFlags;
    const bool mIsSoundTrigger;
          app_state_t mAppState;
    EffectDescriptorCollection mEnabledEffects;
};

class SourceClientDescriptor: public TrackClientDescriptor
{
public:
    SourceClientDescriptor(audio_port_handle_t portId, uid_t uid, audio_attributes_t attributes,
                           const struct audio_port_config &config,
                           const sp<DeviceDescriptor>& srcDevice,
                           audio_stream_type_t stream, product_strategy_t strategy,
                           VolumeSource volumeSource,
                           bool isInternal);

    ~SourceClientDescriptor() override = default;

    void connect(audio_patch_handle_t patchHandle, const sp<DeviceDescriptor>& sinkDevice) {
        mPatchHandle = patchHandle;
        mSinkDevice = sinkDevice;
    }
    void disconnect() {
        mPatchHandle = AUDIO_PATCH_HANDLE_NONE;
        mSinkDevice = nullptr;
    }
    bool belongsToOutput(const sp<SwAudioOutputDescriptor> &swOutput) const {
        return swOutput != nullptr && mSwOutput.promote() == swOutput;
    }
    void setUseSwBridge() { mUseSwBridge = true; }
    bool useSwBridge() const { return mUseSwBridge; }
    bool canCloseOutput() const { return mCloseOutput; }
    bool isConnected() const { return mPatchHandle != AUDIO_PATCH_HANDLE_NONE; }
    audio_patch_handle_t getPatchHandle() const { return mPatchHandle; }
    sp<DeviceDescriptor> srcDevice() const { return mSrcDevice; }
    sp<DeviceDescriptor> sinkDevice() const { return mSinkDevice; }
    wp<SwAudioOutputDescriptor> swOutput() const { return mSwOutput; }
    void setSwOutput(const sp<SwAudioOutputDescriptor>& swOutput, bool closeOutput = false);
    wp<HwAudioOutputDescriptor> hwOutput() const { return mHwOutput; }
    void setHwOutput(const sp<HwAudioOutputDescriptor>& hwOutput);
    bool isInternal() const override { return mIsInternal; }

    using ClientDescriptor::dump;
    void dump(String8 *dst, int spaces) const override;

 private:
    audio_patch_handle_t mPatchHandle = AUDIO_PATCH_HANDLE_NONE;
    const sp<DeviceDescriptor> mSrcDevice;
    sp<DeviceDescriptor> mSinkDevice;
    wp<SwAudioOutputDescriptor> mSwOutput;
    wp<HwAudioOutputDescriptor> mHwOutput;
    bool mUseSwBridge = false;
    /**
     * For either HW bridge associated to a SwOutput for activity / volume or SwBridge for also
     * sample rendering / activity & volume, an existing playback thread may be reused (e.g.
     * not already opened at APM startup or Direct Output).
     * If reusing an already opened output, when this output is not used anymore, the AudioFlinger
     * patch must be updated to refine the output device(s) information and ensure the right
     * behavior of AudioDeviceCallback.
     */
    bool mCloseOutput = false;
    /**
     * True for specialized Client Descriptor for either a raw patch created from
     * @see createAudioPatch API or for internal audio patches managed by APM
     * (e.g. phone call patches).
     * Whatever the bridge created (software or hardware), we need a client to track the activity
     * and manage volumes.
     * The Audio Patch requested sink is expressed as a preferred device which allows to route
     * the SwOutput. Then APM will performs checks on the UID (against UID of Audioserver) of the
     * requester to prevent rerouting SwOutput involved in raw patches.
     */
    bool mIsInternal = false;
};

class SourceClientCollection :
    public DefaultKeyedVector< audio_port_handle_t, sp<SourceClientDescriptor> >
{
public:
    void dump(String8 *dst) const;
};

typedef std::vector< sp<TrackClientDescriptor> > TrackClientVector;
typedef std::vector< sp<RecordClientDescriptor> > RecordClientVector;

// A Map that associates a portId with a client (type T)
// which is either TrackClientDescriptor or RecordClientDescriptor.

template<typename T>
class ClientMapHandler {
public:
    virtual ~ClientMapHandler() = default;

    // Track client management
    virtual void addClient(const sp<T> &client) {
        const audio_port_handle_t portId = client->portId();
        LOG_ALWAYS_FATAL_IF(!mClients.emplace(portId, client).second,
                "%s(%d): attempting to add client that already exists", __func__, portId);
    }
    sp<T> getClient(audio_port_handle_t portId) const {
        auto it = mClients.find(portId);
        if (it == mClients.end()) return nullptr;
        return it->second;
    }
    virtual void removeClient(audio_port_handle_t portId) {
        auto it = mClients.find(portId);
        LOG_ALWAYS_FATAL_IF(it == mClients.end(),
                "%s(%d): client does not exist", __func__, portId);
        LOG_ALWAYS_FATAL_IF(it->second->active(),
                "%s(%d): removing client still active!", __func__, portId);
        (void)mClients.erase(it);
    }
    size_t getClientCount() const {
        return mClients.size();
    }
    virtual void dump(String8 *dst, int spaces, const char* extraInfo = nullptr) const {
        (void)extraInfo;
        size_t index = 0;
        for (const auto& client: getClientIterable()) {
            const std::string prefix = base::StringPrintf("%*s %zu. ", spaces, "", ++index);
            dst->appendFormat("%s", prefix.c_str());
            client->dump(dst, prefix.size());
        }
    }

    // helper types
    using ClientMap = std::map<audio_port_handle_t, sp<T>>;
    using ClientMapIterator = typename ClientMap::const_iterator;  // ClientMap is const qualified
    class ClientIterable {
    public:
        explicit ClientIterable(const ClientMapHandler<T> &ref) : mClientMapHandler(ref) { }

        class iterator {
        public:
            // traits
            using iterator_category = std::forward_iterator_tag;
            using value_type = sp<T>;
            using difference_type = ptrdiff_t;
            using pointer = const sp<T>*;    // Note: const
            using reference = const sp<T>&;  // Note: const

            // implementation
            explicit iterator(const ClientMapIterator &it) : mIt(it) { }
            iterator& operator++()    /* prefix */     { ++mIt; return *this; }
            reference operator* () const               { return mIt->second; }
            reference operator->() const               { return mIt->second; } // as if sp<>
            difference_type operator-(const iterator& rhs) {return mIt - rhs.mIt; }
            bool operator==(const iterator& rhs) const { return mIt == rhs.mIt; }
            bool operator!=(const iterator& rhs) const { return mIt != rhs.mIt; }
        private:
            ClientMapIterator mIt;
        };

        iterator begin() const { return iterator{mClientMapHandler.mClients.begin()}; }
        iterator end() const { return iterator{mClientMapHandler.mClients.end()}; }

    private:
        const ClientMapHandler<T>& mClientMapHandler; // iterating does not modify map.
    };

    // return an iterable object that can be used in a range-based-for to enumerate clients.
    // this iterable does not allow modification, it should be used as a temporary.
    ClientIterable getClientIterable() const {
        return ClientIterable{*this};
    }

private:
    // ClientMap maps a portId to a client descriptor (both uniquely identify each other).
    ClientMap mClients;
};

} // namespace android
