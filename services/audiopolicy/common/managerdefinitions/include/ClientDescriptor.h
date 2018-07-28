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

#include <vector>
#include <map>
#include <unistd.h>
#include <sys/types.h>

#include <system/audio.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/RefBase.h>
#include <utils/String8.h>
#include "AudioPatch.h"
#include "RoutingStrategy.h"

namespace android {

class DeviceDescriptor;
class HwAudioOutputDescriptor;
class SwAudioOutputDescriptor;

class ClientDescriptor: public RefBase
{
public:
    ClientDescriptor(audio_port_handle_t portId, uid_t uid, audio_session_t sessionId,
                   audio_attributes_t attributes, audio_config_base_t config,
                   audio_port_handle_t preferredDeviceId) :
        mPortId(portId), mUid(uid), mSessionId(sessionId), mAttributes(attributes),
        mConfig(config), mPreferredDeviceId(preferredDeviceId), mActive(false) {}
    ~ClientDescriptor() override = default;

    status_t dump(int fd, int spaces, int index);
    virtual status_t dump(String8& dst, int spaces, int index);

    audio_port_handle_t portId() const { return mPortId; }
    uid_t uid() const { return mUid; }
    audio_session_t session() const { return mSessionId; };
    audio_attributes_t attributes() const { return mAttributes; }
    audio_config_base_t config() const { return mConfig; }
    audio_port_handle_t preferredDeviceId() const { return mPreferredDeviceId; };
    void setPreferredDeviceId(audio_port_handle_t preferredDeviceId) {
        mPreferredDeviceId = preferredDeviceId;
    };
    void setActive(bool active) { mActive = active; }
    bool active() const { return mActive; }
    bool hasPreferredDevice(bool activeOnly = false) const {
        return mPreferredDeviceId != AUDIO_PORT_HANDLE_NONE && (!activeOnly || mActive);
    }

private:
    const audio_port_handle_t mPortId;  // unique Id for this client
    const uid_t mUid;                     // client UID
    const audio_session_t mSessionId;       // audio session ID
    const audio_attributes_t mAttributes; // usage...
    const audio_config_base_t mConfig;
          audio_port_handle_t mPreferredDeviceId;  // selected input device port ID
          bool mActive;

protected:
    // FIXME: use until other descriptor classes have a dump to String8 method
    int mDumpFd;
};

class TrackClientDescriptor: public ClientDescriptor
{
public:
    TrackClientDescriptor(audio_port_handle_t portId, uid_t uid, audio_session_t sessionId,
                   audio_attributes_t attributes, audio_config_base_t config,
                   audio_port_handle_t preferredDeviceId, audio_stream_type_t stream,
                          routing_strategy strategy, audio_output_flags_t flags) :
        ClientDescriptor(portId, uid, sessionId, attributes, config, preferredDeviceId),
        mStream(stream), mStrategy(strategy), mFlags(flags) {}
    ~TrackClientDescriptor() override = default;

    using ClientDescriptor::dump;
    status_t dump(String8& dst, int spaces, int index) override;

    audio_output_flags_t flags() const { return mFlags; }
    audio_stream_type_t stream() const { return mStream; }
    routing_strategy strategy() const { return mStrategy; }

private:
    const audio_stream_type_t mStream;
    const routing_strategy mStrategy;
    const audio_output_flags_t mFlags;
};

class RecordClientDescriptor: public ClientDescriptor
{
public:
    RecordClientDescriptor(audio_port_handle_t portId, uid_t uid, audio_session_t sessionId,
                        audio_attributes_t attributes, audio_config_base_t config,
                        audio_port_handle_t preferredDeviceId,
                        audio_source_t source, audio_input_flags_t flags) :
        ClientDescriptor(portId, uid, sessionId, attributes, config, preferredDeviceId),
        mSource(source), mFlags(flags) {}
    ~RecordClientDescriptor() override = default;

    using ClientDescriptor::dump;
    status_t dump(String8& dst, int spaces, int index) override;

    audio_source_t source() const { return mSource; }
    audio_input_flags_t flags() const { return mFlags; }

private:
    const audio_source_t mSource;
    const audio_input_flags_t mFlags;
};

class SourceClientDescriptor: public TrackClientDescriptor
{
public:
    SourceClientDescriptor(audio_port_handle_t portId, uid_t uid, audio_attributes_t attributes,
                           const sp<AudioPatch>& patchDesc, const sp<DeviceDescriptor>& srcDevice,
                           audio_stream_type_t stream, routing_strategy strategy);
    ~SourceClientDescriptor() override = default;

    sp<AudioPatch> patchDesc() const { return mPatchDesc; }
    sp<DeviceDescriptor> srcDevice() const { return mSrcDevice; };
    wp<SwAudioOutputDescriptor> swOutput() const { return mSwOutput; }
    void setSwOutput(const sp<SwAudioOutputDescriptor>& swOutput);
    wp<HwAudioOutputDescriptor> hwOutput() const { return mHwOutput; }
    void setHwOutput(const sp<HwAudioOutputDescriptor>& hwOutput);

    using ClientDescriptor::dump;
    status_t dump(String8& dst, int spaces, int index) override;

 private:
    const sp<AudioPatch> mPatchDesc;
    const sp<DeviceDescriptor> mSrcDevice;
    wp<SwAudioOutputDescriptor> mSwOutput;
    wp<HwAudioOutputDescriptor> mHwOutput;
};

class SourceClientCollection :
    public DefaultKeyedVector< audio_port_handle_t, sp<SourceClientDescriptor> >
{
public:
    status_t dump(int fd) const;
};

typedef std::vector< sp<TrackClientDescriptor> > TrackClientVector;
typedef std::map< audio_port_handle_t, sp<TrackClientDescriptor> > TrackClientMap;
typedef std::vector< sp<RecordClientDescriptor> > RecordClientVector;
typedef std::map< audio_port_handle_t, sp<RecordClientDescriptor> > RecordClientMap;

} // namespace android
