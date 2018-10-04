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

#define LOG_TAG "APM_ClientDescriptor"
//#define LOG_NDEBUG 0

#include <sstream>
#include <utils/Log.h>
#include <utils/String8.h>
#include "AudioGain.h"
#include "AudioOutputDescriptor.h"
#include "AudioPatch.h"
#include "ClientDescriptor.h"
#include "DeviceDescriptor.h"
#include "HwModule.h"
#include "IOProfile.h"

namespace android {

status_t ClientDescriptor::dump(int fd, int spaces, int index)
{
    String8 out;

    // FIXME: use until other descriptor classes have a dump to String8 method
    mDumpFd = fd;

    status_t status = dump(out, spaces, index);
    if (status == NO_ERROR) {
        write(fd, out.string(), out.size());
    }

    return status;
}

std::string ClientDescriptor::toShortString() const
{
    std::stringstream ss;

    ss << "PortId: " << mPortId << " SessionId: " << mSessionId << " Uid: " << mUid;
    return ss.str();
}

status_t ClientDescriptor::dump(String8& out, int spaces, int index)
{
    out.appendFormat("%*sClient %d:\n", spaces, "", index+1);
    out.appendFormat("%*s- Port Id: %d Session Id: %d UID: %d\n", spaces, "",
             mPortId, mSessionId, mUid);
    out.appendFormat("%*s- Format: %08x Sampling rate: %d Channels: %08x\n", spaces, "",
             mConfig.format, mConfig.sample_rate, mConfig.channel_mask);
    out.appendFormat("%*s- Preferred Device Id: %08x\n", spaces, "", mPreferredDeviceId);
    out.appendFormat("%*s- State: %s\n", spaces, "", mActive ? "Active" : "Inactive");
    return NO_ERROR;
}

status_t TrackClientDescriptor::dump(String8& out, int spaces, int index)
{
    ClientDescriptor::dump(out, spaces, index);

    out.appendFormat("%*s- Stream: %d flags: %08x\n", spaces, "", mStream, mFlags);

    return NO_ERROR;
}

std::string TrackClientDescriptor::toShortString() const
{
    std::stringstream ss;

    ss << ClientDescriptor::toShortString() << " Stream: " << mStream;
    return ss.str();
}

status_t RecordClientDescriptor::dump(String8& out, int spaces, int index)
{
    ClientDescriptor::dump(out, spaces, index);

    out.appendFormat("%*s- Source: %d flags: %08x\n", spaces, "", mSource, mFlags);

    return NO_ERROR;
}

SourceClientDescriptor::SourceClientDescriptor(audio_port_handle_t portId, uid_t uid,
         audio_attributes_t attributes, const sp<AudioPatch>& patchDesc,
         const sp<DeviceDescriptor>& srcDevice, audio_stream_type_t stream,
         routing_strategy strategy) :
    TrackClientDescriptor::TrackClientDescriptor(portId, uid, AUDIO_SESSION_NONE, attributes,
        AUDIO_CONFIG_BASE_INITIALIZER, AUDIO_PORT_HANDLE_NONE,
        stream, strategy, AUDIO_OUTPUT_FLAG_NONE),
        mPatchDesc(patchDesc), mSrcDevice(srcDevice)
{
}

void SourceClientDescriptor::setSwOutput(const sp<SwAudioOutputDescriptor>& swOutput)
{
    mSwOutput = swOutput;
}

void SourceClientDescriptor::setHwOutput(const sp<HwAudioOutputDescriptor>& hwOutput)
{
    mHwOutput = hwOutput;
}

status_t SourceClientDescriptor::dump(String8& out, int spaces, int index)
{
    TrackClientDescriptor::dump(out, spaces, index);

    if (mDumpFd >= 0) {
        out.appendFormat("%*s- Device:\n", spaces, "");
        write(mDumpFd, out.string(), out.size());

        mSrcDevice->dump(mDumpFd, 2, 0);
        mDumpFd = -1;
    }

    return NO_ERROR;
}

status_t SourceClientCollection::dump(int fd) const
{
    String8 out;
    out.append("\nAudio sources:\n");
    write(fd, out.string(), out.size());
    for (size_t i = 0; i < size(); i++) {
        valueAt(i)->dump(fd, 2, i);
    }

    return NO_ERROR;
}

}; //namespace android
