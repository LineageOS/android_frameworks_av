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

#include <utils/Log.h>
#include <utils/String8.h>
#include "ClientDescriptor.h"

namespace android {

status_t ClientDescriptor::dump(int fd, int spaces, int index)
{
    String8 out;

    status_t status = dump(out, spaces, index);
    if (status == NO_ERROR) {
        write(fd, out.string(), out.size());
    }

    return status;
}

status_t ClientDescriptor::dump(String8& out, int spaces, int index)
{
    out.appendFormat("%*sClient %d:\n", spaces, "", index+1);
    out.appendFormat("%*s- Port ID: %d Session Id: %d UID: %d\n", spaces, "",
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

status_t RecordClientDescriptor::dump(String8& out, int spaces, int index)
{
    ClientDescriptor::dump(out, spaces, index);

    out.appendFormat("%*s- Source: %d flags: %08x\n", spaces, "", mSource, mFlags);

    return NO_ERROR;
}

}; //namespace android
