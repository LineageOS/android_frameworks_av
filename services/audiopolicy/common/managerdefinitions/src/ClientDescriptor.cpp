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

#include <utils/String8.h>
#include "ClientDescriptor.h"

namespace android {

status_t ClientDescriptor::dump(int fd)
{
    const size_t SIZE = 256;
    char buffer[SIZE];
    String8 result;

    snprintf(buffer, SIZE, " Port ID: %d Session Id: %d UID: %d\n", mPortId, mSessionId, mUid);
    result.append(buffer);
    snprintf(buffer, SIZE, " Format: %08x Sampling rate: %d Channels: %08x\n",
             mConfig.format, mConfig.sample_rate, mConfig.channel_mask);
    result.append(buffer);
    snprintf(buffer, SIZE, " Preferred Device Id: %08x\n", mPreferredDeviceId);
    result.append(buffer);
    snprintf(buffer, SIZE, " State: %s\n", mActive ? "Active" : "Inactive");
    result.append(buffer);

    write(fd, result.string(), result.size());

    return NO_ERROR;
}

status_t TrackClientDescriptor::dump(int fd)
{
    ClientDescriptor::dump(fd);

    const size_t SIZE = 256;
    char buffer[SIZE];
    String8 result;

    snprintf(buffer, SIZE, " Stream: %d flags: %08x\n", mStream, mFlags);
    result.append(buffer);

    write(fd, result.string(), result.size());

    return NO_ERROR;
}

status_t RecordClientDescriptor::dump(int fd)
{
    ClientDescriptor::dump(fd);

    const size_t SIZE = 256;
    char buffer[SIZE];
    String8 result;

    snprintf(buffer, SIZE, " Source: %d flags: %08x\n", mSource, mFlags);
    result.append(buffer);

    write(fd, result.string(), result.size());

    return NO_ERROR;
}

}; //namespace android
