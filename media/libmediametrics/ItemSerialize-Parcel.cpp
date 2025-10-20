/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "mediametrics::Item-Serialization"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/endian.h>
#include <sys/types.h>

#include <binder/Parcel.h>
#include <cutils/multiuser.h>
#include <cutils/properties.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/SortedVector.h>
#include <utils/threads.h>

#include <android/media/BnMediaMetricsService.h> // for direct Binder access
#include <android/media/IMediaMetricsService.h>
#include <binder/IServiceManager.h>
#include <media/MediaMetricsItem.h>
#include <private/android_filesystem_config.h>

namespace android::mediametrics {

// Parcel / serialize things for binder calls
//

status_t mediametrics::Item::readFromParcel(const Parcel& data) {
    int32_t version;
    status_t status = data.readInt32(&version);
    if (status != NO_ERROR) return status;

    switch (version) {
    case 0:
      return readFromParcel0(data);
    default:
      ALOGE("%s: unsupported parcel version: %d", __func__, version);
      return INVALID_OPERATION;
    }
}

status_t mediametrics::Item::readFromParcel0(const Parcel& data) {
    mKey = std::string{data.readString8()};
    int32_t pid, uid;
    status_t status = data.readInt32(&pid) ?: data.readInt32(&uid);
    if (status != NO_ERROR) return status;
    mPid = (pid_t)pid;
    mUid = (uid_t)uid;
    mPkgName = std::string(data.readString8());
    int32_t count;
    int64_t version, timestamp;
    status = data.readInt64(&version) ?: data.readInt64(&timestamp) ?: data.readInt32(&count);
    if (status != NO_ERROR) return status;
    if (count < 0) return BAD_VALUE;
    mPkgVersionCode = version;
    mTimestamp = timestamp;
    for (int i = 0; i < count; i++) {
        Prop prop;
        status_t status = prop.readFromParcel(data);
        if (status != NO_ERROR) return status;
        mProps[prop.getName()] = std::move(prop);
    }
    return NO_ERROR;
}

status_t mediametrics::Item::writeToParcel(Parcel *data) const {
    if (data == nullptr) return BAD_VALUE;

    const int32_t version = 0;
    status_t status = data->writeInt32(version);
    if (status != NO_ERROR) return status;

    switch (version) {
    case 0:
      return writeToParcel0(data);
    default:
      ALOGE("%s: unsupported parcel version: %d", __func__, version);
      return INVALID_OPERATION;
    }
}

status_t mediametrics::Item::writeToParcel0(Parcel *data) const {
    status_t status =
        data->writeString8(String8{mKey})
        ?: data->writeInt32(mPid)
        ?: data->writeInt32(mUid)
        ?: data->writeString8(String8{mPkgName})
        ?: data->writeInt64(mPkgVersionCode)
        ?: data->writeInt64(mTimestamp);
    if (status != NO_ERROR) return status;

    data->writeInt32((int32_t)mProps.size());
    for (auto &prop : *this) {
        status = prop.writeToParcel(data);
        if (status != NO_ERROR) return status;
    }
    return NO_ERROR;
}

status_t mediametrics::Item::Prop::readFromParcel(const Parcel& data)
{
    const std::string key {data.readString8()};
    int32_t type;
    status_t status = data.readInt32(&type);
    if (status != NO_ERROR) return status;
    switch (type) {
    case mediametrics::kTypeInt32: {
        int32_t value;
        status = data.readInt32(&value);
        if (status != NO_ERROR) return status;
        mElem = value;
    } break;
    case mediametrics::kTypeInt64: {
        int64_t value;
        status = data.readInt64(&value);
        if (status != NO_ERROR) return status;
        mElem = value;
    } break;
    case mediametrics::kTypeDouble: {
        double value;
        status = data.readDouble(&value);
        if (status != NO_ERROR) return status;
        mElem = value;
    } break;
    case mediametrics::kTypeCString: {
        mElem = std::string{data.readString8()};
    } break;
    case mediametrics::kTypeRate: {
        std::pair<int64_t, int64_t> rate;
        status = data.readInt64(&rate.first)
                ?: data.readInt64(&rate.second);
        if (status != NO_ERROR) return status;
        mElem = rate;
    } break;
    case mediametrics::kTypeNone: {
        mElem = std::monostate{};
    } break;
    default:
        ALOGE("%s: reading bad item type: %d", __func__, type);
        return BAD_VALUE;
    }
    setName(key);
    return NO_ERROR;
}

} // namespace android::mediametrics
