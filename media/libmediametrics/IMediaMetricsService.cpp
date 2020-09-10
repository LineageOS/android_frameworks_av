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

#define LOG_TAG "MediaMetrics"

#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>

#include <binder/Parcel.h>
#include <binder/IMemory.h>
#include <binder/IPCThreadState.h>

#include <utils/Errors.h>  // for status_t
#include <utils/List.h>
#include <utils/Log.h>
#include <utils/String8.h>

#include <media/MediaMetricsItem.h>
#include <media/IMediaMetricsService.h>

namespace android {

// TODO: Currently ONE_WAY transactions, make both ONE_WAY and synchronous options.

enum {
    SUBMIT_ITEM = IBinder::FIRST_CALL_TRANSACTION,
    SUBMIT_BUFFER,
};

class BpMediaMetricsService: public BpInterface<IMediaMetricsService>
{
public:
    explicit BpMediaMetricsService(const sp<IBinder>& impl)
        : BpInterface<IMediaMetricsService>(impl)
    {
    }

    status_t submit(mediametrics::Item *item) override
    {
        if (item == nullptr) {
            return BAD_VALUE;
        }
        ALOGV("%s: (ONEWAY) item=%s", __func__, item->toString().c_str());

        Parcel data;
        data.writeInterfaceToken(IMediaMetricsService::getInterfaceDescriptor());

        status_t status = item->writeToParcel(&data);
        if (status != NO_ERROR) { // assume failure logged in item
            return status;
        }

        status = remote()->transact(
                SUBMIT_ITEM, data, nullptr /* reply */, IBinder::FLAG_ONEWAY);
        ALOGW_IF(status != NO_ERROR, "%s: bad response from service for submit, status=%d",
                __func__, status);
        return status;
    }

    status_t submitBuffer(const char *buffer, size_t length) override
    {
        if (buffer == nullptr || length > INT32_MAX) {
            return BAD_VALUE;
        }
        ALOGV("%s: (ONEWAY) length:%zu", __func__, length);

        Parcel data;
        data.writeInterfaceToken(IMediaMetricsService::getInterfaceDescriptor());

        status_t status = data.writeInt32(length)
                ?: data.write((uint8_t*)buffer, length);
        if (status != NO_ERROR) {
            return status;
        }

        status = remote()->transact(
                SUBMIT_BUFFER, data, nullptr /* reply */, IBinder::FLAG_ONEWAY);
        ALOGW_IF(status != NO_ERROR, "%s: bad response from service for submit, status=%d",
                __func__, status);
        return status;
    }
};

IMPLEMENT_META_INTERFACE(MediaMetricsService, "android.media.IMediaMetricsService");

// ----------------------------------------------------------------------

status_t BnMediaMetricsService::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    switch (code) {
    case SUBMIT_ITEM: {
        CHECK_INTERFACE(IMediaMetricsService, data, reply);

        mediametrics::Item * const item = mediametrics::Item::create();
        status_t status = item->readFromParcel(data);
        if (status != NO_ERROR) { // assume failure logged in item
            return status;
        }
        status = submitInternal(item, true /* release */);
        // assume failure logged by submitInternal
        return NO_ERROR;
    }
    case SUBMIT_BUFFER: {
        CHECK_INTERFACE(IMediaMetricsService, data, reply);
        int32_t length;
        status_t status = data.readInt32(&length);
        if (status != NO_ERROR || length <= 0) {
            return BAD_VALUE;
        }
        const void *ptr = data.readInplace(length);
        if (ptr == nullptr) {
            return BAD_VALUE;
        }
        status = submitBuffer(static_cast<const char *>(ptr), length);
        // assume failure logged by submitBuffer
        return NO_ERROR;
    }

    default:
        return BBinder::onTransact(code, data, reply, flags);
    }
}

// ----------------------------------------------------------------------------

} // namespace android
