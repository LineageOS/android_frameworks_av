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

#define LOG_TAG "MediaAnalytics"

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

#include <media/MediaAnalyticsItem.h>
#include <media/IMediaAnalyticsService.h>

namespace android {

enum {
    SUBMIT_ITEM_ONEWAY = IBinder::FIRST_CALL_TRANSACTION,
};

class BpMediaAnalyticsService: public BpInterface<IMediaAnalyticsService>
{
public:
    explicit BpMediaAnalyticsService(const sp<IBinder>& impl)
        : BpInterface<IMediaAnalyticsService>(impl)
    {
    }

    status_t submit(MediaAnalyticsItem *item) override
    {
        if (item == nullptr) {
            return BAD_VALUE;
        }
        ALOGV("%s: (ONEWAY) item=%s", __func__, item->toString().c_str());

        Parcel data;
        data.writeInterfaceToken(IMediaAnalyticsService::getInterfaceDescriptor());
        item->writeToParcel(&data);

        status_t err = remote()->transact(
                SUBMIT_ITEM_ONEWAY, data, nullptr /* reply */, IBinder::FLAG_ONEWAY);
        ALOGW_IF(err != NO_ERROR, "%s: bad response from service for submit, err=%d",
                __func__, err);
        return err;
    }
};

IMPLEMENT_META_INTERFACE(MediaAnalyticsService, "android.media.IMediaAnalyticsService");

// ----------------------------------------------------------------------

status_t BnMediaAnalyticsService::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    const int clientPid = IPCThreadState::self()->getCallingPid();

    switch (code) {
    case SUBMIT_ITEM_ONEWAY: {
        CHECK_INTERFACE(IMediaAnalyticsService, data, reply);

        MediaAnalyticsItem * const item = MediaAnalyticsItem::create();
        if (item->readFromParcel(data) < 0) {
            return BAD_VALUE;
        }
        item->setPid(clientPid);
        const status_t status __unused = submitInternal(item, true /* release */);
        return NO_ERROR;
    } break;

    default:
        return BBinder::onTransact(code, data, reply, flags);
    }
}

// ----------------------------------------------------------------------------

} // namespace android
