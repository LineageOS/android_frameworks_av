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
#include <media/IHDCP.h>
#include <media/IMediaCodecList.h>
#include <media/IMediaHTTPService.h>
#include <media/IMediaPlayerService.h>
#include <media/IMediaRecorder.h>
#include <media/IOMX.h>
#include <media/IRemoteDisplay.h>
#include <media/IRemoteDisplayClient.h>
#include <media/IStreamSource.h>

#include <utils/Errors.h>  // for status_t
#include <utils/List.h>
#include <utils/Log.h>
#include <utils/String8.h>

#include <media/MediaAnalyticsItem.h>
#include <media/IMediaAnalyticsService.h>

#define DEBUGGING               0
#define DEBUGGING_FLOW          0
#define DEBUGGING_RETURNS       0

namespace android {

enum {
    GENERATE_UNIQUE_SESSIONID = IBinder::FIRST_CALL_TRANSACTION,
    SUBMIT_ITEM,
    GET_ITEM_LIST,
};

class BpMediaAnalyticsService: public BpInterface<IMediaAnalyticsService>
{
public:
    explicit BpMediaAnalyticsService(const sp<IBinder>& impl)
        : BpInterface<IMediaAnalyticsService>(impl)
    {
    }

    virtual MediaAnalyticsItem::SessionID_t generateUniqueSessionID() {
        Parcel data, reply;
        status_t err;
        MediaAnalyticsItem::SessionID_t sessionid =
                        MediaAnalyticsItem::SessionIDInvalid;

        data.writeInterfaceToken(IMediaAnalyticsService::getInterfaceDescriptor());
        err = remote()->transact(GENERATE_UNIQUE_SESSIONID, data, &reply);
        if (err != NO_ERROR) {
            ALOGW("bad response from service");
            return MediaAnalyticsItem::SessionIDInvalid;
        }
        sessionid = reply.readInt64();
        if (DEBUGGING_RETURNS) {
            ALOGD("the caller gets a sessionid of %" PRId64 " back", sessionid);
        }
        return sessionid;
    }

    virtual MediaAnalyticsItem::SessionID_t submit(sp<MediaAnalyticsItem> item, bool forcenew)
    {
        // have this record submit itself
        // this will be a binder call with appropriate timing
        // return value is the uuid that the system generated for it.
        // the return value 0 and -1 are reserved.
        // -1 to indicate that there was a problem recording...

        Parcel data, reply;
        status_t err;

        if (item == NULL) {
                return MediaAnalyticsItem::SessionIDInvalid;
        }

        data.writeInterfaceToken(IMediaAnalyticsService::getInterfaceDescriptor());
        if(DEBUGGING_FLOW) {
            ALOGD("client offers record: %s", item->toString().c_str());
        }
        data.writeBool(forcenew);
        item->writeToParcel(&data);

        err = remote()->transact(SUBMIT_ITEM, data, &reply);
        if (err != NO_ERROR) {
            return MediaAnalyticsItem::SessionIDInvalid;
        }

        // get an answer out of 'reply'
        int64_t sessionid = reply.readInt64();
        if (DEBUGGING_RETURNS) {
            ALOGD("the caller gets sessionid=%" PRId64 "", sessionid);
        }
        return sessionid;
    }

    virtual List<sp<MediaAnalyticsItem>> *getMediaAnalyticsItemList(bool finished, nsecs_t ts)
    {
            return getMediaAnalyticsItemList(finished, ts, MediaAnalyticsItem::kKeyAny);
    }

    virtual List<sp<MediaAnalyticsItem>> *getMediaAnalyticsItemList(bool finished, nsecs_t ts, MediaAnalyticsItem::Key key)
    {
        Parcel data, reply;
        status_t err;

        data.writeInterfaceToken(IMediaAnalyticsService::getInterfaceDescriptor());
        data.writeInt32(finished);
        data.writeInt64(ts);
        const char *str = key.c_str();
        if (key.empty()) {
            str = MediaAnalyticsItem::kKeyNone.c_str();
        }
        data.writeCString(str);
        err = remote()->transact(GET_ITEM_LIST, data, &reply);
	if (err != NO_ERROR) {
	    return NULL;
	}

        // read a count
        int32_t count = reply.readInt32();
        List<sp<MediaAnalyticsItem>> *list = NULL;

        if (count > 0) {
            list = new List<sp<MediaAnalyticsItem>>();
            for (int i=0;i<count;i++) {
                sp<MediaAnalyticsItem> item = new MediaAnalyticsItem;
                // XXX: watch for failures here
                item->readFromParcel(reply);
                list->push_back(item);
            }
        }

        return list;
    }
};

IMPLEMENT_META_INTERFACE(MediaAnalyticsService, "android.media.IMediaAnalyticsService");

// ----------------------------------------------------------------------

status_t BnMediaAnalyticsService::onTransact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{


    // get calling pid/tid
    IPCThreadState *ipc = IPCThreadState::self();
    int clientPid = ipc->getCallingPid();
    // permission checking

    if(DEBUGGING_FLOW) {
        ALOGD("running in service, code %d, pid %d; called from pid %d",
            code, getpid(), clientPid);
    }

    switch (code) {

        case GENERATE_UNIQUE_SESSIONID: {
            CHECK_INTERFACE(IMediaAnalyticsService, data, reply);

            MediaAnalyticsItem::SessionID_t sessionid = generateUniqueSessionID();
            reply->writeInt64(sessionid);

            return NO_ERROR;
        } break;

        case SUBMIT_ITEM: {
            CHECK_INTERFACE(IMediaAnalyticsService, data, reply);

            bool forcenew;
            sp<MediaAnalyticsItem> item = new MediaAnalyticsItem;

            data.readBool(&forcenew);
            item->readFromParcel(data);

            item->setPid(clientPid);

	    // submit() takes ownership of / responsibility for the item
            MediaAnalyticsItem::SessionID_t sessionid = submit(item, forcenew);
            reply->writeInt64(sessionid);

            return NO_ERROR;
        } break;

        case GET_ITEM_LIST: {
            CHECK_INTERFACE(IMediaPlayerService, data, reply);
            // get the parameters
            bool finished = data.readInt32();
            nsecs_t ts = data.readInt64();
            MediaAnalyticsItem::Key key = data.readCString();

            // find the (0 or more) items
            List<sp<MediaAnalyticsItem>> *list =  getMediaAnalyticsItemList(finished, ts, key);
            // encapsulate/serialize them
            reply->writeInt32(list->size());
            if (list->size() > 0) {
                    for (List<sp<MediaAnalyticsItem>>::iterator it = list->begin();
                         it != list->end(); it++) {
                            (*it)->writeToParcel(reply);
                    }


            }

            // avoid leakiness; organized discarding of list and its contents
            list->clear();
            delete list;

            return NO_ERROR;
        } break;

        default:
            return BBinder::onTransact(code, data, reply, flags);
    }
}

// ----------------------------------------------------------------------------

} // namespace android
