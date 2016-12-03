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

#undef LOG_TAG
#define LOG_TAG "MediaAnalyticsItem"

#include <sys/types.h>
#include <inttypes.h>

#include <binder/Parcel.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/Mutex.h>
#include <utils/RefBase.h>
#include <utils/SortedVector.h>
#include <utils/threads.h>

#include <media/stagefright/foundation/AString.h>

#include <binder/IServiceManager.h>
#include <media/IMediaAnalyticsService.h>
#include <media/MediaAnalyticsItem.h>

namespace android {

#define DEBUG_SERVICEACCESS     0

// the few universal keys we have
const MediaAnalyticsItem::Key MediaAnalyticsItem::kKeyAny  = "any";
const MediaAnalyticsItem::Key MediaAnalyticsItem::kKeyNone  = "none";

const char * const MediaAnalyticsItem::EnabledProperty  = "media.analytics.enabled";
const char * const MediaAnalyticsItem::EnabledPropertyPersist  = "persist.media.analytics.enabled";
const int MediaAnalyticsItem::EnabledProperty_default  = 0;


// access functions for the class
MediaAnalyticsItem::MediaAnalyticsItem()
    : RefBase(),
      mPid(0),
      mUid(0),
      mSessionID(MediaAnalyticsItem::SessionIDNone),
      mTimestamp(0),
      mFinalized(0) {
    mKey = MediaAnalyticsItem::kKeyNone;
}

MediaAnalyticsItem::MediaAnalyticsItem(MediaAnalyticsItem::Key key)
    : RefBase(),
      mPid(0),
      mUid(0),
      mSessionID(MediaAnalyticsItem::SessionIDNone),
      mTimestamp(0),
      mFinalized(0) {
    mKey = key;
}

MediaAnalyticsItem::~MediaAnalyticsItem() {
    clear();
}

// so clients can send intermediate values to be overlaid later
MediaAnalyticsItem &MediaAnalyticsItem::setFinalized(bool value) {
    mFinalized = value;
    return *this;
}

bool MediaAnalyticsItem::getFinalized() const {
    return mFinalized;
}

MediaAnalyticsItem &MediaAnalyticsItem::setSessionID(MediaAnalyticsItem::SessionID_t id) {
    mSessionID = id;
    return *this;
}

MediaAnalyticsItem::SessionID_t MediaAnalyticsItem::getSessionID() const {
    return mSessionID;
}

MediaAnalyticsItem::SessionID_t MediaAnalyticsItem::generateSessionID() {
    MediaAnalyticsItem::SessionID_t newid = SessionIDNone;
    ALOGD("generateSessionID()");

    if (mSessionID == SessionIDNone) {
        // get one from the server
        sp<IMediaAnalyticsService> svc = getInstance();
        if (svc != NULL) {
            newid = svc->generateUniqueSessionID();
        }
        mSessionID = newid;
    }

    return mSessionID;
}

MediaAnalyticsItem &MediaAnalyticsItem::clearSessionID() {
    mSessionID = MediaAnalyticsItem::SessionIDNone;
    return *this;
}

MediaAnalyticsItem &MediaAnalyticsItem::setTimestamp(nsecs_t ts) {
    mTimestamp = ts;
    return *this;
}

nsecs_t MediaAnalyticsItem::getTimestamp() const {
    return mTimestamp;
}

MediaAnalyticsItem &MediaAnalyticsItem::setPid(pid_t pid) {
    mPid = pid;
    return *this;
}

pid_t MediaAnalyticsItem::getPid() const {
    return mPid;
}

MediaAnalyticsItem &MediaAnalyticsItem::setUid(uid_t uid) {
    mUid = uid;
    return *this;
}

uid_t MediaAnalyticsItem::getUid() const {
    return mUid;
}

void MediaAnalyticsItem::clear() {

    mKey.clear();

#if 0
    // not sure that I need to (or should) be doing this...
    // seeing some strangeness in some records
    int count = mItems.size();
    for (int i = 0 ; i < count; i++ ) {
        MediaAnalyticsItem::Attr attr = mItems.keyAt(i);
        const sp<Item> value = mItems.valueAt(i);
        value->clear();
        attr.clear();
    }
    mItems.clear();
#endif

    return;
}

// this key is for the overall record -- "vid" or "aud"
// assuming for the moment we use int32_t like the
// media frameworks MetaData.cpp
MediaAnalyticsItem &MediaAnalyticsItem::setKey(MediaAnalyticsItem::Key key) {
    // XXX: possible validation of legal keys.
    mKey = key;
    return *this;
}

MediaAnalyticsItem::Key MediaAnalyticsItem::getKey() {
    return mKey;
}

// number of keys we have in our dictionary
// we won't upload empty records
int32_t MediaAnalyticsItem::count() const {
    return mItems.size();
}

// set the values
bool MediaAnalyticsItem::setInt32(MediaAnalyticsItem::Attr attr, int32_t value) {
    ssize_t i = mItems.indexOfKey(attr);
    bool overwrote = true;
    if (i<0) {
        sp<Item> item = new Item();
        i = mItems.add(attr, item);
        overwrote = false;
    }
    sp<Item> &item = mItems.editValueAt(i);
    item->mType = MediaAnalyticsItem::Item::kTypeInt32;
    item->u.int32Value = value;
    return overwrote;
}

bool MediaAnalyticsItem::setInt64(MediaAnalyticsItem::Attr attr, int64_t value) {
    ssize_t i = mItems.indexOfKey(attr);
    bool overwrote = true;
    if (i<0) {
        sp<Item> item = new Item();
        i = mItems.add(attr, item);
        overwrote = false;
    }
    sp<Item> &item = mItems.editValueAt(i);
    item->mType = MediaAnalyticsItem::Item::kTypeInt64;
    item->u.int64Value = value;
    return overwrote;
}

bool MediaAnalyticsItem::setDouble(MediaAnalyticsItem::Attr attr, double value) {
    ssize_t i = mItems.indexOfKey(attr);
    bool overwrote = true;
    if (i<0) {
        sp<Item> item = new Item();
        i = mItems.add(attr, item);
        overwrote = false;
    }
    sp<Item> &item = mItems.editValueAt(i);
    item->mType = MediaAnalyticsItem::Item::kTypeDouble;
    item->u.doubleValue = value;
    return overwrote;
}

bool MediaAnalyticsItem::setCString(MediaAnalyticsItem::Attr attr, const char *value) {
    bool overwrote = true;
    if (value == NULL) return false;
    // we store our own copy of the supplied string
    char *nvalue = strdup(value);
    if (nvalue == NULL) {
            return false;
    }
    ssize_t i = mItems.indexOfKey(attr);
    if (i<0) {
        sp<Item> item = new Item();
        i = mItems.add(attr, item);
        overwrote = false;
    }
    sp<Item> &item = mItems.editValueAt(i);
    if (item->mType == MediaAnalyticsItem::Item::kTypeCString
        && item->u.CStringValue != NULL) {
            free(item->u.CStringValue);
            item->u.CStringValue = NULL;
    }
    item->mType = MediaAnalyticsItem::Item::kTypeCString;
    item->u.CStringValue = nvalue;
    return true;
}

// find/add/set fused into a single operation
bool MediaAnalyticsItem::addInt32(MediaAnalyticsItem::Attr attr, int32_t value) {
    ssize_t i = mItems.indexOfKey(attr);
    bool overwrote = true;
    if (i<0) {
        sp<Item> item = new Item();
        i = mItems.add(attr, item);
        overwrote = false;
    }
    sp<Item> &item = mItems.editValueAt(i);
    if (overwrote
        && item->mType == MediaAnalyticsItem::Item::kTypeInt32) {
        item->u.int32Value += value;
    } else {
        // start clean if there was a type mismatch
        item->u.int32Value = value;
    }
    item->mType = MediaAnalyticsItem::Item::kTypeInt32;
    return overwrote;
}

bool MediaAnalyticsItem::addInt64(MediaAnalyticsItem::Attr attr, int64_t value) {
    ssize_t i = mItems.indexOfKey(attr);
    bool overwrote = true;
    if (i<0) {
        sp<Item> item = new Item();
        i = mItems.add(attr, item);
        overwrote = false;
    }
    sp<Item> &item = mItems.editValueAt(i);
    if (overwrote
        && item->mType == MediaAnalyticsItem::Item::kTypeInt64) {
        item->u.int64Value += value;
    } else {
        // start clean if there was a type mismatch
        item->u.int64Value = value;
    }
    item->mType = MediaAnalyticsItem::Item::kTypeInt64;
    return overwrote;
}

bool MediaAnalyticsItem::addDouble(MediaAnalyticsItem::Attr attr, double value) {
    ssize_t i = mItems.indexOfKey(attr);
    bool overwrote = true;
    if (i<0) {
        sp<Item> item = new Item();
        i = mItems.add(attr, item);
        overwrote = false;
    }
    sp<Item> &item = mItems.editValueAt(i);
    if (overwrote
        && item->mType == MediaAnalyticsItem::Item::kTypeDouble) {
        item->u.doubleValue += value;
    } else {
        // start clean if there was a type mismatch
        item->u.doubleValue = value;
    }
    item->mType = MediaAnalyticsItem::Item::kTypeDouble;
    return overwrote;
}

// find & extract values
bool MediaAnalyticsItem::getInt32(MediaAnalyticsItem::Attr attr, int32_t *value) {
    ssize_t i = mItems.indexOfKey(attr);
    if (i < 0) {
        return false;
    }
    sp<Item> &item = mItems.editValueAt(i);
    *value = item->u.int32Value;
    return true;
}
bool MediaAnalyticsItem::getInt64(MediaAnalyticsItem::Attr attr, int64_t *value) {
    ssize_t i = mItems.indexOfKey(attr);
    if (i < 0) {
        return false;
    }
    sp<Item> &item = mItems.editValueAt(i);
    *value = item->u.int64Value;
    return true;
}
bool MediaAnalyticsItem::getDouble(MediaAnalyticsItem::Attr attr, double *value) {
    ssize_t i = mItems.indexOfKey(attr);
    if (i < 0) {
        return false;
    }
    sp<Item> &item = mItems.editValueAt(i);
    *value = item->u.doubleValue;
    return true;
}

// caller responsible for the returned string
bool MediaAnalyticsItem::getCString(MediaAnalyticsItem::Attr attr, char **value) {
    ssize_t i = mItems.indexOfKey(attr);
    if (i < 0) {
        return false;
    }
    sp<Item> &item = mItems.editValueAt(i);
    char *p = strdup(item->u.CStringValue);
    *value = p;
    return true;
}

// remove indicated keys and their values
// return value is # keys removed
int32_t MediaAnalyticsItem::filter(int n, MediaAnalyticsItem::Attr attrs[]) {
    int zapped = 0;
    if (attrs == NULL) {
        return -1;
    }
    if (n <= 0) {
        return -1;
    }
    for (ssize_t i = 0 ; i < n ;  i++) {
        ssize_t j = mItems.indexOfKey(attrs[i]);
        if (j >= 0) {
            mItems.removeItemsAt(j);
            zapped++;
        }
    }
    return zapped;
}

// remove any keys NOT in the provided list
// return value is # keys removed
int32_t MediaAnalyticsItem::filterNot(int n, MediaAnalyticsItem::Attr attrs[]) {
    int zapped = 0;
    if (attrs == NULL) {
        return -1;
    }
    if (n <= 0) {
        return -1;
    }
    for (ssize_t i = mItems.size()-1 ; i >=0 ;  i--) {
        const MediaAnalyticsItem::Attr& lattr = mItems.keyAt(i);
        ssize_t j;
        for (j= 0; j < n ; j++) {
            if (lattr == attrs[j]) {
                mItems.removeItemsAt(i);
                zapped++;
                break;
            }
        }
    }
    return zapped;
}

// remove a single key
// return value is 0 (not found) or 1 (found and removed)
int32_t MediaAnalyticsItem::filter(MediaAnalyticsItem::Attr attr) {
    if (attr == 0) return -1;
    ssize_t i = mItems.indexOfKey(attr);
    if (i < 0) {
        return 0;
    }
    mItems.removeItemsAt(i);
    return 1;
}


// handle individual items/properties stored within the class
//
MediaAnalyticsItem::Item::Item()
        : mType(kTypeNone)
{
}

MediaAnalyticsItem::Item::~Item()
{
    clear();
}

void MediaAnalyticsItem::Item::clear()
{
    if (mType == kTypeCString && u.CStringValue != NULL) {
        free(u.CStringValue);
        u.CStringValue = NULL;
    }
    mType = kTypeNone;
}

// Parcel / serialize things for binder calls
//

int32_t MediaAnalyticsItem::readFromParcel(const Parcel& data) {
    // into 'this' object
    // .. we make a copy of the string to put away.
    mKey = data.readCString();
    mSessionID = data.readInt64();
    mFinalized = data.readInt32();
    mTimestamp = data.readInt64();

    int count = data.readInt32();
    for (int i = 0; i < count ; i++) {
            MediaAnalyticsItem::Attr attr = data.readCString();
            int32_t ztype = data.readInt32();
                switch (ztype) {
                    case MediaAnalyticsItem::Item::kTypeInt32:
                            setInt32(attr, data.readInt32());
                            break;
                    case MediaAnalyticsItem::Item::kTypeInt64:
                            setInt64(attr, data.readInt64());
                            break;
                    case MediaAnalyticsItem::Item::kTypeDouble:
                            setDouble(attr, data.readDouble());
                            break;
                    case MediaAnalyticsItem::Item::kTypeCString:
                            setCString(attr, data.readCString());
                            break;
                    default:
                            ALOGE("reading bad item type: %d, idx %d",
                                  ztype, i);
                            return -1;
                }
    }

    return 0;
}

int32_t MediaAnalyticsItem::writeToParcel(Parcel *data) {
    if (data == NULL) return -1;


    data->writeCString(mKey.c_str());
    data->writeInt64(mSessionID);
    data->writeInt32(mFinalized);
    data->writeInt64(mTimestamp);

    // set of items
    int count = mItems.size();
    data->writeInt32(count);
    for (int i = 0 ; i < count; i++ ) {
            MediaAnalyticsItem::Attr attr = mItems.keyAt(i);
            sp<Item> value = mItems.valueAt(i);
            {
                data->writeCString(attr.c_str());
                data->writeInt32(value->mType);
                switch (value->mType) {
                    case MediaAnalyticsItem::Item::kTypeInt32:
                            data->writeInt32(value->u.int32Value);
                            break;
                    case MediaAnalyticsItem::Item::kTypeInt64:
                            data->writeInt64(value->u.int64Value);
                            break;
                    case MediaAnalyticsItem::Item::kTypeDouble:
                            data->writeDouble(value->u.doubleValue);
                            break;
                    case MediaAnalyticsItem::Item::kTypeCString:
                            data->writeCString(value->u.CStringValue);
                            break;
                    default:
                            ALOGE("found bad item type: %d, idx %d",
                                  value->mType, i);
                            break;
                }
            }
    }

    return 0;
}



AString MediaAnalyticsItem::toString() {

    AString result = "(";
    char buffer[256];

    // same order as we spill into the parcel, although not required
    // key+session are our primary matching criteria
    result.append(mKey.c_str());
    result.append(":");
    snprintf(buffer, sizeof(buffer), "%" PRId64 ":", mSessionID);
    result.append(buffer);

    // we need these internally, but don't want to upload them
    snprintf(buffer, sizeof(buffer), "%d:%d", mUid, mPid);
    result.append(buffer);

    snprintf(buffer, sizeof(buffer), "%d:", mFinalized);
    result.append(buffer);
    snprintf(buffer, sizeof(buffer), "%" PRId64 ":", mTimestamp);
    result.append(buffer);

    // set of items
    int count = mItems.size();
    snprintf(buffer, sizeof(buffer), "%d:", count);
    result.append(buffer);
    for (int i = 0 ; i < count; i++ ) {
            const MediaAnalyticsItem::Attr attr = mItems.keyAt(i);
            const sp<Item> value = mItems.valueAt(i);
            switch (value->mType) {
                case MediaAnalyticsItem::Item::kTypeInt32:
                        snprintf(buffer,sizeof(buffer),
                        "%s=%d:", attr.c_str(), value->u.int32Value);
                        break;
                case MediaAnalyticsItem::Item::kTypeInt64:
                        snprintf(buffer,sizeof(buffer),
                        "%s=%" PRId64 ":", attr.c_str(), value->u.int64Value);
                        break;
                case MediaAnalyticsItem::Item::kTypeDouble:
                        snprintf(buffer,sizeof(buffer),
                        "%s=%e:", attr.c_str(), value->u.doubleValue);
                        break;
                case MediaAnalyticsItem::Item::kTypeCString:
                        // XXX: worry about escape chars
                        // XXX: worry about overflowing buffer
                        snprintf(buffer,sizeof(buffer), "%s=", attr.c_str());
                        result.append(buffer);
                        result.append(value->u.CStringValue);
                        buffer[0] = ':';
                        buffer[1] = '\0';
                        break;
                default:
                        ALOGE("to_String bad item type: %d",
                              value->mType);
                        break;
            }
            result.append(buffer);
    }

    result.append(")");

    return result;
}

// for the lazy, we offer methods that finds the service and
// calls the appropriate daemon
bool MediaAnalyticsItem::selfrecord() {
    return selfrecord(false);
}

bool MediaAnalyticsItem::selfrecord(bool forcenew) {

    AString p = this->toString();
    ALOGD("selfrecord of: %s [forcenew=%d]", p.c_str(), forcenew);

    sp<IMediaAnalyticsService> svc = getInstance();

    if (svc != NULL) {
        svc->submit(this, forcenew);
        return true;
    } else {
        return false;
    }
}

// get a connection we can reuse for most of our lifetime
// static
sp<IMediaAnalyticsService> MediaAnalyticsItem::sAnalyticsService;
static Mutex sInitMutex;

//static
bool MediaAnalyticsItem::isEnabled() {
    int enabled = property_get_int32(MediaAnalyticsItem::EnabledProperty, -1);

    if (enabled == -1) {
        enabled = property_get_int32(MediaAnalyticsItem::EnabledPropertyPersist, -1);
    }
    if (enabled == -1) {
        enabled = MediaAnalyticsItem::EnabledProperty_default;
    }
    if (enabled <= 0) {
        return false;
    }
    return true;
}

//static
sp<IMediaAnalyticsService> MediaAnalyticsItem::getInstance() {
    static const char *servicename = "media.analytics";
    int enabled = isEnabled();

    if (enabled == false) {
        if (DEBUG_SERVICEACCESS) {
                ALOGD("disabled");
        }
        return NULL;
    }

    {
        Mutex::Autolock _l(sInitMutex);
        const char *badness = "";


        if (sAnalyticsService == NULL) {
            sp<IServiceManager> sm = defaultServiceManager();
            if (sm != NULL) {
                sp<IBinder> binder = sm->getService(String16(servicename));
                if (binder != NULL) {
                    sAnalyticsService = interface_cast<IMediaAnalyticsService>(binder);
                } else {
                    badness = "did not find service";
                }
            } else {
                badness = "No Service Manager access";
            }
            // always
            if (1 || DEBUG_SERVICEACCESS) {
                if (sAnalyticsService == NULL) {
                    ALOGD("Unable to bind to service %s: %s", servicename, badness);
                }
            }
        }
        return sAnalyticsService;
    }
}


// merge the info from 'incoming' into this record.
// we finish with a union of this+incoming and special handling for collisions
bool MediaAnalyticsItem::merge(sp<MediaAnalyticsItem> incoming) {

    // if I don't have key or session id, take them from incoming
    // 'this' should never be missing both of them...
    if (mKey.empty()) {
        mKey = incoming->mKey;
    } else if (mSessionID == 0) {
        mSessionID = incoming->mSessionID;
    }

    // we always take the more recent 'finalized' value
    setFinalized(incoming->getFinalized());

    // for each attribute from 'incoming', resolve appropriately
    int nattr = incoming->mItems.size();
    for (int i = 0 ; i < nattr; i++ ) {
        const MediaAnalyticsItem::Attr attr = incoming->mItems.keyAt(i);
        const sp<Item> value = incoming->mItems.valueAt(i);

        const char *p = attr.c_str();
        char semantic = p[strlen(p)-1];

        switch (semantic) {
            default:        // default operation is keep new
            case '>':       // last aka keep new
                mItems.replaceValueFor(attr, value);
                break;

            case '<':       /* first aka keep first*/
                /* nop */
                break;

            case '+':       /* sum */
                // XXX validate numeric types, sum in place
                break;

        }
    }

    // not sure when we'd return false...
    return true;
}

} // namespace android

