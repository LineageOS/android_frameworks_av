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

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <mutex>

#include <binder/Parcel.h>
#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/SortedVector.h>
#include <utils/threads.h>

#include <binder/IServiceManager.h>
#include <media/IMediaAnalyticsService.h>
#include <media/MediaAnalyticsItem.h>
#include <private/android_filesystem_config.h>

namespace android {

#define DEBUG_SERVICEACCESS     0
#define DEBUG_API               0
#define DEBUG_ALLOCATIONS       0

// after this many failed attempts, we stop trying [from this process] and just say that
// the service is off.
#define SVC_TRIES               2

// So caller doesn't need to know size of allocated space
MediaAnalyticsItem *MediaAnalyticsItem::create()
{
    return MediaAnalyticsItem::create(kKeyNone);
}

MediaAnalyticsItem *MediaAnalyticsItem::create(MediaAnalyticsItem::Key key)
{
    MediaAnalyticsItem *item = new MediaAnalyticsItem(key);
    return item;
}

MediaAnalyticsItem* MediaAnalyticsItem::convert(mediametrics_handle_t handle) {
    MediaAnalyticsItem *item = (android::MediaAnalyticsItem *) handle;
    return item;
}

mediametrics_handle_t MediaAnalyticsItem::convert(MediaAnalyticsItem *item ) {
    mediametrics_handle_t handle = (mediametrics_handle_t) item;
    return handle;
}

MediaAnalyticsItem::~MediaAnalyticsItem() {
    if (DEBUG_ALLOCATIONS) {
        ALOGD("Destroy  MediaAnalyticsItem @ %p", this);
    }
    clear();
}

void MediaAnalyticsItem::clear() {

    // clean allocated storage from key
    mKey.clear();

    // clean attributes
    // contents of the attributes
    for (size_t i = 0 ; i < mPropCount; i++ ) {
        mProps[i].clear();
    }
    // the attribute records themselves
    if (mProps != NULL) {
        free(mProps);
        mProps = NULL;
    }
    mPropSize = 0;
    mPropCount = 0;

    return;
}

// make a deep copy of myself
MediaAnalyticsItem *MediaAnalyticsItem::dup() {
    MediaAnalyticsItem *dst = new MediaAnalyticsItem(this->mKey);

    if (dst != NULL) {
        // key as part of constructor
        dst->mPid = this->mPid;
        dst->mUid = this->mUid;
        dst->mPkgName = this->mPkgName;
        dst->mPkgVersionCode = this->mPkgVersionCode;
        dst->mTimestamp = this->mTimestamp;

        // properties aka attributes
        dst->growProps(this->mPropCount);
        for(size_t i=0;i<mPropCount;i++) {
            dst->mProps[i] = this->mProps[i];
        }
        dst->mPropCount = this->mPropCount;
    }

    return dst;
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

MediaAnalyticsItem &MediaAnalyticsItem::setPkgName(const std::string &pkgName) {
    mPkgName = pkgName;
    return *this;
}

MediaAnalyticsItem &MediaAnalyticsItem::setPkgVersionCode(int64_t pkgVersionCode) {
    mPkgVersionCode = pkgVersionCode;
    return *this;
}

int64_t MediaAnalyticsItem::getPkgVersionCode() const {
    return mPkgVersionCode;
}

// this key is for the overall record -- "codec", "player", "drm", etc
MediaAnalyticsItem &MediaAnalyticsItem::setKey(MediaAnalyticsItem::Key key) {
    mKey = key;
    return *this;
}

// number of attributes we have in this record
int32_t MediaAnalyticsItem::count() const {
    return mPropCount;
}

// find the proper entry in the list
size_t MediaAnalyticsItem::findPropIndex(const char *name, size_t len) const
{
    size_t i = 0;
    for (; i < mPropCount; i++) {
        if (mProps[i].isNamed(name, len)) break;
    }
    return i;
}

MediaAnalyticsItem::Prop *MediaAnalyticsItem::findProp(const char *name) const {
    size_t len = strlen(name);
    size_t i = findPropIndex(name, len);
    if (i < mPropCount) {
        return &mProps[i];
    }
    return NULL;
}

// consider this "find-or-allocate".
// caller validates type and uses clearPropValue() accordingly
MediaAnalyticsItem::Prop *MediaAnalyticsItem::allocateProp(const char *name) {
    size_t len = strlen(name);
    size_t i = findPropIndex(name, len);
    Prop *prop;

    if (i < mPropCount) {
        prop = &mProps[i];
    } else {
        if (i == mPropSize) {
            if (growProps() == false) {
                ALOGE("failed allocation for new props");
                return NULL;
            }
        }
        i = mPropCount++;
        prop = &mProps[i];
        prop->setName(name, len);
    }

    return prop;
}

// used within the summarizers; return whether property existed
bool MediaAnalyticsItem::removeProp(const char *name) {
    size_t len = strlen(name);
    size_t i = findPropIndex(name, len);
    if (i < mPropCount) {
        mProps[i].clear();
        if (i != mPropCount-1) {
            // in the middle, bring last one down to fill gap
            mProps[i].swap(mProps[mPropCount-1]);
        }
        mPropCount--;
        return true;
    }
    return false;
}

// remove indicated keys and their values
// return value is # keys removed
int32_t MediaAnalyticsItem::filter(int n, MediaAnalyticsItem::Attr attrs[]) {
    int zapped = 0;
    if (attrs == NULL || n <= 0) {
        return -1;
    }
    for (ssize_t i = 0 ; i < n ;  i++) {
        const char *name = attrs[i];
        size_t len = strlen(name);
        size_t j = findPropIndex(name, len);
        if (j >= mPropCount) {
            // not there
            continue;
        } else if (j+1 == mPropCount) {
            // last one, shorten
            zapped++;
            mProps[j].clear();
            mPropCount--;
        } else {
            // in the middle, bring last one down and shorten
            zapped++;
            mProps[j].clear();
            mProps[j] = mProps[mPropCount-1];
            mPropCount--;
        }
    }
    return zapped;
}

// remove any keys NOT in the provided list
// return value is # keys removed
int32_t MediaAnalyticsItem::filterNot(int n, MediaAnalyticsItem::Attr attrs[]) {
    int zapped = 0;
    if (attrs == NULL || n <= 0) {
        return -1;
    }
    for (ssize_t i = mPropCount-1 ; i >=0 ;  i--) {
        Prop *prop = &mProps[i];
        for (ssize_t j = 0; j < n ; j++) {
            if (prop->isNamed(attrs[j])) {
                prop->clear();
                zapped++;
                if (i != (ssize_t)(mPropCount-1)) {
                    *prop = mProps[mPropCount-1];
                }
                mProps[mPropCount-1].clear();
                mPropCount--;
                break;
            }
        }
    }
    return zapped;
}

// remove a single key
// return value is 0 (not found) or 1 (found and removed)
int32_t MediaAnalyticsItem::filter(MediaAnalyticsItem::Attr name) {
    return filter(1, &name);
}

bool MediaAnalyticsItem::growProps(int increment)
{
    if (increment <= 0) {
        increment = kGrowProps;
    }
    int nsize = mPropSize + increment;
    Prop *ni = (Prop *)realloc(mProps, sizeof(Prop) * nsize);

    if (ni != NULL) {
        for (int i = mPropSize; i < nsize; i++) {
            new (&ni[i]) Prop(); // placement new
        }
        mProps = ni;
        mPropSize = nsize;
        return true;
    } else {
        ALOGW("MediaAnalyticsItem::growProps fails");
        return false;
    }
}

// Parcel / serialize things for binder calls
//

int32_t MediaAnalyticsItem::readFromParcel(const Parcel& data) {
    int32_t version = data.readInt32();

    switch(version) {
        case 0:
          return readFromParcel0(data);
          break;
        default:
          ALOGE("Unsupported MediaAnalyticsItem Parcel version: %d", version);
          return -1;
    }
}

int32_t MediaAnalyticsItem::readFromParcel0(const Parcel& data) {
    // into 'this' object
    // .. we make a copy of the string to put away.
    mKey = data.readCString();
    mPid = data.readInt32();
    mUid = data.readInt32();
    mPkgName = data.readCString();
    mPkgVersionCode = data.readInt64();
    // We no longer pay attention to user setting of finalized, BUT it's
    // still part of the wire packet -- so read & discard.
    mTimestamp = data.readInt64();

    int count = data.readInt32();
    for (int i = 0; i < count ; i++) {
            MediaAnalyticsItem::Attr attr = data.readCString();
            int32_t ztype = data.readInt32();
                switch (ztype) {
                    case MediaAnalyticsItem::kTypeInt32:
                            setInt32(attr, data.readInt32());
                            break;
                    case MediaAnalyticsItem::kTypeInt64:
                            setInt64(attr, data.readInt64());
                            break;
                    case MediaAnalyticsItem::kTypeDouble:
                            setDouble(attr, data.readDouble());
                            break;
                    case MediaAnalyticsItem::kTypeCString:
                            setCString(attr, data.readCString());
                            break;
                    case MediaAnalyticsItem::kTypeRate:
                            {
                                int64_t count = data.readInt64();
                                int64_t duration = data.readInt64();
                                setRate(attr, count, duration);
                            }
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

    int32_t version = 0;
    data->writeInt32(version);

    switch(version) {
        case 0:
          return writeToParcel0(data);
          break;
        default:
          ALOGE("Unsupported MediaAnalyticsItem Parcel version: %d", version);
          return -1;
    }
}

int32_t MediaAnalyticsItem::writeToParcel0(Parcel *data) {

    data->writeCString(mKey.c_str());
    data->writeInt32(mPid);
    data->writeInt32(mUid);
    data->writeCString(mPkgName.c_str());
    data->writeInt64(mPkgVersionCode);
    data->writeInt64(mTimestamp);

    // set of items
    const size_t count = mPropCount;
    data->writeInt32(count);
    for (size_t i = 0 ; i < count; i++ ) {
        mProps[i].writeToParcel(data);
    }
    return 0;
}

const char *MediaAnalyticsItem::toCString() {
   return toCString(PROTO_LAST);
}

const char * MediaAnalyticsItem::toCString(int version) {
    std::string val = toString(version);
    return strdup(val.c_str());
}

std::string MediaAnalyticsItem::toString() const {
   return toString(PROTO_LAST);
}

std::string MediaAnalyticsItem::toString(int version) const {

    // v0 : released with 'o'
    // v1 : bug fix (missing pid/finalized separator),
    //      adds apk name, apk version code

    if (version <= PROTO_FIRST) {
        // default to original v0 format, until proper parsers are in place
        version = PROTO_V0;
    } else if (version > PROTO_LAST) {
        version = PROTO_LAST;
    }

    std::string result;
    char buffer[512];

    if (version == PROTO_V0) {
        result = "(";
    } else {
        snprintf(buffer, sizeof(buffer), "[%d:", version);
        result.append(buffer);
    }

    // same order as we spill into the parcel, although not required
    // key+session are our primary matching criteria
    result.append(mKey.c_str());
    result.append(":0:"); // sessionID

    snprintf(buffer, sizeof(buffer), "%d:", mUid);
    result.append(buffer);

    if (version >= PROTO_V1) {
        result.append(mPkgName);
        snprintf(buffer, sizeof(buffer), ":%"  PRId64 ":", mPkgVersionCode);
        result.append(buffer);
    }

    // in 'o' (v1) , the separator between pid and finalized was omitted
    if (version <= PROTO_V0) {
        snprintf(buffer, sizeof(buffer), "%d", mPid);
    } else {
        snprintf(buffer, sizeof(buffer), "%d:", mPid);
    }
    result.append(buffer);

    snprintf(buffer, sizeof(buffer), "%d:", 0 /* finalized */); // TODO: remove this.
    result.append(buffer);
    snprintf(buffer, sizeof(buffer), "%" PRId64 ":", mTimestamp);
    result.append(buffer);

    // set of items
    int count = mPropCount;
    snprintf(buffer, sizeof(buffer), "%d:", count);
    result.append(buffer);
    for (int i = 0 ; i < count; i++ ) {
        mProps[i].toString(buffer, sizeof(buffer));
        result.append(buffer);
    }

    if (version == PROTO_V0) {
        result.append(")");
    } else {
        result.append("]");
    }

    return result;
}

// for the lazy, we offer methods that finds the service and
// calls the appropriate daemon
bool MediaAnalyticsItem::selfrecord() {
    ALOGD_IF(DEBUG_API, "%s: delivering %s", __func__, this->toString().c_str());
    sp<IMediaAnalyticsService> svc = getInstance();
    if (svc != NULL) {
        status_t status = svc->submit(this);
        if (status != NO_ERROR) {
            ALOGW("%s: failed to record: %s", __func__, this->toString().c_str());
            return false;
        }
        return true;
    } else {
        return false;
    }
}


//static
bool MediaAnalyticsItem::isEnabled() {
    // completely skip logging from certain UIDs. We do this here
    // to avoid the multi-second timeouts while we learn that
    // sepolicy will not let us find the service.
    // We do this only for a select set of UIDs
    // The sepolicy protection is still in place, we just want a faster
    // response from this specific, small set of uids.

    // This is checked only once in the lifetime of the process.
    const uid_t uid = getuid();
    switch (uid) {
    case AID_RADIO:     // telephony subsystem, RIL
        return false;
    }

    int enabled = property_get_int32(MediaAnalyticsItem::EnabledProperty, -1);
    if (enabled == -1) {
        enabled = property_get_int32(MediaAnalyticsItem::EnabledPropertyPersist, -1);
    }
    if (enabled == -1) {
        enabled = MediaAnalyticsItem::EnabledProperty_default;
    }
    return enabled > 0;
}

// monitor health of our connection to the metrics service
class MediaMetricsDeathNotifier : public IBinder::DeathRecipient {
        virtual void binderDied(const wp<IBinder> &) {
            ALOGW("Reacquire service connection on next request");
            MediaAnalyticsItem::dropInstance();
        }
};

static sp<MediaMetricsDeathNotifier> sNotifier;
// static
sp<IMediaAnalyticsService> MediaAnalyticsItem::sAnalyticsService;
static std::mutex sServiceMutex;
static int sRemainingBindAttempts = SVC_TRIES;

// static
void MediaAnalyticsItem::dropInstance() {
    std::lock_guard  _l(sServiceMutex);
    sRemainingBindAttempts = SVC_TRIES;
    sAnalyticsService = nullptr;
}

//static
sp<IMediaAnalyticsService> MediaAnalyticsItem::getInstance() {
    static const char *servicename = "media.metrics";
    static const bool enabled = isEnabled(); // singleton initialized

    if (enabled == false) {
        ALOGD_IF(DEBUG_SERVICEACCESS, "disabled");
        return nullptr;
    }
    std::lock_guard _l(sServiceMutex);
    // think of remainingBindAttempts as telling us whether service == nullptr because
    // (1) we haven't tried to initialize it yet
    // (2) we've tried to initialize it, but failed.
    if (sAnalyticsService == nullptr && sRemainingBindAttempts > 0) {
        const char *badness = "";
        sp<IServiceManager> sm = defaultServiceManager();
        if (sm != nullptr) {
            sp<IBinder> binder = sm->getService(String16(servicename));
            if (binder != nullptr) {
                sAnalyticsService = interface_cast<IMediaAnalyticsService>(binder);
                sNotifier = new MediaMetricsDeathNotifier();
                binder->linkToDeath(sNotifier);
            } else {
                badness = "did not find service";
            }
        } else {
            badness = "No Service Manager access";
        }
        if (sAnalyticsService == nullptr) {
            if (sRemainingBindAttempts > 0) {
                sRemainingBindAttempts--;
            }
            ALOGD_IF(DEBUG_SERVICEACCESS, "%s: unable to bind to service %s: %s",
                    __func__, servicename, badness);
        }
    }
    return sAnalyticsService;
}

// merge the info from 'incoming' into this record.
// we finish with a union of this+incoming and special handling for collisions
bool MediaAnalyticsItem::merge(MediaAnalyticsItem *incoming) {

    // if I don't have key or session id, take them from incoming
    // 'this' should never be missing both of them...
    if (mKey.empty()) {
        mKey = incoming->mKey;
    }

    // for each attribute from 'incoming', resolve appropriately
    int nattr = incoming->mPropCount;
    for (int i = 0 ; i < nattr; i++ ) {
        Prop *iprop = &incoming->mProps[i];
        const char *p = iprop->mName;
        size_t len = strlen(p);

        // should ignore a zero length name...
        if (len == 0) {
            continue;
        }

        Prop *oprop = findProp(iprop->mName);

        if (oprop == NULL) {
            // no oprop, so we insert the new one
            oprop = allocateProp(p);
            if (oprop != NULL) {
                *oprop = *iprop;
            } else {
                ALOGW("dropped property '%s'", iprop->mName);
            }
        } else {
            *oprop = *iprop;
        }
    }

    // not sure when we'd return false...
    return true;
}

// a byte array; contents are
// overall length (uint32) including the length field itself
// encoding version (uint32)
// count of properties (uint32)
// N copies of:
//     property name as length(int16), bytes
//         the bytes WILL include the null terminator of the name
//     type (uint8 -- 1 byte)
//     size of value field (int16 -- 2 bytes)
//     value (size based on type)
//       int32, int64, double -- little endian 4/8/8 bytes respectively
//       cstring -- N bytes of value [WITH terminator]

enum { kInt32 = 0, kInt64, kDouble, kRate, kCString};

bool MediaAnalyticsItem::dumpAttributes(char **pbuffer, size_t *plength) {

    char *build = NULL;

    if (pbuffer == NULL || plength == NULL)
        return false;

    // consistency for the caller, who owns whatever comes back in this pointer.
    *pbuffer = NULL;

    // first, let's calculate sizes
    int32_t goal = 0;
    int32_t version = 0;

    goal += sizeof(uint32_t);   // overall length, including the length field
    goal += sizeof(uint32_t);   // encoding version
    goal += sizeof(uint32_t);   // # properties

    int32_t count = mPropCount;
    for (int i = 0 ; i < count; i++ ) {
        Prop *prop = &mProps[i];
        goal += sizeof(uint16_t);           // name length
        goal += strlen(prop->mName) + 1;    // string + null
        goal += sizeof(uint8_t);            // type
        goal += sizeof(uint16_t);           // size of value
        switch (prop->mType) {
            case MediaAnalyticsItem::kTypeInt32:
                    goal += sizeof(uint32_t);
                    break;
            case MediaAnalyticsItem::kTypeInt64:
                    goal += sizeof(uint64_t);
                    break;
            case MediaAnalyticsItem::kTypeDouble:
                    goal += sizeof(double);
                    break;
            case MediaAnalyticsItem::kTypeRate:
                    goal += 2 * sizeof(uint64_t);
                    break;
            case MediaAnalyticsItem::kTypeCString:
                    // length + actual string + null
                    goal += strlen(prop->u.CStringValue) + 1;
                    break;
            default:
                    ALOGE("found bad Prop type: %d, idx %d, name %s",
                          prop->mType, i, prop->mName);
                    return false;
        }
    }

    // now that we have a size... let's allocate and fill
    build = (char *)malloc(goal);
    if (build == NULL)
        return false;

    memset(build, 0, goal);

    char *filling = build;

#define _INSERT(val, size) \
    { memcpy(filling, &(val), (size)); filling += (size);}
#define _INSERTSTRING(val, size) \
    { memcpy(filling, (val), (size)); filling += (size);}

    _INSERT(goal, sizeof(int32_t));
    _INSERT(version, sizeof(int32_t));
    _INSERT(count, sizeof(int32_t));

    for (int i = 0 ; i < count; i++ ) {
        Prop *prop = &mProps[i];
        int16_t attrNameLen = strlen(prop->mName) + 1;
        _INSERT(attrNameLen, sizeof(int16_t));
        _INSERTSTRING(prop->mName, attrNameLen);    // termination included
        int8_t elemtype;
        int16_t elemsize;
        switch (prop->mType) {
            case MediaAnalyticsItem::kTypeInt32:
                {
                    elemtype = kInt32;
                    _INSERT(elemtype, sizeof(int8_t));
                    elemsize = sizeof(int32_t);
                    _INSERT(elemsize, sizeof(int16_t));

                    _INSERT(prop->u.int32Value, sizeof(int32_t));
                    break;
                }
            case MediaAnalyticsItem::kTypeInt64:
                {
                    elemtype = kInt64;
                    _INSERT(elemtype, sizeof(int8_t));
                    elemsize = sizeof(int64_t);
                    _INSERT(elemsize, sizeof(int16_t));

                    _INSERT(prop->u.int64Value, sizeof(int64_t));
                    break;
                }
            case MediaAnalyticsItem::kTypeDouble:
                {
                    elemtype = kDouble;
                    _INSERT(elemtype, sizeof(int8_t));
                    elemsize = sizeof(double);
                    _INSERT(elemsize, sizeof(int16_t));

                    _INSERT(prop->u.doubleValue, sizeof(double));
                    break;
                }
            case MediaAnalyticsItem::kTypeRate:
                {
                    elemtype = kRate;
                    _INSERT(elemtype, sizeof(int8_t));
                    elemsize = 2 * sizeof(uint64_t);
                    _INSERT(elemsize, sizeof(int16_t));

                    _INSERT(prop->u.rate.count, sizeof(uint64_t));
                    _INSERT(prop->u.rate.duration, sizeof(uint64_t));
                    break;
                }
            case MediaAnalyticsItem::kTypeCString:
                {
                    elemtype = kCString;
                    _INSERT(elemtype, sizeof(int8_t));
                    elemsize = strlen(prop->u.CStringValue) + 1;
                    _INSERT(elemsize, sizeof(int16_t));

                    _INSERTSTRING(prop->u.CStringValue, elemsize);
                    break;
                }
            default:
                    // error if can't encode; warning if can't decode
                    ALOGE("found bad Prop type: %d, idx %d, name %s",
                          prop->mType, i, prop->mName);
                    goto badness;
        }
    }

    if (build + goal != filling) {
        ALOGE("problems populating; wrote=%d planned=%d",
              (int)(filling-build), goal);
        goto badness;
    }

    *pbuffer = build;
    *plength = goal;

    return true;

  badness:
    free(build);
    return false;
}

void MediaAnalyticsItem::Prop::writeToParcel(Parcel *data) const
{
   data->writeCString(mName);
   data->writeInt32(mType);
   switch (mType) {
   case kTypeInt32:
       data->writeInt32(u.int32Value);
       break;
   case kTypeInt64:
       data->writeInt64(u.int64Value);
       break;
   case kTypeDouble:
       data->writeDouble(u.doubleValue);
       break;
   case kTypeRate:
       data->writeInt64(u.rate.count);
       data->writeInt64(u.rate.duration);
       break;
   case kTypeCString:
       data->writeCString(u.CStringValue);
       break;
   default:
       ALOGE("%s: found bad type: %d, name %s", __func__, mType, mName);
       break;
   }
}

void MediaAnalyticsItem::Prop::toString(char *buffer, size_t length) const {
    switch (mType) {
    case kTypeInt32:
        snprintf(buffer, length, "%s=%d:", mName, u.int32Value);
        break;
    case MediaAnalyticsItem::kTypeInt64:
        snprintf(buffer, length, "%s=%lld:", mName, (long long)u.int64Value);
        break;
    case MediaAnalyticsItem::kTypeDouble:
        snprintf(buffer, length, "%s=%e:", mName, u.doubleValue);
        break;
    case MediaAnalyticsItem::kTypeRate:
        snprintf(buffer, length, "%s=%lld/%lld:",
                mName, (long long)u.rate.count, (long long)u.rate.duration);
        break;
    case MediaAnalyticsItem::kTypeCString:
        // TODO sanitize string for ':' '='
        snprintf(buffer, length, "%s=%s:", mName, u.CStringValue);
        break;
    default:
        ALOGE("%s: bad item type: %d for %s", __func__, mType, mName);
        if (length > 0) buffer[0] = 0;
        break;
    }
}

} // namespace android

