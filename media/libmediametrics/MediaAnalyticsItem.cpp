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

#define LOG_TAG "MediaAnalyticsItem"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <mutex>
#include <set>

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


// find the proper entry in the list
size_t MediaAnalyticsItem::findPropIndex(const char *name) const
{
    size_t i = 0;
    for (; i < mPropCount; i++) {
        if (mProps[i].isNamed(name)) break;
    }
    return i;
}

MediaAnalyticsItem::Prop *MediaAnalyticsItem::findProp(const char *name) const {
    const size_t i = findPropIndex(name);
    if (i < mPropCount) {
        return &mProps[i];
    }
    return nullptr;
}

// consider this "find-or-allocate".
// caller validates type and uses clearPropValue() accordingly
MediaAnalyticsItem::Prop *MediaAnalyticsItem::allocateProp(const char *name) {
    const size_t i = findPropIndex(name);
    if (i < mPropCount) {
        return &mProps[i]; // already have it, return
    }

    Prop *prop = allocateProp(); // get a new prop
    if (prop == nullptr) return nullptr;
    prop->setName(name);
    return prop;
}

MediaAnalyticsItem::Prop *MediaAnalyticsItem::allocateProp() {
    if (mPropCount == mPropSize && growProps() == false) {
        ALOGE("%s: failed allocation for new properties", __func__);
        return nullptr;
    }
    return &mProps[mPropCount++];
}

// used within the summarizers; return whether property existed
bool MediaAnalyticsItem::removeProp(const char *name) {
    const size_t i = findPropIndex(name);
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
size_t MediaAnalyticsItem::filter(size_t n, const char *attrs[]) {
    size_t zapped = 0;
    for (size_t i = 0; i < n; ++i) {
        const char *name = attrs[i];
        size_t j = findPropIndex(name);
        if (j >= mPropCount) {
            // not there
            continue;
        } else if (j + 1 == mPropCount) {
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
size_t MediaAnalyticsItem::filterNot(size_t n, const char *attrs[]) {
    std::set<std::string> check(attrs, attrs + n);
    size_t zapped = 0;
    for (size_t j = 0; j < mPropCount;) {
        if (check.find(mProps[j].getName()) != check.end()) {
            ++j;
            continue;
        }
        if (j + 1 == mPropCount) {
            // last one, shorten
            zapped++;
            mProps[j].clear();
            mPropCount--;
            break;
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

status_t MediaAnalyticsItem::readFromParcel(const Parcel& data) {
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

status_t MediaAnalyticsItem::readFromParcel0(const Parcel& data) {
    const char *s = data.readCString();
    mKey = s == nullptr ? "" : s;
    int32_t pid, uid;
    status_t status = data.readInt32(&pid) ?: data.readInt32(&uid);
    if (status != NO_ERROR) return status;
    mPid = (pid_t)pid;
    mUid = (uid_t)uid;
    s = data.readCString();
    mPkgName = s == nullptr ? "" : s;
    int32_t count;
    int64_t version, timestamp;
    status = data.readInt64(&version) ?: data.readInt64(&timestamp) ?: data.readInt32(&count);
    if (status != NO_ERROR) return status;
    if (count < 0) return BAD_VALUE;
    mPkgVersionCode = version;
    mTimestamp = timestamp;
    for (int i = 0; i < count ; i++) {
        Prop *prop = allocateProp();
        status_t status = prop->readFromParcel(data);
        if (status != NO_ERROR) return status;
    }
    return NO_ERROR;
}

status_t MediaAnalyticsItem::writeToParcel(Parcel *data) const {
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

status_t MediaAnalyticsItem::writeToParcel0(Parcel *data) const {
    status_t status =
        data->writeCString(mKey.c_str())
        ?: data->writeInt32(mPid)
        ?: data->writeInt32(mUid)
        ?: data->writeCString(mPkgName.c_str())
        ?: data->writeInt64(mPkgVersionCode)
        ?: data->writeInt64(mTimestamp);
    if (status != NO_ERROR) return status;

    data->writeInt32((int32_t)mPropCount);
    for (size_t i = 0 ; i < mPropCount; ++i) {
        status = mProps[i].writeToParcel(data);
        if (status != NO_ERROR) return status;
    }
    return NO_ERROR;
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

namespace {

template <typename T>
status_t insert(const T& val, char **bufferpptr, char *bufferptrmax)
{
    const size_t size = sizeof(val);
    if (*bufferpptr + size > bufferptrmax) {
        ALOGE("%s: buffer exceeded with size %zu", __func__, size);
        return BAD_VALUE;
    }
    memcpy(*bufferpptr, &val, size);
    *bufferpptr += size;
    return NO_ERROR;
}

template <>
status_t insert(const char * const& val, char **bufferpptr, char *bufferptrmax)
{
    const size_t size = strlen(val) + 1;
    if (size > UINT16_MAX || *bufferpptr + size > bufferptrmax) {
        ALOGE("%s: buffer exceeded with size %zu", __func__, size);
        return BAD_VALUE;
    }
    memcpy(*bufferpptr, val, size);
    *bufferpptr += size;
    return NO_ERROR;
}

template <>
 __unused
status_t insert(char * const& val, char **bufferpptr, char *bufferptrmax)
{
    return insert((const char *)val, bufferpptr, bufferptrmax);
}

template <typename T>
status_t extract(T *val, const char **bufferpptr, const char *bufferptrmax)
{
    const size_t size = sizeof(*val);
    if (*bufferpptr + size > bufferptrmax) {
        ALOGE("%s: buffer exceeded with size %zu", __func__, size);
        return BAD_VALUE;
    }
    memcpy(val, *bufferpptr, size);
    *bufferpptr += size;
    return NO_ERROR;
}

template <>
status_t extract(char **val, const char **bufferpptr, const char *bufferptrmax)
{
    const char *ptr = *bufferpptr;
    while (*ptr != 0) {
        if (ptr >= bufferptrmax) {
            ALOGE("%s: buffer exceeded", __func__);
        }
        ++ptr;
    }
    const size_t size = (ptr - *bufferpptr) + 1;
    *val = (char *)malloc(size);
    memcpy(*val, *bufferpptr, size);
    *bufferpptr += size;
    return NO_ERROR;
}

} // namespace

status_t MediaAnalyticsItem::writeToByteString(char **pbuffer, size_t *plength) const
{
    if (pbuffer == nullptr || plength == nullptr)
        return BAD_VALUE;

    // get size
    const size_t keySizeZeroTerminated = strlen(mKey.c_str()) + 1;
    if (keySizeZeroTerminated > UINT16_MAX) {
        ALOGW("%s: key size %zu too large", __func__, keySizeZeroTerminated);
        return INVALID_OPERATION;
    }
    const uint16_t version = 0;
    const uint32_t header_len =
        sizeof(uint32_t)     // overall length
        + sizeof(header_len) // header length
        + sizeof(version)    // encoding version
        + sizeof(uint16_t)   // key length
        + keySizeZeroTerminated // key, zero terminated
        + sizeof(int32_t)    // pid
        + sizeof(int32_t)    // uid
        + sizeof(int64_t)    // timestamp
        ;

    uint32_t len = header_len
        + sizeof(uint32_t) // # properties
        ;
    for (size_t i = 0 ; i < mPropCount; ++i) {
        const size_t size = mProps[i].getByteStringSize();
        if (size > UINT_MAX - 1) {
            ALOGW("%s: prop %zu has size %zu", __func__, i, size);
            return INVALID_OPERATION;
        }
        len += size;
    }

    // TODO: consider package information and timestamp.

    // now that we have a size... let's allocate and fill
    char *build = (char *)calloc(1 /* nmemb */, len);
    if (build == nullptr) return NO_MEMORY;

    char *filling = build;
    char *buildmax = build + len;
    if (insert(len, &filling, buildmax) != NO_ERROR
            || insert(header_len, &filling, buildmax) != NO_ERROR
            || insert(version, &filling, buildmax) != NO_ERROR
            || insert((uint16_t)keySizeZeroTerminated, &filling, buildmax) != NO_ERROR
            || insert(mKey.c_str(), &filling, buildmax) != NO_ERROR
            || insert((int32_t)mPid, &filling, buildmax) != NO_ERROR
            || insert((int32_t)mUid, &filling, buildmax) != NO_ERROR
            || insert((int64_t)mTimestamp, &filling, buildmax) != NO_ERROR
            || insert((uint32_t)mPropCount, &filling, buildmax) != NO_ERROR) {
        ALOGD("%s:could not write header", __func__);
        free(build);
        return INVALID_OPERATION;
    }
    for (size_t i = 0 ; i < mPropCount; ++i) {
        if (mProps[i].writeToByteString(&filling, buildmax) != NO_ERROR) {
            free(build);
            ALOGD("%s:could not write prop %zu of %zu", __func__, i, mPropCount);
            return INVALID_OPERATION;
        }
    }

    if (filling != buildmax) {
        ALOGE("problems populating; wrote=%d planned=%d",
              (int)(filling - build), len);
        free(build);
        return INVALID_OPERATION;
    }
    *pbuffer = build;
    *plength = len;
    return NO_ERROR;
}

status_t MediaAnalyticsItem::readFromByteString(const char *bufferptr, size_t length)
{
    if (bufferptr == nullptr) return BAD_VALUE;

    const char *read = bufferptr;
    const char *readend = bufferptr + length;

    uint32_t len;
    uint32_t header_len;
    int16_t version;
    int16_t key_len;
    char *key = nullptr;
    int32_t pid;
    int32_t uid;
    int64_t timestamp;
    uint32_t propCount;
    if (extract(&len, &read, readend) != NO_ERROR
            || extract(&header_len, &read, readend) != NO_ERROR
            || extract(&version, &read, readend) != NO_ERROR
            || extract(&key_len, &read, readend) != NO_ERROR
            || extract(&key, &read, readend) != NO_ERROR
            || extract(&pid, &read, readend) != NO_ERROR
            || extract(&uid, &read, readend) != NO_ERROR
            || extract(&timestamp, &read, readend) != NO_ERROR
            || len > length
            || header_len > len) {
        free(key);
        ALOGD("%s: invalid header", __func__);
        return INVALID_OPERATION;
    }
    mKey = key;
    free(key);
    const size_t pos = read - bufferptr;
    if (pos > header_len) {
        ALOGD("%s: invalid header pos:%zu > header_len:%u",
                __func__, pos, header_len);
        return INVALID_OPERATION;
    } else if (pos < header_len) {
        ALOGD("%s: mismatched header pos:%zu < header_len:%u, advancing",
                __func__, pos, header_len);
        read += (header_len - pos);
    }
    if (extract(&propCount, &read, readend) != NO_ERROR) {
        ALOGD("%s: cannot read prop count", __func__);
        return INVALID_OPERATION;
    }
    mPid = pid;
    mUid = uid;
    mTimestamp = timestamp;
    for (size_t i = 0; i < propCount; ++i) {
        Prop *prop = allocateProp();
        if (prop->readFromByteString(&read, readend) != NO_ERROR) {
            ALOGD("%s: cannot read prop %zu", __func__, i);
            return INVALID_OPERATION;
        }
    }
    return NO_ERROR;
}

status_t MediaAnalyticsItem::Prop::writeToParcel(Parcel *data) const
{
   switch (mType) {
   case kTypeInt32:
       return data->writeCString(mName)
               ?: data->writeInt32(mType)
               ?: data->writeInt32(u.int32Value);
   case kTypeInt64:
       return data->writeCString(mName)
               ?: data->writeInt32(mType)
               ?: data->writeInt64(u.int64Value);
   case kTypeDouble:
       return data->writeCString(mName)
               ?: data->writeInt32(mType)
               ?: data->writeDouble(u.doubleValue);
   case kTypeRate:
       return data->writeCString(mName)
               ?: data->writeInt32(mType)
               ?: data->writeInt64(u.rate.first)
               ?: data->writeInt64(u.rate.second);
   case kTypeCString:
       return data->writeCString(mName)
               ?: data->writeInt32(mType)
               ?: data->writeCString(u.CStringValue);
   default:
       ALOGE("%s: found bad type: %d, name %s", __func__, mType, mName);
       return BAD_VALUE;
   }
}

status_t MediaAnalyticsItem::Prop::readFromParcel(const Parcel& data)
{
    const char *key = data.readCString();
    if (key == nullptr) return BAD_VALUE;
    int32_t type;
    status_t status = data.readInt32(&type);
    if (status != NO_ERROR) return status;
    switch (type) {
    case kTypeInt32:
        status = data.readInt32(&u.int32Value);
        break;
    case kTypeInt64:
        status = data.readInt64(&u.int64Value);
        break;
    case kTypeDouble:
        status = data.readDouble(&u.doubleValue);
        break;
    case kTypeCString: {
        const char *s = data.readCString();
        if (s == nullptr) return BAD_VALUE;
        set(s);
        break;
        }
    case kTypeRate: {
        std::pair<int64_t, int64_t> rate;
        status = data.readInt64(&rate.first)
                ?: data.readInt64(&rate.second);
        if (status == NO_ERROR) {
            set(rate);
        }
        break;
        }
    default:
        ALOGE("%s: reading bad item type: %d", __func__, mType);
        return BAD_VALUE;
    }
    if (status == NO_ERROR) {
        setName(key);
        mType = (Type)type;
    }
    return status;
}

void MediaAnalyticsItem::Prop::toString(char *buffer, size_t length) const
{
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
                mName, (long long)u.rate.first, (long long)u.rate.second);
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

size_t MediaAnalyticsItem::Prop::getByteStringSize() const
{
    const size_t header =
        sizeof(uint16_t)      // length
        + sizeof(uint8_t)     // type
        + strlen(mName) + 1;  // mName + 0 termination
    size_t payload = 0;
    switch (mType) {
    case MediaAnalyticsItem::kTypeInt32:
        payload = sizeof(u.int32Value);
        break;
    case MediaAnalyticsItem::kTypeInt64:
        payload = sizeof(u.int64Value);
        break;
    case MediaAnalyticsItem::kTypeDouble:
        payload = sizeof(u.doubleValue);
        break;
    case MediaAnalyticsItem::kTypeRate:
        payload = sizeof(u.rate.first) + sizeof(u.rate.second);
        break;
    case MediaAnalyticsItem::kTypeCString:
        payload = strlen(u.CStringValue) + 1;
        break;
    default:
        ALOGE("%s: found bad prop type: %d, name %s",
                __func__, mType, mName); // no payload computed
        break;
    }
    return header + payload;
}

// TODO: fold into a template later.
status_t MediaAnalyticsItem::writeToByteString(
        const char *name, int32_t value, char **bufferpptr, char *bufferptrmax)
{
    const size_t len = 2 + 1 + strlen(name) + 1 + sizeof(value);
    if (len > UINT16_MAX) return BAD_VALUE;
    return insert((uint16_t)len, bufferpptr, bufferptrmax)
            ?: insert((uint8_t)kTypeInt32, bufferpptr, bufferptrmax)
            ?: insert(name, bufferpptr, bufferptrmax)
            ?: insert(value, bufferpptr, bufferptrmax);
}

status_t MediaAnalyticsItem::writeToByteString(
        const char *name, int64_t value, char **bufferpptr, char *bufferptrmax)
{
    const size_t len = 2 + 1 + strlen(name) + 1 + sizeof(value);
    if (len > UINT16_MAX) return BAD_VALUE;
    return insert((uint16_t)len, bufferpptr, bufferptrmax)
            ?: insert((uint8_t)kTypeInt64, bufferpptr, bufferptrmax)
            ?: insert(name, bufferpptr, bufferptrmax)
            ?: insert(value, bufferpptr, bufferptrmax);
}

status_t MediaAnalyticsItem::writeToByteString(
        const char *name, double value, char **bufferpptr, char *bufferptrmax)
{
    const size_t len = 2 + 1 + strlen(name) + 1 + sizeof(value);
    if (len > UINT16_MAX) return BAD_VALUE;
    return insert((uint16_t)len, bufferpptr, bufferptrmax)
            ?: insert((uint8_t)kTypeDouble, bufferpptr, bufferptrmax)
            ?: insert(name, bufferpptr, bufferptrmax)
            ?: insert(value, bufferpptr, bufferptrmax);
}

status_t MediaAnalyticsItem::writeToByteString(
        const char *name, const std::pair<int64_t, int64_t> &value, char **bufferpptr, char *bufferptrmax)
{
    const size_t len = 2 + 1 + strlen(name) + 1 + 8 + 8;
    if (len > UINT16_MAX) return BAD_VALUE;
    return insert((uint16_t)len, bufferpptr, bufferptrmax)
            ?: insert((uint8_t)kTypeRate, bufferpptr, bufferptrmax)
            ?: insert(name, bufferpptr, bufferptrmax)
            ?: insert(value.first, bufferpptr, bufferptrmax)
            ?: insert(value.second, bufferpptr, bufferptrmax);
}

status_t MediaAnalyticsItem::writeToByteString(
        const char *name, char * const &value, char **bufferpptr, char *bufferptrmax)
{
    const size_t len = 2 + 1 + strlen(name) + 1 + strlen(value) + 1;
    if (len > UINT16_MAX) return BAD_VALUE;
    return insert((uint16_t)len, bufferpptr, bufferptrmax)
            ?: insert((uint8_t)kTypeCString, bufferpptr, bufferptrmax)
            ?: insert(name, bufferpptr, bufferptrmax)
            ?: insert(value, bufferpptr, bufferptrmax);
}

status_t MediaAnalyticsItem::writeToByteString(
        const char *name, const none_t &, char **bufferpptr, char *bufferptrmax)
{
    const size_t len = 2 + 1 + strlen(name) + 1;
    if (len > UINT16_MAX) return BAD_VALUE;
    return insert((uint16_t)len, bufferpptr, bufferptrmax)
            ?: insert((uint8_t)kTypeCString, bufferpptr, bufferptrmax)
            ?: insert(name, bufferpptr, bufferptrmax);
}

status_t MediaAnalyticsItem::Prop::writeToByteString(
        char **bufferpptr, char *bufferptrmax) const
{
    switch (mType) {
    case kTypeInt32:
        return MediaAnalyticsItem::writeToByteString(mName, u.int32Value, bufferpptr, bufferptrmax);
    case kTypeInt64:
        return MediaAnalyticsItem::writeToByteString(mName, u.int64Value, bufferpptr, bufferptrmax);
    case kTypeDouble:
        return MediaAnalyticsItem::writeToByteString(mName, u.doubleValue, bufferpptr, bufferptrmax);
    case kTypeRate:
        return MediaAnalyticsItem::writeToByteString(mName, u.rate, bufferpptr, bufferptrmax);
    case kTypeCString:
        return MediaAnalyticsItem::writeToByteString(mName, u.CStringValue, bufferpptr, bufferptrmax);
    case kTypeNone:
        return MediaAnalyticsItem::writeToByteString(mName, none_t{}, bufferpptr, bufferptrmax);
    default:
        ALOGE("%s: found bad prop type: %d, name %s",
                __func__, mType, mName);  // no payload sent
        return BAD_VALUE;
    }
}

status_t MediaAnalyticsItem::Prop::readFromByteString(
        const char **bufferpptr, const char *bufferptrmax)
{
    uint16_t len;
    char *name;
    uint8_t type;
    status_t status = extract(&len, bufferpptr, bufferptrmax)
            ?: extract(&type, bufferpptr, bufferptrmax)
            ?: extract(&name, bufferpptr, bufferptrmax);
    if (status != NO_ERROR) return status;
    if (mName != nullptr) {
        free(mName);
    }
    mName = name;
    if (mType == kTypeCString) {
        free(u.CStringValue);
        u.CStringValue = nullptr;
    }
    mType = (Type)type;
    switch (mType) {
    case kTypeInt32:
        return extract(&u.int32Value, bufferpptr, bufferptrmax);
    case kTypeInt64:
        return extract(&u.int64Value, bufferpptr, bufferptrmax);
    case kTypeDouble:
        return extract(&u.doubleValue, bufferpptr, bufferptrmax);
    case kTypeRate:
        return extract(&u.rate.first, bufferpptr, bufferptrmax)
                ?: extract(&u.rate.second, bufferpptr, bufferptrmax);
    case kTypeCString:
        status = extract(&u.CStringValue, bufferpptr, bufferptrmax);
        if (status != NO_ERROR) mType = kTypeNone;
        return status;
    case kTypeNone:
        return NO_ERROR;
    default:
        mType = kTypeNone;
        ALOGE("%s: found bad prop type: %d, name %s",
                __func__, mType, mName);  // no payload sent
        return BAD_VALUE;
    }
}

} // namespace android
