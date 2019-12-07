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

#ifndef ANDROID_MEDIA_MEDIAMETRICSITEM_H
#define ANDROID_MEDIA_MEDIAMETRICSITEM_H

#include "MediaMetrics.h"

#include <algorithm>
#include <map>
#include <string>
#include <sys/types.h>

#include <cutils/properties.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/RefBase.h>
#include <utils/StrongPointer.h>
#include <utils/Timers.h>

namespace android {

class IMediaMetricsService;
class Parcel;

/*
 * MediaMetrics Item
 *
 * Byte string format.
 *
 * For Java
 *  int64 corresponds to long
 *  int32, uint32 corresponds to int
 *  uint16 corresponds to char
 *  uint8, int8 corresponds to byte
 *
 * Hence uint8 and uint32 values are limited to INT8_MAX and INT32_MAX.
 *
 * Physical layout of integers and doubles within the MediaMetrics byte string
 * is in Native / host order, which is nearly always little endian.
 *
 * -- begin of item
 * -- begin of header
 * (uint32) item size: including the item size field
 * (uint32) header size, including the item size and header size fields.
 * (uint16) version: exactly 0
 * (uint16) key size, that is key strlen + 1 for zero termination.
 * (int8)+ key string which is 0 terminated
 * (int32) pid
 * (int32) uid
 * (int64) timestamp
 * -- end of header
 * -- begin body
 * (uint32) number of properties
 * -- repeat for number of properties
 *     (uint16) property size, including property size field itself
 *     (uint8) type of property
 *     (int8)+ key string, including 0 termination
 *      based on type of property (given above), one of:
 *       (int32)
 *       (int64)
 *       (double)
 *       (int8)+ for cstring, including 0 termination
 *       (int64, int64) for rate
 * -- end body
 * -- end of item
 */

namespace mediametrics {

// Type must match MediaMetrics.java
enum Type {
    kTypeNone = 0,
    kTypeInt32 = 1,
    kTypeInt64 = 2,
    kTypeDouble = 3,
    kTypeCString = 4,
    kTypeRate = 5,
};

template<size_t N>
static inline bool startsWith(const std::string &s, const char (&comp)[N]) {
    return !strncmp(s.c_str(), comp, N-1);
}

/**
 * Media Metrics BaseItem
 *
 * A base class which contains utility static functions to write to a byte stream
 * and access the Media Metrics service.
 */

class BaseItem {
    friend class MediaMetricsDeathNotifier; // for dropInstance
    // enabled 1, disabled 0
public:
    // are we collecting metrics data
    static bool isEnabled();
    static sp<IMediaMetricsService> getService();

protected:
    static constexpr const char * const EnabledProperty = "media.metrics.enabled";
    static constexpr const char * const EnabledPropertyPersist = "persist.media.metrics.enabled";
    static const int EnabledProperty_default = 1;

    // let's reuse a binder connection
    static sp<IMediaMetricsService> sMediaMetricsService;

    static void dropInstance();
    static bool submitBuffer(const char *buffer, size_t len);

    static status_t writeToByteString(
            const char *name, int32_t value, char **bufferpptr, char *bufferptrmax);
    static status_t writeToByteString(
            const char *name, int64_t value, char **bufferpptr, char *bufferptrmax);
    static status_t writeToByteString(
            const char *name, double value, char **bufferpptr, char *bufferptrmax);
    static status_t writeToByteString(
            const char *name, const std::pair<int64_t, int64_t> &value,
            char **bufferpptr, char *bufferptrmax);
    static status_t writeToByteString(
            const char *name, char * const &value, char **bufferpptr, char *bufferptrmax);
    static status_t writeToByteString(
            const char *name, const char * const &value, char **bufferpptr, char *bufferptrmax);
    struct none_t {}; // for mediametrics::kTypeNone
    static status_t writeToByteString(
            const char *name, const none_t &, char **bufferpptr, char *bufferptrmax);

    template<typename T>
    static status_t sizeOfByteString(const char *name, const T& value) {
        return 2 + 1 + strlen(name) + 1 + sizeof(value);
    }
    template<> // static
    status_t sizeOfByteString(const char *name, char * const &value) {
        return 2 + 1 + strlen(name) + 1 + strlen(value) + 1;
    }
    template<> // static
    status_t sizeOfByteString(const char *name, const char * const &value) {
        return 2 + 1 + strlen(name) + 1 + strlen(value) + 1;
    }
    template<> // static
    status_t sizeOfByteString(const char *name, const none_t &) {
         return 2 + 1 + strlen(name) + 1;
    }
};

/**
 * Media Metrics BufferedItem
 *
 * A base class which represents a put-only Media Metrics item, storing
 * the Media Metrics data in a buffer with begin and end pointers.
 *
 * If a property key is entered twice, it will be stored in the buffer twice,
 * and (implementation defined) the last value for that key will be used
 * by the Media Metrics service.
 *
 * For realloc, a baseRealloc pointer must be passed in either explicitly
 * or implicitly in the constructor. This will be updated with the value used on realloc.
 */
class BufferedItem : public BaseItem {
public:
    static inline constexpr uint16_t kVersion = 0;

    virtual ~BufferedItem() = default;
    BufferedItem(const BufferedItem&) = delete;
    BufferedItem& operator=(const BufferedItem&) = delete;

    BufferedItem(const std::string key, char *begin, char *end)
        : BufferedItem(key.c_str(), begin, end) { }

    BufferedItem(const char *key, char *begin, char *end)
        : BufferedItem(key, begin, end, nullptr) { }

    BufferedItem(const char *key, char **begin, char *end)
        : BufferedItem(key, *begin, end, begin) { }

    BufferedItem(const char *key, char *begin, char *end, char **baseRealloc)
        : mBegin(begin)
        , mEnd(end)
        , mBaseRealloc(baseRealloc)
    {
        init(key);
    }

    template<typename T>
    BufferedItem &set(const char *key, const T& value) {
        reallocFor(sizeOfByteString(key, value));
        if (mStatus == NO_ERROR) {
            mStatus = BaseItem::writeToByteString(key, value, &mBptr, mEnd);
            ++mPropCount;
        }
        return *this;
    }

    template<typename T>
    BufferedItem &set(const std::string& key, const T& value) {
        return set(key.c_str(), value);
    }

    BufferedItem &setPid(pid_t pid) {
        if (mStatus == NO_ERROR) {
            copyTo(mBegin + mHeaderLen - 16, (int32_t)pid);
        }
        return *this;
    }

    BufferedItem &setUid(uid_t uid) {
        if (mStatus == NO_ERROR) {
            copyTo(mBegin + mHeaderLen - 12, (int32_t)uid);
        }
        return *this;
    }

    BufferedItem &setTimestamp(nsecs_t timestamp) {
        if (mStatus == NO_ERROR) {
            copyTo(mBegin + mHeaderLen - 8, (int64_t)timestamp);
        }
        return *this;
    }

    bool record() {
        return updateHeader()
                && BaseItem::submitBuffer(getBuffer(), getLength());
    }

    bool isValid () const {
        return mStatus == NO_ERROR;
    }

    char *getBuffer() const { return mBegin; }
    size_t getLength() const { return mBptr - mBegin; }
    size_t getRemaining() const { return mEnd - mBptr; }
    size_t getCapacity() const { return mEnd - mBegin; }

    bool updateHeader() {
        if (mStatus != NO_ERROR) return false;
        copyTo(mBegin + 0, (uint32_t)getLength());
        copyTo(mBegin + 4, (uint32_t)mHeaderLen);
        copyTo(mBegin + mHeaderLen, (uint32_t)mPropCount);
        return true;
    }

protected:
    BufferedItem() = default;

    void reallocFor(size_t required) {
        if (mStatus != NO_ERROR) return;
        const size_t remaining = getRemaining();
        if (required <= remaining) return;
        if (mBaseRealloc == nullptr) {
            mStatus = NO_MEMORY;
            return;
        }

        const size_t current = getLength();
        size_t minimum = current + required;
        if (minimum > SSIZE_MAX >> 1) {
            mStatus = NO_MEMORY;
            return;
        }
        minimum <<= 1;
        void *newptr = realloc(*mBaseRealloc, minimum);
        if (newptr == nullptr) {
            mStatus = NO_MEMORY;
            return;
        }
        if (newptr != *mBaseRealloc) {
            // ALOGD("base changed! current:%zu new size %zu", current, minimum);
            if (*mBaseRealloc == nullptr) {
                memcpy(newptr, mBegin, current);
            }
            mBegin = (char *)newptr;
            *mBaseRealloc = mBegin;
            mEnd = mBegin + minimum;
            mBptr = mBegin + current;
        } else {
            // ALOGD("base kept! current:%zu new size %zu", current, minimum);
            mEnd = mBegin + minimum;
        }
    }
    template<typename T>
    void copyTo(char *ptr, const T& value) {
        memcpy(ptr, &value, sizeof(value));
    }

    void init(const char *key) {
        mBptr = mBegin;
        const size_t keylen = strlen(key) + 1;
        mHeaderLen = 4 + 4 + 2 + 2 + keylen + 4 + 4 + 8;
        reallocFor(mHeaderLen);
        if (mStatus != NO_ERROR) return;
        mBptr = mBegin + mHeaderLen + 4; // this includes propcount.

        if (mEnd < mBptr || keylen > UINT16_MAX) {
           mStatus = NO_MEMORY;
           mBptr = mEnd;
           return;
        }
        copyTo(mBegin + 8, kVersion);
        copyTo(mBegin + 10, (uint16_t)keylen);
        strcpy(mBegin + 12, key);

        // initialize some parameters (that could be overridden)
        setPid(-1);
        setUid(-1);
        setTimestamp(0);
    }

    char *mBegin = nullptr;
    char *mEnd = nullptr;
    char **mBaseRealloc = nullptr;  // set to an address if realloc should be done.
                                    // upon return, that pointer is updated with
                                    // whatever needs to be freed.
    char *mBptr = nullptr;
    status_t mStatus = NO_ERROR;
    uint32_t mPropCount = 0;
    uint32_t mHeaderLen = 0;
};

/**
 * MediaMetrics LogItem is a stack allocated mediametrics item used for
 * fast logging.  It falls over to a malloc if needed.
 *
 * This is templated with a buffer size to allocate on the stack.
 */
template <size_t N = 4096>
class LogItem : public BufferedItem {
public:
    explicit LogItem(const std::string key) : LogItem(key.c_str()) { }

    // Since this class will not be defined before the base class, we initialize variables
    // in our own order.
    explicit LogItem(const char *key) {
         mBegin = mBuffer;
         mEnd = mBuffer + N;
         mBaseRealloc = &mReallocPtr;
         init(key);
    }

    ~LogItem() override {
        if (mReallocPtr != nullptr) { // do the check before calling free to avoid overhead.
            free(mReallocPtr);
        }
    }

private:
    char *mReallocPtr = nullptr;  // set non-null by base class if realloc happened.
    char mBuffer[N];
};


/**
 * Media Metrics Item
 *
 * A mutable item representing an event or record that will be
 * logged with the Media Metrics service.  For client logging, one should
 * use the mediametrics::Item.
 *
 * The Item is designed for the service as it has getters.
 */
class Item : public mediametrics::BaseItem {
public:

        enum {
            PROTO_V0 = 0,
            PROTO_FIRST = PROTO_V0,
            PROTO_V1 = 1,
            PROTO_LAST = PROTO_V1,
        };

    // T must be convertible to mKey
    template <typename T>
    explicit Item(T key)
        : mKey(key) { }
    Item() = default;

    bool operator==(const Item& other) const {
        if (mPid != other.mPid
            || mUid != other.mUid
            || mPkgName != other.mPkgName
            || mPkgVersionCode != other.mPkgVersionCode
            || mKey != other.mKey
            || mTimestamp != other.mTimestamp
            || mProps != other.mProps) return false;
         return true;
    }
    bool operator!=(const Item& other) const {
        return !(*this == other);
    }

    template <typename T>
    static Item* create(T key) {
        return new Item(key);
    }
    static Item* create() {
        return new Item();
    }

        static Item* convert(mediametrics_handle_t);
        static mediametrics_handle_t convert(Item *);

        // access functions for the class
        ~Item();

    void clear() {
        mPid = -1;
        mUid = -1;
        mPkgName.clear();
        mPkgVersionCode = 0;
        mTimestamp = 0;
        mKey.clear();
        mProps.clear();
    }

    Item *dup() const { return new Item(*this); }

    Item &setKey(const char *key) {
        mKey = key;
        return *this;
    }
    const std::string& getKey() const { return mKey; }

    // # of properties in the record
    size_t count() const { return mProps.size(); }

    template<typename S, typename T>
    Item &set(S key, T value) {
        findOrAllocateProp(key).set(value);
        return *this;
    }

    // set values appropriately
    Item &setInt32(const char *key, int32_t value) {
        return set(key, value);
    }
    Item &setInt64(const char *key, int64_t value) {
        return set(key, value);
    }
    Item &setDouble(const char *key, double value) {
        return set(key, value);
    }
    Item &setRate(const char *key, int64_t count, int64_t duration) {
        return set(key, std::make_pair(count, duration));
    }
    Item &setCString(const char *key, const char *value) {
        return set(key, value);
    }

    // fused get/add/set; if attr wasn't there, it's a simple set.
    // type-mismatch counts as "wasn't there".
    template<typename S, typename T>
    Item &add(S key, T value) {
        findOrAllocateProp(key).add(value);
        return *this;
    }

    Item &addInt32(const char *key, int32_t value) {
        return add(key, value);
    }
    Item &addInt64(const char *key, int64_t value) {
        return add(key, value);
    }
    Item &addDouble(const char *key, double value) {
        return add(key, value);
    }
    Item &addRate(const char *key, int64_t count, int64_t duration) {
        return add(key, std::make_pair(count, duration));
    }

    // find & extract values
    // return indicates whether attr exists (and thus value filled in)
    // NULL parameter value suppresses storage of value.
    template<typename S, typename T>
    bool get(S key, T *value) const {
        const Prop *prop = findProp(key);
        return prop != nullptr && prop->get(value);
    }

    bool getInt32(const char *key, int32_t *value) const {
        return get(key, value);
    }
    bool getInt64(const char *key, int64_t *value) const {
        return get(key, value);
    }
    bool getDouble(const char *key, double *value) const {
        return get(key, value);
    }
    bool getRate(const char *key, int64_t *count, int64_t *duration, double *rate) const {
        std::pair<int64_t, int64_t> value;
        if (!get(key, &value)) return false;
        if (count != nullptr) *count = value.first;
        if (duration != nullptr) *duration = value.second;
        if (rate != nullptr) {
            if (value.second != 0) {
                *rate = (double)value.first / value.second;  // TODO: isn't INF OK?
            } else {
                *rate = 0.;
            }
        }
        return true;
    }
    // Caller owns the returned string
    bool getCString(const char *key, char **value) const {
        const char *cs;
        if (get(key, &cs)) {
            *value = cs != nullptr ? strdup(cs) : nullptr;
            return true;
        }
        return false;
    }
    bool getString(const char *key, std::string *value) const {
        return get(key, value);
    }

        // Deliver the item to MediaMetrics
        bool selfrecord();

    // remove indicated attributes and their values
    // filterNot() could also be called keepOnly()
    // return value is # attributes removed
    // XXX: perhaps 'remove' instead of 'filter'
    // XXX: filterNot would become 'keep'
    size_t filter(size_t count, const char *attrs[]);
    size_t filterNot(size_t count, const char *attrs[]);
    size_t filter(const char *attr) { return filter(1, &attr); }

        // below here are used on server side or to talk to server
        // clients need not worry about these.

        // timestamp, pid, and uid only used on server side
        // timestamp is in 'nanoseconds, unix time'
        Item &setTimestamp(nsecs_t);
        nsecs_t getTimestamp() const;

        Item &setPid(pid_t);
        pid_t getPid() const;

        Item &setUid(uid_t);
        uid_t getUid() const;

        Item &setPkgName(const std::string &pkgName);
        std::string getPkgName() const { return mPkgName; }

        Item &setPkgVersionCode(int64_t);
        int64_t getPkgVersionCode() const;

    // our serialization code for binder calls
    status_t writeToParcel(Parcel *) const;
    status_t readFromParcel(const Parcel&);

    status_t writeToByteString(char **bufferptr, size_t *length) const;
    status_t readFromByteString(const char *bufferptr, size_t length);


        std::string toString() const;
        std::string toString(int version) const;
        const char *toCString();
        const char *toCString(int version);

private:
    // handle Parcel version 0
    int32_t writeToParcel0(Parcel *) const;
    int32_t readFromParcel0(const Parcel&);

    // checks equality even with nullptr.
    static bool stringEquals(const char *a, const char *b) {
        if (a == nullptr) {
            return b == nullptr;
        } else {
            return b != nullptr && strcmp(a, b) == 0;
        }
    }

public:
    class Prop {
    public:
        Prop() = default;
        Prop(const Prop& other) {
           *this = other;
        }
        Prop& operator=(const Prop& other) {
            mName = other.mName;
            mType = other.mType;
            switch (mType) {
            case mediametrics::kTypeInt32:
                u.int32Value = other.u.int32Value;
                break;
            case mediametrics::kTypeInt64:
                u.int64Value = other.u.int64Value;
                break;
            case mediametrics::kTypeDouble:
                u.doubleValue = other.u.doubleValue;
                break;
            case mediametrics::kTypeCString:
                u.CStringValue = strdup(other.u.CStringValue);
                break;
            case mediametrics::kTypeRate:
                u.rate = other.u.rate;
                break;
            case mediametrics::kTypeNone:
                break;
            default:
                // abort?
                break;
            }
            return *this;
        }
        Prop(Prop&& other) {
            *this = std::move(other);
        }
        Prop& operator=(Prop&& other) {
            mName = std::move(other.mName);
            mType = other.mType;
            switch (mType) {
            case mediametrics::kTypeInt32:
                u.int32Value = other.u.int32Value;
                break;
            case mediametrics::kTypeInt64:
                u.int64Value = other.u.int64Value;
                break;
            case mediametrics::kTypeDouble:
                u.doubleValue = other.u.doubleValue;
                break;
            case mediametrics::kTypeCString:
                u.CStringValue = other.u.CStringValue;
                break;
            case mediametrics::kTypeRate:
                u.rate = other.u.rate;
                break;
            case mediametrics::kTypeNone:
                break;
            default:
                // abort?
                break;
            }
            other.mType = mediametrics::kTypeNone;
            return *this;
        }

        bool operator==(const Prop& other) const {
            if (mName != other.mName
                    || mType != other.mType) return false;
            switch (mType) {
            case mediametrics::kTypeInt32:
                return u.int32Value == other.u.int32Value;
            case mediametrics::kTypeInt64:
                return u.int64Value == other.u.int64Value;
            case mediametrics::kTypeDouble:
                return u.doubleValue == other.u.doubleValue;
            case mediametrics::kTypeCString:
                return stringEquals(u.CStringValue, other.u.CStringValue);
            case mediametrics::kTypeRate:
                return u.rate == other.u.rate;
            case mediametrics::kTypeNone:
            default:
                return true;
            }
        }
        bool operator!=(const Prop& other) const {
            return !(*this == other);
        }

        void clear() {
            mName.clear();
            clearValue();
        }
        void clearValue() {
            if (mType == mediametrics::kTypeCString) {
                free(u.CStringValue);
                u.CStringValue = nullptr;
            }
            mType = mediametrics::kTypeNone;
        }

        mediametrics::Type getType() const {
            return mType;
        }

        const char *getName() const {
            return mName.c_str();
        }

        void swap(Prop& other) {
            std::swap(mName, other.mName);
            std::swap(mType, other.mType);
            std::swap(u, other.u);
        }

        void setName(const char *name) {
            mName = name;
        }

        bool isNamed(const char *name) const {
            return mName == name;
        }

        template <typename T> void visit(T f) const {
            switch (mType) {
            case mediametrics::kTypeInt32:
                f(u.int32Value);
                return;
            case mediametrics::kTypeInt64:
                f(u.int64Value);
                return;
            case mediametrics::kTypeDouble:
                f(u.doubleValue);
                return;
            case mediametrics::kTypeRate:
                f(u.rate);
                return;
            case mediametrics::kTypeCString:
                f(u.CStringValue);
                return;
            default:
                return;
            }
        }

        template <typename T> bool get(T *value) const = delete;
        template <>
        bool get(int32_t *value) const {
           if (mType != mediametrics::kTypeInt32) return false;
           if (value != nullptr) *value = u.int32Value;
           return true;
        }
        template <>
        bool get(int64_t *value) const {
           if (mType != mediametrics::kTypeInt64) return false;
           if (value != nullptr) *value = u.int64Value;
           return true;
        }
        template <>
        bool get(double *value) const {
           if (mType != mediametrics::kTypeDouble) return false;
           if (value != nullptr) *value = u.doubleValue;
           return true;
        }
        template <>
        bool get(const char** value) const {
            if (mType != mediametrics::kTypeCString) return false;
            if (value != nullptr) *value = u.CStringValue;
            return true;
        }
        template <>
        bool get(std::string* value) const {
            if (mType != mediametrics::kTypeCString) return false;
            if (value != nullptr) *value = u.CStringValue;
            return true;
        }
        template <>
        bool get(std::pair<int64_t, int64_t> *value) const {
           if (mType != mediametrics::kTypeRate) return false;
           if (value != nullptr) {
               *value = u.rate;
           }
           return true;
        }

        template <typename T> void set(const T& value) = delete;
        template <>
        void set(const int32_t& value) {
            mType = mediametrics::kTypeInt32;
            u.int32Value = value;
        }
        template <>
        void set(const int64_t& value) {
            mType = mediametrics::kTypeInt64;
            u.int64Value = value;
        }
        template <>
        void set(const double& value) {
            mType = mediametrics::kTypeDouble;
            u.doubleValue = value;
        }
        template <>
        void set(const char* const& value) {
            if (mType == mediametrics::kTypeCString) {
                free(u.CStringValue);
            } else {
                mType = mediametrics::kTypeCString;
            }
            if (value == nullptr) {
                u.CStringValue = nullptr;
            } else {
                size_t len = strlen(value);
                if (len > UINT16_MAX - 1) {
                    len = UINT16_MAX - 1;
                }
                u.CStringValue = (char *)malloc(len + 1);
                strncpy(u.CStringValue, value, len);
                u.CStringValue[len] = 0;
            }
        }
        template <>
        void set(const std::pair<int64_t, int64_t> &value) {
            mType = mediametrics::kTypeRate;
            u.rate = {value.first, value.second};
        }

        template <typename T> void add(const T& value) = delete;
        template <>
        void add(const int32_t& value) {
            if (mType == mediametrics::kTypeInt32) {
                u.int32Value += value;
            } else {
                mType = mediametrics::kTypeInt32;
                u.int32Value = value;
            }
        }
        template <>
        void add(const int64_t& value) {
            if (mType == mediametrics::kTypeInt64) {
                u.int64Value += value;
            } else {
                mType = mediametrics::kTypeInt64;
                u.int64Value = value;
            }
        }
        template <>
        void add(const double& value) {
            if (mType == mediametrics::kTypeDouble) {
                u.doubleValue += value;
            } else {
                mType = mediametrics::kTypeDouble;
                u.doubleValue = value;
            }
        }
        template <>
        void add(const std::pair<int64_t, int64_t>& value) {
            if (mType == mediametrics::kTypeRate) {
                u.rate.first += value.first;
                u.rate.second += value.second;
            } else {
                mType = mediametrics::kTypeRate;
                u.rate = value;
            }
        }

        status_t writeToParcel(Parcel *data) const;
        status_t readFromParcel(const Parcel& data);
        void toString(char *buffer, size_t length) const;
        size_t getByteStringSize() const;
        status_t writeToByteString(char **bufferpptr, char *bufferptrmax) const;
        status_t readFromByteString(const char **bufferpptr, const char *bufferptrmax);

    // TODO: consider converting to std::variant
    private:
        std::string mName;
        mediametrics::Type mType = mediametrics::kTypeNone;
        union u__ {
            u__() { zero(); }
            u__(u__ &&other) {
                *this = std::move(other);
            }
            u__& operator=(u__ &&other) {
                memcpy(this, &other, sizeof(*this));
                other.zero();
                return *this;
            }
            void zero() { memset(this, 0, sizeof(*this)); }

            int32_t int32Value;
            int64_t int64Value;
            double doubleValue;
            char *CStringValue;
            std::pair<int64_t, int64_t> rate;
        } u;
    };

    // Iteration of props within item
    class iterator {
    public:
        iterator(const std::map<std::string, Prop>::const_iterator &_it) : it(_it) { }
        iterator &operator++() {
            ++it;
            return *this;
        }
        bool operator!=(iterator &other) const {
            return it != other.it;
        }
        const Prop &operator*() const {
            return it->second;
        }

    private:
        std::map<std::string, Prop>::const_iterator it;
    };

    iterator begin() const {
        return iterator(mProps.cbegin());
    }

    iterator end() const {
        return iterator(mProps.cend());
    }

private:

    const Prop *findProp(const char *key) const {
        auto it = mProps.find(key);
        return it != mProps.end() ? &it->second : nullptr;
    }

    Prop &findOrAllocateProp(const char *key) {
        auto it = mProps.find(key);
        if (it != mProps.end()) return it->second;
        Prop &prop = mProps[key];
        prop.setName(key);
        return prop;
    }

    pid_t         mPid = -1;
    uid_t         mUid = -1;
    std::string   mPkgName;
    int64_t       mPkgVersionCode = 0;
    std::string   mKey;
    nsecs_t       mTimestamp = 0;
    std::map<std::string, Prop> mProps;
};

} // namespace mediametrics
} // namespace android

#endif // ANDROID_MEDIA_MEDIAMETRICSITEM_H
