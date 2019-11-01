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

#ifndef ANDROID_MEDIA_MEDIAANALYTICSITEM_H
#define ANDROID_MEDIA_MEDIAANALYTICSITEM_H

#include "MediaMetrics.h"

#include <algorithm>
#include <string>
#include <sys/types.h>

#include <cutils/properties.h>
#include <utils/Errors.h>
#include <utils/KeyedVector.h>
#include <utils/RefBase.h>
#include <utils/StrongPointer.h>
#include <utils/Timers.h>

namespace android {

class IMediaAnalyticsService;
class Parcel;

/*
 * Media Metrics
 * Byte String format for communication of MediaAnalyticsItem.
 *
 * .... begin of item
 * .... begin of header
 * (uint32) length: including the length field itself
 * (uint32) header length, including header_length and length fields.
 * (uint16) version: 0
 * (uint16) key length, including zero termination
 * (int8)+ key string, including 0 termination
 * (int32) pid
 * (int32) uid
 * (int64) timestamp
 * .... end of header
 * .... begin body
 * (uint32) properties
 * #properties of the following:
 *     (uint16) property_length, including property_length field itself
 *     (uint8) type of property
 *     (int8)+ key string, including 0 termination
 *      based on type of property (above), one of:
 *       (int32)
 *       (int64)
 *       (double)
 *       (int8)+ for cstring, including 0 termination
 *       (int64, int64) for rate
 * .... end body
 * .... end of item
 */

/**
 * Media Metrics MediaAnalyticsItem
 *
 * A mutable item representing an event or record that will be
 * logged with the Media Metrics service.
 *
 */

class MediaAnalyticsItem {
    friend class MediaMetricsJNI;           // TODO: remove this access
    friend class MediaMetricsDeathNotifier; // for dropInstance

public:

            enum Type {
                kTypeNone = 0,
                kTypeInt32 = 1,
                kTypeInt64 = 2,
                kTypeDouble = 3,
                kTypeCString = 4,
                kTypeRate = 5,
            };

    static constexpr const char * const kKeyNone = "none";
    static constexpr const char * const kKeyAny = "any";

        enum {
            PROTO_V0 = 0,
            PROTO_FIRST = PROTO_V0,
            PROTO_V1 = 1,
            PROTO_LAST = PROTO_V1,
        };

    // T must be convertible to mKey
    template <typename T>
    explicit MediaAnalyticsItem(T key)
        : mKey(key) { }
    MediaAnalyticsItem() = default;

    MediaAnalyticsItem(const MediaAnalyticsItem&) = delete;
    MediaAnalyticsItem &operator=(const MediaAnalyticsItem&) = delete;

    bool operator==(const MediaAnalyticsItem& other) const {
        if (mPropCount != other.mPropCount
            || mPid != other.mPid
            || mUid != other.mUid
            || mPkgName != other.mPkgName
            || mPkgVersionCode != other.mPkgVersionCode
            || mKey != other.mKey
            || mTimestamp != other.mTimestamp) return false;
         for (size_t i = 0; i < mPropCount; ++i) {
             Prop *p = other.findProp(mProps[i].getName());
             if (p == nullptr || mProps[i] != *p) return false;
         }
         return true;
    }
    bool operator!=(const MediaAnalyticsItem& other) const {
        return !(*this == other);
    }

    template <typename T>
    static MediaAnalyticsItem* create(T key) {
        return new MediaAnalyticsItem(key);
    }
    static MediaAnalyticsItem* create() {
        return new MediaAnalyticsItem();
    }

        static MediaAnalyticsItem* convert(mediametrics_handle_t);
        static mediametrics_handle_t convert(MediaAnalyticsItem *);

        // access functions for the class
        ~MediaAnalyticsItem();

        // reset all contents, discarding any extra data
        void clear();
        MediaAnalyticsItem *dup();

    MediaAnalyticsItem &setKey(const char *key) {
        mKey = key;
        return *this;
    }
    const std::string& getKey() const { return mKey; }

    // # of properties in the record
    size_t count() const { return mPropCount; }

    template<typename S, typename T>
    MediaAnalyticsItem &set(S key, T value) {
        allocateProp(key)->set(value);
        return *this;
    }

    // set values appropriately
    MediaAnalyticsItem &setInt32(const char *key, int32_t value) {
        return set(key, value);
    }
    MediaAnalyticsItem &setInt64(const char *key, int64_t value) {
        return set(key, value);
    }
    MediaAnalyticsItem &setDouble(const char *key, double value) {
        return set(key, value);
    }
    MediaAnalyticsItem &setRate(const char *key, int64_t count, int64_t duration) {
        return set(key, std::make_pair(count, duration));
    }
    MediaAnalyticsItem &setCString(const char *key, const char *value) {
        return set(key, value);
    }

    // fused get/add/set; if attr wasn't there, it's a simple set.
    // type-mismatch counts as "wasn't there".
    template<typename S, typename T>
    MediaAnalyticsItem &add(S key, T value) {
        allocateProp(key)->add(value);
        return *this;
    }

    MediaAnalyticsItem &addInt32(const char *key, int32_t value) {
        return add(key, value);
    }
    MediaAnalyticsItem &addInt64(const char *key, int64_t value) {
        return add(key, value);
    }
    MediaAnalyticsItem &addDouble(const char *key, double value) {
        return add(key, value);
    }
    MediaAnalyticsItem &addRate(const char *key, int64_t count, int64_t duration) {
        return add(key, std::make_pair(count, duration));
    }

    // find & extract values
    // return indicates whether attr exists (and thus value filled in)
    // NULL parameter value suppresses storage of value.
    template<typename S, typename T>
    bool get(S key, T *value) const {
        Prop *prop = findProp(key);
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
        MediaAnalyticsItem &setTimestamp(nsecs_t);
        nsecs_t getTimestamp() const;

        MediaAnalyticsItem &setPid(pid_t);
        pid_t getPid() const;

        MediaAnalyticsItem &setUid(uid_t);
        uid_t getUid() const;

        MediaAnalyticsItem &setPkgName(const std::string &pkgName);
        std::string getPkgName() const { return mPkgName; }

        MediaAnalyticsItem &setPkgVersionCode(int64_t);
        int64_t getPkgVersionCode() const;

    // our serialization code for binder calls
    status_t writeToParcel(Parcel *) const;
    status_t readFromParcel(const Parcel&);

    status_t writeToByteString(char **bufferptr, size_t *length) const;
    status_t readFromByteString(const char *bufferptr, size_t length);

    static status_t writeToByteString(
            const char *name, int32_t value, char **bufferpptr, char *bufferptrmax);
    static status_t writeToByteString(
            const char *name, int64_t value, char **bufferpptr, char *bufferptrmax);
    static status_t writeToByteString(
            const char *name, double value, char **bufferpptr, char *bufferptrmax);
    static status_t writeToByteString(
            const char *name, const std::pair<int64_t, int64_t> &value, char **bufferpptr, char *bufferptrmax);
    static status_t writeToByteString(
            const char *name, char * const &value, char **bufferpptr, char *bufferptrmax);
    struct none_t {}; // for kTypeNone
    static status_t writeToByteString(
            const char *name, const none_t &, char **bufferpptr, char *bufferptrmax);

        std::string toString() const;
        std::string toString(int version) const;
        const char *toCString();
        const char *toCString(int version);

        // are we collecting analytics data
        static bool isEnabled();

    protected:

        // merge fields from arg into this
        // with rules for first/last/add, etc
        // XXX: document semantics and how they are indicated
        // caller continues to own 'incoming'
        bool merge(MediaAnalyticsItem *incoming);

private:
    // handle Parcel version 0
    int32_t writeToParcel0(Parcel *) const;
    int32_t readFromParcel0(const Parcel&);

    // enabled 1, disabled 0
    static constexpr const char * const EnabledProperty = "media.metrics.enabled";
    static constexpr const char * const EnabledPropertyPersist = "persist.media.metrics.enabled";
    static const int EnabledProperty_default = 1;

    // let's reuse a binder connection
    static sp<IMediaAnalyticsService> sAnalyticsService;
    static sp<IMediaAnalyticsService> getInstance();
    static void dropInstance();

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
    friend class MediaMetricsJNI;           // TODO: remove this access
    public:
        Prop() = default;
        Prop(const Prop& other) {
           *this = other;
        }
        Prop& operator=(const Prop& other) {
            if (other.mName != nullptr) {
                mName = strdup(other.mName);
            } else {
                mName = nullptr;
            }
            mType = other.mType;
            switch (mType) {
            case kTypeInt32:
                u.int32Value = other.u.int32Value;
                break;
            case kTypeInt64:
                u.int64Value = other.u.int64Value;
                break;
            case kTypeDouble:
                u.doubleValue = other.u.doubleValue;
                break;
            case kTypeCString:
                u.CStringValue = strdup(other.u.CStringValue);
                break;
            case kTypeRate:
                u.rate = other.u.rate;
                break;
            case kTypeNone:
                break;
            default:
                // abort?
                break;
            }
            return *this;
        }
        bool operator==(const Prop& other) const {
            if (!stringEquals(mName, other.mName)
                    || mType != other.mType) return false;
            switch (mType) {
            case kTypeInt32:
                return u.int32Value == other.u.int32Value;
            case kTypeInt64:
                return u.int64Value == other.u.int64Value;
            case kTypeDouble:
                return u.doubleValue == other.u.doubleValue;
            case kTypeCString:
                return stringEquals(u.CStringValue, other.u.CStringValue);
            case kTypeRate:
                return u.rate == other.u.rate;
            case kTypeNone:
            default:
                return true;
            }
        }
        bool operator!=(const Prop& other) const {
            return !(*this == other);
        }

        void clear() {
            free(mName);
            mName = nullptr;
            clearValue();
        }
        void clearValue() {
            if (mType == kTypeCString) {
                free(u.CStringValue);
                u.CStringValue = nullptr;
            }
            mType = kTypeNone;
        }

        Type getType() const {
            return mType;
        }

        const char *getName() const {
            return mName;
        }

        void swap(Prop& other) {
            std::swap(mName, other.mName);
            std::swap(mType, other.mType);
            std::swap(u, other.u);
        }

        void setName(const char *name) {
            free(mName);
            if (name != nullptr) {
                mName = strdup(name);
            } else {
                mName = nullptr;
            }
        }

        bool isNamed(const char *name) const {
            return strcmp(name, mName) == 0;
        }

        template <typename T> bool get(T *value) const = delete;
        template <>
        bool get(int32_t *value) const {
           if (mType != kTypeInt32) return false;
           if (value != nullptr) *value = u.int32Value;
           return true;
        }
        template <>
        bool get(int64_t *value) const {
           if (mType != kTypeInt64) return false;
           if (value != nullptr) *value = u.int64Value;
           return true;
        }
        template <>
        bool get(double *value) const {
           if (mType != kTypeDouble) return false;
           if (value != nullptr) *value = u.doubleValue;
           return true;
        }
        template <>
        bool get(const char** value) const {
            if (mType != kTypeCString) return false;
            if (value != nullptr) *value = u.CStringValue;
            return true;
        }
        template <>
        bool get(std::string* value) const {
            if (mType != kTypeCString) return false;
            if (value != nullptr) *value = u.CStringValue;
            return true;
        }
        template <>
        bool get(std::pair<int64_t, int64_t> *value) const {
           if (mType != kTypeRate) return false;
           if (value != nullptr) {
               *value = u.rate;
           }
           return true;
        }

        template <typename T> void set(const T& value) = delete;
        template <>
        void set(const int32_t& value) {
            mType = kTypeInt32;
            u.int32Value = value;
        }
        template <>
        void set(const int64_t& value) {
            mType = kTypeInt64;
            u.int64Value = value;
        }
        template <>
        void set(const double& value) {
            mType = kTypeDouble;
            u.doubleValue = value;
        }
        template <>
        void set(const char* const& value) {
            if (mType == kTypeCString) {
                free(u.CStringValue);
            } else {
                mType = kTypeCString;
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
            mType = kTypeRate;
            u.rate = {value.first, value.second};
        }

        template <typename T> void add(const T& value) = delete;
        template <>
        void add(const int32_t& value) {
            if (mType == kTypeInt32) {
                u.int32Value += value;
            } else {
                mType = kTypeInt32;
                u.int32Value = value;
            }
        }
        template <>
        void add(const int64_t& value) {
            if (mType == kTypeInt64) {
                u.int64Value += value;
            } else {
                mType = kTypeInt64;
                u.int64Value = value;
            }
        }
        template <>
        void add(const double& value) {
            if (mType == kTypeDouble) {
                u.doubleValue += value;
            } else {
                mType = kTypeDouble;
                u.doubleValue = value;
            }
        }
        template <>
        void add(const std::pair<int64_t, int64_t>& value) {
            if (mType == kTypeRate) {
                u.rate.first += value.first;
                u.rate.second += value.second;
            } else {
                mType = kTypeRate;
                u.rate = value;
            }
        }

        status_t writeToParcel(Parcel *data) const;
        status_t readFromParcel(const Parcel& data);
        void toString(char *buffer, size_t length) const;
        size_t getByteStringSize() const;
        status_t writeToByteString(char **bufferpptr, char *bufferptrmax) const;
        status_t readFromByteString(const char **bufferpptr, const char *bufferptrmax);

    // TODO: make private (and consider converting to std::variant)
    // private:
        char *mName = nullptr;
        Type mType = kTypeNone;
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

    class iterator {
    public:
       iterator(size_t pos, const MediaAnalyticsItem &_item)
           : i(std::min(pos, _item.count()))
           , item(_item) { }
       iterator &operator++() {
           i = std::min(i + 1, item.count());
           return *this;
       }
       bool operator!=(iterator &other) const {
           return i != other.i;
       }
       Prop &operator*() const {
           return item.mProps[i];
       }

    private:
      size_t i;
      const MediaAnalyticsItem &item;
    };

    iterator begin() const {
        return iterator(0, *this);
    }
    iterator end() const {
        return iterator(SIZE_MAX, *this);
    }

private:

    // TODO: make prop management class
    size_t findPropIndex(const char *name) const;
    Prop *findProp(const char *name) const;
    Prop *allocateProp();

        enum {
            kGrowProps = 10
        };
        bool growProps(int increment = kGrowProps);
        Prop *allocateProp(const char *name);
        bool removeProp(const char *name);
    Prop *allocateProp(const std::string& name) { return allocateProp(name.c_str()); }

        size_t mPropCount = 0;
        size_t mPropSize = 0;
        Prop *mProps = nullptr;

    pid_t         mPid = -1;
    uid_t         mUid = -1;
    std::string   mPkgName;
    int64_t       mPkgVersionCode = 0;
    std::string   mKey{kKeyNone};
    nsecs_t       mTimestamp = 0;
};

} // namespace android

#endif
