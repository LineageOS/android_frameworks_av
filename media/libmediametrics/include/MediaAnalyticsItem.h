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

// the class interface
//

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

    // Key: the record descriminator
    // values for the record discriminator
    // values can be "component/component"
    // basic values: "video", "audio", "drm"
    // XXX: need to better define the format
    using Key = std::string;
    static constexpr const char * const kKeyNone = "none";
    static constexpr const char * const kKeyAny = "any";

        // Attr: names for attributes within a record
        // format "prop1" or "prop/subprop"
        // XXX: need to better define the format
        typedef const char *Attr;


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
    MediaAnalyticsItem(const MediaAnalyticsItem&) = delete;
    MediaAnalyticsItem &operator=(const MediaAnalyticsItem&) = delete;

        static MediaAnalyticsItem* create(Key key);
        static MediaAnalyticsItem* create();

        static MediaAnalyticsItem* convert(mediametrics_handle_t);
        static mediametrics_handle_t convert(MediaAnalyticsItem *);

        // access functions for the class
        ~MediaAnalyticsItem();

        // reset all contents, discarding any extra data
        void clear();
        MediaAnalyticsItem *dup();

        // set the key discriminator for the record.
        // most often initialized as part of the constructor
        MediaAnalyticsItem &setKey(MediaAnalyticsItem::Key);
        const MediaAnalyticsItem::Key& getKey() const { return mKey; }

        // # of attributes in the record
        int32_t count() const;

    template<typename S, typename T>
    MediaAnalyticsItem &set(S key, T value) {
        allocateProp(key)->set(value);
        return *this;
    }

    // set values appropriately
    MediaAnalyticsItem &setInt32(Attr key, int32_t value) {
        return set(key, value);
    }
    MediaAnalyticsItem &setInt64(Attr key, int64_t value) {
        return set(key, value);
    }
    MediaAnalyticsItem &setDouble(Attr key, double value) {
        return set(key, value);
    }
    MediaAnalyticsItem &setRate(Attr key, int64_t count, int64_t duration) {
        return set(key, std::make_pair(count, duration));
    }
    MediaAnalyticsItem &setCString(Attr key, const char *value) {
        return set(key, value);
    }

    // fused get/add/set; if attr wasn't there, it's a simple set.
    // type-mismatch counts as "wasn't there".
    template<typename S, typename T>
    MediaAnalyticsItem &add(S key, T value) {
        allocateProp(key)->add(value);
        return *this;
    }

    MediaAnalyticsItem &addInt32(Attr key, int32_t value) {
        return add(key, value);
    }
    MediaAnalyticsItem &addInt64(Attr key, int64_t value) {
        return add(key, value);
    }
    MediaAnalyticsItem &addDouble(Attr key, double value) {
        return add(key, value);
    }
    MediaAnalyticsItem &addRate(Attr key, int64_t count, int64_t duration) {
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

    bool getInt32(Attr key, int32_t *value) const {
        return get(key, value);
    }
    bool getInt64(Attr key, int64_t *value) const {
        return get(key, value);
    }
    bool getDouble(Attr key, double *value) const {
        return get(key, value);
    }
    bool getRate(Attr key, int64_t *count, int64_t *duration, double *rate) const {
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
    bool getCString(Attr key, char **value) const {
        return get(key, value);
    }
    bool getString(Attr key, std::string *value) const {
        return get(key, value);
    }

        // Deliver the item to MediaMetrics
        bool selfrecord();

        // remove indicated attributes and their values
        // filterNot() could also be called keepOnly()
        // return value is # attributes removed
        // XXX: perhaps 'remove' instead of 'filter'
        // XXX: filterNot would become 'keep'
        int32_t filter(int count, Attr attrs[]);
        int32_t filterNot(int count, Attr attrs[]);
        int32_t filter(Attr attr);

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
        int32_t writeToParcel(Parcel *);
        int32_t readFromParcel(const Parcel&);

        // supports the stable interface
        bool dumpAttributes(char **pbuffer, size_t *plength);

        std::string toString() const;
        std::string toString(int version) const;
        const char *toCString();
        const char *toCString(int version);

        // are we collecting analytics data
        static bool isEnabled();

    private:
        // handle Parcel version 0
        int32_t writeToParcel0(Parcel *);
        int32_t readFromParcel0(const Parcel&);

    protected:

        // merge fields from arg into this
        // with rules for first/last/add, etc
        // XXX: document semantics and how they are indicated
        // caller continues to own 'incoming'
        bool merge(MediaAnalyticsItem *incoming);

    // enabled 1, disabled 0
    static constexpr const char * const EnabledProperty = "media.metrics.enabled";
    static constexpr const char * const EnabledPropertyPersist = "persist.media.metrics.enabled";
    static const int EnabledProperty_default = 1;

    private:

    // let's reuse a binder connection
    static sp<IMediaAnalyticsService> sAnalyticsService;
    static sp<IMediaAnalyticsService> getInstance();
    static void dropInstance();

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
            mNameLen = other.mNameLen;
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
                u.rate = {other.u.rate.count, other.u.rate.duration};
                break;
            case kTypeNone:
                break;
            default:
                // abort?
                break;
            }
            return *this;
        }

        void clear() {
            free(mName);
            mName = nullptr;
            mNameLen = 0;
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
            std::swap(mNameLen, other.mNameLen);
            std::swap(mType, other.mType);
            std::swap(u, other.u);
        }

        void setName(const char *name, size_t len) {
            free(mName);
            if (name != nullptr) {
                mName = (char *)malloc(len + 1);
                mNameLen = len;
                strncpy(mName, name, len);
                mName[len] = 0;
            } else {
                mName = nullptr;
                mNameLen = 0;
            }
        }

        bool isNamed(const char *name, size_t len) const {
            return len == mNameLen && memcmp(name, mName, len) == 0;
        }

        // TODO: remove duplicate but different definition
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
        bool get(char** value) const {
            if (mType != kTypeCString) return false;
            if (value != nullptr) *value = strdup(u.CStringValue);
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
               value->first = u.rate.count;
               value->second = u.rate.duration;
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
                u.CStringValue = strdup(value);
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
                u.rate.count += value.first;
                u.rate.duration += value.second;
            } else {
                mType = kTypeRate;
                u.rate = {value.first, value.second};
            }
        }

        void writeToParcel(Parcel *data) const;
        void toString(char *buffer, size_t length) const;

    // TODO: make private
    // private:
        char *mName = nullptr;
        size_t mNameLen = 0;    // the strlen(), doesn't include the null
        Type mType = kTypeNone;
        union {
            int32_t int32Value;
            int64_t int64Value;
            double doubleValue;
            char *CStringValue;
            struct { int64_t count, duration; } rate;
        } u;
    };

    size_t findPropIndex(const char *name, size_t len) const;
    Prop *findProp(const char *name) const;

        enum {
            kGrowProps = 10
        };
        bool growProps(int increment = kGrowProps);
        Prop *allocateProp(const char *name);
        bool removeProp(const char *name);

        size_t mPropCount = 0;
        size_t mPropSize = 0;
        Prop *mProps = nullptr;

    pid_t         mPid = -1;
    uid_t         mUid = -1;
    std::string   mPkgName;
    int64_t       mPkgVersionCode = 0;
    Key           mKey{kKeyNone};
    nsecs_t       mTimestamp = 0;
};

} // namespace android

#endif
