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
#include "MediaMetricsConstants.h"

#include <algorithm>
#include <map>
#include <string>
#include <sys/types.h>
#include <variant>

#include <binder/Parcel.h>
#include <log/log.h>
#include <utils/Errors.h>
#include <utils/Timers.h> // nsecs_t

namespace android {

class IMediaMetricsService;
class Parcel;

/*
 * MediaMetrics Item
 *
 * The MediaMetrics Item allows get/set operations and recording to the service.
 *
 * The MediaMetrics LogItem is a faster logging variant. It allows set operations only,
 * and then recording to the service.
 *
 * The Byte String format is as follows:
 *
 * For Java
 *  int64 corresponds to long
 *  int32, uint32 corresponds to int
 *  uint16 corresponds to char
 *  uint8, int8 corresponds to byte
 *
 * For items transmitted from Java, uint8 and uint32 values are limited
 * to INT8_MAX and INT32_MAX.  This constrains the size of large items
 * to 2GB, which is consistent with ByteBuffer max size. A native item
 * can conceivably have size of 4GB.
 *
 * Physical layout of integers and doubles within the MediaMetrics byte string
 * is in Native / host order, which is usually little endian.
 *
 * Note that primitive data (ints, doubles) within a Byte String has
 * no extra padding or alignment requirements, like ByteBuffer.
 *
 * -- begin of item
 * -- begin of header
 * (uint32) item size: including the item size field
 * (uint32) header size, including the item size and header size fields.
 * (uint16) version: exactly 0
 * (uint16) key size, that is key strlen + 1 for zero termination.
 * (int8)+ key, a string which is 0 terminated (UTF-8).
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
 *       (int8)+ for TYPE_CSTRING, including 0 termination
 *       (int64, int64) for rate
 * -- end body
 * -- end of item
 *
 * The Byte String format must match MediaMetrics.java.
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

/*
 * Time printing
 *
 * kPrintFormatLong time string is 19 characters (including null termination).
 * Example Long Form: "03-27 16:47:06.187"
 *                     MM DD HH MM SS MS
 *
 * kPrintFormatShort time string is 13 characters (including null termination).
 * Example Short Form: "16:47:06.187"
 *                      HH MM SS MS
 */

enum PrintFormat {
    kPrintFormatLong = 0,
    kPrintFormatShort = 1,
};

/**
 * Converts real time in ns to a time string object, with format similar to logcat.
 *
 * \param ns         input real time in nanoseconds to convert.
 * \param buffer     the buffer location to put the converted string.
 * \param bufferSize the size of buffer in bytes.
 * \param format     format, from enum PrintFormat.
 */
void nsToString(
        int64_t ns, char *buffer, size_t bufferSize, PrintFormat format = kPrintFormatLong);

// Contains the time string
struct time_string_t {
    char time[19]; /* minimum size buffer */
};

/**
 * Converts real time in ns to a time string object, with format similar to logcat.
 *
 * \param ns     input real time in nanoseconds to convert.
 * \param format format, from enum PrintFormat.
 * \return       a time_string_t object with the time string encoded.
 */
static inline time_string_t timeStringFromNs(int64_t ns, PrintFormat format = kPrintFormatLong) {
    time_string_t ts;
    nsToString(ns, ts.time, sizeof(ts.time), format);
    return ts;
}

/**
 * Finds the end of the common time prefix.
 *
 * This is as an option to remove the common time prefix to avoid
 * unnecessary duplicated strings.
 *
 * \param time1 a time string from timeStringFromNs
 * \param time2 a time string from timeStringFromNs
 * \return      the position where the common time prefix ends. For abbreviated
 *              printing of time2, offset the character pointer by this position.
 */
static inline size_t commonTimePrefixPosition(const char *time1, const char *time2) {
    size_t i;

    // Find location of the first mismatch between strings
    for (i = 0; ; ++i) {
        if (time1[i] != time2[i]) {
            break;
        }
        if (time1[i] == 0) {
            return i; // strings match completely
        }
    }

    // Go backwards until we find a delimeter or space.
    for (; i > 0
           && isdigit(time1[i]) // still a number
           && time1[i - 1] != ' '
         ; --i) {
    }
    return i;
}

/**
 * The MediaMetrics Item has special Item properties,
 * derived internally or through dedicated setters.
 *
 * For consistency we use the following keys to represent
 * these special Item properties when in a generic Bundle
 * or in a std::map.
 *
 * These values must match MediaMetrics.java
 */
static inline constexpr const char *BUNDLE_TOTAL_SIZE = "_totalSize";
static inline constexpr const char *BUNDLE_HEADER_SIZE = "_headerSize";
static inline constexpr const char *BUNDLE_VERSION = "_version";
static inline constexpr const char *BUNDLE_KEY_SIZE = "_keySize";
static inline constexpr const char *BUNDLE_KEY = "_key";
static inline constexpr const char *BUNDLE_PID = "_pid";
static inline constexpr const char *BUNDLE_UID = "_uid";
static inline constexpr const char *BUNDLE_TIMESTAMP = "_timestamp";
static inline constexpr const char *BUNDLE_PROPERTY_COUNT = "_propertyCount";

template<size_t N>
static inline bool startsWith(const std::string &s, const char (&comp)[N]) {
    return !strncmp(s.c_str(), comp, N - 1); // last char is null termination
}

static inline bool startsWith(const std::string& s, const std::string& comp) {
    return !strncmp(s.c_str(), comp.c_str(), comp.size());
}

/**
 * Defers a function to run in the destructor.
 *
 * This helper class is used to log results on exit of a method.
 */
class Defer {
public:
    template <typename U>
    explicit Defer(U &&f) : mThunk(std::forward<U>(f)) {}
    ~Defer() { mThunk(); }

private:
    const std::function<void()> mThunk;
};

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

    template <typename T>
    struct is_item_type {
        static constexpr inline bool value =
             std::is_same<T, int32_t>::value
             || std::is_same<T, int64_t>::value
             || std::is_same<T, double>::value
             || std::is_same<T, std::pair<int64_t, int64_t>>:: value
             || std::is_same<T, std::string>::value
             || std::is_same<T, std::monostate>::value;
    };

    template <typename T>
    struct get_type_of {
        static_assert(is_item_type<T>::value);
        static constexpr inline Type value =
             std::is_same<T, int32_t>::value ? kTypeInt32
             : std::is_same<T, int64_t>::value ? kTypeInt64
             : std::is_same<T, double>::value ? kTypeDouble
             : std::is_same<T, std::pair<int64_t, int64_t>>:: value ? kTypeRate
             : std::is_same<T, std::string>::value ? kTypeCString
             : std::is_same<T, std::monostate>::value ? kTypeNone
         : kTypeNone;
    };

    template <typename T>
    static size_t sizeOfByteString(const char *name, const T& value) {
        static_assert(is_item_type<T>::value);
        return 2 + 1 + strlen(name) + 1 + sizeof(value);
    }
    template <> // static
    size_t sizeOfByteString(const char *name, const std::string& value) {
        return 2 + 1 + strlen(name) + 1 + value.size() + 1;
    }
    template <> // static
    size_t sizeOfByteString(const char *name, const std::monostate&) {
         return 2 + 1 + strlen(name) + 1;
    }
    // for speed
    static size_t sizeOfByteString(const char *name, const char *value) {
        return 2 + 1 + strlen(name) + 1 + strlen(value) + 1;
    }

    template <typename T>
    static status_t insert(const T& val, char **bufferpptr, char *bufferptrmax) {
        static_assert(std::is_trivially_constructible<T>::value);
        const size_t size = sizeof(val);
        if (*bufferpptr + size > bufferptrmax) {
            ALOGE("%s: buffer exceeded with size %zu", __func__, size);
            return BAD_VALUE;
        }
        memcpy(*bufferpptr, &val, size);
        *bufferpptr += size;
        return NO_ERROR;
    }
    template <> // static
    status_t insert(const std::string& val, char **bufferpptr, char *bufferptrmax) {
        const size_t size = val.size() + 1;
        if (size > UINT16_MAX || *bufferpptr + size > bufferptrmax) {
            ALOGE("%s: buffer exceeded with size %zu", __func__, size);
            return BAD_VALUE;
        }
        memcpy(*bufferpptr, val.c_str(), size);
        *bufferpptr += size;
        return NO_ERROR;
    }
    template <> // static
    status_t insert(const std::pair<int64_t, int64_t>& val,
            char **bufferpptr, char *bufferptrmax) {
        const size_t size = sizeof(val.first) + sizeof(val.second);
        if (*bufferpptr + size > bufferptrmax) {
            ALOGE("%s: buffer exceeded with size %zu", __func__, size);
            return BAD_VALUE;
        }
        memcpy(*bufferpptr, &val.first, sizeof(val.first));
        memcpy(*bufferpptr + sizeof(val.first), &val.second, sizeof(val.second));
        *bufferpptr += size;
        return NO_ERROR;
    }
    template <> // static
    status_t insert(const std::monostate&, char **, char *) {
        return NO_ERROR;
    }
    // for speed
    static status_t insert(const char *val, char **bufferpptr, char *bufferptrmax) {
        const size_t size = strlen(val) + 1;
        if (size > UINT16_MAX || *bufferpptr + size > bufferptrmax) {
            ALOGE("%s: buffer exceeded with size %zu", __func__, size);
            return BAD_VALUE;
        }
        memcpy(*bufferpptr, val, size);
        *bufferpptr += size;
        return NO_ERROR;
    }

    template <typename T>
    static status_t writeToByteString(
            const char *name, const T& value, char **bufferpptr, char *bufferptrmax) {
        static_assert(is_item_type<T>::value);
        const size_t len = sizeOfByteString(name, value);
        if (len > UINT16_MAX) return BAD_VALUE;
        return insert((uint16_t)len, bufferpptr, bufferptrmax)
                ?: insert((uint8_t)get_type_of<T>::value, bufferpptr, bufferptrmax)
                ?: insert(name, bufferpptr, bufferptrmax)
                ?: insert(value, bufferpptr, bufferptrmax);
    }
    // for speed
    static status_t writeToByteString(
            const char *name, const char *value, char **bufferpptr, char *bufferptrmax) {
        const size_t len = sizeOfByteString(name, value);
        if (len > UINT16_MAX) return BAD_VALUE;
        return insert((uint16_t)len, bufferpptr, bufferptrmax)
                ?: insert((uint8_t)kTypeCString, bufferpptr, bufferptrmax)
                ?: insert(name, bufferpptr, bufferptrmax)
                ?: insert(value, bufferpptr, bufferptrmax);
    }

    template <typename T>
    static void toStringBuffer(
            const char *name, const T& value, char *buffer, size_t length) = delete;
    template <> // static
    void toStringBuffer(
            const char *name, const int32_t& value, char *buffer, size_t length) {
        snprintf(buffer, length, "%s=%d", name, value);
    }
    template <> // static
    void toStringBuffer(
            const char *name, const int64_t& value, char *buffer, size_t length) {
        snprintf(buffer, length, "%s=%lld", name, (long long)value);
    }
    template <> // static
    void toStringBuffer(
            const char *name, const double& value, char *buffer, size_t length) {
        snprintf(buffer, length, "%s=%e", name, value);
    }
    template <> // static
    void toStringBuffer(
            const char *name, const std::pair<int64_t, int64_t>& value,
            char *buffer, size_t length) {
        snprintf(buffer, length, "%s=%lld/%lld",
                name, (long long)value.first, (long long)value.second);
    }
    template <> // static
    void toStringBuffer(
            const char *name, const std::string& value, char *buffer, size_t length) {
        // TODO sanitize string for ':' '='
        snprintf(buffer, length, "%s=%s", name, value.c_str());
    }
    template <> // static
    void toStringBuffer(
            const char *name, const std::monostate&, char *buffer, size_t length) {
        snprintf(buffer, length, "%s=()", name);
    }

    template <typename T>
    static status_t writeToParcel(
            const char *name, const T& value, Parcel *parcel) = delete;
    template <> // static
    status_t writeToParcel(
            const char *name, const int32_t& value, Parcel *parcel) {
        return parcel->writeCString(name)
               ?: parcel->writeInt32(get_type_of<int32_t>::value)
               ?: parcel->writeInt32(value);
    }
    template <> // static
    status_t writeToParcel(
            const char *name, const int64_t& value, Parcel *parcel) {
        return parcel->writeCString(name)
               ?: parcel->writeInt32(get_type_of<int64_t>::value)
               ?: parcel->writeInt64(value);
    }
    template <> // static
    status_t writeToParcel(
            const char *name, const double& value, Parcel *parcel) {
        return parcel->writeCString(name)
               ?: parcel->writeInt32(get_type_of<double>::value)
               ?: parcel->writeDouble(value);
    }
    template <> // static
    status_t writeToParcel(
            const char *name, const std::pair<int64_t, int64_t>& value, Parcel *parcel) {
        return parcel->writeCString(name)
               ?: parcel->writeInt32(get_type_of< std::pair<int64_t, int64_t>>::value)
               ?: parcel->writeInt64(value.first)
               ?: parcel->writeInt64(value.second);
    }
    template <> // static
    status_t writeToParcel(
            const char *name, const std::string& value, Parcel *parcel) {
        return parcel->writeCString(name)
               ?: parcel->writeInt32(get_type_of<std::string>::value)
               ?: parcel->writeCString(value.c_str());
    }
    template <> // static
    status_t writeToParcel(
            const char *name, const std::monostate&, Parcel *parcel) {
        return parcel->writeCString(name)
               ?: parcel->writeInt32(get_type_of<std::monostate>::value);
    }

    template <typename T>
    static status_t extract(T *val, const char **bufferpptr, const char *bufferptrmax) {
        static_assert(std::is_trivially_constructible<T>::value);
        const size_t size = sizeof(*val);
        if (*bufferpptr + size > bufferptrmax) {
            ALOGE("%s: buffer exceeded with size %zu", __func__, size);
            return BAD_VALUE;
        }
        memcpy(val, *bufferpptr, size);
        *bufferpptr += size;
        return NO_ERROR;
    }
    template <> // static
    status_t extract(std::string *val, const char **bufferpptr, const char *bufferptrmax) {
        const char *ptr = *bufferpptr;
        do {
            if (ptr >= bufferptrmax) {
                ALOGE("%s: buffer exceeded", __func__);
                android_errorWriteLog(0x534e4554, "204445255");
                return BAD_VALUE;
            }
        } while (*ptr++ != 0);
        // ptr is terminator+1, == bufferptrmax if we finished entire buffer
        *val = *bufferpptr;
        *bufferpptr = ptr;
        return NO_ERROR;
    }
    template <> // static
    status_t extract(std::pair<int64_t, int64_t> *val,
            const char **bufferpptr, const char *bufferptrmax) {
        const size_t size = sizeof(val->first) + sizeof(val->second);
        if (*bufferpptr + size > bufferptrmax) {
            ALOGE("%s: buffer exceeded with size %zu", __func__, size);
            return BAD_VALUE;
        }
        memcpy(&val->first, *bufferpptr, sizeof(val->first));
        memcpy(&val->second, *bufferpptr + sizeof(val->first), sizeof(val->second));
        *bufferpptr += size;
        return NO_ERROR;
    }
    template <> // static
    status_t extract(std::monostate *, const char **, const char *) {
        return NO_ERROR;
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

    BufferedItem(const std::string& key, char *begin, char *end)
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
        const size_t keylen = key == nullptr ? 0 : strlen(key) + 1;
        if (keylen <= 1) {
            mStatus = BAD_VALUE; // prevent null pointer or empty keys.
            return;
        }
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
    explicit LogItem(const std::string& key) : LogItem(key.c_str()) { }

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
class Item final : public mediametrics::BaseItem {
public:

    class Prop {
    public:
        using Elem = std::variant<
                std::monostate,               // kTypeNone
                int32_t,                      // kTypeInt32
                int64_t,                      // kTypeInt64
                double,                       // kTypeDouble
                std::string,                  // kTypeCString
                std::pair<int64_t, int64_t>   // kTypeRate
                >;

        Prop() = default;
        Prop(const Prop& other) {
           *this = other;
        }
        Prop& operator=(const Prop& other) {
            mName = other.mName;
            mElem = other.mElem;
            return *this;
        }
        Prop(Prop&& other) noexcept {
            *this = std::move(other);
        }
        Prop& operator=(Prop&& other) noexcept {
            mName = std::move(other.mName);
            mElem = std::move(other.mElem);
            return *this;
        }

        bool operator==(const Prop& other) const {
            return mName == other.mName && mElem == other.mElem;
        }
        bool operator!=(const Prop& other) const {
            return !(*this == other);
        }

        void clear() {
            mName.clear();
            mElem = std::monostate{};
        }
        void clearValue() {
            mElem = std::monostate{};
        }

        const char *getName() const {
            return mName.c_str();
        }

        void swap(Prop& other) {
            std::swap(mName, other.mName);
            std::swap(mElem, other.mElem);
        }

        void setName(const char *name) {
            mName = name;
        }

        bool isNamed(const char *name) const {
            return mName == name;
        }

        template <typename T> void visit(T f) const {
            std::visit(f, mElem);
        }

        template <typename T> bool get(T *value) const {
            auto pval = std::get_if<T>(&mElem);
            if (pval != nullptr) {
                *value = *pval;
                return true;
            }
            return false;
        }

        const Elem& get() const {
            return mElem;
        }

        template <typename T> void set(const T& value) {
            mElem = value;
        }

        template <typename T> void add(const T& value) {
            auto pval = std::get_if<T>(&mElem);
            if (pval != nullptr) {
                *pval += value;
            } else {
                mElem = value;
            }
        }

        template <> void add(const std::pair<int64_t, int64_t>& value) {
            auto pval = std::get_if<std::pair<int64_t, int64_t>>(&mElem);
            if (pval != nullptr) {
                pval->first += value.first;
                pval->second += value.second;
            } else {
                mElem = value;
            }
        }

        status_t writeToParcel(Parcel *parcel) const {
            return std::visit([this, parcel](auto &value) {
                    return BaseItem::writeToParcel(mName.c_str(), value, parcel);}, mElem);
        }

        void toStringBuffer(char *buffer, size_t length) const {
            return std::visit([this, buffer, length](auto &value) {
                BaseItem::toStringBuffer(mName.c_str(), value, buffer, length);}, mElem);
        }

        size_t getByteStringSize() const {
            return std::visit([this](auto &value) {
                return BaseItem::sizeOfByteString(mName.c_str(), value);}, mElem);
        }

        status_t writeToByteString(char **bufferpptr, char *bufferptrmax) const {
            return std::visit([this, bufferpptr, bufferptrmax](auto &value) {
                return BaseItem::writeToByteString(mName.c_str(), value, bufferpptr, bufferptrmax);
            }, mElem);
        }

        status_t readFromParcel(const Parcel& data);

        status_t readFromByteString(const char **bufferpptr, const char *bufferptrmax);

    private:
        std::string mName;
        Elem mElem;
    };

    // Iteration of props within item
    class iterator {
    public:
        explicit iterator(const std::map<std::string, Prop>::const_iterator &_it) : it(_it) { }
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

    // T must be convertible to mKey
    template <typename T>
    explicit Item(T key)
        : mKey(key) { }
    Item() = default;

    // We enable default copy and move constructors and make this class final
    // to prevent a derived class; this avoids possible data slicing.
    Item(const Item& other) = default;
    Item(Item&& other) = default;
    Item& operator=(const Item& other) = default;
    Item& operator=(Item&& other) = default;

    bool operator==(const Item& other) const {
        return mPid == other.mPid
            && mUid == other.mUid
            && mPkgName == other.mPkgName
            && mPkgVersionCode == other.mPkgVersionCode
            && mKey == other.mKey
            && mTimestamp == other.mTimestamp
            && mProps == other.mProps
            ;
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
        std::string s;
        if (get(key, &s)) {
            *value = strdup(s.c_str());
            return true;
        }
        return false;
    }
    bool getString(const char *key, std::string *value) const {
        return get(key, value);
    }

    const Prop::Elem* get(const char *key) const {
        const Prop *prop = findProp(key);
        return prop == nullptr ? nullptr : &prop->get();
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
        const char *toCString();

    /**
     * Returns true if the item has a property with a target value.
     *
     * If propName is nullptr, hasPropElem() returns false.
     *
     * \param propName is the property name.
     * \param elem is the value to match.  std::monostate matches any.
     */
    bool hasPropElem(const char *propName, const Prop::Elem& elem) const {
        if (propName == nullptr) return false;
        const Prop::Elem *e = get(propName);
        return e != nullptr && (std::holds_alternative<std::monostate>(elem) || elem == *e);
    }

    /**
     * Returns -2, -1, 0 (success) if the item has a property (wildcard matched) with a
     * target value.
     *
     * The enum RecursiveWildcardCheck designates the meaning of the returned value.
     *
     * RECURSIVE_WILDCARD_CHECK_NO_MATCH_NO_WILDCARD = -2,
     * RECURSIVE_WILDCARD_CHECK_NO_MATCH_WILDCARD_FOUND = -1,
     * RECURSIVE_WILDCARD_CHECK_MATCH_FOUND = 0.
     *
     * If url is nullptr, RECURSIVE_WILDCARD_CHECK_NO_MATCH_NO_WILDCARD is returned.
     *
     * \param url is the full item + property name, which may have wildcards '*'
     *            denoting an arbitrary sequence of 0 or more characters.
     * \param elem is the target property value to match. std::monostate matches any.
     * \return 0 if the property was matched,
     *         -1 if the property was not matched and a wildcard char was encountered,
     *         -2 if the property was not matched with no wildcard char encountered.
     */
    enum RecursiveWildcardCheck {
        RECURSIVE_WILDCARD_CHECK_NO_MATCH_NO_WILDCARD = -2,
        RECURSIVE_WILDCARD_CHECK_NO_MATCH_WILDCARD_FOUND = -1,
        RECURSIVE_WILDCARD_CHECK_MATCH_FOUND = 0,
    };

    enum RecursiveWildcardCheck recursiveWildcardCheckElem(
        const char *url, const Prop::Elem& elem) const {
        if (url == nullptr) return RECURSIVE_WILDCARD_CHECK_NO_MATCH_NO_WILDCARD;
        return recursiveWildcardCheckElem(getKey().c_str(), url, elem);
    }

private:

    enum RecursiveWildcardCheck recursiveWildcardCheckElem(
            const char *itemKeyPtr, const char *url, const Prop::Elem& elem) const {
        for (; *url && *itemKeyPtr; ++url, ++itemKeyPtr) {
            if (*url != *itemKeyPtr) {
                if (*url == '*') { // wildcard
                    ++url;
                    while (true) {
                        if (recursiveWildcardCheckElem(itemKeyPtr, url, elem)
                                == RECURSIVE_WILDCARD_CHECK_MATCH_FOUND) {
                            return RECURSIVE_WILDCARD_CHECK_MATCH_FOUND;
                        }
                        if (*itemKeyPtr == 0) break;
                        ++itemKeyPtr;
                    }
                    return RECURSIVE_WILDCARD_CHECK_NO_MATCH_WILDCARD_FOUND;
                }
                return RECURSIVE_WILDCARD_CHECK_NO_MATCH_NO_WILDCARD;
            }
        }
        if (itemKeyPtr[0] != 0 || url[0] != '.') {
            return RECURSIVE_WILDCARD_CHECK_NO_MATCH_NO_WILDCARD;
        }
        const char *propName = url + 1; // skip the '.'
        return hasPropElem(propName, elem)
                ? RECURSIVE_WILDCARD_CHECK_MATCH_FOUND
                : RECURSIVE_WILDCARD_CHECK_NO_MATCH_NO_WILDCARD;
    }

    // handle Parcel version 0
    int32_t writeToParcel0(Parcel *) const;
    int32_t readFromParcel0(const Parcel&);

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

    // Changes to member variables below require changes to clear().
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
