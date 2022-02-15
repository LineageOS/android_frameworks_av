/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <any>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <variant>
#include <vector>

#include <android-base/thread_annotations.h>
#include <media/MediaMetricsItem.h>
#include <utils/Timers.h>

namespace android::mediametrics {

// define a way of printing the monostate
inline std::ostream & operator<< (std::ostream& s,
                           std::monostate const& v __unused) {
    s << "none_item";
    return s;
}

// define a way of printing a std::pair.
template <typename T, typename U>
std::ostream & operator<< (std::ostream& s,
                           const std::pair<T, U>& v) {
    s << "{ " << v.first << ", " << v.second << " }";
    return s;
}

// define a way of printing a variant
// see https://en.cppreference.com/w/cpp/utility/variant/visit
template <typename T0, typename ... Ts>
std::ostream & operator<< (std::ostream& s,
                           std::variant<T0, Ts...> const& v) {
    std::visit([&s](auto && arg){ s << std::forward<decltype(arg)>(arg); }, v);
    return s;
}

/**
 * The TimeMachine is used to record timing changes of MediaAnalyticItem
 * properties.
 *
 * Any URL that ends with '#' (AMEDIAMETRICS_PROP_SUFFIX_CHAR_DUPLICATES_ALLOWED)
 * will have a time sequence that keeps duplicates.
 *
 * The TimeMachine is NOT thread safe.
 */
class TimeMachine final { // made final as we have copy constructor instead of dup() override.
public:
    using Elem = Item::Prop::Elem;  // use the Item property element.
    using PropertyHistory = std::multimap<int64_t /* time */, Elem>;

private:

    // KeyHistory contains no lock.
    // Access is through the TimeMachine, and a hash-striped lock is used
    // before calling into KeyHistory.
    class KeyHistory  {
    public:
        template <typename T>
        KeyHistory(T key, uid_t allowUid, int64_t time)
            : mKey(key)
            , mAllowUid(allowUid)
            , mCreationTime(time)
            , mLastModificationTime(time)
        {
            (void)mCreationTime; // suppress unused warning.

            // allowUid allows an untrusted client with a matching uid to set properties
            // in this key.
            // If allowUid == (uid_t)-1, no untrusted client may set properties in the key.
            if (allowUid != (uid_t)-1) {
                // Set ALLOWUID property here; does not change after key creation.
                putValue(AMEDIAMETRICS_PROP_ALLOWUID, (int32_t)allowUid, time);
            }
        }

        KeyHistory(const KeyHistory &other) = default;

        // Return NO_ERROR only if the passed in uidCheck is -1 or matches
        // the internal mAllowUid.
        // An external submit will always have a valid uidCheck parameter.
        // An internal get request within mediametrics will have a uidCheck == -1 which
        // we allow to proceed.
        status_t checkPermission(uid_t uidCheck) const {
            return uidCheck != (uid_t)-1 && uidCheck != mAllowUid ? PERMISSION_DENIED : NO_ERROR;
        }

        template <typename T>
        status_t getValue(const std::string &property, T* value, int64_t time = 0) const
                REQUIRES(mPseudoKeyHistoryLock) {
            if (time == 0) time = systemTime(SYSTEM_TIME_REALTIME);
            const auto tsptr = mPropertyMap.find(property);
            if (tsptr == mPropertyMap.end()) return BAD_VALUE;
            const auto& timeSequence = tsptr->second;
            auto eptr = timeSequence.upper_bound(time);
            if (eptr == timeSequence.begin()) return BAD_VALUE;
            --eptr;
            if (eptr == timeSequence.end()) return BAD_VALUE;
            const T* vptr = std::get_if<T>(&eptr->second);
            if (vptr == nullptr) return BAD_VALUE;
            *value = *vptr;
            return NO_ERROR;
        }

        template <typename T>
        status_t getValue(const std::string &property, T defaultValue, int64_t time = 0) const
                REQUIRES(mPseudoKeyHistoryLock){
            T value;
            return getValue(property, &value, time) != NO_ERROR ? defaultValue : value;
        }

        void putProp(
                const std::string &name, const mediametrics::Item::Prop &prop, int64_t time = 0)
                REQUIRES(mPseudoKeyHistoryLock) {
            //alternatively: prop.visit([&](auto value) { putValue(name, value, time); });
            putValue(name, prop.get(), time);
        }

        template <typename T>
        void putValue(const std::string &property, T&& e, int64_t time = 0)
                REQUIRES(mPseudoKeyHistoryLock) {
            if (time == 0) time = systemTime(SYSTEM_TIME_REALTIME);
            mLastModificationTime = time;
            if (mPropertyMap.size() >= kKeyMaxProperties &&
                    !mPropertyMap.count(property)) {
                ALOGV("%s: too many properties, rejecting %s", __func__, property.c_str());
                return;
            }
            auto& timeSequence = mPropertyMap[property];
            Elem el{std::forward<T>(e)};
            if (timeSequence.empty()           // no elements
                    || property.back() == AMEDIAMETRICS_PROP_SUFFIX_CHAR_DUPLICATES_ALLOWED
                    || timeSequence.rbegin()->second != el) { // value changed
                timeSequence.emplace_hint(timeSequence.end(), time, std::move(el));

                if (timeSequence.size() > kTimeSequenceMaxElements) {
                    ALOGV("%s: restricting maximum elements (discarding oldest) for %s",
                            __func__, property.c_str());
                    timeSequence.erase(timeSequence.begin());
                }
            }
        }

        std::pair<std::string, int32_t> dump(int32_t lines, int64_t time) const
                REQUIRES(mPseudoKeyHistoryLock) {
            std::stringstream ss;
            int32_t ll = lines;
            for (auto& tsPair : mPropertyMap) {
                if (ll <= 0) break;
                std::string s = dump(mKey, tsPair, time);
                if (s.size() > 0) {
                    --ll;
                    ss << s;
                }
            }
            return { ss.str(), lines - ll };
        }

        int64_t getLastModificationTime() const REQUIRES(mPseudoKeyHistoryLock) {
            return mLastModificationTime;
        }

    private:
        static std::string dump(
                const std::string &key,
                const std::pair<std::string /* prop */, PropertyHistory>& tsPair,
                int64_t time) {
            const auto timeSequence = tsPair.second;
            auto eptr = timeSequence.lower_bound(time);
            if (eptr == timeSequence.end()) {
                return {}; // don't dump anything. tsPair.first + "={};\n";
            }
            std::stringstream ss;
            ss << key << "." << tsPair.first << "={";

            time_string_t last_timestring{}; // last timestring used.
            while (true) {
                const time_string_t timestring = mediametrics::timeStringFromNs(eptr->first);
                // find common prefix offset.
                const size_t offset = commonTimePrefixPosition(timestring.time,
                        last_timestring.time);
                last_timestring = timestring;
                ss << "(" << (offset == 0 ? "" : "~") << &timestring.time[offset]
                    << ") " << eptr->second;
                if (++eptr == timeSequence.end()) {
                    break;
                }
                ss << ", ";
            }
            ss << "};\n";
            return ss.str();
        }

        const std::string mKey;
        const uid_t mAllowUid;
        const int64_t mCreationTime;

        int64_t mLastModificationTime;
        std::map<std::string /* property */, PropertyHistory> mPropertyMap;
    };

    using History = std::map<std::string /* key */, std::shared_ptr<KeyHistory>>;

    static inline constexpr size_t kTimeSequenceMaxElements = 50;
    static inline constexpr size_t kKeyMaxProperties = 50;
    static inline constexpr size_t kKeyLowWaterMark = 400;
    static inline constexpr size_t kKeyHighWaterMark = 500;

    // Estimated max data space usage is 3KB * kKeyHighWaterMark.

public:

    TimeMachine() = default;
    TimeMachine(size_t keyLowWaterMark, size_t keyHighWaterMark)
        : mKeyLowWaterMark(keyLowWaterMark)
        , mKeyHighWaterMark(keyHighWaterMark) {
        LOG_ALWAYS_FATAL_IF(keyHighWaterMark <= keyLowWaterMark,
              "%s: required that keyHighWaterMark:%zu > keyLowWaterMark:%zu",
                  __func__, keyHighWaterMark, keyLowWaterMark);
    }

    // The TimeMachine copy constructor/assignment uses a deep copy,
    // though the snapshot is not instantaneous nor isochronous.
    //
    // If there are concurrent operations ongoing in the other TimeMachine
    // then there may be some history more recent than others (a time shear).
    // This is expected to be a benign addition in history as small number of
    // future elements are incorporated.
    TimeMachine(const TimeMachine& other) {
        *this = other;
    }
    TimeMachine& operator=(const TimeMachine& other) {
        std::lock_guard lock(mLock);
        mHistory.clear();

        {
            std::lock_guard lock2(other.mLock);
            mHistory = other.mHistory;
            mGarbageCollectionCount = other.mGarbageCollectionCount.load();
        }

        // Now that we safely have our own shared pointers, let's dup them
        // to ensure they are decoupled.  We do this by acquiring the other lock.
        for (const auto &[lkey, lhist] : mHistory) {
            std::lock_guard lock2(other.getLockForKey(lkey));
            mHistory[lkey] = std::make_shared<KeyHistory>(*lhist);
        }
        return *this;
    }

    /**
     * Put all the properties from an item into the Time Machine log.
     */
    status_t put(const std::shared_ptr<const mediametrics::Item>& item, bool isTrusted = false) {
        const int64_t time = item->getTimestamp();
        const std::string &key = item->getKey();

        ALOGV("%s(%zu, %zu): key: %s  isTrusted:%d  size:%zu",
                __func__, mKeyLowWaterMark, mKeyHighWaterMark,
                key.c_str(), (int)isTrusted, item->count());
        std::shared_ptr<KeyHistory> keyHistory;
        {
            std::vector<std::any> garbage;
            std::lock_guard lock(mLock);

            auto it = mHistory.find(key);
            if (it == mHistory.end()) {
                if (!isTrusted) return PERMISSION_DENIED;

                (void)gc(garbage);

                // We set the allowUid for client access on key creation.
                int32_t allowUid = -1;
                (void)item->get(AMEDIAMETRICS_PROP_ALLOWUID, &allowUid);
                // no keylock needed here as we are sole owner
                // until placed on mHistory.
                keyHistory = std::make_shared<KeyHistory>(
                    key, allowUid, time);
                mHistory[key] = keyHistory;
            } else {
                keyHistory = it->second;
            }
        }

        // deferred contains remote properties (for other keys) to do later.
        std::vector<const mediametrics::Item::Prop *> deferred;
        {
            // handle local properties
            std::lock_guard lock(getLockForKey(key));
            if (!isTrusted) {
                status_t status = keyHistory->checkPermission(item->getUid());
                if (status != NO_ERROR) return status;
            }

            for (const auto &prop : *item) {
                const std::string &name = prop.getName();
                if (name.size() == 0 || name[0] == '_') continue;

                // Cross key settings are with [key]property
                if (name[0] == '[') {
                    if (!isTrusted) continue;
                    deferred.push_back(&prop);
                } else {
                    keyHistory->putProp(name, prop, time);
                }
            }
        }

        // handle remote properties, if any
        for (const auto propptr : deferred) {
            const auto &prop = *propptr;
            const std::string &name = prop.getName();
            size_t end = name.find_first_of(']'); // TODO: handle nested [] or escape?
            if (end == 0) continue;
            std::string remoteKey = name.substr(1, end - 1);
            std::string remoteName = name.substr(end + 1);
            if (remoteKey.size() == 0 || remoteName.size() == 0) continue;
            std::shared_ptr<KeyHistory> remoteKeyHistory;
            {
                std::lock_guard lock(mLock);
                auto it = mHistory.find(remoteKey);
                if (it == mHistory.end()) continue;
                remoteKeyHistory = it->second;
            }
            std::lock_guard lock(getLockForKey(remoteKey));
            remoteKeyHistory->putProp(remoteName, prop, time);
        }
        return NO_ERROR;
    }

    template <typename T>
    status_t get(const std::string &key, const std::string &property,
            T* value, int32_t uidCheck = -1, int64_t time = 0) const {
        std::shared_ptr<KeyHistory> keyHistory;
        {
            std::lock_guard lock(mLock);
            const auto it = mHistory.find(key);
            if (it == mHistory.end()) return BAD_VALUE;
            keyHistory = it->second;
        }
        std::lock_guard lock(getLockForKey(key));
        return keyHistory->checkPermission(uidCheck)
                ?: keyHistory->getValue(property, value, time);
    }

    /**
     * Individual property put.
     *
     * Put takes in a time (if none is provided then SYSTEM_TIME_REALTIME is used).
     */
    template <typename T>
    status_t put(const std::string &url, T &&e, int64_t time = 0) {
        std::string key;
        std::string prop;
        std::shared_ptr<KeyHistory> keyHistory =
            getKeyHistoryFromUrl(url, &key, &prop);
        if (keyHistory == nullptr) return BAD_VALUE;
        if (time == 0) time = systemTime(SYSTEM_TIME_REALTIME);
        std::lock_guard lock(getLockForKey(key));
        keyHistory->putValue(prop, std::forward<T>(e), time);
        return NO_ERROR;
    }

    /**
     * Individual property get
     */
    template <typename T>
    status_t get(const std::string &url, T* value, int32_t uidCheck, int64_t time = 0) const {
        std::string key;
        std::string prop;
        std::shared_ptr<KeyHistory> keyHistory =
            getKeyHistoryFromUrl(url, &key, &prop);
        if (keyHistory == nullptr) return BAD_VALUE;

        std::lock_guard lock(getLockForKey(key));
        return keyHistory->checkPermission(uidCheck)
               ?: keyHistory->getValue(prop, value, time);
    }

    /**
     * Individual property get with default
     */
    template <typename T>
    T get(const std::string &url, const T &defaultValue, int32_t uidCheck,
            int64_t time = 0) const {
        T value;
        return get(url, &value, uidCheck, time) == NO_ERROR
                ? value : defaultValue;
    }

    /**
     *  Returns number of keys in the Time Machine.
     */
    size_t size() const {
        std::lock_guard lock(mLock);
        return mHistory.size();
    }

    /**
     * Clears all properties from the Time Machine.
     */
    void clear() {
        std::lock_guard lock(mLock);
        mHistory.clear();
        mGarbageCollectionCount = 0;
    }

    /**
     * Returns a pair consisting of the TimeMachine state as a string
     * and the number of lines in the string.
     *
     * The number of lines in the returned pair is used as an optimization
     * for subsequent line limiting.
     *
     * \param lines the maximum number of lines in the string returned.
     * \param key selects only that key.
     * \param sinceNs the nanoseconds since Unix epoch to start dump (0 shows all)
     * \param prefix the desired key prefix to match (nullptr shows all)
     */
    std::pair<std::string, int32_t> dump(
            int32_t lines = INT32_MAX, int64_t sinceNs = 0, const char *prefix = nullptr) const {
        std::lock_guard lock(mLock);
        std::stringstream ss;
        int32_t ll = lines;

        for (auto it = prefix != nullptr ? mHistory.lower_bound(prefix) : mHistory.begin();
                it != mHistory.end();
                ++it) {
            if (ll <= 0) break;
            if (prefix != nullptr && !startsWith(it->first, prefix)) break;
            std::lock_guard lock2(getLockForKey(it->first));
            auto [s, l] = it->second->dump(ll, sinceNs);
            ss << s;
            ll -= l;
        }
        return { ss.str(), lines - ll };
    }

    size_t getGarbageCollectionCount() const {
        return mGarbageCollectionCount;
    }

private:

    // Obtains the lock for a KeyHistory.
    std::mutex &getLockForKey(const std::string &key) const
            RETURN_CAPABILITY(mPseudoKeyHistoryLock) {
        return mKeyLocks[std::hash<std::string>{}(key) % std::size(mKeyLocks)];
    }

    // Finds a KeyHistory from a URL.  Returns nullptr if not found.
    std::shared_ptr<KeyHistory> getKeyHistoryFromUrl(
            const std::string& url, std::string* key, std::string *prop) const {
        std::lock_guard lock(mLock);

        auto it = mHistory.upper_bound(url);
        if (it == mHistory.begin()) {
           return nullptr;
        }
        --it;  // go to the actual key, if it exists.

        const std::string& itKey = it->first;
        if (strncmp(itKey.c_str(), url.c_str(), itKey.size())) {
            return nullptr;
        }
        if (key) *key = itKey;
        if (prop) *prop = url.substr(itKey.size() + 1);
        return it->second;
    }

    /**
     * Garbage collects if the TimeMachine size exceeds the high water mark.
     *
     * This GC operation limits the number of keys stored (not the size of properties
     * stored in each key).
     *
     * \param garbage a type-erased vector of elements to be destroyed
     *        outside of lock.  Move large items to be destroyed here.
     *
     * \return true if garbage collection was done.
     */
    bool gc(std::vector<std::any>& garbage) REQUIRES(mLock) {
        // TODO: something better than this for garbage collection.
        if (mHistory.size() < mKeyHighWaterMark) return false;

        // erase everything explicitly expired.
        std::multimap<int64_t, std::string> accessList;
        // use a stale vector with precise type to avoid type erasure overhead in garbage
        std::vector<std::shared_ptr<KeyHistory>> stale;

        for (auto it = mHistory.begin(); it != mHistory.end();) {
            const std::string& key = it->first;
            std::shared_ptr<KeyHistory> &keyHist = it->second;

            std::lock_guard lock(getLockForKey(it->first));
            int64_t expireTime = keyHist->getValue("_expire", -1 /* default */);
            if (expireTime != -1) {
                stale.emplace_back(std::move(it->second));
                it = mHistory.erase(it);
            } else {
                accessList.emplace(keyHist->getLastModificationTime(), key);
                ++it;
            }
        }

        if (mHistory.size() > mKeyLowWaterMark) {
           const size_t toDelete = mHistory.size() - mKeyLowWaterMark;
           auto it = accessList.begin();
           for (size_t i = 0; i < toDelete; ++i) {
               auto it2 = mHistory.find(it->second);
               stale.emplace_back(std::move(it2->second));
               mHistory.erase(it2);
               ++it;
           }
        }
        garbage.emplace_back(std::move(accessList));
        garbage.emplace_back(std::move(stale));

        ALOGD("%s(%zu, %zu): key size:%zu",
                __func__, mKeyLowWaterMark, mKeyHighWaterMark,
                mHistory.size());

        ++mGarbageCollectionCount;
        return true;
    }

    const size_t mKeyLowWaterMark = kKeyLowWaterMark;
    const size_t mKeyHighWaterMark = kKeyHighWaterMark;

    std::atomic<size_t> mGarbageCollectionCount{};

    /**
     * Locking Strategy
     *
     * Each key in the History has a KeyHistory. To get a shared pointer to
     * the KeyHistory requires a lookup of mHistory under mLock.  Once the shared
     * pointer to KeyHistory is obtained, the mLock for mHistory can be released.
     *
     * Once the shared pointer to the key's KeyHistory is obtained, the KeyHistory
     * can be locked for read and modification through the method getLockForKey().
     *
     * Instead of having a mutex per KeyHistory, we use a hash striped lock
     * which assigns a mutex based on the hash of the key string.
     *
     * Once the last shared pointer reference to KeyHistory is released, it is
     * destroyed.  This is done through the garbage collection method.
     *
     * This two level locking allows multiple threads to access the TimeMachine
     * in parallel.
     */

    mutable std::mutex mLock;           // Lock for mHistory
    History mHistory GUARDED_BY(mLock);

    // KEY_LOCKS is the number of mutexes for keys.
    // It need not be a power of 2, but faster that way.
    static inline constexpr size_t KEY_LOCKS = 256;
    mutable std::mutex mKeyLocks[KEY_LOCKS];  // Hash-striped lock for KeyHistory based on key.

    // Used for thread-safety analysis, we create a fake mutex object to represent
    // the hash stripe lock mechanism, which is then tracked by the compiler.
    class CAPABILITY("mutex") PseudoLock {};
    static inline PseudoLock mPseudoKeyHistoryLock;
};

} // namespace android::mediametrics
