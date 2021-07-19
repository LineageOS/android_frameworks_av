/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <list>
#include <sstream>
#include <unordered_map>

namespace android::mediametrics {

/**
 * LruSet keeps a set of the last "Size" elements added or accessed.
 *
 * (Lru stands for least-recently-used eviction policy).
 *
 * Runs in O(1) time for add, remove, and check.  Internally implemented
 * with an unordered_map and a list.  In order to remove elements,
 * a list iterator is stored in the unordered_map
 * (noting that std::list::erase() contractually
 * does not affect iterators other than the one erased).
 */

template <typename T>
class LruSet {
    const size_t mMaxSize;
    std::list<T> mAccessOrder;                 // front is the most recent, back is the oldest.
    // item T with its access order iterator.
    std::unordered_map<T, typename std::list<T>::iterator> mMap;

public:
    /**
     * Constructs a LruSet which checks whether the element was
     * accessed or added recently.
     *
     * The parameter maxSize is used to cap growth of LruSet;
     * eviction is based on least recently used LRU.
     * If maxSize is zero, the LruSet contains no elements
     * and check() always returns false.
     *
     * \param maxSize the maximum number of elements that are tracked.
     */
    explicit LruSet(size_t maxSize) : mMaxSize(maxSize) {}

    /**
     * Returns the number of entries in the LruSet.
     *
     * This is a number between 0 and maxSize.
     */
    size_t size() const {
        return mMap.size();
    }

    /** Clears the container contents. */
    void clear() {
        mMap.clear();
        mAccessOrder.clear();
    }

    /** Returns a string dump of the last n entries. */
    std::string dump(size_t n) const {
        std::stringstream ss;
        auto it = mAccessOrder.cbegin();
        for (size_t i = 0; i < n && it != mAccessOrder.cend(); ++i) {
            ss << *it++ << "\n";
        }
        return ss.str();
    }

    /** Adds a new item to the set. */
    void add(const T& t) {
        if (mMaxSize == 0) return;
        auto it = mMap.find(t);
        if (it != mMap.end()) { // already exists.
            mAccessOrder.erase(it->second);  // move-to-front on the chronologically ordered list.
        } else if (mAccessOrder.size() >= mMaxSize) {
            const T last = mAccessOrder.back();
            mAccessOrder.pop_back();
            mMap.erase(last);
        }
        mAccessOrder.push_front(t);
        mMap[t] = mAccessOrder.begin();
    }

    /**
     * Removes an item from the set.
     *
     * \param t item to be removed.
     * \return false if the item doesn't exist.
     */
    bool remove(const T& t) {
        auto it = mMap.find(t);
        if (it == mMap.end()) return false;
        mAccessOrder.erase(it->second);
        mMap.erase(it);
        return true;
    }

    /** Returns true if t is present (and moves the access order of t to the front). */
    bool check(const T& t) { // not const, as it adjusts the least-recently-used order.
        auto it = mMap.find(t);
        if (it == mMap.end()) return false;
        mAccessOrder.erase(it->second);
        mAccessOrder.push_front(it->first);
        it->second = mAccessOrder.begin();
        return true;
    }
};

} // namespace android::mediametrics
