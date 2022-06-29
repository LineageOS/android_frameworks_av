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

#include "LruSet.h"
#include "StringUtils.h"
#include "Wrap.h"

namespace android::mediametrics {

/*
 * ValidateId is used to check whether the log session id is properly formed
 * and has been registered (i.e. from the Java MediaMetricsManagerService).
 *
 * The default memory window to track registered ids is set to SINGLETON_LRU_SET_SIZE.
 *
 * This class is not thread-safe, but the singleton returned by get() uses LockWrap<>
 * to ensure thread-safety.
 */
class ValidateId {
    mediametrics::LruSet<std::string> mIdSet;
    size_t mInvalidIds = 0;  // count invalid ids encountered.
public:
    /** Creates a ValidateId object with size memory window. */
    explicit ValidateId(size_t size) : mIdSet{size} {}

    /** Returns a string dump of recent contents and stats. */
    std::string dump() const;

    /**
     * Registers the id string.
     *
     * If id string is malformed (not 16 Base64Url chars), it is ignored.
     * Once registered, calling validateId() will return id (instead of the empty string).
     * ValidateId may "forget" the id after not encountering it within the past N ids,
     * where N is the size set in the constructor.
     *
     * param id string (from MediaMetricsManagerService).
     */
    void registerId(const std::string& id);

    /**
     * Returns the empty string if id string is malformed (not 16 Base64Url chars)
     * or if id string has not been seen (in the recent size ids);
     * otherwise it returns the same id parameter.
     *
     * \param id string (to be sent to statsd).
     */
    const std::string& validateId(const std::string& id);

    /** Singleton set size */
    static inline constexpr size_t SINGLETON_LRU_SET_SIZE = 2000;

    using LockedValidateId = mediametrics::LockWrap<ValidateId>;
    /**
     * Returns a singleton locked ValidateId object that is thread-safe using LockWrap<>.
     *
     * The Singleton ValidateId object is created with size LRU_SET_SIZE (during first call).
     */
    static inline LockedValidateId& get() {
        static LockedValidateId privateSet{SINGLETON_LRU_SET_SIZE};
        return privateSet;
    }
};

} // namespace android::mediametrics
