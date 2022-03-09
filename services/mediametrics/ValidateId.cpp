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

//#define LOG_NDEBUG 0
#define LOG_TAG "MediaMetricsService"  // not ValidateId
#include <utils/Log.h>

#include "ValidateId.h"

namespace android::mediametrics {

std::string ValidateId::dump() const
{
    std::stringstream ss;
    ss << "Entries:" << mIdSet.size() << "  InvalidIds:" << mInvalidIds << "\n";
    ss << mIdSet.dump(10);
    return ss.str();
}

void ValidateId::registerId(const std::string& id)
{
    if (id.empty()) return;
    if (!mediametrics::stringutils::isLogSessionId(id.c_str())) {
        ALOGW("%s: rejecting malformed id %s", __func__, id.c_str());
        return;
    }
    ALOGV("%s: registering %s", __func__, id.c_str());
    mIdSet.add(id);
}

const std::string& ValidateId::validateId(const std::string& id)
{
    static const std::string empty{};
    if (id.empty()) return empty;

    // reject because the id is malformed
    if (!mediametrics::stringutils::isLogSessionId(id.c_str())) {
        ALOGW("%s: rejecting malformed id %s", __func__, id.c_str());
        ++mInvalidIds;
        return empty;
    }

    // reject because the id is unregistered
    if (!mIdSet.check(id)) {
        ALOGW("%s: rejecting unregistered id %s", __func__, id.c_str());
        ++mInvalidIds;
        return empty;
    }
    return id;
}

} // namespace android::mediametrics
