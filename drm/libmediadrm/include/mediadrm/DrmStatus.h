/*
 * Copyright (C) 2022 The Android Open Source Project
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

#ifndef DRM_STATUS_
#define DRM_STATUS_
#include <stdint.h>

#include <media/stagefright/foundation/ABase.h>
#include <media/stagefright/MediaErrors.h>
#include <utils/Errors.h>

namespace android {

struct DrmStatus {
  public:
    DrmStatus(status_t status, int32_t cdmerr = 0, int32_t oemerr = 0)
        : mStatus(status), mCdmErr(cdmerr), mOemErr(oemerr) {}
    operator status_t() const { return mStatus; }
    int32_t cdmErr() const { return mCdmErr; }
    int32_t oemErr() const { return mOemErr; }
    bool operator==(status_t other) const { return mStatus == other; }
    bool operator!=(status_t other) const { return mStatus != other; }

  private:
    status_t mStatus;
    int32_t mCdmErr{}, mOemErr{};
};

}  // namespace android

#endif  // DRM_STATUS_
