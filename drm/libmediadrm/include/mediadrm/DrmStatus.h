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

#include <media/stagefright/foundation/ABase.h>
#include <media/stagefright/MediaErrors.h>
#include <utils/Errors.h>

#include <stdint.h>
#include <string>

namespace android {

struct DrmStatus {
  public:
    DrmStatus(status_t status, int32_t cdmErr = 0, int32_t oemErr = 0,
              int32_t ctx = 0, std::string errMsg = "")
        : mStatus(status), mCdmErr(cdmErr), mOemErr(oemErr),
          mCtx(ctx), mErrMsg(errMsg) {}
    operator status_t() const { return mStatus; }
    int32_t getCdmErr() const { return mCdmErr; }
    int32_t getOemErr() const { return mOemErr; }
    int32_t getContext() const { return mCtx; }
    std::string getErrorMessage() const { return mErrMsg; }
    bool operator==(status_t other) const { return mStatus == other; }
    bool operator!=(status_t other) const { return mStatus != other; }

  private:
    status_t mStatus;
    int32_t mCdmErr{}, mOemErr{}, mCtx{};
    std::string mErrMsg;
};

}  // namespace android

#endif  // DRM_STATUS_
