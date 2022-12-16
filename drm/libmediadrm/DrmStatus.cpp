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

#include <mediadrm/DrmStatus.h>
#include <json/json.h>

namespace android {

DrmStatus::DrmStatus(status_t err, const char *msg) : mStatus(err) {
    Json::Value errorDetails;
    Json::Reader reader;
    if (!reader.parse(msg, errorDetails)) {
        mErrMsg = msg;
        return;
    }

    std::string errMsg;
    auto val = errorDetails["cdmError"];
    if (!val.isNull()) {
        mCdmErr = val.asInt();
    }
    val = errorDetails["oemError"];
    if (!val.isNull()) {
        mOemErr = val.asInt();
    }
    val = errorDetails["context"];
    if (!val.isNull()) {
        mCtx = val.asInt();
    }
    val = errorDetails["errorMessage"];
    if (!val.isNull()) {
        mErrMsg = val.asString();
    } else {
        mErrMsg = msg;
    }
}

}  // namespace android
