/*
 * Copyright 2016 The Android Open Source Project
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

#ifndef BINDING_OBOE_STREAM_REQUEST_H
#define BINDING_OBOE_STREAM_REQUEST_H

#include <stdint.h>

#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <oboe/OboeDefinitions.h>

#include "binding/OboeStreamConfiguration.h"

using android::status_t;
using android::Parcel;
using android::Parcelable;

namespace oboe {

class OboeStreamRequest : public Parcelable {
public:
    OboeStreamRequest();
    virtual ~OboeStreamRequest();

    uid_t getUserId() const {
        return mUserId;
    }

    void setUserId(uid_t userId) {
        mUserId = userId;
    }

    pid_t getProcessId() const {
        return mProcessId;
    }

    void setProcessId(pid_t processId) {
        mProcessId = processId;
    }

    OboeStreamConfiguration &getConfiguration() {
        return mConfiguration;
    }

    virtual status_t writeToParcel(Parcel* parcel) const override;

    virtual status_t readFromParcel(const Parcel* parcel) override;

    oboe_result_t validate();

    void dump();

protected:
    OboeStreamConfiguration  mConfiguration;
    uid_t    mUserId;
    pid_t    mProcessId;
};

} /* namespace oboe */

#endif //BINDING_OBOE_STREAM_REQUEST_H
