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

#ifndef ANDROID_BINDING_AAUDIO_STREAM_REQUEST_H
#define ANDROID_BINDING_AAUDIO_STREAM_REQUEST_H

// go/keep-sorted start
#include <aaudio/AAudio.h>
#include <aaudio/IAAudioClientCallback.h>
#include <aaudio/StreamRequest.h>
#include <android/content/AttributionSourceState.h>
// go/keep-sorted end

#include <stdint.h>

#include "AAudioStreamConfiguration.h"

namespace aaudio {

using android::content::AttributionSourceState;

class AAudioStreamRequest {
public:
    AAudioStreamRequest() = default;

    // Construct based on a parcelable representation.
    explicit AAudioStreamRequest(const StreamRequest& parcelable);

    const AttributionSourceState &getAttributionSource() const {
        return mAttributionSource;
    }

    void setAttributionSource(const AttributionSourceState &attributionSource) {
        mAttributionSource = attributionSource;
    }

    bool isSharingModeMatchRequired() const {
        return mSharingModeMatchRequired;
    }

    void setSharingModeMatchRequired(bool required) {
        mSharingModeMatchRequired = required;
    }

    const AAudioStreamConfiguration &getConstantConfiguration() const {
        return mConfiguration;
    }

    AAudioStreamConfiguration &getConfiguration() {
        return mConfiguration;
    }

    bool isInService() const {
        return mInService;
    }

    void setInService(bool inService) {
        mInService = inService;
    }

    void setCallback(const android::sp<IAAudioClientCallback>& callback) {
        mCallback = callback;
    }

    const android::sp<IAAudioClientCallback>& getCallback() const {
        return mCallback;
    }

    aaudio_result_t validate() const;

    void dump() const;

    // Extract a parcelable representation of this object.
    StreamRequest parcelable() const;

private:
    AAudioStreamConfiguration  mConfiguration;
    AttributionSourceState mAttributionSource;
    android::sp<IAAudioClientCallback> mCallback;
    bool                       mSharingModeMatchRequired = false;
    bool                       mInService = false; // Stream opened by AAudioservice
};

} /* namespace aaudio */

#endif //ANDROID_BINDING_AAUDIO_STREAM_REQUEST_H
