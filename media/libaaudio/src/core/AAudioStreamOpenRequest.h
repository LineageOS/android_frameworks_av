/*
 * Copyright 2025 The Android Open Source Project
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

#include <aaudio/AAudio.h>

// go/keep-sorted start
#include <set>
#include <stdint.h>
// go/keep-sorted end

#include "AAudioStreamParameters.h"

namespace aaudio {

/**
 * Parameters that are used to open an aaudio stream.
 */
class AAudioStreamOpenRequest : public AAudioStreamParameters {
public:
    AAudioStreamOpenRequest(
            const AAudioStreamParameters* parameters,
            bool isSharingModeMatchRequired);

    bool isSharingModeMatchRequired() const {
        return mSharingModeMatchRequired;
    }

    AAudioStream_dataCallback getDataCallbackProc() const {
        return mDataCallbackProc;
    }

    void setPartialDataCallbackProcVoid(AAudioStream_partialDataCallback proc) {
        mPartialDataCallbackProc = proc;
    }

    AAudioStream_partialDataCallback getPartialDataCallbackProc() const {
        return mPartialDataCallbackProc;
    }

    bool isDataCallbackSet() const {
        return mDataCallbackProc != nullptr || mPartialDataCallbackProc != nullptr;
    }

    void setDataCallbackUserDataVoid(void *userData) {
        mDataCallbackUserData = userData;
    }

    void* getDataCallbackUserData() const {
        return mDataCallbackUserData;
    }

    AAudioStream_errorCallback getErrorCallbackProc() const {
        return mErrorCallbackProc;
    }

    void* getErrorCallbackUserData() const {
        return mErrorCallbackUserData;
    }

    void setPresentationEndCallbackProcVoid(AAudioStream_presentationEndCallback proc) {
        mPresentationEndCallbackProc = proc;
    }

    AAudioStream_presentationEndCallback getPresentationEndCallbackProc() const {
        return mPresentationEndCallbackProc;
    }

    void setPresentationEndCallbackUserDataVoid(void *userData) {
        mPresentationEndCallbackUserData = userData;
    }

    void* getPresentationEndCallbackUserData() const {
        return mPresentationEndCallbackUserData;
    }

    AAudioStream_routingChangedCallback getRoutingChangedCallbackProc() const {
        return mRoutingChangedCallbackProc;
    }

    void* getRoutingChangedCallbackUserData() const {
        return mRoutingChangedCallbackUserData;
    }

    int32_t getFramesPerDataCallback() const {
        return mFramesPerDataCallback;
    }

    privacy_sensitive_t getPrivacySensitiveReq() const {
        return mPrivacySensitiveReq;
    }

    aaudio_result_t validate() const override;

protected:

    bool mSharingModeMatchRequired = false; // must match sharing mode requested

    AAudioStream_dataCallback mDataCallbackProc = nullptr;  // external callback functions
    void* mDataCallbackUserData = nullptr;
    int32_t mFramesPerDataCallback = AAUDIO_UNSPECIFIED; // frames

    AAudioStream_partialDataCallback mPartialDataCallbackProc = nullptr;

    AAudioStream_errorCallback mErrorCallbackProc = nullptr;
    void* mErrorCallbackUserData = nullptr;

    AAudioStream_presentationEndCallback mPresentationEndCallbackProc = nullptr;
    void* mPresentationEndCallbackUserData = nullptr;

    AAudioStream_routingChangedCallback mRoutingChangedCallbackProc = nullptr;
    void* mRoutingChangedCallbackUserData = nullptr;

    privacy_sensitive_t mPrivacySensitiveReq = PRIVACY_SENSITIVE_DEFAULT;
};

} /* namespace aaudio */
