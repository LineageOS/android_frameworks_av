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

#include "impl/ACameraCaptureSession.h"

#include <camera/NdkCameraCaptureSession.h>

using namespace android;

template <class CallbackType>
camera_status_t captureTemplate(
        ACameraCaptureSession* session,
        /*optional*/CallbackType* cbs,
        int numRequests, ACaptureRequest** requests,
        /*optional*/int* captureSequenceId) {
    ATRACE_CALL();
    if (session == nullptr || requests == nullptr || numRequests < 1) {
        ALOGE("%s: Error: invalid input: session %p, numRequest %d, requests %p",
                __FUNCTION__, session, numRequests, requests);
        return ACAMERA_ERROR_INVALID_PARAMETER;
    }

    if (session->isClosed()) {
        ALOGE("%s: session %p is already closed", __FUNCTION__, session);
        if (captureSequenceId) {
            *captureSequenceId = CAPTURE_SEQUENCE_ID_NONE;
        }
        return ACAMERA_ERROR_SESSION_CLOSED;
    }

    return session->capture(
            cbs, numRequests, requests, captureSequenceId);
}

template <class CallbackType>
camera_status_t setRepeatingRequestTemplate(
        ACameraCaptureSession* session,
        /*optional*/CallbackType* cbs,
        int numRequests, ACaptureRequest** requests,
        /*optional*/int* captureSequenceId) {
    ATRACE_CALL();
    if (session == nullptr || requests == nullptr || numRequests < 1) {
        ALOGE("%s: Error: invalid input: session %p, numRequest %d, requests %p",
                __FUNCTION__, session, numRequests, requests);
        return ACAMERA_ERROR_INVALID_PARAMETER;
    }

    if (session->isClosed()) {
        ALOGE("%s: session %p is already closed", __FUNCTION__, session);
        if (captureSequenceId) {
            *captureSequenceId = CAPTURE_SEQUENCE_ID_NONE;
        }
        return ACAMERA_ERROR_SESSION_CLOSED;
    }

    return session->setRepeatingRequest(cbs, numRequests, requests, captureSequenceId);
}
