/*
 * Copyright (C) 2013 The Android Open Source Project
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
#define LOG_TAG "PlayerServiceMediaHTTP"
#include <utils/Log.h>

#include <datasource/PlayerServiceMediaHTTP.h>

#include <binder/IServiceManager.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/ALooper.h>
#include <media/stagefright/FoundationUtils.h>

#include <media/MediaHTTPConnection.h>

namespace android {

PlayerServiceMediaHTTP::PlayerServiceMediaHTTP(const sp<MediaHTTPConnection> &conn)
    : MediaHTTP(conn),
      mDrmManagerClient(NULL) {
    (void) DrmInitialization(nullptr);
}

PlayerServiceMediaHTTP::~PlayerServiceMediaHTTP() {
    clearDRMState_l();
}

// DRM...

sp<DecryptHandle> PlayerServiceMediaHTTP::DrmInitialization(const char *mime) {
    if (mDrmManagerClient == NULL) {
        mDrmManagerClient = new DrmManagerClient();
    }

    if (mDrmManagerClient == NULL) {
        return NULL;
    }

    if (mDecryptHandle == NULL) {
        mDecryptHandle = mDrmManagerClient->openDecryptSession(
                String8(mLastURI.c_str()), mime);
    }

    if (mDecryptHandle == NULL) {
        delete mDrmManagerClient;
        mDrmManagerClient = NULL;
    }

    return mDecryptHandle;
}

void PlayerServiceMediaHTTP::clearDRMState_l() {
    if (mDecryptHandle != NULL) {
        // To release mDecryptHandle
        CHECK(mDrmManagerClient);
        mDrmManagerClient->closeDecryptSession(mDecryptHandle);
        mDecryptHandle = NULL;
    }
}

}  // namespace android
