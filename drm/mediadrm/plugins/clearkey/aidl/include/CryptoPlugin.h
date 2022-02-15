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

#include <aidl/android/hardware/drm/BnCryptoPlugin.h>
#include <aidl/android/hardware/drm/Status.h>

#include <aidl/android/hardware/common/Ashmem.h>

#include <android/binder_auto_utils.h>

#include <memory>
#include <mutex>

#include "ClearKeyTypes.h"
#include "Session.h"

namespace {
static const size_t KEY_ID_SIZE = 16;
static const size_t KEY_IV_SIZE = 16;
}  // namespace

namespace aidl {
namespace android {
namespace hardware {
namespace drm {
namespace clearkey {

using namespace clearkeydrm;
using ::aidl::android::hardware::drm::DecryptArgs;
using ::aidl::android::hardware::drm::Status;

struct SharedBufferBase {
    uint8_t* mBase;
    int64_t mSize;
    SharedBufferBase(const ::aidl::android::hardware::drm::SharedBuffer& mem);
    ~SharedBufferBase();
};

struct CryptoPlugin : public BnCryptoPlugin {
    explicit CryptoPlugin(const std::vector<uint8_t>& sessionId) {
        const auto res = setMediaDrmSession(sessionId);
        mInitStatus = Status::OK;
        if (!res.isOk() && res.getExceptionCode() == EX_SERVICE_SPECIFIC) {
            mInitStatus = static_cast<Status>(res.getServiceSpecificError());
        }
    }
    virtual ~CryptoPlugin() {}

    ::ndk::ScopedAStatus decrypt(const DecryptArgs& in_args, int32_t* _aidl_return) override;

    ::ndk::ScopedAStatus getLogMessages(
            std::vector<::aidl::android::hardware::drm::LogMessage>* _aidl_return) override;

    ::ndk::ScopedAStatus notifyResolution(int32_t in_width, int32_t in_height) override;

    ::ndk::ScopedAStatus requiresSecureDecoderComponent(const std::string& in_mime,
                                                        bool* _aidl_return) override;

    ::ndk::ScopedAStatus setMediaDrmSession(const std::vector<uint8_t>& in_sessionId) override;

    ::ndk::ScopedAStatus setSharedBufferBase(
            const ::aidl::android::hardware::drm::SharedBuffer& in_base) override;

    ::aidl::android::hardware::drm::Status getInitStatus() const { return mInitStatus; }

  private:
    CLEARKEY_DISALLOW_COPY_AND_ASSIGN(CryptoPlugin);

    std::mutex mSharedBufferLock;
    std::map<uint32_t, std::shared_ptr<SharedBufferBase>> mSharedBufferMap
            GUARDED_BY(mSharedBufferLock);
    ::android::sp<Session> mSession;
    ::aidl::android::hardware::drm::Status mInitStatus;
};

}  // namespace clearkey
}  // namespace drm
}  // namespace hardware
}  // namespace android
}  // namespace aidl
