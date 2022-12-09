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
#define LOG_TAG "clearkey-CryptoPlugin"

#include <utils/Log.h>
#include <cerrno>
#include <cstring>

#include "CryptoPlugin.h"
#include "SessionLibrary.h"
#include "AidlUtils.h"

namespace aidl {
namespace android {
namespace hardware {
namespace drm {
namespace clearkey {

using ::aidl::android::hardware::drm::Status;

::ndk::ScopedAStatus CryptoPlugin::decrypt(const DecryptArgs& in_args, int32_t* _aidl_return) {
    const char* detailedError = "";

    *_aidl_return = 0;
    if (in_args.secure) {
        detailedError = "secure decryption is not supported with ClearKey";
        return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE, detailedError);
    }

    std::lock_guard<std::mutex> shared_buffer_lock(mSharedBufferLock);
    if (mSharedBufferMap.find(in_args.source.bufferId) == mSharedBufferMap.end()) {
        detailedError = "source decrypt buffer base not set";
        return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE, detailedError);
    }

    const auto NON_SECURE = DestinationBuffer::Tag::nonsecureMemory;
    if (in_args.destination.getTag() != NON_SECURE) {
        detailedError = "destination type not supported";
        return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE, detailedError);
    }

    const SharedBuffer& destBuffer = in_args.destination.get<NON_SECURE>();
    if (mSharedBufferMap.find(destBuffer.bufferId) == mSharedBufferMap.end()) {
        detailedError = "destination decrypt buffer base not set";
        return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE, detailedError);
    }

    auto src = mSharedBufferMap[in_args.source.bufferId];
    if (src->mBase == nullptr) {
        detailedError = "source is a nullptr";
        return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE, detailedError);
    }

    size_t totalSize = 0;
    if (__builtin_add_overflow(in_args.source.offset, in_args.offset, &totalSize) ||
        __builtin_add_overflow(totalSize, in_args.source.size, &totalSize) ||
        totalSize > src->mSize) {
        android_errorWriteLog(0x534e4554, "176496160");
        detailedError = "invalid buffer size";
        return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE, detailedError);
    }

    // destination type must be non-secure shared memory
    auto dest = mSharedBufferMap[destBuffer.bufferId];
    if (dest->mBase == nullptr) {
        detailedError = "destination is a nullptr";
        return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE, detailedError);
    }

    totalSize = 0;
    if (__builtin_add_overflow(destBuffer.offset, destBuffer.size, &totalSize) ||
        totalSize > dest->mSize) {
        android_errorWriteLog(0x534e4554, "176444622");
        detailedError = "invalid buffer size";
        return toNdkScopedAStatus(Status::ERROR_DRM_FRAME_TOO_LARGE, detailedError);
    }

    // Calculate the output buffer size and determine if any subsamples are
    // encrypted.
    uint8_t* srcPtr = src->mBase + in_args.source.offset + in_args.offset;
    uint8_t* destPtr = dest->mBase + destBuffer.offset;
    size_t destSize = 0;
    size_t srcSize = 0;
    bool haveEncryptedSubsamples = false;
    for (size_t i = 0; i < in_args.subSamples.size(); i++) {
        const SubSample& subSample = in_args.subSamples[i];
        if (__builtin_add_overflow(destSize, subSample.numBytesOfClearData, &destSize) ||
            __builtin_add_overflow(srcSize, subSample.numBytesOfClearData, &srcSize)) {
            detailedError = "subsample clear size overflow";
            return toNdkScopedAStatus(Status::ERROR_DRM_FRAME_TOO_LARGE, detailedError);
        }
        if (__builtin_add_overflow(destSize, subSample.numBytesOfEncryptedData, &destSize) ||
            __builtin_add_overflow(srcSize, subSample.numBytesOfEncryptedData, &srcSize)) {
            detailedError = "subsample encrypted size overflow";
            return toNdkScopedAStatus(Status::ERROR_DRM_FRAME_TOO_LARGE, detailedError);
        }
        if (subSample.numBytesOfEncryptedData > 0) {
            haveEncryptedSubsamples = true;
        }
    }

    if (destSize > destBuffer.size || srcSize > in_args.source.size) {
        detailedError = "subsample sum too large";
        return toNdkScopedAStatus(Status::ERROR_DRM_FRAME_TOO_LARGE, detailedError);
    }

    if (in_args.mode == Mode::UNENCRYPTED) {
        if (haveEncryptedSubsamples) {
            detailedError = "Encrypted subsamples found in allegedly unencrypted data.";
            return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE, detailedError);
        }

        size_t offset = 0;
        for (size_t i = 0; i < in_args.subSamples.size(); ++i) {
            const SubSample& subSample = in_args.subSamples[i];
            if (subSample.numBytesOfClearData != 0) {
                memcpy(reinterpret_cast<uint8_t*>(destPtr) + offset,
                       reinterpret_cast<const uint8_t*>(srcPtr) + offset,
                       subSample.numBytesOfClearData);
                offset += subSample.numBytesOfClearData;
            }
        }

        *_aidl_return = static_cast<ssize_t>(offset);
        return toNdkScopedAStatus(Status::OK);
    } else if (in_args.mode == Mode::AES_CTR) {
        size_t bytesDecrypted{};
        std::vector<int32_t> clearDataLengths;
        std::vector<int32_t> encryptedDataLengths;
        for (auto ss : in_args.subSamples) {
            clearDataLengths.push_back(ss.numBytesOfClearData);
            encryptedDataLengths.push_back(ss.numBytesOfEncryptedData);
        }
        if (in_args.keyId.size() != kBlockSize || in_args.iv.size() != kBlockSize) {
            android_errorWriteLog(0x534e4554, "244569759");
            detailedError = "invalid decrypt parameter size";
            return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE, detailedError);
        }
        auto res =
                mSession->decrypt(in_args.keyId.data(), in_args.iv.data(),
                                  srcPtr, static_cast<uint8_t*>(destPtr),
                                  clearDataLengths, encryptedDataLengths,
                                  &bytesDecrypted);
        if (res == clearkeydrm::OK) {
            *_aidl_return = static_cast<ssize_t>(bytesDecrypted);
            return toNdkScopedAStatus(Status::OK);
        } else {
            *_aidl_return = 0;
            detailedError = "Decryption Error";
            return toNdkScopedAStatus(static_cast<Status>(res), detailedError);
        }
    } else {
        *_aidl_return = 0;
        detailedError = "selected encryption mode is not supported by the ClearKey DRM Plugin";
        return toNdkScopedAStatus(Status::ERROR_DRM_CANNOT_HANDLE, detailedError);
    }
}

::ndk::ScopedAStatus CryptoPlugin::getLogMessages(
        std::vector<::aidl::android::hardware::drm::LogMessage>* _aidl_return) {
    using std::chrono::duration_cast;
    using std::chrono::milliseconds;
    using std::chrono::system_clock;

    auto timeMillis = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();

    std::vector<::aidl::android::hardware::drm::LogMessage> logs = {
            {timeMillis, ::aidl::android::hardware::drm::LogPriority::ERROR,
             std::string("Not implemented")}};
    *_aidl_return = logs;
    return toNdkScopedAStatus(Status::OK);
}

::ndk::ScopedAStatus CryptoPlugin::notifyResolution(int32_t in_width, int32_t in_height) {
    UNUSED(in_width);
    UNUSED(in_height);
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus CryptoPlugin::requiresSecureDecoderComponent(const std::string& in_mime,
                                                                  bool* _aidl_return) {
    UNUSED(in_mime);
    *_aidl_return = false;
    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus CryptoPlugin::setMediaDrmSession(const std::vector<uint8_t>& in_sessionId) {
    Status status = Status::OK;
    if (!in_sessionId.size()) {
        mSession = nullptr;
    } else {
        mSession = SessionLibrary::get()->findSession(in_sessionId);
        if (!mSession.get()) {
            status = Status::ERROR_DRM_SESSION_NOT_OPENED;
        }
    }
    return toNdkScopedAStatus(status);
}

::ndk::ScopedAStatus CryptoPlugin::setSharedBufferBase(const SharedBuffer& in_base) {
    std::lock_guard<std::mutex> shared_buffer_lock(mSharedBufferLock);
    mSharedBufferMap[in_base.bufferId] = std::make_shared<SharedBufferBase>(in_base);
    return ::ndk::ScopedAStatus::ok();
}

SharedBufferBase::SharedBufferBase(const SharedBuffer& mem)
        : mBase(nullptr),
          mSize(mem.size) {
    if (mem.handle.fds.empty()) {
        return;
    }
    auto fd = mem.handle.fds[0].get();
    auto addr = mmap(nullptr, mem.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        ALOGE("mmap err: fd %d; errno %s", fd, strerror(errno));
    } else {
        mBase = static_cast<uint8_t*>(addr);
    }
}

SharedBufferBase::~SharedBufferBase() {
    if (mBase && munmap(mBase, mSize)) {
        ALOGE("munmap err: base %p; errno %s",
              mBase, strerror(errno));
    }
}
}  // namespace clearkey
}  // namespace drm
}  // namespace hardware
}  // namespace android
}  // namespace aidl
