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

#define LOG_TAG "SharedMemoryParcelable"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/mman.h>
#include <aaudio/AAudio.h>

#include <android-base/unique_fd.h>
#include <binder/Parcelable.h>
#include <utility/AAudioUtilities.h>

#include "binding/SharedMemoryParcelable.h"

using android::base::unique_fd;
using android::NO_ERROR;
using android::status_t;
using android::media::SharedFileRegion;

using namespace aaudio;

SharedMemoryParcelable::SharedMemoryParcelable(SharedFileRegion&& parcelable) {
    mFd = parcelable.fd.release();
    mSizeInBytes = parcelable.size;
    mOffsetInBytes = parcelable.offset;
}

SharedFileRegion SharedMemoryParcelable::parcelable() && {
    SharedFileRegion result;
    result.fd.reset(std::move(mFd));
    result.size = mSizeInBytes;
    result.offset = mOffsetInBytes;
    return result;
}

SharedMemoryParcelable SharedMemoryParcelable::dup() const {
    SharedMemoryParcelable result;
    result.setup(mFd, static_cast<int32_t>(mSizeInBytes));
    return result;
}

void SharedMemoryParcelable::setup(const unique_fd& fd, int32_t sizeInBytes) {
    constexpr int minFd = 3; // skip over stdout, stdin and stderr
    mFd.reset(fcntl(fd.get(), F_DUPFD_CLOEXEC, minFd)); // store a duplicate FD
    ALOGV("setup(fd = %d -> %d, size = %d) this = %p\n", fd.get(), mFd.get(), sizeInBytes, this);
    mSizeInBytes = sizeInBytes;
}

aaudio_result_t SharedMemoryParcelable::close() {
    if (mResolvedAddress != MMAP_UNRESOLVED_ADDRESS) {
        int err = munmap(mResolvedAddress, mSizeInBytes);
        if (err < 0) {
            ALOGE("close() munmap() failed %d", err);
            return AAudioConvert_androidToAAudioResult(err);
        }
        mResolvedAddress = MMAP_UNRESOLVED_ADDRESS;
    }
    return AAUDIO_OK;
}

aaudio_result_t SharedMemoryParcelable::resolveSharedMemory(const unique_fd& fd) {
    mResolvedAddress = (uint8_t *) mmap(0, mSizeInBytes, PROT_READ | PROT_WRITE,
                                        MAP_SHARED, fd.get(), 0);
    if (mResolvedAddress == MMAP_UNRESOLVED_ADDRESS) {
        ALOGE("mmap() failed for fd = %d, nBytes = %" PRId64 ", errno = %s",
              fd.get(), mSizeInBytes, strerror(errno));
        return AAUDIO_ERROR_INTERNAL;
    }
    return AAUDIO_OK;
}

aaudio_result_t SharedMemoryParcelable::resolve(int32_t offsetInBytes, int32_t sizeInBytes,
                                              void **regionAddressPtr) {
    if (offsetInBytes < 0) {
        ALOGE("illegal offsetInBytes = %d", offsetInBytes);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    } else if ((offsetInBytes + sizeInBytes) > mSizeInBytes) {
        ALOGE("out of range, offsetInBytes = %d, "
                      "sizeInBytes = %d, mSizeInBytes = %" PRId64,
              offsetInBytes, sizeInBytes, mSizeInBytes);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }

    aaudio_result_t result = AAUDIO_OK;

    if (mResolvedAddress == MMAP_UNRESOLVED_ADDRESS) {
        if (mFd.get() != -1) {
            result = resolveSharedMemory(mFd);
        } else {
            ALOGE("has no file descriptor for shared memory.");
            result = AAUDIO_ERROR_INTERNAL;
        }
    }

    if (result == AAUDIO_OK && mResolvedAddress != MMAP_UNRESOLVED_ADDRESS) {
        *regionAddressPtr = mResolvedAddress + offsetInBytes;
        ALOGV("mResolvedAddress = %p", mResolvedAddress);
        ALOGV("offset by %d, *regionAddressPtr = %p", offsetInBytes, *regionAddressPtr);
    }
    return result;
}

int32_t SharedMemoryParcelable::getSizeInBytes() {
    return mSizeInBytes;
}

aaudio_result_t SharedMemoryParcelable::validate() const {
    if (mSizeInBytes < 0 || mSizeInBytes >= MAX_MMAP_SIZE_BYTES) {
        ALOGE("invalid mSizeInBytes = %" PRId64, mSizeInBytes);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }
    if (mOffsetInBytes != 0) {
        ALOGE("invalid mOffsetInBytes = %" PRId64, mOffsetInBytes);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }
    return AAUDIO_OK;
}

void SharedMemoryParcelable::dump() {
    ALOGD("mFd = %d", mFd.get());
    ALOGD("mSizeInBytes = %" PRId64, mSizeInBytes);
}
