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

#define LOG_TAG "AAudio"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include <stdint.h>
#include <stdio.h>

#include <sys/mman.h>
#include <aaudio/AAudio.h>

#include <binder/Parcelable.h>
#include <utility/AAudioUtilities.h>

#include "binding/SharedMemoryParcelable.h"

using android::NO_ERROR;
using android::status_t;
using android::Parcel;
using android::Parcelable;

using namespace aaudio;

SharedMemoryParcelable::SharedMemoryParcelable() {}
SharedMemoryParcelable::~SharedMemoryParcelable() {};

void SharedMemoryParcelable::setup(int fd, int32_t sizeInBytes) {
    mFd = fd;
    mSizeInBytes = sizeInBytes;

}

status_t SharedMemoryParcelable::writeToParcel(Parcel* parcel) const {
    status_t status = parcel->writeInt32(mSizeInBytes);
    if (status != NO_ERROR) return status;
    if (mSizeInBytes > 0) {
        status = parcel->writeDupFileDescriptor(mFd);
        ALOGE_IF(status != NO_ERROR, "SharedMemoryParcelable writeDupFileDescriptor failed : %d", status);
    }
    return status;
}

status_t SharedMemoryParcelable::readFromParcel(const Parcel* parcel) {
    status_t status = parcel->readInt32(&mSizeInBytes);
    if (status != NO_ERROR) {
        return status;
    }
    if (mSizeInBytes > 0) {
        int originalFD = parcel->readFileDescriptor();
        mFd = fcntl(originalFD, F_DUPFD_CLOEXEC, 0);
        if (mFd == -1) {
            status = -errno;
            ALOGE("SharedMemoryParcelable readFileDescriptor fcntl() failed : %d", status);
        }
    }
    return status;
}

aaudio_result_t SharedMemoryParcelable::close() {
    if (mResolvedAddress != nullptr) {
        int err = munmap(mResolvedAddress, mSizeInBytes);
        if (err < 0) {
            ALOGE("SharedMemoryParcelable::close() munmap() failed %d", err);
            return AAudioConvert_androidToAAudioResult(err);
        }
        mResolvedAddress = nullptr;
    }
    if (mFd != -1) {
        ::close(mFd);
        mFd = -1;
    }
    return AAUDIO_OK;
}

aaudio_result_t SharedMemoryParcelable::resolve(int32_t offsetInBytes, int32_t sizeInBytes,
                                              void **regionAddressPtr) {

    if (offsetInBytes < 0) {
        ALOGE("SharedMemoryParcelable illegal offsetInBytes = %d", offsetInBytes);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    } else if ((offsetInBytes + sizeInBytes) > mSizeInBytes) {
        ALOGE("SharedMemoryParcelable out of range, offsetInBytes = %d, "
              "sizeInBytes = %d, mSizeInBytes = %d",
              offsetInBytes, sizeInBytes, mSizeInBytes);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }
    if (mResolvedAddress == nullptr) {
        mResolvedAddress = (uint8_t *) mmap(0, mSizeInBytes, PROT_READ|PROT_WRITE,
                                          MAP_SHARED, mFd, 0);
        if (mResolvedAddress == nullptr) {
            ALOGE("SharedMemoryParcelable mmap failed for fd = %d", mFd);
            return AAUDIO_ERROR_INTERNAL;
        }
    }
    *regionAddressPtr = mResolvedAddress + offsetInBytes;
    ALOGV("SharedMemoryParcelable mResolvedAddress = %p", mResolvedAddress);
    ALOGV("SharedMemoryParcelable offset by %d, *regionAddressPtr = %p",
          offsetInBytes, *regionAddressPtr);
    return AAUDIO_OK;
}

int32_t SharedMemoryParcelable::getSizeInBytes() {
    return mSizeInBytes;
}

aaudio_result_t SharedMemoryParcelable::validate() {
    if (mSizeInBytes < 0 || mSizeInBytes >= MAX_MMAP_SIZE_BYTES) {
        ALOGE("SharedMemoryParcelable invalid mSizeInBytes = %d", mSizeInBytes);
        return AAUDIO_ERROR_OUT_OF_RANGE;
    }
    if (mSizeInBytes > 0) {
        if (mFd == -1) {
            ALOGE("SharedMemoryParcelable uninitialized mFd = %d", mFd);
            return AAUDIO_ERROR_INTERNAL;
        }
    }
    return AAUDIO_OK;
}

void SharedMemoryParcelable::dump() {
    ALOGD("SharedMemoryParcelable mFd = %d", mFd);
    ALOGD("SharedMemoryParcelable mSizeInBytes = %d", mSizeInBytes);
    ALOGD("SharedMemoryParcelable mResolvedAddress = %p", mResolvedAddress);
}
