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

#include <stdint.h>

#include <sys/mman.h>
#include <oboe/OboeDefinitions.h>

#include <binder/Parcelable.h>

#include "binding/SharedMemoryParcelable.h"

using android::NO_ERROR;
using android::status_t;
using android::Parcel;
using android::Parcelable;

using namespace oboe;

SharedMemoryParcelable::SharedMemoryParcelable() {}
SharedMemoryParcelable::~SharedMemoryParcelable() {};

void SharedMemoryParcelable::setup(int fd, int32_t sizeInBytes) {
    mFd = fd;
    mSizeInBytes = sizeInBytes;
}

status_t SharedMemoryParcelable::writeToParcel(Parcel* parcel) const {
    parcel->writeInt32(mSizeInBytes);
    if (mSizeInBytes > 0) {
        parcel->writeDupFileDescriptor(mFd);
    }
    return NO_ERROR; // TODO check for errors above
}

status_t SharedMemoryParcelable::readFromParcel(const Parcel* parcel) {
    parcel->readInt32(&mSizeInBytes);
    if (mSizeInBytes > 0) {
        mFd = dup(parcel->readFileDescriptor());
    }
    return NO_ERROR; // TODO check for errors above
}

// TODO Add code to unmmap()

oboe_result_t SharedMemoryParcelable::resolve(int32_t offsetInBytes, int32_t sizeInBytes,
                                              void **regionAddressPtr) {
    if (offsetInBytes < 0) {
        ALOGE("SharedMemoryParcelable illegal offsetInBytes = %d", offsetInBytes);
        return OBOE_ERROR_OUT_OF_RANGE;
    } else if ((offsetInBytes + sizeInBytes) > mSizeInBytes) {
        ALOGE("SharedMemoryParcelable out of range, offsetInBytes = %d, "
              "sizeInBytes = %d, mSizeInBytes = %d",
              offsetInBytes, sizeInBytes, mSizeInBytes);
        return OBOE_ERROR_OUT_OF_RANGE;
    }
    if (mResolvedAddress == nullptr) {
        mResolvedAddress = (uint8_t *) mmap(0, mSizeInBytes, PROT_READ|PROT_WRITE,
                                          MAP_SHARED, mFd, 0);
        if (mResolvedAddress == nullptr) {
            ALOGE("SharedMemoryParcelable mmap failed for fd = %d", mFd);
            return OBOE_ERROR_INTERNAL;
        }
    }
    *regionAddressPtr = mResolvedAddress + offsetInBytes;
    ALOGD("SharedMemoryParcelable mResolvedAddress = %p", mResolvedAddress);
    ALOGD("SharedMemoryParcelable offset by %d, *regionAddressPtr = %p",
          offsetInBytes, *regionAddressPtr);
    return OBOE_OK;
}

int32_t SharedMemoryParcelable::getSizeInBytes() {
    return mSizeInBytes;
}

oboe_result_t SharedMemoryParcelable::validate() {
    if (mSizeInBytes < 0 || mSizeInBytes >= MAX_MMAP_SIZE) {
        ALOGE("SharedMemoryParcelable invalid mSizeInBytes = %d", mSizeInBytes);
        return OBOE_ERROR_INTERNAL;
    }
    if (mSizeInBytes > 0) {
        if (mFd == -1) {
            ALOGE("SharedMemoryParcelable uninitialized mFd = %d", mFd);
            return OBOE_ERROR_INTERNAL;
        }
    }
    return OBOE_OK;
}

void SharedMemoryParcelable::dump() {
    ALOGD("SharedMemoryParcelable mFd = %d", mFd);
    ALOGD("SharedMemoryParcelable mSizeInBytes = %d", mSizeInBytes);
    ALOGD("SharedMemoryParcelable mResolvedAddress = %p", mResolvedAddress);
}
