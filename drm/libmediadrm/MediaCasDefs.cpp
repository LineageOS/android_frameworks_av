/*
 * Copyright (C) 2017 The Android Open Source Project
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
#define LOG_TAG "MediaCas"

#include <media/MediaCasDefs.h>
#include <utils/Log.h>
#include <binder/IMemory.h>

namespace android {
namespace media {

///////////////////////////////////////////////////////////////////////////////
namespace MediaCas {

status_t ParcelableCasData::readFromParcel(const Parcel* parcel) {
    return parcel->readByteVector(this);
}

status_t ParcelableCasData::writeToParcel(Parcel* parcel) const  {
    return parcel->writeByteVector(*this);
}

///////////////////////////////////////////////////////////////////////////////

status_t ParcelableCasPluginDescriptor::readFromParcel(const Parcel* /*parcel*/) {
    ALOGE("CAPluginDescriptor::readFromParcel() shouldn't be called");
    return INVALID_OPERATION;
}

status_t ParcelableCasPluginDescriptor::writeToParcel(Parcel* parcel) const {
    status_t err = parcel->writeInt32(mCASystemId);
    if (err != NO_ERROR) {
        return err;
    }
    return parcel->writeString16(mName);
}

} // namespace MediaCas
///////////////////////////////////////////////////////////////////////////////

namespace MediaDescrambler {

DescrambleInfo::DescrambleInfo() {}

DescrambleInfo::~DescrambleInfo() {}

status_t DescrambleInfo::readFromParcel(const Parcel* parcel) {
    status_t err = parcel->readInt32((int32_t*)&dstType);
    if (err != OK) {
        return err;
    }
    if (dstType != kDestinationTypeNativeHandle
            && dstType != kDestinationTypeVmPointer) {
        return BAD_VALUE;
    }

    err = parcel->readInt32((int32_t*)&scramblingControl);
    if (err != OK) {
        return err;
    }

    err = parcel->readUint32((uint32_t*)&numSubSamples);
    if (err != OK) {
        return err;
    }
    if (numSubSamples > 0xffff) {
        return BAD_VALUE;
    }

    subSamples = new DescramblerPlugin::SubSample[numSubSamples];
    if (subSamples == NULL) {
        return NO_MEMORY;
    }

    for (size_t i = 0; i < numSubSamples; i++) {
        err = parcel->readUint32(&subSamples[i].mNumBytesOfClearData);
        if (err != OK) {
            return err;
        }
        err = parcel->readUint32(&subSamples[i].mNumBytesOfEncryptedData);
        if (err != OK) {
            return err;
        }
    }

    srcMem = interface_cast<IMemory>(parcel->readStrongBinder());
    if (srcMem == NULL) {
        return BAD_VALUE;
    }

    err = parcel->readInt32(&srcOffset);
    if (err != OK) {
        return err;
    }

    native_handle_t *nativeHandle = NULL;
    if (dstType == kDestinationTypeNativeHandle) {
        nativeHandle = parcel->readNativeHandle();
        dstPtr = static_cast<void *>(nativeHandle);
    } else {
        dstPtr = NULL;
    }

    err = parcel->readInt32(&dstOffset);
    if (err != OK) {
        return err;
    }

    return OK;
}

status_t DescrambleInfo::writeToParcel(Parcel* parcel) const {
    if (dstType != kDestinationTypeNativeHandle
            && dstType != kDestinationTypeVmPointer) {
        return BAD_VALUE;
    }

    status_t err = parcel->writeInt32((int32_t)dstType);
    if (err != OK) {
        return err;
    }

    err = parcel->writeInt32(scramblingControl);
    if (err != OK) {
        return err;
    }

    err = parcel->writeUint32(numSubSamples);
    if (err != OK) {
        return err;
    }

    for (size_t i = 0; i < numSubSamples; i++) {
        err = parcel->writeUint32(subSamples[i].mNumBytesOfClearData);
        if (err != OK) {
            return err;
        }
        err = parcel->writeUint32(subSamples[i].mNumBytesOfEncryptedData);
        if (err != OK) {
            return err;
        }
    }

    err = parcel->writeStrongBinder(IInterface::asBinder(srcMem));
    if (err != OK) {
        return err;
    }

    err = parcel->writeInt32(srcOffset);
    if (err != OK) {
        return err;
    }

    if (dstType == kDestinationTypeNativeHandle) {
        parcel->writeNativeHandle(static_cast<native_handle_t *>(dstPtr));
    }

    err = parcel->writeInt32(dstOffset);
    if (err != OK) {
        return err;
    }

    return OK;
}

} // namespace MediaDescrambler

} // namespace media
} // namespace android

