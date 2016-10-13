/*
 * Copyright 2016, The Android Open Source Project
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
#define LOG_TAG "OMXBuffer"

#include <media/MediaCodecBuffer.h>
#include <media/OMXBuffer.h>
#include <binder/IMemory.h>
#include <binder/Parcel.h>
#include <ui/GraphicBuffer.h>
#include <utils/NativeHandle.h>

namespace android {

//static
OMXBuffer OMXBuffer::sPreset(static_cast<sp<MediaCodecBuffer> >(NULL));

OMXBuffer::OMXBuffer()
    : mBufferType(kBufferTypeInvalid) {
}

OMXBuffer::OMXBuffer(const sp<MediaCodecBuffer>& codecBuffer)
    : mBufferType(kBufferTypePreset),
      mRangeLength(codecBuffer != NULL ? codecBuffer->size() : 0) {
}

OMXBuffer::OMXBuffer(const sp<IMemory> &mem)
    : mBufferType(kBufferTypeSharedMem),
      mMem(mem) {
}

OMXBuffer::OMXBuffer(const sp<GraphicBuffer> &gbuf)
    : mBufferType(kBufferTypeANWBuffer),
      mGraphicBuffer(gbuf) {
}

OMXBuffer::OMXBuffer(const sp<NativeHandle> &handle)
    : mBufferType(kBufferTypeNativeHandle),
      mNativeHandle(handle) {
}

OMXBuffer::~OMXBuffer() {
}

status_t OMXBuffer::writeToParcel(Parcel *parcel) const {
    parcel->writeInt32(mBufferType);

    switch(mBufferType) {
        case kBufferTypePreset:
        {
            return parcel->writeUint32(mRangeLength);
        }

        case kBufferTypeSharedMem:
        {
            return parcel->writeStrongBinder(IInterface::asBinder(mMem));
        }

        case kBufferTypeANWBuffer:
        {
            return parcel->write(*mGraphicBuffer);
        }

        case kBufferTypeNativeHandle:
        {
            return parcel->writeNativeHandle(mNativeHandle->handle());
        }

        default:
            return BAD_VALUE;
    }
    return BAD_VALUE;
}

status_t OMXBuffer::readFromParcel(const Parcel *parcel) {
    BufferType bufferType = (BufferType) parcel->readInt32();

    switch(bufferType) {
        case kBufferTypePreset:
        {
            mRangeLength = parcel->readUint32();
            break;
        }

        case kBufferTypeSharedMem:
        {
            mMem = interface_cast<IMemory>(parcel->readStrongBinder());
            break;
        }

        case kBufferTypeANWBuffer:
        {
            sp<GraphicBuffer> buffer = new GraphicBuffer();

            status_t err = parcel->read(*buffer);

            if (err != OK) {
                return err;
            }

            mGraphicBuffer = buffer;
            break;
        }

        case kBufferTypeNativeHandle:
        {
            sp<NativeHandle> handle = NativeHandle::create(
                    parcel->readNativeHandle(), true /* ownsHandle */);

            mNativeHandle = handle;
            break;
        }

        default:
            return BAD_VALUE;
    }

    mBufferType = bufferType;
    return OK;
}

} // namespace android




