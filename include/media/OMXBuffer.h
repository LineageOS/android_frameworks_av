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

#ifndef _OMXBUFFER_H_
#define _OMXBUFFER_H_

#include <cutils/native_handle.h>
#include <media/IOMX.h>
#include <system/window.h>
#include <utils/StrongPointer.h>

namespace android {

class GraphicBuffer;
class IMemory;
class MediaCodecBuffer;
class NativeHandle;
class OMXNodeInstance;

class OMXBuffer {
public:
    // sPreset is used in places where we are referring to a pre-registered
    // buffer on a port. It has type kBufferTypePreset and mRangeLength of 0.
    static OMXBuffer sPreset;

    // Default constructor, constructs a buffer of type kBufferTypeInvalid.
    OMXBuffer();

    // Constructs a buffer of type kBufferTypePreset with mRangeLength set to
    // |codecBuffer|'s size (or 0 if |codecBuffer| is NULL).
    OMXBuffer(const sp<MediaCodecBuffer> &codecBuffer);

    // Constructs a buffer of type kBufferTypeSharedMem.
    OMXBuffer(const sp<IMemory> &mem);

    // Constructs a buffer of type kBufferTypeANWBuffer.
    OMXBuffer(const sp<GraphicBuffer> &gbuf);

    // Constructs a buffer of type kBufferTypeNativeHandle.
    OMXBuffer(const sp<NativeHandle> &handle);

    // Parcelling/Un-parcelling.
    status_t writeToParcel(Parcel *parcel) const;
    status_t readFromParcel(const Parcel *parcel);

    ~OMXBuffer();

private:
    friend class OMXNodeInstance;

    enum BufferType {
        kBufferTypeInvalid = 0,
        kBufferTypePreset,
        kBufferTypeSharedMem,
        kBufferTypeANWBuffer,
        kBufferTypeNativeHandle,
    };

    BufferType mBufferType;

    // kBufferTypePreset
    // If the port is operating in byte buffer mode, mRangeLength is the valid
    // range length. Otherwise the range info should also be ignored.
    OMX_U32 mRangeLength;

    // kBufferTypeSharedMem
    sp<IMemory> mMem;

    // kBufferTypeANWBuffer
    sp<GraphicBuffer> mGraphicBuffer;

    // kBufferTypeNativeHandle
    sp<NativeHandle> mNativeHandle;

    OMXBuffer(const OMXBuffer &);
    OMXBuffer &operator=(const OMXBuffer &);
};

}  // namespace android

#endif  // _OMXBUFFER_H_
