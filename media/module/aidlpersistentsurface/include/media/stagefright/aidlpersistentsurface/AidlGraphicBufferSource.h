/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <media/stagefright/bqhelper/GraphicBufferSource.h>
#include <media/stagefright/foundation/ABase.h>

#include <media/stagefright/aidlpersistentsurface/IAidlNodeWrapper.h>

#include <utils/Errors.h>

#include <aidl/android/media/BnAidlBufferSource.h>

namespace android::media {

/*
 * This class is used to feed codec encoders from a Surface via BufferQueue or
 * HW producer using AIDL binder interfaces.
 *
 * See media/stagefright/bqhelper/GraphicBufferSource.h for documentation.
 */
class AidlGraphicBufferSource : public GraphicBufferSource {
public:
    AidlGraphicBufferSource() = default;
    virtual ~AidlGraphicBufferSource() = default;

    // For IAidlBufferSource interface
    // ------------------------------

    // When we can start handling buffers.  If we already have buffers of data
    // sitting in the BufferQueue, this will send them to the codec.
    ::ndk::ScopedAStatus onStart();

    // When the codec is meant to return all buffers back to the client for
    // them to be freed. Do NOT submit any more buffers to the component.
    ::ndk::ScopedAStatus onStop();

    // When we are shutting down.
    ::ndk::ScopedAStatus onRelease();

    // Rest of the interface in GraphicBufferSource.

    // IAidlGraphicBufferSource interface
    // ------------------------------

    // Configure the buffer source to be used with a codec2 aidl node given
    // parameters.
    status_t configure(
        const sp<IAidlNodeWrapper> &aidlNode,
        int32_t dataSpace,
        int32_t bufferCount,
        uint32_t frameWidth,
        uint32_t frameHeight,
        uint64_t consumerUsage);

    // Rest of the interface in GraphicBufferSource.

private:
    DISALLOW_EVIL_CONSTRUCTORS(AidlGraphicBufferSource);
};

}  // namespace android::media
