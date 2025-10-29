/*
 * Copyright 2024 The Android Open Source Project
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

#include <aidl/android/hardware/media/c2/BnInputSink.h>
#include <aidl/android/hardware/media/c2/BnInputSurfaceConnection.h>
#include <media/NdkImage.h>
#include <utils/RefBase.h>

#include <C2.h>

#include <list>
#include <map>
#include <memory>

namespace aidl::android::hardware::media::c2::implementation {
class InputSurfaceSource;
class FrameQueueThread;
}

class C2Allocator;

namespace aidl::android::hardware::media::c2::utils {

struct InputSurfaceConnection : public BnInputSurfaceConnection {
    InputSurfaceConnection(
            const std::shared_ptr<IInputSink>& sink,
            ::android::sp<c2::implementation::InputSurfaceSource> const &source);
    c2_status_t status() const;

    // Methods from IInputSurfaceConnection follow.
    ::ndk::ScopedAStatus disconnect() override;
    ::ndk::ScopedAStatus signalEndOfStream() override;

    // implementation specific interface.

    // Submit a buffer to the connected component.
    c2_status_t submitBuffer(
            int32_t bufferId,
            const AImage *buffer = nullptr,
            int64_t timestamp = 0,
            int fenceFd = -1);

    // Submit eos to the connected component.
    c2_status_t submitEos(int32_t bufferId);

    // notify dataspace being changed to the component.
    void dispatchDataSpaceChanged(
            int32_t dataSpace, int32_t aspects, int32_t pixelFormat);

    void release();

    // InputSurface config
    void setAdjustTimestampGapUs(int32_t gapUs);

    void onInputBufferDone(c2_cntr64_t index);

    void onInputBufferEmptied();

protected:
    virtual ~InputSurfaceConnection() override;

private:
    c2_status_t mInit;
    std::atomic<bool> mReleased;

    std::shared_ptr<IInputSink> mSink;
    ::android::wp<c2::implementation::InputSurfaceSource> mSource;
    std::shared_ptr<c2::implementation::FrameQueueThread> mQueueThread;

    std::atomic_uint64_t mFrameIndex;

    // WORKAROUND: timestamp adjustment

    // if >0: this is the max timestamp gap, if <0: this is -1 times the fixed timestamp gap
    // if 0: no timestamp adjustment is made
    // note that C2OMXNode can be recycled between encoding sessions.
    int32_t mAdjustTimestampGapUs;
    bool mFirstInputFrame; // true for first input
    c2_cntr64_t mPrevInputTimestamp; // input timestamp for previous frame
    c2_cntr64_t mPrevCodecTimestamp; // adjusted (codec) timestamp for previous frame

    // Tracks the status of buffers
    struct BuffersTracker {
        BuffersTracker() = default;

        // For synchronization of data accesses and/or modifications.
        std::mutex mMutex;
        // Keeps track of buffers that are used by the component. Maps timestamp -> ID
        std::map<uint64_t, uint32_t> mIdsInUse;
        // Keeps track of the buffer IDs that are available after being released from the component.
        std::list<uint32_t> mAvailableIds;
    };
    BuffersTracker mBuffersTracker;

    c2_status_t submitBufferInternal(
            int32_t bufferId, const AImage *buffer, int64_t timestamp, int fenceFd, bool eos);

    void notifyInputBufferEmptied(int32_t bufferId);
};

}  // namespace aidl::android::hardware::media::c2::utils
