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

//#define LOG_NDEBUG 0
#define LOG_TAG "Codec2-InputSurfaceConnection"

#include <android_media_codec.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include <codec2/aidl/inputsurface/FrameQueueThread.h>
#include <codec2/aidl/inputsurface/InputSurfaceConnection.h>
#include <codec2/aidl/inputsurface/InputSurfaceSource.h>

#include <C2AllocatorGralloc.h>
#include <C2BlockInternal.h>

namespace aidl::android::hardware::media::c2::utils {

InputSurfaceConnection::InputSurfaceConnection(
        const std::shared_ptr<IInputSink>& sink,
        ::android::sp<c2::implementation::InputSurfaceSource> const &source)
    : mSink{sink}, mSource{source},
      mQueueThread{std::make_shared<implementation::FrameQueueThread>(sink)}, mFrameIndex(0),
      mAdjustTimestampGapUs(0), mFirstInputFrame(true) {
    if (!mSink) {
        mInit = C2_NO_INIT;
        return;
    }
    mInit = C2_OK;
}

InputSurfaceConnection::~InputSurfaceConnection() {
}

c2_status_t InputSurfaceConnection::status() const {
    return mInit;
}

::ndk::ScopedAStatus InputSurfaceConnection::disconnect() {
    auto source = mSource.promote();
    if (!source) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(C2_CORRUPTED);
    }
    (void)source->stop();
    (void)source->release();

    return ::ndk::ScopedAStatus::ok();
}

::ndk::ScopedAStatus InputSurfaceConnection::signalEndOfStream() {
    auto source = mSource.promote();
    if (!source) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(C2_CORRUPTED);
    }

    c2_status_t status = source->signalEndOfInputStream();
    if (status != C2_OK) {
        return ::ndk::ScopedAStatus::fromServiceSpecificError(status);
    }
    return ::ndk::ScopedAStatus::ok();
}

c2_status_t InputSurfaceConnection::submitBuffer(
        int32_t bufferId, const AImage *buffer, int64_t timestamp, int fenceFd) {
    return submitBufferInternal(bufferId, buffer, timestamp, fenceFd, false);
}

c2_status_t InputSurfaceConnection::submitEos(int32_t bufferId) {
    return submitBufferInternal(bufferId, nullptr, 0, -1, true);
}

void InputSurfaceConnection::dispatchDataSpaceChanged(
            int32_t dataSpace, int32_t aspects, int32_t pixelFormat) {
    (void)aspects;
    (void)pixelFormat;
    android_dataspace d = (android_dataspace)dataSpace;
    mQueueThread->setDataspace(d);
}

void InputSurfaceConnection::setAdjustTimestampGapUs(int32_t gapUs) {
    mAdjustTimestampGapUs = gapUs;
}


void InputSurfaceConnection::onInputBufferDone(c2_cntr64_t index) {
    if (::android::media::codec::provider_->input_surface_throttle()) {
        std::unique_lock<std::mutex> l(mBuffersTracker.mMutex);
        auto it = mBuffersTracker.mIdsInUse.find(index.peeku());
        if (it == mBuffersTracker.mIdsInUse.end()) {
            ALOGV("Untracked input index %llu (maybe already removed)", index.peekull());
            return;
        }
        int32_t bufferId = it->second;
        (void)mBuffersTracker.mIdsInUse.erase(it);
        mBuffersTracker.mAvailableIds.push_back(bufferId);
    } else {
        {
            auto source = mSource.promote();
            if (!source) {
                return;
            }
        }
        int32_t bufferId = 0;
        {
            std::unique_lock<std::mutex> l(mBuffersTracker.mMutex);
            auto it = mBuffersTracker.mIdsInUse.find(index.peeku());
            if (it == mBuffersTracker.mIdsInUse.end()) {
                ALOGV("Untracked input index %llu (maybe already removed)", index.peekull());
                return;
            }
            bufferId = it->second;
            (void)mBuffersTracker.mIdsInUse.erase(it);
        }
        notifyInputBufferEmptied(bufferId);
    }
}

void InputSurfaceConnection::onInputBufferEmptied() {
    if (!::android::media::codec::provider_->input_surface_throttle()) {
        ALOGE("onInputBufferEmptied should not be called "
              "when input_surface_throttle is false");
        return;
    }
    {
        auto source = mSource.promote();
        if (!source) {
            return;
        }
    }
    int32_t bufferId = 0;
    {
        std::unique_lock<std::mutex> l(mBuffersTracker.mMutex);
        if (mBuffersTracker.mAvailableIds.empty()) {
            ALOGV("The codec is ready to take more input buffers "
                    "but no input buffers are ready yet.");
            return;
        }
        bufferId = mBuffersTracker.mAvailableIds.front();
        mBuffersTracker.mAvailableIds.pop_front();
    }
    notifyInputBufferEmptied(bufferId);
}

c2_status_t InputSurfaceConnection::submitBufferInternal(
        int32_t bufferId, const AImage *buffer, int64_t timestamp, int fenceFd, bool eos) {
    // close fenceFd on returning an error.
    ::android::base::unique_fd ufd(fenceFd);
    std::shared_ptr<IInputSink> sink = mSink;
    if (!sink) {
        ALOGE("inputsurface does not have valid sink");
        return C2_BAD_STATE;
    }

    uint32_t c2Flags = (eos == true) ? C2FrameData::FLAG_END_OF_STREAM : 0;
    AHardwareBuffer *hwBuffer = nullptr;

    if (buffer) {
        if (AImage_getHardwareBuffer(buffer, &hwBuffer) != AMEDIA_OK) {
            ALOGE("cannot get AHardwareBuffer form AImage");
            return C2_CORRUPTED;
        }
    } else if (!eos) {
        ALOGE("buffer should be submitted, but was nullptr");
        return C2_BAD_VALUE;
    }

    std::shared_ptr<C2GraphicBlock> block;
    if (hwBuffer) {
        block = _C2BlockFactory::CreateGraphicBlock(hwBuffer);
    }

    std::unique_ptr<C2Work> work(new C2Work);
    work->input.flags = (C2FrameData::flags_t)c2Flags;
    work->input.ordinal.timestamp = timestamp;
    {
        work->input.ordinal.customOrdinal = timestamp; // save input timestamp
        if (mFirstInputFrame) {
            // grab timestamps on first frame
            mPrevInputTimestamp = timestamp;
            mPrevCodecTimestamp = timestamp;
            mFirstInputFrame = false;
        } else if (mAdjustTimestampGapUs > 0) {
            work->input.ordinal.timestamp =
                mPrevCodecTimestamp
                        + c2_min((timestamp - mPrevInputTimestamp).peek(), mAdjustTimestampGapUs);
        } else if (mAdjustTimestampGapUs < 0) {
            work->input.ordinal.timestamp = mPrevCodecTimestamp - mAdjustTimestampGapUs;
        }
        mPrevInputTimestamp = work->input.ordinal.customOrdinal;
        mPrevCodecTimestamp = work->input.ordinal.timestamp;
        ALOGV("adjusting %lld to %lld (gap=%lld)",
              work->input.ordinal.customOrdinal.peekll(),
              work->input.ordinal.timestamp.peekll(),
              (long long)mAdjustTimestampGapUs);
    }

    work->input.ordinal.frameIndex = mFrameIndex++;
    work->input.buffers.clear();
    if (block) {
        std::shared_ptr<C2Buffer> c2Buffer(
                C2Buffer::CreateGraphicBuffer(block->share(
                        C2Rect(block->width(), block->height()), ::C2Fence())));
        work->input.buffers.push_back(c2Buffer);
        std::shared_ptr<C2StreamHdrStaticInfo::input> staticInfo;
        std::shared_ptr<C2StreamHdrDynamicMetadataInfo::input> dynamicInfo;
        ::android::GetHdrMetadataFromGralloc4Handle(
                block->handle(),
                &staticInfo,
                &dynamicInfo);
        if (staticInfo && *staticInfo) {
            c2Buffer->setInfo(staticInfo);
        }
        if (dynamicInfo && *dynamicInfo) {
            c2Buffer->setInfo(dynamicInfo);
        }
    }
    work->worklets.clear();
    work->worklets.emplace_back(new C2Worklet);
    {
        std::unique_lock<std::mutex> l(mBuffersTracker.mMutex);
        mBuffersTracker.mIdsInUse.emplace(work->input.ordinal.frameIndex.peeku(), bufferId);
    }
    mQueueThread->queue(std::move(work), ufd.release());

    return C2_OK;
}

void InputSurfaceConnection::notifyInputBufferEmptied(int32_t bufferId) {
    auto source = mSource.promote();
    if (!source) {
        return;
    }
    source->onInputBufferEmptied(bufferId, -1);
}

}  // namespace aidl::android::hardware::media::c2::utils
