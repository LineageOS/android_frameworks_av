/*
 * Copyright 2019 The Android Open Source Project
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
#define LOG_TAG "FrameReassembler"

#include <log/log.h>

#include <media/stagefright/foundation/AMessage.h>

#include "FrameReassembler.h"

namespace android {

static constexpr uint64_t kToleranceUs = 1000;  // 1ms

FrameReassembler::FrameReassembler()
    : mUsage{0, 0},
      mSampleRate(0u),
      mChannelCount(0u),
      mEncoding(C2Config::PCM_16),
      mCurrentOrdinal({0, 0, 0}) {
}

void FrameReassembler::init(
        const std::shared_ptr<C2BlockPool> &pool,
        C2MemoryUsage usage,
        uint32_t frameSize,
        uint32_t sampleRate,
        uint32_t channelCount,
        C2Config::pcm_encoding_t encoding) {
    mBlockPool = pool;
    mUsage = usage;
    mFrameSize = frameSize;
    mSampleRate = sampleRate;
    mChannelCount = channelCount;
    mEncoding = encoding;
}

void FrameReassembler::updateFrameSize(uint32_t frameSize) {
    finishCurrentBlock(&mPendingWork);
    mFrameSize = frameSize;
}

void FrameReassembler::updateSampleRate(uint32_t sampleRate) {
    finishCurrentBlock(&mPendingWork);
    mSampleRate = sampleRate;
}

void FrameReassembler::updateChannelCount(uint32_t channelCount) {
    finishCurrentBlock(&mPendingWork);
    mChannelCount = channelCount;
}

void FrameReassembler::updatePcmEncoding(C2Config::pcm_encoding_t encoding) {
    finishCurrentBlock(&mPendingWork);
    mEncoding = encoding;
}

void FrameReassembler::reset() {
    flush();
    mCurrentOrdinal = {0, 0, 0};
    mBlockPool.reset();
    mFrameSize.reset();
    mSampleRate = 0u;
    mChannelCount = 0u;
    mEncoding = C2Config::PCM_16;
}

FrameReassembler::operator bool() const {
    return mFrameSize.has_value();
}

c2_status_t FrameReassembler::process(
        const sp<MediaCodecBuffer> &buffer,
        std::list<std::unique_ptr<C2Work>> *items) {
    int64_t timeUs;
    if (!buffer->meta()->findInt64("timeUs", &timeUs)) {
        return C2_BAD_VALUE;
    }

    items->splice(items->end(), mPendingWork);

    // Fill mCurrentBlock
    if (mCurrentBlock) {
        // First check the timestamp
        c2_cntr64_t endTimestampUs = mCurrentOrdinal.timestamp;
        endTimestampUs += bytesToSamples(mWriteView->size()) * 1000000 / mSampleRate;
        if (timeUs < endTimestampUs.peek()) {
            uint64_t diffUs = (endTimestampUs - timeUs).peeku();
            if (diffUs > kToleranceUs) {
                // The timestamp is going back in time in large amount.
                // TODO: b/145702136
                ALOGW("timestamp going back in time! from %lld to %lld",
                        endTimestampUs.peekll(), (long long)timeUs);
            }
        } else {  // timeUs >= endTimestampUs.peek()
            uint64_t diffUs = (timeUs - endTimestampUs).peeku();
            if (diffUs > kToleranceUs) {
                // The timestamp is going forward; add silence as necessary.
                size_t gapSamples = usToSamples(diffUs);
                size_t remainingSamples =
                    (mWriteView->capacity() - mWriteView->size())
                    / mChannelCount / bytesPerSample();
                if (gapSamples < remainingSamples) {
                    size_t gapBytes = gapSamples * mChannelCount * bytesPerSample();
                    memset(mWriteView->base() + mWriteView->size(), 0u, gapBytes);
                    mWriteView->setSize(mWriteView->size() + gapBytes);
                } else {
                    finishCurrentBlock(items);
                }
            }
        }
    }

    if (mCurrentBlock) {
        // Append the data at the end of the current block
        size_t copySize = std::min(
                buffer->size(),
                size_t(mWriteView->capacity() - mWriteView->size()));
        memcpy(mWriteView->base() + mWriteView->size(), buffer->data(), copySize);
        buffer->setRange(buffer->offset() + copySize, buffer->size() - copySize);
        mWriteView->setSize(mWriteView->size() + copySize);
        if (mWriteView->size() == mWriteView->capacity()) {
            finishCurrentBlock(items);
        }
        timeUs += bytesToSamples(copySize) * 1000000 / mSampleRate;
    }

    if (buffer->size() > 0) {
        mCurrentOrdinal.timestamp = timeUs;
        mCurrentOrdinal.customOrdinal = timeUs;
    }

    size_t frameSizeBytes = mFrameSize.value() * mChannelCount * bytesPerSample();
    while (buffer->size() > 0) {
        LOG_ALWAYS_FATAL_IF(
                mCurrentBlock,
                "There's remaining data but the pending block is not filled & finished");
        std::unique_ptr<C2Work> work(new C2Work);
        c2_status_t err = mBlockPool->fetchLinearBlock(frameSizeBytes, mUsage, &mCurrentBlock);
        if (err != C2_OK) {
            return err;
        }
        size_t copySize = std::min(buffer->size(), frameSizeBytes);
        mWriteView = mCurrentBlock->map().get();
        if (mWriteView->error() != C2_OK) {
            return mWriteView->error();
        }
        ALOGV("buffer={offset=%zu size=%zu} copySize=%zu",
                buffer->offset(), buffer->size(), copySize);
        memcpy(mWriteView->base(), buffer->data(), copySize);
        mWriteView->setOffset(0u);
        mWriteView->setSize(copySize);
        buffer->setRange(buffer->offset() + copySize, buffer->size() - copySize);
        if (copySize == frameSizeBytes) {
            finishCurrentBlock(items);
        }
    }

    int32_t eos = 0;
    if (buffer->meta()->findInt32("eos", &eos) && eos) {
        finishCurrentBlock(items);
    }

    return C2_OK;
}

void FrameReassembler::flush() {
    mPendingWork.clear();
    mWriteView.reset();
    mCurrentBlock.reset();
}

uint64_t FrameReassembler::bytesToSamples(size_t numBytes) const {
    return numBytes / mChannelCount / bytesPerSample();
}

size_t FrameReassembler::usToSamples(uint64_t us) const {
    return (us * mChannelCount * mSampleRate / 1000000);
}

uint32_t FrameReassembler::bytesPerSample() const {
    return (mEncoding == C2Config::PCM_8) ? 1
         : (mEncoding == C2Config::PCM_16) ? 2
         : (mEncoding == C2Config::PCM_FLOAT) ? 4 : 0;
}

void FrameReassembler::finishCurrentBlock(std::list<std::unique_ptr<C2Work>> *items) {
    if (!mCurrentBlock) {
        // No-op
        return;
    }
    if (mWriteView->size() < mWriteView->capacity()) {
        memset(mWriteView->base() + mWriteView->size(), 0u,
                mWriteView->capacity() - mWriteView->size());
        mWriteView->setSize(mWriteView->capacity());
    }
    std::unique_ptr<C2Work> work{std::make_unique<C2Work>()};
    work->input.ordinal = mCurrentOrdinal;
    work->input.buffers.push_back(C2Buffer::CreateLinearBuffer(
            mCurrentBlock->share(0, mCurrentBlock->capacity(), C2Fence())));
    work->worklets.clear();
    work->worklets.emplace_back(new C2Worklet);
    items->push_back(std::move(work));

    ++mCurrentOrdinal.frameIndex;
    mCurrentOrdinal.timestamp += mFrameSize.value() * 1000000 / mSampleRate;
    mCurrentOrdinal.customOrdinal = mCurrentOrdinal.timestamp;
    mCurrentBlock.reset();
    mWriteView.reset();
}

}  // namespace android
