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

#ifndef FRAME_REASSEMBLER_H_
#define FRAME_REASSEMBLER_H_

#include <set>
#include <memory>

#include <media/MediaCodecBuffer.h>

#include <C2Config.h>
#include <C2Work.h>

namespace android {

class FrameReassembler {
public:
    FrameReassembler();

    void init(
            const std::shared_ptr<C2BlockPool> &pool,
            C2MemoryUsage usage,
            uint32_t frameSize,
            uint32_t sampleRate,
            uint32_t channelCount,
            C2Config::pcm_encoding_t encoding);
    void updateFrameSize(uint32_t frameSize);
    void updateSampleRate(uint32_t sampleRate);
    void updateChannelCount(uint32_t channelCount);
    void updatePcmEncoding(C2Config::pcm_encoding_t encoding);
    void reset();
    void flush();

    explicit operator bool() const;

    c2_status_t process(
            const sp<MediaCodecBuffer> &buffer,
            std::list<std::unique_ptr<C2Work>> *items);

private:
    std::shared_ptr<C2BlockPool> mBlockPool;
    C2MemoryUsage mUsage;
    std::optional<uint32_t> mFrameSize;
    uint32_t mSampleRate;
    uint32_t mChannelCount;
    C2Config::pcm_encoding_t mEncoding;
    std::list<std::unique_ptr<C2Work>> mPendingWork;
    C2WorkOrdinalStruct mCurrentOrdinal;
    std::shared_ptr<C2LinearBlock> mCurrentBlock;
    std::optional<C2WriteView> mWriteView;

    uint64_t bytesToSamples(size_t numBytes) const;
    size_t usToSamples(uint64_t us) const;
    uint32_t bytesPerSample() const;

    void finishCurrentBlock(std::list<std::unique_ptr<C2Work>> *items);
};

}  // namespace android

#endif  // FRAME_REASSEMBLER_H_
