/*
 * Copyright 2020 The Android Open Source Project
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

#include "FrameReassembler.h"

#include <gtest/gtest.h>

#include <C2PlatformSupport.h>

#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/AMessage.h>

namespace android {

static size_t BytesPerSample(C2Config::pcm_encoding_t encoding) {
    return encoding == PCM_8 ? 1
         : encoding == PCM_16 ? 2
         : encoding == PCM_FLOAT ? 4 : 0;
}

static uint64_t Diff(c2_cntr64_t a, c2_cntr64_t b) {
    return std::abs((a - b).peek());
}

class FrameReassemblerTest : public ::testing::Test {
public:
    static const C2MemoryUsage kUsage;
    static constexpr uint64_t kTimestampToleranceUs = 100;

    FrameReassemblerTest() {
        mInitStatus = GetCodec2BlockPool(C2BlockPool::BASIC_LINEAR, nullptr, &mPool);
    }

    status_t initStatus() const { return mInitStatus; }

    void testPushSameSize(
            size_t encoderFrameSize,
            size_t sampleRate,
            size_t channelCount,
            C2Config::pcm_encoding_t encoding,
            size_t inputFrameSizeInBytes,
            size_t count,
            size_t expectedOutputSize,
            bool separateEos) {
        FrameReassembler frameReassembler;
        frameReassembler.init(
                mPool,
                kUsage,
                encoderFrameSize,
                sampleRate,
                channelCount,
                encoding);

        ASSERT_TRUE(frameReassembler) << "FrameReassembler init failed";

        size_t inputIndex = 0, outputIndex = 0;
        size_t expectCount = 0;
        for (size_t i = 0; i < count + (separateEos ? 1 : 0); ++i) {
            sp<MediaCodecBuffer> buffer = new MediaCodecBuffer(
                    new AMessage, new ABuffer(inputFrameSizeInBytes));
            buffer->setRange(0, inputFrameSizeInBytes);
            buffer->meta()->setInt64(
                    "timeUs",
                    inputIndex * 1000000 / sampleRate / channelCount / BytesPerSample(encoding));
            if (i == count - 1) {
                buffer->meta()->setInt32("eos", 1);
            }
            if (i == count && separateEos) {
                buffer->setRange(0, 0);
            } else {
                for (size_t j = 0; j < inputFrameSizeInBytes; ++j, ++inputIndex) {
                    buffer->base()[j] = (inputIndex & 0xFF);
                }
            }
            std::list<std::unique_ptr<C2Work>> items;
            ASSERT_EQ(C2_OK, frameReassembler.process(buffer, &items));
            while (!items.empty()) {
                std::unique_ptr<C2Work> work = std::move(*items.begin());
                items.erase(items.begin());
                // Verify timestamp
                uint64_t expectedTimeUs =
                    outputIndex * 1000000 / sampleRate / channelCount / BytesPerSample(encoding);
                EXPECT_GE(
                        kTimestampToleranceUs,
                        Diff(expectedTimeUs, work->input.ordinal.timestamp))
                    << "expected timestamp: " << expectedTimeUs
                    << " actual timestamp: " << work->input.ordinal.timestamp.peeku()
                    << " output index: " << outputIndex;

                // Verify buffer
                ASSERT_EQ(1u, work->input.buffers.size());
                std::shared_ptr<C2Buffer> buffer = work->input.buffers.front();
                ASSERT_EQ(C2BufferData::LINEAR, buffer->data().type());
                ASSERT_EQ(1u, buffer->data().linearBlocks().size());
                C2ReadView view = buffer->data().linearBlocks().front().map().get();
                ASSERT_EQ(C2_OK, view.error());
                ASSERT_EQ(encoderFrameSize * BytesPerSample(encoding), view.capacity());
                for (size_t j = 0; j < view.capacity(); ++j, ++outputIndex) {
                    ASSERT_TRUE(outputIndex < inputIndex
                             || inputIndex == inputFrameSizeInBytes * count)
                        << "inputIndex = " << inputIndex << " outputIndex = " << outputIndex;
                    uint8_t expected = outputIndex < inputIndex ? (outputIndex & 0xFF) : 0;
                    if (expectCount < 10) {
                        ++expectCount;
                        EXPECT_EQ(expected, view.data()[j]) << "output index = " << outputIndex;
                    }
                }
            }
        }

        ASSERT_EQ(inputFrameSizeInBytes * count, inputIndex);
        size_t encoderFrameSizeInBytes =
            encoderFrameSize * channelCount * BytesPerSample(encoding);
        ASSERT_EQ(0, outputIndex % encoderFrameSizeInBytes)
            << "output size must be multiple of frame size: output size = " << outputIndex
            << " frame size = " << encoderFrameSizeInBytes;
        ASSERT_EQ(expectedOutputSize, outputIndex)
            << "output size must be smallest multiple of frame size, "
            << "equal to or larger than input size. output size = " << outputIndex
            << " input size = " << inputIndex << " frame size = " << encoderFrameSizeInBytes;
    }

private:
    status_t mInitStatus;
    std::shared_ptr<C2BlockPool> mPool;
};

const C2MemoryUsage FrameReassemblerTest::kUsage{C2MemoryUsage::CPU_READ, C2MemoryUsage::CPU_WRITE};

// Push frames with exactly the same size as the encoder requested.
TEST_F(FrameReassemblerTest, PushExactFrameSize) {
    ASSERT_EQ(OK, initStatus());
    for (bool separateEos : {false, true}) {
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_8,
                1024 /* input frame size in bytes = 1024 samples * 1 channel * 1 bytes/sample */,
                10 /* count */,
                10240 /* expected output size = 10 * 1024 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_16,
                2048 /* input frame size in bytes = 1024 samples * 1 channel * 2 bytes/sample */,
                10 /* count */,
                20480 /* expected output size = 10 * 2048 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_FLOAT,
                4096 /* input frame size in bytes = 1024 samples * 1 channel * 4 bytes/sample */,
                10 /* count */,
                40960 /* expected output size = 10 * 4096 bytes/frame */,
                separateEos);
    }
}

// Push frames with half the size that the encoder requested.
TEST_F(FrameReassemblerTest, PushHalfFrameSize) {
    ASSERT_EQ(OK, initStatus());
    for (bool separateEos : {false, true}) {
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_8,
                512 /* input frame size in bytes = 512 samples * 1 channel * 1 bytes/sample */,
                10 /* count */,
                5120 /* expected output size = 5 * 1024 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_16,
                1024 /* input frame size in bytes = 512 samples * 1 channel * 2 bytes/sample */,
                10 /* count */,
                10240 /* expected output size = 5 * 2048 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_FLOAT,
                2048 /* input frame size in bytes = 512 samples * 1 channel * 4 bytes/sample */,
                10 /* count */,
                20480 /* expected output size = 5 * 4096 bytes/frame */,
                separateEos);
    }
}

// Push frames with twice the size that the encoder requested.
TEST_F(FrameReassemblerTest, PushDoubleFrameSize) {
    ASSERT_EQ(OK, initStatus());
    for (bool separateEos : {false, true}) {
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_8,
                2048 /* input frame size in bytes = 2048 samples * 1 channel * 1 bytes/sample */,
                10 /* count */,
                20480 /* expected output size = 20 * 1024 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_16,
                4096 /* input frame size in bytes = 2048 samples * 1 channel * 2 bytes/sample */,
                10 /* count */,
                40960 /* expected output size = 20 * 2048 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_FLOAT,
                8192 /* input frame size in bytes = 2048 samples * 1 channel * 4 bytes/sample */,
                10 /* count */,
                81920 /* expected output size = 20 * 4096 bytes/frame */,
                separateEos);
    }
}

// Push frames with a little bit larger (+5 samples) than the requested size.
TEST_F(FrameReassemblerTest, PushLittleLargerFrameSize) {
    ASSERT_EQ(OK, initStatus());
    for (bool separateEos : {false, true}) {
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_8,
                1029 /* input frame size in bytes = 1029 samples * 1 channel * 1 bytes/sample */,
                10 /* count */,
                11264 /* expected output size = 11 * 1024 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_16,
                2058 /* input frame size in bytes = 1029 samples * 1 channel * 2 bytes/sample */,
                10 /* count */,
                22528 /* expected output size = 11 * 2048 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_FLOAT,
                4116 /* input frame size in bytes = 1029 samples * 1 channel * 4 bytes/sample */,
                10 /* count */,
                45056 /* expected output size = 11 * 4096 bytes/frame */,
                separateEos);
    }
}

// Push frames with a little bit smaller (-5 samples) than the requested size.
TEST_F(FrameReassemblerTest, PushLittleSmallerFrameSize) {
    ASSERT_EQ(OK, initStatus());
    for (bool separateEos : {false, true}) {
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_8,
                1019 /* input frame size in bytes = 1019 samples * 1 channel * 1 bytes/sample */,
                10 /* count */,
                10240 /* expected output size = 10 * 1024 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_16,
                2038 /* input frame size in bytes = 1019 samples * 1 channel * 2 bytes/sample */,
                10 /* count */,
                20480 /* expected output size = 10 * 2048 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_FLOAT,
                4076 /* input frame size in bytes = 1019 samples * 1 channel * 4 bytes/sample */,
                10 /* count */,
                40960 /* expected output size = 10 * 4096 bytes/frame */,
                separateEos);
    }
}

// Push single-byte frames
TEST_F(FrameReassemblerTest, PushSingleByte) {
    ASSERT_EQ(OK, initStatus());
    for (bool separateEos : {false, true}) {
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_8,
                1 /* input frame size in bytes */,
                100000 /* count */,
                100352 /* expected output size = 98 * 1024 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_16,
                1 /* input frame size in bytes */,
                100000 /* count */,
                100352 /* expected output size = 49 * 2048 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_FLOAT,
                1 /* input frame size in bytes */,
                100000 /* count */,
                102400 /* expected output size = 25 * 4096 bytes/frame */,
                separateEos);
    }
}

// Push one big chunk.
TEST_F(FrameReassemblerTest, PushBigChunk) {
    ASSERT_EQ(OK, initStatus());
    for (bool separateEos : {false, true}) {
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_8,
                100000 /* input frame size in bytes */,
                1 /* count */,
                100352 /* expected output size = 98 * 1024 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_16,
                100000 /* input frame size in bytes */,
                1 /* count */,
                100352 /* expected output size = 49 * 2048 bytes/frame */,
                separateEos);
        testPushSameSize(
                1024 /* frame size in samples */,
                48000 /* sample rate */,
                1 /* channel count */,
                PCM_FLOAT,
                100000 /* input frame size in bytes */,
                1 /* count */,
                102400 /* expected output size = 25 * 4096 bytes/frame */,
                separateEos);
    }
}

} // namespace android
