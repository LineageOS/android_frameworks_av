/*
 * Copyright (C) 2019 The Android Open Source Project
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

#ifndef ANDROID_C2_SOFT_OPUS_ENC_H_
#define ANDROID_C2_SOFT_OPUS_ENC_H_

#include <atomic>
#include <SimpleC2Component.h>
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

struct OpusMSEncoder;

namespace android {

struct C2SoftOpusEnc : public SimpleC2Component {
    class IntfImpl;

    C2SoftOpusEnc(const char *name, c2_node_id_t id,
               const std::shared_ptr<IntfImpl> &intfImpl);
    virtual ~C2SoftOpusEnc();

    // From SimpleC2Component
    c2_status_t onInit() override;
    c2_status_t onStop() override;
    void onReset() override;
    void onRelease() override;
    c2_status_t onFlush_sm() override;
    void process(
            const std::unique_ptr<C2Work> &work,
            const std::shared_ptr<C2BlockPool> &pool) override;
    c2_status_t drain(
            uint32_t drainMode,
            const std::shared_ptr<C2BlockPool> &pool) override;
private:
    static const int kMaxNumChannelsSupported = 2;
    static const int kMaxSampleRateSupported = 48000;
    static const int kDefaultFrameDurationMs = 20;
    // For a frame duration of 20ms, payload recommended size is 1276 as per
    // https://www.opus-codec.org/docs/html_api/group__opusencoder.html.
    // For 40ms, 60ms, .. payload size will change proportionately, 1276 x 2, 1276 x 3, ..
    static const int kMaxPayload = 1500; // from tests/test_opus_encode.c

    std::shared_ptr<IntfImpl> mIntf;
    std::shared_ptr<C2LinearBlock> mOutputBlock;

    OpusMSEncoder* mEncoder;
    int16_t* mInputBufferPcm16;

    bool mHeaderGenerated;
    bool mIsFirstFrame;
    bool mEncoderFlushed;
    bool mBufferAvailable;
    bool mSignalledEos;
    bool mSignalledError;
    uint32_t mSampleRate;
    uint32_t mChannelCount;
    uint32_t mFrameDurationMs;
    int64_t mAnchorTimeStamp;
    uint64_t mProcessedSamples;
    // Codec delay in ns
    uint64_t mCodecDelay;
    // Seek pre-roll in ns
    uint64_t mSeekPreRoll;
    int mNumSamplesPerFrame;
    int mBytesEncoded;
    int32_t mFilledLen;
    size_t mNumPcmBytesPerInputFrame;
    std::atomic_uint64_t mOutIndex;
    c2_status_t initEncoder();
    c2_status_t configureEncoder();
    int drainEncoder(uint8_t* outPtr);
    c2_status_t drainInternal(const std::shared_ptr<C2BlockPool>& pool,
                              const std::unique_ptr<C2Work>& work);

    C2_DO_NOT_COPY(C2SoftOpusEnc);
};

}  // namespace android

#endif  // ANDROID_C2_SOFT_OPUS_ENC_H_
