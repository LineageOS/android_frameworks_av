/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef C2_SOFT_AAC_ENC_H_

#define C2_SOFT_AAC_ENC_H_

#include <SimpleC2Component.h>
#include <media/stagefright/foundation/ABase.h>

#include "aacenc_lib.h"

namespace android {

class C2SoftAacEnc : public SimpleC2Component {
public:
    C2SoftAacEnc(const char *name, c2_node_id_t id);
    virtual ~C2SoftAacEnc();

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
    HANDLE_AACENCODER mAACEncoder;

    uint32_t mNumChannels;
    uint32_t mSampleRate;
    uint32_t mBitRate;
    int32_t mSBRMode;
    int32_t mSBRRatio;
    AUDIO_OBJECT_TYPE mAACProfile;
    UINT mNumBytesPerInputFrame;
    UINT mOutBufferSize;

    bool mSentCodecSpecificData;
    size_t mInputSize;
    int64_t mInputTimeUs;

    bool mSignalledError;

    status_t initEncoder();

    status_t setAudioParams();

    DISALLOW_EVIL_CONSTRUCTORS(C2SoftAacEnc);
};

}  // namespace android

#endif  // C2_SOFT_AAC_ENC_H_
