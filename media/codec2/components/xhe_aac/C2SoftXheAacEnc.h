/*
* Copyright (C) 2025 The Android Open Source Project
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

#ifndef ANDROID_C2_SOFT_XHE_AAC_ENC_H_
#define ANDROID_C2_SOFT_XHE_AAC_ENC_H_

#include <atomic>
#include <optional>

#include <SimpleC2Component.h>
#include <util/C2InterfaceHelper.h>

#include "xHEAACEnc.h"

namespace android {

class C2SoftXheAacEnc final : public SimpleC2Component {
  public:
    class IntfImpl;

    C2SoftXheAacEnc(const char *name, c2_node_id_t id, const std::shared_ptr<IntfImpl> &intfImpl);
    C2SoftXheAacEnc(const char *name, c2_node_id_t id,
                    const std::shared_ptr<C2ReflectorHelper> &helper);
    virtual ~C2SoftXheAacEnc();

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
    static constexpr size_t kMaxChannelCount = 2;
    static constexpr uint32_t kMaxQualityLevel = 6;
    static constexpr uint32_t kDefaultQualityLevel = 3;

    std::shared_ptr<IntfImpl> mIntf{};

    IIS_XHEAACENC_INSTANCE_HANDLE mInstance{};

    uint32_t mFrameSize;
    uint32_t mOutBufferSize;
    uint32_t mOutSampleRate;
    std::vector<float> mInputBuffer{};

    bool mSentCodecSpecificData;
    std::optional<c2_cntr64_t> mNextFrameTimestampOutputTicks;
    std::optional<c2_cntr64_t> mLastFrameEndTimestampUs;

    bool mSignalledError = false;
    std::atomic_uint64_t mOutIndex{};

    c2_status_t initEncoder();

    IIS_XHEAACENC_CONFIG_INSTANCE_HANDLE setAudioParams();

    C2_DO_NOT_COPY(C2SoftXheAacEnc);
};

}  // namespace android

#endif  // ANDROID_C2_SOFT_XHE_AAC_ENC_H_
