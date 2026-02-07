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

#ifndef ANDROID_C2_APEX_AAC_DEC_H_
#define ANDROID_C2_APEX_AAC_DEC_H_

#include <deque>
#include <list>
#include <memory>
#include <vector>
#include <queue>

#include <SimpleC2Interface.h>
#include <apex/ApexCodecsImpl.h>

#include "DrcPresModeWrapRustAac.h"

extern "C" {
    #include "aacdecoder_lib.h"
    #include "aacdec_errorcodes.h"
    #include "aacdec_info.h"
}

namespace android {

class C2ApexAacDec : public ::android::apexcodecs::ApexComponentIntf {
public:
    static constexpr char COMPONENT_NAME[] = "c2.android.inproc.aac.decoder";

private:
    class IntfImpl;

public:
    explicit C2ApexAacDec(const std::shared_ptr<IntfImpl>& intfImpl);
    virtual ~C2ApexAacDec();

    static std::unique_ptr<::android::apexcodecs::ApexComponentIntf> Create(
            const std::shared_ptr<C2ReflectorHelper>& helper);
    static std::shared_ptr<C2Component::Traits> MakeTraits();
    static void *Map(void *addr, size_t size, int prot, int flags, int fd, off_t offset);
    static int Unmap(void *addr, size_t size);

    // From ApexComponentIntf
    ApexCodec_Status start() override;
    ApexCodec_Status flush() override;
    ApexCodec_Status reset() override;
    std::unique_ptr<::android::apexcodecs::ApexConfigurableIntf> getConfigurable() override;
    ApexCodec_Status process(
            const ApexCodec_Buffer* input,
            ApexCodec_Buffer* output,
            size_t* consumed,
            size_t* produced) override;

private:
    ApexCodec_Status initDecoder();
    void updateParams();
    bool isConfigured() const;
    uint32_t maskFromCount(uint32_t channelCount);

    template <typename... Args>
    static bool AppendParamsToVector(
            std::vector<uint8_t> *configUpdate,
            Args... paramsArg);

    // Manages the component's configuration parameters.
    std::unique_ptr<::android::apexcodecs::ApexConfigurableImpl> mConfigurable;
    // The interface implementation that defines the component's parameters.
    std::shared_ptr<IntfImpl> mIntf;

    // The handle to the core AAC decoder library.
    HANDLE_AACDECODER mAACDecoder;
    // Holds information about the output audio stream from the decoder.
    OutputInfo mOutputInfo;
    StreamInfo mStreamInfo;
    MetadataInfo mMetadataInfo;
    // DRC wrapper
    DrcPresModeWrapRustAac mDrcWrap;
    // A flag to indicate if this is the first input buffer being processed.
    bool mIsFirstInput;
    // A flag to indicate if this is the first output buffer being processed.
    bool mIsFirstOutput;
    // A flag to indicate if an error has occurred.
    bool mSignalledError;

    // A flag to indicate that the end of the input stream has been reached.
    bool mEndOfInput;
    // A flag to indicate that the end of the output stream has been reached.
    bool mEndOfOutput;
    // The current timestamp for the output buffer.
    uint64_t mCurrentTimestampUs;
    // The current frame index for the output buffer.
    uint64_t mCurrentFrameIndex;
    // The number of samples to discard from the beginning of the output.
    int32_t mSamplesToDiscard;
    // The buffer to hold the leftover samples from the previous output.
    std::vector<float> mLeftoverBuffer;
    // The number of leftover samples from the previous output.
    size_t mLeftoverSamples;
    // The queue to hold the timestamps of the pending input buffers.
    std::queue<std::pair<uint64_t, uint64_t>> mPendingTimestamps;
    // The device API level.
    const int32_t mDeviceApiLevel;

    C2_DO_NOT_COPY(C2ApexAacDec);
};

}  // namespace android

#endif  // ANDROID_C2_APEX_AAC_DEC_H_
