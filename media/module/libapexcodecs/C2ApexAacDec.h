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

#include <SimpleC2Interface.h>
#include <apex/ApexCodecsImpl.h>

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
    void drainDecoder();
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
    // A flag to indicate if this is the first buffer being processed.
    bool mIsFirst;
    // A counter for the number of input buffers received.
    size_t mInputBufferCount;
    // A counter for the number of output buffers produced.
    size_t mOutputBufferCount;
    // A flag to indicate if an error has occurred.
    bool mSignalledError;
    // The delay introduced by the output port.
    size_t mOutputPortDelay;

    // A flag to indicate that the end of the input stream has been reached.
    bool mEndOfInput;
    // A flag to indicate that the end of the output stream has been reached.
    bool mEndOfOutput;
    // The number of samples that have been compensated for output delay.
    int32_t mOutputDelayCompensated;
    // The size of the ring buffer used for output delay compensation.
    int32_t mOutputDelayRingBufferSize;
    // The ring buffer itself, used to manage output delay.
    std::unique_ptr<float[]> mOutputDelayRingBuffer;
    // The write position in the ring buffer.
    int32_t mOutputDelayRingBufferWritePos;
    // The read position in the ring buffer.
    int32_t mOutputDelayRingBufferReadPos;
    // The number of samples currently in the ring buffer.
    int32_t mOutputDelayRingBufferFilled;
    // Puts a given number of samples into the ring buffer.
    bool outputDelayRingBufferPutSamples(float *samples, int numSamples);
    // Gets a given number of samples from the ring buffer.
    int32_t outputDelayRingBufferGetSamples(float *samples, int numSamples);
    // Returns the number of samples currently available to be read from the ring buffer.
    int32_t outputDelayRingBufferSamplesAvailable();
    // Returns the amount of space (in samples) left in the ring buffer for writing.
    int32_t outputDelayRingBufferSpaceLeft();

    struct FrameInfo {
        uint64_t frameIndex;
        uint64_t timestamp;
        size_t numSamples;
    };
    std::deque<FrameInfo> mPendingFrameInfos;
    std::deque<FrameInfo> mRingBufferFrameInfos;

    C2_DO_NOT_COPY(C2ApexAacDec);
};

}  // namespace android

#endif  // ANDROID_C2_APEX_AAC_DEC_H_
