/*
 * Copyright (C) 2024 The Android Open Source Project
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

#ifndef ANDROID_C2_SOFT_IAMF_DEC_H_
#define ANDROID_C2_SOFT_IAMF_DEC_H_

#include <cstddef>
#include <cstdint>
#include <optional>

#include <SimpleC2Component.h>
#include <iamf_tools/iamf_decoder_factory.h>
#include <iamf_tools/iamf_decoder_interface.h>
#include <iamf_tools/iamf_tools_api_types.h>

namespace android {

class C2SoftIamfDec : public SimpleC2Component {
  public:
    // Forward declaration of the C2 interface implementation.
    class IntfImpl;

    C2SoftIamfDec(const char* name, c2_node_id_t id, const std::shared_ptr<IntfImpl>& intfImpl);
    virtual ~C2SoftIamfDec();

    // From SimpleC2Component
    c2_status_t onInit() override;
    c2_status_t onStop() override;
    void onReset() override;
    void onRelease() override;
    c2_status_t onFlush_sm() override;
    void process(const std::unique_ptr<C2Work>& work,
                 const std::shared_ptr<C2BlockPool>& pool) override;
    c2_status_t drain(uint32_t drainMode, const std::shared_ptr<C2BlockPool>& pool) override;

  private:
    // Returns the layout requested by the caller via channel count or mask.
    std::optional<::iamf_tools::api::OutputLayout> getTargetOutputLayout();

    ::iamf_tools::api::IamfDecoderFactory::Settings getIamfDecoderSettings();

    // Clears errors, destroys decoder, zeros state.
    void resetDecodingState();

    // Initializes a decoder without the IAMF config (Descriptor OBUs).  They will be parsed from
    // subsequent calls to Decode.
    c2_status_t createDecoder();

    // Creates a decoder when the Descriptor OBUs are provided as one block and signaled with the
    // codec config flag.
    c2_status_t createNewDecoderWithDescriptorObus(const uint8_t* data, size_t data_size);

    // Fetches any decoded audio from the decoder, writing into work output.
    void getAnyTemporalUnits(const std::unique_ptr<C2Work>& work,
                             const std::shared_ptr<C2BlockPool>& pool);

    // Gets values from the decoder to update parameters like output channel mask, channel count.
    c2_status_t fetchValuesAndUpdateParameters(const std::unique_ptr<C2Work>& work);

    std::shared_ptr<IntfImpl> mIntf;
    std::unique_ptr<::iamf_tools::api::IamfDecoderInterface> mIamfDecoder;

    // Values for tracking if and how output layout config has changed.
    static constexpr uint32_t UNSET_OUTPUT_CHANNEL_MASK = 0;
    uint32_t mCachedOutputChannelMask = UNSET_OUTPUT_CHANNEL_MASK;

    static constexpr uint32_t UNSET_MAX_OUTPUT_CHANNELS = 0;
    uint32_t mCachedMaxOutputChannelCount = UNSET_MAX_OUTPUT_CHANNELS;

    std::optional<::iamf_tools::api::SelectedMix> mActualOutputMix;

    // N.B.: Calculation of this number assumes int16_t samples.
    size_t mOutputBufferSizeBytes = 0;
    bool mCreatedWithDescriptorObus = false;
    bool mFetchedAndUpdatedParameters = false;
    bool mSignalledError = false;
    bool mSignalledEos = false;

    C2_DO_NOT_COPY(C2SoftIamfDec);
};

}  // namespace android

#endif  // ANDROID_C2_SOFT_IAMF_DEC_H_
