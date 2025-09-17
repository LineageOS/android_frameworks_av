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

#define LOG_TAG "AHAL_Separator"

#include "Separator.h"

#include <android-base/logging.h>
#include <cstring>
#include <memory>

namespace aidl::android::hardware::audio::effect {

bool Separator::process(const std::span<float>& input, std::vector<std::vector<float>>& outputs) {
    if (!isInitialized()) {
        LOG(ERROR) << "Separator not initialized, skipping process";
        return false;
    }

    // Ensure the internal separated buffer is the correct size.
    if (outputs.size() != mOutputChannels) {
        LOG(ERROR) << "Output channels " << outputs.size() << " mismatch with " << mOutputChannels;
        return false;
    }

    const auto inputSamples = input.size();
    size_t padSizeAtEnd = 0;
    // most likely at the end of stream, zero padding to run the last inference
    if (mWorkBuffer.size() + inputSamples < mInputTensorSamples) {
        padSizeAtEnd = mInputTensorSamples - mWorkBuffer.size() - inputSamples;
        // This is the last batch audio samples, zero padding at the end
        std::fill_n(std::back_inserter(mWorkBuffer), padSizeAtEnd, 0.f);
    }

    // Append new input data to the end of work buffer.
    mWorkBuffer.insert(mWorkBuffer.end(), input.begin(), input.end());

    const auto outputChSamples = mOutputTensorSamples / mOutputChannels;
    // Get the model interpreter input/output tensor flatbuffer.
    auto inputTensor = typedInputTensor<float>();
    auto outputTensor = typedOutputTensor<float>();
    // Process all complete windows in the buffer.
    while (mWorkBuffer.size() >= mInputTensorSamples) {
        // Copy one window of audio samples from workbuffer to tensor flatbuffer.
        std::copy(mWorkBuffer.begin(), mWorkBuffer.begin() + mInputTensorSamples,
                  inputTensor.begin());

        // Run separator model inference.
        if (!invoke()) {
            LOG(ERROR) << " Separator interpreter invocation failed.";
            // Clear buffer to prevent repeated failures on the same data.
            mWorkBuffer.clear();
            return false;
        }

        // Skip the overlap at the beginning and copy output tensor from flatbuffer.
        const size_t flatBufStartIdx = outputChSamples - padSizeAtEnd - inputSamples,
                     flatBufEndIdx = outputChSamples - padSizeAtEnd;
        for (size_t ch = 0; ch < mOutputChannels; ++ch) {
            std::copy(&outputTensor[ch * outputChSamples + flatBufStartIdx],
                      &outputTensor[ch * outputChSamples + flatBufEndIdx], outputs[ch].begin());
        }

        // slide the window by erasing the size of input data from the front of work buffer
        mWorkBuffer.erase(mWorkBuffer.begin(), mWorkBuffer.begin() + inputSamples);
    }

    return true;
}

}  // namespace aidl::android::hardware::audio::effect
