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

#pragma once

#pragma clang diagnostic push

#pragma clang diagnostic ignored "-Wsign-compare"
#pragma clang diagnostic ignored "-Wunused-parameter"

#include <tensorflow/lite/c/c_api_types.h>
#include <tensorflow/lite/interpreter.h>
#include <tensorflow/lite/kernels/register.h>
#include <tensorflow/lite/model.h>

#pragma clang diagnostic pop

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace aidl::android::hardware::audio::effect {

/**
 * @brief A generic wrapper for a TensorFlow Lite model interpreter.
 *
 * It is designed to be stateless, leaving buffer and stream management (such as padding and
 * creating overlapping windows) to the client.
 *
 */
class LiteRTInstance {
  public:
    // Constructor stores configuration, does not load model yet
    explicit LiteRTInstance(const std::string_view& modelPath);
    ~LiteRTInstance();

    /**
     * @brief Initialization: Loads model, creates delegate, builds interpreter, allocate tensors,
     * and warmup with an model invoke with all zero data, calculate and allocate the work buffer.
     * @param inputSamples Number of input audio samples for each processing cycle.
     * @param overlapSamples The overlapping size in audio samples for model inferencing.
     * The overlapping audio was introduced to enhance the robust of model inferencing result, make
     * it more consistent and reliable.
     * @param numThreads Optional: Number of threads for the interpreter. Default set to `-1`, lets
     * TFLite decide.
     * @return true on success, false on failure.
     */
    bool initialize(size_t inputSamples, size_t overlapSamples, int numThreads = -1);

    /**
     * @brief Checks if the instance has been successfully initialized.
     * @return true if initialized, false otherwise.
     */
    bool isInitialized() const { return mInterpreter != nullptr; }

    // Releases TFLite resources (interpreter, model) in the correct order.
    // Safe to call multiple times or on a non-initialized instance
    void cleanup();

    // Gets a pointer to the underlying TFLite interpreter.
    tflite::Interpreter* interpreter() const { return mInterpreter.get(); }
    // Gets the data type of the primary input tensor.
    TfLiteType inputTensorType() const { return mInputTensorType; }
    // Gets the data type of the primary output tensor.
    TfLiteType outputTensorType() const { return mOutputTensorType; }

    /**
     * @brief Runs a single inference cycle on the current input tensor data.
     *
     * The client must have already populated the input tensor before calling this.
     *
     * @param input A pointer to the client-managed input buffer.
     * @param output A pointer to the client-managed output buffer.
     * @return true if model inference invoke success, false otherwise.
     */
    bool invoke() const;

    /**
     * @brief Gets the total number of elements in the primary input tensor.
     * Determined by the product of its dimensions.
     * @return The size of the input tensor, or 0 if not initialized.
     */
    size_t inputTensorSize() const { return mInputTensorSamples; }

    /**
     * @brief Gets the total number of elements in the primary output tensor.
     * Determined by the product of its dimensions.
     * @return The size of the output tensor, or 0 if not initialized.
     */
    size_t outputTensorSize() const { return mOutputTensorSamples; }

    /**
     * @brief Gets a non-owning view of the input tensor data.
     * @return Span of type T to the data of input tensor.
     */
    template <class T>
    std::span<T> typedInputTensor() const {
        if (!isInitialized()) {
            return std::span<T>();
        }
        return {mInterpreter->typed_input_tensor<T>(0), mInputTensorSamples};
    }

    /**
     * @brief Gets a non-owning view of the output tensor data.
     * @return Span of type T to the data of output tensor.
     */
    template <class T>
    std::span<T> typedOutputTensor() const {
        if (!isInitialized()) {
            return std::span<T>();
        }
        return {mInterpreter->typed_output_tensor<T>(0), mOutputTensorSamples};
    }

    /**
     * @brief Dumps details about the loaded model (inputs, outputs, ops).
     * Useful for debugging. Requires interpreter to be initialized.
     * @return A string containing model details, or an error message.
     */
    std::string dumpModelDetails() const;

    /**
     * @brief Resets the internal buffer.
     */
    void reset();

  protected:
    const std::string mModelPath;
    // Resources (Managed internally)
    std::unique_ptr<tflite::FlatBufferModel> mModel;
    std::unique_ptr<tflite::Interpreter> mInterpreter;
    tflite::ops::builtin::BuiltinOpResolver mResolver;

    size_t mInputTensorSamples = 0;
    TfLiteType mInputTensorType = kTfLiteNoType;
    std::vector<int> mInputTensorDims;

    size_t mOutputTensorSamples = 0;
    TfLiteType mOutputTensorType = kTfLiteNoType;
    std::vector<int> mOutputTensorDims;

    // Internal buffer for managing input audio stream and window sliding.
    std::vector<float> mWorkBuffer;
    // The work buffer padding size.
    size_t mWorkBufPadSize = 0;

    /**
     * @brief Dumps shape information for a specific tensor.
     * @param tensorIndex The index of the tensor.
     * @return A string describing the tensor's shape, or an error message.
     */
    std::string dumpTensorShape(const int tensorIndex) const;

    // Prevent copying and moving as this class manages unique resources.
    LiteRTInstance(const LiteRTInstance&) = delete;
    LiteRTInstance& operator=(const LiteRTInstance&) = delete;
    LiteRTInstance(LiteRTInstance&&) = delete;
    LiteRTInstance& operator=(LiteRTInstance&&) = delete;

    // Performs a warmup inference run, this can help optimize subsequent inference calls.
    bool warmup() const;
};

}  // namespace aidl::android::hardware::audio::effect