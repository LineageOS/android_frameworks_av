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

#define LOG_TAG "AHAL_LiteRTInstance"

#include <sstream>
#include <string>

#include <android-base/logging.h>

#include "LiteRTInstance.h"

namespace aidl::android::hardware::audio::effect {

namespace {
// Helper to convert TfLiteType to a human-readable string.
const char* tfliteTypeToString(TfLiteType type) {
    switch (type) {
        case kTfLiteNoType:
            return "NoType";
        case kTfLiteFloat32:
            return "Float32";
        case kTfLiteInt32:
            return "Int32";
        case kTfLiteUInt8:
            return "UInt8";
        case kTfLiteInt64:
            return "Int64";
        case kTfLiteString:
            return "String";
        case kTfLiteBool:
            return "Bool";
        case kTfLiteInt16:
            return "Int16";
        case kTfLiteComplex64:
            return "Complex64";
        case kTfLiteInt8:
            return "Int8";
        case kTfLiteFloat16:
            return "Float16";
        case kTfLiteFloat64:
            return "Float64";
        case kTfLiteComplex128:
            return "Complex128";
        case  kTfLiteUInt64:
            return "Uint64";
        case kTfLiteResource:
            return "Resource";
        case kTfLiteVariant:
            return "Variant";
        case kTfLiteUInt32:
            return "UInt32";
        case kTfLiteUInt16:
            return "UInt16";
    }
    return "Unknown";
}

// Helper to calculate the total number of elements in a tensor.
size_t getTensorSize(const TfLiteTensor* tensor) {
    if (tensor == nullptr || tensor->dims == nullptr) {
        return 0;
    }
    size_t size = 1;
    for (int i = 0; i < tensor->dims->size; ++i) {
        size *= tensor->dims->data[i];
    }
    return size;
}

}  // namespace

LiteRTInstance::LiteRTInstance(const std::string_view& modelPath) : mModelPath(modelPath) {
    LOG(DEBUG) << "LiteRTInstance created for model: " << mModelPath;
}

LiteRTInstance::~LiteRTInstance() {
    cleanup();
    LOG(DEBUG) << "LiteRTInstance destructor called for model: " << mModelPath;
}

bool LiteRTInstance::initialize(size_t inputSamples, size_t overlapSamples, int numThreads) {
    if (isInitialized()) {
        LOG(WARNING) << "Instance already initialized for model " << mModelPath;
        return true;
    }

    mModel = tflite::FlatBufferModel::VerifyAndBuildFromFile(std::string(mModelPath).c_str());
    if (!mModel) {
        LOG(ERROR) << "Failed to load model file " << mModelPath;
        return false;
    }

    tflite::InterpreterBuilder builder(*mModel, mResolver);
    const TfLiteStatus status = builder(&mInterpreter);
    if(status != kTfLiteOk || mInterpreter == nullptr) {
        LOG(ERROR) << "Interpreter builder failed with ret " << status << ", interpreter "
                   << mInterpreter;
        cleanup();
        return false;
    }

    if (builder.SetNumThreads(numThreads) != kTfLiteOk) {
        LOG(ERROR) << "Failed to set number of threads to: " << numThreads;
        cleanup();
        return false;
    }

    if (mInterpreter->AllocateTensors() != kTfLiteOk) {
        LOG(ERROR) << "Failed to allocate tensors";
        cleanup();
        return false;
    }

    // Get Input and Output Tensor Details for sanity checks
    if (mInterpreter->inputs().empty() || mInterpreter->outputs().empty()) {
        LOG(ERROR) << "Invalid input/output for model " << mModelPath;
        cleanup();
        return false;
    }

    const auto inputTensorIndex = mInterpreter->inputs()[0];
    TfLiteTensor* inputTensor = mInterpreter->tensor(inputTensorIndex);
    if (!inputTensor || inputTensor->type != kTfLiteFloat32) {
        LOG(ERROR) << " Input tensor invalid or not supported";
        cleanup();
        return false;
    }
    mInputTensorType = inputTensor->type;
    mInputTensorSamples = getTensorSize(inputTensor);
    assert(mInputTensorSamples != 0);

    const auto outputTensorIndex = mInterpreter->outputs()[0];
    TfLiteTensor* outputTensor = mInterpreter->tensor(outputTensorIndex);
    if (!outputTensor || outputTensor->type != kTfLiteFloat32) {
        LOG(ERROR) << " Output tensor invalid or not supported";
        cleanup();
        return false;
    }
    mOutputTensorType = outputTensor->type;
    mOutputTensorSamples = getTensorSize(outputTensor);
    assert(mOutputTensorSamples != 0);

    // prepad the beginning of work buffer
    mWorkBufPadSize = std::max(overlapSamples, mInputTensorSamples - inputSamples);
    mWorkBuffer.assign(mWorkBufPadSize, 0.f);

    LOG(DEBUG) << "Model " << mModelPath << " instance successfully inited: " << dumpModelDetails()
               << " work buffer padding size: " << mWorkBufPadSize;
    return warmup();
}

bool LiteRTInstance::invoke() const {
    if (!isInitialized()) {
        LOG(ERROR) << " instance not initialized.";
        return false;
    }
    TfLiteStatus invokeStatus = mInterpreter->Invoke();
    if (invokeStatus != kTfLiteOk) {
        LOG(ERROR) << " Model " << mModelPath << " invoke failed: " <<  invokeStatus;
        return false;
    }

    return true;
}

// Releases resources in the correct order
void LiteRTInstance::cleanup() {
    // Interpreter must be reset before the delegate it uses
    mInterpreter.reset();
    mModel.reset();
    LOG(DEBUG) << "Instance cleaned up " << mModelPath;
}

void LiteRTInstance::reset() {
    mWorkBuffer.assign(mWorkBufPadSize, 0.f);
}

// warmup inference once with all zero data
bool LiteRTInstance::warmup() const {
    if (!isInitialized()) {
        LOG(DEBUG) << "Warmup called on non-initialized instance: " << mModelPath;
        return false;
    }

    TfLiteStatus invokeStatus = mInterpreter->Invoke();
    if (invokeStatus != kTfLiteOk) {
        LOG(ERROR) << "Model " << mModelPath << " warmup failed: " <<  invokeStatus;
        return false;
    }
    return true;
}

std::string LiteRTInstance::dumpTensorShape(const int tensorIndex) const {
    if (!isInitialized()) {
        return "Not Initialized";
    }
    TfLiteTensor* tensor = mInterpreter->tensor(tensorIndex);
    if (!tensor || !tensor->dims) {
        return "Invalid Tensor or Dims";
    }

    // TODO: move to utility method
    std::ostringstream oss;
    oss << "Name: " << (tensor->name ? tensor->name : "<Unnamed>") << "\n";
    oss << "Type: " << tfliteTypeToString(tensor->type) << "\n";
    oss << "Dimensions: [";
    for (int i = 0; i < tensor->dims->size; ++i) {
        oss << tensor->dims->data[i] << (i == tensor->dims->size - 1 ? "" : ", ");
    }
    oss << "]";
    return oss.str();
}

std::string LiteRTInstance::dumpModelDetails() const {
    if (!isInitialized()) {
       return "uninitialized.";
    }

    std::ostringstream oss;
    oss << "Model Path: " << mModelPath << "\n";
    oss << "Input Tensors (" << mInterpreter->inputs().size() << "):\n";
    for (int index : mInterpreter->inputs()) {
        TfLiteTensor* tensor = mInterpreter->tensor(index);
        oss << "  Index " << index << ": " << (tensor ? tensor->name : "N/A")
            << ", Type " << static_cast<int>(tensor ? tensor->type : kTfLiteNoType)
            << ", Shape " << dumpTensorShape(index) << "\n";
    }

    oss << "Output Tensors (" << mInterpreter->outputs().size() << "):\n";
    for (int index : mInterpreter->outputs()) {
        TfLiteTensor* tensor = mInterpreter->tensor(index);
        oss << "  Index " << index << ": " << (tensor ? tensor->name : "N/A")
            << ", Type " << static_cast<int>(tensor ? tensor->type : kTfLiteNoType)
            << ", Shape " << dumpTensorShape(index) << "\n";
    }
    return oss.str();
}

}  // namespace aidl::android::hardware::audio::effect
