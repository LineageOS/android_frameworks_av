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

#define LOG_TAG "AHAL_Classifier"

#include "EraserUtils.h"
#include "Classifier.h"
#include "LiteRTInstance.h"

#include <android-base/logging.h>
#include <algorithm>
#include <utility>
#include <unordered_map>

using aidl::android::media::audio::eraser::Classification;
using aidl::android::media::audio::eraser::ClassificationConfig;
using aidl::android::media::audio::eraser::ClassificationMetadata;
using aidl::android::media::audio::eraser::ClassificationMetadataList;
using aidl::android::media::audio::eraser::SoundClassification;

namespace aidl::android::hardware::audio::effect {

void Classifier::setConfig(const android::media::audio::eraser::Configuration& config) {
    mSoundThresholdMap = buildThresholdMap(config.classificationConfigs);
    mMaxMetadata = config.maxClassificationMetadata;
    setCallback(config.callback);
}

void Classifier::setCallback(
        std::shared_ptr<android::media::audio::eraser::IEraserCallback> callback) {
    mCallback = std::move(callback);
}

std::unordered_map<SoundClassification, float /*threshold*/> Classifier::buildThresholdMap(
        const std::vector<ClassificationConfig>& configs) {
    std::unordered_map<SoundClassification, float> classificationThresholds;
    for (const auto& config : configs) {
        for (const auto& classification : config.classifications) {
            classificationThresholds[classification.classification] = config.confidenceThreshold;
        }
    }
    return classificationThresholds;
}

void Classifier::process(const std::span<float>& input) {
    if (!isInitialized()) {
        LOG(ERROR) << __func__ << ": not initialized";
        return;
    }

    // Add incoming samples to end of buffer
    mWorkBuffer.insert(mWorkBuffer.end(), input.begin(), input.end());

    // Process buffer while it contains enough data for a full tensor
    while (mWorkBuffer.size() >= mInputTensorSamples) {
        std::span<float> inputTensor = typedInputTensor<float>();
        // Copy Tensor size of data from buffer to the model's input
        std::memcpy(inputTensor.data(), mWorkBuffer.data(), mInputTensorSamples * sizeof(float));

        // Invoke the model
        if (!invoke()) {
            LOG(ERROR) << __func__ << " classifier instance invoke failed, dropping data";
            mWorkBuffer.clear();
            return;
        }

        // Read the result directly from the model's output tensor
        const std::span<float> scores = typedOutputTensor<float>();
        if (scores.size() != mOutputTensorSamples) {
            LOG(ERROR) << __func__ << " read classifier output with size " << mOutputTensorSamples
                       << " failed or size mismatch";
            // slide the workbuffer window and skip these data
            mWorkBuffer.erase(mWorkBuffer.begin(), mWorkBuffer.begin() + input.size());
            return;
        }

        // Get max scores by category
        std::unordered_map<SoundClassification, float> categoryScores;
        const auto& categoryMap = getYamnetToCustomCategoryMap();
        for (const auto& [category, indices] : categoryMap) {
            float maxScore = 0.f;
            for (const auto idx : indices) maxScore = std::max(scores[idx], maxScore);
            categoryScores[category] = maxScore;
        }

        // Compare the confidence score to the threshold, add active sound categories to the
        // callback list, record the top sound classification of all active sound categories.
        std::vector<ClassificationMetadata> activeCategories;
        float maxScore = 0;
        Classification maxClassification;
        for (const auto& [category, score] : categoryScores) {
            if (!mSoundThresholdMap.contains(category) || score >= mSoundThresholdMap[category]) {
                Classification currClassification({.classification = category});
                activeCategories.push_back(ClassificationMetadata{
                        .confidenceScore = score, .classification = currClassification});
                if (score > maxScore) {
                    maxScore = score;
                    maxClassification = currClassification;
                }
                LOG(DEBUG) << __func__ << " soundId " << mSoundId
                           << " detected sound: " << toString(category) << ", score: " << score;
            }
        }
        mTopSoundClassification = std::make_pair(maxClassification, maxScore);

        // TODO: update timeMs with the calculated timestamp within the audio stream.
        if (mCallback) {
            mCallback->onClassifierUpdate(
                    mSoundId,
                    ClassificationMetadataList{.timeMs = 0, .metadatas = activeCategories});
            LOG(DEBUG) << __func__ << " SoundID " << mSoundId
                       << " CB with: " << activeCategories.size();
        }

        // Slide the window by erasing the size of input data at the front of work buffer.
        mWorkBuffer.erase(mWorkBuffer.begin(), mWorkBuffer.begin() + input.size());
    }
}

std::pair<Classification, float/*confidenceScore*/> Classifier::getTopClassification() const {
    return mTopSoundClassification;
}

}  // namespace aidl::android::hardware::audio::effect
