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

#include "LiteRTInstance.h"

#include <aidl/android/media/audio/eraser/Configuration.h>
#include <aidl/android/media/audio/eraser/IEraserCallback.h>
#include <android-base/logging.h>

#include <cstdio>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>

namespace aidl::android::hardware::audio::effect {

/**
 * Manages the sound classification model for stream-based audio.
 *
 * This class encapsulates a TFLite sound classification model, manages internal buffering,
 * windowing for model input, audio data overlapping for more robust classification result, running
 * inference, and invoking callbacks with the results.
 *
 * The classifier is designed to operate on a continuous stream of audio data, making it suitable
 * for real-time applications.
 */
class Classifier final : public LiteRTInstance {
  public:
    Classifier(const std::string& modelPath, int soundId)
        : LiteRTInstance(modelPath), mSoundId(soundId) {}

    ~Classifier() { LOG(DEBUG) << __func__; }

    /**
     * @brief Sets the eraser configurations to classifier instance.
     *
     * @param config Eraser configuration to set.
     */
    void setConfig(const android::media::audio::eraser::Configuration& config);

    /**
     * @brief Run the classification model with the input audio samples.
     *
     * When the input audio accumulated to be more than the model input tensor size, copy the input
     * audio to the model's input tensor and inference. The results of the inference are then sent
     * via the registered callback.
     * The process does not make any change to the input audio and does not produce output audio.
     */
    void process(const std::span<float>& input);

    // Get the top sound classification result.
    std::pair<android::media::audio::eraser::Classification, float /*confidenceScore*/>
    getTopClassification() const;

  private:
    // Eraser callback registered by the client.
    std::shared_ptr<android::media::audio::eraser::IEraserCallback> mCallback;
    // Sound ID to identify separated sounds, always 0 for the CLASSIFIER mode.
    int mSoundId = 0;
    // Maximum number of classification metadata generated.
    int mMaxMetadata = 0;
    // Mapping of SoundClassification and the classification confidencial score threshold.
    std::unordered_map<android::media::audio::eraser::SoundClassification, float /*threshold*/>
            mSoundThresholdMap;
    // The latest top sound classification.
    std::pair<android::media::audio::eraser::Classification, float /*confidenceScore*/>
            mTopSoundClassification;

    /**
     * @brief Sets the callback interface for reporting classification results.
     *
     * The provided callback will be invoked when new classification results are available after
     * processing audio data.
     *
     * @param callback An IEraserCallback shared pointer to handle classification updates.
     */
    void setCallback(std::shared_ptr<android::media::audio::eraser::IEraserCallback> callback);

    /**
     * @brief Build a map of sound classification and corresponding confidence score threshold.
     */
    static std::unordered_map<android::media::audio::eraser::SoundClassification,
                              float /*threshold*/>
    buildThresholdMap(
            const std::vector<android::media::audio::eraser::ClassificationConfig>& configs);
};

}  // namespace aidl::android::hardware::audio::effect
