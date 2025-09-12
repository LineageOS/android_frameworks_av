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

#define LOG_TAG "AHAL_EraserContext"

#include "EraserContext.h"
#include "EraserUtils.h"

#include <android-base/logging.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <algorithm>
#include <cstring>

using aidl::android::media::audio::common::AudioChannelLayout;
using aidl::android::media::audio::eraser::Classification;
using aidl::android::media::audio::eraser::ClassificationMetadata;
using aidl::android::media::audio::eraser::ClassificationMetadataList;
using aidl::android::media::audio::eraser::ClassifierCapability;
using aidl::android::media::audio::eraser::Mode;
using aidl::android::media::audio::eraser::RemixerCapability;
using aidl::android::media::audio::eraser::SeparatorCapability;
using aidl::android::media::audio::eraser::SoundClassification;

namespace aidl::android::hardware::audio::effect {

const ClassifierCapability EraserContext::kClassifierCapability = {
        .windowSizeMs = kClassifierWindowSizeMs,
        .supportedClassifications = {
                Classification{.classification = SoundClassification::HUMAN},
                Classification{.classification = SoundClassification::ANIMAL},
                Classification{.classification = SoundClassification::NATURE},
                Classification{.classification = SoundClassification::MUSIC},
                Classification{.classification = SoundClassification::THINGS},
                Classification{.classification = SoundClassification::AMBIGUOUS},
                Classification{.classification = SoundClassification::ENVIRONMENT},
        }};

const SeparatorCapability EraserContext::kSeparatorCapability = {
        .supported = true, .maxSoundSources = kSeparatorMaxSoundNum};

const RemixerCapability EraserContext::kRemixerCapability = {
        .supported = true, .maxGainFactor = kRemixerGainFactorMax};

const EraserContext::EraserConfiguration EraserContext::kDefaultConfig = {.mode = Mode::CLASSIFIER};

const EraserContext::EraserCapability& EraserContext::getCapability() {
    static const EraserCapability cap({
            .sampleRates = {EraserContext::kSampleRate},
            .channelLayouts = {AudioChannelLayout::make<AudioChannelLayout::layoutMask>(
                    AudioChannelLayout::LAYOUT_MONO)},
            .modes = {Mode::ERASER, Mode::CLASSIFIER},
            .separator = EraserContext::kSeparatorCapability,
            .classifier = EraserContext::kClassifierCapability,
            .remixer = EraserContext::kRemixerCapability,
    });

    return cap;
}

EraserContext::EraserContext(int statusDepth, const Parameter::Common& common)
    : EffectContext(statusDepth, common), mCommon(common), mConfig(kDefaultConfig) {
    LOG(DEBUG) << __func__ << ": Creating EraserContext";
}

EraserContext::~EraserContext() {
    LOG(DEBUG) << __func__ << ": Destroying EraserContext";
}

RetCode EraserContext::enable() {
    const size_t inputSamples = getInputFrameSize() * mCommon.input.frameCount / sizeof(float);
    const size_t minOverlapSamples = inputSamples >> 1;
    size_t numClassifier = 1;
    if (mConfig.mode == Mode::ERASER) {
        if (!mSeparator) {
            mSeparator = std::make_unique<Separator>(kSeparatorModelPath, kSeparatorMaxSoundNum);
        }
        if (!mSeparator || !mSeparator->initialize(inputSamples, minOverlapSamples)) {
            LOG(ERROR) << __func__ << "Failed to initialize separator";
            return RetCode::ERROR_EFFECT_LIB_ERROR;
        }
        numClassifier = kSeparatorMaxSoundNum;
    }

    numClassifier = numClassifier - mClassifiers.size();
    for (size_t soundId = 0; soundId < numClassifier; soundId ++) {
        auto classifierInstance = std::make_unique<Classifier>(kClassifierModelPath, soundId);
        if (!classifierInstance ||
            !classifierInstance->initialize(inputSamples, minOverlapSamples)) {
            LOG(ERROR) << __func__ << "Failed to initialize classifier, cleanup all instances";
            mClassifiers.clear();
            mSeparator.reset();
            return RetCode::ERROR_EFFECT_LIB_ERROR;
        }

        classifierInstance->setConfig(mConfig);
        mClassifiers.emplace_back(std::move(classifierInstance));
    }
    return RetCode::SUCCESS;
}

RetCode EraserContext::disable() {
    return reset();
}

RetCode EraserContext::reset() {
    std::for_each(mClassifiers.begin(), mClassifiers.end(),
                  [](auto& classifier) { classifier->reset(); });

    if (mSeparator) {
        mSeparator->reset();
    }
    return RetCode::SUCCESS;
}

std::optional<Eraser> EraserContext::getParam(Eraser::Tag tag) {
    switch (tag) {
        case Eraser::capability:
            return Eraser::make<Eraser::capability>(getCapability());
        case Eraser::configuration:
            return Eraser::make<Eraser::configuration>(mConfig);
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return std::nullopt;
        }
    }
}

ndk::ScopedAStatus EraserContext::setParam(Eraser eraser) {
    const auto tag = eraser.getTag();
    switch (tag) {
        case Eraser::configuration: {
            mConfig = eraser.get<Eraser::configuration>();
            LOG(DEBUG) << __func__ << " config: " << mConfig.toString();
            std::for_each(mClassifiers.begin(), mClassifiers.end(), [&](auto& classifier) {
                if (classifier) classifier->setConfig(mConfig);
            });

            return ndk::ScopedAStatus::ok();
        }
        default: {
            LOG(ERROR) << __func__ << " unsupported tag: " << toString(tag);
            return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
        }
    }
}

IEffect::Status EraserContext::process(float* in, float* out, int samples) {
    IEffect::Status procStatus = {EX_ILLEGAL_ARGUMENT, 0, 0};
    RETURN_VALUE_IF(!in, procStatus, "nullInput");
    RETURN_VALUE_IF(!out, procStatus, "nullOutput");

    const auto inputChCount = common::getChannelCount(mCommon.input.base.channelMask);
    const auto outputChCount = common::getChannelCount(mCommon.output.base.channelMask);
    if (inputChCount == 0 || outputChCount == 0) {
        LOG(ERROR) << __func__ << " invalid channel count, in: " << inputChCount
                   << " out: " << outputChCount;
        return procStatus;
    }
    const int inputFrames = samples / inputChCount;

    const std::span<float> inputData(in, in + samples);
    std::span<float> outputData(out, out + samples);

    if (mConfig.mode == Mode::ERASER && mSeparator &&
        mClassifiers.size() == kSeparatorMaxSoundNum) {
        std::vector<std::vector<float>> separatedBuffer(kSeparatorMaxSoundNum,
                                                        std::vector<float>(samples, 0.f));
        // Separate the input into multiple channels.
        if (!mSeparator->process(inputData, separatedBuffer)) {
            return procStatus;
        }

        // Classify each separated channel to determine the sound classification and confidence
        // score, find the target gainFactor for the sound classification.
        std::vector<std::pair<std::vector<float> /*audioSamples*/, float /*gainFactor*/>>
                remixerInputs;
        for (size_t i = 0; i < kSeparatorMaxSoundNum; i++) {
            const std::span<float> inputSpan{separatedBuffer[i]};
            mClassifiers[i]->process(inputSpan);
            // Get the gainFactor for the classified sound classification.
            const auto classificationScore = mClassifiers[i]->getTopClassification();
            float gain = 1.f;
            for (const auto& cfg : mConfig.classificationConfigs) {
                if (std::find(cfg.classifications.begin(), cfg.classifications.end(),
                              classificationScore.first /*Classification*/) !=
                            cfg.classifications.end() &&
                    classificationScore.second /*confidenceScore*/ >= cfg.confidenceThreshold) {
                    gain = cfg.gainFactor;
                    break;
                }
            }
            remixerInputs.emplace_back(separatedBuffer[i], gain);
        }

        // Remix with gainFactor for each channel based on the configuration.
        if (!Remixer::process(remixerInputs, outputData)) return procStatus;
    } else if (mConfig.mode == Mode::CLASSIFIER && mClassifiers.size() > 0) {
        // For classifier-only mode, only the first classifier instance used, the original audio
        // pass through to output.
        mClassifiers[0]->process(inputData);
        std::memcpy(out, in, samples * sizeof(float));
    } else {
        // Default pass-through if there are missing components.
        std::memcpy(out, in, samples * sizeof(float));
    }

    return IEffect::Status{.status = STATUS_OK,
                           .fmqConsumed = static_cast<int32_t>(inputFrames * inputChCount),
                           .fmqProduced = static_cast<int32_t>(inputFrames * outputChCount)};
}

}  // namespace aidl::android::hardware::audio::effect
