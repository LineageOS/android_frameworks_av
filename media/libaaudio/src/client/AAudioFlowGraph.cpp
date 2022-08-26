/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "AAudioFlowGraph"
//#define LOG_NDEBUG 0
#include <utils/Log.h>

#include "AAudioFlowGraph.h"

#include <flowgraph/Limiter.h>
#include <flowgraph/ManyToMultiConverter.h>
#include <flowgraph/MonoBlend.h>
#include <flowgraph/MonoToMultiConverter.h>
#include <flowgraph/MultiToManyConverter.h>
#include <flowgraph/RampLinear.h>
#include <flowgraph/SinkFloat.h>
#include <flowgraph/SinkI16.h>
#include <flowgraph/SinkI24.h>
#include <flowgraph/SinkI32.h>
#include <flowgraph/SourceFloat.h>
#include <flowgraph/SourceI16.h>
#include <flowgraph/SourceI24.h>
#include <flowgraph/SourceI32.h>

using namespace FLOWGRAPH_OUTER_NAMESPACE::flowgraph;

aaudio_result_t AAudioFlowGraph::configure(audio_format_t sourceFormat,
                          int32_t sourceChannelCount,
                          audio_format_t sinkFormat,
                          int32_t sinkChannelCount,
                          bool useMonoBlend,
                          float audioBalance,
                          bool isExclusive) {
    FlowGraphPortFloatOutput *lastOutput = nullptr;

    // TODO change back to ALOGD
    ALOGI("%s() source format = 0x%08x, channels = %d, sink format = 0x%08x, channels = %d, "
          "useMonoBlend = %d, audioBalance = %f, isExclusive %d",
          __func__, sourceFormat, sourceChannelCount, sinkFormat, sinkChannelCount,
          useMonoBlend, audioBalance, isExclusive);

    switch (sourceFormat) {
        case AUDIO_FORMAT_PCM_FLOAT:
            mSource = std::make_unique<SourceFloat>(sourceChannelCount);
            break;
        case AUDIO_FORMAT_PCM_16_BIT:
            mSource = std::make_unique<SourceI16>(sourceChannelCount);
            break;
        case AUDIO_FORMAT_PCM_24_BIT_PACKED:
            mSource = std::make_unique<SourceI24>(sourceChannelCount);
            break;
        case AUDIO_FORMAT_PCM_32_BIT:
            mSource = std::make_unique<SourceI32>(sourceChannelCount);
            break;
        default:
            ALOGE("%s() Unsupported source format = %d", __func__, sourceFormat);
            return AAUDIO_ERROR_UNIMPLEMENTED;
    }
    lastOutput = &mSource->output;

    if (useMonoBlend) {
        mMonoBlend = std::make_unique<MonoBlend>(sourceChannelCount);
        lastOutput->connect(&mMonoBlend->input);
        lastOutput = &mMonoBlend->output;
    }

    // For a pure float graph, there is chance that the data range may be very large.
    // So we should limit to a reasonable value that allows a little headroom.
    if (sourceFormat == AUDIO_FORMAT_PCM_FLOAT && sinkFormat == AUDIO_FORMAT_PCM_FLOAT) {
        mLimiter = std::make_unique<Limiter>(sourceChannelCount);
        lastOutput->connect(&mLimiter->input);
        lastOutput = &mLimiter->output;
    }

    // Expand the number of channels if required.
    if (sourceChannelCount == 1 && sinkChannelCount > 1) {
        mChannelConverter = std::make_unique<MonoToMultiConverter>(sinkChannelCount);
        lastOutput->connect(&mChannelConverter->input);
        lastOutput = &mChannelConverter->output;
    } else if (sourceChannelCount != sinkChannelCount) {
        ALOGE("%s() Channel reduction not supported.", __func__);
        return AAUDIO_ERROR_UNIMPLEMENTED;
    }

    // Apply volume ramps for only exclusive streams.
    if (isExclusive) {
        // Apply volume ramps to set the left/right audio balance and target volumes.
        // The signals will be decoupled, volume ramps will be applied, before the signals are
        // combined again.
        mMultiToManyConverter = std::make_unique<MultiToManyConverter>(sinkChannelCount);
        mManyToMultiConverter = std::make_unique<ManyToMultiConverter>(sinkChannelCount);
        lastOutput->connect(&mMultiToManyConverter->input);
        for (int i = 0; i < sinkChannelCount; i++) {
            mVolumeRamps.emplace_back(std::make_unique<RampLinear>(1));
            mPanningVolumes.emplace_back(1.0f);
            lastOutput = mMultiToManyConverter->outputs[i].get();
            lastOutput->connect(&(mVolumeRamps[i].get()->input));
            lastOutput = &(mVolumeRamps[i].get()->output);
            lastOutput->connect(mManyToMultiConverter->inputs[i].get());
        }
        lastOutput = &mManyToMultiConverter->output;
        setAudioBalance(audioBalance);
    }

    switch (sinkFormat) {
        case AUDIO_FORMAT_PCM_FLOAT:
            mSink = std::make_unique<SinkFloat>(sinkChannelCount);
            break;
        case AUDIO_FORMAT_PCM_16_BIT:
            mSink = std::make_unique<SinkI16>(sinkChannelCount);
            break;
        case AUDIO_FORMAT_PCM_24_BIT_PACKED:
            mSink = std::make_unique<SinkI24>(sinkChannelCount);
            break;
        case AUDIO_FORMAT_PCM_32_BIT:
            mSink = std::make_unique<SinkI32>(sinkChannelCount);
            break;
        default:
            ALOGE("%s() Unsupported sink format = %d", __func__, sinkFormat);
            return AAUDIO_ERROR_UNIMPLEMENTED;
    }
    lastOutput->connect(&mSink->input);

    return AAUDIO_OK;
}

void AAudioFlowGraph::process(const void *source, void *destination, int32_t numFrames) {
    mSource->setData(source, numFrames);
    mSink->read(destination, numFrames);
}

/**
 * @param volume between 0.0 and 1.0
 */
void AAudioFlowGraph::setTargetVolume(float volume) {
    for (int i = 0; i < mVolumeRamps.size(); i++) {
        mVolumeRamps[i]->setTarget(volume * mPanningVolumes[i]);
    }
    mTargetVolume = volume;
}

/**
 * @param audioBalance between -1.0 and 1.0
 */
void AAudioFlowGraph::setAudioBalance(float audioBalance) {
    if (mPanningVolumes.size() >= 2) {
        float leftMultiplier = 0;
        float rightMultiplier = 0;
        mBalance.computeStereoBalance(audioBalance, &leftMultiplier, &rightMultiplier);
        mPanningVolumes[0] = leftMultiplier;
        mPanningVolumes[1] = rightMultiplier;
        mVolumeRamps[0]->setTarget(mTargetVolume * leftMultiplier);
        mVolumeRamps[1]->setTarget(mTargetVolume * rightMultiplier);
    }
}

/**
 * @param numFrames to slowly adjust for volume changes
 */
void AAudioFlowGraph::setRampLengthInFrames(int32_t numFrames) {
    for (auto& ramp : mVolumeRamps) {
        ramp->setLengthInFrames(numFrames);
    }
}
