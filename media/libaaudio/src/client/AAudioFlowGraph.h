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

#ifndef ANDROID_AAUDIO_FLOW_GRAPH_H
#define ANDROID_AAUDIO_FLOW_GRAPH_H

#include <memory>
#include <stdint.h>
#include <sys/types.h>
#include <system/audio.h>

#include <aaudio/AAudio.h>
#include <audio_utils/Balance.h>
#include <flowgraph/Limiter.h>
#include <flowgraph/ManyToMultiConverter.h>
#include <flowgraph/MonoBlend.h>
#include <flowgraph/MonoToMultiConverter.h>
#include <flowgraph/MultiToManyConverter.h>
#include <flowgraph/RampLinear.h>
#include <flowgraph/SampleRateConverter.h>

class AAudioFlowGraph {
public:
    /** Connect several modules together to convert from source to sink.
     * This should only be called once for each instance.
     *
     * @param sourceFormat
     * @param sourceChannelCount
     * @param sourceSampleRate
     * @param sinkFormat
     * @param sinkChannelCount
     * @param sinkSampleRate
     * @param useMonoBlend
     * @param useVolumeRamps
     * @param audioBalance
     * @param resamplerQuality
     * @return
     */
    aaudio_result_t configure(audio_format_t sourceFormat,
                              int32_t sourceChannelCount,
                              int32_t sourceSampleRate,
                              audio_format_t sinkFormat,
                              int32_t sinkChannelCount,
                              int32_t sinkSampleRate,
                              bool useMonoBlend,
                              bool useVolumeRamps,
                              float audioBalance,
                              aaudio::resampler::MultiChannelResampler::Quality resamplerQuality);

    /**
     * Attempt to read targetFramesToRead from the flowgraph.
     * This function returns the number of frames actually read.
     *
     * This function does nothing if process() was not called before.
     *
     * @param destination
     * @param targetFramesToRead
     * @return numFramesRead
     */
    int32_t pull(void *destination, int32_t targetFramesToRead);

    // Reset the entire graph so that volume ramps start at their
    // target value and sample rate converters start with no phase offset.
    void reset() {
        mSink->pullReset();
    }

    /**
     * Set numFramesToWrite frames from the source into the flowgraph.
     * Then, attempt to read targetFramesToRead from the flowgraph.
     * This function returns the number of frames actually read.
     *
     * There may be data still in the flowgraph if targetFramesToRead is not large enough.
     * Before calling process() again, pull() must be called until until all the data is consumed.
     *
     * TODO: b/289510598 - Calculate the exact number of input frames needed for Y output frames.
     *
     * @param source
     * @param numFramesToWrite
     * @param destination
     * @param targetFramesToRead
     * @return numFramesRead
     */
    int32_t process(const void *source, int32_t numFramesToWrite, void *destination,
                    int32_t targetFramesToRead);

    /**
     * @param volume between 0.0 and 1.0
     */
    void setTargetVolume(float volume);

    /**
     * @param audioBalance between -1.0 and 1.0
     */
    void setAudioBalance(float audioBalance);

    /**
     * @param numFrames to slowly adjust for volume changes
     */
    void setRampLengthInFrames(int32_t numFrames);

private:
    std::unique_ptr<FLOWGRAPH_OUTER_NAMESPACE::flowgraph::FlowGraphSourceBuffered> mSource;
    std::unique_ptr<RESAMPLER_OUTER_NAMESPACE::resampler::MultiChannelResampler> mResampler;
    std::unique_ptr<FLOWGRAPH_OUTER_NAMESPACE::flowgraph::SampleRateConverter> mRateConverter;
    std::unique_ptr<FLOWGRAPH_OUTER_NAMESPACE::flowgraph::MonoBlend> mMonoBlend;
    std::unique_ptr<FLOWGRAPH_OUTER_NAMESPACE::flowgraph::Limiter> mLimiter;
    std::unique_ptr<FLOWGRAPH_OUTER_NAMESPACE::flowgraph::MonoToMultiConverter> mChannelConverter;
    std::unique_ptr<FLOWGRAPH_OUTER_NAMESPACE::flowgraph::ManyToMultiConverter>
            mManyToMultiConverter;
    std::unique_ptr<FLOWGRAPH_OUTER_NAMESPACE::flowgraph::MultiToManyConverter>
            mMultiToManyConverter;
    std::vector<std::unique_ptr<FLOWGRAPH_OUTER_NAMESPACE::flowgraph::RampLinear>> mVolumeRamps;
    std::vector<float> mPanningVolumes;
    float mTargetVolume = 1.0f;
    android::audio_utils::Balance mBalance;
    std::unique_ptr<FLOWGRAPH_OUTER_NAMESPACE::flowgraph::FlowGraphSink> mSink;
};


#endif //ANDROID_AAUDIO_FLOW_GRAPH_H
