/*
 * Copyright 2019 The Android Open Source Project
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

#ifndef PIPELINE_WATCHER_H_
#define PIPELINE_WATCHER_H_

#include <chrono>
#include <map>
#include <memory>

#include <C2Work.h>

namespace android {

/**
 * PipelineWatcher watches the status of the work.
 */
class PipelineWatcher {
public:
    typedef std::chrono::steady_clock Clock;

    PipelineWatcher()
        : mInputDelay(0),
          mPipelineDelay(0),
          mOutputDelay(0),
          mSmoothnessFactor(0) {}
    ~PipelineWatcher() = default;

    PipelineWatcher &inputDelay(uint32_t value);
    PipelineWatcher &pipelineDelay(uint32_t value);
    PipelineWatcher &outputDelay(uint32_t value);
    PipelineWatcher &smoothnessFactor(uint32_t value);

    void onWorkQueued(
            uint64_t frameIndex,
            std::vector<std::shared_ptr<C2Buffer>> &&buffers,
            const Clock::time_point &queuedAt);
    std::shared_ptr<C2Buffer> onInputBufferReleased(
            uint64_t frameIndex, size_t arrayIndex);
    void onWorkDone(uint64_t frameIndex);
    void flush();

    bool pipelineFull() const;
    Clock::duration elapsed(const Clock::time_point &now, size_t n) const;

private:
    uint32_t mInputDelay;
    uint32_t mPipelineDelay;
    uint32_t mOutputDelay;
    uint32_t mSmoothnessFactor;

    struct Frame {
        Frame(std::vector<std::shared_ptr<C2Buffer>> &&b,
              const Clock::time_point &q)
            : buffers(b),
              queuedAt(q) {}
        std::vector<std::shared_ptr<C2Buffer>> buffers;
        const Clock::time_point queuedAt;
    };
    std::map<uint64_t, Frame> mFramesInPipeline;
};

}  // namespace android

#endif  // PIPELINE_WATCHER_H_
