/*
 * Copyright 2020 The Android Open Source Project
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
#include <chrono>
#include <thread>

#include "fuzzer/FuzzedDataProvider.h"
#include "mediautils/TimeCheck.h"

static constexpr int kMaxStringLen = 256;

// While it might be interesting to test long-running
// jobs, it seems unlikely it'd lead to the types of crashes
// we're looking for, and would mean a significant increase in fuzzer time.
// Therefore, we are setting a low cap.
static constexpr uint32_t kMaxTimeoutMs = 1000;
static constexpr uint32_t kMinTimeoutMs = 200;
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider data_provider(data, size);

    // There's essentially 5 operations that we can access in this class
    // 1. The time it takes to run this operation. As mentioned above,
    //    long-running tasks are not good for fuzzing, but there will be
    //    some change in the run time.
    uint32_t timeoutMs =
        data_provider.ConsumeIntegralInRange<uint32_t>(kMinTimeoutMs, kMaxTimeoutMs);
    uint8_t pid_size = data_provider.ConsumeIntegral<uint8_t>();
    std::vector<pid_t> pids(pid_size);
    for (auto& pid : pids) {
        pid = data_provider.ConsumeIntegral<pid_t>();
    }

    // 2. We also have setAudioHalPids, which is populated with the pids set
    // above.
    android::mediautils::TimeCheck::setAudioHalPids(pids);
    std::string name = data_provider.ConsumeRandomLengthString(kMaxStringLen);

    // 3. The constructor, which is fuzzed here:
    android::mediautils::TimeCheck timeCheck(name.c_str(), {} /* onTimer */,
            std::chrono::milliseconds(timeoutMs),
            {} /* secondChanceDuration */, true /* crashOnTimeout */);
    // We will leave some buffer to avoid sleeping too long
    uint8_t sleep_amount_ms = data_provider.ConsumeIntegralInRange<uint8_t>(0, timeoutMs / 2);

    // We want to make sure we can cover the time out functionality.
    if (sleep_amount_ms) {
        auto ms = std::chrono::milliseconds(sleep_amount_ms);
        std::this_thread::sleep_for(ms);
    }

    // 4. Finally, the destructor on timecheck. These seem to be the only factors
    // in play.
    return 0;
}
