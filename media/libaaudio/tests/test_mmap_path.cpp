/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "test_mmap_path"

#include <vector>

#include <aaudio/AAudio.h>
#include <aaudio/AAudioTesting.h>
#include <android/log.h>
#include <android/media/audio/common/AudioMMapPolicyInfo.h>
#include <android/media/audio/common/AudioMMapPolicyType.h>
#include <media/AudioSystem.h>

#include <gtest/gtest.h>

#include "utility/AAudioUtilities.h"

using android::media::audio::common::AudioMMapPolicyInfo;
using android::media::audio::common::AudioMMapPolicyType;

/**
 * Open a stream via AAudio API and set the performance mode as LOW_LATENCY. When MMAP is supported,
 * the stream is supposed to be on MMAP path instead of legacy path. This is guaranteed on pixel
 * devices, but may not be guaranteed on other vendor devices.
 * @param direction the direction for the stream
 */
static void openStreamAndVerify(aaudio_direction_t direction) {
    std::vector<AudioMMapPolicyInfo> policyInfos;
    ASSERT_EQ(android::NO_ERROR, android::AudioSystem::getMmapPolicyInfo(
            AudioMMapPolicyType::DEFAULT, &policyInfos));
    if (AAudio_getAAudioPolicy(policyInfos) == AAUDIO_POLICY_NEVER) {
        // Query the system MMAP policy, if it is NEVER, it indicates there is no MMAP support.
        // In that case, there is no need to run the test. The reason of adding the query is to
        // avoid someone accidentally run the test on device that doesn't support MMAP,
        // such as cuttlefish.
        ALOGD("Skip test as mmap is not supported");
        return;
    }

    AAudioStreamBuilder *aaudioBuilder = nullptr;
    AAudioStream *aaudioStream = nullptr;

    ASSERT_EQ(AAUDIO_OK, AAudio_createStreamBuilder(&aaudioBuilder));

    AAudioStreamBuilder_setDirection(aaudioBuilder, direction);
    AAudioStreamBuilder_setPerformanceMode(aaudioBuilder, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);

    EXPECT_EQ(AAUDIO_OK, AAudioStreamBuilder_openStream(aaudioBuilder, &aaudioStream));
    EXPECT_EQ(AAUDIO_PERFORMANCE_MODE_LOW_LATENCY, AAudioStream_getPerformanceMode(aaudioStream));
    EXPECT_TRUE(AAudioStream_isMMapUsed(aaudioStream));

    AAudioStream_close(aaudioStream);
    AAudioStreamBuilder_delete(aaudioBuilder);
}

TEST(test_mmap_path, input) {
    openStreamAndVerify(AAUDIO_DIRECTION_INPUT);
}

TEST(test_mmap_path, output) {
    openStreamAndVerify(AAUDIO_DIRECTION_OUTPUT);
}
