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

// #define LOG_NDEBUG 0
#define LOG_TAG "sounddosemanager_tests"

#include <SoundDoseManager.h>

#include <gtest/gtest.h>

namespace android {
namespace {

TEST(SoundDoseManagerTest, GetProcessorForExistingStream) {
    SoundDoseManager soundDoseManager;
    sp<audio_utils::MelProcessor> processor1 =
        soundDoseManager.getOrCreateProcessorForDevice(/*deviceId=*/1,
            /*streamHandle=*/1,
            /*sampleRate*/44100,
            /*channelCount*/2,
            /*format*/AUDIO_FORMAT_PCM_FLOAT);
    sp<audio_utils::MelProcessor> processor2 =
        soundDoseManager.getOrCreateProcessorForDevice(/*deviceId=*/2,
            /*streamHandle=*/1,
            /*sampleRate*/44100,
            /*channelCount*/2,
            /*format*/AUDIO_FORMAT_PCM_FLOAT);

    EXPECT_EQ(processor1, processor2);
}

TEST(SoundDoseManagerTest, RemoveExistingStream) {
    SoundDoseManager soundDoseManager;
    sp<audio_utils::MelProcessor> processor1 =
        soundDoseManager.getOrCreateProcessorForDevice(/*deviceId=*/1,
            /*streamHandle=*/1,
            /*sampleRate*/44100,
            /*channelCount*/2,
            /*format*/AUDIO_FORMAT_PCM_FLOAT);

    soundDoseManager.removeStreamProcessor(1);
    sp<audio_utils::MelProcessor> processor2 =
        soundDoseManager.getOrCreateProcessorForDevice(/*deviceId=*/2,
            /*streamHandle=*/1,
            /*sampleRate*/44100,
            /*channelCount*/2,
            /*format*/AUDIO_FORMAT_PCM_FLOAT);

    EXPECT_NE(processor1, processor2);
}

TEST(SoundDoseManagerTest, NewMelValuesCacheNewRecord) {
    SoundDoseManager soundDoseManager;
    std::vector<float>mels{1, 1};

    soundDoseManager.onNewMelValues(mels, 0, mels.size(), /*deviceId=*/1);

    EXPECT_EQ(soundDoseManager.getCachedMelRecordsSize(), size_t{1});
}

}  // namespace
}  // namespace android
