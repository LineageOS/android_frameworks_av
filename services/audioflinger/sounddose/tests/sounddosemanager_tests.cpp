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

TEST(SoundDoseManagerTest, GetCallbackForExistingStream) {
    SoundDoseManager soundDoseManager;
    sp<audio_utils::MelProcessor::MelCallback> callback1 =
        soundDoseManager.getOrCreateCallbackForDevice(/*deviceId=*/1, /*streamHandle=*/1);
    sp<audio_utils::MelProcessor::MelCallback> callback2 =
        soundDoseManager.getOrCreateCallbackForDevice(/*deviceId=*/2, /*streamHandle=*/1);

    EXPECT_EQ(callback1, callback2);
}

TEST(SoundDoseManagerTest, RemoveExistingStream) {
    SoundDoseManager soundDoseManager;
    sp<audio_utils::MelProcessor::MelCallback> callback1 =
        soundDoseManager.getOrCreateCallbackForDevice(/*deviceId=*/1, /*streamHandle=*/1);

    soundDoseManager.removeStreamCallback(1);
    sp<audio_utils::MelProcessor::MelCallback> callback2 =
        soundDoseManager.getOrCreateCallbackForDevice(/*deviceId=*/2, /*streamHandle=*/1);

    EXPECT_NE(callback1, callback2);
}

TEST(SoundDoseManagerTest, NewMelValuesCacheNewRecord) {
    SoundDoseManager soundDoseManager;
    std::vector<float>mels{1, 1};
    sp<audio_utils::MelProcessor::MelCallback> callback =
        soundDoseManager.getOrCreateCallbackForDevice(/*deviceId=*/1, /*streamHandle=*/1);

    callback->onNewMelValues(mels, 0, mels.size());

    EXPECT_EQ(soundDoseManager.getCachedMelRecordsSize(), size_t{1});
}

}  // namespace
}  // namespace android
