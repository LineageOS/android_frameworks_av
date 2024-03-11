/*
 * Copyright (C) 2024 The Android Open Source Project
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

#define LOG_TAG "Spatializer_Test"

#include "Spatializer.h"

#include <string>
#include <unordered_set>

#include <gtest/gtest.h>

#include <android/media/audio/common/AudioLatencyMode.h>
#include <android/media/audio/common/HeadTracking.h>
#include <android/media/audio/common/Spatialization.h>
#include <com_android_media_audio.h>
#include <utils/Log.h>

using namespace android;
using media::audio::common::HeadTracking;
using media::audio::common::Spatialization;

class TestSpatializerPolicyCallback :
        public SpatializerPolicyCallback {
public:
    void onCheckSpatializer() override {};
};

class SpatializerTest : public ::testing::Test {
protected:
    void SetUp() override {
        const sp<EffectsFactoryHalInterface> effectsFactoryHal
                = EffectsFactoryHalInterface::create();
        mSpatializer = Spatializer::create(&mTestCallback, effectsFactoryHal);
        if (mSpatializer == nullptr) {
            GTEST_SKIP() << "Skipping Spatializer tests: no spatializer";
        }
        std::vector<Spatialization::Level> levels;
        binder::Status status = mSpatializer->getSupportedLevels(&levels);
        ASSERT_TRUE(status.isOk());
        for (auto level : levels) {
            if (level != Spatialization::Level::NONE) {
                mSpatializer->setLevel(level);
                break;
            }
        }
        mSpatializer->setOutput(sTestOutput);
    }

    void TearDown() override {
        if (mSpatializer == nullptr) {
            return;
        }
        mSpatializer->setLevel(Spatialization::Level::NONE);
        mSpatializer->setOutput(AUDIO_IO_HANDLE_NONE);
        mSpatializer->setDesiredHeadTrackingMode(HeadTracking::Mode::DISABLED);
        mSpatializer->setHeadSensor(SpatializerPoseController::INVALID_SENSOR);
        mSpatializer->updateActiveTracks(0);
    }

    static constexpr audio_io_handle_t sTestOutput= 1977;
    static constexpr int sTestSensorHandle = 1980;

    const static inline std::vector<audio_latency_mode_t> sA2DPLatencyModes = {
        AUDIO_LATENCY_MODE_LOW,
        AUDIO_LATENCY_MODE_FREE
    };
    const static inline std::vector<audio_latency_mode_t> sBLELatencyModes = {
        AUDIO_LATENCY_MODE_LOW,
        AUDIO_LATENCY_MODE_DYNAMIC_SPATIAL_AUDIO_SOFTWARE,
        AUDIO_LATENCY_MODE_DYNAMIC_SPATIAL_AUDIO_HARDWARE,
        AUDIO_LATENCY_MODE_FREE
    };

    bool setpUpForHeadtracking() {
        bool htSupported;
        mSpatializer->isHeadTrackingSupported(&htSupported);
        if (!htSupported) {
            return false;
        }

        std::vector<HeadTracking::Mode> htModes;
        mSpatializer->getSupportedHeadTrackingModes(&htModes);
        for (auto htMode : htModes) {
            if (htMode != HeadTracking::Mode::DISABLED) {
                mSpatializer->setDesiredHeadTrackingMode(htMode);
                break;
            }
        }

        mSpatializer->setHeadSensor(sTestSensorHandle);
        return true;
    }

    TestSpatializerPolicyCallback mTestCallback;
    sp<Spatializer> mSpatializer;
};

TEST_F(SpatializerTest, SupportedA2dpLatencyTest) {
    if (!setpUpForHeadtracking()) {
        GTEST_SKIP() << "Skipping SupportedA2dpLatencyTest: head tracking not supported";
    }
    std::vector<audio_latency_mode_t> latencies = sA2DPLatencyModes;
    mSpatializer->onSupportedLatencyModesChangedMsg(sTestOutput, std::move(latencies));

    std::vector<audio_latency_mode_t> supportedLatencies =
            mSpatializer->getSupportedLatencyModes();

    ASSERT_TRUE(supportedLatencies == sA2DPLatencyModes);
    // Free mode must always be the last of the ordered list
    ASSERT_TRUE(supportedLatencies.back() == AUDIO_LATENCY_MODE_FREE);
}

TEST_F(SpatializerTest, SupportedBleLatencyTest) {
    if (!setpUpForHeadtracking()) {
        GTEST_SKIP() << "Skipping SupportedBleLatencyTest: head tracking not supported";
    }
    if (!com::android::media::audio::dsa_over_bt_le_audio()) {
        GTEST_SKIP() << "Skipping SupportedBleLatencyTest: DSA over LE not enabled";
    }
    std::vector<audio_latency_mode_t> latencies = sBLELatencyModes;
    mSpatializer->onSupportedLatencyModesChangedMsg(sTestOutput, std::move(latencies));

    std::vector<audio_latency_mode_t> supportedLatencies =
            mSpatializer->getSupportedLatencyModes();

    ASSERT_TRUE(supportedLatencies.back() == AUDIO_LATENCY_MODE_FREE);
    ASSERT_TRUE(std::find(supportedLatencies.begin(), supportedLatencies.end(),
            AUDIO_LATENCY_MODE_LOW) != supportedLatencies.end());

    std::vector<audio_latency_mode_t> orderedLowLatencyModes =
        mSpatializer->getOrderedLowLatencyModes();

    std::vector<audio_latency_mode_t> supportedLowLatencyModes;
    // remove free mode at the end of the supported list to only retain low latency modes
    std::copy(supportedLatencies.begin(),
              supportedLatencies.begin() + supportedLatencies.size() - 1,
              std::back_inserter(supportedLowLatencyModes));

    // Verify that supported low latency modes are always in ordered latency modes list and
    // in the same order
    std::vector<audio_latency_mode_t>::iterator lastIt = orderedLowLatencyModes.begin();
    for (auto latency : supportedLowLatencyModes) {
        auto it = std::find(orderedLowLatencyModes.begin(), orderedLowLatencyModes.end(), latency);
        ASSERT_NE(it, orderedLowLatencyModes.end());
        ASSERT_LE(lastIt, it);
        lastIt = it;
    }
}

TEST_F(SpatializerTest, RequestedA2dpLatencyTest) {
    if (!setpUpForHeadtracking()) {
        GTEST_SKIP() << "Skipping RequestedA2dpLatencyTest: head tracking not supported";
    }

    std::vector<audio_latency_mode_t> latencies = sA2DPLatencyModes;
    mSpatializer->onSupportedLatencyModesChangedMsg(sTestOutput, std::move(latencies));

    // requested latency mode must be free if no spatialized tracks are active
    audio_latency_mode_t requestedLatencyMode = mSpatializer->getRequestedLatencyMode();
    ASSERT_EQ(requestedLatencyMode, AUDIO_LATENCY_MODE_FREE);

    // requested latency mode must be low if at least one spatialized tracks is active
    mSpatializer->updateActiveTracks(1);
    requestedLatencyMode = mSpatializer->getRequestedLatencyMode();
    ASSERT_EQ(requestedLatencyMode, AUDIO_LATENCY_MODE_LOW);

    // requested latency mode must be free after stopping the last spatialized tracks
    mSpatializer->updateActiveTracks(0);
    requestedLatencyMode = mSpatializer->getRequestedLatencyMode();
    ASSERT_EQ(requestedLatencyMode, AUDIO_LATENCY_MODE_FREE);
}

TEST_F(SpatializerTest, RequestedBleLatencyTest) {
    if (!setpUpForHeadtracking()) {
        GTEST_SKIP() << "Skipping RequestedBleLatencyTest: head tracking not supported";
    }
    if (!com::android::media::audio::dsa_over_bt_le_audio()) {
        GTEST_SKIP() << "Skipping RequestedBleLatencyTest: DSA over LE not enabled";
    }

    mSpatializer->onSupportedLatencyModesChangedMsg(sTestOutput,
            { AUDIO_LATENCY_MODE_DYNAMIC_SPATIAL_AUDIO_SOFTWARE,
              AUDIO_LATENCY_MODE_FREE });

    // requested latency mode must be free if no spatialized tracks are active
    audio_latency_mode_t requestedLatencyMode = mSpatializer->getRequestedLatencyMode();
    ASSERT_EQ(requestedLatencyMode, AUDIO_LATENCY_MODE_FREE);

    // requested latency mode must be low software if at least one spatialized tracks is active
    // and the only supported low latency mode is low software
    mSpatializer->updateActiveTracks(1);
    requestedLatencyMode = mSpatializer->getRequestedLatencyMode();
    ASSERT_EQ(requestedLatencyMode, AUDIO_LATENCY_MODE_DYNAMIC_SPATIAL_AUDIO_SOFTWARE);

    mSpatializer->onSupportedLatencyModesChangedMsg(sTestOutput,
            { AUDIO_LATENCY_MODE_DYNAMIC_SPATIAL_AUDIO_SOFTWARE,
              AUDIO_LATENCY_MODE_DYNAMIC_SPATIAL_AUDIO_HARDWARE,
              AUDIO_LATENCY_MODE_FREE });

    requestedLatencyMode = mSpatializer->getRequestedLatencyMode();
    HeadTracking::ConnectionMode connectionMode = mSpatializer->getHeadtrackingConnectionMode();

    // If low hardware mode is used, the spatializer must use either use one of the sensor
    // connection tunneled modes.
    // Otherwise, low software mode must be used
    if (requestedLatencyMode == AUDIO_LATENCY_MODE_DYNAMIC_SPATIAL_AUDIO_HARDWARE) {
        ASSERT_TRUE(connectionMode == HeadTracking::ConnectionMode::DIRECT_TO_SENSOR_TUNNEL
                        || connectionMode == HeadTracking::ConnectionMode::DIRECT_TO_SENSOR_SW);
    } else {
        ASSERT_EQ(requestedLatencyMode, AUDIO_LATENCY_MODE_DYNAMIC_SPATIAL_AUDIO_SOFTWARE);
    }

    // requested latency mode must be free after stopping the last spatialized tracks
    mSpatializer->updateActiveTracks(0);
    requestedLatencyMode = mSpatializer->getRequestedLatencyMode();
    ASSERT_EQ(requestedLatencyMode, AUDIO_LATENCY_MODE_FREE);
}
