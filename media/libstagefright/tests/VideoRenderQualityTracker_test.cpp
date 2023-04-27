/*
 * Copyright 2023 The Android Open Source Project
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
#define LOG_TAG "VideoRenderQualityTracker_test"
#include <utils/Log.h>

#include <gtest/gtest.h>

#include <media/stagefright/VideoRenderQualityTracker.h>

namespace android {

using Metrics = VideoRenderQualityMetrics;
using Configuration = VideoRenderQualityTracker::Configuration;

class Helper {
public:
    Helper(double contentFrameDurationMs, const Configuration &configuration) :
            mVideoRenderQualityTracker(configuration) {
        mContentFrameDurationUs = int64_t(contentFrameDurationMs * 1000);
        mMediaTimeUs = 0;
        mClockTimeNs = 0;
    }

    void changeContentFrameDuration(double contentFrameDurationMs) {
        mContentFrameDurationUs = int64_t(contentFrameDurationMs * 1000);
    }

    template<typename T>
    void render(std::initializer_list<T> renderDurationMsList) {
        for (auto renderDurationMs : renderDurationMsList) {
            mVideoRenderQualityTracker.onFrameReleased(mMediaTimeUs);
            mVideoRenderQualityTracker.onFrameRendered(mMediaTimeUs, mClockTimeNs);
            mMediaTimeUs += mContentFrameDurationUs;
            mClockTimeNs += int64_t(renderDurationMs * 1000 * 1000);
        }
    }

    void skip(int numFrames) {
        for (int i = 0; i < numFrames; ++i) {
            mVideoRenderQualityTracker.onFrameSkipped(mMediaTimeUs);
            mMediaTimeUs += mContentFrameDurationUs;
            mClockTimeNs += mContentFrameDurationUs * 1000;
        }
    }

    void drop(int numFrames) {
        for (int i = 0; i < numFrames; ++i) {
            mVideoRenderQualityTracker.onFrameReleased(mMediaTimeUs);
            mMediaTimeUs += mContentFrameDurationUs;
            mClockTimeNs += mContentFrameDurationUs * 1000;
        }
    }

    const Metrics & getMetrics() const {
        return mVideoRenderQualityTracker.getMetrics();
    }

private:
    VideoRenderQualityTracker mVideoRenderQualityTracker;
    int64_t mContentFrameDurationUs;
    int64_t mMediaTimeUs;
    int64_t mClockTimeNs;
};

class VideoRenderQualityTrackerTest : public ::testing::Test {
public:
    VideoRenderQualityTrackerTest() {}
};

TEST_F(VideoRenderQualityTrackerTest, countsReleasedFrames) {
    Configuration c;
    Helper h(16.66, c);
    h.drop(10);
    h.render({16.66, 16.66, 16.66});
    h.skip(10); // skipped frames aren't released so they are not counted
    h.render({16.66, 16.66, 16.66, 16.66});
    h.drop(10);
    EXPECT_EQ(27, h.getMetrics().frameReleasedCount);
}

TEST_F(VideoRenderQualityTrackerTest, countsSkippedFrames) {
    Configuration c;
    Helper h(16.66, c);
    h.drop(10); // dropped frames are not counted
    h.skip(10); // frames skipped before rendering a frame are not counted
    h.render({16.66, 16.66, 16.66}); // rendered frames are not counted
    h.drop(10); // dropped frames are not counted
    h.skip(10);
    h.render({16.66, 16.66, 16.66, 16.66}); // rendered frames are not counted
    h.skip(10); // frames skipped at the end of playback are not counted
    h.drop(10); // dropped frames are not counted
    EXPECT_EQ(10, h.getMetrics().frameSkippedCount);
}

TEST_F(VideoRenderQualityTrackerTest, whenSkippedFramesAreDropped_countsDroppedFrames) {
    Configuration c;
    c.areSkippedFramesDropped = true;
    Helper h(16.66, c);
    h.skip(10); // skipped frames at the beginning of playback are not counted
    h.drop(10);
    h.skip(10); // skipped frames at the beginning of playback after dropped frames are not counted
    h.render({16.66, 16.66, 16.66});  // rendered frames are not counted
    h.drop(10);
    h.skip(10);
    h.render({16.66, 16.66, 16.66, 16.66}); // rendered frames are not counted
    h.drop(10); // dropped frames at the end of playback are not counted
    h.skip(10); // skipped frames at the end of playback are not counted
    EXPECT_EQ(30, h.getMetrics().frameDroppedCount);
}

TEST_F(VideoRenderQualityTrackerTest, whenNotSkippedFramesAreDropped_countsDroppedFrames) {
    Configuration c;
    c.areSkippedFramesDropped = false;
    Helper h(16.66, c);
    h.skip(10); // skipped frames at the beginning of playback are not counted
    h.drop(10);
    h.skip(10); // skipped frames at the beginning of playback after dropped frames are not coutned
    h.render({16.66, 16.66, 16.66}); // rendered frames are not counted
    h.drop(10);
    h.skip(10); // skipped frames are not counted
    h.render({16.66, 16.66, 16.66, 16.66}); // rendered frames are not counted
    h.drop(10); // dropped frames at the end of playback are not counted
    h.skip(10); // skipped frames at the end of playback are not counted
    EXPECT_EQ(20, h.getMetrics().frameDroppedCount);
}

TEST_F(VideoRenderQualityTrackerTest, countsRenderedFrames) {
    Configuration c;
    Helper h(16.66, c);
    h.drop(10); // dropped frames are not counted
    h.render({16.66, 16.66, 16.66});
    h.skip(10); // skipped frames are not counted
    h.render({16.66, 16.66, 16.66, 16.66});
    h.drop(10); // dropped frames are not counted
    EXPECT_EQ(7, h.getMetrics().frameRenderedCount);
}

TEST_F(VideoRenderQualityTrackerTest, detectsFrameRate) {
    Configuration c;
    c.frameRateDetectionToleranceUs = 2 * 1000; // 2 ms
    Helper h(16.66, c);
    h.render({16.6, 16.7, 16.6, 16.7});
    EXPECT_NEAR(h.getMetrics().contentFrameRate, 60.0, 0.5);
    EXPECT_NEAR(h.getMetrics().actualFrameRate, 60.0, 0.5);
}

TEST_F(VideoRenderQualityTrackerTest, whenLowTolerance_doesntDetectFrameRate) {
    Configuration c;
    c.frameRateDetectionToleranceUs = 0;
    Helper h(16.66, c);
    h.render({16.6, 16.7, 16.6, 16.7});
    EXPECT_NEAR(h.getMetrics().contentFrameRate, 60.0, 0.5);
    EXPECT_EQ(h.getMetrics().actualFrameRate, FRAME_RATE_UNDETERMINED);
}

TEST_F(VideoRenderQualityTrackerTest, whenFrameRateDestabilizes_detectsFrameRate) {
    Configuration c;
    c.frameRateDetectionToleranceUs = 2 * 1000; // 2 ms
    Helper h(16.66, c);
    h.render({16.6, 16.7, 16.6, 16.7});
    h.render({30.0, 16.6, 30.0, 16.6});
    EXPECT_NEAR(h.getMetrics().contentFrameRate, 60.0, 0.5);
    EXPECT_NEAR(h.getMetrics().actualFrameRate, 60.0, 0.5);
}

TEST_F(VideoRenderQualityTrackerTest, detects32Pulldown) {
    Configuration c;
    c.frameRateDetectionToleranceUs = 2 * 1000; // 2 ms
    Helper h(41.66, c);
    h.render({49.9, 33.2, 50.0, 33.4, 50.1, 33.2});
    EXPECT_NEAR(h.getMetrics().contentFrameRate, 24.0, 0.5);
    EXPECT_EQ(h.getMetrics().actualFrameRate, FRAME_RATE_24HZ_3_2_PULLDOWN);
}

TEST_F(VideoRenderQualityTrackerTest, whenBad32Pulldown_doesntDetect32Pulldown) {
    Configuration c;
    c.frameRateDetectionToleranceUs = 2 * 1000; // 2 ms
    Helper h(41.66, c);
    h.render({50.0, 33.33, 33.33, 50.00, 33.33, 50.00});
    EXPECT_NEAR(h.getMetrics().contentFrameRate, 24.0, 0.5);
    EXPECT_EQ(h.getMetrics().actualFrameRate, FRAME_RATE_UNDETERMINED);
}

TEST_F(VideoRenderQualityTrackerTest, whenFrameRateChanges_detectsMostRecentFrameRate) {
    Configuration c;
    c.frameRateDetectionToleranceUs = 2 * 1000; // 2 ms
    Helper h(16.66, c);
    h.render({16.6, 16.7, 16.6, 16.7});
    EXPECT_NEAR(h.getMetrics().contentFrameRate, 60.0, 0.5);
    EXPECT_NEAR(h.getMetrics().actualFrameRate, 60.0, 0.5);
    h.changeContentFrameDuration(41.66);
    h.render({50.0, 33.33, 50.0, 33.33, 50.0, 33.33});
    EXPECT_NEAR(h.getMetrics().contentFrameRate, 24.0, 0.5);
    EXPECT_EQ(h.getMetrics().actualFrameRate, FRAME_RATE_24HZ_3_2_PULLDOWN);
}

TEST_F(VideoRenderQualityTrackerTest, whenFrameRateIsUnstable_doesntDetectFrameRate) {
    Configuration c;
    c.frameRateDetectionToleranceUs = 2 * 1000; // 2 ms
    Helper h(16.66, c);
    h.render({16.66, 30.0, 16.66, 30.0, 16.66});
    EXPECT_NEAR(h.getMetrics().contentFrameRate, 60.0, 0.5);
    EXPECT_EQ(h.getMetrics().actualFrameRate, FRAME_RATE_UNDETERMINED);
}

} // android
