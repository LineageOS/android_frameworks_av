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

    void render(int numFrames) {
        for (int i = 0; i < numFrames; ++i) {
            mVideoRenderQualityTracker.onFrameReleased(mMediaTimeUs);
            mVideoRenderQualityTracker.onFrameRendered(mMediaTimeUs, mClockTimeNs);
            mMediaTimeUs += mContentFrameDurationUs;
            mClockTimeNs += mContentFrameDurationUs * 1000;
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

TEST_F(VideoRenderQualityTrackerTest, capturesFreezeDurationHistogram) {
    Configuration c;
    // +17 because freeze durations include the render time of the previous frame
    c.freezeDurationMsHistogramBuckets = {2 * 17 + 17, 3 * 17 + 17, 6 * 17 + 17};
    Helper h(17, c);
    h.render(1);
    h.drop(1); // below
    h.render(1);
    h.drop(3); // bucket 1
    h.render(1);
    h.drop(2); // bucket 0
    h.render(1);
    h.drop(4); // bucket 1
    h.render(1);
    h.drop(2); // bucket 0
    h.render(1);
    h.drop(5); // bucket 1
    h.render(1);
    h.drop(10); // above
    h.render(1);
    h.drop(15); // above
    h.render(1);
    EXPECT_EQ(h.getMetrics().freezeDurationMsHistogram.emit(), "1{2,3}2");
    EXPECT_EQ(h.getMetrics().freezeDurationMsHistogram.getCount(), 8);
    // the smallest frame drop was 1, +17 because it includes the previous frame render time
    EXPECT_EQ(h.getMetrics().freezeDurationMsHistogram.getMin(), 1 * 17 + 17);
    // the largest frame drop was 10, +17 because it includes the previous frame render time
    EXPECT_EQ(h.getMetrics().freezeDurationMsHistogram.getMax(), 15 * 17 + 17);
    // total frame drop count, multiplied by 17, plus 17 for each occurrence, divided by occurrences
    EXPECT_EQ(h.getMetrics().freezeDurationMsHistogram.getAvg(), ((1 + 3 + 2 + 4 + 2 + 5 + 10 + 15)
                                                                   * 17 + 8 * 17) / 8);
}

TEST_F(VideoRenderQualityTrackerTest, capturesFreezeDistanceHistogram) {
    Configuration c;
    c.freezeDistanceMsHistogramBuckets = {1 * 17, 5 * 17, 6 * 17};
    Helper h(17, c);
    h.render(1);
    h.drop(1);
    h.render(5); // bucket 0
    h.drop(3);
    h.render(3); // bucket 0
    h.drop(2);
    h.render(9); // above
    h.drop(5);
    h.render(1); // below
    h.drop(2);
    h.render(6); // bucket 1
    h.drop(4);
    h.render(12); // above
    h.drop(2);
    h.render(1);
    EXPECT_EQ(h.getMetrics().freezeDistanceMsHistogram.emit(), "1{2,1}2");
    EXPECT_EQ(h.getMetrics().freezeDistanceMsHistogram.getCount(), 6);
    // the smallest render between drops was 1, -17 because the last frame rendered also froze
    EXPECT_EQ(h.getMetrics().freezeDistanceMsHistogram.getMin(), 1 * 17 - 17);
    // the largest render between drops was 12, -17 because the last frame rendered also froze
    EXPECT_EQ(h.getMetrics().freezeDistanceMsHistogram.getMax(), 12 * 17 - 17);
    // total render count between, multiplied by 17, minus 17 for each occurrence, divided by
    // occurrences
    EXPECT_EQ(h.getMetrics().freezeDistanceMsHistogram.getAvg(), ((5 + 3 + 9 + 1 + 6 + 12) * 17 -
                                                                  6 * 17) / 6);
}

} // android
