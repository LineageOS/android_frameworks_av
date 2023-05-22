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
using FreezeEvent = VideoRenderQualityTracker::FreezeEvent;
using JudderEvent = VideoRenderQualityTracker::JudderEvent;

static constexpr float FRAME_RATE_UNDETERMINED = VideoRenderQualityMetrics::FRAME_RATE_UNDETERMINED;
static constexpr float FRAME_RATE_24_3_2_PULLDOWN =
        VideoRenderQualityMetrics::FRAME_RATE_24_3_2_PULLDOWN;

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
            mVideoRenderQualityTracker.onFrameRendered(mMediaTimeUs, mClockTimeNs, &mFreezeEvent,
                                                       &mJudderEvent);
            mMediaTimeUs += mContentFrameDurationUs;
            mClockTimeNs += int64_t(renderDurationMs * 1000 * 1000);
        }
    }

    void render(int numFrames, float durationMs = -1) {
        int64_t durationUs = durationMs < 0 ? mContentFrameDurationUs : durationMs * 1000;
        for (int i = 0; i < numFrames; ++i) {
            mVideoRenderQualityTracker.onFrameReleased(mMediaTimeUs);
            mVideoRenderQualityTracker.onFrameRendered(mMediaTimeUs, mClockTimeNs, &mFreezeEvent,
                                                       &mJudderEvent);
            mMediaTimeUs += mContentFrameDurationUs;
            mClockTimeNs += durationUs * 1000;
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

    const Metrics & getMetrics() {
        return mVideoRenderQualityTracker.getMetrics();
    }

    FreezeEvent getAndClearFreezeEvent() {
        FreezeEvent e = std::move(mFreezeEvent);
        mFreezeEvent.valid = false;
        return e;
    }

    JudderEvent getAndClearJudderEvent() {
        JudderEvent e = std::move(mJudderEvent);
        mJudderEvent.valid = false;
        return e;
    }

private:
    VideoRenderQualityTracker mVideoRenderQualityTracker;
    int64_t mContentFrameDurationUs;
    int64_t mMediaTimeUs;
    int64_t mClockTimeNs;
    VideoRenderQualityTracker::FreezeEvent mFreezeEvent;
    VideoRenderQualityTracker::JudderEvent mJudderEvent;
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
    EXPECT_EQ(h.getMetrics().actualFrameRate, FRAME_RATE_24_3_2_PULLDOWN);
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
    EXPECT_EQ(h.getMetrics().actualFrameRate, FRAME_RATE_24_3_2_PULLDOWN);
}

TEST_F(VideoRenderQualityTrackerTest, whenFrameRateIsUnstable_doesntDetectFrameRate) {
    Configuration c;
    c.frameRateDetectionToleranceUs = 2 * 1000; // 2 ms
    Helper h(16.66, c);
    h.render({16.66, 30.0, 16.66, 30.0, 16.66});
    EXPECT_NEAR(h.getMetrics().contentFrameRate, 60.0, 0.5);
    EXPECT_EQ(h.getMetrics().actualFrameRate, FRAME_RATE_UNDETERMINED);
}

TEST_F(VideoRenderQualityTrackerTest, capturesFreezeRate) {
    Configuration c;
    Helper h(20, c);
    h.render(3);
    EXPECT_EQ(h.getMetrics().freezeRate, 0);
    h.drop(3);
    h.render(3);
    // +1 because the first frame before drops is considered frozen
    // and then -1 because the last frame has an unknown render duration
    EXPECT_EQ(h.getMetrics().freezeRate, 4.0 / 8.0);
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

TEST_F(VideoRenderQualityTrackerTest, when60hz_hasNoJudder) {
    Configuration c;
    Helper h(16.66, c); // ~24Hz
    h.render({16.66, 16.66, 16.66, 16.66, 16.66, 16.66, 16.66});
    EXPECT_LE(h.getMetrics().judderScoreHistogram.getMax(), 0);
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getCount(), 0);
}

TEST_F(VideoRenderQualityTrackerTest, whenSmallVariance60hz_hasNoJudder) {
    Configuration c;
    Helper h(16.66, c); // ~24Hz
    h.render({14, 18, 14, 18, 14, 18, 14, 18});
    EXPECT_LE(h.getMetrics().judderScoreHistogram.getMax(), 0);
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getCount(), 0);
}

TEST_F(VideoRenderQualityTrackerTest, whenBadSmallVariance60Hz_hasJudder) {
    Configuration c;
    Helper h(16.66, c); // ~24Hz
    h.render({14, 18, 14, /* no 18 between 14s */ 14, 18, 14, 18});
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getCount(), 1);
}

TEST_F(VideoRenderQualityTrackerTest, when30Hz_hasNoJudder) {
    Configuration c;
    Helper h(33.33, c);
    h.render({33.33, 33.33, 33.33, 33.33, 33.33, 33.33});
    EXPECT_LE(h.getMetrics().judderScoreHistogram.getMax(), 0);
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getCount(), 0);
}

TEST_F(VideoRenderQualityTrackerTest, whenSmallVariance30Hz_hasNoJudder) {
    Configuration c;
    Helper h(33.33, c);
    h.render({29.0, 35.0, 29.0, 35.0, 29.0, 35.0});
    EXPECT_LE(h.getMetrics().judderScoreHistogram.getMax(), 0);
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getCount(), 0);
}

TEST_F(VideoRenderQualityTrackerTest, whenBadSmallVariance30Hz_hasJudder) {
    Configuration c;
    Helper h(33.33, c);
    h.render({29.0, 35.0, 29.0, /* no 35 between 29s */ 29.0, 35.0, 29.0, 35.0});
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getCount(), 1);
}

TEST_F(VideoRenderQualityTrackerTest, whenBad30HzTo60Hz_hasJudder) {
    Configuration c;
    Helper h(33.33, c);
    h.render({33.33, 33.33, 50.0, /* frame stayed 1 vsync too long */ 16.66, 33.33, 33.33});
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getCount(), 2); // note: 2 counts of judder
}

TEST_F(VideoRenderQualityTrackerTest, when24HzTo60Hz_hasNoJudder) {
    Configuration c;
    Helper h(41.66, c);
    h.render({50.0, 33.33, 50.0, 33.33, 50.0, 33.33});
    EXPECT_LE(h.getMetrics().judderScoreHistogram.getMax(), 0);
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getCount(), 0);
}

TEST_F(VideoRenderQualityTrackerTest, when25HzTo60Hz_hasJudder) {
    Configuration c;
    Helper h(40, c);
    h.render({33.33, 33.33, 50.0});
    h.render({33.33, 33.33, 50.0});
    h.render({33.33, 33.33, 50.0});
    h.render({33.33, 33.33, 50.0});
    h.render({33.33, 33.33, 50.0});
    h.render({33.33, 33.33, 50.0});
    EXPECT_GT(h.getMetrics().judderScoreHistogram.getCount(), 0);
}

TEST_F(VideoRenderQualityTrackerTest, when50HzTo60Hz_hasJudder) {
    Configuration c;
    Helper h(20, c);
    h.render({16.66, 16.66, 16.66, 33.33});
    h.render({16.66, 16.66, 16.66, 33.33});
    h.render({16.66, 16.66, 16.66, 33.33});
    h.render({16.66, 16.66, 16.66, 33.33});
    h.render({16.66, 16.66, 16.66, 33.33});
    h.render({16.66, 16.66, 16.66, 33.33});
    EXPECT_GT(h.getMetrics().judderScoreHistogram.getCount(), 0);
}

TEST_F(VideoRenderQualityTrackerTest, when30HzTo50Hz_hasJudder) {
    Configuration c;
    Helper h(33.33, c);
    h.render({40.0, 40.0, 40.0, 60.0});
    h.render({40.0, 40.0, 40.0, 60.0});
    h.render({40.0, 40.0, 40.0, 60.0});
    h.render({40.0, 40.0, 40.0, 60.0});
    h.render({40.0, 40.0, 40.0, 60.0});
    EXPECT_GT(h.getMetrics().judderScoreHistogram.getCount(), 0);
}

TEST_F(VideoRenderQualityTrackerTest, whenSmallVariancePulldown24HzTo60Hz_hasNoJudder) {
    Configuration c;
    Helper h(41.66, c);
    h.render({52.0, 31.33, 52.0, 31.33, 52.0, 31.33});
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getCount(), 0);
}

TEST_F(VideoRenderQualityTrackerTest, whenBad24HzTo60Hz_hasJudder) {
    Configuration c;
    Helper h(41.66, c);
    h.render({50.0, 33.33, 50.0, 33.33, /* no 50 between 33s */ 33.33, 50.0, 33.33});
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getCount(), 1);
}

TEST_F(VideoRenderQualityTrackerTest, capturesJudderScoreHistogram) {
    Configuration c;
    c.judderErrorToleranceUs = 2000;
    c.judderScoreHistogramBuckets = {1, 5, 8};
    Helper h(16, c);
    h.render({16, 16, 23, 16, 16, 10, 16, 4, 16, 20, 16, 16});
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.emit(), "0{1,2}1");
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getCount(), 4);
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getMin(), 4);
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getMax(), 12);
    EXPECT_EQ(h.getMetrics().judderScoreHistogram.getAvg(), (7 + 6 + 12 + 4) / 4);
}

TEST_F(VideoRenderQualityTrackerTest, ranksJudderScoresInOrder) {
    // Each rendering is ranked from best to worst from a user experience
    Configuration c;
    c.judderErrorToleranceUs = 2000;
    c.judderScoreHistogramBuckets = {0, 1000};
    int64_t previousScore = 0;

    // 30fps poorly displayed at 60Hz
    {
        Helper h(33.33, c);
        h.render({33.33, 33.33, 16.66, 50.0, 33.33, 33.33});
        int64_t scoreBad30fpsTo60Hz = h.getMetrics().judderScoreHistogram.getMax();
        EXPECT_GT(scoreBad30fpsTo60Hz, previousScore);
        previousScore = scoreBad30fpsTo60Hz;
    }

    // 25fps displayed at 60hz
    {
        Helper h(40, c);
        h.render({33.33, 33.33, 50.0});
        h.render({33.33, 33.33, 50.0});
        h.render({33.33, 33.33, 50.0});
        h.render({33.33, 33.33, 50.0});
        h.render({33.33, 33.33, 50.0});
        h.render({33.33, 33.33, 50.0});
        int64_t score25fpsTo60hz = h.getMetrics().judderScoreHistogram.getMax();
        EXPECT_GT(score25fpsTo60hz, previousScore);
        previousScore = score25fpsTo60hz;
    }

    // 50fps displayed at 60hz
    {
        Helper h(20, c);
        h.render({16.66, 16.66, 16.66, 33.33});
        h.render({16.66, 16.66, 16.66, 33.33});
        h.render({16.66, 16.66, 16.66, 33.33});
        h.render({16.66, 16.66, 16.66, 33.33});
        h.render({16.66, 16.66, 16.66, 33.33});
        h.render({16.66, 16.66, 16.66, 33.33});
        int64_t score50fpsTo60hz = h.getMetrics().judderScoreHistogram.getMax();
        EXPECT_GT(score50fpsTo60hz, previousScore);
        previousScore = score50fpsTo60hz;
    }

    // 24fps poorly displayed at 60Hz
    {
        Helper h(41.66, c);
        h.render({50.0, 33.33, 50.0, 33.33, 33.33, 50.0, 33.33});
        int64_t scoreBad24HzTo60Hz = h.getMetrics().judderScoreHistogram.getMax();
        EXPECT_GT(scoreBad24HzTo60Hz, previousScore);
        previousScore = scoreBad24HzTo60Hz;
    }

    // 30fps displayed at 50hz
    {
        Helper h(33.33, c);
        h.render({40.0, 40.0, 40.0, 60.0});
        h.render({40.0, 40.0, 40.0, 60.0});
        h.render({40.0, 40.0, 40.0, 60.0});
        h.render({40.0, 40.0, 40.0, 60.0});
        h.render({40.0, 40.0, 40.0, 60.0});
        int64_t score30fpsTo50hz = h.getMetrics().judderScoreHistogram.getMax();
        EXPECT_GT(score30fpsTo50hz, previousScore);
        previousScore = score30fpsTo50hz;
    }

    // 24fps displayed at 50Hz
    {
        Helper h(41.66, c);
        h.render(40.0, 11);
        h.render(60.0, 1);
        h.render(40.0, 11);
        h.render(60.0, 1);
        h.render(40.0, 11);
        int64_t score24HzTo50Hz = h.getMetrics().judderScoreHistogram.getMax();
        EXPECT_GT(score24HzTo50Hz, previousScore);
        previousScore = score24HzTo50Hz;
    }
}

TEST_F(VideoRenderQualityTrackerTest, capturesFreezeEvents) {
    Configuration c;
    c.freezeEventMax = 5;
    c.freezeEventDetailsMax = 4;
    c.freezeEventDistanceToleranceMs = 1000;
    Helper h(20, c);
    h.render(10);
    EXPECT_EQ(h.getAndClearFreezeEvent().valid, false);
    h.drop(3);
    h.render(1000 / 20); // +1 because it's unclear if the current frame is frozen
    EXPECT_EQ(h.getAndClearFreezeEvent().valid, false);
    h.drop(1);
    h.render(10);
    EXPECT_EQ(h.getAndClearFreezeEvent().valid, false);
    h.drop(6);
    h.render(12);
    EXPECT_EQ(h.getAndClearFreezeEvent().valid, false);
    h.drop(10);
    h.render(1000 / 20 + 1); // +1 because it's unclear if the current frame is frozen
    EXPECT_EQ(h.getMetrics().freezeEventCount, 1);
    FreezeEvent e = h.getAndClearFreezeEvent();
    EXPECT_EQ(e.valid, true); // freeze event
    // -1 because the last rendered frame is considered frozen
    EXPECT_EQ(e.initialTimeUs, 9 * 20 * 1000);
    // only count the last frame of the first group of rendered frames
    EXPECT_EQ(e.durationMs, (1 + 3 + 1000 / 20 + 1 + 10 + 6 + 12 + 10) * 20);
    EXPECT_EQ(e.count, 4);
    // number of dropped frames
    // +1 because the last rendered frame is considered frozen
    EXPECT_EQ(e.sumDurationMs, (4 + 2 + 7 + 11) * 20);
    // number of rendered frames between dropped frames
    // -1 because the last rendered frame is considered frozen
    EXPECT_EQ(e.sumDistanceMs, ((1000 / 20) - 1 + 9 + 11) * 20);
    // +1 for each since the last rendered frame is considered frozen
    ASSERT_EQ(e.details.durationMs.size(), 4);
    EXPECT_EQ(e.details.durationMs[0], 4 * 20);
    EXPECT_EQ(e.details.durationMs[1], 2 * 20);
    EXPECT_EQ(e.details.durationMs[2], 7 * 20);
    EXPECT_EQ(e.details.durationMs[3], 11 * 20);
    // -1 for each since the last rendered frame is considered frozen
    ASSERT_EQ(e.details.distanceMs.size(), 4);
    EXPECT_EQ(e.details.distanceMs[0], -1);
    EXPECT_EQ(e.details.distanceMs[1], 1000 - 20);
    EXPECT_EQ(e.details.distanceMs[2], 9 * 20);
    EXPECT_EQ(e.details.distanceMs[3], 11 * 20);
    int64_t previousEventEndTimeUs = e.initialTimeUs + e.durationMs * 1000;
    h.drop(1);
    h.render(4);
    h.drop(1);
    h.render(4);
    h.drop(1);
    h.render(4);
    h.drop(1);
    h.render(4);
    h.drop(1);
    h.render(1000 / 20 + 1);
    EXPECT_EQ(h.getMetrics().freezeEventCount, 2);
    e = h.getAndClearFreezeEvent();
    EXPECT_EQ(e.valid, true);
    // 1000ms tolerance means 1000ms from the end of the last event to the beginning of this event
    EXPECT_EQ(e.initialTimeUs, previousEventEndTimeUs + 1000 * 1000);
    EXPECT_EQ(e.count, 5);
    // 5 freezes captured in the freeze event, but only 4 details are recorded
    EXPECT_EQ(e.details.durationMs.size(), 4);
    EXPECT_EQ(e.details.distanceMs.size(), 4);
    EXPECT_EQ(e.details.distanceMs[0], 1000); // same as the tolerance
    // The duration across the entire series f freezes is captured, with only 4 details captured
    // +1 because the first rendered frame is considered frozen (not the 1st dropped frame)
    EXPECT_EQ(e.durationMs, (1 + 1 + 4 + 1 + 4 + 1 + 4 + 1 + 4 + 1) * 20);
    // The duration of all 5 freeze events are captured, with only 4 details captured
    EXPECT_EQ(e.sumDurationMs, (2 + 2 + 2 + 2 + 2) * 20);
    // The distance of all 5 freeze events are captured, with only 4 details captured
    EXPECT_EQ(e.sumDistanceMs, (3 + 3 + 3 + 3) * 20);
    h.drop(1);
    h.render(1000 / 20 + 1);
    EXPECT_EQ(h.getMetrics().freezeEventCount, 3);
    EXPECT_EQ(h.getAndClearFreezeEvent().valid, true);
    h.drop(1);
    h.render(1000 / 20 + 1);
    EXPECT_EQ(h.getMetrics().freezeEventCount, 4);
    EXPECT_EQ(h.getAndClearFreezeEvent().valid, true);
    h.drop(1);
    h.render(1000 / 20 + 1);
    EXPECT_EQ(h.getMetrics().freezeEventCount, 5);
    EXPECT_EQ(h.getAndClearFreezeEvent().valid, true);
    h.drop(1);
    h.render(1000 / 20 + 1);
    // The 6th event isn't captured because it exceeds the configured limit
    EXPECT_EQ(h.getMetrics().freezeEventCount, 6);
    EXPECT_EQ(h.getAndClearFreezeEvent().valid, false);
}

TEST_F(VideoRenderQualityTrackerTest, capturesJudderEvents) {
    Configuration c;
    c.judderEventMax = 4;
    c.judderEventDetailsMax = 3;
    c.judderEventDistanceToleranceMs = 100;
    Helper h(20, c);
    h.render({19, 20, 19});
    EXPECT_EQ(h.getAndClearJudderEvent().valid, false);
    h.render({15, 19, 20, 19});
    EXPECT_EQ(h.getAndClearJudderEvent().valid, false);
    h.render({28, 20, 19});
    EXPECT_EQ(h.getAndClearJudderEvent().valid, false);
    h.render({13, 20, 20, 20, 20});
    EXPECT_EQ(h.getAndClearJudderEvent().valid, false);
    // Start with judder for the next event at the end of the sequence, because judder is scored
    // one frame behind, and for combining judder occurrences into events, it's not clear yet if
    // the current frame has judder or not.
    h.render({15, 20, 20, 20, 20, 20, 15});
    JudderEvent e = h.getAndClearJudderEvent();
    EXPECT_EQ(e.valid, true);
    EXPECT_EQ(e.initialTimeUs, (19 + 20 + 19) * 1000);
    EXPECT_EQ(e.durationMs, 15 + 19 + 20 + 19 /**/ + 28 + 20 + 19 /**/ + 13 + 20 * 4 /**/ + 15);
    EXPECT_EQ(e.count, 4);
    EXPECT_EQ(e.sumScore, (20 - 15) + (28 - 20) + (20 - 13) + (20 - 15));
    EXPECT_EQ(e.sumDistanceMs, 19 + 20 + 19 /**/ + 20 + 19 /**/ + 20 * 4);
    ASSERT_EQ(e.details.actualRenderDurationUs.size(), 3); // 3 details per configured maximum
    EXPECT_EQ(e.details.actualRenderDurationUs[0], 15 * 1000);
    EXPECT_EQ(e.details.actualRenderDurationUs[1], 28 * 1000);
    EXPECT_EQ(e.details.actualRenderDurationUs[2], 13 * 1000);
    ASSERT_EQ(e.details.contentRenderDurationUs.size(), 3);
    EXPECT_EQ(e.details.contentRenderDurationUs[0], 20 * 1000);
    EXPECT_EQ(e.details.contentRenderDurationUs[1], 20 * 1000);
    EXPECT_EQ(e.details.contentRenderDurationUs[2], 20 * 1000);
    ASSERT_EQ(e.details.distanceMs.size(), 3);
    EXPECT_EQ(e.details.distanceMs[0], -1);
    EXPECT_EQ(e.details.distanceMs[1], 19 + 20 + 19);
    EXPECT_EQ(e.details.distanceMs[2], 20 + 19);
    h.render({20, 20, 20, 20, 20, 15});
    e = h.getAndClearJudderEvent();
    EXPECT_EQ(e.valid, true);
    ASSERT_EQ(e.details.distanceMs.size(), 1);
    EXPECT_EQ(e.details.distanceMs[0], 100); // same as the tolerance
    h.render({20, 20, 20, 20, 20, 15});
    EXPECT_EQ(h.getAndClearJudderEvent().valid, true);
    h.render({20, 20, 20, 20, 20, 15});
    EXPECT_EQ(h.getAndClearJudderEvent().valid, true);
    h.render({20, 20, 20, 20, 20, 20});
    EXPECT_EQ(h.getAndClearJudderEvent().valid, false); // max number of judder events exceeded
}

} // android
