/*
 * Copyright 2023, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef VIDEO_RENDER_QUALITY_TRACKER_H_

#define VIDEO_RENDER_QUALITY_TRACKER_H_

#include <assert.h>
#include <list>
#include <queue>

#include <media/stagefright/MediaHistogram.h>

namespace android {

// A variety of video rendering quality metrics.
struct VideoRenderQualityMetrics {
    static constexpr float FRAME_RATE_UNDETERMINED = -1.0f;
    static constexpr float FRAME_RATE_24_3_2_PULLDOWN = -2.0f;

    VideoRenderQualityMetrics();

    void clear();

    // The render time of the first video frame.
    int64_t firstRenderTimeUs;

    // The number of frames released to be rendered.
    int64_t frameReleasedCount;

    // The number of frames actually rendered.
    int64_t frameRenderedCount;

    // The number of frames dropped - frames that were released but never rendered.
    int64_t frameDroppedCount;

    // The number of frames that were intentionally dropped/skipped by the app.
    int64_t frameSkippedCount;

    // The frame rate as detected by looking at the position timestamp from the content stream.
    float contentFrameRate;

    // The frame rate as detected by looking at the desired render time passed in by the app.
    float desiredFrameRate;

    // The frame rate as detected by looking at the actual render time, as returned by the system
    // post-render.
    float actualFrameRate;

    // A histogram of the durations of freezes due to dropped/skipped frames.
    MediaHistogram<int32_t> freezeDurationMsHistogram;
    // The computed overall freeze score using the above histogram and score conversion table.
    int32_t freezeScore;
    // The computed percentage of total playback duration that was frozen.
    float freezeRate;

    // A histogram of the durations between each freeze.
    MediaHistogram<int32_t> freezeDistanceMsHistogram;

    // A histogram of the judder scores.
    MediaHistogram<int32_t> judderScoreHistogram;
    // The computed overall judder score using the above histogram and score conversion table.
    int32_t judderScore;
    // The computed percentage of total frames that had judder.
    float judderRate;
};

///////////////////////////////////////////////////////
// This class analyzes various timestamps related to video rendering to compute a set of metrics
// that attempt to capture the quality of the user experience during video playback.
//
// The following timestamps (in microseconds) are analyzed to compute these metrics:
//   * The content timestamp found in the content stream, indicating the position of each video
//     frame.
//   * The desired timestamp passed in by the app, indicating at what point in time in the future
//     the app would like the frame to be rendered.
//   * The actual timestamp passed in by the display subsystem, indicating the point in time at
//     which the frame was actually rendered.
//
// Core to the algorithms are deriving frame durations based on these timestamps and determining
// the result of each video frame in the content stream:
//   * skipped: the app didn't want to render the frame
//   * dropped: the display subsystem could not render the frame in time
//   * rendered: the display subsystem rendered the frame
//
class VideoRenderQualityTracker {
public:
    // Configurable elements of the metrics algorithms
    class Configuration {
    public:
        Configuration();

        // Whether or not frame render quality is tracked.
        bool enabled;

        // Whether or not frames that are intentionally not rendered by the app should be considered
        // as dropped.
        bool areSkippedFramesDropped;

        // How large of a jump forward in content time is allowed before it is considered a
        // discontinuity (seek/playlist) and various internal states are reset.
        int32_t maxExpectedContentFrameDurationUs;

        // How much tolerance in frame duration when considering whether or not two frames have the
        // same frame rate.
        int32_t frameRateDetectionToleranceUs;

        // A skip forward in content time could occur during frame drops of live content. Therefore
        // the content frame duration and the app-desired frame duration are compared using this
        // tolerance to determine whether the app is intentionally seeking forward or whether the
        // skip forward in content time is due to frame drops. If the app-desired frame duration is
        // short, but the content frame duration is large, it is assumed the app is intentionally
        // seeking forward.
        int32_t contentTimeAdvancedForLiveContentToleranceUs;

        // Freeze configuration
        //
        // The values used to distribute freeze durations across a histogram.
        std::vector<int32_t> freezeDurationMsHistogramBuckets;
        // The values used to compare against freeze duration counts when determining an overall
        // score.
        std::vector<int64_t> freezeDurationMsHistogramToScore;
        // The values used to distribute distances between freezes across a histogram.
        std::vector<int32_t> freezeDistanceMsHistogramBuckets;

        // Judder configuration
        //
        // A judder error lower than this value is not scored as judder.
        int32_t judderErrorToleranceUs;
        // The values used to distribute judder scores across a histogram.
        std::vector<int32_t> judderScoreHistogramBuckets;
        // The values used to compare against judder score histogram counts when determining an
        // overall score.
        std::vector<int32_t> judderScoreHistogramToScore;
    };

    VideoRenderQualityTracker();
    VideoRenderQualityTracker(const Configuration &configuration);

    // Called when a tunnel mode frame has been queued.
    void onTunnelFrameQueued(int64_t contentTimeUs);

    // Called when the app has intentionally decided not to render this frame.
    void onFrameSkipped(int64_t contentTimeUs);

    // Called when the app has requested the frame to be rendered as soon as possible.
    void onFrameReleased(int64_t contentTimeUs);

    // Called when the app has requested the frame to be rendered at a specific point in time in the
    // future.
    void onFrameReleased(int64_t contentTimeUs, int64_t desiredRenderTimeNs);

    // Called when the system has detected that the frame has actually been rendered to the display.
    void onFrameRendered(int64_t contentTimeUs, int64_t actualRenderTimeNs);

    // Retrieve the metrics.
    const VideoRenderQualityMetrics &getMetrics();

    // Called when a change in codec state will result in a content discontinuity - e.g. flush.
    void resetForDiscontinuity();

    // Clear out all metrics and tracking - e.g. codec reconfigured.
    void clear();

private:
    // Tracking of frames that are pending to be rendered to the display.
    struct FrameInfo {
        int64_t contentTimeUs;
        int64_t desiredRenderTimeUs;
    };

    // Historic tracking of frame durations
    struct FrameDurationUs {
        static const int SIZE = 5;

        FrameDurationUs() {
            for (int i = 0; i < SIZE; ++i) {
                durationUs[i] = -1;
            }
            priorTimestampUs = -1;
        }

        int32_t &operator[](int index) {
            assert(index < SIZE);
            return durationUs[index];
        }

        const int32_t &operator[](int index) const {
            assert(index < SIZE);
            return durationUs[index];
        }

        // The duration of the past N frames.
        int32_t durationUs[SIZE];

        // The timestamp of the previous frame.
        int64_t priorTimestampUs;
    };

    // Configure histograms for the metrics.
    static void configureHistograms(VideoRenderQualityMetrics &m, const Configuration &c);

    // The current time in microseconds.
    static int64_t nowUs();

    // A new frame has been processed, so update the frame durations based on the new frame
    // timestamp.
    static void updateFrameDurations(FrameDurationUs &durationUs, int64_t newTimestampUs);

    // Update a frame rate if, and only if, one can be detected.
    static void updateFrameRate(float &frameRate, const FrameDurationUs &durationUs,
                                const Configuration &c);

    // Examine the past few frames to detect the frame rate based on each frame's render duration.
    static float detectFrameRate(const FrameDurationUs &durationUs, const Configuration &c);

    // Determine whether or not 3:2 pulldowng for displaying 24fps content on 60Hz displays is
    // occurring.
    static bool is32pulldown(const FrameDurationUs &durationUs, const Configuration &c);

    // Process a frame freeze.
    static void processFreeze(int64_t actualRenderTimeUs, int64_t lastRenderTimeUs,
                              int64_t lastFreezeEndTimeUs, VideoRenderQualityMetrics &m);

    // Compute a judder score for the previously-rendered frame.
    static int64_t computePreviousJudderScore(const FrameDurationUs &actualRenderDurationUs,
                                              const FrameDurationUs &contentRenderDurationUs,
                                              const Configuration &c);

    // Check to see if a discontinuity has occurred by examining the content time and the
    // app-desired render time. If so, reset some internal state.
    bool resetIfDiscontinuity(int64_t contentTimeUs, int64_t desiredRenderTimeUs);

    // Update the metrics because a skipped frame was detected.
    void processMetricsForSkippedFrame(int64_t contentTimeUs);

    // Update the metrics because a dropped frame was detected.
    void processMetricsForDroppedFrame(int64_t contentTimeUs, int64_t desiredRenderTimeUs);

    // Update the metrics because a rendered frame was detected.
    void processMetricsForRenderedFrame(int64_t contentTimeUs, int64_t desiredRenderTimeUs,
                                        int64_t actualRenderTimeUs);

    // Configurable elements of the metrics algorithms.
    const Configuration mConfiguration;

    // Metrics are updated every time a frame event occurs - skipped, dropped, rendered.
    VideoRenderQualityMetrics mMetrics;

    // The most recently processed timestamp referring to the position in the content stream.
    int64_t mLastContentTimeUs;

    // The most recently processed timestamp referring to the wall clock time a frame was rendered.
    int64_t mLastRenderTimeUs;

    // The most recent timestamp of the first frame rendered after the freeze.
    int64_t mLastFreezeEndTimeUs;

    // The render duration of the playback.
    int64_t mRenderDurationMs;

    // Frames skipped at the end of playback shouldn't really be considered skipped, therefore keep
    // a list of the frames, and process them as skipped frames the next time a frame is rendered.
    std::list<int64_t> mPendingSkippedFrameContentTimeUsList;

    // Since the system only signals when a frame is rendered, dropped frames are detected by
    // checking to see if the next expected frame is rendered. If not, it is considered dropped.
    std::queue<FrameInfo> mNextExpectedRenderedFrameQueue;

    // When B-frames are present in the stream, a P-frame will be queued before the B-frame even
    // though it is rendered after. Therefore, the P-frame is held here and not inserted into
    // mNextExpectedRenderedFrameQueue until it should be inserted to maintain render order.
    int64_t mTunnelFrameQueuedContentTimeUs;

    // Frame durations derived from timestamps encoded into the content stream. These are the
    // durations that each frame is supposed to be rendered for.
    FrameDurationUs mContentFrameDurationUs;

    // Frame durations derived from timestamps passed in by the app, indicating the wall clock time
    // at which the app would like to have the frame rendered.
    FrameDurationUs mDesiredFrameDurationUs;

    // Frame durations derived from timestamps captured by the display subsystem, indicating the
    // wall clock atime at which the frame is actually rendered.
    FrameDurationUs mActualFrameDurationUs;
};

}  // namespace android

#endif  // VIDEO_RENDER_QUALITY_TRACKER_H_
