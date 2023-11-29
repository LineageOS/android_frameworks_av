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

    // The render time of the last video frame.
    int64_t lastRenderTimeUs;

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

    // The amount of content duration skipped by the app after a pause when video was trying to
    // resume. This sometimes happen when catching up to the audio position which continued playing
    // after video pauses.
    int32_t maxContentDroppedAfterPauseMs;

    // A histogram of the durations of freezes due to dropped/skipped frames.
    MediaHistogram<int32_t> freezeDurationMsHistogram;
    // The computed overall freeze score using the above histogram and score conversion table. The
    // score is based on counts in the histogram bucket, multiplied by the value in the score
    // conversion table for that bucket. For example, the impact of a short freeze may be minimal,
    // but the impact of long freeze may be disproportionally worse. Therefore, the score
    // multipliers for each bucket might increase exponentially instead of linearly. A score
    // multiplier of zero would reflect that small freeze durations have near-zero impact to the
    // user experience.
    int32_t freezeScore;
    // The computed percentage of total playback duration that was frozen.
    float freezeRate;
    // The number of freeze events.
    int32_t freezeEventCount;

    // A histogram of the durations between each freeze.
    MediaHistogram<int32_t> freezeDistanceMsHistogram;

    // A histogram of the judder scores - based on the error tolerance between actual render
    // duration of each frame and the ideal render duration.
    MediaHistogram<int32_t> judderScoreHistogram;
    // The computed overall judder score using the above histogram and score conversion table. The
    // score is based on counts in the histogram bucket, multiplied by the value in the score
    // conversion table for that bucket. For example, the impact of minimal judder may be small,
    // but the impact of large judder may be disproportionally worse. Therefore, the score
    // multipliers for each bucket might increase exponentially instead of linearly. A score
    // multiplier of zero would reflect that small judder errors have near-zero impact to the user
    // experience.
    int32_t judderScore;
    // The computed percentage of total frames that had judder.
    float judderRate;
    // The number of judder events.
    int32_t judderEventCount;
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
        // system/server_configurable_flags/libflags/include/get_flags.h:GetServerConfigurableFlag
        typedef std::string (*GetServerConfigurableFlagFn)(
                const std::string& experiment_category_name,
                const std::string& experiment_flag_name,
                const std::string& default_value);

        static Configuration getFromServerConfigurableFlags(
                GetServerConfigurableFlagFn getServerConfigurableFlagFn);

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
        int32_t liveContentFrameDropToleranceUs;

        // The amount of time it takes for audio to stop playback after a pause is initiated. Used
        // for providing some allowance of dropped video frames to catch back up to the audio
        // position when resuming playback.
        int32_t pauseAudioLatencyUs;

        // Freeze configuration
        //
        // The values used to distribute freeze durations across a histogram.
        std::vector<int32_t> freezeDurationMsHistogramBuckets;
        //
        // The values used to multiply the counts in the histogram buckets above to compute an
        // overall score. This allows the score to reflect disproportionate impact as freeze
        // durations increase.
        std::vector<int64_t> freezeDurationMsHistogramToScore;
        //
        // The values used to distribute distances between freezes across a histogram.
        std::vector<int32_t> freezeDistanceMsHistogramBuckets;
        //
        // The maximum number of freeze events to send back to the caller.
        int32_t freezeEventMax;
        //
        // The maximum number of detail entries tracked per freeze event.
        int32_t freezeEventDetailsMax;
        //
        // The maximum distance in time between two freeze occurrences such that both will be
        // lumped into the same freeze event.
        int32_t freezeEventDistanceToleranceMs;

        // Judder configuration
        //
        // A judder error lower than this value is not scored as judder.
        int32_t judderErrorToleranceUs;
        //
        // The values used to distribute judder scores across a histogram.
        std::vector<int32_t> judderScoreHistogramBuckets;
        //
        // The values used to multiply the counts in the histogram buckets above to compute an
        // overall score. This allows the score to reflect disproportionate impact as judder scores
        // increase.
        std::vector<int64_t> judderScoreHistogramToScore;
        //
        // The maximum number of judder events to send back to the caller.
        int32_t judderEventMax;
        //
        // The maximum number of detail entries tracked per judder event.
        int32_t judderEventDetailsMax;
        //
        // The maximum distance in time between two judder occurrences such that both will be
        // lumped into the same judder event.
        int32_t judderEventDistanceToleranceMs;
        //
        // Whether or not Perfetto trace trigger is enabled.
        bool traceTriggerEnabled;
        //
        // The throttle time for Perfetto trace trigger to avoid triggering multiple traces for
        // the same event in a short time.
        int32_t traceTriggerThrottleMs;
        //
        // The minimum frame render duration to recognize video freeze event to collect trace.
        int32_t traceMinFreezeDurationMs;
    };

    struct FreezeEvent {
        // Details are captured for each freeze up to a limited number. The arrays are guaranteed to
        // have the same size.
        struct Details {
            /// The duration of the freeze.
            std::vector<int32_t> durationMs;
            // The distance between the beginning of this freeze and the end of the previous freeze.
            std::vector<int32_t> distanceMs;
        };
        // Whether or not the data in this structure is valid.
        bool valid = false;
        // The time at which the first freeze for this event was detected.
        int64_t initialTimeUs;
        // The total duration from the beginning of the first freeze to the end of the last freeze
        // in this event.
        int32_t durationMs;
        // The number of freezes in this event.
        int64_t count;
        // The sum of all durations of all freezes in this event.
        int64_t sumDurationMs;
        // The sum of all distances between each freeze in this event.
        int64_t sumDistanceMs;
        // Detailed information for the first N freezes in this event.
        Details details;
    };

    struct JudderEvent {
        // Details are captured for each frame judder up to a limited number. The arrays are
        // guaranteed to have the same size.
        struct Details {
            // The actual render duration of the frame for this judder occurrence.
            std::vector<int32_t> actualRenderDurationUs;
            // The content render duration of the frame for this judder occurrence.
            std::vector<int32_t> contentRenderDurationUs;
            // The distance from this judder occurrence and the previous judder occurrence.
            std::vector<int32_t> distanceMs;
        };
        // Whether or not the data in this structure is valid.
        bool valid = false;
        // The time at which the first judder occurrence for this event was detected.
        int64_t initialTimeUs;
        // The total duration from the first judder occurrence to the last judder occurrence in this
        // event.
        int32_t durationMs;
        // The number of judder occurrences in this event.
        int64_t count;
        // The sum of all judder scores in this event.
        int64_t sumScore;
        // The sum of all distances between each judder occurrence in this event.
        int64_t sumDistanceMs;
        // Detailed information for the first N judder occurrences in this event.
        Details details;
    };

    typedef void (*TraceTriggerFn)();

    VideoRenderQualityTracker();
    VideoRenderQualityTracker(const Configuration &configuration,
                              const TraceTriggerFn traceTriggerFn = nullptr);

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
    // Returns any freeze events or judder events that were detected.
    void onFrameRendered(int64_t contentTimeUs, int64_t actualRenderTimeNs,
                         FreezeEvent *freezeEventOut = nullptr,
                         JudderEvent *judderEventOut = nullptr);

    // Gets and resets data for the current freeze event.
    FreezeEvent getAndResetFreezeEvent();

    // Gets and resets data for the current judder event.
    JudderEvent getAndResetJudderEvent();

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
                              int64_t lastFreezeEndTimeUs, FreezeEvent &e,
                              VideoRenderQualityMetrics &m, const Configuration &c,
                              const TraceTriggerFn traceTriggerFn);

    // Retrieve a freeze event if an event just finished.
    static void maybeCaptureFreezeEvent(int64_t actualRenderTimeUs, int64_t lastFreezeEndTimeUs,
                                        FreezeEvent &e, const VideoRenderQualityMetrics & m,
                                        const Configuration &c, FreezeEvent *freezeEventOut);

    // Compute a judder score for the previously-rendered frame.
    static int64_t computePreviousJudderScore(const FrameDurationUs &actualRenderDurationUs,
                                              const FrameDurationUs &contentRenderDurationUs,
                                              const Configuration &c);

    // Process a frame judder.
    static void processJudder(int32_t judderScore, int64_t judderTimeUs,
                              int64_t lastJudderEndTimeUs,
                              const FrameDurationUs &contentDurationUs,
                              const FrameDurationUs &actualDurationUs, JudderEvent &e,
                              VideoRenderQualityMetrics &m, const Configuration &c);

    // Retrieve a judder event if an event just finished.
    static void maybeCaptureJudderEvent(int64_t actualRenderTimeUs, int64_t lastJudderEndTimeUs,
                                        JudderEvent &e, const VideoRenderQualityMetrics & m,
                                        const Configuration &c, JudderEvent *judderEventOut);

    // Trigger trace collection for video freeze.
    static void triggerTrace();

    // Trigger collection of a Perfetto Always-On-Tracing (AOT) trace file for video freeze,
    // triggerTimeUs is used as a throttle to avoid triggering multiple traces in a short time.
    static void triggerTraceWithThrottle(TraceTriggerFn traceTriggerFn,
                                         const Configuration &c, const int64_t triggerTimeUs);

    // Check to see if a discontinuity has occurred by examining the content time and the
    // app-desired render time. If so, reset some internal state.
    bool resetIfDiscontinuity(int64_t contentTimeUs, int64_t desiredRenderTimeUs);

    // Update the metrics because a skipped frame was detected.
    void processMetricsForSkippedFrame(int64_t contentTimeUs);

    // Update the metrics because a dropped frame was detected.
    void processMetricsForDroppedFrame(int64_t contentTimeUs, int64_t desiredRenderTimeUs);

    // Update the metrics because a rendered frame was detected.
    void processMetricsForRenderedFrame(int64_t contentTimeUs, int64_t desiredRenderTimeUs,
                                        int64_t actualRenderTimeUs,
                                        FreezeEvent *freezeEventOut, JudderEvent *judderEventOut);

    // Configurable elements of the metrics algorithms.
    const Configuration mConfiguration;

    // The function for triggering trace collection for video freeze.
    const TraceTriggerFn mTraceTriggerFn;

    // Metrics are updated every time a frame event occurs - skipped, dropped, rendered.
    VideoRenderQualityMetrics mMetrics;

    // The most recently processed timestamp referring to the position in the content stream.
    int64_t mLastContentTimeUs;

    // The most recently processed timestamp referring to the wall clock time a frame was rendered.
    int64_t mLastRenderTimeUs;

    // The most recent timestamp of the first frame rendered after the freeze.
    int64_t mLastFreezeEndTimeUs;

    // The most recent timestamp of frame judder.
    int64_t mLastJudderEndTimeUs;

    // The render duration of the playback.
    int64_t mRenderDurationMs;

    // The duration of the content that was dropped.
    int64_t mDroppedContentDurationUs;

    // The freeze event that's currently being tracked.
    FreezeEvent mFreezeEvent;

    // The judder event that's currently being tracked.
    JudderEvent mJudderEvent;

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

    // Token of async atrace for video frame dropped/skipped by the app.
    int64_t mTraceFrameSkippedToken= -1;
};

}  // namespace android

#endif  // VIDEO_RENDER_QUALITY_TRACKER_H_
