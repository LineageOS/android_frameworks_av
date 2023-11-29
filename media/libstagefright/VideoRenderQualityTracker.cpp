/*
 * Copyright (C) 2023 The Android Open Source Project
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

#define LOG_TAG "VideoRenderQualityTracker"
#define ATRACE_TAG ATRACE_TAG_VIDEO

#include <utils/Log.h>
#include <utils/Trace.h>
#include <utils/Mutex.h>

#include <media/stagefright/VideoRenderQualityTracker.h>

#include <assert.h>
#include <charconv>
#include <cmath>
#include <stdio.h>
#include <sys/time.h>
#include <sys/wait.h>

#include <android-base/macros.h>
#include <android-base/parsebool.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>

namespace android {

using android::base::ParseBoolResult;

static constexpr float FRAME_RATE_UNDETERMINED = VideoRenderQualityMetrics::FRAME_RATE_UNDETERMINED;
static constexpr float FRAME_RATE_24_3_2_PULLDOWN =
        VideoRenderQualityMetrics::FRAME_RATE_24_3_2_PULLDOWN;

typedef VideoRenderQualityTracker::Configuration::GetServerConfigurableFlagFn
        GetServerConfigurableFlagFn;
typedef VideoRenderQualityTracker::TraceTriggerFn TraceTriggerFn;

static void getServerConfigurableFlag(GetServerConfigurableFlagFn getServerConfigurableFlagFn,
                                      char const *flagNameSuffix, bool *value) {
    std::string flagName("render_metrics_");
    flagName.append(flagNameSuffix);
    std::string valueStr = (*getServerConfigurableFlagFn)("media_native", flagName,
                                                          *value ? "true" : "false");
    switch (android::base::ParseBool(valueStr)) {
    case ParseBoolResult::kTrue: *value = true; break;
    case ParseBoolResult::kFalse: *value = false; break;
    case ParseBoolResult::kError:
        ALOGW("failed to parse server-configurable flag '%s' from '%s'", flagNameSuffix,
              valueStr.c_str());
        break;
    }
}

static void getServerConfigurableFlag(GetServerConfigurableFlagFn getServerConfigurableFlagFn,
                                      char const *flagNameSuffix, int32_t *value) {
    char defaultStr[11];
    sprintf(defaultStr, "%d", int(*value));
    std::string flagName("render_metrics_");
    flagName.append(flagNameSuffix);
    std::string valueStr = (*getServerConfigurableFlagFn)("media_native", flagName, defaultStr);
    if (!android::base::ParseInt(valueStr.c_str(), value) || valueStr.size() == 0) {
        ALOGW("failed to parse server-configurable flag '%s' from '%s'", flagNameSuffix,
              valueStr.c_str());
        return;
    }
}

template<typename T>
static void getServerConfigurableFlag(GetServerConfigurableFlagFn getServerConfigurableFlagFn,
                                      char const *flagNameSuffix, std::vector<T> *value) {
    std::stringstream sstr;
    for (int i = 0; i < value->size(); ++i) {
        if (i != 0) {
            sstr << ",";
        }
        sstr << (*value)[i];
    }
    std::string flagName("render_metrics_");
    flagName.append(flagNameSuffix);
    std::string valueStr = (*getServerConfigurableFlagFn)("media_native", flagName, sstr.str());
    if (valueStr.size() == 0) {
        return;
    }
    // note: using android::base::Tokenize fails to catch parsing failures for values ending in ','
    std::vector<T> newValues;
    const char *p = valueStr.c_str();
    const char *last = p + valueStr.size();
    while (p != last) {
        if (*p == ',') {
            p++;
        }
        T value = -1;
        auto [ptr, error] = std::from_chars(p, last, value);
        if (error == std::errc::invalid_argument || error == std::errc::result_out_of_range) {
            ALOGW("failed to parse server-configurable flag '%s' from '%s'", flagNameSuffix,
                  valueStr.c_str());
            return;
        }
        p = ptr;
        newValues.push_back(value);
    }
    *value = std::move(newValues);
}

VideoRenderQualityMetrics::VideoRenderQualityMetrics() {
    clear();
}

void VideoRenderQualityMetrics::clear() {
    firstRenderTimeUs = 0;
    frameReleasedCount = 0;
    frameRenderedCount = 0;
    frameDroppedCount = 0;
    frameSkippedCount = 0;
    contentFrameRate = FRAME_RATE_UNDETERMINED;
    desiredFrameRate = FRAME_RATE_UNDETERMINED;
    actualFrameRate = FRAME_RATE_UNDETERMINED;
    maxContentDroppedAfterPauseMs = 0;
    freezeEventCount = 0;
    freezeDurationMsHistogram.clear();
    freezeDistanceMsHistogram.clear();
    judderEventCount = 0;
    judderScoreHistogram.clear();
}

VideoRenderQualityTracker::Configuration
        VideoRenderQualityTracker::Configuration::getFromServerConfigurableFlags(
            GetServerConfigurableFlagFn getServerConfigurableFlagFn) {
    VideoRenderQualityTracker::Configuration c;
#define getFlag(FIELDNAME, FLAGNAME) \
    getServerConfigurableFlag(getServerConfigurableFlagFn, FLAGNAME, &c.FIELDNAME)
    getFlag(enabled, "enabled");
    getFlag(areSkippedFramesDropped, "are_skipped_frames_dropped");
    getFlag(maxExpectedContentFrameDurationUs, "max_expected_content_frame_duration_us");
    getFlag(frameRateDetectionToleranceUs, "frame_rate_detection_tolerance_us");
    getFlag(liveContentFrameDropToleranceUs, "live_content_frame_drop_tolerance_us");
    getFlag(pauseAudioLatencyUs, "pause_audio_latency_us");
    getFlag(freezeDurationMsHistogramBuckets, "freeze_duration_ms_histogram_buckets");
    getFlag(freezeDurationMsHistogramToScore, "freeze_duration_ms_histogram_to_score");
    getFlag(freezeDistanceMsHistogramBuckets, "freeze_distance_ms_histogram_buckets");
    getFlag(freezeEventMax, "freeze_event_max");
    getFlag(freezeEventDetailsMax, "freeze_event_details_max");
    getFlag(freezeEventDistanceToleranceMs, "freeze_event_distance_tolerance_ms");
    getFlag(judderErrorToleranceUs, "judder_error_tolerance_us");
    getFlag(judderScoreHistogramBuckets, "judder_score_histogram_buckets");
    getFlag(judderScoreHistogramToScore, "judder_score_histogram_to_score");
    getFlag(judderEventMax, "judder_event_max");
    getFlag(judderEventDetailsMax, "judder_event_details_max");
    getFlag(judderEventDistanceToleranceMs, "judder_event_distance_tolerance_ms");
    getFlag(traceTriggerEnabled, "trace_trigger_enabled");
    getFlag(traceTriggerThrottleMs, "trace_trigger_throttle_ms");
    getFlag(traceMinFreezeDurationMs, "trace_minimum_freeze_duration_ms");
#undef getFlag
    return c;
}

VideoRenderQualityTracker::Configuration::Configuration() {
    enabled = false;

    // Assume that the app is skipping frames because it's detected that the frame couldn't be
    // rendered in time.
    areSkippedFramesDropped = true;

    // 400ms is 8 frames at 20 frames per second and 24 frames at 60 frames per second
    maxExpectedContentFrameDurationUs = 400 * 1000;

    // Allow for 2 milliseconds of deviation when detecting frame rates
    frameRateDetectionToleranceUs = 2 * 1000;

    // Allow for a tolerance of 200 milliseconds for determining if we moved forward in content time
    // because of frame drops for live content, or because the user is seeking.
    liveContentFrameDropToleranceUs = 200 * 1000;

    // After a pause is initiated, audio should likely stop playback within 200ms.
    pauseAudioLatencyUs = 200 * 1000;

    // Freeze configuration
    freezeDurationMsHistogramBuckets = {1, 20, 40, 60, 80, 100, 120, 150, 175, 225, 300, 400, 500};
    freezeDurationMsHistogramToScore = {1,  1,  1,  1,  1,   1,   1,   1,   1,   1,   1,   1,   1};
    freezeDistanceMsHistogramBuckets = {0, 20, 100, 400, 1000, 2000, 3000, 4000, 8000, 15000, 30000,
                                        60000};
    freezeEventMax = 0; // enabled only when debugging
    freezeEventDetailsMax = 20;
    freezeEventDistanceToleranceMs = 60000; // lump freeze occurrences together when 60s or less

    // Judder configuration
    judderErrorToleranceUs = 2000;
    judderScoreHistogramBuckets = {1, 4, 5, 9, 11, 20, 30, 40, 50, 60, 70, 80};
    judderScoreHistogramToScore = {1, 1, 1, 1,  1,  1,  1,  1,  1,  1,  1,  1};
    judderEventMax = 0; // enabled only when debugging
    judderEventDetailsMax = 20;
    judderEventDistanceToleranceMs = 5000; // lump judder occurrences together when 5s or less

    // Perfetto trigger configuration.
    traceTriggerEnabled = android::base::GetProperty(
        "ro.build.type", "user") != "user"; // Enabled for non-user builds for debugging.
    traceTriggerThrottleMs = 5 * 60 * 1000; // 5 mins.
    traceMinFreezeDurationMs = 400;
}

VideoRenderQualityTracker::VideoRenderQualityTracker()
    : mConfiguration(Configuration()), mTraceTriggerFn(triggerTrace) {
    configureHistograms(mMetrics, mConfiguration);
    clear();
}

VideoRenderQualityTracker::VideoRenderQualityTracker(const Configuration &configuration,
                                                     const TraceTriggerFn traceTriggerFn)
    : mConfiguration(configuration),
      mTraceTriggerFn(traceTriggerFn == nullptr ? triggerTrace : traceTriggerFn) {
    configureHistograms(mMetrics, mConfiguration);
    clear();
}

void VideoRenderQualityTracker::onTunnelFrameQueued(int64_t contentTimeUs) {
    if (!mConfiguration.enabled) {
        return;
    }

    // Since P-frames are queued out of order, hold onto the P-frame until we can track it in
    // render order. This only works because it depends on today's encoding algorithms that only
    // allow B-frames to refer to ONE P-frame that comes after it. If the cardinality of P-frames
    // in a single mini-GOP is increased, this algorithm breaks down.
    if (mTunnelFrameQueuedContentTimeUs == -1) {
        mTunnelFrameQueuedContentTimeUs = contentTimeUs;
    } else if (contentTimeUs < mTunnelFrameQueuedContentTimeUs) {
        onFrameReleased(contentTimeUs, 0);
    } else {
        onFrameReleased(mTunnelFrameQueuedContentTimeUs, 0);
        mTunnelFrameQueuedContentTimeUs = contentTimeUs;
    }
}

void VideoRenderQualityTracker::onFrameSkipped(int64_t contentTimeUs) {
    if (!mConfiguration.enabled) {
        return;
    }

    // Frames skipped at the beginning shouldn't really be counted as skipped frames, since the
    // app might be seeking to a starting point that isn't the first key frame.
    if (mLastRenderTimeUs == -1) {
        return;
    }

    resetIfDiscontinuity(contentTimeUs, -1);

    if (mTraceFrameSkippedToken == -1) {
       mTraceFrameSkippedToken = contentTimeUs;
       ATRACE_ASYNC_BEGIN("Video frame(s) skipped", mTraceFrameSkippedToken);
    }

    // Frames skipped at the end of playback shouldn't be counted as skipped frames, since the
    // app could be terminating the playback. The pending count will be added to the metrics if and
    // when the next frame is rendered.
    mPendingSkippedFrameContentTimeUsList.push_back(contentTimeUs);
}

void VideoRenderQualityTracker::onFrameReleased(int64_t contentTimeUs) {
    onFrameReleased(contentTimeUs, nowUs() * 1000);
}

void VideoRenderQualityTracker::onFrameReleased(int64_t contentTimeUs,
                                                int64_t desiredRenderTimeNs) {
    if (!mConfiguration.enabled) {
        return;
    }

    int64_t desiredRenderTimeUs = desiredRenderTimeNs / 1000;
    resetIfDiscontinuity(contentTimeUs, desiredRenderTimeUs);
    mMetrics.frameReleasedCount++;
    mNextExpectedRenderedFrameQueue.push({contentTimeUs, desiredRenderTimeUs});
    mLastContentTimeUs = contentTimeUs;
}

void VideoRenderQualityTracker::onFrameRendered(int64_t contentTimeUs, int64_t actualRenderTimeNs,
                                                FreezeEvent *freezeEventOut,
                                                JudderEvent *judderEventOut) {
    if (!mConfiguration.enabled) {
        return;
    }

    if (mTraceFrameSkippedToken != -1) {
        ATRACE_ASYNC_END("Video frame(s) skipped", mTraceFrameSkippedToken);
        mTraceFrameSkippedToken = -1;
    }

    int64_t actualRenderTimeUs = actualRenderTimeNs / 1000;

    if (mLastRenderTimeUs != -1) {
        mRenderDurationMs += (actualRenderTimeUs - mLastRenderTimeUs) / 1000;
    }

    // Now that a frame has been rendered, the previously skipped frames can be processed as skipped
    // frames since the app is not skipping them to terminate playback.
    for (int64_t contentTimeUs : mPendingSkippedFrameContentTimeUsList) {
        processMetricsForSkippedFrame(contentTimeUs);
    }
    mPendingSkippedFrameContentTimeUsList = {};

    // We can render a pending queued frame if it's the last frame of the video, so release it
    // immediately.
    if (contentTimeUs == mTunnelFrameQueuedContentTimeUs && mTunnelFrameQueuedContentTimeUs != -1) {
        onFrameReleased(mTunnelFrameQueuedContentTimeUs, 0);
        mTunnelFrameQueuedContentTimeUs = -1;
    }

    static const FrameInfo noFrame = {-1, -1};
    FrameInfo nextExpectedFrame = noFrame;
    while (!mNextExpectedRenderedFrameQueue.empty()) {
        nextExpectedFrame = mNextExpectedRenderedFrameQueue.front();
        mNextExpectedRenderedFrameQueue.pop();
        // Happy path - the rendered frame is what we expected it to be
        if (contentTimeUs == nextExpectedFrame.contentTimeUs) {
            break;
        }
        // This isn't really supposed to happen - the next rendered frame should be the expected
        // frame, or, if there's frame drops, it will be a frame later in the content stream
        if (contentTimeUs < nextExpectedFrame.contentTimeUs) {
            ALOGW("Rendered frame is earlier than the next expected frame (%lld, %lld)",
                  (long long) contentTimeUs, (long long) nextExpectedFrame.contentTimeUs);
            break;
        }
        processMetricsForDroppedFrame(nextExpectedFrame.contentTimeUs,
                                      nextExpectedFrame.desiredRenderTimeUs);
    }
    processMetricsForRenderedFrame(nextExpectedFrame.contentTimeUs,
                                   nextExpectedFrame.desiredRenderTimeUs, actualRenderTimeUs,
                                   freezeEventOut, judderEventOut);
    mLastRenderTimeUs = actualRenderTimeUs;
}

VideoRenderQualityTracker::FreezeEvent VideoRenderQualityTracker::getAndResetFreezeEvent() {
    FreezeEvent event = std::move(mFreezeEvent);
    mFreezeEvent.valid = false;
    return event;
}

VideoRenderQualityTracker::JudderEvent VideoRenderQualityTracker::getAndResetJudderEvent() {
    JudderEvent event = std::move(mJudderEvent);
    mJudderEvent.valid = false;
    return event;
}

const VideoRenderQualityMetrics &VideoRenderQualityTracker::getMetrics() {
    if (!mConfiguration.enabled) {
        return mMetrics;
    }

    mMetrics.freezeScore = 0;
    if (mConfiguration.freezeDurationMsHistogramToScore.size() ==
        mMetrics.freezeDurationMsHistogram.size()) {
        for (int i = 0; i < mMetrics.freezeDurationMsHistogram.size(); ++i) {
            mMetrics.freezeScore += mMetrics.freezeDurationMsHistogram[i] *
                    mConfiguration.freezeDurationMsHistogramToScore[i];
        }
    }
    mMetrics.freezeRate = float(double(mMetrics.freezeDurationMsHistogram.getSum()) /
            mRenderDurationMs);

    mMetrics.judderScore = 0;
    if (mConfiguration.judderScoreHistogramToScore.size() == mMetrics.judderScoreHistogram.size()) {
        for (int i = 0; i < mMetrics.judderScoreHistogram.size(); ++i) {
            mMetrics.judderScore += mMetrics.judderScoreHistogram[i] *
                    mConfiguration.judderScoreHistogramToScore[i];
        }
    }
    mMetrics.judderRate = float(double(mMetrics.judderScoreHistogram.getCount()) /
            (mMetrics.frameReleasedCount + mMetrics.frameSkippedCount));

    return mMetrics;
}

void VideoRenderQualityTracker::clear() {
    mRenderDurationMs = 0;
    mMetrics.clear();
    resetForDiscontinuity();
}

void VideoRenderQualityTracker::resetForDiscontinuity() {
    mLastContentTimeUs = -1;
    mLastRenderTimeUs = -1;
    mLastFreezeEndTimeUs = -1;
    mLastJudderEndTimeUs = -1;
    mDroppedContentDurationUs = 0;
    mFreezeEvent.valid = false;
    mJudderEvent.valid = false;

    // Don't worry about tracking frame rendering times from now up until playback catches up to
    // the discontinuity. While stuttering or freezing could be found in the next few frames, the
    // impact to the user is is minimal, so better to just keep things simple and don't bother.
    mNextExpectedRenderedFrameQueue = {};
    mTunnelFrameQueuedContentTimeUs = -1;

    // Ignore any frames that were skipped just prior to the discontinuity.
    mPendingSkippedFrameContentTimeUsList = {};

    // All frame durations can be now ignored since all bets are off now on what the render
    // durations should be after the discontinuity.
    for (int i = 0; i < FrameDurationUs::SIZE; ++i) {
        mActualFrameDurationUs[i] = -1;
        mDesiredFrameDurationUs[i] = -1;
        mContentFrameDurationUs[i] = -1;
    }
    mActualFrameDurationUs.priorTimestampUs = -1;
    mDesiredFrameDurationUs.priorTimestampUs = -1;
    mContentFrameDurationUs.priorTimestampUs = -1;
}

bool VideoRenderQualityTracker::resetIfDiscontinuity(int64_t contentTimeUs,
                                                     int64_t desiredRenderTimeUs) {
    if (mLastContentTimeUs == -1) {
        resetForDiscontinuity();
        return true;
    }
    if (contentTimeUs < mLastContentTimeUs) {
        ALOGI("Video playback jumped %d ms backwards in content time (%d -> %d)",
              int((mLastContentTimeUs - contentTimeUs) / 1000), int(mLastContentTimeUs / 1000),
              int(contentTimeUs / 1000));
        resetForDiscontinuity();
        return true;
    }
    if (contentTimeUs - mLastContentTimeUs > mConfiguration.maxExpectedContentFrameDurationUs) {
        // The content frame duration could be long due to frame drops for live content. This can be
        // detected by looking at the app's desired rendering duration. If the app's rendered frame
        // duration is roughly the same as the content's frame duration, then it is assumed that
        // the forward discontinuity is due to frame drops for live content. A false positive can
        // occur if the time the user spends seeking is equal to the duration of the seek. This is
        // very unlikely to occur in practice but CAN occur - the user starts seeking forward, gets
        // distracted, and then returns to seeking forward.
        bool skippedForwardDueToLiveContentFrameDrops = false;
        if (desiredRenderTimeUs != -1) {
            int64_t contentFrameDurationUs = contentTimeUs - mLastContentTimeUs;
            int64_t desiredFrameDurationUs = desiredRenderTimeUs - mLastRenderTimeUs;
            skippedForwardDueToLiveContentFrameDrops =
                    abs(contentFrameDurationUs - desiredFrameDurationUs) <
                    mConfiguration.liveContentFrameDropToleranceUs;
        }
        if (!skippedForwardDueToLiveContentFrameDrops) {
            ALOGI("Video playback jumped %d ms forward in content time (%d -> %d) ",
                int((contentTimeUs - mLastContentTimeUs) / 1000), int(mLastContentTimeUs / 1000),
                int(contentTimeUs / 1000));
            resetForDiscontinuity();
            return true;
        }
    }
    return false;
}

void VideoRenderQualityTracker::processMetricsForSkippedFrame(int64_t contentTimeUs) {
    mMetrics.frameSkippedCount++;
    if (mConfiguration.areSkippedFramesDropped) {
        processMetricsForDroppedFrame(contentTimeUs, -1);
        return;
    }
    updateFrameDurations(mContentFrameDurationUs, contentTimeUs);
    updateFrameDurations(mDesiredFrameDurationUs, -1);
    updateFrameDurations(mActualFrameDurationUs, -1);
    updateFrameRate(mMetrics.contentFrameRate, mContentFrameDurationUs, mConfiguration);
    mDroppedContentDurationUs = 0;
}

void VideoRenderQualityTracker::processMetricsForDroppedFrame(int64_t contentTimeUs,
                                                              int64_t desiredRenderTimeUs) {
    mMetrics.frameDroppedCount++;
    updateFrameDurations(mContentFrameDurationUs, contentTimeUs);
    updateFrameDurations(mDesiredFrameDurationUs, desiredRenderTimeUs);
    updateFrameDurations(mActualFrameDurationUs, -1);
    updateFrameRate(mMetrics.contentFrameRate, mContentFrameDurationUs, mConfiguration);
    updateFrameRate(mMetrics.desiredFrameRate, mDesiredFrameDurationUs, mConfiguration);
    if (mContentFrameDurationUs[0] != -1) {
        mDroppedContentDurationUs += mContentFrameDurationUs[0];
    }
}

void VideoRenderQualityTracker::processMetricsForRenderedFrame(int64_t contentTimeUs,
                                                               int64_t desiredRenderTimeUs,
                                                               int64_t actualRenderTimeUs,
                                                               FreezeEvent *freezeEventOut,
                                                               JudderEvent *judderEventOut) {
    const Configuration& c = mConfiguration;

    // Capture the timestamp at which the first frame was rendered
    if (mMetrics.firstRenderTimeUs == 0) {
        mMetrics.firstRenderTimeUs = actualRenderTimeUs;
    }
    // Capture the timestamp at which the last frame was rendered
    mMetrics.lastRenderTimeUs = actualRenderTimeUs;

    mMetrics.frameRenderedCount++;

    // The content time is -1 when it was rendered after a discontinuity (e.g. seek) was detected.
    // So, even though a frame was rendered, it's impact on the user is insignificant, so don't do
    // anything other than count it as a rendered frame.
    if (contentTimeUs == -1) {
        return;
    }
    updateFrameDurations(mContentFrameDurationUs, contentTimeUs);
    updateFrameDurations(mDesiredFrameDurationUs, desiredRenderTimeUs);
    updateFrameDurations(mActualFrameDurationUs, actualRenderTimeUs);
    updateFrameRate(mMetrics.contentFrameRate, mContentFrameDurationUs, mConfiguration);
    updateFrameRate(mMetrics.desiredFrameRate, mDesiredFrameDurationUs, mConfiguration);
    updateFrameRate(mMetrics.actualFrameRate, mActualFrameDurationUs, mConfiguration);

    // A freeze occurs if frames were dropped NOT after a discontinuity
    if (mDroppedContentDurationUs != 0 && mLastRenderTimeUs != -1) {
        // When pausing, audio playback may continue for a brief period of time after video
        // pauses while the audio buffers drain. When resuming, a small number of video frames
        // might be dropped to catch up to the audio position. This is acceptable behacvior and
        // should not count as a freeze.
        bool isLikelyCatchingUpAfterPause = false;
        // A pause can be detected if a freeze occurs for a longer period of time than the
        // content duration of the dropped frames. This strategy works because, for freeze
        // events (no video pause), the content duration of the dropped frames will closely track
        // the wall clock time (freeze duration). When pausing, however, the wall clock time
        // (freeze duration) will be longer than the content duration of the dropped frames
        // required to catch up to the audio position.
        const int64_t wallClockDurationUs = actualRenderTimeUs - mLastRenderTimeUs;
        // 200ms is chosen because it is larger than what a hiccup in the display pipeline could
        // likely be, but shorter than the duration for which a user could pause for.
        static const int32_t MAX_PIPELINE_HICCUP_DURATION_US = 200 * 1000;
        if (wallClockDurationUs > mDroppedContentDurationUs + MAX_PIPELINE_HICCUP_DURATION_US) {
            // Capture the amount of content that is dropped after pause, so we can push apps to be
            // better about this behavior.
            if (mDroppedContentDurationUs / 1000 > mMetrics.maxContentDroppedAfterPauseMs) {
                mMetrics.maxContentDroppedAfterPauseMs = int32_t(mDroppedContentDurationUs / 1000);
            }
            isLikelyCatchingUpAfterPause = mDroppedContentDurationUs <= c.pauseAudioLatencyUs;
        }
        if (!isLikelyCatchingUpAfterPause) {
            processFreeze(actualRenderTimeUs, mLastRenderTimeUs, mLastFreezeEndTimeUs, mFreezeEvent,
                        mMetrics, mConfiguration, mTraceTriggerFn);
            mLastFreezeEndTimeUs = actualRenderTimeUs;
        }
    }
    maybeCaptureFreezeEvent(actualRenderTimeUs, mLastFreezeEndTimeUs, mFreezeEvent, mMetrics,
                            mConfiguration, freezeEventOut);

    // Judder is computed on the prior video frame, not the current video frame
    int64_t judderScore = computePreviousJudderScore(mActualFrameDurationUs,
                                                     mContentFrameDurationUs,
                                                     mConfiguration);
    if (judderScore != 0) {
        int64_t judderTimeUs = actualRenderTimeUs - mActualFrameDurationUs[0] -
                mActualFrameDurationUs[1];
        processJudder(judderScore, judderTimeUs, mLastJudderEndTimeUs, mActualFrameDurationUs,
                      mContentFrameDurationUs, mJudderEvent, mMetrics, mConfiguration);
        mLastJudderEndTimeUs = judderTimeUs + mActualFrameDurationUs[1];
    }
    maybeCaptureJudderEvent(actualRenderTimeUs, mLastJudderEndTimeUs, mJudderEvent, mMetrics,
                            mConfiguration, judderEventOut);

    mDroppedContentDurationUs = 0;
}

void VideoRenderQualityTracker::processFreeze(int64_t actualRenderTimeUs, int64_t lastRenderTimeUs,
                                              int64_t lastFreezeEndTimeUs, FreezeEvent &e,
                                              VideoRenderQualityMetrics &m, const Configuration &c,
                                              const TraceTriggerFn traceTriggerFn) {
    int32_t durationMs = int32_t((actualRenderTimeUs - lastRenderTimeUs) / 1000);
    m.freezeDurationMsHistogram.insert(durationMs);
    int32_t distanceMs = -1;
    if (lastFreezeEndTimeUs != -1) {
        // The distance to the last freeze is measured from the end of the last freze to the start
        // of this freeze.
        distanceMs = int32_t((lastRenderTimeUs - lastFreezeEndTimeUs) / 1000);
        m.freezeDistanceMsHistogram.insert(distanceMs);
    }
    if (c.freezeEventMax > 0) {
        if (e.valid == false) {
            m.freezeEventCount++;
            e.valid = true;
            e.initialTimeUs = lastRenderTimeUs;
            e.durationMs = 0;
            e.sumDurationMs = 0;
            e.sumDistanceMs = 0;
            e.count = 0;
            e.details.durationMs.clear();
            e.details.distanceMs.clear();
        // The first occurrence in the event should not have the distance recorded as part of the
        // event, because it belongs in a vacuum between two events. However we still want the
        // distance recorded in the details to calculate times in all details in all events.
        } else if (distanceMs != -1) {
            e.durationMs += distanceMs;
            e.sumDistanceMs += distanceMs;
        }
        e.durationMs += durationMs;
        e.count++;
        e.sumDurationMs += durationMs;
        if (e.details.durationMs.size() < c.freezeEventDetailsMax) {
            e.details.durationMs.push_back(durationMs);
            e.details.distanceMs.push_back(distanceMs); // -1 for first detail in the first event
        }
    }

    if (c.traceTriggerEnabled && durationMs >= c.traceMinFreezeDurationMs) {
        ALOGI("Video freezed %lld ms", (long long) durationMs);
        triggerTraceWithThrottle(traceTriggerFn, c, actualRenderTimeUs);
    }
}

void VideoRenderQualityTracker::maybeCaptureFreezeEvent(int64_t actualRenderTimeUs,
                                                        int64_t lastFreezeEndTimeUs, FreezeEvent &e,
                                                        const VideoRenderQualityMetrics & m,
                                                        const Configuration &c,
                                                        FreezeEvent *freezeEventOut) {
    if (lastFreezeEndTimeUs == -1 || !e.valid) {
        return;
    }
    // Future freeze occurrences are still pulled into the current freeze event if under tolerance
    int64_t distanceMs = (actualRenderTimeUs - lastFreezeEndTimeUs) / 1000;
    if (distanceMs < c.freezeEventDistanceToleranceMs) {
        return;
    }
    if (freezeEventOut != nullptr && m.freezeEventCount <= c.freezeEventMax) {
        *freezeEventOut = std::move(e);
    }
    // start recording a new freeze event after pushing the current one back to the caller
    e.valid = false;
}

int64_t VideoRenderQualityTracker::computePreviousJudderScore(
        const FrameDurationUs &actualFrameDurationUs,
        const FrameDurationUs &contentFrameDurationUs,
        const Configuration &c) {
    // If the frame before or after was dropped, then don't generate a judder score, since any
    // problems with frame drops are scored as a freeze instead.
    if (actualFrameDurationUs[0] == -1 || actualFrameDurationUs[1] == -1 ||
        actualFrameDurationUs[2] == -1) {
        return 0;
    }

    // Don't score judder for when playback is paused or rebuffering (long frame duration), or if
    // the player is intentionally playing each frame at a slow rate (e.g. half-rate). If the long
    // frame duration was unintentional, it is assumed that this will be coupled with a later frame
    // drop, and be scored as a freeze instead of judder.
    if (actualFrameDurationUs[1] >= 2 * contentFrameDurationUs[1]) {
        return 0;
    }

    // The judder score is based on the error of this frame
    int64_t errorUs = actualFrameDurationUs[1] - contentFrameDurationUs[1];
    // Don't score judder if the previous frame has high error, but this frame has low error
    if (abs(errorUs) < c.judderErrorToleranceUs) {
        return 0;
    }

    // Add a penalty if this frame has judder that amplifies the problem introduced by previous
    // judder, instead of catching up for the previous judder (50, 16, 16, 50) vs (50, 16, 50, 16)
    int64_t previousErrorUs = actualFrameDurationUs[2] - contentFrameDurationUs[2];
    // Don't add the pentalty for errors from the previous frame if the previous frame has low error
    if (abs(previousErrorUs) >= c.judderErrorToleranceUs) {
        errorUs = abs(errorUs) + abs(errorUs + previousErrorUs);
    }

    // Avoid scoring judder for 3:2 pulldown or other minimally-small frame duration errors
    if (abs(errorUs) < contentFrameDurationUs[1] / 4) {
        return 0;
    }

    return abs(errorUs) / 1000; // error in millis to keep numbers small
}

void VideoRenderQualityTracker::processJudder(int32_t judderScore, int64_t judderTimeUs,
                                              int64_t lastJudderEndTime,
                                              const FrameDurationUs &actualDurationUs,
                                              const FrameDurationUs &contentDurationUs,
                                              JudderEvent &e, VideoRenderQualityMetrics &m,
                                              const Configuration &c) {
    int32_t distanceMs = -1;
    if (lastJudderEndTime != -1) {
        distanceMs = int32_t((judderTimeUs - lastJudderEndTime) / 1000);
    }
    m.judderScoreHistogram.insert(judderScore);
    if (c.judderEventMax > 0) {
        if (!e.valid) {
            m.judderEventCount++;
            e.valid = true;
            e.initialTimeUs = judderTimeUs;
            e.durationMs = 0;
            e.sumScore = 0;
            e.sumDistanceMs = 0;
            e.count = 0;
            e.details.contentRenderDurationUs.clear();
            e.details.actualRenderDurationUs.clear();
            e.details.distanceMs.clear();
        // The first occurrence in the event should not have the distance recorded as part of the
        // event, because it belongs in a vacuum between two events. However we still want the
        // distance recorded in the details to calculate the times using all details in all events.
        } else if (distanceMs != -1) {
            e.durationMs += distanceMs;
            e.sumDistanceMs += distanceMs;
        }
        e.durationMs += actualDurationUs[1] / 1000;
        e.count++;
        e.sumScore += judderScore;
        if (e.details.contentRenderDurationUs.size() < c.judderEventDetailsMax) {
            e.details.actualRenderDurationUs.push_back(actualDurationUs[1]);
            e.details.contentRenderDurationUs.push_back(contentDurationUs[1]);
            e.details.distanceMs.push_back(distanceMs); // -1 for first detail in the first event
        }
    }
}

void VideoRenderQualityTracker::maybeCaptureJudderEvent(int64_t actualRenderTimeUs,
                                                        int64_t lastJudderEndTimeUs, JudderEvent &e,
                                                        const VideoRenderQualityMetrics &m,
                                                        const Configuration &c,
                                                        JudderEvent *judderEventOut) {
    if (lastJudderEndTimeUs == -1 || !e.valid) {
        return;
    }
    // Future judder occurrences are still pulled into the current judder event if under tolerance
    int64_t distanceMs = (actualRenderTimeUs - lastJudderEndTimeUs) / 1000;
    if (distanceMs < c.judderEventDistanceToleranceMs) {
        return;
    }
    if (judderEventOut != nullptr && m.judderEventCount <= c.judderEventMax) {
        *judderEventOut = std::move(e);
    }
    // start recording a new judder event after pushing the current one back to the caller
    e.valid = false;
}

void VideoRenderQualityTracker::configureHistograms(VideoRenderQualityMetrics &m,
                                                    const Configuration &c) {
    m.freezeDurationMsHistogram.setup(c.freezeDurationMsHistogramBuckets);
    m.freezeDistanceMsHistogram.setup(c.freezeDistanceMsHistogramBuckets);
    m.judderScoreHistogram.setup(c.judderScoreHistogramBuckets);
}

int64_t VideoRenderQualityTracker::nowUs() {
    struct timespec t;
    t.tv_sec = t.tv_nsec = 0;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec * 1000000000LL + t.tv_nsec) / 1000LL;
}

void VideoRenderQualityTracker::updateFrameDurations(FrameDurationUs &durationUs,
                                                     int64_t newTimestampUs) {
    for (int i = FrameDurationUs::SIZE - 1; i > 0; --i ) {
        durationUs[i] = durationUs[i - 1];
    }
    if (newTimestampUs == -1) {
        durationUs[0] = -1;
    } else {
        durationUs[0] = durationUs.priorTimestampUs == -1 ? -1 :
                newTimestampUs - durationUs.priorTimestampUs;
        durationUs.priorTimestampUs = newTimestampUs;
    }
}

void VideoRenderQualityTracker::updateFrameRate(float &frameRate, const FrameDurationUs &durationUs,
                                                const Configuration &c) {
    float newFrameRate = detectFrameRate(durationUs, c);
    if (newFrameRate != FRAME_RATE_UNDETERMINED) {
        frameRate = newFrameRate;
    }
}

float VideoRenderQualityTracker::detectFrameRate(const FrameDurationUs &durationUs,
                                                 const Configuration &c) {
    // At least 3 frames are necessary to detect stable frame rates
    assert(FrameDurationUs::SIZE >= 3);
    if (durationUs[0] == -1 || durationUs[1] == -1 || durationUs[2] == -1) {
        return FRAME_RATE_UNDETERMINED;
    }
    // Only determine frame rate if the render durations are stable across 3 frames
    if (abs(durationUs[0] - durationUs[1]) > c.frameRateDetectionToleranceUs ||
        abs(durationUs[0] - durationUs[2]) > c.frameRateDetectionToleranceUs) {
        return is32pulldown(durationUs, c) ? FRAME_RATE_24_3_2_PULLDOWN : FRAME_RATE_UNDETERMINED;
    }
    return 1000.0 * 1000.0 / durationUs[0];
}

bool VideoRenderQualityTracker::is32pulldown(const FrameDurationUs &durationUs,
                                             const Configuration &c) {
    // At least 5 frames are necessary to detect stable 3:2 pulldown
    assert(FrameDurationUs::SIZE >= 5);
    if (durationUs[0] == -1 || durationUs[1] == -1 || durationUs[2] == -1 || durationUs[3] == -1 ||
        durationUs[4] == -1) {
        return false;
    }
    // 3:2 pulldown expects that every other frame has identical duration...
    if (abs(durationUs[0] - durationUs[2]) > c.frameRateDetectionToleranceUs ||
        abs(durationUs[1] - durationUs[3]) > c.frameRateDetectionToleranceUs ||
        abs(durationUs[0] - durationUs[4]) > c.frameRateDetectionToleranceUs) {
        return false;
    }
    // ... for either 2 vsysncs or 3 vsyncs
    if ((abs(durationUs[0] - 33333) < c.frameRateDetectionToleranceUs &&
         abs(durationUs[1] - 50000) < c.frameRateDetectionToleranceUs) ||
        (abs(durationUs[0] - 50000) < c.frameRateDetectionToleranceUs &&
         abs(durationUs[1] - 33333) < c.frameRateDetectionToleranceUs)) {
        return true;
    }
    return false;
}

void VideoRenderQualityTracker::triggerTraceWithThrottle(const TraceTriggerFn traceTriggerFn,
                                                         const Configuration &c,
                                                         const int64_t triggerTimeUs) {
    static int64_t lastTriggerUs = -1;
    static Mutex updateLastTriggerLock;

    {
        Mutex::Autolock autoLock(updateLastTriggerLock);
        if (lastTriggerUs != -1) {
            int32_t sinceLastTriggerMs = int32_t((triggerTimeUs - lastTriggerUs) / 1000);
            // Throttle the trace trigger calls to reduce continuous PID fork calls in a short time
            // to impact device performance, and reduce spamming trace reports.
            if (sinceLastTriggerMs < c.traceTriggerThrottleMs) {
                ALOGI("Not triggering trace - not enough time since last trigger");
                return;
            }
        }
        lastTriggerUs = triggerTimeUs;
    }

    (*traceTriggerFn)();
}

void VideoRenderQualityTracker::triggerTrace() {
    // Trigger perfetto to stop always-on-tracing (AOT) to collect trace into a file for video
    // freeze event, the collected trace categories are configured by AOT.
    static const char* args[] = {"/system/bin/trigger_perfetto",
                                 "com.android.codec-video-freeze", NULL};

    pid_t pid = fork();
    if (pid < 0) {
        ALOGI("Failed to fork for triggering trace");
    } else if (pid == 0) {
        // Child process.
        ALOGI("Trigger trace %s", args[1]);
        execvp(args[0], const_cast<char**>(args));
        ALOGW("Failed to trigger trace %s", args[1]);
        _exit(1);
    } else {
        // Parent process.
        int status;
        // Wait for the child process (pid) gets terminated, and allow the system to release
        // the resource associated with the child. Or the child process will remain in a
        // zombie state and get killed by llkd to cause foreground app crash.
        if (waitpid(pid, &status, 0) < 0) {
            ALOGW("Failed to waitpid for triggering trace");
        }
    }
}

} // namespace android
