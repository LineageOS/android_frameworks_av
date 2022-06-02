/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifndef ANDROID_AUDIO_TRACKMETRICS_H
#define ANDROID_AUDIO_TRACKMETRICS_H

#include <mutex>

namespace android {

/**
 * TrackMetrics handles the AudioFlinger track metrics.
 *
 * We aggregate metrics for a particular device for proper analysis.
 * This includes power, performance, and usage metrics.
 *
 * This class is thread-safe with a lock for safety.  There is no risk of deadlock
 * as this class only executes external one-way calls in Mediametrics and does not
 * call any other AudioFlinger class.
 *
 * Terminology:
 * An AudioInterval is a contiguous playback segment.
 * An AudioIntervalGroup is a group of continuous playback segments on the same device.
 *
 * We currently deliver metrics based on an AudioIntervalGroup.
 */
class TrackMetrics final {
public:
    TrackMetrics(std::string metricsId, bool isOut)
        : mMetricsId(std::move(metricsId))
        , mIsOut(isOut)
        {}  // we don't log a constructor item, we wait for more info in logConstructor().

    ~TrackMetrics() {
        logEndInterval();
        std::lock_guard l(mLock);
        deliverCumulativeMetrics(AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP);
        // we don't log a destructor item here.
    }

    // Called under the following circumstances
    // 1) when we are added to the Thread
    // 2) when we have a createPatch in the Thread.
    void logBeginInterval(const std::string& devices) {
        std::lock_guard l(mLock);
        if (mDevices != devices) {
            deliverCumulativeMetrics(AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP);
            mDevices = devices;
            resetIntervalGroupMetrics();
            deliverDeviceMetrics(
                    AMEDIAMETRICS_PROP_EVENT_VALUE_BEGINAUDIOINTERVALGROUP, devices.c_str());
        }
        ++mIntervalCount;
    }

    void logConstructor(pid_t creatorPid, uid_t creatorUid, int32_t internalTrackId,
            const std::string& traits = {},
            audio_stream_type_t streamType = AUDIO_STREAM_DEFAULT) const {
        // Once this item is logged by the server, the client can add properties.
        // no lock required, all local or const variables.
        mediametrics::LogItem item(mMetricsId);
        item.setPid(creatorPid)
            .setUid(creatorUid)
            .set(AMEDIAMETRICS_PROP_ALLOWUID, (int32_t)creatorUid)
            .set(AMEDIAMETRICS_PROP_EVENT,
                    AMEDIAMETRICS_PROP_PREFIX_SERVER AMEDIAMETRICS_PROP_EVENT_VALUE_CTOR)
            .set(AMEDIAMETRICS_PROP_INTERNALTRACKID, internalTrackId)
            .set(AMEDIAMETRICS_PROP_TRAITS, traits);
        // log streamType from the service, since client doesn't know chosen streamType.
        if (streamType != AUDIO_STREAM_DEFAULT) {
            item.set(AMEDIAMETRICS_PROP_STREAMTYPE, toString(streamType).c_str());
        }
        item.record();
    }

    // Called when we are removed from the Thread.
    void logEndInterval() {
        std::lock_guard l(mLock);
        if (mLastVolumeChangeTimeNs != 0) {
            logVolume_l(mVolume); // flush out the last volume.
            mLastVolumeChangeTimeNs = 0;
        }
    }

    void logInvalidate() const {
        // no lock required, all local or const variables.
        mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_EVENT,
                 AMEDIAMETRICS_PROP_EVENT_VALUE_INVALIDATE)
            .record();
    }

    void logLatencyAndStartup(double latencyMs, double startupMs) {
        mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_LATENCYMS, latencyMs)
            .set(AMEDIAMETRICS_PROP_STARTUPMS, startupMs)
            .record();
        std::lock_guard l(mLock);
        mDeviceLatencyMs.add(latencyMs);
        mDeviceStartupMs.add(startupMs);
    }

    void updateMinMaxVolume(int64_t durationNs, double deviceVolume) {
        if (deviceVolume > mMaxVolume) {
            mMaxVolume = deviceVolume;
            mMaxVolumeDurationNs = durationNs;
        } else if (deviceVolume == mMaxVolume) {
            mMaxVolumeDurationNs += durationNs;
        }
        if (deviceVolume < mMinVolume) {
            mMinVolume = deviceVolume;
            mMinVolumeDurationNs = durationNs;
        } else if (deviceVolume == mMinVolume) {
            mMinVolumeDurationNs += durationNs;
        }
    }

    // may be called multiple times during an interval
    void logVolume(float volume) {
        std::lock_guard l(mLock);
        logVolume_l(volume);
    }

    // Use absolute numbers returned by AudioTrackShared.
    void logUnderruns(size_t count, size_t frames) {
        std::lock_guard l(mLock);
        mUnderrunCount = count;
        mUnderrunFrames = frames;
        // Consider delivering a message here (also be aware of excessive spam).
    }

private:

    // no lock required - all arguments and constants.
    void deliverDeviceMetrics(const char *eventName, const char *devices) const {
        mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_EVENT, eventName)
            .set(mIsOut ? AMEDIAMETRICS_PROP_OUTPUTDEVICES
                   : AMEDIAMETRICS_PROP_INPUTDEVICES, devices)
           .record();
    }

    void logVolume_l(float volume) REQUIRES(mLock) {
        const int64_t timeNs = systemTime();
        const int64_t durationNs = mLastVolumeChangeTimeNs == 0
                ? 0 : timeNs - mLastVolumeChangeTimeNs;
        if (durationNs > 0) {
            // See West's algorithm for weighted averages
            // https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance
            mDeviceVolume += (mVolume - mDeviceVolume) * durationNs
                      / (durationNs + mDeviceTimeNs);
            mDeviceTimeNs += durationNs;
            mCumulativeTimeNs += durationNs;
        }
        updateMinMaxVolume(durationNs, mVolume); // always update.
        mVolume = volume;
        mLastVolumeChangeTimeNs = timeNs;
    }

    void deliverCumulativeMetrics(const char *eventName) const REQUIRES(mLock) {
        if (mIntervalCount > 0) {
            mediametrics::LogItem item(mMetricsId);
            item.set(AMEDIAMETRICS_PROP_CUMULATIVETIMENS, mCumulativeTimeNs)
                .set(AMEDIAMETRICS_PROP_DEVICETIMENS, mDeviceTimeNs)
                .set(AMEDIAMETRICS_PROP_EVENT, eventName)
                .set(AMEDIAMETRICS_PROP_INTERVALCOUNT, (int32_t)mIntervalCount);
            if (mIsOut) {
                item.set(AMEDIAMETRICS_PROP_DEVICEVOLUME, mDeviceVolume)
                    .set(AMEDIAMETRICS_PROP_DEVICEMAXVOLUMEDURATIONNS, mMaxVolumeDurationNs)
                    .set(AMEDIAMETRICS_PROP_DEVICEMAXVOLUME, mMaxVolume)
                    .set(AMEDIAMETRICS_PROP_DEVICEMINVOLUMEDURATIONNS, mMinVolumeDurationNs)
                    .set(AMEDIAMETRICS_PROP_DEVICEMINVOLUME, mMinVolume);
            }
            if (mDeviceLatencyMs.getN() > 0) {
                item.set(AMEDIAMETRICS_PROP_DEVICELATENCYMS, mDeviceLatencyMs.getMean())
                    .set(AMEDIAMETRICS_PROP_DEVICESTARTUPMS, mDeviceStartupMs.getMean());
            }
            if (mUnderrunCount > 0) {
                item.set(AMEDIAMETRICS_PROP_UNDERRUN,
                        (int32_t)(mUnderrunCount - mUnderrunCountSinceIntervalGroup))
                    .set(AMEDIAMETRICS_PROP_UNDERRUNFRAMES,
                        (int64_t)(mUnderrunFrames - mUnderrunFramesSinceIntervalGroup));
            }
            item.record();
        }
    }

    void resetIntervalGroupMetrics() REQUIRES(mLock) {
        // mDevices is not reset by resetIntervalGroupMetrics.

        mIntervalCount = 0;
        // mCumulativeTimeNs is not reset by resetIntervalGroupMetrics.
        mDeviceTimeNs = 0;

        mVolume = 0.f;
        mDeviceVolume = 0.f;
        mLastVolumeChangeTimeNs = 0;  // last time volume logged, cleared on endInterval
        mMinVolume = AMEDIAMETRICS_INITIAL_MIN_VOLUME;
        mMaxVolume = AMEDIAMETRICS_INITIAL_MAX_VOLUME;
        mMinVolumeDurationNs = 0;
        mMaxVolumeDurationNs = 0;

        mDeviceLatencyMs.reset();
        mDeviceStartupMs.reset();

        mUnderrunCountSinceIntervalGroup = mUnderrunCount;
        mUnderrunFramesSinceIntervalGroup = mUnderrunFrames;
        // do not reset mUnderrunCount - it keeps continuously running for tracks.
    }

    const std::string mMetricsId;
    const bool        mIsOut;  // if true, than a playback track, otherwise used for record.

    mutable           std::mutex mLock;

    // Devices in the interval group.
    std::string       mDevices GUARDED_BY(mLock);

    // Number of intervals and playing time
    int32_t           mIntervalCount GUARDED_BY(mLock) = 0;
    int64_t           mCumulativeTimeNs GUARDED_BY(mLock) = 0; // total time.
    int64_t           mDeviceTimeNs GUARDED_BY(mLock) = 0;     // time on device.

    // Average volume
    double            mVolume GUARDED_BY(mLock) = 0.f;       // last set volume.
    double            mDeviceVolume GUARDED_BY(mLock) = 0.f; // running average volume.
    int64_t           mLastVolumeChangeTimeNs GUARDED_BY(mLock) = 0;

    // Min/Max volume
    double            mMinVolume GUARDED_BY(mLock) = AMEDIAMETRICS_INITIAL_MIN_VOLUME;
    double            mMaxVolume GUARDED_BY(mLock) = AMEDIAMETRICS_INITIAL_MAX_VOLUME;
    int64_t           mMinVolumeDurationNs GUARDED_BY(mLock) = 0;
    int64_t           mMaxVolumeDurationNs GUARDED_BY(mLock) = 0;

    // latency and startup for each interval.
    audio_utils::Statistics<double> mDeviceLatencyMs GUARDED_BY(mLock);
    audio_utils::Statistics<double> mDeviceStartupMs GUARDED_BY(mLock);

    // underrun count and frames
    int64_t           mUnderrunCount GUARDED_BY(mLock) = 0;
    int64_t           mUnderrunFrames GUARDED_BY(mLock) = 0;
    int64_t           mUnderrunCountSinceIntervalGroup GUARDED_BY(mLock) = 0;
    int64_t           mUnderrunFramesSinceIntervalGroup GUARDED_BY(mLock) = 0;
};

} // namespace android

#endif // ANDROID_AUDIO_TRACKMETRICS_H
