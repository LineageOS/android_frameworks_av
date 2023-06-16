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

#ifndef ANDROID_AUDIO_THREADMETRICS_H
#define ANDROID_AUDIO_THREADMETRICS_H

#include <mutex>

namespace android {

/**
 * ThreadMetrics handles the AudioFlinger thread log statistics.
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
class ThreadMetrics final {
public:
    ThreadMetrics(std::string metricsId, bool isOut)
        : mMetricsId(std::move(metricsId))
        , mIsOut(isOut)
        {}

    ~ThreadMetrics() {
        logEndInterval(); // close any open interval groups
        std::lock_guard l(mLock);
        deliverCumulativeMetrics(AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP);
        mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_DTOR)
            .record();
    }

    // Called under the following circumstances
    // 1) Upon a createPatch and we are not in standby
    // 2) We come out of standby
    void logBeginInterval() {
        std::lock_guard l(mLock);
        // The devices we look for change depend on whether the Thread is input or output.
        const std::string& patchDevices = mIsOut ? mCreatePatchOutDevices : mCreatePatchInDevices;
        if (mDevices != patchDevices) {
            deliverCumulativeMetrics(AMEDIAMETRICS_PROP_EVENT_VALUE_ENDAUDIOINTERVALGROUP);
            mDevices = patchDevices; // set after endAudioIntervalGroup
            resetIntervalGroupMetrics();
            deliverDeviceMetrics(
                    AMEDIAMETRICS_PROP_EVENT_VALUE_BEGINAUDIOINTERVALGROUP, mDevices.c_str());
        }
        if (mIntervalStartTimeNs == 0) {
            ++mIntervalCount;
            mIntervalStartTimeNs = systemTime();
        }
    }

    void logConstructor(pid_t pid, const char *threadType, int32_t id) const {
        mediametrics::LogItem(mMetricsId)
            .setPid(pid)
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_CTOR)
            .set(AMEDIAMETRICS_PROP_TYPE, threadType)
            .set(AMEDIAMETRICS_PROP_THREADID, id)
            .record();
    }

    void logCreatePatch(const std::string& inDevices, const std::string& outDevices) {
        std::lock_guard l(mLock);
        mCreatePatchInDevices = inDevices;
        mCreatePatchOutDevices = outDevices;
        mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_EVENT, AMEDIAMETRICS_PROP_EVENT_VALUE_CREATEAUDIOPATCH)
            .set(AMEDIAMETRICS_PROP_INPUTDEVICES, inDevices)
            .set(AMEDIAMETRICS_PROP_OUTPUTDEVICES, outDevices)
            .record();
    }

    // Called when we are removed from the Thread.
    void logEndInterval() {
        std::lock_guard l(mLock);
        if (mIntervalStartTimeNs != 0) {
            const int64_t elapsedTimeNs = systemTime() - mIntervalStartTimeNs;
            mIntervalStartTimeNs = 0;
            mCumulativeTimeNs += elapsedTimeNs;
            mDeviceTimeNs += elapsedTimeNs;
        }
    }

    void logThrottleMs(double throttleMs) const {
        mediametrics::LogItem(mMetricsId)
            // ms units always double
            .set(AMEDIAMETRICS_PROP_THROTTLEMS, (double)throttleMs)
            .record();
    }

    void logLatency(double latencyMs) {
        mediametrics::LogItem(mMetricsId)
            .set(AMEDIAMETRICS_PROP_LATENCYMS, latencyMs)
            .record();
        std::lock_guard l(mLock);
        mDeviceLatencyMs.add(latencyMs);
    }

    void logUnderrunFrames(size_t frames) {
        std::lock_guard l(mLock);
        if (mLastUnderrun == false && frames > 0) {
            ++mUnderrunCount; // count non-continguous underrun sequences.
        }
        mLastUnderrun = (frames > 0);
        mUnderrunFrames += frames;
    }

    const std::string& getMetricsId() const {
        return mMetricsId;
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

    void deliverCumulativeMetrics(const char *eventName) const REQUIRES(mLock) {
        if (mIntervalCount > 0) {
            mediametrics::LogItem item(mMetricsId);
            item.set(AMEDIAMETRICS_PROP_CUMULATIVETIMENS, mCumulativeTimeNs)
                .set(AMEDIAMETRICS_PROP_DEVICETIMENS, mDeviceTimeNs)
                .set(AMEDIAMETRICS_PROP_EVENT, eventName)
                .set(AMEDIAMETRICS_PROP_INTERVALCOUNT, (int32_t)mIntervalCount)
                // we set "last" device to indicate the device the group was
                // associated with (because a createPatch which is logged in ThreadMetrics
                // could have changed the device).
                .set(mIsOut
                        ? AMEDIAMETRICS_PROP_PREFIX_LAST AMEDIAMETRICS_PROP_OUTPUTDEVICES
                        : AMEDIAMETRICS_PROP_PREFIX_LAST AMEDIAMETRICS_PROP_INPUTDEVICES,
                        mDevices.c_str());
            if (mDeviceLatencyMs.getN() > 0) {
                item.set(AMEDIAMETRICS_PROP_DEVICELATENCYMS, mDeviceLatencyMs.getMean());
            }
            if (mUnderrunCount > 0) {
                item.set(AMEDIAMETRICS_PROP_UNDERRUN, (int32_t)mUnderrunCount)
                    .set(AMEDIAMETRICS_PROP_UNDERRUNFRAMES, (int64_t)mUnderrunFrames);
            }
            item.record();
        }
    }

    void resetIntervalGroupMetrics() REQUIRES(mLock) {
        // mDevices is not reset by clear

        mIntervalCount = 0;
        mIntervalStartTimeNs = 0;
        // mCumulativeTimeNs is not reset by clear.
        mDeviceTimeNs = 0;

        mDeviceLatencyMs.reset();

        mLastUnderrun = false;
        mUnderrunCount = 0;
        mUnderrunFrames = 0;
    }

    const std::string mMetricsId;
    const bool        mIsOut;  // if true, than a playback track, otherwise used for record.

    mutable           std::mutex mLock;

    // Devices in the interval group.
    std::string       mDevices GUARDED_BY(mLock); // last input or output devices based on mIsOut.
    std::string       mCreatePatchInDevices GUARDED_BY(mLock);
    std::string       mCreatePatchOutDevices GUARDED_BY(mLock);

    // Number of intervals and playing time
    int32_t           mIntervalCount GUARDED_BY(mLock) = 0;
    int64_t           mIntervalStartTimeNs GUARDED_BY(mLock) = 0;
    int64_t           mCumulativeTimeNs GUARDED_BY(mLock) = 0;
    int64_t           mDeviceTimeNs GUARDED_BY(mLock) = 0;

    // latency and startup for each interval.
    audio_utils::Statistics<double> mDeviceLatencyMs GUARDED_BY(mLock);

    // underrun count and frames
    bool              mLastUnderrun GUARDED_BY(mLock) = false; // checks consecutive underruns
    int64_t           mUnderrunCount GUARDED_BY(mLock) = 0;    // number of consecutive underruns
    int64_t           mUnderrunFrames GUARDED_BY(mLock) = 0;   // total estimated frames underrun
};

} // namespace android

#endif // ANDROID_AUDIO_THREADMETRICS_H
