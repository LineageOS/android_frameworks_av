/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <android-base/thread_annotations.h>
#include "AnalyticsActions.h"
#include "AnalyticsState.h"
#include "AudioPowerUsage.h"
#include "HeatMap.h"
#include "StatsdLog.h"
#include "TimedAction.h"
#include "Wrap.h"

namespace android::mediametrics {

class AudioAnalytics
{
    // AudioAnalytics action / state helper classes
    friend AudioPowerUsage;

public:
    explicit AudioAnalytics(const std::shared_ptr<StatsdLog>& statsdLog);
    ~AudioAnalytics();

    /**
     * Returns success if AudioAnalytics recognizes item.
     *
     * AudioAnalytics requires the item key to start with "audio.".
     *
     * A trusted source can create a new key, an untrusted source
     * can only modify the key if the uid will match that authorized
     * on the existing key.
     *
     * \param item the item to be submitted.
     * \param isTrusted whether the transaction comes from a trusted source.
     *        In this case, a trusted source is verified by binder
     *        UID to be a system service by MediaMetrics service.
     *        Do not use true if you haven't really checked!
     *
     * \return NO_ERROR on success,
     *         PERMISSION_DENIED if the item cannot be put into the AnalyticsState,
     *         BAD_VALUE if the item key does not start with "audio.".
     */
    status_t submit(const std::shared_ptr<const mediametrics::Item>& item, bool isTrusted);

    /**
     * Returns a pair consisting of the dump string, and the number of lines in the string.
     *
     * The number of lines in the returned pair is used as an optimization
     * for subsequent line limiting.
     *
     * The TimeMachine and the TransactionLog are dumped separately under
     * different locks, so may not be 100% consistent with the last data
     * delivered.
     *
     * \param lines the maximum number of lines in the string returned.
     * \param sinceNs the nanoseconds since Unix epoch to start dump (0 shows all)
     * \param prefix the desired key prefix to match (nullptr shows all)
     */
    std::pair<std::string, int32_t> dump(
            int32_t lines = INT32_MAX, int64_t sinceNs = 0, const char *prefix = nullptr) const;

    /**
     * Returns a pair consisting of the dump string and the number of lines in the string.
     *
     * HeatMap dump.
     */
    std::pair<std::string, int32_t> dumpHeatMap(int32_t lines = INT32_MAX) const {
        return mHeatMap.dump(lines);
    }

    /**
     * Returns a pair consisting of the dump string and the number of lines in the string.
     *
     * Health dump.
     */
    std::pair<std::string, int32_t> dumpHealth(int32_t lines = INT32_MAX) const {
        return mHealth.dump(lines);
    }

    /**
     * Returns a pair consisting of the dump string and the number of lines in the string.
     *
     * Spatializer dump.
     */
    std::pair<std::string, int32_t> dumpSpatializer(int32_t lines = INT32_MAX) const {
        return mSpatializer.dump(lines);
    }

    void clear() {
        // underlying state is locked.
        mPreviousAnalyticsState->clear();
        mAnalyticsState->clear();

        // Clears the status map
        mHeatMap.clear();

        // Clear power usage state.
        mAudioPowerUsage.clear();
    }

private:

    /*
     * AudioAnalytics class does not contain a monitor mutex.
     * Instead, all of its variables are individually locked for access.
     * Since data and items are generally added only (gc removes it), this is a reasonable
     * compromise for availability/concurrency versus consistency.
     *
     * It is possible for concurrent threads to be reading and writing inside of AudioAnalytics.
     * Reads based on a prior time (e.g. one second) in the past from the TimeMachine can be
     * used to achieve better consistency if needed.
     */

    /**
     * Processes any pending actions for a particular item.
     *
     * \param item to check against the current AnalyticsActions.
     */
    void processActions(const std::shared_ptr<const mediametrics::Item>& item);

    /**
     * Processes status information contained in the item.
     *
     * \param item to check against for status handling
     */
    void processStatus(const std::shared_ptr<const mediametrics::Item>& item);

    // Specific reporting methods
    bool reportAudioRecordStatus(
            const std::shared_ptr<const mediametrics::Item>& item,
            const std::string& key, const std::string& eventStr,
            const std::string& statusString, uid_t uid, const std::string& message,
            int32_t subCode) const;

    bool reportAudioTrackStatus(
            const std::shared_ptr<const mediametrics::Item>& item,
            const std::string& key, const std::string& eventStr,
            const std::string& statusString, uid_t uid, const std::string& message,
            int32_t subCode) const;

    // HELPER METHODS
    /**
     * Return the audio thread associated with an audio track name.
     * e.g. "audio.track.32" -> "audio.thread.10" if the associated
     * threadId for the audio track is 10.
     */
    std::string getThreadFromTrack(const std::string& track) const;

    /**
     * return the device name, if present.
     *
     * This is currently enabled only for Bluetooth output devices.
     */
    std::string getDeviceNamesFromOutputDevices(std::string_view devices) const;

    const bool mDeliverStatistics;

    // Actions is individually locked
    AnalyticsActions mActions;

    // AnalyticsState is individually locked, and we use SharedPtrWrap
    // to allow safe access even if the shared pointer changes underneath.
    // These wrap pointers always point to a valid state object.
    SharedPtrWrap<AnalyticsState> mAnalyticsState;
    SharedPtrWrap<AnalyticsState> mPreviousAnalyticsState;

    TimedAction mTimedAction; // locked internally
    const std::shared_ptr<StatsdLog> mStatsdLog; // locked internally, ok for multiple threads.

    static constexpr size_t kHeatEntries = 100;
    HeatMap mHeatMap{kHeatEntries}; // locked internally, ok for multiple threads.

    // DeviceUse is a nested class which handles audio device usage accounting.
    // We define this class at the end to ensure prior variables all properly constructed.
    // TODO: Track / Thread interaction
    // TODO: Consider statistics aggregation.
    class DeviceUse {
    public:
        enum ItemType {
            RECORD = 0,
            THREAD = 1,
            TRACK = 2,
        };

        explicit DeviceUse(AudioAnalytics &audioAnalytics) : mAudioAnalytics{audioAnalytics} {}

        // Called every time an endAudioIntervalGroup message is received.
        void endAudioIntervalGroup(
                const std::shared_ptr<const android::mediametrics::Item> &item,
                ItemType itemType) const;

    private:
        AudioAnalytics &mAudioAnalytics;
    } mDeviceUse{*this};

    // DeviceConnected is a nested class which handles audio device connection
    // We define this class at the end to ensure prior variables all properly constructed.
    // TODO: Track / Thread interaction
    // TODO: Consider statistics aggregation.
    class DeviceConnection {
    public:
        explicit DeviceConnection(AudioAnalytics &audioAnalytics)
            : mAudioAnalytics{audioAnalytics} {}

        // Called every time an endAudioIntervalGroup message is received.
        void a2dpConnected(
                const std::shared_ptr<const android::mediametrics::Item> &item);

        // Called when we have an AudioFlinger createPatch
        void createPatch(
                const std::shared_ptr<const android::mediametrics::Item> &item);

        // Called through AudioManager when the BT service wants to notify connection
        void postBluetoothA2dpDeviceConnectionStateSuppressNoisyIntent(
                const std::shared_ptr<const android::mediametrics::Item> &item);

        // When the timer expires.
        void expire();

    private:
        AudioAnalytics &mAudioAnalytics;

        mutable std::mutex mLock;
        std::string mA2dpDeviceName;
        int64_t mA2dpConnectionRequestNs GUARDED_BY(mLock) = 0;  // Time for BT service request.
        int64_t mA2dpConnectionServiceNs GUARDED_BY(mLock) = 0;  // Time audio service agrees.

        int32_t mA2dpConnectionRequests GUARDED_BY(mLock) = 0;
        int32_t mA2dpConnectionServices GUARDED_BY(mLock) = 0;

        // See the statsd atoms.proto
        int32_t mA2dpConnectionSuccesses GUARDED_BY(mLock) = 0;
        int32_t mA2dpConnectionJavaServiceCancels GUARDED_BY(mLock) = 0;
        int32_t mA2dpConnectionUnknowns GUARDED_BY(mLock) = 0;
    } mDeviceConnection{*this};

    // AAudioStreamInfo is a nested class which collect aaudio stream info from both client and
    // server side.
    class AAudioStreamInfo {
    public:
        // All the enum here must be kept the same as the ones defined in atoms.proto
        enum CallerPath {
            CALLER_PATH_UNKNOWN = 0,
            CALLER_PATH_LEGACY = 1,
            CALLER_PATH_MMAP = 2,
        };

        explicit AAudioStreamInfo(AudioAnalytics &audioAnalytics)
            : mAudioAnalytics(audioAnalytics) {}

        void endAAudioStream(
                const std::shared_ptr<const android::mediametrics::Item> &item,
                CallerPath path) const;

    private:

        AudioAnalytics &mAudioAnalytics;
    } mAAudioStreamInfo{*this};

    // Create new state, typically occurs after an AudioFlinger ctor event.
    void newState();

    // Health is a nested class that tracks audioserver health properties
    class Health {
    public:
        explicit Health(AudioAnalytics &audioAnalytics)
            : mAudioAnalytics(audioAnalytics) {}

        enum class Module {
            AUDIOFLINGER,
            AUDIOPOLICY,
        };

        const char *getModuleName(Module module) {
            switch (module) {
                case Module::AUDIOFLINGER: return "AudioFlinger";
                case Module::AUDIOPOLICY: return "AudioPolicy";
            }
            return "Unknown";
        }

        // Called when we believe audioserver starts (AudioFlinger ctor)
        void onAudioServerStart(Module module,
                const std::shared_ptr<const android::mediametrics::Item> &item);

        // Called when we believe audioserver crashes (TimeCheck timeouts).
        void onAudioServerTimeout(Module module,
                const std::shared_ptr<const android::mediametrics::Item> &item);

        std::pair<std::string, int32_t> dump(
                int32_t lines = INT32_MAX, const char *prefix = nullptr) const;

    private:
        AudioAnalytics& mAudioAnalytics;

        mutable std::mutex mLock;

        // Life cycle of AudioServer
        // mAudioFlingerCtorTime
        // mAudioPolicyCtorTime
        // mAudioPolicyCtorDoneTime
        // ...
        // possibly mStopTime  (if TimeCheck thread)
        //
        // UpTime is measured from mStopTime - mAudioFlingerCtorTime.
        //
        // The stop events come from TimeCheck timeout aborts.  There may be other
        // uncaught signals, e.g. SIGSEGV, that cause missing stop events.
        std::chrono::system_clock::time_point mAudioFlingerCtorTime GUARDED_BY(mLock);
        std::chrono::system_clock::time_point mAudioPolicyCtorTime GUARDED_BY(mLock);
        std::chrono::system_clock::time_point mAudioPolicyCtorDoneTime GUARDED_BY(mLock);
        std::chrono::system_clock::time_point mStopTime GUARDED_BY(mLock);

        // mStartCount and mStopCount track the audioserver start and stop events.
        int64_t mStartCount GUARDED_BY(mLock) = 0;
        int64_t mStopCount GUARDED_BY(mLock) = 0;

        SimpleLog mSimpleLog GUARDED_BY(mLock) {64};
    } mHealth{*this};

    // Spatializer is a nested class that tracks related messages.
    class Spatializer {
    public:
        explicit Spatializer(AudioAnalytics &audioAnalytics)
            : mAudioAnalytics(audioAnalytics) {}

        // an item that starts with "audio.spatializer"
        void onEvent(const std::shared_ptr<const android::mediametrics::Item> &item);

        std::pair<std::string, int32_t> dump(
                int32_t lines = INT32_MAX, const char *prefix = nullptr) const;

    private:

        // Current device state as strings:
        // "" means unknown, "true" or "false".
        struct DeviceState {
            std::string enabled;
            std::string hasHeadTracker;
            std::string headTrackerEnabled;
        };

        AudioAnalytics& mAudioAnalytics;
        static constexpr int64_t kBootDurationThreshold = 120 /* seconds */ * 1e9;
        mutable std::mutex mLock;
        int64_t mFirstCreateTimeNs GUARDED_BY(mLock) = 0;
        std::map<std::string, DeviceState> mDeviceStateMap GUARDED_BY(mLock);
        SimpleLog mSimpleLog GUARDED_BY(mLock) {64};
    } mSpatializer{*this};

    AudioPowerUsage mAudioPowerUsage;
};

} // namespace android::mediametrics
