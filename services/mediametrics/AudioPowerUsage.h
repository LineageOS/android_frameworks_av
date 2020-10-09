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

#pragma once

#include <android-base/thread_annotations.h>
#include <deque>
#include <media/MediaMetricsItem.h>
#include <mutex>
#include <thread>

namespace android::mediametrics {

class AudioAnalytics;

class AudioPowerUsage {
public:
    explicit AudioPowerUsage(AudioAnalytics *audioAnalytics);
    ~AudioPowerUsage();

    void checkTrackRecord(const std::shared_ptr<const mediametrics::Item>& item, bool isTrack);
    void checkMode(const std::shared_ptr<const mediametrics::Item>& item);
    void checkVoiceVolume(const std::shared_ptr<const mediametrics::Item>& item);
    void checkCreatePatch(const std::shared_ptr<const mediametrics::Item>& item);
    void clear();

    /**
     * Returns a pair consisting of the dump string, and the number of lines in the string.
     *
     * The number of lines in the returned pair is used as an optimization
     * for subsequent line limiting.
     *
     * \param lines the maximum number of lines in the string returned.
     */
    std::pair<std::string, int32_t> dump(int32_t lines = INT32_MAX) const;

    // align with message AudioUsageDataReported in frameworks/base/cmds/statsd/src/atoms.proto
    enum AudioType {
        UNKNOWN_TYPE = 0,
        VOICE_CALL_TYPE = 1,            // voice call
        VOIP_CALL_TYPE = 2,             // voip call, including uplink and downlink
        MEDIA_TYPE = 3,                 // music and system sound
        RINGTONE_NOTIFICATION_TYPE = 4, // ringtone and notification
        ALARM_TYPE = 5,                 // alarm type
        // record type
        CAMCORDER_TYPE = 6,             // camcorder
        RECORD_TYPE = 7,                // other recording
    };

    enum AudioDevice {
        OUTPUT_EARPIECE         = 0x1,
        OUTPUT_SPEAKER          = 0x2,
        OUTPUT_WIRED_HEADSET    = 0x4,
        OUTPUT_USB_HEADSET      = 0x8,
        OUTPUT_BLUETOOTH_SCO    = 0x10,
        OUTPUT_BLUETOOTH_A2DP   = 0x20,
        OUTPUT_SPEAKER_SAFE     = 0x40,

        INPUT_DEVICE_BIT        = 0x40000000,
        INPUT_BUILTIN_MIC       = INPUT_DEVICE_BIT | 0x1, // non-negative positive int32.
        INPUT_BUILTIN_BACK_MIC  = INPUT_DEVICE_BIT | 0x2,
        INPUT_WIRED_HEADSET_MIC = INPUT_DEVICE_BIT | 0x4,
        INPUT_USB_HEADSET_MIC   = INPUT_DEVICE_BIT | 0x8,
        INPUT_BLUETOOTH_SCO     = INPUT_DEVICE_BIT | 0x10,
    };

    static bool typeFromString(const std::string& type_string, int32_t& type);
    static bool deviceFromString(const std::string& device_string, int32_t& device);
    static int32_t deviceFromStringPairs(const std::string& device_strings);
private:
    bool saveAsItem_l(int32_t device, int64_t duration, int32_t type, double average_vol)
         REQUIRES(mLock);
    static void sendItem(const std::shared_ptr<const mediametrics::Item>& item);
    void collect();
    bool saveAsItems_l(int32_t device, int64_t duration, int32_t type, double average_vol)
         REQUIRES(mLock);

    AudioAnalytics * const mAudioAnalytics;
    const bool mDisabled;
    const int32_t mIntervalHours;

    mutable std::mutex mLock;
    std::deque<std::shared_ptr<mediametrics::Item>> mItems GUARDED_BY(mLock);

    double mVoiceVolume GUARDED_BY(mLock) = 0.;
    double mDeviceVolume GUARDED_BY(mLock) = 0.;
    int64_t mStartCallNs GUARDED_BY(mLock) = 0; // advisory only
    int64_t mVolumeTimeNs GUARDED_BY(mLock) = 0;
    int64_t mDeviceTimeNs GUARDED_BY(mLock) = 0;
    int32_t mPrimaryDevice GUARDED_BY(mLock) = OUTPUT_SPEAKER;
    std::string mMode GUARDED_BY(mLock) {"AUDIO_MODE_NORMAL"};
};

} // namespace android::mediametrics
